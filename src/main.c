/*
 * main.c - punkt wejścia programu pcapan.
 *
 * Przebieg działania (potok / "pipeline"):
 *
 *   plik.pcap --> [parser] --> packet_t --> [stats] --> stats_t
 *                                                          |
 *                       [anomaly] <------------------------+
 *                           |                              |
 *                           v                              v
 *                      anomalies_t --> [plots] --> pliki PNG
 *                                          \
 *                                           --> [report] --> raport.pdf
 *
 * Każdy moduł ma jedną odpowiedzialność i własny plik .c/.h.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>      /* getopt */
#include <sys/stat.h>    /* mkdir */
#include <cairo.h>       /* tylko dla cairo_debug_reset_static_data */
#include "parser.h"
#include "stats.h"
#include "anomaly.h"
#include "plots.h"
#include "report.h"
#include "export.h"

static void usage(const char *prog)
{
    /* stderr - strumień na komunikaty diagnostyczne, stdout - na wyniki */
    fprintf(stderr,
        "Użycie: %s [opcje] plik.pcap\n"
        "\n"
        "Analizuje ruch TCP i UDP z pliku .pcap/.pcapng i tworzy raport PDF oraz wykresy PNG.\n"
        "\n"
        "Opcje:\n"
        "  -o KATALOG   katalog wyjściowy (domyślnie: raport)\n"
        "  -p N         próg skanowania portów: liczba różnych portów (domyślnie 15)\n"
        "  -n N         próg skanowania sieci: liczba różnych hostów (domyślnie 15)\n"
        "  -s N         próg SYN flood: niedokończone połączenia (domyślnie 100)\n"
        "  -r PROCENT   próg retransmisji w %% pakietów TCP (domyślnie 3)\n"
        "  -u N         próg UDP flood w pakietach/s (domyślnie 500)\n"
        "  -h           ta pomoc\n"
        "\n"
        "Przykład: %s -o wynik samples/mixed.pcap\n", prog, prog);
}

/* Tworzy katalog; brak błędu, jeśli już istnieje. */
static int make_dir(const char *path)
{
    if (mkdir(path, 0755) == 0 || errno == EEXIST)
        return 0;
    perror(path);   /* wypisuje opis ostatniego błędu systemowego (errno) */
    return -1;
}

/* Krótkie podsumowanie w terminalu. */
static void print_summary(const stats_t *s, const anomalies_t *a)
{
    printf("\n=== Podsumowanie ===\n");
    printf("Pakiety:      %llu (TCP %llu, UDP %llu, inne %llu, uszkodzone %llu)\n",
           (unsigned long long)s->total_pkts, (unsigned long long)s->tcp_pkts,
           (unsigned long long)s->udp_pkts, (unsigned long long)s->other_pkts,
           (unsigned long long)s->bad_pkts);
    printf("Bajty:        %llu\n", (unsigned long long)s->total_bytes);
    printf("Czas trwania: %.2f s\n", stats_duration(s));
    printf("Hosty:        %zu, przepływy: %zu (TCP %llu, UDP %llu)\n", s->n_hosts,
           s->n_flows, (unsigned long long)s->tcp_flows, (unsigned long long)s->udp_flows);
    printf("Retransmisje: %llu\n", (unsigned long long)s->tcp_retrans);

    printf("\n=== Wynik ryzyka: %d/100 (%s) ===\n", a->risk_score,
           risk_level_name(risk_level(a->risk_score)));
    printf("\n=== Incydenty (%zu) ===\n", a->n);
    for (size_t i = 0; i < a->n; i++) {
        const anomaly_t *an = &a->items[i];
        printf("[%s] %s  |  %s -> %s\n    %s\n", severity_name(an->severity),
               an->category, an->source, an->target, an->text);
    }
    if (a->n == 0)
        printf("Brak.\n");
}

int main(int argc, char **argv)
{
    const char *outdir = "raport";
    thresholds_t th;
    thresholds_default(&th);

    /* getopt przetwarza opcje typu "-o wartość". Napis "o:p:..." mówi,
     * które litery są dozwolone; dwukropek = opcja wymaga wartości. */
    int opt;
    while ((opt = getopt(argc, argv, "o:p:n:s:r:u:h")) != -1) {
        switch (opt) {
        case 'o': outdir = optarg; break;
        case 'p': th.scan_min_ports = atoi(optarg); break;
        case 'n': th.sweep_min_hosts = atoi(optarg); break;
        case 's': th.synflood_min = atoi(optarg); break;
        case 'r': th.retrans_ratio = atof(optarg) / 100.0; break;
        case 'u': th.udpflood_pps = atof(optarg); break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 2;
        }
    }
    if (optind != argc - 1) {     /* oczekujemy dokładnie jednego pliku */
        usage(argv[0]);
        return 2;
    }
    const char *input = argv[optind];

    /* ---- 1. Otwarcie pliku ---- */
    char err[256];
    parser_t *parser = parser_open(input, err);
    if (parser == NULL) {
        fprintf(stderr, "Nie można otworzyć %s: %s\n", input, err);
        return 1;
    }

    stats_t *stats = stats_create();
    if (stats == NULL) {
        fprintf(stderr, "Brak pamięci\n");
        parser_close(parser);
        return 1;
    }

    /* ---- 2. Czytanie pakietów i zbieranie statystyk ---- */
    printf("Analiza pliku %s (łącze: %s)...\n", input, parser_linktype_name(parser));
    packet_t pkt;
    parse_result_t r;
    while ((r = parser_next(parser, &pkt)) != PARSE_END) {
        if (r == PARSE_OK) {
            if (stats_add_packet(stats, &pkt) != 0) {
                fprintf(stderr, "Brak pamięci podczas analizy\n");
                break;
            }
        } else {
            stats_add_other(stats, &pkt, r == PARSE_BAD);
        }
    }
    /* Typ łącza kopiujemy, bo po parser_close() napis może przestać istnieć. */
    char linktype[64];
    snprintf(linktype, sizeof linktype, "%s", parser_linktype_name(parser));
    parser_close(parser);

    if (stats->total_pkts == 0) {
        fprintf(stderr, "Plik nie zawiera pakietów.\n");
        stats_free(stats);
        return 1;
    }

    /* ---- 3. Wykrywanie anomalii ---- */
    anomalies_t anomalies;
    if (anomalies_detect(stats, &th, &anomalies) != 0) {
        fprintf(stderr, "Brak pamięci podczas wykrywania anomalii\n");
        anomalies_free(&anomalies);
        stats_free(stats);
        return 1;
    }

    /* ---- 4. Wykresy i raport ---- */
    int rc = 0;
    if (make_dir(outdir) != 0) {
        rc = 1;
    } else {
        int n_png = 0;
        int errors = plots_generate(stats, &anomalies, outdir, &n_png);
        if (errors)
            fprintf(stderr, "Uwaga: %d wykresów nie udało się wygenerować\n", errors);
        int n_csv = export_csv(stats, &anomalies, outdir);

        char pdf_path[512];
        snprintf(pdf_path, sizeof pdf_path, "%s/raport.pdf", outdir);
        report_input_t rin = {
            .input_path = input,      /* "designated initializers" - pola po nazwie */
            .linktype   = linktype,
            .output_pdf = pdf_path,
            .stats      = stats,
            .anomalies  = &anomalies,
            .thresholds = &th,
        };
        if (report_write(&rin) != 0)
            rc = 1;

        print_summary(stats, &anomalies);
        printf("\nRaport:      %s\nWykresy PNG: %d plików, CSV: %d plików w katalogu %s/\n",
               pdf_path, n_png, n_csv, outdir);
    }

    /* ---- 5. Sprzątanie ---- */
    anomalies_free(&anomalies);
    stats_free(stats);
    /* Zwalnia wewnętrzne bufory cairo (czcionki) - dzięki temu narzędzia
     * do wykrywania wycieków pamięci nie zgłaszają fałszywych alarmów. */
    cairo_debug_reset_static_data();
    return rc;
}
