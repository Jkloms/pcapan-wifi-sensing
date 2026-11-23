/*
 * main.c - pcapan: wykrywanie ruchu człowieka i zakłóceń z nagrań Wi-Fi (.pcap).
 *
 *   plik.pcap -> parser -> stats -> sensing (ruch, zakłócenia, łącze)
 *                                -> anomaly (ataki, dodatkowo)
 *                                -> plots (PNG), export (CSV), report (PDF)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cairo.h>
#include "parser.h"
#include "stats.h"
#include "sensing.h"
#include "anomaly.h"
#include "plots.h"
#include "report.h"
#include "export.h"

static void usage(const char *prog)
{
    fprintf(stderr,
        "Użycie: %s [-o KATALOG] plik.pcap\n"
        "\n"
        "Szuka okresów ruchu człowieka (wahania RSSI) i zakłóceń w nagraniu Wi-Fi\n"
        "(radiotap) oraz analizuje ruch TCP/UDP. Wynik: raport.pdf, wykresy PNG, CSV.\n"
        "\n"
        "  -o KATALOG   katalog wyjściowy (domyślnie: raport)\n"
        "  -h           pomoc\n", prog);
}

static int make_dir(const char *path)
{
    if (mkdir(path, 0755) == 0 || errno == EEXIST)
        return 0;
    perror(path);
    return -1;
}

static void print_summary(const stats_t *s, const sensing_t *x, const anomalies_t *a)
{
    printf("\nPakiety: %llu (TCP %llu, UDP %llu, ramki Wi-Fi %llu), czas %.0f s\n",
           (unsigned long long)s->total_pkts, (unsigned long long)s->tcp_pkts,
           (unsigned long long)s->udp_pkts, (unsigned long long)s->wifi_frames,
           stats_duration(s));
    if (x->ref_tx >= 0)
        printf("Próg ruchu: %.1f dB\n", x->motion_thr);
    else
        printf("Brak danych radiowych - wykrywanie ruchu pominięte.\n");

    printf("\nZdarzenia (%zu):\n", x->n_ev);
    for (size_t i = 0; i < x->n_ev; i++) {
        const event_t *e = &x->ev[i];
        const char *name = event_name(e->type);
        int chars = 0;                       /* liczba znaków UTF-8, nie bajtów */
        for (const char *c = name; *c; c++)
            chars += (*c & 0xC0) != 0x80;
        printf("  %4.0f-%4.0f s  %s%*s %s\n", e->t0, e->t1, name, 20 - chars, "", e->detail);
    }
    if (a->n > 0) {
        printf("\nAtaki (%zu):\n", a->n);
        for (size_t i = 0; i < a->n; i++)
            printf("  %-28s %s\n", a->items[i].category, a->items[i].source);
    }
}

int main(int argc, char **argv)
{
    const char *outdir = "raport";
    int opt;
    while ((opt = getopt(argc, argv, "o:h")) != -1) {
        switch (opt) {
        case 'o': outdir = optarg; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 2;
        }
    }
    if (optind != argc - 1) {
        usage(argv[0]);
        return 2;
    }
    const char *input = argv[optind];

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

    /* 1. czytanie pakietów */
    printf("Analiza %s (łącze: %s)...\n", input, parser_linktype_name(parser));
    packet_t pkt;
    parse_result_t r;
    int oom = 0;
    while (!oom && (r = parser_next(parser, &pkt)) != PARSE_END) {
        if (r == PARSE_OK)
            oom = stats_add_packet(stats, &pkt) != 0;
        else
            stats_add_other(stats, &pkt, r == PARSE_BAD);
        if (pkt.has_radio && stats_add_radio(stats, &pkt) != 0)
            oom = 1;
    }
    char linktype[64];
    snprintf(linktype, sizeof linktype, "%s", parser_linktype_name(parser));
    parser_close(parser);
    if (oom)
        fprintf(stderr, "Brak pamięci podczas analizy - wynik częściowy\n");
    if (stats->total_pkts == 0) {
        fprintf(stderr, "Plik nie zawiera pakietów.\n");
        stats_free(stats);
        return 1;
    }

    /* 2. wykrywanie */
    sensing_t sensing;
    anomalies_t attacks = { 0 };
    thresholds_t th;
    thresholds_default(&th);
    int rc = 0;
    if (sensing_run(stats, &sensing) != 0 || anomalies_detect(stats, &th, &attacks) != 0) {
        fprintf(stderr, "Brak pamięci\n");
        rc = 1;
    }

    /* 3. wyniki */
    if (rc == 0 && make_dir(outdir) == 0) {
        analysis_t an = { stats, &sensing, &attacks };
        int n_png = 0;
        if (plots_generate(&an, outdir, &n_png) != 0)
            fprintf(stderr, "Uwaga: nie wszystkie wykresy się udały\n");
        int n_csv = export_csv(&an, outdir);

        char pdf[512];
        snprintf(pdf, sizeof pdf, "%s/raport.pdf", outdir);
        report_input_t rin = { input, linktype, pdf, an };
        if (report_write(&rin) != 0)
            rc = 1;
        print_summary(stats, &sensing, &attacks);
        printf("\nRaport: %s  (+ %d wykresów PNG, %d plików CSV)\n", pdf, n_png, n_csv);
    } else {
        rc = 1;
    }

    sensing_free(&sensing);
    anomalies_free(&attacks);
    stats_free(stats);
    cairo_debug_reset_static_data();   /* żeby ASan nie zgłaszał buforów czcionek */
    return rc;
}
