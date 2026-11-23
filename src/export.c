/*
 * export.c - zapis wyników do CSV (opis w export.h).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "export.h"

/*
 * Wypisuje pole tekstowe w cudzysłowie. Cudzysłów wewnątrz tekstu
 * trzeba podwoić ("") - tak wymaga format CSV.
 */
static void csv_str(FILE *f, const char *s)
{
    fputc('"', f);
    for (; *s; s++) {
        if (*s == '"')
            fputc('"', f);
        fputc(*s, f);
    }
    fputc('"', f);
}

/* Otwiera plik outdir/name do zapisu; przy błędzie wypisuje komunikat. */
static FILE *open_out(const char *outdir, const char *name)
{
    char path[512];
    snprintf(path, sizeof path, "%s/%s", outdir, name);
    FILE *f = fopen(path, "w");
    if (f == NULL)
        perror(path);
    return f;
}

static int write_incidents(const stats_t *s, const anomalies_t *a, const char *dir)
{
    FILE *f = open_out(dir, "incydenty.csv");
    if (f == NULL)
        return 0;
    fprintf(f, "waga;kategoria;zrodlo;cel;start_s;koniec_s;opis;rekomendacja\n");
    for (size_t i = 0; i < a->n; i++) {
        const anomaly_t *an = &a->items[i];
        csv_str(f, severity_name(an->severity));  fputc(';', f);
        csv_str(f, an->category);                 fputc(';', f);
        csv_str(f, an->source);                   fputc(';', f);
        csv_str(f, an->target);                   fputc(';', f);
        /* czas względem początku nagrania; puste pole = całe nagranie */
        if (an->t_start > 0)
            fprintf(f, "%.3f;%.3f;", an->t_start - s->first_ts, an->t_end - s->first_ts);
        else
            fprintf(f, ";;");
        csv_str(f, an->text);                     fputc(';', f);
        csv_str(f, an->advice ? an->advice : ""); fputc('\n', f);
    }
    fclose(f);
    return 1;
}

static int write_ioc(const anomalies_t *a, const char *dir)
{
    ioc_t *list;
    long n = anomalies_ioc(a, &list);
    if (n < 0)
        return 0;
    FILE *f = open_out(dir, "ioc.csv");
    if (f == NULL) {
        free(list);
        return 0;
    }
    fprintf(f, "ip;rola;incydenty_jako_zrodlo;incydenty_jako_cel;najwyzsza_waga\n");
    for (long i = 0; i < n; i++) {
        char ip[ADDR_STR_LEN];
        addr_to_str(&list[i].ip, ip);
        const char *role = list[i].attacker && list[i].victim ? "źródło i cel"
                         : list[i].attacker ? "źródło ataku" : "cel ataku";
        fprintf(f, "%s;%s;%d;%d;%s\n", ip, role, list[i].attacker, list[i].victim,
                severity_name(list[i].max_sev));
    }
    fclose(f);
    free(list);
    return 1;
}

static int write_hosts(const stats_t *s, const char *dir)
{
    FILE *f = open_out(dir, "hosty.csv");
    if (f == NULL)
        return 0;
    fprintf(f, "ip;pakiety_wyslane;bajty_wyslane;pakiety_odebrane;bajty_odebrane\n");
    for (size_t i = 0; i < s->n_hosts; i++) {
        const host_t *h = s->hosts[i];
        char ip[ADDR_STR_LEN];
        addr_to_str(&h->addr, ip);
        fprintf(f, "%s;%llu;%llu;%llu;%llu\n", ip,
                (unsigned long long)h->pkts_out, (unsigned long long)h->bytes_out,
                (unsigned long long)h->pkts_in, (unsigned long long)h->bytes_in);
    }
    fclose(f);
    return 1;
}

static int write_flows(const stats_t *s, const char *dir)
{
    FILE *f = open_out(dir, "przeplywy.csv");
    if (f == NULL)
        return 0;
    /* Większy bufor zapisu = mniej wywołań systemowych przy milionach wierszy. */
    static char buf[1 << 16];
    setvbuf(f, buf, _IOFBF, sizeof buf);
    fprintf(f, "proto;klient;port_klienta;serwer;port_serwera;pakiety_k2s;pakiety_s2k;"
               "bajty_k2s;bajty_s2k;start_s;czas_s;rtt_ms;retransmisje;stan\n");
    for (size_t i = 0; i < s->n_flows; i++) {
        const flow_t *fl = s->flows[i];
        char c[ADDR_STR_LEN], v[ADDR_STR_LEN];
        addr_to_str(&fl->cli, c);
        addr_to_str(&fl->srv, v);
        fprintf(f, "%s;%s;%u;%s;%u;%llu;%llu;%llu;%llu;%.3f;%.3f;",
                fl->proto == PROTO_TCP ? "TCP" : "UDP", c, fl->cport, v, fl->sport,
                (unsigned long long)fl->pkts[0], (unsigned long long)fl->pkts[1],
                (unsigned long long)fl->bytes[0], (unsigned long long)fl->bytes[1],
                fl->first_ts - s->first_ts, fl->last_ts - fl->first_ts);
        if (fl->rtt >= 0) fprintf(f, "%.3f", fl->rtt * 1000.0);
        fprintf(f, ";%u;%s\n", fl->retrans, flow_state_str(fl));
    }
    fclose(f);
    return 1;
}

int export_csv(const stats_t *s, const anomalies_t *a, const char *outdir)
{
    return write_incidents(s, a, outdir) + write_ioc(a, outdir) +
           write_hosts(s, outdir) + write_flows(s, outdir);
}
