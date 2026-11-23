/* export.c - pliki CSV (separator ';') do dalszej analizy, np. w Excelu. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "export.h"

/* Napis w cudzysłowie; cudzysłów w środku zapisujemy podwójnie. */
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

static int write_events(const analysis_t *an, const char *dir)
{
    FILE *f = open_out(dir, "zdarzenia.csv");
    if (f == NULL)
        return 0;
    fprintf(f, "typ;start_s;koniec_s;czas_s;szczyt;opis\n");
    for (size_t i = 0; i < an->x->n_ev; i++) {
        const event_t *e = &an->x->ev[i];
        csv_str(f, event_name(e->type));
        fprintf(f, ";%.0f;%.0f;%.0f;%.2f;", e->t0, e->t1, e->t1 - e->t0, e->peak);
        csv_str(f, e->detail);
        fputc('\n', f);
    }
    fclose(f);
    return 1;
}

static void num(FILE *f, double v)
{
    if (!isnan(v))
        fprintf(f, "%.2f", v);
}

/* Serie sekundowe - te same dane co na wykresach. */
static int write_seconds(const analysis_t *an, const char *dir)
{
    FILE *f = open_out(dir, "sekundy.csv");
    if (f == NULL)
        return 0;
    const sensing_t *x = an->x;
    fprintf(f, "sekunda;rssi_dbm;wskaznik_ruchu_db;szum_dbm;powtorzenia_proc;rtt_ms;"
               "retransmisje;pakiety\n");
    for (size_t i = 0; i < x->n_sec; i++) {
        fprintf(f, "%zu;", i);
        num(f, x->rssi[i]);    fputc(';', f);
        num(f, x->motion[i]);  fputc(';', f);
        num(f, x->noise[i]);   fputc(';', f);
        num(f, x->retry[i]);   fputc(';', f);
        num(f, x->rtt[i]);     fputc(';', f);
        fprintf(f, "%.0f;%.0f\n", x->retrans[i], x->pps[i]);
    }
    fclose(f);
    return 1;
}

static int write_incidents(const stats_t *s, const anomalies_t *a, const char *dir)
{
    FILE *f = open_out(dir, "ataki.csv");
    if (f == NULL)
        return 0;
    fprintf(f, "waga;kategoria;zrodlo;cel;start_s;koniec_s;opis;rekomendacja\n");
    for (size_t i = 0; i < a->n; i++) {
        const anomaly_t *an = &a->items[i];
        csv_str(f, severity_name(an->severity));  fputc(';', f);
        csv_str(f, an->category);                 fputc(';', f);
        csv_str(f, an->source);                   fputc(';', f);
        csv_str(f, an->target);                   fputc(';', f);
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

static int write_flows(const stats_t *s, const char *dir)
{
    FILE *f = open_out(dir, "przeplywy.csv");
    if (f == NULL)
        return 0;
    /* duży bufor = mniej wywołań systemowych */
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

int export_csv(const analysis_t *an, const char *outdir)
{
    return write_events(an, outdir) + write_seconds(an, outdir) +
           write_incidents(an->s, an->a, outdir) + write_flows(an->s, outdir);
}
