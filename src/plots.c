/* plots.c - wykresy raportu: dane radiowe, łącze i podstawowe statystyki TCP/UDP. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "plots.h"
#include "charts.h"

size_t top_n(const double *values, size_t count, size_t *idx, size_t n_top)
{
    size_t used = 0;
    if (n_top == 0)
        return 0;
    for (size_t i = 0; i < count; i++) {
        double v = values[i];
        if (v <= 0)
            continue;
        if (used == n_top && v <= values[idx[used - 1]])
            continue;
        /* sortowanie przez wstawianie */
        size_t pos = (used < n_top) ? used++ : used - 1;
        while (pos > 0 && values[idx[pos - 1]] < v) {
            idx[pos] = idx[pos - 1];
            pos--;
        }
        idx[pos] = i;
    }
    return used;
}

#define MAX_POINTS 600   /* więcej punktów niż pikseli nie ma sensu */

/* Uśrednia serię sekundową do <= MAX_POINTS punktów (pomija NAN). */
static double *resample(const double *v, size_t n, size_t *n_out, size_t *width)
{
    size_t w = (n + MAX_POINTS - 1) / MAX_POINTS;
    if (w == 0) w = 1;
    size_t m = (n + w - 1) / w;
    double *out = malloc((m ? m : 1) * sizeof *out);
    if (out == NULL)
        return NULL;
    for (size_t k = 0; k < m; k++) {
        double sum = 0;
        int cnt = 0;
        for (size_t i = k * w; i < (k + 1) * w && i < n; i++)
            if (!isnan(v[i])) { sum += v[i]; cnt++; }
        out[k] = cnt ? sum / cnt : NAN;
    }
    *n_out = m;
    *width = w;
    return out;
}

/* Pasy z wykrytych zdarzeń; 'mask' wybiera typy (bit 1 << EV_...). */
static size_t build_bands(const sensing_t *x, unsigned mask, chart_band_t *b, size_t max)
{
    static const char *short_name[EV_COUNT] = {
        "ruch", "zakłócenia", "opóźnienie", "retransmisje", "przerwa"
    };
    size_t n = 0;
    for (size_t i = 0; i < x->n_ev && n < max; i++) {
        const event_t *e = &x->ev[i];
        if (!(mask & (1u << e->type)))
            continue;
        b[n].x0 = e->t0;
        b[n].x1 = e->t1;
        b[n].kind = (e->type == EV_MOTION) ? BAND_MOTION
                  : (e->type == EV_INTERFERENCE) ? BAND_WARN : BAND_CRIT;
        b[n].label = short_name[e->type];
        n++;
    }
    return n;
}

#define M_MOTION (1u << EV_MOTION)
#define M_RADIO  (1u << EV_INTERFERENCE)
#define M_LINK   ((1u << EV_DELAY) | (1u << EV_RETRANS) | (1u << EV_GAP))
#define M_ALL    (M_MOTION | M_RADIO | M_LINK)

/* Wspólny kod wykresu jednej serii sekundowej z pasami zdarzeń. */
static int one_series(const analysis_t *an, cairo_t *cr, const char *path,
                      const double *v, const char *name, const char *title,
                      const char *sub, const char *y_title, unsigned mask,
                      int y_from_data, double thr, const char *thr_label)
{
    size_t n, w;
    double *r = resample(v, an->x->n_sec, &n, &w);
    if (r == NULL)
        return -1;
    chart_band_t bands[64];
    line_chart_t c = {
        .title = title, .subtitle = sub, .y_title = y_title,
        .series = (const double *const[]){ r }, .names = (const char *const[]){ name },
        .n_series = 1, .n_points = n, .x_step = (double)w,
        .bands = bands, .n_bands = build_bands(an->x, mask, bands, 64),
        .y_from_data = y_from_data, .threshold = thr, .threshold_label = thr_label,
    };
    int rc = chart_lines(cr, path, &c);
    free(r);
    return rc;
}

static int plot_rssi(const analysis_t *an, cairo_t *cr, const char *path)
{
    char sub[96] = "Brak danych radiowych (plik bez nagłówków radiotap)";
    if (an->x->ref_tx >= 0) {
        char mac[18];
        mac_to_str(an->s->tx[an->x->ref_tx].mac, mac);
        snprintf(sub, sizeof sub, "Nadajnik %s; fioletowe pasy = podejrzenie ruchu", mac);
    }
    return one_series(an, cr, path, an->x->rssi, "RSSI", "Siła sygnału Wi-Fi i ruch",
                      sub, "dBm", M_MOTION, 1, NAN, NULL);
}

static int plot_motion(const analysis_t *an, cairo_t *cr, const char *path)
{
    char thr[48];
    snprintf(thr, sizeof thr, "próg %.1f dB", an->x->motion_thr);
    return one_series(an, cr, path, an->x->motion, "wskaźnik ruchu",
                      "Wskaźnik ruchu", "Odchylenie standardowe RSSI w oknie 3 s",
                      "dB", M_MOTION, 0, an->x->ref_tx >= 0 ? an->x->motion_thr : NAN, thr);
}

static int plot_retry(const analysis_t *an, cairo_t *cr, const char *path)
{
    return one_series(an, cr, path, an->x->retry, "powtórzone ramki",
                      "Zakłócenia radiowe: powtórzenia ramek",
                      "Odsetek ramek z flagą Retry", "%", M_RADIO, 0, 25, "próg 25%");
}

static int plot_noise(const analysis_t *an, cairo_t *cr, const char *path)
{
    return one_series(an, cr, path, an->x->noise, "szum", "Poziom szumu",
                      "Szum tła zgłaszany przez kartę Wi-Fi", "dBm", M_RADIO, 1, NAN, NULL);
}

static int plot_pps(const analysis_t *an, cairo_t *cr, const char *path)
{
    return one_series(an, cr, path, an->x->pps, "TCP+UDP", "Ruch w sieci i wszystkie zdarzenia",
                      "Pakiety na sekundę", "pakiety / s", M_ALL, 0, NAN, NULL);
}

static int plot_rtt(const analysis_t *an, cairo_t *cr, const char *path)
{
    char thr[48];
    snprintf(thr, sizeof thr, "próg %.0f ms", an->x->rtt_thr);
    return one_series(an, cr, path, an->x->rtt, "RTT", "Opóźnienie TCP (RTT)",
                      "Czas od wysłania danych do potwierdzenia ACK", "ms",
                      (1u << EV_DELAY) | (1u << EV_GAP), 0,
                      an->x->rtt_thr > 0 ? an->x->rtt_thr : NAN, thr);
}

static int plot_retrans(const analysis_t *an, cairo_t *cr, const char *path)
{
    return one_series(an, cr, path, an->x->retrans, "retransmisje",
                      "Retransmisje TCP", "Powtórzone segmenty na sekundę", "na sekundę",
                      (1u << EV_RETRANS), 0, NAN, NULL);
}

static int plot_top_hosts(const analysis_t *an, cairo_t *cr, const char *path)
{
    const stats_t *s = an->s;
    double *vals = malloc((s->n_hosts ? s->n_hosts : 1) * sizeof(double));
    if (vals == NULL)
        return -1;
    for (size_t i = 0; i < s->n_hosts; i++)
        vals[i] = (double)(s->hosts[i]->bytes_out + s->hosts[i]->bytes_in);

    size_t idx[10];
    size_t n = top_n(vals, s->n_hosts, idx, 10);
    char names[10][ADDR_STR_LEN];
    const char *labels[10];
    double values[10];
    for (size_t i = 0; i < n; i++) {
        addr_to_str(&s->hosts[idx[i]]->addr, names[i]);
        labels[i] = names[i];
        values[i] = vals[idx[i]];
    }
    free(vals);
    return chart_hbar(cr, path, "Najaktywniejsze hosty", "Bajty wysłane + odebrane, top 10",
                      labels, values, n, "B");
}

static int plot_top_services(const analysis_t *an, cairo_t *cr, const char *path)
{
    const stats_t *s = an->s;
    /* porty TCP: indeksy 0..65535, UDP: 65536..131071 */
    double *vals = malloc(2 * 65536 * sizeof(double));
    if (vals == NULL)
        return -1;
    for (size_t i = 0; i < 65536; i++) {
        vals[i] = (double)s->tcp_port_pkts[i];
        vals[65536 + i] = (double)s->udp_port_pkts[i];
    }
    size_t idx[10];
    size_t n = top_n(vals, 2 * 65536, idx, 10);
    char names[10][48];
    const char *labels[10];
    double values[10];
    for (size_t i = 0; i < n; i++) {
        int is_udp = idx[i] >= 65536;
        uint16_t port = (uint16_t)(idx[i] % 65536);
        const char *svc = port_service_name(is_udp ? PROTO_UDP : PROTO_TCP, port);
        snprintf(names[i], sizeof names[i], "%s/%u%s%s%s", is_udp ? "UDP" : "TCP", port,
                 svc ? " (" : "", svc ? svc : "", svc ? ")" : "");
        labels[i] = names[i];
        values[i] = vals[idx[i]];
    }
    free(vals);
    return chart_hbar(cr, path, "Usługi (porty serwerów)",
                      "Liczba pakietów, top 10", labels, values, n, "pakietów");
}

static int plot_flow_states(const analysis_t *an, cairo_t *cr, const char *path)
{
    const stats_t *s = an->s;
    double counts[FS_COUNT] = { 0 };
    for (size_t i = 0; i < s->n_flows; i++)
        if (s->flows[i]->proto == PROTO_TCP)
            counts[flow_state(s->flows[i])]++;

    size_t idx[FS_COUNT];
    size_t n = top_n(counts, FS_COUNT, idx, FS_COUNT);
    const char *labels[FS_COUNT];
    double values[FS_COUNT];
    for (size_t i = 0; i < n; i++) {
        labels[i] = flow_state_name((flow_state_t)idx[i]);
        values[i] = counts[idx[i]];
    }
    return chart_hbar(cr, path, "Stany połączeń TCP", "Liczba przepływów TCP",
                      labels, values, n, "połączeń");
}

const plot_def_t PLOTS[] = {
    { "01_rssi_ruch.png", "Gdy ktoś się porusza, RSSI zaczyna skakać - te okresy są zaznaczone.", plot_rssi },
    { "02_wskaznik_ruchu.png", "Powyżej linii progu uznajemy, że w pomieszczeniu był ruch.", plot_motion },
    { "03_powtorzenia.png", "Dużo powtórzonych ramek = zakłócenia lub kolizje w kanale.", plot_retry },
    { "04_szum.png", "Wzrost szumu oznacza obce źródło sygnału na tym kanale.", plot_noise },
    { "05_ruch_sieciowy.png", "Natężenie ruchu na tle wszystkich wykrytych zdarzeń.", plot_pps },
    { "06_rtt.png", "Skoki ponad próg to chwilowe problemy z łączem.", plot_rtt },
    { "07_retransmisje.png", "Retransmisje pojawiają się, gdy pakiety giną po drodze.", plot_retrans },
    { "08_uslugi.png", "Najczęściej używane usługi.", plot_top_services },
    { "09_hosty.png", "Hosty, które wymieniły najwięcej danych.", plot_top_hosts },
    { "10_stany_tcp.png", "Jak kończyły się połączenia TCP.", plot_flow_states },
    { NULL, NULL, NULL }
};

int plots_generate(const analysis_t *an, const char *outdir, int *n_ok)
{
    int errors = 0;
    *n_ok = 0;
    for (const plot_def_t *p = PLOTS; p->file != NULL; p++) {
        char path[512];
        snprintf(path, sizeof path, "%s/%s", outdir, p->file);
        if (p->draw(an, NULL, path) == 0) (*n_ok)++;
        else errors++;
    }
    return errors;
}
