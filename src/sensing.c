/* sensing.c - serie sekundowe i wykrywanie okresów ruchu / zakłóceń. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "sensing.h"

#define MOTION_MIN_THR  1.5   /* dB - minimalny próg wskaźnika ruchu */
#define RETRY_THR      25.0   /* % ramek powtórzonych */
#define NOISE_RISE      6.0   /* dB powyżej typowego szumu */
#define GAP_MIN         3     /* s bez ruchu TCP/UDP */

const char *event_name(event_type_t t)
{
    static const char *n[EV_COUNT] = {
        "Podejrzenie ruchu", "Zakłócenia radiowe", "Wzrost opóźnienia",
        "Retransmisje TCP", "Przerwa w ruchu"
    };
    return (t < EV_COUNT) ? n[t] : "?";
}

int sensing_count(const sensing_t *x, event_type_t t)
{
    int c = 0;
    for (size_t i = 0; i < x->n_ev; i++)
        c += (x->ev[i].type == t);
    return c;
}

static int cmp_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

/* Percentyl (0..100) z wartości różnych od NAN; NAN, gdy brak danych. */
static double percentile(const double *v, size_t n, double pct)
{
    double *tmp = malloc((n ? n : 1) * sizeof *tmp);
    if (tmp == NULL)
        return NAN;
    size_t k = 0;
    for (size_t i = 0; i < n; i++)
        if (!isnan(v[i]))
            tmp[k++] = v[i];
    double r = NAN;
    if (k > 0) {
        qsort(tmp, k, sizeof *tmp, cmp_double);
        r = tmp[(size_t)((k - 1) * pct / 100.0 + 0.5)];
    }
    free(tmp);
    return r;
}

static int add_event(sensing_t *x, event_type_t type, double t0, double t1,
                     double peak, const char *detail)
{
    if (x->n_ev == x->cap_ev) {
        size_t cap = x->cap_ev ? x->cap_ev * 2 : 16;
        event_t *tmp = realloc(x->ev, cap * sizeof *tmp);
        if (tmp == NULL)
            return -1;
        x->ev = tmp;
        x->cap_ev = cap;
    }
    event_t *e = &x->ev[x->n_ev++];
    e->type = type;
    e->t0 = t0;
    e->t1 = t1;
    e->peak = peak;
    snprintf(e->detail, sizeof e->detail, "%s", detail);
    return 0;
}

/* Zamyka okres [start, end] - dodaje zdarzenie, jeśli trwał >= min_len s. */
static int close_period(sensing_t *x, size_t start, size_t end, const double *val,
                        event_type_t type, int min_len, const char *fmt, const char *unit)
{
    if ((int)(end - start + 1) < min_len)
        return 0;
    double peak = 0;
    for (size_t t = start; t <= end; t++)
        if (val && !isnan(val[t]) && val[t] > peak) peak = val[t];
    char d[96];
    snprintf(d, sizeof d, fmt, peak, unit);
    return add_event(x, type, (double)start, (double)(end + 1), peak, d);
}

/*
 * Zamienia flagi "sekunda podejrzana" na okresy: łączy okresy oddalone
 * o <= max_gap s i odrzuca krótsze niż min_len s.
 */
static int flags_to_events(sensing_t *x, const unsigned char *flag, const double *val,
                           event_type_t type, int max_gap, int min_len,
                           const char *fmt, const char *unit)
{
    int open = 0;
    size_t start = 0, end = 0;
    for (size_t i = 0; i < x->n_sec; i++) {
        if (!flag[i])
            continue;
        if (open && i - end - 1 <= (size_t)max_gap) {
            end = i;                          /* przedłużamy bieżący okres */
            continue;
        }
        if (open && close_period(x, start, end, val, type, min_len, fmt, unit) != 0)
            return -1;
        open = 1;
        start = end = i;
    }
    if (open)
        return close_period(x, start, end, val, type, min_len, fmt, unit);
    return 0;
}

/* Nadajnik odniesienia: ten, który był słyszany w największej liczbie sekund. */
static int pick_ref_tx(const stats_t *s)
{
    int best = -1;
    size_t best_sec = 0;
    for (size_t t = 0; t < s->n_tx; t++) {
        size_t sec = 0;
        for (size_t i = 0; i < s->tx[t].cap && i < s->tl_len; i++)
            sec += (s->tx[t].n[i] >= 3);
        if (sec > best_sec) { best_sec = sec; best = (int)t; }
    }
    return best;
}

static int detect_motion(const stats_t *s, sensing_t *x, unsigned char *flag)
{
    x->ref_tx = pick_ref_tx(s);
    if (x->ref_tx < 0)
        return 0;
    const radio_tx_t *t = &s->tx[x->ref_tx];
    size_t n = x->n_sec;
    size_t m = (t->cap < n) ? t->cap : n;

    for (size_t i = 0; i < m; i++)
        if (t->n[i] > 0)
            x->rssi[i] = t->sum[i] / t->n[i];

    /* odchylenie standardowe w oknie [i-1, i+1]: sqrt(E[x^2] - E[x]^2) */
    for (size_t i = 0; i < m; i++) {
        double N = 0, S = 0, S2 = 0;
        for (size_t j = (i ? i - 1 : 0); j <= i + 1 && j < m; j++) {
            N += t->n[j];
            S += t->sum[j];
            S2 += t->sum2[j];
        }
        if (N >= 8) {
            double var = S2 / N - (S / N) * (S / N);
            x->motion[i] = sqrt(var > 0 ? var : 0);
        }
    }

    /* próg = 2x poziom "ciszy" (25. percentyl), ale nie mniej niż 1,5 dB */
    double quiet = percentile(x->motion, n, 25);
    x->motion_thr = isnan(quiet) ? MOTION_MIN_THR : fmax(MOTION_MIN_THR, 2 * quiet);

    memset(flag, 0, n);
    for (size_t i = 0; i < n; i++)
        flag[i] = !isnan(x->motion[i]) && x->motion[i] > x->motion_thr;
    size_t before = x->n_ev;
    if (flags_to_events(x, flag, x->motion, EV_MOTION, 2, 2,
                        "wahania RSSI do %.1f %s", "dB") != 0)
        return -1;
    for (size_t e = before; e < x->n_ev; e++)
        x->motion_sec += x->ev[e].t1 - x->ev[e].t0;
    return 0;
}

static int detect_interference(const stats_t *s, sensing_t *x, unsigned char *flag)
{
    size_t n = x->n_sec;
    for (size_t i = 0; i < n; i++) {
        const tl_bucket_t *b = &s->timeline[i];
        if (b->wifi >= 5)
            x->retry[i] = 100.0 * b->wifi_retry / b->wifi;
        if (b->noise_n > 0)
            x->noise[i] = (double)b->noise_sum / b->noise_n;
    }
    double noise_med = percentile(x->noise, n, 50);
    double *score = malloc(n * sizeof *score);   /* do opisu: max % powtórzeń */
    if (score == NULL)
        return -1;
    for (size_t i = 0; i < n; i++) {
        int bad_retry = !isnan(x->retry[i]) && x->retry[i] > RETRY_THR;
        int bad_noise = !isnan(x->noise[i]) && !isnan(noise_med) &&
                        x->noise[i] > noise_med + NOISE_RISE;
        flag[i] = bad_retry || bad_noise;
        score[i] = isnan(x->retry[i]) ? 0 : x->retry[i];
    }
    int rc = flags_to_events(x, flag, score, EV_INTERFERENCE, 2, 2,
                             "powtórzone ramki do %.0f%s", "%");
    free(score);
    return rc;
}

static int detect_link(const stats_t *s, sensing_t *x, unsigned char *flag)
{
    size_t n = x->n_sec;
    for (size_t i = 0; i < n; i++) {
        const tl_bucket_t *b = &s->timeline[i];
        if (b->rtt_n > 0)
            x->rtt[i] = 1000.0 * b->rtt_sum / b->rtt_n;
        x->retrans[i] = b->retrans;
        x->pps[i] = b->pkts[0] + b->pkts[1];
    }

    /* opóźnienie: RTT > max(3 x mediana, mediana + 50 ms) */
    double med = percentile(x->rtt, n, 50);
    if (!isnan(med)) {
        x->rtt_thr = fmax(3 * med, med + 50);
        for (size_t i = 0; i < n; i++)
            flag[i] = !isnan(x->rtt[i]) && x->rtt[i] > x->rtt_thr;
        if (flags_to_events(x, flag, x->rtt, EV_DELAY, 2, 1,
                            "RTT do %.0f %s", "ms") != 0)
            return -1;
    }

    /* retransmisje: >= 3 na sekundę i >= 10% pakietów TCP */
    for (size_t i = 0; i < n; i++) {
        uint32_t r = s->timeline[i].retrans, tcp = s->timeline[i].pkts[0];
        flag[i] = r >= 3 && r * 10 >= tcp;
    }
    if (flags_to_events(x, flag, x->retrans, EV_RETRANS, 2, 1,
                        "do %.0f retransmisji%s", "/s") != 0)
        return -1;

    /* przerwa: >= 3 s ciszy, ale tylko gdy ruch zwykle jest ciągły */
    if (percentile(x->pps, n, 50) >= 2) {
        size_t i = 0;
        while (i < n) {
            if (x->pps[i] > 0) { i++; continue; }
            size_t j = i;
            while (j < n && x->pps[j] == 0) j++;
            if (j - i >= GAP_MIN && j < n) {
                char d[96];
                snprintf(d, sizeof d, "brak pakietów TCP/UDP przez %zu s", j - i);
                if (add_event(x, EV_GAP, (double)i, (double)j, (double)(j - i), d) != 0)
                    return -1;
            }
            i = j;
        }
    }
    return 0;
}

static int cmp_event(const void *a, const void *b)
{
    const event_t *x = a, *y = b;
    return (x->t0 > y->t0) - (x->t0 < y->t0);
}

int sensing_run(const stats_t *s, sensing_t *x)
{
    memset(x, 0, sizeof *x);
    x->ref_tx = -1;
    size_t n = x->n_sec = s->tl_len;
    if (n == 0)
        return 0;

    double **series[] = { &x->rssi, &x->motion, &x->noise, &x->retry,
                          &x->rtt, &x->retrans, &x->pps };
    for (size_t k = 0; k < sizeof series / sizeof series[0]; k++) {
        *series[k] = malloc(n * sizeof(double));
        if (*series[k] == NULL)
            return -1;
        for (size_t i = 0; i < n; i++)
            (*series[k])[i] = NAN;
    }
    unsigned char *flag = calloc(n, 1);
    if (flag == NULL)
        return -1;

    int rc = 0;
    if (detect_motion(s, x, flag) || detect_interference(s, x, flag) || detect_link(s, x, flag))
        rc = -1;
    free(flag);
    if (x->n_ev > 1)
        qsort(x->ev, x->n_ev, sizeof *x->ev, cmp_event);
    return rc;
}

void sensing_free(sensing_t *x)
{
    free(x->rssi);
    free(x->motion);
    free(x->noise);
    free(x->retry);
    free(x->rtt);
    free(x->retrans);
    free(x->pps);
    free(x->ev);
    memset(x, 0, sizeof *x);
}
