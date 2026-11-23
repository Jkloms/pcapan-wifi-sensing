/*
 * sensing.h - wykrywanie ruchu człowieka i zakłóceń (WiFi sensing).
 *
 * Pomysł: gdy ktoś się porusza między nadajnikiem a odbiornikiem, sygnał
 * odbija się inaczej i RSSI (siła sygnału) zaczyna "skakać". Liczymy więc
 * odchylenie standardowe RSSI w oknie 3 s i porównujemy z progiem.
 */
#ifndef PCAPAN_SENSING_H
#define PCAPAN_SENSING_H

#include "stats.h"

typedef enum {
    EV_MOTION,        /* podejrzenie ruchu */
    EV_INTERFERENCE,  /* zakłócenia radiowe (szum, powtórzenia ramek) */
    EV_DELAY,         /* wzrost opóźnienia (RTT) */
    EV_RETRANS,       /* seria retransmisji TCP */
    EV_GAP,           /* przerwa w ruchu */
    EV_COUNT
} event_type_t;

typedef struct {
    event_type_t type;
    double t0, t1;          /* sekundy od początku nagrania */
    double peak;            /* największa wartość w okresie */
    char   detail[96];
} event_t;

/* Serie sekundowe (NAN = brak danych w tej sekundzie) i wykryte zdarzenia. */
typedef struct {
    size_t  n_sec;
    int     ref_tx;         /* indeks nadajnika odniesienia w stats->tx, -1 = brak Wi-Fi */
    double *rssi;           /* średnie RSSI [dBm] */
    double *motion;         /* wskaźnik ruchu: odchylenie std RSSI w oknie 3 s [dB] */
    double  motion_thr;
    double *noise;          /* szum [dBm] */
    double *retry;          /* ramki powtórzone [%] */
    double *rtt;            /* RTT [ms] */
    double  rtt_thr;
    double *retrans;        /* retransmisje TCP na sekundę */
    double *pps;            /* pakiety TCP+UDP na sekundę */

    event_t *ev;
    size_t   n_ev, cap_ev;
    double   motion_sec;    /* łączny czas podejrzenia ruchu */
} sensing_t;

int  sensing_run(const stats_t *s, sensing_t *out);   /* 0 = OK, -1 = brak pamięci */
void sensing_free(sensing_t *x);
const char *event_name(event_type_t t);
int  sensing_count(const sensing_t *x, event_type_t t);

#endif
