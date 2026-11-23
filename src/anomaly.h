/*
 * anomaly.h - wykrywanie potencjalnych nieprawidłowości w ruchu.
 *
 * Wszystkie detektory działają na gotowych statystykach (stats_t),
 * czyli PO wczytaniu całego pliku. Każdy wykryty problem trafia na listę
 * anomalii z poziomem ważności i opisem tekstowym.
 *
 * Wykrywane zjawiska:
 *   - skanowanie portów (jeden host próbuje wielu portów innego hosta),
 *   - skanowanie sieci (jeden host próbuje tego samego portu na wielu hostach),
 *   - SYN flood (wiele niedokończonych połączeń TCP do jednej usługi),
 *   - wysoki poziom retransmisji TCP (problemy z siecią),
 *   - duży odsetek połączeń zrywanych przez RST,
 *   - UDP flood (bardzo duża liczba pakietów UDP/s między parą hostów),
 *   - nietypowe flagi TCP (NULL / XMAS / SYN+FIN - typowe dla skanerów),
 *   - nagłe skoki natężenia ruchu (statystycznie odstające sekundy).
 */
#ifndef PCAPAN_ANOMALY_H
#define PCAPAN_ANOMALY_H

#include "stats.h"

/* Progi detekcji - można je zmieniać opcjami w linii poleceń. */
typedef struct {
    int    scan_min_ports;     /* min. liczba różnych portów -> skan portów */
    int    sweep_min_hosts;    /* min. liczba różnych hostów -> skan sieci */
    int    synflood_min;       /* min. liczba niedokończonych handshake -> SYN flood */
    double retrans_ratio;      /* próg odsetka retransmisji (0.03 = 3%) */
    double rst_ratio;          /* próg odsetka przepływów TCP zerwanych RST */
    double udpflood_pps;       /* próg pakietów UDP/s dla pary hostów */
    double spike_sigma;        /* ile odchyleń standardowych to "skok" ruchu */
} thresholds_t;

/* Wartości domyślne progów. */
void thresholds_default(thresholds_t *t);

typedef enum { SEV_INFO = 0, SEV_WARN = 1, SEV_CRIT = 2 } severity_t;

typedef struct {
    severity_t severity;
    char category[48];      /* np. "Skanowanie portów" */
    char text[400];         /* opis po polsku */
} anomaly_t;

/* Wynik "kto ile różnych celów (host:port) próbował" - do wykresu podejrzanych. */
typedef struct {
    ip_addr_t addr;
    uint32_t  targets;      /* liczba różnych (host, port) docelowych */
    uint32_t  failed;       /* w tym prób nieudanych (brak odpowiedzi / RST) */
} fanout_t;

typedef struct {
    anomaly_t *items;
    size_t     n, cap;
    fanout_t  *fanout;      /* posortowane malejąco wg 'targets' */
    size_t     n_fanout;
    size_t     spike_count; /* liczba sekund uznanych za skok ruchu */
} anomalies_t;

/* Uruchamia wszystkie detektory. Zwraca 0 albo -1 przy braku pamięci. */
int anomalies_detect(const stats_t *s, const thresholds_t *t, anomalies_t *out);

/* Nazwa poziomu ważności: "INFO", "OSTRZEŻENIE", "KRYTYCZNE". */
const char *severity_name(severity_t s);

void anomalies_free(anomalies_t *a);

#endif
