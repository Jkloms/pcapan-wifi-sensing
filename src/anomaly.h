/* anomaly.h - wykrywanie typowych ataków sieciowych (dodatek do głównej analizy). */
#ifndef PCAPAN_ANOMALY_H
#define PCAPAN_ANOMALY_H

#include "stats.h"

/* Progi detekcji - można je zmieniać opcjami w linii poleceń. */
typedef struct {
    int    scan_min_ports;     /* min. liczba różnych portów -> skan portów */
    int    sweep_min_hosts;    /* min. liczba różnych hostów -> skan sieci */
    int    synflood_min;       /* min. liczba niedokończonych handshake -> SYN flood */
    double rst_ratio;          /* próg odsetka przepływów TCP zerwanych RST */
    double udpflood_pps;       /* próg pakietów UDP/s dla jednego hosta */
} thresholds_t;

/* Wartości domyślne progów. */
void thresholds_default(thresholds_t *t);

typedef enum { SEV_INFO = 0, SEV_WARN = 1, SEV_CRIT = 2 } severity_t;

/* Jeden incydent. */
typedef struct {
    severity_t  severity;
    char        category[48];   /* np. "Skanowanie portów TCP" */
    char        text[400];      /* opis po polsku z liczbami (dowody) */
    char        source[96];     /* kto: np. "10.0.0.66" albo "4000 adresów (sfałszowane)" */
    char        target[64];     /* kogo: np. "10.0.0.5:80" */
    double      t_start, t_end; /* okno czasowe (sekundy od 1970); 0 = całe nagranie */
    const char *advice;         /* rekomendacja - stały napis */

    /* Adresy do listy IOC ("wskaźników kompromitacji"): */
    ip_addr_t   src_ip, dst_ip;
    int         has_src_ip, has_dst_ip;
} anomaly_t;

/* Wynik "kto ile różnych celów (host:port) próbował" - do wykresu podejrzanych. */
typedef struct {
    ip_addr_t addr;
    uint32_t  targets;      /* liczba różnych (host, port) docelowych */
    uint32_t  failed;       /* w tym prób nieudanych (brak odpowiedzi / RST) */
} fanout_t;

typedef struct {
    anomaly_t *items;       /* posortowane od najpoważniejszych */
    size_t     n, cap;
    fanout_t  *fanout;      /* posortowane malejąco wg 'targets' */
    size_t     n_fanout;
} anomalies_t;

/* Uruchamia wszystkie detektory. Zwraca 0 albo -1 przy braku pamięci. */
int anomalies_detect(const stats_t *s, const thresholds_t *t, anomalies_t *out);

/* Nazwa poziomu ważności: "INFO", "OSTRZEŻENIE", "KRYTYCZNE". */
const char *severity_name(severity_t s);

void anomalies_free(anomalies_t *a);

#endif
