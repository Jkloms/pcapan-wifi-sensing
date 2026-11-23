/*
 * anomaly.h - wykrywanie potencjalnych nieprawidłowości ("incydentów").
 *
 * Wszystkie detektory działają na gotowych statystykach (stats_t),
 * czyli PO wczytaniu całego pliku. Każdy wykryty problem trafia na listę
 * jako incydent: poziom ważności, opis, źródło, cel, okno czasowe
 * i rekomendacja "co zrobić".
 *
 * Wykrywane zjawiska:
 *   - skanowanie portów TCP/UDP (jeden host próbuje wielu portów innego hosta),
 *   - skanowanie sieci (jeden host próbuje tego samego portu na wielu hostach),
 *   - SYN flood (wiele niedokończonych połączeń TCP do jednej usługi),
 *   - wysoki poziom retransmisji TCP (problemy z siecią),
 *   - duży odsetek połączeń zrywanych przez RST,
 *   - UDP flood (bardzo duża liczba pakietów UDP/s do jednego hosta),
 *   - nietypowe flagi TCP (NULL / XMAS / SYN+FIN - typowe dla skanerów),
 *   - nagłe skoki natężenia ruchu (statystycznie odstające sekundy).
 *
 * Na końcu liczony jest łączny WYNIK RYZYKA 0-100.
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
    double udpflood_pps;       /* próg pakietów UDP/s dla jednego hosta */
    double spike_sigma;        /* ile odchyleń standardowych to "skok" ruchu */
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
    size_t     spike_count; /* liczba sekund uznanych za skok ruchu */
    int        risk_score;  /* 0-100 */
} anomalies_t;

/* Uruchamia wszystkie detektory. Zwraca 0 albo -1 przy braku pamięci. */
int anomalies_detect(const stats_t *s, const thresholds_t *t, anomalies_t *out);

/* Nazwa poziomu ważności: "INFO", "OSTRZEŻENIE", "KRYTYCZNE". */
const char *severity_name(severity_t s);

/* Poziom ryzyka dla wyniku 0-100: 0 = niskie ... 3 = krytyczne. */
int risk_level(int score);
const char *risk_level_name(int level);

/* Wpis listy IOC (Indicator of Compromise) - adres IP powiązany z incydentami. */
typedef struct {
    ip_addr_t  ip;
    int        attacker;     /* liczba incydentów, w których był źródłem */
    int        victim;       /* liczba incydentów, w których był celem */
    severity_t max_sev;      /* najpoważniejszy incydent z jego udziałem */
} ioc_t;

/*
 * Buduje listę IOC z incydentów (bez duplikatów, najpierw atakujący i najgroźniejsi).
 * *out trzeba zwolnić free(). Zwraca liczbę wpisów albo -1 przy braku pamięci.
 */
long anomalies_ioc(const anomalies_t *a, ioc_t **out);

void anomalies_free(anomalies_t *a);

#endif
