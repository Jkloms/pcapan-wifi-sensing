/*
 * plots.h - przygotowanie danych ze statystyk i wygenerowanie wszystkich
 * wykresów PNG. Łączy moduł statystyk (stats) z generycznymi wykresami (charts).
 */
#ifndef PCAPAN_PLOTS_H
#define PCAPAN_PLOTS_H

#include "stats.h"
#include "anomaly.h"

#define MAX_PLOTS 16

/* Opis jednego wygenerowanego wykresu - raport PDF wstawia je po kolei. */
typedef struct {
    char path[512];      /* pełna ścieżka do pliku PNG */
    char caption[256];   /* podpis pod wykresem w raporcie */
} plot_info_t;

typedef struct {
    plot_info_t items[MAX_PLOTS];
    int n;
} plot_list_t;

/* Generuje wykresy do katalogu 'outdir'. Zwraca liczbę błędów (0 = OK). */
int plots_generate(const stats_t *s, const anomalies_t *a, const char *outdir,
                   plot_list_t *out);

/*
 * Pomocnicza funkcja "top N": wybiera indeksy N największych wartości.
 * Wynik w idx[] posortowany malejąco. Zwraca liczbę wybranych (<= n_top).
 * Używana też przez raport PDF (tabele).
 */
size_t top_n(const double *values, size_t count, size_t *idx, size_t n_top);

#endif
