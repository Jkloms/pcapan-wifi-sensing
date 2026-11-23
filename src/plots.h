/*
 * plots.h - przygotowanie danych ze statystyk i rysowanie konkretnych
 * wykresów. Łączy moduł statystyk (stats) z generycznymi wykresami (charts).
 *
 * Każdy wykres to jedna funkcja typu plot_fn. Ta sama funkcja potrafi
 * zapisać PNG (cr == NULL) albo narysować wykres wektorowo w PDF (cr != NULL).
 */
#ifndef PCAPAN_PLOTS_H
#define PCAPAN_PLOTS_H

#include <cairo.h>
#include "stats.h"
#include "anomaly.h"

/* Wskaźnik na funkcję rysującą wykres. */
typedef int (*plot_fn)(const stats_t *s, const anomalies_t *a, cairo_t *cr, const char *path);

/* Opis jednego wykresu. */
typedef struct {
    const char *file;      /* nazwa pliku PNG, np. "01_ruch_pakiety.png" */
    const char *caption;   /* "Jak czytać" - podpis w raporcie */
    plot_fn     draw;      /* funkcja rysująca */
} plot_def_t;

/* Lista wszystkich wykresów (tablica zakończona elementem z file == NULL). */
extern const plot_def_t PLOTS[];

/* Wykres osi czasu z zaznaczonymi incydentami - używany też na 1. stronie raportu. */
int plot_timeline_packets(const stats_t *s, const anomalies_t *a, cairo_t *cr, const char *path);

/* Zapisuje wszystkie wykresy PNG do katalogu 'outdir'. Zwraca liczbę błędów. */
int plots_generate(const stats_t *s, const anomalies_t *a, const char *outdir, int *n_ok);

/*
 * Pomocnicza funkcja "top N": wybiera indeksy N największych wartości.
 * Wynik w idx[] posortowany malejąco. Zwraca liczbę wybranych (<= n_top).
 * Działa w czasie O(count * n_top) - dla małego N dużo szybciej niż
 * sortowanie całej tablicy. Używana też przez raport PDF (tabele).
 */
size_t top_n(const double *values, size_t count, size_t *idx, size_t n_top);

#endif
