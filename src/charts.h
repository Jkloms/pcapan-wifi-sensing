/*
 * charts.h - rysowanie wykresów do plików PNG (biblioteka cairo).
 *
 * Moduł jest "generyczny": nie wie nic o sieciach ani pakietach.
 * Dostaje tylko etykiety i liczby. Dzięki temu łatwo go użyć ponownie.
 * Wszystkie funkcje zwracają 0 przy sukcesie i -1 przy błędzie.
 */
#ifndef PCAPAN_CHARTS_H
#define PCAPAN_CHARTS_H

#include <stddef.h>

/* Rozmiar obrazków w pikselach. */
#define CHART_W 1000
#define CHART_H 560

/* Poziomy wykres słupkowy - dobry do rankingów "top N" (długie etykiety). */
int chart_hbar(const char *path, const char *title, const char *subtitle,
               const char *const *labels, const double *values, size_t n,
               const char *unit);

/* Pionowy wykres słupkowy - dobry do histogramów i kategorii. */
int chart_vbar(const char *path, const char *title, const char *subtitle,
               const char *const *labels, const double *values, size_t n,
               const char *x_title, const char *y_title);

/*
 * Wykres liniowy (oś czasu) z kilkoma seriami.
 *   series[s][i] - wartość serii 's' w punkcie 'i',
 *   x_step       - ile sekund odpowiada jednemu punktowi.
 */
int chart_lines(const char *path, const char *title, const char *subtitle,
                const double *const *series, const char *const *names,
                size_t n_series, size_t n_points, double x_step,
                const char *y_title);

#endif
