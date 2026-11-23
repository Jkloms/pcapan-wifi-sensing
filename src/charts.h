/* charts.h - proste wykresy: słupkowe i liniowe (z zaznaczonymi okresami). */
#ifndef PCAPAN_CHARTS_H
#define PCAPAN_CHARTS_H

#include <stddef.h>
#include <cairo.h>

#define CHART_W 1000
#define CHART_H 560

/* Funkcje przyjmują 'cr': NULL = zapis do pliku PNG 'path',
 * inaczej rysowanie w podanym kontekście (np. strona PDF). */

enum { BAND_MOTION, BAND_WARN, BAND_CRIT };

typedef struct {
    double x0, x1;          /* sekundy od początku osi X */
    int    kind;            /* BAND_* - kolor pasa */
    const char *label;
} chart_band_t;

typedef struct {
    const char *title, *subtitle, *y_title;
    const double *const *series;   /* n_series tablic po n_points; NAN = brak danych */
    const char *const *names;
    size_t n_series, n_points;
    double x_step;                 /* sekundy na punkt */
    const chart_band_t *bands;
    size_t n_bands;
    int    y_from_data;            /* 1 = oś Y od minimum danych (np. dBm), 0 = od zera */
    double threshold;              /* NAN = bez linii progu */
    const char *threshold_label;
} line_chart_t;

int chart_hbar(cairo_t *cr, const char *path, const char *title, const char *subtitle,
               const char *const *labels, const double *values, size_t n, const char *unit);

int chart_vbar(cairo_t *cr, const char *path, const char *title, const char *subtitle,
               const char *const *labels, const double *values, size_t n,
               const char *x_title, const char *y_title);

int chart_lines(cairo_t *cr, const char *path, const line_chart_t *c);

#endif
