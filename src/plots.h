/* plots.h - lista wykresów raportu; każdy rysuje się do PNG albo do PDF. */
#ifndef PCAPAN_PLOTS_H
#define PCAPAN_PLOTS_H

#include <cairo.h>
#include "stats.h"
#include "sensing.h"
#include "anomaly.h"

/* Wszystkie wyniki analizy w jednym miejscu. */
typedef struct {
    const stats_t     *s;
    const sensing_t   *x;
    const anomalies_t *a;
} analysis_t;

/* Wskaźnik na funkcję rysującą: cr == NULL -> plik PNG 'path'. */
typedef int (*plot_fn)(const analysis_t *an, cairo_t *cr, const char *path);

typedef struct {
    const char *file;
    const char *caption;   /* jedno zdanie "jak czytać" */
    plot_fn     draw;
} plot_def_t;

extern const plot_def_t PLOTS[];         /* zakończona elementem {NULL} */

enum { PLOT_RSSI, PLOT_MOTION, PLOT_RETRY, PLOT_NOISE, PLOT_PPS, PLOT_RTT,
       PLOT_RETRANS, PLOT_SERVICES, PLOT_HOSTS, PLOT_STATES };

int    plots_generate(const analysis_t *an, const char *outdir, int *n_ok);
size_t top_n(const double *values, size_t count, size_t *idx, size_t n_top);

#endif
