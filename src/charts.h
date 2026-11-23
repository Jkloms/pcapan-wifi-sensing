/*
 * charts.h - rysowanie wykresów (biblioteka cairo).
 *
 * Moduł jest "generyczny": nie wie nic o sieciach ani pakietach.
 * Dostaje tylko etykiety i liczby. Dzięki temu łatwo go użyć ponownie.
 *
 * Każda funkcja rysuje w jednym z dwóch trybów:
 *   - cr == NULL  -> tworzy obraz PNG i zapisuje go pod ścieżką 'path',
 *   - cr != NULL  -> rysuje WEKTOROWO w podanym kontekście cairo
 *                    (tak raport PDF wstawia ostre, skalowalne wykresy).
 * Wykres zawsze zajmuje obszar CHART_W x CHART_H jednostek; wywołujący
 * może go przeskalować (cairo_scale) do dowolnego rozmiaru.
 *
 * Wszystkie funkcje zwracają 0 przy sukcesie i -1 przy błędzie.
 */
#ifndef PCAPAN_CHARTS_H
#define PCAPAN_CHARTS_H

#include <stddef.h>
#include <cairo.h>

/* Rozmiar "płótna" wykresu (piksele w PNG). */
#define CHART_W 1000
#define CHART_H 560

/* Zaznaczony przedział czasu na wykresie liniowym (np. okno ataku). */
typedef struct {
    double x0, x1;        /* sekundy od początku osi X */
    int    critical;      /* 1 = czerwony (krytyczne), 0 = pomarańczowy */
    const char *label;    /* krótki podpis, np. "SYN flood" */
} chart_band_t;

/* Poziomy wykres słupkowy - dobry do rankingów "top N" (długie etykiety). */
int chart_hbar(cairo_t *cr, const char *path, const char *title, const char *subtitle,
               const char *const *labels, const double *values, size_t n,
               const char *unit);

/* Pionowy wykres słupkowy - dobry do histogramów i kategorii. */
int chart_vbar(cairo_t *cr, const char *path, const char *title, const char *subtitle,
               const char *const *labels, const double *values, size_t n,
               const char *x_title, const char *y_title);

/*
 * Wykres liniowy (oś czasu) z kilkoma seriami.
 *   series[s][i] - wartość serii 's' w punkcie 'i',
 *   x_step       - ile sekund odpowiada jednemu punktowi,
 *   bands        - opcjonalne zaznaczone przedziały (może być NULL).
 */
int chart_lines(cairo_t *cr, const char *path, const char *title, const char *subtitle,
                const double *const *series, const char *const *names,
                size_t n_series, size_t n_points, double x_step,
                const char *y_title, const chart_band_t *bands, size_t n_bands);

#endif
