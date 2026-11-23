/*
 * report.h - generowanie raportu PDF (cairo, powierzchnia PDF).
 */
#ifndef PCAPAN_REPORT_H
#define PCAPAN_REPORT_H

#include "stats.h"
#include "anomaly.h"
#include "plots.h"

/* Wszystko, czego raport potrzebuje - zebrane w jednej strukturze,
 * żeby funkcja nie miała dziesięciu parametrów. */
typedef struct {
    const char         *input_path;   /* analizowany plik .pcap */
    const char         *linktype;     /* typ łącza, np. "EN10MB" */
    const char         *output_pdf;   /* ścieżka wynikowego PDF */
    const stats_t      *stats;
    const anomalies_t  *anomalies;
    const thresholds_t *thresholds;
    const plot_list_t  *plots;
} report_input_t;

/* Tworzy plik PDF. Zwraca 0 przy sukcesie, -1 przy błędzie. */
int report_write(const report_input_t *in);

#endif
