/* report.h - krótki raport PDF: wykresy najpierw, mało tekstu. */
#ifndef PCAPAN_REPORT_H
#define PCAPAN_REPORT_H

#include "plots.h"

typedef struct {
    const char *input_path;
    const char *linktype;
    const char *output_pdf;
    analysis_t  an;
} report_input_t;

int report_write(const report_input_t *in);   /* 0 = OK */

#endif
