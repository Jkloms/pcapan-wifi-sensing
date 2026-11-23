/* export.h - zapis wyników do plików CSV. */
#ifndef PCAPAN_EXPORT_H
#define PCAPAN_EXPORT_H

#include "plots.h"

/* zdarzenia.csv, sekundy.csv, ataki.csv, przeplywy.csv; zwraca liczbę zapisanych plików */
int export_csv(const analysis_t *an, const char *outdir);

#endif
