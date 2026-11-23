/*
 * export.h - eksport wyników do plików CSV (do Excela / LibreOffice / skryptów).
 *
 * Pliki używają średnika jako separatora (polski Excel domyślnie tak czyta)
 * i kodowania UTF-8. Tworzone pliki:
 *   incydenty.csv   - wykryte incydenty z rekomendacjami
 *   ioc.csv         - adresy IP powiązane z incydentami (np. do zablokowania)
 *   hosty.csv       - statystyki każdego adresu IP
 *   przeplywy.csv   - wszystkie przepływy (połączenia)
 */
#ifndef PCAPAN_EXPORT_H
#define PCAPAN_EXPORT_H

#include "stats.h"
#include "anomaly.h"

/* Zwraca liczbę zapisanych plików (4 = wszystko OK). */
int export_csv(const stats_t *s, const anomalies_t *a, const char *outdir);

#endif
