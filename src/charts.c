/*
 * charts.c - implementacja wykresów (cairo).
 *
 * Cairo to biblioteka grafiki wektorowej 2D. Schemat pracy:
 *   1. tworzymy "powierzchnię" (surface) - tu obraz PNG w pamięci,
 *   2. tworzymy "kontekst" (cairo_t) - nim rysujemy: ustawiamy kolor,
 *      budujemy ścieżkę (linie, prostokąty), a potem ją wypełniamy (fill)
 *      lub obrysowujemy (stroke),
 *   3. zapisujemy powierzchnię do pliku i zwalniamy obiekty.
 *
 * Układ współrzędnych: (0,0) to lewy górny róg, y rośnie W DÓŁ.
 */
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <cairo.h>
#include "charts.h"

/* ---- Kolory (R, G, B w zakresie 0..1) ---- */
typedef struct { double r, g, b; } rgb_t;

/* Zamiana koloru zapisanego jak w CSS (0xRRGGBB) na rgb_t. */
static rgb_t hex(unsigned v)
{
    rgb_t c = { ((v >> 16) & 0xFF) / 255.0, ((v >> 8) & 0xFF) / 255.0, (v & 0xFF) / 255.0 };
    return c;
}

#define COL_SURFACE   0xFCFCFB   /* tło */
#define COL_TEXT      0x0B0B0B   /* tekst główny */
#define COL_TEXT2     0x52514E   /* tekst pomocniczy (osie, podpisy) */
#define COL_GRID      0xE4E3DF   /* linie siatki */
#define COL_CRIT      0xC62828   /* kolor statusu: krytyczne */
#define COL_WARN      0xD97706   /* kolor statusu: ostrzeżenie */
static const unsigned SERIES_COLORS[] = { 0x2A78D6, 0xEB6834, 0x1BAF7A, 0xEDA100 };

static void set_color(cairo_t *cr, unsigned v)
{
    rgb_t c = hex(v);
    cairo_set_source_rgb(cr, c.r, c.g, c.b);
}

#define FONT "DejaVu Sans"

static void set_font(cairo_t *cr, double size, int bold)
{
    cairo_select_font_face(cr, FONT, CAIRO_FONT_SLANT_NORMAL,
                           bold ? CAIRO_FONT_WEIGHT_BOLD : CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, size);
}

/* Sposób wyrównania tekstu względem punktu (x, y). */
enum { AL_LEFT, AL_CENTER, AL_RIGHT };

/* Rysuje tekst; y to linia bazowa (dolna krawędź liter bez "ogonków"). */
static void draw_text(cairo_t *cr, double x, double y, const char *s, int align)
{
    cairo_text_extents_t ext;
    cairo_text_extents(cr, s, &ext);
    if (align == AL_CENTER)     x -= ext.x_advance / 2;
    else if (align == AL_RIGHT) x -= ext.x_advance;
    cairo_move_to(cr, x, y);
    cairo_show_text(cr, s);
}

/* Formatuje liczbę krótko: 1234 -> "1.2k", 5300000 -> "5.3M". */
static void fmt_num(double v, char *out, size_t len)
{
    double a = fabs(v);
    if (a >= 1e9)       snprintf(out, len, "%.1fG", v / 1e9);
    else if (a >= 1e6)  snprintf(out, len, "%.1fM", v / 1e6);
    else if (a >= 1e4)  snprintf(out, len, "%.0fk", v / 1e3);
    else if (a >= 1e3)  snprintf(out, len, "%.1fk", v / 1e3);
    else if (a == floor(a)) snprintf(out, len, "%.0f", v);
    else                snprintf(out, len, "%.2f", v);
}

/*
 * "Ładny" krok osi: wybiera 1, 2 lub 5 razy potęga dziesięciu,
 * tak by na osi było ok. 'ticks' kresek (np. 0, 20, 40, 60...).
 */
static double nice_step(double max, int ticks)
{
    if (max <= 0)
        return 1;
    double raw = max / ticks;
    double mag = pow(10, floor(log10(raw)));
    double f = raw / mag;
    double nice = (f <= 1) ? 1 : (f <= 2) ? 2 : (f <= 5) ? 5 : 10;
    return nice * mag;
}

/*
 * Przygotowuje rysowanie: tło, tytuł, podtytuł.
 * Jeśli 'target' == NULL, tworzy nowy obraz PNG w pamięci (*surf).
 * W przeciwnym razie rysuje w podanym kontekście (np. strona PDF);
 * cairo_save/cairo_restore chronią ustawienia wywołującego.
 */
static cairo_t *begin_chart(cairo_t *target, cairo_surface_t **surf,
                            const char *title, const char *subtitle)
{
    cairo_t *cr;
    if (target == NULL) {
        *surf = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, CHART_W, CHART_H);
        cr = cairo_create(*surf);
    } else {
        *surf = NULL;
        cr = target;
        cairo_save(cr);
        cairo_rectangle(cr, 0, 0, CHART_W, CHART_H);
        cairo_clip(cr);                      /* nie wychodzimy poza obszar wykresu */
    }
    set_color(cr, COL_SURFACE);
    cairo_paint(cr);                         /* wypełnia całe tło */

    set_color(cr, COL_TEXT);
    set_font(cr, 26, 1);
    draw_text(cr, 32, 46, title, AL_LEFT);
    if (subtitle && *subtitle) {
        set_color(cr, COL_TEXT2);
        set_font(cr, 16, 0);
        draw_text(cr, 32, 72, subtitle, AL_LEFT);
    }
    return cr;
}

/* Kończy rysowanie: zapisuje PNG albo przywraca stan kontekstu PDF. */
static int end_chart(cairo_surface_t *surf, cairo_t *cr, const char *path)
{
    if (surf == NULL) {                      /* tryb wektorowy (PDF) */
        cairo_restore(cr);
        return 0;
    }
    cairo_destroy(cr);
    cairo_status_t st = cairo_surface_write_to_png(surf, path);
    cairo_surface_destroy(surf);
    if (st != CAIRO_STATUS_SUCCESS) {
        fprintf(stderr, "Błąd zapisu %s: %s\n", path, cairo_status_to_string(st));
        return -1;
    }
    return 0;
}

/*
 * Prostokąt z zaokrąglonym tylko jednym końcem (końcem "danych" słupka).
 * horizontal=1: zaokrąglony prawy koniec; 0: zaokrąglony górny koniec.
 */
static void bar_path(cairo_t *cr, double x, double y, double w, double h, int horizontal)
{
    double r = 4;
    if (horizontal) { if (r > w) r = w; if (r > h / 2) r = h / 2; }
    else            { if (r > h) r = h; if (r > w / 2) r = w / 2; }
    if (r <= 0.5) {
        cairo_rectangle(cr, x, y, w, h);
        return;
    }
    cairo_new_sub_path(cr);
    if (horizontal) {
        cairo_move_to(cr, x, y);
        cairo_line_to(cr, x + w - r, y);
        cairo_arc(cr, x + w - r, y + r, r, -M_PI / 2, 0);
        cairo_line_to(cr, x + w, y + h - r);
        cairo_arc(cr, x + w - r, y + h - r, r, 0, M_PI / 2);
        cairo_line_to(cr, x, y + h);
    } else {
        cairo_move_to(cr, x, y + h);
        cairo_line_to(cr, x, y + r);
        cairo_arc(cr, x + r, y + r, r, M_PI, 1.5 * M_PI);
        cairo_line_to(cr, x + w - r, y);
        cairo_arc(cr, x + w - r, y + r, r, 1.5 * M_PI, 2 * M_PI);
        cairo_line_to(cr, x + w, y + h);
    }
    cairo_close_path(cr);
}

/* Komunikat zamiast pustego wykresu. */
static int empty_chart(cairo_surface_t *surf, cairo_t *cr, const char *path)
{
    set_color(cr, COL_TEXT2);
    set_font(cr, 18, 0);
    draw_text(cr, CHART_W / 2.0, CHART_H / 2.0, "Brak danych do pokazania", AL_CENTER);
    return end_chart(surf, cr, path);
}

/* ------------------------------------------------------------------ */

int chart_hbar(cairo_t *target, const char *path, const char *title, const char *subtitle,
               const char *const *labels, const double *values, size_t n,
               const char *unit)
{
    cairo_surface_t *surf;
    cairo_t *cr = begin_chart(target, &surf, title, subtitle);
    if (n == 0)
        return empty_chart(surf, cr, path);

    double max = 0;
    for (size_t i = 0; i < n; i++)
        if (values[i] > max) max = values[i];

    /* Obszar rysowania: miejsce na etykiety po lewej i wartości po prawej. */
    double left = 300, right = CHART_W - 150, top = 96, bottom = CHART_H - 30;
    double row = (bottom - top) / n;
    double bar_h = row * 0.62;
    if (bar_h > 34) bar_h = 34;

    /* Linia bazowa (oś) */
    set_color(cr, COL_GRID);
    cairo_set_line_width(cr, 1);
    cairo_move_to(cr, left + 0.5, top);
    cairo_line_to(cr, left + 0.5, bottom);
    cairo_stroke(cr);

    for (size_t i = 0; i < n; i++) {
        double cy = top + row * i + row / 2;
        double w = (max > 0) ? (right - left) * values[i] / max : 0;

        set_color(cr, SERIES_COLORS[0]);
        bar_path(cr, left + 1, cy - bar_h / 2, w, bar_h, 1);
        cairo_fill(cr);

        /* etykieta po lewej (przycięta, jeśli za długa) */
        char lab[48];
        snprintf(lab, sizeof lab, "%s", labels[i]);
        set_color(cr, COL_TEXT);
        set_font(cr, 16, 0);
        draw_text(cr, left - 12, cy + 5, lab, AL_RIGHT);

        /* wartość za słupkiem */
        char num[32], txt[64];
        fmt_num(values[i], num, sizeof num);
        /* krótkie jednostki (np. "B") doklejamy bez spacji: "1.2MB" */
        int space = unit && strlen(unit) > 2;
        snprintf(txt, sizeof txt, "%s%s%s", num, space ? " " : "", unit ? unit : "");
        set_color(cr, COL_TEXT2);
        set_font(cr, 15, 0);
        draw_text(cr, left + w + 10, cy + 5, txt, AL_LEFT);
    }
    return end_chart(surf, cr, path);
}

/* ------------------------------------------------------------------ */

/* Rysuje poziome linie siatki i opisy osi Y; zwraca maksimum osi. */
static double draw_y_axis(cairo_t *cr, double max, double left, double right,
                          double top, double bottom)
{
    double step = nice_step(max, 5);
    double axis_max = ceil(max / step) * step;
    if (axis_max <= 0)
        axis_max = 1;

    set_font(cr, 14, 0);
    cairo_set_line_width(cr, 1);
    for (double v = 0; v <= axis_max + step / 2; v += step) {
        double y = bottom - (bottom - top) * v / axis_max;
        set_color(cr, COL_GRID);
        cairo_move_to(cr, left, floor(y) + 0.5);   /* +0.5 = ostra linia 1 px */
        cairo_line_to(cr, right, floor(y) + 0.5);
        cairo_stroke(cr);
        char num[32];
        fmt_num(v, num, sizeof num);
        set_color(cr, COL_TEXT2);
        draw_text(cr, left - 8, y + 4, num, AL_RIGHT);
    }
    return axis_max;
}

/* Pionowy podpis osi Y (obrócony o -90 stopni). */
static void draw_y_title(cairo_t *cr, const char *s, double top, double bottom)
{
    if (!s) return;
    cairo_save(cr);                          /* zapamiętaj stan (np. obrót) */
    set_color(cr, COL_TEXT2);
    set_font(cr, 15, 0);
    cairo_translate(cr, 22, (top + bottom) / 2);
    cairo_rotate(cr, -M_PI / 2);
    draw_text(cr, 0, 0, s, AL_CENTER);
    cairo_restore(cr);                       /* przywróć stan */
}

int chart_vbar(cairo_t *target, const char *path, const char *title, const char *subtitle,
               const char *const *labels, const double *values, size_t n,
               const char *x_title, const char *y_title)
{
    cairo_surface_t *surf;
    cairo_t *cr = begin_chart(target, &surf, title, subtitle);
    if (n == 0)
        return empty_chart(surf, cr, path);

    double max = 0;
    for (size_t i = 0; i < n; i++)
        if (values[i] > max) max = values[i];

    double left = 90, right = CHART_W - 30, top = 100, bottom = CHART_H - 70;
    double axis_max = draw_y_axis(cr, max, left, right, top, bottom);
    draw_y_title(cr, y_title, top, bottom);

    double slot = (right - left) / n;
    double gap = slot * 0.25;
    if (gap < 2) gap = 2;                    /* min. 2 px odstępu między słupkami */

    for (size_t i = 0; i < n; i++) {
        double h = (bottom - top) * values[i] / axis_max;
        double x = left + slot * i + gap / 2;
        set_color(cr, SERIES_COLORS[0]);
        bar_path(cr, x, bottom - h, slot - gap, h, 0);
        cairo_fill(cr);

        /* wartość nad słupkiem */
        char num[32];
        fmt_num(values[i], num, sizeof num);
        set_color(cr, COL_TEXT2);
        set_font(cr, 14, 0);
        draw_text(cr, x + (slot - gap) / 2, bottom - h - 6, num, AL_CENTER);

        set_color(cr, COL_TEXT);
        set_font(cr, 15, 0);
        draw_text(cr, x + (slot - gap) / 2, bottom + 20, labels[i], AL_CENTER);
    }
    if (x_title) {
        set_color(cr, COL_TEXT2);
        set_font(cr, 15, 0);
        draw_text(cr, (left + right) / 2, CHART_H - 18, x_title, AL_CENTER);
    }
    return end_chart(surf, cr, path);
}

/* ------------------------------------------------------------------ */

/* Czas w sekundach -> tekst osi X: "45s", "12:30" (mm:ss) albo "1:05h". */
static void fmt_time(double sec, double total, char *out, size_t len)
{
    long s = (long)(sec + 0.5);
    if (total < 120)
        snprintf(out, len, "%lds", s);
    else if (total < 2 * 3600)
        snprintf(out, len, "%ld:%02ld", s / 60, s % 60);
    else
        snprintf(out, len, "%ld:%02ldh", s / 3600, (s / 60) % 60);
}

int chart_lines(cairo_t *target, const char *path, const char *title, const char *subtitle,
                const double *const *series, const char *const *names,
                size_t n_series, size_t n_points, double x_step,
                const char *y_title, const chart_band_t *bands, size_t n_bands)
{
    cairo_surface_t *surf;
    cairo_t *cr = begin_chart(target, &surf, title, subtitle);
    if (n_points == 0 || n_series == 0)
        return empty_chart(surf, cr, path);

    double max = 0;
    for (size_t s = 0; s < n_series; s++)
        for (size_t i = 0; i < n_points; i++)
            if (series[s][i] > max) max = series[s][i];

    double left = 90, right = CHART_W - 30, top = 110, bottom = CHART_H - 60;
    double axis_max = draw_y_axis(cr, max, left, right, top, bottom);
    draw_y_title(cr, y_title, top, bottom);

    /* Oś X: czas od początku nagrania */
    double total = x_step * n_points;
    double tstep = nice_step(total, 8);
    set_font(cr, 14, 0);
    set_color(cr, COL_TEXT2);
    for (double t = 0; t <= total + 1e-9; t += tstep) {
        double x = left + (right - left) * t / total;
        char lab[32];
        fmt_time(t, total, lab, sizeof lab);
        draw_text(cr, x, bottom + 20, lab, AL_CENTER);
    }
    draw_text(cr, (left + right) / 2, CHART_H - 14, "czas od początku nagrania", AL_CENTER);

    /* Legenda w jednym wierszu nad wykresem */
    double lx = left;
    set_font(cr, 15, 0);
    for (size_t s = 0; s < n_series; s++) {
        set_color(cr, SERIES_COLORS[s % 4]);
        cairo_set_line_width(cr, 3);
        cairo_move_to(cr, lx, 90);
        cairo_line_to(cr, lx + 22, 90);
        cairo_stroke(cr);
        set_color(cr, COL_TEXT);
        cairo_text_extents_t ext;
        cairo_text_extents(cr, names[s], &ext);
        draw_text(cr, lx + 30, 95, names[s], AL_LEFT);
        lx += 30 + ext.x_advance + 28;
    }

    /* Zaznaczone przedziały (okna incydentów): półprzezroczyste pasy.
     * Kolor ze stałą alfa (przezroczystością) - linie danych zostają widoczne. */
    double last_label_x = -1000;
    for (size_t b = 0; b < n_bands; b++) {
        double x0 = left + (right - left) * bands[b].x0 / total;
        double x1 = left + (right - left) * bands[b].x1 / total;
        if (x1 - x0 < 4) { double c = (x0 + x1) / 2; x0 = c - 2; x1 = c + 2; }  /* min. 4 px */
        if (x0 < left) x0 = left;
        if (x1 > right) x1 = right;
        rgb_t c = hex(bands[b].critical ? COL_CRIT : COL_WARN);
        cairo_set_source_rgba(cr, c.r, c.g, c.b, 0.13);
        cairo_rectangle(cr, x0, top - 6, x1 - x0, bottom - top + 6);
        cairo_fill(cr);
        cairo_set_source_rgba(cr, c.r, c.g, c.b, 0.9);
        cairo_rectangle(cr, x0, top - 6, x1 - x0, 3);
        cairo_fill(cr);
        /* podpis tylko, gdy nie nachodzi na poprzedni (pasy mogą się pokrywać) */
        if (bands[b].label && fabs(x0 - last_label_x) > 18) {
            last_label_x = x0;
            /* podpis pionowo wzdłuż lewej krawędzi pasa */
            cairo_save(cr);
            set_font(cr, 13, 1);
            cairo_translate(cr, x0 + 4, top + 4);
            cairo_rotate(cr, M_PI / 2);
            draw_text(cr, 0, 0, bands[b].label, AL_LEFT);
            cairo_restore(cr);
        }
    }

    /* Linie serii: punkt i leży na środku swojego przedziału czasu */
    cairo_set_line_width(cr, 2);
    cairo_set_line_join(cr, CAIRO_LINE_JOIN_ROUND);
    for (size_t s = 0; s < n_series; s++) {
        set_color(cr, SERIES_COLORS[s % 4]);
        for (size_t i = 0; i < n_points; i++) {
            double x = left + (right - left) * ((i + 0.5) / n_points);
            double y = bottom - (bottom - top) * series[s][i] / axis_max;
            if (i == 0) cairo_move_to(cr, x, y);
            else        cairo_line_to(cr, x, y);
        }
        cairo_stroke(cr);
    }
    return end_chart(surf, cr, path);
}
