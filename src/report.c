/*
 * report.c - składanie raportu PDF.
 *
 * Cairo potrafi rysować nie tylko do PNG, ale też do PDF - używamy tych
 * samych funkcji rysujących (tekst, prostokąty, łuki), a cairo zapisuje
 * je jako strony PDF. Jednostką są punkty typograficzne (1 pt = 1/72 cala).
 * Strona A4 ma 595 x 842 pt.
 *
 * Układ raportu (myśl: "najpierw decyzja, potem szczegóły"):
 *   str. 1  Podsumowanie dla decydenta: wynik ryzyka 0-100, werdykt,
 *           kluczowe liczby, oś czasu z zaznaczonymi atakami, top incydenty
 *   str. 2  Plan działania (co zrobić, w kolejności) + lista IP (IOC)
 *   dalej   Karty incydentów: źródło, cel, czas, dowody, rekomendacja
 *           Charakterystyka ruchu: wykresy WEKTOROWE z opisem "jak czytać"
 *           Szczegóły: tabele hostów, usług, przepływów
 *           Metodologia i słowniczek pojęć
 *
 * Ciekawostki techniczne:
 *   - raport renderujemy DWA RAZY: pierwszy przebieg (do "nikąd") liczy
 *     strony, drugi zapisuje plik - dzięki temu stopka może mieć "Strona 3 z 9",
 *   - zakładki PDF (panel boczny w przeglądarce) i klikalne odnośniki
 *     z listy incydentów do ich kart (cairo_pdf_surface_add_outline, cairo_tag_*),
 *   - wykresy są rysowane bezpośrednio w PDF (wektorowo), więc są ostre
 *     przy każdym powiększeniu, a plik jest mniejszy.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <cairo.h>
#include <cairo-pdf.h>
#include "report.h"
#include "charts.h"

/* ---- wymiary strony ---- */
#define PAGE_W   595.28
#define PAGE_H   841.89
#define MARGIN_X 48.0
#define MARGIN_T 52.0
#define MARGIN_B 58.0
#define CONTENT_W (PAGE_W - 2 * MARGIN_X)

#define FONT "DejaVu Sans"

/* ---- kolory ---- */
#define COL_NAVY   0x0E2A47
#define COL_TEXT   0x0B0B0B
#define COL_TEXT2  0x52514E
#define COL_MUTED  0x8A8984
#define COL_RULE   0xE4E3DF
#define COL_PANEL  0xF4F3F0
#define COL_ZEBRA  0xF7F6F3
#define COL_ACCENT 0x2A78D6
#define COL_ADVICE 0xEAF2FC
/* kolory statusu (zawsze razem z napisem - nigdy sam kolor) */
#define COL_CRIT   0xC62828
#define COL_WARN   0xB45309
#define COL_INFO   0x2A78D6
#define COL_OK     0x1B7F3B

typedef struct {
    cairo_surface_t *surf;
    cairo_t *cr;
    double y;          /* bieżąca pozycja pionowa (pt od góry strony) */
    int page;          /* numer bieżącej strony */
    int total_pages;   /* znane w drugim przebiegu (0 w pierwszym) */
    int real;          /* 1 = przebieg zapisujący plik */
    const char *file_label;   /* nazwa pliku do stopki */
} pdf_t;

/* ------------------------------------------------------------------ */
/* Podstawowe operacje                                                 */
/* ------------------------------------------------------------------ */

static void color(pdf_t *p, unsigned v)
{
    cairo_set_source_rgb(p->cr, ((v >> 16) & 0xFF) / 255.0,
                         ((v >> 8) & 0xFF) / 255.0, (v & 0xFF) / 255.0);
}

static void color_a(pdf_t *p, unsigned v, double alpha)
{
    cairo_set_source_rgba(p->cr, ((v >> 16) & 0xFF) / 255.0,
                          ((v >> 8) & 0xFF) / 255.0, (v & 0xFF) / 255.0, alpha);
}

static void font(pdf_t *p, double size, int bold)
{
    cairo_select_font_face(p->cr, FONT, CAIRO_FONT_SLANT_NORMAL,
                           bold ? CAIRO_FONT_WEIGHT_BOLD : CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(p->cr, size);
}

static double text_w(pdf_t *p, const char *s)
{
    cairo_text_extents_t e;
    cairo_text_extents(p->cr, s, &e);
    return e.x_advance;
}

static void text_at(pdf_t *p, double x, double y, const char *s)
{
    cairo_move_to(p->cr, x, y);
    cairo_show_text(p->cr, s);
}

static void text_right(pdf_t *p, double x_right, double y, const char *s)
{
    text_at(p, x_right - text_w(p, s), y, s);
}

/* Prostokąt z zaokrąglonymi rogami (promień r). */
static void round_rect(pdf_t *p, double x, double y, double w, double h, double r)
{
    cairo_t *cr = p->cr;
    cairo_new_sub_path(cr);
    cairo_arc(cr, x + w - r, y + r, r, -M_PI / 2, 0);
    cairo_arc(cr, x + w - r, y + h - r, r, 0, M_PI / 2);
    cairo_arc(cr, x + r, y + h - r, r, M_PI / 2, M_PI);
    cairo_arc(cr, x + r, y + r, r, M_PI, 1.5 * M_PI);
    cairo_close_path(cr);
}

static unsigned sev_color(severity_t s)
{
    return s == SEV_CRIT ? COL_CRIT : s == SEV_WARN ? COL_WARN : COL_INFO;
}

static unsigned risk_color(int level)
{
    static const unsigned c[] = { COL_OK, COL_WARN, 0xD9480F, COL_CRIT };
    return c[level];
}

/* "Plakietka" z poziomem ważności; zwraca jej szerokość. */
static double chip(pdf_t *p, double x, double y, const char *label, unsigned col, double size)
{
    font(p, size, 1);
    double w = text_w(p, label) + size * 1.4;
    double h = size * 1.75;
    color(p, col);
    round_rect(p, x, y, w, h, h / 2);
    cairo_fill(p->cr);
    cairo_set_source_rgb(p->cr, 1, 1, 1);
    text_at(p, x + size * 0.7, y + h * 0.7, label);
    return w;
}

/* Stopka: nazwa pliku, numer strony "N z M". */
static void footer(pdf_t *p)
{
    char buf[64];
    color(p, COL_RULE);
    cairo_rectangle(p->cr, MARGIN_X, PAGE_H - 40, CONTENT_W, 0.6);
    cairo_fill(p->cr);
    color(p, COL_MUTED);
    font(p, 7.5, 0);
    char left[300];
    snprintf(left, sizeof left, "pcapan  ·  raport bezpieczeństwa sieci  ·  %s", p->file_label);
    text_at(p, MARGIN_X, PAGE_H - 28, left);
    if (p->total_pages > 0)
        snprintf(buf, sizeof buf, "Strona %d z %d", p->page, p->total_pages);
    else
        snprintf(buf, sizeof buf, "Strona %d", p->page);
    text_right(p, PAGE_W - MARGIN_X, PAGE_H - 28, buf);
}

static void new_page(pdf_t *p)
{
    footer(p);
    cairo_show_page(p->cr);    /* kończy stronę; kolejne rysowanie trafi na nową */
    p->page++;
    p->y = MARGIN_T;
}

/* Upewnia się, że zostało co najmniej 'h' punktów miejsca; inaczej nowa strona. */
static void ensure(pdf_t *p, double h)
{
    if (p->y + h > PAGE_H - MARGIN_B)
        new_page(p);
}

/*
 * Akapit z automatycznym zawijaniem wierszy.
 * Algorytm: dokładamy kolejne słowa do bieżącej linii, dopóki mieści się
 * w szerokości 'width'. Gdy nie - kończymy linię i zaczynamy następną.
 * Gdy draw == 0, nic nie rysujemy, tylko zwracamy wysokość akapitu
 * (przydaje się, żeby sprawdzić, czy cała "karta" zmieści się na stronie).
 * Akapit rysowany jest od pozycji y (górna krawędź), bez łamania strony.
 */
static double paragraph_box(pdf_t *p, double x, double y, double width, const char *text,
                            double size, int bold, unsigned col, int draw)
{
    font(p, size, bold);
    color(p, col);
    double lh = size * 1.42;          /* wysokość linii */
    double h = 0;

    char line[1024] = "";
    const char *s = text;
    while (*s) {
        /* wytnij kolejne słowo (do spacji) */
        const char *e = strchr(s, ' ');
        size_t wl = e ? (size_t)(e - s) : strlen(s);
        char word[512];
        if (wl >= sizeof word) wl = sizeof word - 1;
        memcpy(word, s, wl);
        word[wl] = '\0';

        char cand[sizeof line + sizeof word + 2];   /* zawsze się zmieści */
        snprintf(cand, sizeof cand, "%s%s%s", line, *line ? " " : "", word);
        if (*line && text_w(p, cand) > width) {
            if (draw) text_at(p, x, y + h + size, line);
            h += lh;
            snprintf(line, sizeof line, "%s", word);
        } else if (strlen(cand) < sizeof line) {
            memcpy(line, cand, strlen(cand) + 1);
        }
        s = e ? e + 1 : s + wl;
    }
    if (*line) {
        if (draw) text_at(p, x, y + h + size, line);
        h += lh;
    }
    return h;
}

/* Akapit w bieżącym miejscu strony (z łamaniem strony, jeśli trzeba). */
static void paragraph(pdf_t *p, const char *text, double size, unsigned col)
{
    double h = paragraph_box(p, MARGIN_X, p->y, CONTENT_W, text, size, 0, col, 0);
    ensure(p, h);
    paragraph_box(p, MARGIN_X, p->y, CONTENT_W, text, size, 0, col, 1);
    p->y += h + 5;
}

/* Wpis w zakładkach PDF (panel boczny przeglądarki). Zwraca id wpisu. */
static int outline(pdf_t *p, int parent, const char *title)
{
    if (!p->real)
        return 0;
    char attrs[96];
    snprintf(attrs, sizeof attrs, "page=%d pos=[0 %.0f]", p->page, p->y);
    return cairo_pdf_surface_add_outline(p->surf, parent, title, attrs, 0);
}

/* Nagłówek sekcji: numer w kolorowym kwadracie + tytuł + zakładka PDF. */
static int heading(pdf_t *p, const char *num, const char *text)
{
    ensure(p, 90);                     /* nie zostawiaj nagłówka samotnie na dole strony */
    if (p->y > MARGIN_T) p->y += 8;
    char title[128];
    snprintf(title, sizeof title, "%s. %s", num, text);
    int id = outline(p, CAIRO_PDF_OUTLINE_ROOT, title);

    color(p, COL_NAVY);
    round_rect(p, MARGIN_X, p->y, 22, 22, 4);
    cairo_fill(p->cr);
    cairo_set_source_rgb(p->cr, 1, 1, 1);
    font(p, 11, 1);
    text_at(p, MARGIN_X + 11 - text_w(p, num) / 2, p->y + 15.5, num);
    color(p, COL_TEXT);
    font(p, 16, 1);
    text_at(p, MARGIN_X + 32, p->y + 16.5, text);
    p->y += 34;
    return id;
}

static void subheading(pdf_t *p, int parent, const char *text)
{
    ensure(p, 60);
    p->y += 4;
    outline(p, parent, text);
    font(p, 11.5, 1);
    color(p, COL_TEXT);
    text_at(p, MARGIN_X, p->y + 12, text);
    p->y += 20;
}

/* Skraca tekst, aby zmieścił się w szerokości 'w' (dodaje "..."). */
static void fit_text(pdf_t *p, const char *in, double w, char *out, size_t len)
{
    snprintf(out, len, "%s", in);
    if (text_w(p, out) <= w)
        return;
    size_t n = strlen(out);
    while (n > 0) {
        n--;
        /* nie tniemy w środku znaku UTF-8 (bajty kontynuacji to 10xxxxxx) */
        while (n > 0 && ((unsigned char)out[n] & 0xC0) == 0x80)
            n--;
        out[n] = '\0';
        char tmp[512];
        snprintf(tmp, sizeof tmp, "%s...", out);
        if (text_w(p, tmp) <= w) {
            snprintf(out, len, "%s", tmp);
            return;
        }
    }
}

/*
 * Tabela. cells to tablica napisów wierszami: cells[wiersz * ncols + kolumna].
 * right[k] = 1 -> kolumna k wyrównana do prawej (liczby).
 * row_color (może być NULL): kolor tekstu pierwszej kolumny dla każdego wiersza.
 */
static void table(pdf_t *p, int ncols, const char *const *headers, const double *widths,
                  const int *right, const char *const *cells, size_t nrows,
                  const unsigned *row_color)
{
    const double rh = 15.5;           /* wysokość wiersza */
    int need_header = 1;

    for (size_t r = 0; r <= nrows; r++) {
        if (r < nrows && p->y + rh * (need_header ? 2 : 1) > PAGE_H - MARGIN_B) {
            new_page(p);
            need_header = 1;          /* powtórz nagłówek na nowej stronie */
        }
        if (need_header) {
            double x = MARGIN_X;
            font(p, 7.5, 1);
            color(p, COL_TEXT2);
            for (int c = 0; c < ncols; c++) {
                if (right[c]) text_right(p, x + widths[c] - 4, p->y + 10, headers[c]);
                else          text_at(p, x + 4, p->y + 10, headers[c]);
                x += widths[c];
            }
            p->y += rh;
            color(p, COL_TEXT);
            cairo_rectangle(p->cr, MARGIN_X, p->y - 2, CONTENT_W, 0.8);
            cairo_fill(p->cr);
            need_header = 0;
        }
        if (r == nrows)
            break;

        if (r % 2 == 1) {             /* "zebra" - co drugi wiersz z tłem */
            color(p, COL_ZEBRA);
            cairo_rectangle(p->cr, MARGIN_X, p->y - 1, CONTENT_W, rh);
            cairo_fill(p->cr);
        }
        double x = MARGIN_X;
        for (int c = 0; c < ncols; c++) {
            char buf[512];
            font(p, 8, c == 0 && row_color);
            color(p, (c == 0 && row_color) ? row_color[r] : COL_TEXT);
            fit_text(p, cells[r * ncols + c], widths[c] - 8, buf, sizeof buf);
            if (right[c]) text_right(p, x + widths[c] - 4, p->y + 10.5, buf);
            else          text_at(p, x + 4, p->y + 10.5, buf);
            x += widths[c];
        }
        p->y += rh;
    }
    p->y += 10;
}

/* Wykres narysowany WEKTOROWO: przeskalowany obszar CHART_W x CHART_H. */
static void vector_chart(pdf_t *p, plot_fn draw, const report_input_t *in, double width)
{
    double scale = width / CHART_W;
    double h = CHART_H * scale;
    cairo_save(p->cr);
    cairo_translate(p->cr, MARGIN_X, p->y);
    cairo_scale(p->cr, scale, scale);
    draw(in->stats, in->anomalies, p->cr, NULL);
    cairo_restore(p->cr);
    color(p, COL_RULE);
    cairo_set_line_width(p->cr, 0.6);
    cairo_rectangle(p->cr, MARGIN_X, p->y, width, h);
    cairo_stroke(p->cr);
    p->y += h;
}

/* ------------------------------------------------------------------ */
/* Formatowanie liczb i czasu                                          */
/* ------------------------------------------------------------------ */

static void fmt_bytes(double b, char *out, size_t len)
{
    const char *units[] = { "B", "KB", "MB", "GB", "TB" };
    int u = 0;
    while (b >= 1024 && u < 4) { b /= 1024; u++; }
    if (u == 0) snprintf(out, len, "%.0f B", b);
    else if (b >= 100) snprintf(out, len, "%.0f %s", b, units[u]);
    else        snprintf(out, len, "%.1f %s", b, units[u]);
}

/* Krótki zapis dużych liczb do kafelków: 1911891 -> "1,91 mln". */
static void fmt_compact(unsigned long long v, char *out, size_t len);

/* Liczba z odstępami co 3 cyfry: 1234567 -> "1 234 567" (polski zapis). */
static void fmt_int(unsigned long long v, char *out, size_t len)
{
    char raw[32];
    snprintf(raw, sizeof raw, "%llu", v);
    size_t n = strlen(raw), o = 0;
    for (size_t i = 0; i < n && o + 2 < len; i++) {
        if (i > 0 && (n - i) % 3 == 0)
            out[o++] = ' ';
        out[o++] = raw[i];
    }
    out[o] = '\0';
}

static void fmt_compact(unsigned long long v, char *out, size_t len)
{
    if (v >= 1000000ULL)
        snprintf(out, len, "%.2f mln", v / 1e6);
    else if (v >= 100000ULL)
        snprintf(out, len, "%.0f tys.", v / 1e3);
    else
        fmt_int(v, out, len);
    /* polski zapis ułamków: przecinek zamiast kropki */
    for (char *c = out; *c; c++)
        if (*c == '.' && c[1] != '\0') *c = ',';
}

static void fmt_clock(double ts, char *out, size_t len)
{
    time_t t = (time_t)ts;
    struct tm tm;
    localtime_r(&t, &tm);              /* wersja "_r" jest bezpieczna wątkowo */
    strftime(out, len, "%H:%M:%S", &tm);
}

static void fmt_datetime(double ts, char *out, size_t len)
{
    time_t t = (time_t)ts;
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(out, len, "%Y-%m-%d %H:%M:%S", &tm);
}

static void fmt_duration(double sec, char *out, size_t len)
{
    if (sec < 10) snprintf(out, len, "%.1f s", sec);
    else if (sec < 60) snprintf(out, len, "%.0f s", sec);
    else if (sec < 3600) snprintf(out, len, "%d min %d s", (int)sec / 60, (int)sec % 60);
    else snprintf(out, len, "%d h %d min", (int)sec / 3600, ((int)sec / 60) % 60);
}

/* Okno czasowe incydentu: "14:00:20 - 14:00:24 (4.1 s)" albo "całe nagranie". */
static void fmt_window(const anomaly_t *a, char *out, size_t len)
{
    if (a->t_start <= 0) {
        snprintf(out, len, "całe nagranie");
        return;
    }
    char c1[16], c2[16], d[32];
    fmt_clock(a->t_start, c1, sizeof c1);
    fmt_clock(a->t_end, c2, sizeof c2);
    fmt_duration(a->t_end - a->t_start, d, sizeof d);
    snprintf(out, len, "%s - %s (%s)", c1, c2, d);
}

static double pct(uint64_t part, uint64_t total)
{
    return total ? 100.0 * (double)part / (double)total : 0.0;
}

/* Liczniki incydentów wg ważności. */
static void count_sev(const anomalies_t *a, size_t cnt[3])
{
    cnt[0] = cnt[1] = cnt[2] = 0;
    for (size_t i = 0; i < a->n; i++)
        cnt[a->items[i].severity]++;
}

/* ------------------------------------------------------------------ */
/* Strona 1: podsumowanie dla decydenta                                */
/* ------------------------------------------------------------------ */

/* Wskaźnik w kształcie łuku (jak prędkościomierz) z wynikiem 0-100. */
static void risk_gauge(pdf_t *p, double cx, double cy, double r, int score)
{
    int level = risk_level(score);
    const double a0 = 0.75 * M_PI, sweep = 1.5 * M_PI;   /* łuk 270 stopni */
    cairo_new_path(p->cr);
    cairo_set_line_cap(p->cr, CAIRO_LINE_CAP_ROUND);
    cairo_set_line_width(p->cr, 11);
    color(p, COL_RULE);
    cairo_arc(p->cr, cx, cy, r, a0, a0 + sweep);
    cairo_stroke(p->cr);
    if (score > 0) {
        color(p, risk_color(level));
        cairo_arc(p->cr, cx, cy, r, a0, a0 + sweep * score / 100.0);
        cairo_stroke(p->cr);
    }
    cairo_set_line_cap(p->cr, CAIRO_LINE_CAP_BUTT);

    char num[8];
    snprintf(num, sizeof num, "%d", score);
    font(p, 30, 1);
    color(p, COL_TEXT);
    text_at(p, cx - text_w(p, num) / 2, cy + 8, num);
    font(p, 8, 0);
    color(p, COL_TEXT2);
    text_at(p, cx - text_w(p, "/ 100") / 2, cy + 22, "/ 100");
}

static void kpi_tile(pdf_t *p, double x, double y, double w, const char *label, const char *value)
{
    color(p, COL_PANEL);
    round_rect(p, x, y, w, 46, 5);
    cairo_fill(p->cr);
    font(p, 7, 1);
    color(p, COL_TEXT2);
    text_at(p, x + 8, y + 14, label);
    font(p, 13, 1);
    color(p, COL_TEXT);
    char buf[64];
    fit_text(p, value, w - 14, buf, sizeof buf);
    text_at(p, x + 8, y + 35, buf);
}

static const char *VERDICTS[4] = {
    "Nie wykryto istotnych zagrożeń",
    "Wykryto podejrzane zdarzenia - zalecana weryfikacja",
    "Wykryto poważne nieprawidłowości - zalecana reakcja",
    "Wykryto aktywne ataki - wymagana natychmiastowa reakcja",
};

static void page_summary(pdf_t *p, const report_input_t *in)
{
    const stats_t *s = in->stats;
    const anomalies_t *a = in->anomalies;
    int level = risk_level(a->risk_score);
    char buf[700], b1[96], b2[64], b3[64];

    /* --- pasek nagłówka --- */
    color(p, COL_NAVY);
    cairo_rectangle(p->cr, 0, 0, PAGE_W, 124);
    cairo_fill(p->cr);
    color(p, risk_color(level));
    cairo_rectangle(p->cr, 0, 124, PAGE_W, 4);
    cairo_fill(p->cr);

    p->y = 0;
    outline(p, CAIRO_PDF_OUTLINE_ROOT, "Podsumowanie");
    font(p, 8, 1);
    color_a(p, 0xFFFFFF, 0.6);
    text_at(p, MARGIN_X, 38, "RAPORT BEZPIECZEŃSTWA SIECI  ·  PCAPAN");
    font(p, 23, 1);
    cairo_set_source_rgb(p->cr, 1, 1, 1);
    text_at(p, MARGIN_X, 68, "Analiza ruchu TCP i UDP");
    fmt_datetime(s->first_ts, b1, sizeof b1);
    fmt_clock(s->last_ts, b2, sizeof b2);
    fmt_duration(stats_duration(s), b3, sizeof b3);
    char now[32];
    time_t t = time(NULL);
    strftime(now, sizeof now, "%Y-%m-%d %H:%M", localtime(&t));
    snprintf(buf, sizeof buf, "Plik: %s", in->input_path);
    font(p, 8.5, 0);
    color_a(p, 0xFFFFFF, 0.8);
    char fitted[300];
    fit_text(p, buf, CONTENT_W, fitted, sizeof fitted);
    text_at(p, MARGIN_X, 90, fitted);
    snprintf(buf, sizeof buf, "Nagranie: %s - %s (%s)   ·   Wygenerowano: %s", b1, b2, b3, now);
    text_at(p, MARGIN_X, 104, buf);

    /* --- panel ryzyka --- */
    double py = 144, ph = 128;
    color(p, COL_PANEL);
    round_rect(p, MARGIN_X, py, CONTENT_W, ph, 8);
    cairo_fill(p->cr);
    risk_gauge(p, MARGIN_X + 72, py + 60, 42, a->risk_score);
    snprintf(b1, sizeof b1, "RYZYKO: %s", risk_level_name(level));
    font(p, 7.5, 1);
    double cw = text_w(p, b1) + 10.5;
    chip(p, MARGIN_X + 72 - cw / 2, py + 104, b1, risk_color(level), 7.5);

    double tx = MARGIN_X + 152, tw = CONTENT_W - 166;
    double h = paragraph_box(p, tx, py + 14, tw, VERDICTS[level], 13.5, 1, risk_color(level), 1);

    size_t cnt[3];
    count_sev(a, cnt);
    fmt_int(s->total_pkts, b1, sizeof b1);
    fmt_duration(stats_duration(s), b2, sizeof b2);
    int n_written = snprintf(buf, sizeof buf,
        "W nagraniu trwającym %s przeanalizowano %s pakietów wymienionych przez %zu "
        "adresów IP. Wykryto incydenty: krytyczne %zu, ostrzeżenia %zu.",
        b2, b1, s->n_hosts, cnt[SEV_CRIT], cnt[SEV_WARN]);
    if (n_written > 0 && (size_t)n_written < sizeof buf) {
        if (a->n > 0 && a->items[0].severity > SEV_INFO)
            snprintf(buf + n_written, sizeof buf - (size_t)n_written,
                     " Najpoważniejszy: %s (źródło: %s, cel: %s).",
                     a->items[0].category, a->items[0].source, a->items[0].target);
        else
            snprintf(buf + n_written, sizeof buf - (size_t)n_written,
                     " Ruch wygląda na typowy dla zdrowej sieci.");
    }
    paragraph_box(p, tx, py + 18 + h, tw, buf, 9, 0, COL_TEXT, 1);
    p->y = py + ph + 12;

    /* --- kafelki KPI --- */
    uint64_t established = 0;
    for (size_t i = 0; i < s->n_flows; i++)
        if (s->flows[i]->proto == PROTO_TCP && (s->flows[i]->handshake & HS_ACK))
            established++;
    char k[6][64];
    fmt_compact(s->total_pkts, k[0], 64);
    fmt_bytes((double)s->total_bytes, k[1], 64);
    fmt_compact(s->n_hosts, k[2], 64);
    fmt_compact(s->n_flows, k[3], 64);
    snprintf(k[4], 64, "%.0f%%", pct(established, s->tcp_flows));
    snprintf(k[5], 64, "%.2f%%", pct(s->tcp_retrans, s->tcp_pkts));
    const char *labels[6] = { "PAKIETY", "DANE", "ADRESY IP", "PRZEPŁYWY",
                              "UDANE POŁ. TCP", "RETRANSMISJE" };
    double gap = 6, w = (CONTENT_W - 5 * gap) / 6;
    for (int i = 0; i < 6; i++)
        kpi_tile(p, MARGIN_X + i * (w + gap), p->y, w, labels[i], k[i]);
    p->y += 58;

    /* --- oś czasu z incydentami (wektorowo) --- */
    vector_chart(p, plot_timeline_packets, in, CONTENT_W);
    p->y += 12;

    /* --- najważniejsze incydenty (klikalne) --- */
    font(p, 11.5, 1);
    color(p, COL_TEXT);
    text_at(p, MARGIN_X, p->y + 11, "Najważniejsze incydenty");
    font(p, 7.5, 0);
    color(p, COL_MUTED);
    text_right(p, PAGE_W - MARGIN_X, p->y + 11, "kliknij wiersz, aby przejść do karty incydentu");
    p->y += 18;
    int shown = 0;
    for (size_t i = 0; i < a->n && shown < 5; i++) {
        const anomaly_t *an = &a->items[i];
        if (an->severity == SEV_INFO)
            continue;
        if (p->y + 17 > PAGE_H - MARGIN_B)
            break;
        char link[48];
        snprintf(link, sizeof link, "dest='inc%zu'", i + 1);
        cairo_tag_begin(p->cr, CAIRO_TAG_LINK, link);
        chip(p, MARGIN_X, p->y + 2, severity_name(an->severity), sev_color(an->severity), 6.5);
        font(p, 9, 1);
        color(p, COL_TEXT);
        text_at(p, MARGIN_X + 74, p->y + 11, an->category);
        /* najpierw czas (z prawej), żeby wiedzieć, ile miejsca zostaje na adresy */
        if (an->t_start > 0) {
            char c1[16], d[32];
            fmt_clock(an->t_start, c1, sizeof c1);
            fmt_duration(an->t_end - an->t_start, d, sizeof d);
            snprintf(b1, sizeof b1, "%s (%s)", c1, d);
        } else {
            snprintf(b1, sizeof b1, "całe nagranie");
        }
        font(p, 8.5, 0);
        double time_w = text_w(p, b1);
        if (strcmp(an->target, "-") == 0) snprintf(buf, sizeof buf, "%s", an->source);
        else if (strcmp(an->source, "-") == 0) snprintf(buf, sizeof buf, "%s", an->target);
        else snprintf(buf, sizeof buf, "%s  ->  %s", an->source, an->target);
        font(p, 8.5, 0);
        color(p, COL_TEXT2);
        char fb[200];
        fit_text(p, buf, CONTENT_W - 212 - time_w - 10, fb, sizeof fb);
        text_at(p, MARGIN_X + 212, p->y + 11, fb);
        text_right(p, PAGE_W - MARGIN_X, p->y + 11, b1);
        cairo_tag_end(p->cr, CAIRO_TAG_LINK);
        color(p, COL_RULE);
        cairo_rectangle(p->cr, MARGIN_X, p->y + 16, CONTENT_W, 0.5);
        cairo_fill(p->cr);
        p->y += 18;
        shown++;
    }
    if (shown == 0)
        paragraph(p, "Brak incydentów wymagających uwagi.", 9, COL_TEXT2);
}

/* ------------------------------------------------------------------ */
/* Plan działania i lista IOC                                          */
/* ------------------------------------------------------------------ */

/* Statystyki hosta o danym adresie (wyszukiwanie liniowe - wywoływane rzadko). */
static const host_t *find_host(const stats_t *s, const ip_addr_t *ip)
{
    for (size_t i = 0; i < s->n_hosts; i++)
        if (addr_cmp(&s->hosts[i]->addr, ip) == 0)
            return s->hosts[i];
    return NULL;
}

static void section_plan(pdf_t *p, const report_input_t *in)
{
    const anomalies_t *a = in->anomalies;
    new_page(p);
    int sec = heading(p, "1", "Plan działania");
    paragraph(p, "Kroki uporządkowane od najpilniejszych. Każdy punkt odpowiada jednemu "
                 "incydentowi - kliknij jego nazwę, aby zobaczyć dowody.", 9, COL_TEXT2);
    p->y += 2;

    int step = 0;
    for (size_t i = 0; i < a->n; i++) {
        const anomaly_t *an = &a->items[i];
        if (an->severity == SEV_INFO)
            continue;
        step++;
        double tx = MARGIN_X + 30, tw = CONTENT_W - 30;
        double h = 16 + paragraph_box(p, tx, 0, tw, an->advice, 9, 0, COL_TEXT, 0);
        ensure(p, h + 8);

        /* numer kroku w kółku */
        cairo_new_path(p->cr);
        color(p, sev_color(an->severity));
        cairo_arc(p->cr, MARGIN_X + 10, p->y + 8, 10, 0, 2 * M_PI);
        cairo_fill(p->cr);
        char num[16];
        snprintf(num, sizeof num, "%d", step);
        font(p, 9.5, 1);
        cairo_set_source_rgb(p->cr, 1, 1, 1);
        text_at(p, MARGIN_X + 10 - text_w(p, num) / 2, p->y + 11.5, num);

        char link[48], title[200];
        snprintf(link, sizeof link, "dest='inc%zu'", i + 1);
        /* tytuł: kategoria + cel (albo źródło, jeśli celu brak) */
        const char *who = strcmp(an->target, "-") != 0 && an->target[0] ? an->target :
                          strcmp(an->source, "-") != 0 && an->source[0] ? an->source : NULL;
        if (who) snprintf(title, sizeof title, "%s  ·  %s", an->category, who);
        else     snprintf(title, sizeof title, "%s", an->category);
        cairo_tag_begin(p->cr, CAIRO_TAG_LINK, link);
        font(p, 10, 1);
        color(p, COL_TEXT);
        text_at(p, tx, p->y + 11.5, title);
        cairo_tag_end(p->cr, CAIRO_TAG_LINK);
        paragraph_box(p, tx, p->y + 15, tw, an->advice, 9, 0, COL_TEXT, 1);
        p->y += h + 8;
    }
    if (step == 0)
        paragraph(p, "Nie są potrzebne żadne działania. Zalecamy okresowe powtarzanie analizy.",
                  10, COL_OK);

    /* --- lista IOC --- */
    ioc_t *ioc = NULL;
    long n = anomalies_ioc(a, &ioc);
    if (n <= 0) {
        free(ioc);
        return;
    }
    p->y += 6;
    subheading(p, sec, "Adresy IP powiązane z incydentami (IOC)");
    paragraph(p, "IOC (Indicator of Compromise) to ślady ataku, które można wprowadzić do "
                 "zapory lub systemu SIEM. Źródła ataków są kandydatami do zablokowania, cele "
                 "- do sprawdzenia. Lista w formie CSV: plik ioc.csv.", 8.5, COL_TEXT2);
    size_t rows = n > 25 ? 25 : (size_t)n;
    static char c[25][6][64];
    const char *cells[25 * 6];
    unsigned rc[25];
    for (size_t i = 0; i < rows; i++) {
        addr_to_str(&ioc[i].ip, c[i][0]);
        snprintf(c[i][1], 64, "%s", ioc[i].attacker && ioc[i].victim ? "źródło i cel" :
                                    ioc[i].attacker ? "ŹRÓDŁO ATAKU" : "cel ataku");
        snprintf(c[i][2], 64, "%d", ioc[i].attacker + ioc[i].victim);
        snprintf(c[i][3], 64, "%s", severity_name(ioc[i].max_sev));
        const host_t *h = find_host(in->stats, &ioc[i].ip);
        fmt_int(h ? h->pkts_out : 0, c[i][4], 64);
        fmt_int(h ? h->pkts_in : 0, c[i][5], 64);
        for (int k = 0; k < 6; k++)
            cells[i * 6 + k] = c[i][k];
        rc[i] = sev_color(ioc[i].max_sev);
    }
    const char *hdr[] = { "ADRES IP", "ROLA", "INCYDENTY", "NAJWYŻSZA WAGA", "WYSŁANE PAK.", "ODEBRANE PAK." };
    const double w[] = { 115, 95, 60, 95, 65, CONTENT_W - 430 };
    const int right[] = { 0, 0, 1, 0, 1, 1 };
    table(p, 6, hdr, w, right, cells, rows, rc);
    free(ioc);
}

/* ------------------------------------------------------------------ */
/* Karty incydentów                                                    */
/* ------------------------------------------------------------------ */

static void incident_card(pdf_t *p, const anomaly_t *an, size_t idx, int parent)
{
    const double pad = 12, x = MARGIN_X, w = CONTENT_W, iw = w - 2 * pad - 6;
    char buf[128];
    /* wysokość karty liczymy z góry, żeby nie przecinać jej między stronami */
    double h_text = paragraph_box(p, 0, 0, iw, an->text, 9, 0, COL_TEXT, 0);
    double h_adv = paragraph_box(p, 0, 0, iw - 16, an->advice, 8.5, 0, COL_TEXT, 0);
    double h = 66 + h_text + 8 + 22 + h_adv + pad;
    ensure(p, h + 10);

    double y = p->y;
    unsigned col = sev_color(an->severity);

    /* cel dla klikalnych odnośników z podsumowania i planu */
    char dest[80];
    snprintf(dest, sizeof dest, "name='inc%zu' x=0 y=%.0f", idx + 1, y > 10 ? y - 10 : 0);
    cairo_tag_begin(p->cr, CAIRO_TAG_DEST, dest);
    cairo_tag_end(p->cr, CAIRO_TAG_DEST);
    char otitle[96];
    snprintf(otitle, sizeof otitle, "#%zu %s", idx + 1, an->category);
    outline(p, parent, otitle);

    /* tło karty i kolorowy pasek po lewej */
    cairo_new_path(p->cr);
    color(p, 0xFFFFFF);
    round_rect(p, x, y, w, h, 6);
    cairo_fill_preserve(p->cr);
    color(p, COL_RULE);
    cairo_set_line_width(p->cr, 0.8);
    cairo_stroke(p->cr);
    color(p, col);
    cairo_rectangle(p->cr, x, y + 6, 4, h - 12);
    cairo_fill(p->cr);

    /* nagłówek karty */
    double cx = x + pad + 6;
    snprintf(buf, sizeof buf, "#%zu", idx + 1);
    font(p, 9, 1);
    color(p, COL_MUTED);
    text_at(p, cx, y + 20, buf);
    double cw = chip(p, cx + 24, y + 10, severity_name(an->severity), col, 7);
    font(p, 12, 1);
    color(p, COL_TEXT);
    text_at(p, cx + 32 + cw, y + 20, an->category);

    /* trzy kolumny: źródło / cel / czas */
    double gy = y + 32, colw = iw / 3;
    const char *lab[3] = { "ŹRÓDŁO", "CEL", "CZAS" };
    char when[96];
    fmt_window(an, when, sizeof when);
    const char *val[3] = { an->source[0] ? an->source : "-", an->target[0] ? an->target : "-", when };
    for (int i = 0; i < 3; i++) {
        font(p, 6.5, 1);
        color(p, COL_MUTED);
        text_at(p, cx + i * colw, gy + 7, lab[i]);
        font(p, 9, 1);
        color(p, COL_TEXT);
        char fb[96];
        fit_text(p, val[i], colw - 8, fb, sizeof fb);
        text_at(p, cx + i * colw, gy + 20, fb);
    }

    /* opis (dowody) */
    double ty = gy + 34;
    paragraph_box(p, cx, ty, iw, an->text, 9, 0, COL_TEXT, 1);
    ty += h_text + 8;

    /* ramka z rekomendacją */
    color(p, COL_ADVICE);
    round_rect(p, cx, ty, iw, 20 + h_adv, 4);
    cairo_fill(p->cr);
    font(p, 6.5, 1);
    color(p, COL_ACCENT);
    text_at(p, cx + 8, ty + 11, "REKOMENDACJA");
    paragraph_box(p, cx + 8, ty + 14, iw - 16, an->advice, 8.5, 0, COL_TEXT, 1);

    p->y = y + h + 10;
}

static void section_incidents(pdf_t *p, const report_input_t *in)
{
    const anomalies_t *a = in->anomalies;
    new_page(p);
    int sec = heading(p, "2", "Karty incydentów");
    if (a->n == 0) {
        paragraph(p, "Przy bieżących progach detekcji nie wykryto żadnych incydentów.", 10, COL_OK);
        return;
    }
    paragraph(p, "Każda karta to jeden wykryty problem: kto (źródło), kogo dotyczył (cel), "
                 "kiedy, jakie są dowody i co z tym zrobić. Godziny są podane w czasie "
                 "lokalnym komputera, na którym wygenerowano raport.", 9, COL_TEXT2);
    p->y += 4;
    for (size_t i = 0; i < a->n; i++)
        incident_card(p, &a->items[i], i, sec);
}

/* ------------------------------------------------------------------ */
/* Wykresy                                                             */
/* ------------------------------------------------------------------ */

static void section_charts(pdf_t *p, const report_input_t *in)
{
    new_page(p);
    heading(p, "3", "Charakterystyka ruchu");
    double cw = CONTENT_W, ch = CHART_H * cw / CHART_W;
    /* pierwszy wykres (oś czasu) jest już na stronie 1 - tu pokazujemy pozostałe */
    for (const plot_def_t *pd = PLOTS + 1; pd->file != NULL; pd++) {
        double cap = paragraph_box(p, 0, 0, cw, pd->caption, 8.5, 0, COL_TEXT2, 0);
        ensure(p, ch + cap + 22);
        vector_chart(p, pd->draw, in, cw);
        p->y += 5;
        paragraph_box(p, MARGIN_X, p->y, cw, pd->caption, 8.5, 0, COL_TEXT2, 1);
        p->y += cap + 14;
    }
}

/* ------------------------------------------------------------------ */
/* Tabele szczegółowe                                                  */
/* ------------------------------------------------------------------ */

static void section_details(pdf_t *p, const report_input_t *in)
{
    const stats_t *s = in->stats;
    new_page(p);
    int sec = heading(p, "4", "Szczegóły ruchu");

    /* --- 4.1 Podsumowanie liczbowe --- */
    subheading(p, sec, "4.1. Statystyki ogólne");
    {
        uint64_t rtt_n = 0;
        double rtt_sum = 0;
        for (size_t i = 0; i < s->n_flows; i++)
            if (s->flows[i]->rtt >= 0) { rtt_sum += s->flows[i]->rtt; rtt_n++; }
        uint64_t l4 = s->tcp_pkts + s->udp_pkts;
        double dur = stats_duration(s);
        char v[12][96], t1[32], t2[32];
        int k = 0;
        snprintf(v[k++], 96, "%s", in->linktype);
        fmt_int(s->tcp_pkts, t1, sizeof t1);
        snprintf(v[k++], 96, "%s (%.1f%%)", t1, pct(s->tcp_pkts, s->total_pkts));
        fmt_int(s->udp_pkts, t1, sizeof t1);
        snprintf(v[k++], 96, "%s (%.1f%%)", t1, pct(s->udp_pkts, s->total_pkts));
        snprintf(v[k++], 96, "%llu / %llu", (unsigned long long)s->other_pkts,
                 (unsigned long long)s->bad_pkts);
        snprintf(v[k++], 96, "%llu / %llu", (unsigned long long)s->ipv4_pkts,
                 (unsigned long long)s->ipv6_pkts);
        fmt_bytes((double)s->tcp_bytes, t1, sizeof t1);
        fmt_bytes((double)s->udp_bytes, t2, sizeof t2);
        snprintf(v[k++], 96, "TCP %s, UDP %s", t1, t2);
        fmt_bytes((double)s->payload_bytes, v[k++], 96);
        snprintf(v[k++], 96, "%.1f B", l4 ? (double)(s->tcp_bytes + s->udp_bytes) / l4 : 0.0);
        snprintf(v[k++], 96, "%.1f pakietów/s, %.1f kbit/s",
                 dur > 0 ? s->total_pkts / dur : 0.0,
                 dur > 0 ? s->total_bytes * 8.0 / 1000.0 / dur : 0.0);
        snprintf(v[k++], 96, "TCP %llu, UDP %llu", (unsigned long long)s->tcp_flows,
                 (unsigned long long)s->udp_flows);
        snprintf(v[k++], 96, "%llu (%.2f%% pakietów TCP)", (unsigned long long)s->tcp_retrans,
                 pct(s->tcp_retrans, s->tcp_pkts));
        if (rtt_n) snprintf(v[k++], 96, "%.2f ms (z %llu połączeń)", 1000.0 * rtt_sum / rtt_n,
                            (unsigned long long)rtt_n);
        else       snprintf(v[k++], 96, "brak danych");
        const char *keys[12] = {
            "Typ łącza", "Pakiety TCP", "Pakiety UDP", "Inne / uszkodzone pakiety",
            "IPv4 / IPv6 (TCP+UDP)", "Bajty wg protokołu", "Dane aplikacji (payload)",
            "Średni rozmiar pakietu", "Średnie natężenie", "Przepływy",
            "Retransmisje TCP", "Średni czas SYN -> SYN+ACK",
        };
        const char *cells[24];
        for (int i = 0; i < k; i++) {
            cells[2 * i] = keys[i];
            cells[2 * i + 1] = v[i];
        }
        const char *hdr[] = { "PARAMETR", "WARTOŚĆ" };
        const double w[] = { 190, CONTENT_W - 190 };
        const int right[] = { 0, 0 };
        table(p, 2, hdr, w, right, cells, (size_t)k, NULL);
    }

    /* --- 4.2 Najaktywniejsze hosty --- */
    subheading(p, sec, "4.2. Najaktywniejsze hosty");
    {
        double *vals = malloc((s->n_hosts ? s->n_hosts : 1) * sizeof(double));
        if (vals) {
            for (size_t i = 0; i < s->n_hosts; i++)
                vals[i] = (double)(s->hosts[i]->bytes_out + s->hosts[i]->bytes_in);
            size_t idx[15];
            size_t n = top_n(vals, s->n_hosts, idx, 15);
            static char c[15][5][64];   /* 'static' - duża tablica poza stosem */
            const char *cells[15 * 5];
            for (size_t i = 0; i < n; i++) {
                const host_t *h = s->hosts[idx[i]];
                addr_to_str(&h->addr, c[i][0]);
                fmt_int(h->pkts_out, c[i][1], 64);
                fmt_bytes((double)h->bytes_out, c[i][2], 64);
                fmt_int(h->pkts_in, c[i][3], 64);
                fmt_bytes((double)h->bytes_in, c[i][4], 64);
                for (int k = 0; k < 5; k++)
                    cells[i * 5 + k] = c[i][k];
            }
            const char *hdr[] = { "ADRES IP", "WYSŁ. PAKIETY", "WYSŁ. DANE", "ODEBR. PAKIETY", "ODEBR. DANE" };
            const double w[] = { 155, 85, 85, 85, CONTENT_W - 410 };
            const int right[] = { 0, 1, 1, 1, 1 };
            table(p, 5, hdr, w, right, cells, n, NULL);
            free(vals);
        }
    }

    /* --- 4.3 Usługi --- */
    subheading(p, sec, "4.3. Najpopularniejsze usługi");
    {
        double *vals = malloc(2 * 65536 * sizeof(double));
        if (vals) {
            for (size_t i = 0; i < 65536; i++) {
                vals[i] = (double)s->tcp_port_pkts[i];
                vals[65536 + i] = (double)s->udp_port_pkts[i];
            }
            size_t idx[10];
            size_t n = top_n(vals, 2 * 65536, idx, 10);
            static char c[10][5][64];
            const char *cells[10 * 5];
            for (size_t i = 0; i < n; i++) {
                int udp = idx[i] >= 65536;
                uint16_t port = (uint16_t)(idx[i] % 65536);
                const char *svc = port_service_name(udp ? PROTO_UDP : PROTO_TCP, port);
                snprintf(c[i][0], 64, "%s", udp ? "UDP" : "TCP");
                snprintf(c[i][1], 64, "%u", port);
                snprintf(c[i][2], 64, "%s", svc ? svc : "-");
                fmt_int((unsigned long long)vals[idx[i]], c[i][3], 64);
                snprintf(c[i][4], 64, "%.1f%%", 100.0 * vals[idx[i]] / (double)(s->tcp_pkts + s->udp_pkts));
                for (int k = 0; k < 5; k++)
                    cells[i * 5 + k] = c[i][k];
            }
            const char *hdr[] = { "PROTOKÓŁ", "PORT", "USŁUGA", "PAKIETY", "UDZIAŁ" };
            const double w[] = { 70, 70, 155, 100, CONTENT_W - 395 };
            const int right[] = { 0, 1, 0, 1, 1 };
            table(p, 5, hdr, w, right, cells, n, NULL);
            free(vals);
        }
    }

    /* --- 4.4 Największe przepływy (top_n zamiast sortowania wszystkich) --- */
    subheading(p, sec, "4.4. Największe przepływy (połączenia)");
    {
        double *vals = malloc((s->n_flows ? s->n_flows : 1) * sizeof(double));
        if (vals) {
            for (size_t i = 0; i < s->n_flows; i++)
                vals[i] = (double)(s->flows[i]->bytes[0] + s->flows[i]->bytes[1]);
            size_t idx[20];
            size_t n = top_n(vals, s->n_flows, idx, 20);
            static char c[20][7][96];
            const char *cells[20 * 7];
            for (size_t i = 0; i < n; i++) {
                const flow_t *f = s->flows[idx[i]];
                char a1[ADDR_STR_LEN], a2[ADDR_STR_LEN];
                addr_to_str(&f->cli, a1);
                addr_to_str(&f->srv, a2);
                snprintf(c[i][0], 96, "%s", f->proto == PROTO_TCP ? "TCP" : "UDP");
                snprintf(c[i][1], 96, "%s:%u", a1, f->cport);
                snprintf(c[i][2], 96, "%s:%u", a2, f->sport);
                fmt_int(f->pkts[0] + f->pkts[1], c[i][3], 96);
                fmt_bytes((double)(f->bytes[0] + f->bytes[1]), c[i][4], 96);
                snprintf(c[i][5], 96, "%.2f s", f->last_ts - f->first_ts);
                snprintf(c[i][6], 96, "%s", flow_state_str(f));
                for (int k = 0; k < 7; k++)
                    cells[i * 7 + k] = c[i][k];
            }
            const char *hdr[] = { "PROTO", "KLIENT", "SERWER", "PAKIETY", "DANE", "CZAS", "STAN" };
            const double w[] = { 32, 100, 100, 44, 56, 40, CONTENT_W - 372 };
            const int right[] = { 0, 0, 0, 1, 1, 1, 0 };
            table(p, 7, hdr, w, right, cells, n, NULL);
            free(vals);
        }
    }
    paragraph(p, "Pełne dane: pliki hosty.csv i przeplywy.csv w katalogu raportu "
                 "(otworzysz je w Excelu lub LibreOffice).", 8.5, COL_TEXT2);
}

/* ------------------------------------------------------------------ */
/* Metodologia i słowniczek                                            */
/* ------------------------------------------------------------------ */

static void glossary_item(pdf_t *p, const char *term, const char *def)
{
    double h = paragraph_box(p, MARGIN_X + 110, 0, CONTENT_W - 110, def, 8.5, 0, COL_TEXT, 0);
    ensure(p, h + 4);
    font(p, 8.5, 1);
    color(p, COL_TEXT);
    text_at(p, MARGIN_X, p->y + 8.5, term);
    paragraph_box(p, MARGIN_X + 110, p->y, CONTENT_W - 110, def, 8.5, 0, COL_TEXT, 1);
    p->y += h + 4;
}

static void section_method(pdf_t *p, const report_input_t *in)
{
    const thresholds_t *t = in->thresholds;
    char buf[800];
    new_page(p);
    int sec = heading(p, "5", "Metodologia i słowniczek");
    subheading(p, sec, "Jak powstał ten raport");
    paragraph(p, "Pakiety są odczytywane biblioteką libpcap, a nagłówki Ethernet (z VLAN), "
                 "Linux SLL, IPv4, IPv6, TCP i UDP są dekodowane bezpośrednio z bajtów. "
                 "Pakiety łączone są w przepływy - dwukierunkowe rozmowy identyfikowane przez "
                 "protokół oraz adresy i porty obu stron. Klientem jest strona wysyłająca "
                 "SYN (TCP) albo nadawca pierwszego pakietu (UDP).", 9, COL_TEXT);
    paragraph(p, "Retransmisje TCP wykrywane są po numerach sekwencyjnych: segment, którego "
                 "dane nie wychodzą poza już widziany zakres, liczony jest jako retransmisja "
                 "(pakiety przestawione w kolejności również trafiają do tej kategorii). "
                 "RTT to czas między pierwszym SYN a odpowiedzią SYN+ACK.", 9, COL_TEXT);
    snprintf(buf, sizeof buf,
             "Progi: skanowanie portów - co najmniej %d różnych portów jednego hosta, z czego "
             "min. połowa bez udanego połączenia; skanowanie sieci - ten sam port na co "
             "najmniej %d hostach; SYN flood - co najmniej %d niedokończonych połączeń do "
             "jednej usługi (i min. 50%% wszystkich prób); retransmisje - powyżej %.1f%% "
             "pakietów TCP; RST - powyżej %.0f%% przepływów TCP; UDP flood - powyżej %.0f "
             "pakietów/s do jednego hosta (min. 1000 pakietów); skok ruchu - sekunda z "
             "natężeniem powyżej średniej + %.0f odchyleń standardowych.",
             t->scan_min_ports, t->sweep_min_hosts, t->synflood_min, 100 * t->retrans_ratio,
             100 * t->rst_ratio, t->udpflood_pps, t->spike_sigma);
    paragraph(p, buf, 9, COL_TEXT);
    paragraph(p, "Wynik ryzyka: każdy incydent krytyczny dodaje 35 punktów, ostrzeżenie 15 "
                 "(maksymalnie 100). Poziomy: 0-14 niskie, 15-39 podwyższone, 40-69 wysokie, "
                 "70-100 krytyczne. Wyniki to wskazówki do dalszej analizy, a nie "
                 "jednoznaczne dowody ataku - progi można zmienić opcjami programu.", 9, COL_TEXT);

    subheading(p, sec, "Słowniczek");
    glossary_item(p, "Pakiet", "Najmniejsza porcja danych przesyłana w sieci; ma nagłówki "
                  "(adresy, porty) i dane.");
    glossary_item(p, "TCP / UDP", "Dwa główne protokoły transportowe. TCP zestawia połączenie "
                  "i gwarantuje dostarczenie (WWW, SSH, poczta), UDP wysyła pakiety bez "
                  "połączenia (DNS, gry, wideo).");
    glossary_item(p, "Port", "Numer usługi na komputerze, np. 443 = HTTPS, 22 = SSH, 53 = DNS.");
    glossary_item(p, "Przepływ", "Cała rozmowa między dwoma programami: te same adresy IP, "
                  "porty i protokół, w obu kierunkach.");
    glossary_item(p, "SYN, SYN+ACK, ACK", "Trzy kroki nawiązania połączenia TCP (\"3-way "
                  "handshake\"). Brak trzeciego kroku = połączenie niedokończone.");
    glossary_item(p, "RST / FIN", "Flagi TCP: FIN grzecznie kończy połączenie, RST zrywa je "
                  "albo odrzuca próbę połączenia (np. port zamknięty).");
    glossary_item(p, "Retransmisja", "Ponowne wysłanie danych, które nie dotarły - objaw "
                  "gubienia pakietów.");
    glossary_item(p, "RTT", "Round-Trip Time - czas \"tam i z powrotem\" między komputerami.");
    glossary_item(p, "Skanowanie portów", "Sprawdzanie, które usługi są dostępne na hoście - "
                  "zwykle pierwszy krok ataku.");
    glossary_item(p, "SYN flood", "Atak DoS: tysiące niedokończonych połączeń zapychają serwer, "
                  "który przestaje obsługiwać prawdziwych klientów.");
    glossary_item(p, "UDP flood", "Atak DoS: zalewanie hosta pakietami UDP, aby zapchać łącze.");
    glossary_item(p, "IOC", "Indicator of Compromise - ślad ataku (np. adres IP), który można "
                  "zablokować lub wyszukać w innych systemach.");
}

/* ------------------------------------------------------------------ */

/* Funkcja zapisu dla pierwszego przebiegu - wyrzuca dane (jak /dev/null). */
static cairo_status_t discard(void *closure, const unsigned char *data, unsigned int len)
{
    (void)closure; (void)data; (void)len;
    return CAIRO_STATUS_SUCCESS;
}

/* Renderuje cały raport na podanej powierzchni. Zwraca liczbę stron. */
static int render(pdf_t *p, const report_input_t *in)
{
    p->cr = cairo_create(p->surf);
    p->page = 1;
    p->y = MARGIN_T;

    page_summary(p, in);
    section_plan(p, in);
    section_incidents(p, in);
    section_charts(p, in);
    section_details(p, in);
    section_method(p, in);

    footer(p);
    cairo_show_page(p->cr);
    cairo_status_t st = cairo_status(p->cr);
    cairo_destroy(p->cr);
    if (st != CAIRO_STATUS_SUCCESS) {
        fprintf(stderr, "Błąd cairo: %s\n", cairo_status_to_string(st));
        return -1;
    }
    return p->page;
}

int report_write(const report_input_t *in)
{
    /* nazwa pliku bez katalogów - do stopki */
    const char *base = strrchr(in->input_path, '/');
    base = base ? base + 1 : in->input_path;

    /* Przebieg 1: liczymy strony, nic nie zapisując. */
    pdf_t p = { 0 };
    p.file_label = base;
    p.surf = cairo_pdf_surface_create_for_stream(discard, NULL, PAGE_W, PAGE_H);
    int pages = render(&p, in);
    cairo_surface_finish(p.surf);
    cairo_surface_destroy(p.surf);
    if (pages < 0)
        return -1;

    /* Przebieg 2: właściwy plik, stopka zna już liczbę stron. */
    memset(&p, 0, sizeof p);
    p.file_label = base;
    p.total_pages = pages;
    p.real = 1;
    p.surf = cairo_pdf_surface_create(in->output_pdf, PAGE_W, PAGE_H);
    if (cairo_surface_status(p.surf) != CAIRO_STATUS_SUCCESS) {
        fprintf(stderr, "Nie można utworzyć %s\n", in->output_pdf);
        cairo_surface_destroy(p.surf);
        return -1;
    }
    cairo_pdf_surface_set_metadata(p.surf, CAIRO_PDF_METADATA_TITLE,
                                   "Raport bezpieczeństwa sieci - pcapan");
    cairo_pdf_surface_set_metadata(p.surf, CAIRO_PDF_METADATA_CREATOR, "pcapan");
    int rc = render(&p, in);
    cairo_surface_finish(p.surf);       /* dopiero tu PDF jest zapisywany na dysk */
    cairo_surface_destroy(p.surf);
    return rc < 0 ? -1 : 0;
}
