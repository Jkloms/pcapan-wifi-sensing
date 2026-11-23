/*
 * report.c - raport PDF (cairo, A4 w punktach: 595 x 842).
 * Strona 1: podsumowanie, główny wykres i tabela zdarzeń.
 * Dalej: wykresy radiowe, wykresy łącza, krótko o TCP/UDP i atakach.
 */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <cairo.h>
#include <cairo-pdf.h>
#include "report.h"
#include "charts.h"

#define PAGE_W   595.0
#define PAGE_H   842.0
#define MARGIN   40.0
#define CONTENT  (PAGE_W - 2 * MARGIN)

typedef struct {
    cairo_t    *cr;
    double      y;              /* bieżąca pozycja w pionie */
    int         page, pages;
    const char *file;
} pdf_t;

static void rgb(cairo_t *cr, unsigned v)
{
    cairo_set_source_rgb(cr, ((v >> 16) & 0xFF) / 255.0, ((v >> 8) & 0xFF) / 255.0,
                         (v & 0xFF) / 255.0);
}

static void font(cairo_t *cr, double size, int bold)
{
    cairo_select_font_face(cr, "DejaVu Sans", CAIRO_FONT_SLANT_NORMAL,
                           bold ? CAIRO_FONT_WEIGHT_BOLD : CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, size);
}

static void text(cairo_t *cr, double x, double y, const char *s)
{
    cairo_move_to(cr, x, y);
    cairo_show_text(cr, s);
}

static double text_w(cairo_t *cr, const char *s)
{
    cairo_text_extents_t e;
    cairo_text_extents(cr, s, &e);
    return e.x_advance;
}

/* Tekst przycięty do szerokości 'w' (z "..." na końcu). W UTF-8 tniemy
 * tylko przed bajtem zaczynającym znak (nie 10xxxxxx). */
static void text_fit(cairo_t *cr, double x, double y, const char *s, double w)
{
    char buf[256];
    snprintf(buf, sizeof buf, "%s", s);
    size_t len = strlen(buf);
    while (len > 0 && text_w(cr, buf) > w) {
        do len--; while (len > 0 && (s[len] & 0xC0) == 0x80);
        snprintf(buf, sizeof buf, "%.*s...", (int)len, s);
    }
    text(cr, x, y, buf);
}

static void fmt_clock(double ts, char *out, size_t len)
{
    time_t t = (time_t)ts;
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(out, len, "%H:%M:%S", &tm);
}

static void fmt_dur(double sec, char *out, size_t len)
{
    if (sec < 120) snprintf(out, len, "%.0f s", sec);
    else           snprintf(out, len, "%.0f min %02.0f s", floor(sec / 60), fmod(sec, 60));
}

static void footer(pdf_t *p)
{
    cairo_t *cr = p->cr;
    char buf[160];
    font(cr, 8, 0);
    rgb(cr, 0x52514E);
    snprintf(buf, sizeof buf, "pcapan  |  %s", p->file);
    text_fit(cr, MARGIN, PAGE_H - 22, buf, CONTENT - 80);
    snprintf(buf, sizeof buf, "strona %d / %d", p->page, p->pages);
    text(cr, PAGE_W - MARGIN - text_w(cr, buf), PAGE_H - 22, buf);
}

static void new_page(pdf_t *p, const char *title)
{
    if (p->page > 0) {
        footer(p);
        cairo_show_page(p->cr);
    }
    p->page++;
    p->y = MARGIN;
    if (title) {
        font(p->cr, 16, 1);
        rgb(p->cr, 0x0B0B0B);
        text(p->cr, MARGIN, p->y + 16, title);
        p->y += 32;
    }
}

/* Wykres wektorowy przeskalowany do szerokości strony + podpis pod spodem. */
static void chart(pdf_t *p, const analysis_t *an, int which)
{
    const plot_def_t *pd = &PLOTS[which];
    double scale = CONTENT / CHART_W;
    cairo_save(p->cr);
    cairo_translate(p->cr, MARGIN, p->y);
    cairo_scale(p->cr, scale, scale);
    pd->draw(an, p->cr, NULL);
    cairo_restore(p->cr);
    p->y += CHART_H * scale + 12;
    font(p->cr, 8.5, 0);
    rgb(p->cr, 0x52514E);
    text(p->cr, MARGIN, p->y, pd->caption);
    p->y += 18;
}

/* Kafelek z liczbą: kolorowy pasek z lewej, wartość i opis. */
static void tile(cairo_t *cr, double x, double y, double w, unsigned color,
                 const char *value, const char *label)
{
    rgb(cr, 0xF3F2EF);
    cairo_rectangle(cr, x, y, w, 52);
    cairo_fill(cr);
    rgb(cr, color);
    cairo_rectangle(cr, x, y, 4, 52);
    cairo_fill(cr);
    rgb(cr, 0x0B0B0B);
    font(cr, 17, 1);
    text_fit(cr, x + 12, y + 24, value, w - 16);
    rgb(cr, 0x52514E);
    font(cr, 8, 0);
    text_fit(cr, x + 12, y + 41, label, w - 16);
}

/* Tabela: nagłówek + wiersze; 'cols' to szerokości kolumn. */
static void table_row(pdf_t *p, const char *const *cells, const double *cols, int n,
                      int header, unsigned mark)
{
    cairo_t *cr = p->cr;
    if (header) {
        rgb(cr, 0xE4E3DF);
        cairo_rectangle(cr, MARGIN, p->y, CONTENT, 16);
        cairo_fill(cr);
    }
    if (mark) {
        rgb(cr, mark);
        cairo_rectangle(cr, MARGIN, p->y + 3, 3, 10);
        cairo_fill(cr);
    }
    font(cr, 8.5, header);
    rgb(cr, 0x0B0B0B);
    double x = MARGIN + 7;
    for (int i = 0; i < n; i++) {
        text_fit(cr, x, p->y + 11.5, cells[i], cols[i] - 6);
        x += cols[i];
    }
    p->y += 16;
    if (!header) {
        rgb(cr, 0xE4E3DF);
        cairo_set_line_width(cr, 0.5);
        cairo_move_to(cr, MARGIN, p->y);
        cairo_line_to(cr, MARGIN + CONTENT, p->y);
        cairo_stroke(cr);
    }
}

static unsigned event_color(event_type_t t)
{
    if (t == EV_MOTION) return 0x7C3AED;
    if (t == EV_INTERFERENCE) return 0xD97706;
    return 0xC62828;
}

static void section(pdf_t *p, const char *title)
{
    font(p->cr, 11, 1);
    rgb(p->cr, 0x0B0B0B);
    text(p->cr, MARGIN, p->y + 11, title);
    p->y += 20;
}

static void page_summary(pdf_t *p, const report_input_t *in)
{
    const stats_t *s = in->an.s;
    const sensing_t *x = in->an.x;
    cairo_t *cr = p->cr;
    char a[64], b[64], buf[256];

    new_page(p, NULL);
    font(cr, 20, 1);
    rgb(cr, 0x0B0B0B);
    text(cr, MARGIN, p->y + 20, "Wykrywanie ruchu i zakłóceń w sieci Wi-Fi");
    fmt_clock(s->first_ts, a, sizeof a);
    fmt_clock(s->last_ts, b, sizeof b);
    char day[32];
    time_t t0 = (time_t)s->first_ts;
    struct tm tm;
    localtime_r(&t0, &tm);
    strftime(day, sizeof day, "%Y-%m-%d", &tm);
    char dur[32];
    fmt_dur(stats_duration(s), dur, sizeof dur);
    snprintf(buf, sizeof buf, "%s   |   %s %s-%s (%s)   |   łącze %s", in->input_path,
             day, a, b, dur, in->linktype);
    font(cr, 9, 0);
    rgb(cr, 0x52514E);
    text_fit(cr, MARGIN, p->y + 38, buf, CONTENT);
    p->y += 54;

    /* kafelki */
    int n_link = sensing_count(x, EV_DELAY) + sensing_count(x, EV_RETRANS) +
                 sensing_count(x, EV_GAP);
    char v[4][48], l[4][64];
    snprintf(v[0], 48, "%d", sensing_count(x, EV_MOTION));
    snprintf(l[0], 64, "okresy ruchu, razem %.0f s", x->motion_sec);
    snprintf(v[1], 48, "%d", sensing_count(x, EV_INTERFERENCE));
    snprintf(l[1], 64, "zakłócenia radiowe");
    snprintf(v[2], 48, "%d", n_link);
    snprintf(l[2], 64, "problemy łącza");
    snprintf(v[3], 48, "%llu", (unsigned long long)s->total_pkts);
    snprintf(l[3], 64, "ramek / pakietów");
    const unsigned col[4] = { 0x7C3AED, 0xD97706, 0xC62828, 0x2A78D6 };
    double w = (CONTENT - 3 * 8) / 4;
    for (int i = 0; i < 4; i++)
        tile(cr, MARGIN + i * (w + 8), p->y, w, col[i], v[i], l[i]);
    p->y += 66;

    chart(p, &in->an, x->ref_tx >= 0 ? PLOT_RSSI : PLOT_PPS);

    section(p, "Wykryte zdarzenia");
    const double cols[5] = { 118, 58, 58, 52, CONTENT - 286 };
    const char *hdr[5] = { "Typ", "Od", "Do", "Czas", "Szczegóły" };
    table_row(p, hdr, cols, 5, 1, 0);
    size_t shown = 0;
    for (size_t i = 0; i < x->n_ev && p->y < PAGE_H - 70; i++, shown++) {
        const event_t *e = &x->ev[i];
        char c1[16], c2[16], c3[32];
        fmt_clock(s->first_ts + e->t0, c1, sizeof c1);
        fmt_clock(s->first_ts + e->t1, c2, sizeof c2);
        fmt_dur(e->t1 - e->t0, c3, sizeof c3);
        const char *cells[5] = { event_name(e->type), c1, c2, c3, e->detail };
        table_row(p, cells, cols, 5, 0, event_color(e->type));
    }
    font(cr, 8.5, 0);
    rgb(cr, 0x52514E);
    if (x->n_ev == 0)
        text(cr, MARGIN + 7, p->y + 12, "Nie wykryto ruchu ani zakłóceń.");
    else if (shown < x->n_ev) {
        snprintf(buf, sizeof buf, "... oraz %zu kolejnych - pełna lista w zdarzenia.csv",
                 x->n_ev - shown);
        text(cr, MARGIN + 7, p->y + 12, buf);
    }
}

static void page_tcpudp(pdf_t *p, const report_input_t *in)
{
    const stats_t *s = in->an.s;
    const anomalies_t *a = in->an.a;
    char v[6][48];

    new_page(p, "Ruch TCP/UDP i ataki");
    snprintf(v[0], 48, "%llu", (unsigned long long)s->tcp_pkts);
    snprintf(v[1], 48, "%llu", (unsigned long long)s->udp_pkts);
    snprintf(v[2], 48, "%llu (TCP %llu, UDP %llu)", (unsigned long long)s->n_flows,
             (unsigned long long)s->tcp_flows, (unsigned long long)s->udp_flows);
    snprintf(v[3], 48, "%zu", s->n_hosts);
    snprintf(v[4], 48, "%llu", (unsigned long long)s->tcp_retrans);
    snprintf(v[5], 48, "%llu (powtórzone %.1f%%)", (unsigned long long)s->wifi_frames,
             s->wifi_frames ? 100.0 * s->wifi_retry / s->wifi_frames : 0.0);
    const char *names[6] = { "Pakiety TCP", "Pakiety UDP", "Przepływy", "Hosty",
                             "Retransmisje TCP", "Ramki Wi-Fi" };
    const double cols[2] = { 160, CONTENT - 160 };
    for (int i = 0; i < 6; i++) {
        const char *cells[2] = { names[i], v[i] };
        table_row(p, cells, cols, 2, 0, 0);
    }
    p->y += 14;
    chart(p, &in->an, PLOT_SERVICES);

    section(p, "Ataki (dodatkowo)");
    const double acols[3] = { 150, 120, CONTENT - 270 };
    const char *hdr[3] = { "Rodzaj", "Źródło", "Opis" };
    if (a->n == 0) {
        font(p->cr, 8.5, 0);
        rgb(p->cr, 0x52514E);
        text(p->cr, MARGIN, p->y + 10, "Nie wykryto skanowania ani ataków typu flood.");
        p->y += 24;
    } else {
        table_row(p, hdr, acols, 3, 1, 0);
        for (size_t i = 0; i < a->n && i < 6; i++) {
            const anomaly_t *an = &a->items[i];
            const char *cells[3] = { an->category, an->source, an->text };
            table_row(p, cells, acols, 3, 0, an->severity == SEV_CRIT ? 0xC62828 : 0xD97706);
        }
        p->y += 10;
    }

    section(p, "Jak to działa");
    static const char *lines[] = {
        "Ruch: odchylenie standardowe RSSI w oknie 3 s; próg = 2 x poziom ciszy (min. 1,5 dB).",
        "Zakłócenia: ponad 25% powtórzonych ramek albo szum o 6 dB wyższy niż zwykle.",
        "Opóźnienie: RTT (dane -> ACK) powyżej 3 x mediany i co najmniej +50 ms.",
        "Retransmisje: >= 3 na sekundę i >= 10% pakietów TCP. Przerwa: >= 3 s bez pakietów.",
    };
    font(p->cr, 8.5, 0);
    rgb(p->cr, 0x0B0B0B);
    for (size_t i = 0; i < 4; i++) {
        text(p->cr, MARGIN, p->y + 10, lines[i]);
        p->y += 14;
    }
}

int report_write(const report_input_t *in)
{
    cairo_surface_t *surf = cairo_pdf_surface_create(in->output_pdf, PAGE_W, PAGE_H);
    if (cairo_surface_status(surf) != CAIRO_STATUS_SUCCESS) {
        fprintf(stderr, "Nie można utworzyć %s\n", in->output_pdf);
        cairo_surface_destroy(surf);
        return -1;
    }
    cairo_pdf_surface_set_metadata(surf, CAIRO_PDF_METADATA_TITLE, "pcapan - raport");

    const analysis_t *an = &in->an;
    int radio = an->x->ref_tx >= 0 || an->s->wifi_frames > 0;
    const char *slash = strrchr(in->input_path, '/');
    pdf_t p = { .cr = cairo_create(surf), .pages = 3 + radio,
                .file = slash ? slash + 1 : in->input_path };

    page_summary(&p, in);
    if (radio) {
        new_page(&p, "Radio: ruch i zakłócenia");
        chart(&p, an, PLOT_MOTION);
        chart(&p, an, PLOT_RETRY);
    }
    new_page(&p, "Łącze: opóźnienia i straty");
    chart(&p, an, PLOT_RTT);
    chart(&p, an, PLOT_RETRANS);
    page_tcpudp(&p, in);
    footer(&p);

    cairo_destroy(p.cr);
    cairo_surface_finish(surf);
    int rc = cairo_surface_status(surf) == CAIRO_STATUS_SUCCESS ? 0 : -1;
    cairo_surface_destroy(surf);
    return rc;
}
