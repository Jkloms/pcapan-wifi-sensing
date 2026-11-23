/*
 * report.c - składanie raportu PDF.
 *
 * Cairo potrafi rysować nie tylko do PNG, ale też do PDF - używamy tych
 * samych funkcji rysujących (tekst, prostokąty, obrazki), a cairo zapisuje
 * je jako stronę PDF. Jednostką są punkty typograficzne (1 pt = 1/72 cala).
 * Strona A4 ma 595 x 842 pt.
 *
 * Ten plik zawiera:
 *   - mały "silnik układu strony" (pdf_t): pilnuje bieżącej pozycji Y
 *     i sam zaczyna nową stronę, gdy brakuje miejsca,
 *   - funkcje do akapitów (z zawijaniem wierszy), nagłówków, tabel, obrazków,
 *   - właściwą treść raportu (sekcje 1-5).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <cairo.h>
#include <cairo-pdf.h>
#include "report.h"

/* ---- wymiary strony ---- */
#define PAGE_W   595.28
#define PAGE_H   841.89
#define MARGIN_X 50.0
#define MARGIN_T 56.0
#define MARGIN_B 60.0
#define CONTENT_W (PAGE_W - 2 * MARGIN_X)

#define FONT "DejaVu Sans"

/* Kolory (te same co na wykresach) i kolory statusu dla anomalii. */
#define COL_TEXT   0x0B0B0B
#define COL_TEXT2  0x52514E
#define COL_RULE   0xE4E3DF
#define COL_ZEBRA  0xF3F2EF
#define COL_ACCENT 0x2A78D6
#define COL_CRIT   0xC62828
#define COL_WARN   0xB26A00
#define COL_INFO   0x2A78D6

typedef struct {
    cairo_surface_t *surf;
    cairo_t *cr;
    double y;          /* bieżąca pozycja pionowa (pt od góry strony) */
    int page;          /* numer bieżącej strony */
} pdf_t;

/* ------------------------------------------------------------------ */
/* Podstawowe operacje                                                 */
/* ------------------------------------------------------------------ */

static void color(pdf_t *p, unsigned v)
{
    cairo_set_source_rgb(p->cr, ((v >> 16) & 0xFF) / 255.0,
                         ((v >> 8) & 0xFF) / 255.0, (v & 0xFF) / 255.0);
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

/* Stopka z numerem strony. */
static void footer(pdf_t *p)
{
    char buf[64];
    color(p, COL_TEXT2);
    font(p, 8, 0);
    text_at(p, MARGIN_X, PAGE_H - 30, "pcapan - raport analizy ruchu TCP/UDP");
    snprintf(buf, sizeof buf, "Strona %d", p->page);
    text_at(p, PAGE_W - MARGIN_X - text_w(p, buf), PAGE_H - 30, buf);
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
 * w szerokości 'width'. Gdy nie - rysujemy linię i zaczynamy następną.
 */
static void paragraph_at(pdf_t *p, double x, double width, const char *text,
                         double size, int bold, unsigned col)
{
    font(p, size, bold);
    color(p, col);
    double lh = size * 1.45;          /* wysokość linii */

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
            ensure(p, lh);
            font(p, size, bold);      /* nowa strona mogła zmienić czcionkę (stopka) */
            color(p, col);
            text_at(p, x, p->y + size, line);
            p->y += lh;
            snprintf(line, sizeof line, "%s", word);
        } else if (strlen(cand) < sizeof line) {
            memcpy(line, cand, strlen(cand) + 1);
        }
        s = e ? e + 1 : s + wl;
    }
    if (*line) {
        ensure(p, lh);
        font(p, size, bold);
        color(p, col);
        text_at(p, x, p->y + size, line);
        p->y += lh;
    }
}

static void paragraph(pdf_t *p, const char *text)
{
    paragraph_at(p, MARGIN_X, CONTENT_W, text, 10, 0, COL_TEXT);
    p->y += 4;
}

static void heading(pdf_t *p, const char *text)
{
    ensure(p, 80);                     /* nie zostawiaj nagłówka samotnie na dole strony */
    p->y += 10;
    font(p, 16, 1);
    color(p, COL_TEXT);
    text_at(p, MARGIN_X, p->y + 16, text);
    p->y += 24;
    color(p, COL_ACCENT);
    cairo_rectangle(p->cr, MARGIN_X, p->y, 40, 2.5);
    cairo_fill(p->cr);
    p->y += 12;
}

static void subheading(pdf_t *p, const char *text)
{
    ensure(p, 60);
    p->y += 6;
    font(p, 12, 1);
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
 */
static void table(pdf_t *p, int ncols, const char *const *headers, const double *widths,
                  const int *right, const char *const *cells, size_t nrows)
{
    const double rh = 16;             /* wysokość wiersza */
    int need_header = 1;

    for (size_t r = 0; r <= nrows; r++) {
        if (r < nrows && p->y + rh * (need_header ? 2 : 1) > PAGE_H - MARGIN_B) {
            new_page(p);
            need_header = 1;          /* powtórz nagłówek na nowej stronie */
        }
        if (need_header) {
            double x = MARGIN_X;
            font(p, 8.5, 1);
            color(p, COL_TEXT2);
            for (int c = 0; c < ncols; c++) {
                double tx = right[c] ? x + widths[c] - 4 - text_w(p, headers[c]) : x + 4;
                text_at(p, tx, p->y + 11, headers[c]);
                x += widths[c];
            }
            p->y += rh;
            color(p, COL_TEXT);
            cairo_rectangle(p->cr, MARGIN_X, p->y - 1, CONTENT_W, 0.8);
            cairo_fill(p->cr);
            need_header = 0;
        }
        if (r == nrows)
            break;

        if (r % 2 == 1) {             /* "zebra" - co drugi wiersz z tłem */
            color(p, COL_ZEBRA);
            cairo_rectangle(p->cr, MARGIN_X, p->y, CONTENT_W, rh);
            cairo_fill(p->cr);
        }
        double x = MARGIN_X;
        font(p, 8.5, 0);
        color(p, COL_TEXT);
        for (int c = 0; c < ncols; c++) {
            char buf[512];
            fit_text(p, cells[r * ncols + c], widths[c] - 8, buf, sizeof buf);
            double tx = right[c] ? x + widths[c] - 4 - text_w(p, buf) : x + 4;
            text_at(p, tx, p->y + 11.5, buf);
            x += widths[c];
        }
        p->y += rh;
    }
    p->y += 10;
}

/* Wstawia obrazek PNG przeskalowany do szerokości strony + podpis. */
static void image(pdf_t *p, const char *path, const char *caption)
{
    cairo_surface_t *img = cairo_image_surface_create_from_png(path);
    if (cairo_surface_status(img) != CAIRO_STATUS_SUCCESS) {
        cairo_surface_destroy(img);
        paragraph(p, "(nie udało się wczytać wykresu)");
        return;
    }
    double iw = cairo_image_surface_get_width(img);
    double ih = cairo_image_surface_get_height(img);
    double scale = CONTENT_W / iw;
    double h = ih * scale;

    ensure(p, h + 34);
    cairo_save(p->cr);
    cairo_translate(p->cr, MARGIN_X, p->y);
    cairo_scale(p->cr, scale, scale);       /* zmniejszamy obraz do szerokości strony */
    cairo_set_source_surface(p->cr, img, 0, 0);
    cairo_paint(p->cr);
    cairo_restore(p->cr);
    cairo_surface_destroy(img);

    /* cienka ramka */
    color(p, COL_RULE);
    cairo_set_line_width(p->cr, 0.6);
    cairo_rectangle(p->cr, MARGIN_X, p->y, CONTENT_W, h);
    cairo_stroke(p->cr);

    p->y += h + 4;
    paragraph_at(p, MARGIN_X, CONTENT_W, caption, 8.5, 0, COL_TEXT2);
    p->y += 10;
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
    else        snprintf(out, len, "%.2f %s", b, units[u]);
}

static void fmt_epoch(double ts, char *out, size_t len)
{
    time_t t = (time_t)ts;
    struct tm tm;
    localtime_r(&t, &tm);              /* wersja "_r" jest bezpieczna wątkowo */
    char base[32];
    strftime(base, sizeof base, "%Y-%m-%d %H:%M:%S", &tm);
    snprintf(out, len, "%s.%03d", base, (int)((ts - (double)t) * 1000));
}

static void fmt_duration(double sec, char *out, size_t len)
{
    if (sec < 60) snprintf(out, len, "%.2f s", sec);
    else if (sec < 3600) snprintf(out, len, "%d min %d s", (int)sec / 60, (int)sec % 60);
    else snprintf(out, len, "%d h %d min", (int)sec / 3600, ((int)sec / 60) % 60);
}

static double pct(uint64_t part, uint64_t total)
{
    return total ? 100.0 * (double)part / (double)total : 0.0;
}

/* ------------------------------------------------------------------ */
/* Sekcje raportu                                                      */
/* ------------------------------------------------------------------ */

static void section_title(pdf_t *p, const report_input_t *in)
{
    color(p, COL_ACCENT);
    cairo_rectangle(p->cr, 0, 0, PAGE_W, 8);
    cairo_fill(p->cr);

    p->y = 70;
    font(p, 24, 1);
    color(p, COL_TEXT);
    text_at(p, MARGIN_X, p->y, "Raport analizy ruchu sieciowego");
    p->y += 22;
    font(p, 12, 0);
    color(p, COL_TEXT2);
    text_at(p, MARGIN_X, p->y, "Komunikacja TCP i UDP na podstawie pliku pcap");
    p->y += 18;

    char now[64], line[600];
    time_t t = time(NULL);
    strftime(now, sizeof now, "%Y-%m-%d %H:%M", localtime(&t));
    snprintf(line, sizeof line, "Plik: %s   |   Wygenerowano: %s", in->input_path, now);
    font(p, 9, 0);
    paragraph_at(p, MARGIN_X, CONTENT_W, line, 9, 0, COL_TEXT2);
    p->y += 14;
}

/* Kafelek z jedną liczbą (np. "Pakiety: 12 345"). */
static void stat_tile(pdf_t *p, double x, double w, const char *label, const char *value)
{
    color(p, COL_ZEBRA);
    cairo_rectangle(p->cr, x, p->y, w, 52);
    cairo_fill(p->cr);
    font(p, 8.5, 0);
    color(p, COL_TEXT2);
    text_at(p, x + 10, p->y + 17, label);
    font(p, 16, 1);
    color(p, COL_TEXT);
    text_at(p, x + 10, p->y + 41, value);
}

static void section_summary(pdf_t *p, const report_input_t *in)
{
    const stats_t *s = in->stats;
    const anomalies_t *a = in->anomalies;
    char v1[32], v2[32], v3[32], v4[32];

    /* Rząd 4 kafelków z najważniejszymi liczbami */
    snprintf(v1, sizeof v1, "%llu", (unsigned long long)s->total_pkts);
    fmt_bytes((double)s->total_bytes, v2, sizeof v2);
    fmt_duration(stats_duration(s), v3, sizeof v3);
    size_t crit = 0;
    for (size_t i = 0; i < a->n; i++)
        if (a->items[i].severity >= SEV_WARN) crit++;
    snprintf(v4, sizeof v4, "%zu", crit);

    double tw = (CONTENT_W - 3 * 8) / 4;
    stat_tile(p, MARGIN_X, tw, "Pakiety", v1);
    stat_tile(p, MARGIN_X + (tw + 8), tw, "Dane", v2);
    stat_tile(p, MARGIN_X + 2 * (tw + 8), tw, "Czas nagrania", v3);
    stat_tile(p, MARGIN_X + 3 * (tw + 8), tw, "Ostrzeżenia", v4);
    p->y += 66;

    heading(p, "1. Podsumowanie");

    /* Liczymy dodatkowe wskaźniki z tabeli przepływów */
    uint64_t established = 0, rtt_n = 0;
    double rtt_sum = 0;
    for (size_t i = 0; i < s->n_flows; i++) {
        const flow_t *f = s->flows[i];
        if (f->proto == PROTO_TCP && (f->handshake & HS_ACK)) established++;
        if (f->rtt >= 0) { rtt_sum += f->rtt; rtt_n++; }
    }
    uint64_t l4 = s->tcp_pkts + s->udp_pkts;
    double dur = stats_duration(s);

    /* Tabela klucz-wartość: tablica par napisów */
    char buf[24][128];
    int k = 0;
    fmt_epoch(s->first_ts, buf[k++], 128);
    fmt_epoch(s->last_ts, buf[k++], 128);
    snprintf(buf[k++], 128, "%s", in->linktype);
    snprintf(buf[k++], 128, "%llu (%.1f%%)", (unsigned long long)s->tcp_pkts, pct(s->tcp_pkts, s->total_pkts));
    snprintf(buf[k++], 128, "%llu (%.1f%%)", (unsigned long long)s->udp_pkts, pct(s->udp_pkts, s->total_pkts));
    snprintf(buf[k++], 128, "%llu / %llu", (unsigned long long)s->other_pkts, (unsigned long long)s->bad_pkts);
    snprintf(buf[k++], 128, "%llu / %llu", (unsigned long long)s->ipv4_pkts, (unsigned long long)s->ipv6_pkts);
    fmt_bytes((double)s->tcp_bytes, v1, sizeof v1);
    fmt_bytes((double)s->udp_bytes, v2, sizeof v2);
    snprintf(buf[k++], 128, "TCP %s, UDP %s", v1, v2);
    fmt_bytes((double)s->payload_bytes, buf[k++], 128);
    snprintf(buf[k++], 128, "%.1f B", l4 ? (double)(s->tcp_bytes + s->udp_bytes) / l4 : 0.0);
    snprintf(buf[k++], 128, "%.1f pakietów/s, %.1f kbit/s",
             dur > 0 ? s->total_pkts / dur : 0.0, dur > 0 ? s->total_bytes * 8.0 / 1000.0 / dur : 0.0);
    snprintf(buf[k++], 128, "%zu", s->n_hosts);
    snprintf(buf[k++], 128, "TCP %llu, UDP %llu", (unsigned long long)s->tcp_flows, (unsigned long long)s->udp_flows);
    snprintf(buf[k++], 128, "%llu z %llu (%.1f%%)", (unsigned long long)established,
             (unsigned long long)s->tcp_flows, pct(established, s->tcp_flows));
    snprintf(buf[k++], 128, "%llu (%.2f%% pakietów TCP)", (unsigned long long)s->tcp_retrans,
             pct(s->tcp_retrans, s->tcp_pkts));
    if (rtt_n) snprintf(buf[k++], 128, "%.2f ms (z %llu połączeń)", 1000.0 * rtt_sum / rtt_n, (unsigned long long)rtt_n);
    else       snprintf(buf[k++], 128, "brak danych");

    const char *keys[] = {
        "Początek nagrania", "Koniec nagrania", "Typ łącza",
        "Pakiety TCP", "Pakiety UDP", "Inne / uszkodzone pakiety", "IPv4 / IPv6 (TCP+UDP)",
        "Bajty wg protokołu", "Dane aplikacji (payload)", "Średni rozmiar pakietu",
        "Średnie natężenie", "Liczba hostów (adresów IP)", "Przepływy (połączenia)",
        "Połączenia TCP nawiązane", "Retransmisje TCP", "Średni czas SYN -> SYN+ACK",
    };
    const char *cells[2 * 16];
    for (int i = 0; i < k; i++) {
        cells[2 * i] = keys[i];
        cells[2 * i + 1] = buf[i];
    }
    const char *hdr[] = { "Parametr", "Wartość" };
    const double w[] = { 200, CONTENT_W - 200 };
    const int right[] = { 0, 0 };
    table(p, 2, hdr, w, right, cells, (size_t)k);
}

static void section_anomalies(pdf_t *p, const report_input_t *in)
{
    const anomalies_t *a = in->anomalies;
    heading(p, "2. Wykryte nieprawidłowości");

    if (a->n == 0) {
        paragraph(p, "Przy bieżących progach detekcji nie wykryto żadnych nieprawidłowości.");
        return;
    }
    size_t cnt[3] = { 0 };
    for (size_t i = 0; i < a->n; i++)
        cnt[a->items[i].severity]++;
    char buf[256];
    snprintf(buf, sizeof buf, "Znaleziono %zu obserwacji: krytyczne %zu, ostrzeżenia %zu, "
             "informacyjne %zu. Lista jest posortowana od najpoważniejszych.",
             a->n, cnt[SEV_CRIT], cnt[SEV_WARN], cnt[SEV_INFO]);
    paragraph(p, buf);
    p->y += 4;

    for (size_t i = 0; i < a->n; i++) {
        const anomaly_t *an = &a->items[i];
        unsigned col = an->severity == SEV_CRIT ? COL_CRIT :
                       an->severity == SEV_WARN ? COL_WARN : COL_INFO;
        ensure(p, 60);

        /* Plakietka z poziomem ważności: kolor + tekst (nigdy sam kolor). */
        font(p, 8, 1);
        const char *sev = severity_name(an->severity);
        double bw = text_w(p, sev) + 12;
        color(p, col);
        cairo_rectangle(p->cr, MARGIN_X, p->y, bw, 14);
        cairo_fill(p->cr);
        cairo_set_source_rgb(p->cr, 1, 1, 1);
        text_at(p, MARGIN_X + 6, p->y + 10, sev);

        font(p, 11, 1);
        color(p, COL_TEXT);
        text_at(p, MARGIN_X + bw + 8, p->y + 11, an->category);
        p->y += 20;

        /* pionowa kreska po lewej stronie opisu */
        double y0 = p->y;
        int page0 = p->page;
        paragraph_at(p, MARGIN_X + 12, CONTENT_W - 12, an->text, 9.5, 0, COL_TEXT);
        if (p->page == page0) {
            color(p, col);
            cairo_rectangle(p->cr, MARGIN_X + 2, y0, 2, p->y - y0);
            cairo_fill(p->cr);
        }
        p->y += 10;
    }
}

static void section_charts(pdf_t *p, const report_input_t *in)
{
    new_page(p);
    heading(p, "3. Wykresy");
    paragraph(p, "Wykresy są też zapisane jako osobne pliki PNG w katalogu raportu.");
    for (int i = 0; i < in->plots->n; i++)
        image(p, in->plots->items[i].path, in->plots->items[i].caption);
}

/* Porównanie przepływów po liczbie bajtów - do qsort na tablicy wskaźników. */
static int cmp_flow_bytes(const void *x, const void *y)
{
    /* elementy tablicy to 'flow_t *', więc dostajemy wskaźniki na wskaźniki */
    const flow_t *a = *(const flow_t *const *)x;
    const flow_t *b = *(const flow_t *const *)y;
    uint64_t ba = a->bytes[0] + a->bytes[1], bb = b->bytes[0] + b->bytes[1];
    return (ba < bb) - (ba > bb);   /* malejąco */
}

static void section_details(pdf_t *p, const report_input_t *in)
{
    const stats_t *s = in->stats;
    new_page(p);
    heading(p, "4. Szczegóły");

    /* --- 4.1 Najaktywniejsze hosty --- */
    subheading(p, "4.1. Najaktywniejsze hosty");
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
                snprintf(c[i][1], 64, "%llu", (unsigned long long)h->pkts_out);
                fmt_bytes((double)h->bytes_out, c[i][2], 64);
                snprintf(c[i][3], 64, "%llu", (unsigned long long)h->pkts_in);
                fmt_bytes((double)h->bytes_in, c[i][4], 64);
                for (int k = 0; k < 5; k++)
                    cells[i * 5 + k] = c[i][k];
            }
            const char *hdr[] = { "Adres IP", "Wysł. pakiety", "Wysł. dane", "Odebr. pakiety", "Odebr. dane" };
            const double w[] = { 155, 85, 85, 85, CONTENT_W - 410 };
            const int right[] = { 0, 1, 1, 1, 1 };
            table(p, 5, hdr, w, right, cells, n);
            free(vals);
        }
    }

    /* --- 4.2 Usługi --- */
    subheading(p, "4.2. Najpopularniejsze usługi");
    {
        double *vals = malloc(2 * 65536 * sizeof(double));
        if (vals) {
            for (size_t i = 0; i < 65536; i++) {
                vals[i] = (double)s->tcp_port_pkts[i];
                vals[65536 + i] = (double)s->udp_port_pkts[i];
            }
            size_t idx[15];
            size_t n = top_n(vals, 2 * 65536, idx, 15);
            static char c[15][5][64];
            const char *cells[15 * 5];
            for (size_t i = 0; i < n; i++) {
                int udp = idx[i] >= 65536;
                uint16_t port = (uint16_t)(idx[i] % 65536);
                const char *svc = port_service_name(udp ? PROTO_UDP : PROTO_TCP, port);
                snprintf(c[i][0], 64, "%s", udp ? "UDP" : "TCP");
                snprintf(c[i][1], 64, "%u", port);
                snprintf(c[i][2], 64, "%s", svc ? svc : "-");
                snprintf(c[i][3], 64, "%.0f", vals[idx[i]]);
                snprintf(c[i][4], 64, "%.1f%%", 100.0 * vals[idx[i]] / (double)(s->tcp_pkts + s->udp_pkts));
                for (int k = 0; k < 5; k++)
                    cells[i * 5 + k] = c[i][k];
            }
            const char *hdr[] = { "Protokół", "Port", "Usługa", "Pakiety", "Udział" };
            const double w[] = { 70, 70, 155, 100, CONTENT_W - 395 };
            const int right[] = { 0, 1, 0, 1, 1 };
            table(p, 5, hdr, w, right, cells, n);
            free(vals);
        }
    }

    /* --- 4.3 Największe przepływy --- */
    subheading(p, "4.3. Największe przepływy (połączenia)");
    {
        size_t n = s->n_flows;
        const flow_t **sorted = malloc((n ? n : 1) * sizeof *sorted);
        if (sorted) {
            memcpy(sorted, s->flows, n * sizeof *sorted);
            qsort(sorted, n, sizeof *sorted, cmp_flow_bytes);
            if (n > 20) n = 20;
            static char c[20][7][96];
            const char *cells[20 * 7];
            for (size_t i = 0; i < n; i++) {
                const flow_t *f = sorted[i];
                char a1[ADDR_STR_LEN], a2[ADDR_STR_LEN];
                addr_to_str(&f->cli, a1);
                addr_to_str(&f->srv, a2);
                snprintf(c[i][0], 96, "%s", f->proto == PROTO_TCP ? "TCP" : "UDP");
                snprintf(c[i][1], 96, "%s:%u", a1, f->cport);
                snprintf(c[i][2], 96, "%s:%u", a2, f->sport);
                snprintf(c[i][3], 96, "%llu", (unsigned long long)(f->pkts[0] + f->pkts[1]));
                fmt_bytes((double)(f->bytes[0] + f->bytes[1]), c[i][4], 96);
                snprintf(c[i][5], 96, "%.2f s", f->last_ts - f->first_ts);
                snprintf(c[i][6], 96, "%s", flow_state_str(f));
                for (int k = 0; k < 7; k++)
                    cells[i * 7 + k] = c[i][k];
            }
            const char *hdr[] = { "Proto", "Klient", "Serwer", "Pakiety", "Dane", "Czas", "Stan" };
            const double w[] = { 32, 100, 100, 44, 56, 40, CONTENT_W - 372 };
            const int right[] = { 0, 0, 0, 1, 1, 1, 0 };
            table(p, 7, hdr, w, right, cells, n);
            free(sorted);
        }
    }
}

static void section_method(pdf_t *p, const report_input_t *in)
{
    const thresholds_t *t = in->thresholds;
    char buf[700];
    heading(p, "5. Metodologia i progi detekcji");
    paragraph(p, "Pakiety są odczytywane biblioteką libpcap, a nagłówki Ethernet (z VLAN), "
                 "Linux SLL, IPv4, IPv6, TCP i UDP są dekodowane bezpośrednio z bajtów. "
                 "Pakiety łączone są w przepływy - dwukierunkowe rozmowy identyfikowane przez "
                 "protokół oraz adresy i porty obu stron. Klientem jest strona wysyłająca "
                 "SYN (TCP) albo, gdy go brak, strona z wyższym numerem portu.");
    paragraph(p, "Retransmisje TCP wykrywane są po numerach sekwencyjnych: segment, którego "
                 "dane nie wychodzą poza już widziany zakres, liczony jest jako retransmisja "
                 "(pakiety przestawione w kolejności również trafiają do tej kategorii). "
                 "RTT to czas między pierwszym SYN a odpowiedzią SYN+ACK.");
    snprintf(buf, sizeof buf,
             "Progi: skanowanie portów - co najmniej %d różnych portów jednego hosta, z czego "
             "min. połowa bez udanego połączenia; skanowanie sieci - ten sam port na co "
             "najmniej %d hostach; SYN flood - co najmniej %d niedokończonych handshake do "
             "jednej usługi (i min. 50%% wszystkich prób); retransmisje - powyżej %.1f%% "
             "pakietów TCP; RST - powyżej %.0f%% przepływów TCP; UDP flood - powyżej %.0f "
             "pakietów/s do jednego hosta (min. 1000 pakietów); skok ruchu - sekunda z "
             "natężeniem powyżej średniej + %.0f odchyleń standardowych.",
             t->scan_min_ports, t->sweep_min_hosts, t->synflood_min, 100 * t->retrans_ratio,
             100 * t->rst_ratio, t->udpflood_pps, t->spike_sigma);
    paragraph(p, buf);
    paragraph(p, "Wyniki należy traktować jako wskazówki do dalszej analizy, a nie "
                 "jednoznaczne dowody ataku - progi można dostosować opcjami programu.");
}

/* ------------------------------------------------------------------ */

int report_write(const report_input_t *in)
{
    pdf_t p = { 0 };
    p.surf = cairo_pdf_surface_create(in->output_pdf, PAGE_W, PAGE_H);
    if (cairo_surface_status(p.surf) != CAIRO_STATUS_SUCCESS) {
        fprintf(stderr, "Nie można utworzyć %s\n", in->output_pdf);
        cairo_surface_destroy(p.surf);
        return -1;
    }
    cairo_pdf_surface_set_metadata(p.surf, CAIRO_PDF_METADATA_TITLE,
                                   "Raport analizy ruchu sieciowego");
    cairo_pdf_surface_set_metadata(p.surf, CAIRO_PDF_METADATA_CREATOR, "pcapan");
    p.cr = cairo_create(p.surf);
    p.page = 1;
    p.y = MARGIN_T;

    section_title(&p, in);
    section_summary(&p, in);
    section_anomalies(&p, in);
    section_charts(&p, in);
    section_details(&p, in);
    section_method(&p, in);

    footer(&p);
    cairo_show_page(p.cr);
    cairo_status_t st = cairo_status(p.cr);
    cairo_destroy(p.cr);
    cairo_surface_finish(p.surf);       /* dopiero tu PDF jest zapisywany na dysk */
    cairo_surface_destroy(p.surf);
    if (st != CAIRO_STATUS_SUCCESS) {
        fprintf(stderr, "Błąd cairo: %s\n", cairo_status_to_string(st));
        return -1;
    }
    return 0;
}
