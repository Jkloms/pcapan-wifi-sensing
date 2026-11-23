/*
 * plots.c - zamiana statystyk na dane do wykresów (opis w plots.h).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "plots.h"
#include "charts.h"

size_t top_n(const double *values, size_t count, size_t *idx, size_t n_top)
{
    size_t used = 0;
    if (n_top == 0)
        return 0;
    for (size_t i = 0; i < count; i++) {
        double v = values[i];
        if (v <= 0)
            continue;
        /* Czy wartość mieści się w obecnym "top"? */
        if (used == n_top && v <= values[idx[used - 1]])
            continue;
        /* Sortowanie przez wstawianie: przesuwamy mniejsze elementy w prawo. */
        size_t pos = (used < n_top) ? used++ : used - 1;
        while (pos > 0 && values[idx[pos - 1]] < v) {
            idx[pos] = idx[pos - 1];
            pos--;
        }
        idx[pos] = i;
    }
    return used;
}

/* ------------------------------------------------------------------ */
/* Oś czasu                                                            */
/* ------------------------------------------------------------------ */

/* Dane osi czasu po zgrupowaniu sekund w przedziały. */
typedef struct {
    double *tcp, *udp;   /* wartości na sekundę w każdym przedziale */
    size_t  n;           /* liczba punktów */
    size_t  width;       /* ile sekund ma jeden punkt */
} series_t;

/* bytes = 0 -> pakiety/s, bytes = 1 -> kbit/s */
static int build_series(const stats_t *s, int bytes, series_t *out)
{
    /* Za dużo punktów byłoby nieczytelne - grupujemy sekundy w przedziały. */
    const size_t MAX_POINTS = 200;
    size_t width = (s->tl_len + MAX_POINTS - 1) / MAX_POINTS;   /* dzielenie z zaokrągleniem w górę */
    if (width == 0) width = 1;
    size_t n = (s->tl_len + width - 1) / width;

    out->tcp = calloc(n ? n : 1, sizeof(double));
    out->udp = calloc(n ? n : 1, sizeof(double));
    out->n = n;
    out->width = width;
    if (!out->tcp || !out->udp) {
        free(out->tcp);
        free(out->udp);
        return -1;
    }
    for (size_t i = 0; i < s->tl_len; i++) {
        size_t k = i / width;
        if (bytes) {
            out->tcp[k] += (double)s->timeline[i].bytes[0];
            out->udp[k] += (double)s->timeline[i].bytes[1];
        } else {
            out->tcp[k] += s->timeline[i].pkts[0];
            out->udp[k] += s->timeline[i].pkts[1];
        }
    }
    double scale = bytes ? 8.0 / 1000.0 / width : 1.0 / width;   /* bajty -> kilobity */
    for (size_t k = 0; k < n; k++) {
        out->tcp[k] *= scale;
        out->udp[k] *= scale;
    }
    return 0;
}

/* Okna czasowe incydentów (ostrzeżenia i krytyczne) jako pasy na wykresie. */
static size_t build_bands(const stats_t *s, const anomalies_t *a, chart_band_t *bands, size_t max)
{
    size_t n = 0;
    double dur = stats_duration(s);
    for (size_t i = 0; a && i < a->n && n < max; i++) {
        const anomaly_t *an = &a->items[i];
        if (an->severity == SEV_INFO || an->t_start <= 0)
            continue;
        /* pomijamy "incydenty" obejmujące prawie całe nagranie - pas nic by nie mówił */
        if (dur > 0 && an->t_end - an->t_start > 0.8 * dur)
            continue;
        bands[n].x0 = an->t_start - s->first_ts;
        bands[n].x1 = an->t_end - s->first_ts;
        bands[n].critical = an->severity == SEV_CRIT;
        bands[n].label = an->category;
        n++;
    }
    /* sortujemy pasy wg czasu (sortowanie przez wstawianie - pasów jest mało),
     * żeby wykres mógł pominąć nachodzące na siebie podpisy */
    for (size_t i = 1; i < n; i++) {
        chart_band_t tmp = bands[i];
        size_t j = i;
        while (j > 0 && bands[j - 1].x0 > tmp.x0) {
            bands[j] = bands[j - 1];
            j--;
        }
        bands[j] = tmp;
    }
    return n;
}

int plot_timeline_packets(const stats_t *s, const anomalies_t *a, cairo_t *cr, const char *path)
{
    series_t sr;
    if (build_series(s, 0, &sr) != 0)
        return -1;
    chart_band_t bands[16];
    size_t nb = build_bands(s, a, bands, 16);

    char sub[128];
    snprintf(sub, sizeof sub, "Pakiety na sekundę (punkt co %zu s); pasy = okna wykrytych incydentów",
             sr.width);
    /* Tablica wskaźników na tablice - tak przekazujemy kilka serii naraz. */
    const double *ser[2] = { sr.tcp, sr.udp };
    const char *names[2] = { "TCP", "UDP" };
    int rc = chart_lines(cr, path, "Natężenie ruchu i incydenty w czasie", sub,
                         ser, names, 2, sr.n, (double)sr.width, "pakiety / s", bands, nb);
    free(sr.tcp);
    free(sr.udp);
    return rc;
}

static int plot_timeline_bytes(const stats_t *s, const anomalies_t *a, cairo_t *cr, const char *path)
{
    (void)a;   /* parametr nieużywany - rzutowanie na void ucisza ostrzeżenie kompilatora */
    series_t sr;
    if (build_series(s, 1, &sr) != 0)
        return -1;
    char sub[96];
    snprintf(sub, sizeof sub, "Kilobity na sekundę (punkt co %zu s)", sr.width);
    const double *ser[2] = { sr.tcp, sr.udp };
    const char *names[2] = { "TCP", "UDP" };
    int rc = chart_lines(cr, path, "Przepustowość w czasie", sub,
                         ser, names, 2, sr.n, (double)sr.width, "kbit / s", NULL, 0);
    free(sr.tcp);
    free(sr.udp);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Wykresy słupkowe                                                    */
/* ------------------------------------------------------------------ */

static int plot_protocols(const stats_t *s, const anomalies_t *a, cairo_t *cr, const char *path)
{
    (void)a;
    const char *labels[] = { "TCP", "UDP", "Inne (ARP, ICMP...)" };
    double values[] = { (double)s->tcp_pkts, (double)s->udp_pkts, (double)s->other_pkts };
    return chart_vbar(cr, path, "Pakiety według protokołu", "Liczba pakietów",
                      labels, values, 3, NULL, "pakiety");
}

static int plot_top_hosts(const stats_t *s, const anomalies_t *a, cairo_t *cr, const char *path)
{
    (void)a;
    double *vals = malloc((s->n_hosts ? s->n_hosts : 1) * sizeof(double));
    if (vals == NULL)
        return -1;
    for (size_t i = 0; i < s->n_hosts; i++)
        vals[i] = (double)(s->hosts[i]->bytes_out + s->hosts[i]->bytes_in);

    size_t idx[10];
    size_t n = top_n(vals, s->n_hosts, idx, 10);
    char names[10][ADDR_STR_LEN];        /* tablica dwuwymiarowa: 10 napisów */
    const char *labels[10];
    double values[10];
    for (size_t i = 0; i < n; i++) {
        addr_to_str(&s->hosts[idx[i]]->addr, names[i]);
        labels[i] = names[i];
        values[i] = vals[idx[i]];
    }
    free(vals);
    return chart_hbar(cr, path, "Najaktywniejsze hosty", "Bajty wysłane + odebrane, top 10",
                      labels, values, n, "B");
}

static int plot_top_services(const stats_t *s, const anomalies_t *a, cairo_t *cr, const char *path)
{
    (void)a;
    /* Łączymy porty TCP (indeksy 0..65535) i UDP (65536..131071) w jedną tablicę. */
    double *vals = malloc(2 * 65536 * sizeof(double));
    if (vals == NULL)
        return -1;
    for (size_t i = 0; i < 65536; i++) {
        vals[i] = (double)s->tcp_port_pkts[i];
        vals[65536 + i] = (double)s->udp_port_pkts[i];
    }
    size_t idx[10];
    size_t n = top_n(vals, 2 * 65536, idx, 10);
    char names[10][48];
    const char *labels[10];
    double values[10];
    for (size_t i = 0; i < n; i++) {
        int is_udp = idx[i] >= 65536;
        uint16_t port = (uint16_t)(idx[i] % 65536);
        const char *svc = port_service_name(is_udp ? PROTO_UDP : PROTO_TCP, port);
        snprintf(names[i], sizeof names[i], "%s/%u%s%s%s", is_udp ? "UDP" : "TCP", port,
                 svc ? " (" : "", svc ? svc : "", svc ? ")" : "");
        labels[i] = names[i];
        values[i] = vals[idx[i]];
    }
    free(vals);
    return chart_hbar(cr, path, "Najpopularniejsze usługi (porty serwerów)",
                      "Liczba pakietów, top 10", labels, values, n, "pakietów");
}

static int plot_sizes(const stats_t *s, const anomalies_t *a, cairo_t *cr, const char *path)
{
    (void)a;
    double values[SIZE_BINS];
    for (int i = 0; i < SIZE_BINS; i++)
        values[i] = (double)s->size_hist[i];
    return chart_vbar(cr, path, "Rozkład rozmiarów pakietów", "Pakiety TCP i UDP",
                      SIZE_BIN_LABELS, values, SIZE_BINS, "rozmiar pakietu [bajty]", "pakiety");
}

static int plot_flags(const stats_t *s, const anomalies_t *a, cairo_t *cr, const char *path)
{
    (void)a;
    const char *labels[] = { "SYN", "SYN+ACK", "FIN", "RST", "PSH", "sam ACK" };
    double values[] = { (double)s->f_syn, (double)s->f_synack, (double)s->f_fin,
                        (double)s->f_rst, (double)s->f_psh, (double)s->f_ack_only };
    return chart_vbar(cr, path, "Flagi TCP", "Liczba pakietów z daną flagą",
                      labels, values, 6, NULL, "pakiety");
}

static int plot_flow_states(const stats_t *s, const anomalies_t *a, cairo_t *cr, const char *path)
{
    (void)a;
    /* Liczymy przepływy TCP w każdym stanie - indeksem tablicy jest wartość enum. */
    double counts[FS_COUNT] = { 0 };
    for (size_t i = 0; i < s->n_flows; i++)
        if (s->flows[i]->proto == PROTO_TCP)
            counts[flow_state(s->flows[i])]++;

    size_t idx[FS_COUNT];
    size_t n = top_n(counts, FS_COUNT, idx, FS_COUNT);
    const char *labels[FS_COUNT];
    double values[FS_COUNT];
    for (size_t i = 0; i < n; i++) {
        labels[i] = flow_state_name((flow_state_t)idx[i]);
        values[i] = counts[idx[i]];
    }
    return chart_hbar(cr, path, "Stany połączeń TCP", "Liczba przepływów TCP",
                      labels, values, n, "połączeń");
}

static int plot_rtt(const stats_t *s, const anomalies_t *a, cairo_t *cr, const char *path)
{
    (void)a;
    const char *labels[] = { "<1 ms", "1-10 ms", "10-50 ms", "50-100 ms", "100-500 ms", ">500 ms" };
    const double limits[] = { 0.001, 0.010, 0.050, 0.100, 0.500 };
    double values[6] = { 0 };
    size_t n_rtt = 0;
    for (size_t i = 0; i < s->n_flows; i++) {
        double r = s->flows[i]->rtt;
        if (r < 0)
            continue;
        int b = 0;
        while (b < 5 && r >= limits[b])
            b++;
        values[b]++;
        n_rtt++;
    }
    char sub[96];
    snprintf(sub, sizeof sub, "Czas SYN -> SYN+ACK, %zu połączeń", n_rtt);
    return chart_vbar(cr, path, "Czas nawiązania połączenia (RTT)", sub,
                      labels, values, 6, "czas odpowiedzi serwera", "połączenia");
}

static int plot_fanout(const stats_t *s, const anomalies_t *a, cairo_t *cr, const char *path)
{
    (void)s;
    size_t n = a->n_fanout < 10 ? a->n_fanout : 10;
    char names[10][ADDR_STR_LEN];
    const char *labels[10];
    double values[10];
    for (size_t i = 0; i < n; i++) {
        addr_to_str(&a->fanout[i].addr, names[i]);
        labels[i] = names[i];
        values[i] = a->fanout[i].targets;
    }
    return chart_hbar(cr, path, "Hosty kontaktujące najwięcej celów",
                      "Liczba różnych par (host, port) docelowych, top 10",
                      labels, values, n, "celów");
}

/* ------------------------------------------------------------------ */
/* Lista wykresów - kolejność = kolejność w raporcie                    */
/* ------------------------------------------------------------------ */

const plot_def_t PLOTS[] = {
    { "01_ruch_incydenty.png", "Jak czytać: linie pokazują liczbę pakietów na sekundę, a kolorowe "
      "pasy okna czasowe wykrytych incydentów (czerwone - krytyczne, pomarańczowe - ostrzeżenia). "
      "Nagły wzrost w pasie to zwykle sam atak.", plot_timeline_packets },
    { "02_przepustowosc.png", "Jak czytać: ile danych płynęło w każdej chwili. Ataki typu flood "
      "często mają dużo pakietów, ale mało danych - porównaj z wykresem powyżej.",
      plot_timeline_bytes },
    { "03_protokoly.png", "Podział pakietów na TCP, UDP i pozostałe (np. ARP). Nagła przewaga UDP "
      "w sieci, gdzie zwykle dominuje TCP, jest podejrzana.", plot_protocols },
    { "04_top_hosty.png", "Hosty, które wymieniły najwięcej danych. Nieznany adres na szczycie "
      "listy warto sprawdzić.", plot_top_hosts },
    { "05_top_uslugi.png", "Porty po stronie serwera, przez które przeszło najwięcej pakietów - "
      "czyli z jakich usług najczęściej korzystano.", plot_top_services },
    { "06_rozmiary_pakietow.png", "Dużo małych pakietów to sterowanie (ACK, SYN) lub atak flood; "
      "duże pakiety to transfer danych.", plot_sizes },
    { "07_flagi_tcp.png", "Zdrowy ruch ma podobną liczbę SYN i SYN+ACK. Duża przewaga SYN lub "
      "dużo RST wskazuje na skanowanie albo SYN flood.", plot_flags },
    { "08_stany_polaczen.png", "Jak kończyły się połączenia TCP. Większość powinna być "
      "nawiązana i zamknięta FIN; dużo połączeń bez odpowiedzi to obraz ataku.",
      plot_flow_states },
    { "09_rtt.png", "Czas odpowiedzi serwerów na SYN. Długie czasy oznaczają odległe lub "
      "przeciążone serwery.", plot_rtt },
    { "10_rozne_cele.png", "Host łączący się z bardzo wieloma różnymi portami lub hostami to "
      "najczęściej skaner.", plot_fanout },
    { NULL, NULL, NULL }    /* "wartownik" - oznacza koniec tablicy */
};

int plots_generate(const stats_t *s, const anomalies_t *a, const char *outdir, int *n_ok)
{
    int errors = 0;
    *n_ok = 0;
    for (const plot_def_t *p = PLOTS; p->file != NULL; p++) {
        char path[512];
        snprintf(path, sizeof path, "%s/%s", outdir, p->file);
        if (p->draw(s, a, NULL, path) == 0) (*n_ok)++;
        else errors++;
    }
    return errors;
}
