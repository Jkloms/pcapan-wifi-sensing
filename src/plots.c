/*
 * plots.c - zamiana statystyk na dane do wykresów i ich zapis (opis w plots.h).
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

/* Dodaje wykres do listy (jeśli się udało) i zwraca 1 przy błędzie. */
static int add_plot(plot_list_t *out, int rc, const char *path, const char *caption)
{
    if (rc != 0)
        return 1;
    if (out->n < MAX_PLOTS) {
        snprintf(out->items[out->n].path, sizeof out->items[0].path, "%s", path);
        snprintf(out->items[out->n].caption, sizeof out->items[0].caption, "%s", caption);
        out->n++;
    }
    return 0;
}

/* Wykresy osi czasu: pakiety/s i przepustowość. */
static int plot_timeline(const stats_t *s, const char *dir, plot_list_t *out)
{
    char path[512];
    int errors = 0;

    /* Za dużo punktów byłoby nieczytelne - grupujemy sekundy w przedziały. */
    const size_t MAX_POINTS = 200;
    size_t width = (s->tl_len + MAX_POINTS - 1) / MAX_POINTS;   /* dzielenie z zaokrągleniem w górę */
    if (width == 0) width = 1;
    size_t n = (s->tl_len + width - 1) / width;

    double *tcp_p = calloc(n ? n : 1, sizeof(double));
    double *udp_p = calloc(n ? n : 1, sizeof(double));
    double *tcp_b = calloc(n ? n : 1, sizeof(double));
    double *udp_b = calloc(n ? n : 1, sizeof(double));
    if (!tcp_p || !udp_p || !tcp_b || !udp_b) {
        free(tcp_p); free(udp_p); free(tcp_b); free(udp_b);
        return 2;
    }

    for (size_t i = 0; i < s->tl_len; i++) {
        size_t k = i / width;
        tcp_p[k] += s->timeline[i].pkts[0];
        udp_p[k] += s->timeline[i].pkts[1];
        tcp_b[k] += s->timeline[i].bytes[0];
        udp_b[k] += s->timeline[i].bytes[1];
    }
    for (size_t k = 0; k < n; k++) {
        /* średnio na sekundę; bajty -> kilobity (x8 / 1000) */
        tcp_p[k] /= width;
        udp_p[k] /= width;
        tcp_b[k] = tcp_b[k] * 8.0 / 1000.0 / width;
        udp_b[k] = udp_b[k] * 8.0 / 1000.0 / width;
    }

    char sub[128];
    snprintf(sub, sizeof sub, "Średnio na sekundę, punkt co %zu s", width);

    /* Tablica wskaźników na tablice - tak przekazujemy kilka serii naraz. */
    const double *pk[2] = { tcp_p, udp_p };
    const double *bt[2] = { tcp_b, udp_b };
    const char *names[2] = { "TCP", "UDP" };

    snprintf(path, sizeof path, "%s/01_ruch_pakiety.png", dir);
    errors += add_plot(out, chart_lines(path, "Natężenie ruchu w czasie", sub,
                       pk, names, 2, n, (double)width, "pakiety / s"),
                       path, "Liczba pakietów TCP i UDP na sekundę w trakcie nagrania.");

    snprintf(path, sizeof path, "%s/02_ruch_przepustowosc.png", dir);
    errors += add_plot(out, chart_lines(path, "Przepustowość w czasie", sub,
                       bt, names, 2, n, (double)width, "kbit / s"),
                       path, "Przepustowość (kilobity na sekundę) dla TCP i UDP.");

    free(tcp_p); free(udp_p); free(tcp_b); free(udp_b);
    return errors;
}

static int plot_protocols(const stats_t *s, const char *dir, plot_list_t *out)
{
    char path[512];
    const char *labels[] = { "TCP", "UDP", "Inne (ARP, ICMP...)" };
    double values[] = { (double)s->tcp_pkts, (double)s->udp_pkts, (double)s->other_pkts };
    snprintf(path, sizeof path, "%s/03_protokoly.png", dir);
    return add_plot(out, chart_vbar(path, "Pakiety według protokołu", "Liczba pakietów",
                    labels, values, 3, NULL, "pakiety"),
                    path, "Podział pakietów na TCP, UDP i pozostałe.");
}

static int plot_top_hosts(const stats_t *s, const char *dir, plot_list_t *out)
{
    char path[512];
    double *vals = malloc((s->n_hosts ? s->n_hosts : 1) * sizeof(double));
    if (vals == NULL)
        return 1;
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
    snprintf(path, sizeof path, "%s/04_top_hosty.png", dir);
    return add_plot(out, chart_hbar(path, "Najaktywniejsze hosty",
                    "Bajty wysłane + odebrane, top 10", labels, values, n, "B"),
                    path, "Hosty, które wymieniły najwięcej danych (suma w obu kierunkach).");
}

static int plot_top_services(const stats_t *s, const char *dir, plot_list_t *out)
{
    char path[512];
    /* Łączymy porty TCP (indeksy 0..65535) i UDP (65536..131071) w jedną tablicę. */
    double *vals = malloc(2 * 65536 * sizeof(double));
    if (vals == NULL)
        return 1;
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
    snprintf(path, sizeof path, "%s/05_top_uslugi.png", dir);
    return add_plot(out, chart_hbar(path, "Najpopularniejsze usługi (porty serwerów)",
                    "Liczba pakietów, top 10", labels, values, n, "pakietów"),
                    path, "Porty po stronie serwera, przez które przeszło najwięcej pakietów.");
}

static int plot_sizes(const stats_t *s, const char *dir, plot_list_t *out)
{
    char path[512];
    double values[SIZE_BINS];
    for (int i = 0; i < SIZE_BINS; i++)
        values[i] = (double)s->size_hist[i];
    snprintf(path, sizeof path, "%s/06_rozmiary_pakietow.png", dir);
    return add_plot(out, chart_vbar(path, "Rozkład rozmiarów pakietów", "Pakiety TCP i UDP",
                    SIZE_BIN_LABELS, values, SIZE_BINS, "rozmiar pakietu [bajty]", "pakiety"),
                    path, "Histogram rozmiarów pakietów. Dużo małych pakietów to zwykle "
                          "sterowanie (ACK, SYN), duże to transfer danych.");
}

static int plot_flags(const stats_t *s, const char *dir, plot_list_t *out)
{
    char path[512];
    const char *labels[] = { "SYN", "SYN+ACK", "FIN", "RST", "PSH", "sam ACK" };
    double values[] = { (double)s->f_syn, (double)s->f_synack, (double)s->f_fin,
                        (double)s->f_rst, (double)s->f_psh, (double)s->f_ack_only };
    snprintf(path, sizeof path, "%s/07_flagi_tcp.png", dir);
    return add_plot(out, chart_vbar(path, "Flagi TCP", "Liczba pakietów z daną flagą",
                    labels, values, 6, NULL, "pakiety"),
                    path, "Liczba pakietów TCP z poszczególnymi flagami. Przewaga SYN nad "
                          "SYN+ACK lub dużo RST może wskazywać na skanowanie lub atak.");
}

static int plot_flow_states(const stats_t *s, const char *dir, plot_list_t *out)
{
    char path[512];
    /* Te same napisy, które zwraca flow_state_str() */
    const char *states[] = {
        "nawiązane, zamknięte FIN", "nawiązane, otwarte", "nawiązane, zerwane RST",
        "odrzucone (RST)", "brak odpowiedzi na SYN", "półotwarte (brak ACK)",
        "w trakcie (bez handshake)"
    };
    enum { NS = sizeof states / sizeof states[0] };
    double counts[NS] = { 0 };
    for (size_t i = 0; i < s->n_flows; i++) {
        if (s->flows[i]->proto != PROTO_TCP)
            continue;
        const char *st = flow_state_str(s->flows[i]);
        for (int k = 0; k < NS; k++)
            if (strcmp(st, states[k]) == 0) { counts[k]++; break; }
    }
    size_t idx[NS];
    size_t n = top_n(counts, NS, idx, NS);
    const char *labels[NS];
    double values[NS];
    for (size_t i = 0; i < n; i++) {
        labels[i] = states[idx[i]];
        values[i] = counts[idx[i]];
    }
    snprintf(path, sizeof path, "%s/08_stany_polaczen.png", dir);
    return add_plot(out, chart_hbar(path, "Stany połączeń TCP", "Liczba przepływów TCP",
                    labels, values, n, "połączeń"),
                    path, "Jak kończyły się połączenia TCP. Wiele połączeń bez odpowiedzi "
                          "lub odrzuconych to typowy obraz skanowania albo SYN flood.");
}

static int plot_rtt(const stats_t *s, const char *dir, plot_list_t *out)
{
    char path[512];
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
    snprintf(path, sizeof path, "%s/09_rtt.png", dir);
    return add_plot(out, chart_vbar(path, "Czas nawiązania połączenia (RTT)", sub,
                    labels, values, 6, "czas odpowiedzi serwera", "połączenia"),
                    path, "Rozkład czasu odpowiedzi serwera na SYN. Długie czasy oznaczają "
                          "odległe lub przeciążone serwery.");
}

static int plot_fanout(const anomalies_t *a, const char *dir, plot_list_t *out)
{
    char path[512];
    size_t n = a->n_fanout < 10 ? a->n_fanout : 10;
    char names[10][ADDR_STR_LEN];
    const char *labels[10];
    double values[10];
    for (size_t i = 0; i < n; i++) {
        addr_to_str(&a->fanout[i].addr, names[i]);
        labels[i] = names[i];
        values[i] = a->fanout[i].targets;
    }
    snprintf(path, sizeof path, "%s/10_rozne_cele.png", dir);
    return add_plot(out, chart_hbar(path, "Hosty kontaktujące najwięcej celów",
                    "Liczba różnych par (host, port) docelowych, top 10",
                    labels, values, n, "celów"),
                    path, "Host, który łączy się z bardzo wieloma różnymi portami lub hostami, "
                          "to najczęściej skaner.");
}

int plots_generate(const stats_t *s, const anomalies_t *a, const char *outdir,
                   plot_list_t *out)
{
    int errors = 0;
    out->n = 0;
    errors += plot_timeline(s, outdir, out);
    errors += plot_protocols(s, outdir, out);
    errors += plot_top_hosts(s, outdir, out);
    errors += plot_top_services(s, outdir, out);
    errors += plot_sizes(s, outdir, out);
    errors += plot_flags(s, outdir, out);
    errors += plot_flow_states(s, outdir, out);
    errors += plot_rtt(s, outdir, out);
    errors += plot_fanout(a, outdir, out);
    return errors;
}
