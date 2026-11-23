/*
 * anomaly.c - detektory nieprawidłowości (opis w anomaly.h).
 *
 * Główna technika: z tabeli przepływów budujemy tablicę prostych rekordów
 * "próba połączenia" (attempt_t), sortujemy ją funkcją qsort według
 * odpowiedniego klucza i przechodzimy po GRUPACH sąsiednich rekordów
 * o tym samym kluczu. Po posortowaniu np. wszystkie próby z hosta A do
 * hosta B leżą obok siebie - łatwo je policzyć bez dodatkowych struktur.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "anomaly.h"

void thresholds_default(thresholds_t *t)
{
    t->scan_min_ports  = 15;
    t->sweep_min_hosts = 15;
    t->synflood_min    = 100;
    t->retrans_ratio   = 0.03;
    t->rst_ratio       = 0.30;
    t->udpflood_pps    = 500.0;
    t->spike_sigma     = 4.0;
}

const char *severity_name(severity_t s)
{
    switch (s) {
    case SEV_CRIT: return "KRYTYCZNE";
    case SEV_WARN: return "OSTRZEŻENIE";
    default:       return "INFO";
    }
}

/* Rekord pomocniczy: "a próbowało połączyć się z b na porcie port". */
typedef struct {
    ip_addr_t a, b;
    uint16_t  port;
    uint8_t   proto;     /* PROTO_TCP / PROTO_UDP */
    uint8_t   failed;    /* 1 = brak udanego połączenia */
    uint8_t   open;      /* 1 = serwer odpowiedział (port otwarty) */
} attempt_t;

/* ------------------------------------------------------------------ */
/* Dodawanie anomalii do listy                                         */
/* ------------------------------------------------------------------ */

/*
 * Funkcja ze zmienną liczbą argumentów (jak printf). "..." oznacza dowolne
 * dodatkowe argumenty; obsługuje się je makrami z <stdarg.h>.
 */
#include <stdarg.h>
static int add_anomaly(anomalies_t *out, severity_t sev, const char *cat,
                       const char *fmt, ...)
{
    if (out->n == out->cap) {
        size_t nc = out->cap ? out->cap * 2 : 16;
        anomaly_t *tmp = realloc(out->items, nc * sizeof *tmp);
        if (tmp == NULL)
            return -1;
        out->items = tmp;
        out->cap = nc;
    }
    anomaly_t *a = &out->items[out->n++];
    a->severity = sev;
    snprintf(a->category, sizeof a->category, "%s", cat);

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(a->text, sizeof a->text, fmt, ap);   /* bezpieczny printf do bufora */
    va_end(ap);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Funkcje porównujące dla qsort                                       */
/* ------------------------------------------------------------------ */
/*
 * qsort(tablica, liczba, rozmiar_elementu, funkcja_porównująca) to
 * standardowe sortowanie z biblioteki C. Funkcję porównującą przekazujemy
 * jako WSKAŹNIK NA FUNKCJĘ. Dostaje ona dwa wskaźniki 'const void *'
 * (nieznanego typu), które sami rzutujemy na właściwy typ.
 */

/* Sortowanie po (a, b, protokół, port). */
static int cmp_a_b_port(const void *x, const void *y)
{
    const attempt_t *p = x, *q = y;
    int c = addr_cmp(&p->a, &q->a);
    if (c) return c;
    c = addr_cmp(&p->b, &q->b);
    if (c) return c;
    if (p->proto != q->proto)
        return (int)p->proto - (int)q->proto;
    return (int)p->port - (int)q->port;
}

/* Sortowanie po (a, protokół, port, b). */
static int cmp_a_port_b(const void *x, const void *y)
{
    const attempt_t *p = x, *q = y;
    int c = addr_cmp(&p->a, &q->a);
    if (c) return c;
    if (p->proto != q->proto)
        return (int)p->proto - (int)q->proto;
    if (p->port != q->port)
        return (int)p->port - (int)q->port;
    return addr_cmp(&p->b, &q->b);
}

static int cmp_fanout_desc(const void *x, const void *y)
{
    const fanout_t *p = x, *q = y;
    if (p->targets != q->targets)
        return (p->targets < q->targets) ? 1 : -1;
    return addr_cmp(&p->addr, &q->addr);
}

/* Czy przepływ to nieudana próba połączenia? */
static int flow_failed(const flow_t *f)
{
    if (f->proto == PROTO_TCP)
        return !(f->handshake & HS_ACK);
    return f->pkts[DIR_S2C] == 0;      /* UDP: brak jakiejkolwiek odpowiedzi */
}

/* Czy serwer odpowiedział (port otwarty)? */
static int flow_open(const flow_t *f)
{
    if (f->proto == PROTO_TCP)
        return (f->handshake & HS_SYNACK) != 0;
    return f->pkts[DIR_S2C] > 0;
}

/* ------------------------------------------------------------------ */
/* Detektor 1+2: skanowanie portów i sieci, "fan-out" hostów            */
/* ------------------------------------------------------------------ */

static int detect_scans(const stats_t *s, const thresholds_t *t, anomalies_t *out)
{
    if (s->n_flows == 0)
        return 0;
    attempt_t *att = malloc(s->n_flows * sizeof *att);
    if (att == NULL)
        return -1;

    size_t n = 0;
    for (size_t i = 0; i < s->n_flows; i++) {
        const flow_t *f = s->flows[i];
        att[n].a = f->cli;
        att[n].b = f->srv;
        att[n].port = f->sport;
        att[n].proto = f->proto;
        att[n].failed = (uint8_t)flow_failed(f);
        att[n].open = (uint8_t)flow_open(f);
        n++;
    }

    /* ---- Skanowanie portów: grupy (klient, serwer), liczymy różne porty ---- */
    qsort(att, n, sizeof *att, cmp_a_b_port);

    size_t fan_cap = 64, fan_n = 0;
    fanout_t *fan = malloc(fan_cap * sizeof *fan);
    if (fan == NULL) { free(att); return -1; }

    size_t i = 0;
    while (i < n) {
        /* [i, j) to grupa rekordów z tym samym klientem 'a' */
        size_t j = i;
        uint32_t cli_targets = 0, cli_failed = 0;
        while (j < n && addr_cmp(&att[j].a, &att[i].a) == 0) {
            /* [j, k) - podgrupa: ten sam klient, serwer 'b' i protokół */
            size_t k = j;
            uint32_t ports = 0, failed = 0;
            char open_list[128] = "";
            int open_shown = 0;
            while (k < n && addr_cmp(&att[k].a, &att[j].a) == 0 &&
                   addr_cmp(&att[k].b, &att[j].b) == 0 && att[k].proto == att[j].proto) {
                /* nowy port tylko wtedy, gdy różni się od poprzedniego rekordu */
                if (k == j || att[k].port != att[k - 1].port) {
                    ports++;
                    int port_failed = att[k].failed;
                    if (port_failed) failed++;
                    if (att[k].open && open_shown < 8) {
                        size_t len = strlen(open_list);
                        snprintf(open_list + len, sizeof open_list - len, "%s%u",
                                 open_shown ? ", " : "", att[k].port);
                        open_shown++;
                    }
                }
                k++;
            }
            cli_targets += ports;
            cli_failed += failed;

            if ((int)ports >= t->scan_min_ports && failed * 2 >= ports) {
                char a[ADDR_STR_LEN], b[ADDR_STR_LEN];
                addr_to_str(&att[j].a, a);
                addr_to_str(&att[j].b, b);
                severity_t sev = (ports >= 100) ? SEV_CRIT : SEV_WARN;
                int rc;
                if (att[j].proto == PROTO_TCP)
                    rc = add_anomaly(out, sev, "Skanowanie portów TCP",
                        "Host %s próbował połączyć się z %u różnymi portami TCP hosta %s "
                        "(%u prób nieudanych). Odpowiedziały porty: %s.",
                        a, ports, b, failed, open_shown ? open_list : "brak");
                else
                    rc = add_anomaly(out, sev, "Skanowanie portów UDP",
                        "Host %s wysłał pakiety UDP na %u różnych portów hosta %s, z czego "
                        "%u bez żadnej odpowiedzi. To wzorzec skanowania UDP albo zalewu "
                        "pakietami na losowe porty. Odpowiedziały porty: %s.",
                        a, ports, b, failed, open_shown ? open_list : "brak");
                if (rc != 0)
                    goto oom;
            }
            j = k;
        }

        /* zapamiętujemy "fan-out" klienta do wykresu */
        if (fan_n == fan_cap) {
            fan_cap *= 2;
            fanout_t *tmp = realloc(fan, fan_cap * sizeof *fan);
            if (tmp == NULL) goto oom;
            fan = tmp;
        }
        fan[fan_n].addr = att[i].a;
        fan[fan_n].targets = cli_targets;
        fan[fan_n].failed = cli_failed;
        fan_n++;
        i = j;
    }
    qsort(fan, fan_n, sizeof *fan, cmp_fanout_desc);
    out->fanout = fan;
    out->n_fanout = fan_n;
    fan = NULL;          /* od teraz pamięcią zarządza 'out' (zwolni ją anomalies_free) */

    /* ---- Skanowanie sieci: grupy (klient, port), liczymy różne serwery ---- */
    qsort(att, n, sizeof *att, cmp_a_port_b);
    i = 0;
    while (i < n) {
        size_t j = i;
        uint32_t hosts = 0, failed = 0;
        while (j < n && addr_cmp(&att[j].a, &att[i].a) == 0 && att[j].port == att[i].port &&
               att[j].proto == att[i].proto) {
            if (j == i || addr_cmp(&att[j].b, &att[j - 1].b) != 0) {
                hosts++;
                if (att[j].failed) failed++;
            }
            j++;
        }
        if ((int)hosts >= t->sweep_min_hosts && failed * 2 >= hosts) {
            char a[ADDR_STR_LEN];
            addr_to_str(&att[i].a, a);
            if (add_anomaly(out, SEV_WARN, "Skanowanie sieci",
                    "Host %s próbował połączyć się z portem %s/%u na %u różnych hostach "
                    "(%u prób nieudanych).", a, att[i].proto == PROTO_TCP ? "TCP" : "UDP",
                    att[i].port, hosts, failed) != 0)
                goto oom;
        }
        i = j;
    }

    free(att);
    return 0;

oom:   /* "goto" w C jest akceptowane do wspólnej obsługi błędów i sprzątania */
    free(fan);
    free(att);
    return -1;
}

/* ------------------------------------------------------------------ */
/* Detektor 3: SYN flood                                               */
/* ------------------------------------------------------------------ */

static int detect_synflood(const stats_t *s, const thresholds_t *t, anomalies_t *out)
{
    /* Rekordy: a = serwer, port = port usługi, b = klient. */
    attempt_t *att = malloc((s->n_flows ? s->n_flows : 1) * sizeof *att);
    if (att == NULL)
        return -1;
    size_t n = 0;
    for (size_t i = 0; i < s->n_flows; i++) {
        const flow_t *f = s->flows[i];
        if (f->proto != PROTO_TCP || !(f->handshake & HS_SYN))
            continue;               /* interesują nas tylko próby otwarcia TCP */
        att[n].a = f->srv;
        att[n].b = f->cli;
        att[n].port = f->sport;
        att[n].proto = PROTO_TCP;
        att[n].failed = !(f->handshake & HS_ACK);
        att[n].open = 0;
        n++;
    }
    qsort(att, n, sizeof *att, cmp_a_port_b);

    size_t i = 0;
    while (i < n) {
        size_t j = i;
        uint32_t total = 0, incomplete = 0, sources = 0;
        while (j < n && addr_cmp(&att[j].a, &att[i].a) == 0 && att[j].port == att[i].port) {
            total++;
            if (att[j].failed) incomplete++;
            if (j == i || addr_cmp(&att[j].b, &att[j - 1].b) != 0)
                sources++;
            j++;
        }
        if ((int)incomplete >= t->synflood_min && incomplete * 2 >= total) {
            char a[ADDR_STR_LEN];
            addr_to_str(&att[i].a, a);
            if (add_anomaly(out, SEV_CRIT, "SYN flood",
                    "Usługa %s:%u otrzymała %u prób połączenia TCP, z czego %u nie "
                    "zostało dokończonych (%.0f%%), z %u różnych adresów źródłowych. "
                    "Wiele adresów źródłowych sugeruje ich fałszowanie (spoofing).",
                    a, att[i].port, total, incomplete, 100.0 * incomplete / total,
                    sources) != 0) {
                free(att);
                return -1;
            }
        }
        i = j;
    }
    free(att);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Detektor 4+5: retransmisje i RST                                     */
/* ------------------------------------------------------------------ */

static int detect_tcp_health(const stats_t *s, const thresholds_t *t, anomalies_t *out)
{
    if (s->tcp_pkts == 0)
        return 0;

    double ratio = (double)s->tcp_retrans / (double)s->tcp_pkts;
    if (s->tcp_retrans >= 10 && ratio >= t->retrans_ratio) {
        /* znajdź przepływ z największą liczbą retransmisji */
        const flow_t *worst = NULL;
        for (size_t i = 0; i < s->n_flows; i++)
            if (worst == NULL || s->flows[i]->retrans > worst->retrans)
                worst = s->flows[i];
        char a[ADDR_STR_LEN], b[ADDR_STR_LEN];
        addr_to_str(&worst->cli, a);
        addr_to_str(&worst->srv, b);
        severity_t sev = ratio >= 3 * t->retrans_ratio ? SEV_CRIT : SEV_WARN;
        if (add_anomaly(out, sev, "Retransmisje TCP",
                "%.1f%% pakietów TCP to retransmisje (%llu). Może to oznaczać utratę "
                "pakietów, przeciążenie łącza lub problemy z siecią. Najwięcej "
                "(%u) w połączeniu %s:%u -> %s:%u.",
                100.0 * ratio, (unsigned long long)s->tcp_retrans, worst->retrans,
                a, worst->cport, b, worst->sport) != 0)
            return -1;
    } else if (s->tcp_retrans > 0) {
        if (add_anomaly(out, SEV_INFO, "Retransmisje TCP",
                "Wykryto %llu retransmisji (%.2f%% pakietów TCP) - poziom w normie.",
                (unsigned long long)s->tcp_retrans, 100.0 * ratio) != 0)
            return -1;
    }

    /* Odsetek połączeń zerwanych przez RST */
    uint64_t rst_flows = 0;
    for (size_t i = 0; i < s->n_flows; i++) {
        const flow_t *f = s->flows[i];
        if (f->proto == PROTO_TCP && ((f->flags[0] | f->flags[1]) & TCP_RST))
            rst_flows++;
    }
    if (s->tcp_flows > 0) {
        double r = (double)rst_flows / (double)s->tcp_flows;
        if (rst_flows >= 10 && r >= t->rst_ratio) {
            if (add_anomaly(out, SEV_WARN, "Połączenia zrywane RST",
                    "%.0f%% przepływów TCP (%llu z %llu) zawiera flagę RST. Typowe dla "
                    "skanowania portów, odrzucanych połączeń lub awarii usług.",
                    100.0 * r, (unsigned long long)rst_flows,
                    (unsigned long long)s->tcp_flows) != 0)
                return -1;
        }
    }

    /* Nietypowe kombinacje flag */
    uint64_t odd = s->f_null + s->f_xmas + s->f_synfin;
    if (odd > 0) {
        if (add_anomaly(out, SEV_WARN, "Nietypowe flagi TCP",
                "Wykryto pakiety z flagami niespotykanymi w normalnym ruchu: NULL (brak "
                "flag): %llu, XMAS (FIN+PSH+URG): %llu, SYN+FIN: %llu. Takie pakiety "
                "wysyłają skanery (np. nmap -sN/-sX) w celu rozpoznania systemu.",
                (unsigned long long)s->f_null, (unsigned long long)s->f_xmas,
                (unsigned long long)s->f_synfin) != 0)
            return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Detektor 6: UDP flood                                               */
/* ------------------------------------------------------------------ */

typedef struct {
    ip_addr_t victim, attacker;
    uint64_t  pkts;
    double    first, last;
} udp_rec_t;

static int cmp_udp(const void *x, const void *y)
{
    const udp_rec_t *p = x, *q = y;
    int c = addr_cmp(&p->victim, &q->victim);
    return c ? c : addr_cmp(&p->attacker, &q->attacker);
}

static int detect_udpflood(const stats_t *s, const thresholds_t *t, anomalies_t *out)
{
    udp_rec_t *r = malloc((s->n_flows ? s->n_flows : 1) * sizeof *r);
    if (r == NULL)
        return -1;
    size_t n = 0;
    for (size_t i = 0; i < s->n_flows; i++) {
        const flow_t *f = s->flows[i];
        if (f->proto != PROTO_UDP)
            continue;
        /* "Ofiara" to strona, która więcej odbiera, niż wysyła. */
        int to_srv = f->pkts[DIR_C2S] >= f->pkts[DIR_S2C];
        r[n].victim   = to_srv ? f->srv : f->cli;
        r[n].attacker = to_srv ? f->cli : f->srv;
        r[n].pkts     = to_srv ? f->pkts[DIR_C2S] : f->pkts[DIR_S2C];
        r[n].first    = f->first_ts;
        r[n].last     = f->last_ts;
        n++;
    }
    qsort(r, n, sizeof *r, cmp_udp);

    size_t i = 0;
    while (i < n) {
        size_t j = i;
        uint64_t pkts = 0;
        uint32_t sources = 0;
        double first = r[i].first, last = r[i].last;
        while (j < n && addr_cmp(&r[j].victim, &r[i].victim) == 0) {
            pkts += r[j].pkts;
            if (j == i || addr_cmp(&r[j].attacker, &r[j - 1].attacker) != 0)
                sources++;
            if (r[j].first < first) first = r[j].first;
            if (r[j].last > last)   last = r[j].last;
            j++;
        }
        double span = last - first;
        if (span < 1.0)
            span = 1.0;
        double pps = (double)pkts / span;
        if (pkts >= 1000 && pps >= t->udpflood_pps) {
            char v[ADDR_STR_LEN];
            addr_to_str(&r[i].victim, v);
            if (add_anomaly(out, SEV_CRIT, "UDP flood",
                    "Host %s otrzymał %llu pakietów UDP w %.1f s (średnio %.0f pakietów/s) "
                    "od %u nadawców. Tak duże natężenie może oznaczać atak DoS.",
                    v, (unsigned long long)pkts, span, pps, sources) != 0) {
                free(r);
                return -1;
            }
        }
        i = j;
    }
    free(r);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Detektor 7: skoki natężenia ruchu                                   */
/* ------------------------------------------------------------------ */

static int detect_spikes(const stats_t *s, const thresholds_t *t, anomalies_t *out)
{
    if (s->tl_len < 10)
        return 0;     /* za krótkie nagranie, by mówić o statystyce */

    /* Średnia i odchylenie standardowe liczby pakietów na sekundę. */
    double sum = 0, sum2 = 0;
    for (size_t i = 0; i < s->tl_len; i++) {
        double v = s->timeline[i].pkts[0] + s->timeline[i].pkts[1];
        sum += v;
        sum2 += v * v;
    }
    double mean = sum / s->tl_len;
    double var = sum2 / s->tl_len - mean * mean;
    double sd = var > 0 ? sqrt(var) : 0;
    double limit = mean + t->spike_sigma * sd;

    size_t count = 0, max_i = 0;
    double max_v = 0;
    for (size_t i = 0; i < s->tl_len; i++) {
        double v = s->timeline[i].pkts[0] + s->timeline[i].pkts[1];
        if (v > limit && v >= 2 * mean && v >= 100) {
            count++;
            if (v > max_v) { max_v = v; max_i = i; }
        }
    }
    out->spike_count = count;
    if (count > 0) {
        if (add_anomaly(out, SEV_WARN, "Skok natężenia ruchu",
                "Liczba sekund, w których ruch przekroczył %.0f pakietów/s (średnia %.1f + "
                "%.0f odchyleń standardowych): %zu. Największy skok: %.0f pakietów w %zu. "
                "sekundzie nagrania.", limit, mean, t->spike_sigma, count, max_v, max_i) != 0)
            return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */

static int cmp_anomaly_sev(const void *x, const void *y)
{
    const anomaly_t *p = x, *q = y;
    return (int)q->severity - (int)p->severity;   /* najpierw najpoważniejsze */
}

int anomalies_detect(const stats_t *s, const thresholds_t *t, anomalies_t *out)
{
    memset(out, 0, sizeof *out);
    if (detect_scans(s, t, out) != 0)      return -1;
    if (detect_synflood(s, t, out) != 0)   return -1;
    if (detect_tcp_health(s, t, out) != 0) return -1;
    if (detect_udpflood(s, t, out) != 0)   return -1;
    if (detect_spikes(s, t, out) != 0)     return -1;
    if (out->n > 1)
        qsort(out->items, out->n, sizeof *out->items, cmp_anomaly_sev);
    return 0;
}

void anomalies_free(anomalies_t *a)
{
    free(a->items);
    free(a->fanout);
    memset(a, 0, sizeof *a);
}
