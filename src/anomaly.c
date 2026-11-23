/* anomaly.c - wykrywanie ataków (dodatek): skanowanie portów i sieci, SYN flood,
 * UDP flood, połączenia zrywane RST, nietypowe flagi TCP. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <math.h>
#include "anomaly.h"

void thresholds_default(thresholds_t *t)
{
    t->scan_min_ports  = 15;
    t->sweep_min_hosts = 15;
    t->synflood_min    = 100;
    t->rst_ratio       = 0.30;
    t->udpflood_pps    = 500.0;
}

const char *severity_name(severity_t s)
{
    switch (s) {
    case SEV_CRIT: return "KRYTYCZNE";
    case SEV_WARN: return "OSTRZEŻENIE";
    default:       return "INFO";
    }
}

static const char *ADV_PORTSCAN =
    "Zablokuj adres źródłowy na zaporze (firewall). Sprawdź, czy wykryte otwarte porty "
    "są naprawdę potrzebne, i wyłącz zbędne usługi. Rozważ IDS/IPS (np. Suricata) "
    "lub fail2ban, który blokuje skanery automatycznie.";
static const char *ADV_UDPSCAN =
    "Zablokuj adres źródłowy i ogranicz ruch UDP do hosta docelowego tylko do "
    "potrzebnych portów. Jeśli natężenie jest duże, potraktuj to jak atak DoS "
    "(zobacz UDP flood).";
static const char *ADV_SWEEP =
    "Zablokuj źródło. Jeśli to adres z Twojej sieci, sprawdź ten komputer pod kątem "
    "złośliwego oprogramowania (robaki skanują sieć w poszukiwaniu ofiar). "
    "Ogranicz dostęp do tego portu segmentacją sieci.";
static const char *ADV_SYNFLOOD =
    "Włącz SYN cookies na serwerze (sysctl net.ipv4.tcp_syncookies=1), ogranicz "
    "liczbę nowych połączeń na sekundę (rate limiting) i rozważ ochronę anty-DDoS "
    "u dostawcy. Blokowanie pojedynczych adresów nie pomoże, bo są fałszowane.";
static const char *ADV_UDPFLOOD =
    "Ogranicz ruch UDP do atakowanego hosta na brzegu sieci (rate limiting), "
    "zablokuj nadawców i nieużywane porty UDP. Przy trwającym ataku skontaktuj się "
    "z dostawcą Internetu.";
static const char *ADV_RST =
    "Sprawdź, czy usługi docelowe działają i czy zapora nie odrzuca połączeń. "
    "Jeśli RST są skutkiem skanowania, zobacz incydenty skanowania.";
static const char *ADV_FLAGS =
    "Zablokuj nadawcę. Zapora śledząca stan połączeń (stateful firewall) odrzuca "
    "takie pakiety automatycznie - upewnij się, że jest włączona.";

static anomaly_t *add_anomaly(anomalies_t *out, severity_t sev, const char *cat,
                              const char *advice, const char *fmt, ...)
{
    if (out->n == out->cap) {
        size_t nc = out->cap ? out->cap * 2 : 16;
        anomaly_t *tmp = realloc(out->items, nc * sizeof *tmp);
        if (tmp == NULL)
            return NULL;
        out->items = tmp;
        out->cap = nc;
    }
    anomaly_t *a = &out->items[out->n++];
    memset(a, 0, sizeof *a);
    a->severity = sev;
    a->advice = advice;
    snprintf(a->category, sizeof a->category, "%s", cat);

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(a->text, sizeof a->text, fmt, ap);   /* bezpieczny printf do bufora */
    va_end(ap);
    return a;
}

/* Pomocnicze "settery" - uzupełniają pola incydentu. */
static void set_src(anomaly_t *a, const ip_addr_t *ip)
{
    a->src_ip = *ip;
    a->has_src_ip = 1;
    addr_to_str(ip, a->source);
}

static void set_dst(anomaly_t *a, const ip_addr_t *ip, int port)
{
    char buf[ADDR_STR_LEN];
    a->dst_ip = *ip;
    a->has_dst_ip = 1;
    addr_to_str(ip, buf);
    if (port >= 0) snprintf(a->target, sizeof a->target, "%s:%d", buf, port);
    else           snprintf(a->target, sizeof a->target, "%s", buf);
}

/* Rekord pomocniczy: "a próbowało połączyć się z b na porcie port". */
typedef struct {
    ip_addr_t a, b;
    uint16_t  port;
    uint8_t   proto;     /* PROTO_TCP / PROTO_UDP */
    uint8_t   failed;    /* 1 = brak udanego połączenia */
    uint8_t   open;      /* 1 = serwer odpowiedział (port otwarty) */
    double    first, last;
} attempt_t;

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

static int detect_scans(const stats_t *s, const thresholds_t *t, anomalies_t *out)
{
    if (s->n_flows == 0)
        return 0;
    attempt_t *att = malloc(s->n_flows * sizeof *att);
    size_t fan_cap = 64, fan_n = 0;
    fanout_t *fan = malloc(fan_cap * sizeof *fan);
    if (att == NULL || fan == NULL)
        goto oom;

    size_t n = 0;
    for (size_t i = 0; i < s->n_flows; i++) {
        const flow_t *f = s->flows[i];
        att[n].a = f->cli;
        att[n].b = f->srv;
        att[n].port = f->sport;
        att[n].proto = f->proto;
        att[n].failed = (uint8_t)flow_failed(f);
        att[n].open = (uint8_t)flow_open(f);
        att[n].first = f->first_ts;
        att[n].last = f->last_ts;
        n++;
    }

    /* ---- Skanowanie portów: grupy (klient, serwer, protokół), liczymy różne porty ---- */
    qsort(att, n, sizeof *att, cmp_a_b_port);

    size_t i = 0;
    while (i < n) {
        /* [i, j) to grupa rekordów z tym samym klientem 'a' */
        size_t j = i;
        uint32_t cli_targets = 0, cli_failed = 0;
        while (j < n && addr_cmp(&att[j].a, &att[i].a) == 0) {
            /* [j, k) - podgrupa: ten sam klient, serwer 'b' i protokół */
            size_t k = j;
            uint32_t ports = 0, failed = 0;
            double first = att[j].first, last = att[j].last;
            char open_list[128] = "";
            int open_shown = 0;
            while (k < n && addr_cmp(&att[k].a, &att[j].a) == 0 &&
                   addr_cmp(&att[k].b, &att[j].b) == 0 && att[k].proto == att[j].proto) {
                if (att[k].first < first) first = att[k].first;
                if (att[k].last > last)   last = att[k].last;
                /* nowy port tylko wtedy, gdy różni się od poprzedniego rekordu */
                if (k == j || att[k].port != att[k - 1].port) {
                    ports++;
                    if (att[k].failed) failed++;
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
                severity_t sev = (ports >= 100) ? SEV_CRIT : SEV_WARN;
                anomaly_t *an;
                if (att[j].proto == PROTO_TCP)
                    an = add_anomaly(out, sev, "Skanowanie portów TCP", ADV_PORTSCAN,
                        "Próby połączenia z %u różnymi portami TCP, z czego %u nieudanych. "
                        "Odpowiedziały (są otwarte) porty: %s.",
                        ports, failed, open_shown ? open_list : "brak");
                else
                    an = add_anomaly(out, sev, "Skanowanie portów UDP", ADV_UDPSCAN,
                        "Pakiety UDP wysłane na %u różnych portów, z czego %u bez żadnej "
                        "odpowiedzi. To wzorzec skanowania UDP albo zalewu pakietami na "
                        "losowe porty. Odpowiedziały porty: %s.",
                        ports, failed, open_shown ? open_list : "brak");
                if (an == NULL)
                    goto oom;
                set_src(an, &att[j].a);
                set_dst(an, &att[j].b, -1);
                an->t_start = first;
                an->t_end = last;
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

    /* ---- Skanowanie sieci: grupy (klient, protokół, port), liczymy różne serwery ---- */
    qsort(att, n, sizeof *att, cmp_a_port_b);
    i = 0;
    while (i < n) {
        size_t j = i;
        uint32_t hosts = 0, failed = 0;
        double first = att[i].first, last = att[i].last;
        while (j < n && addr_cmp(&att[j].a, &att[i].a) == 0 && att[j].port == att[i].port &&
               att[j].proto == att[i].proto) {
            if (att[j].first < first) first = att[j].first;
            if (att[j].last > last)   last = att[j].last;
            if (j == i || addr_cmp(&att[j].b, &att[j - 1].b) != 0) {
                hosts++;
                if (att[j].failed) failed++;
            }
            j++;
        }
        if ((int)hosts >= t->sweep_min_hosts && failed * 2 >= hosts) {
            anomaly_t *an = add_anomaly(out, SEV_WARN, "Skanowanie sieci", ADV_SWEEP,
                    "Próby połączenia z portem %s/%u na %u różnych hostach, z czego %u "
                    "nieudanych.", att[i].proto == PROTO_TCP ? "TCP" : "UDP",
                    att[i].port, hosts, failed);
            if (an == NULL)
                goto oom;
            set_src(an, &att[i].a);
            snprintf(an->target, sizeof an->target, "%u hostów, port %u", hosts, att[i].port);
            an->t_start = first;
            an->t_end = last;
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

static int cmp_double(const void *x, const void *y)
{
    double a = *(const double *)x, b = *(const double *)y;
    return (a > b) - (a < b);
}

static int detect_synflood(const stats_t *s, const thresholds_t *t, anomalies_t *out)
{
    /* czasy nieudanych prób w bieżącej grupie - do wyznaczenia okna ataku */
    double *times = malloc((s->n_flows ? s->n_flows : 1) * sizeof *times);
    if (times == NULL)
        return -1;
    /* Rekordy: a = serwer, port = port usługi, b = klient. */
    attempt_t *att = malloc((s->n_flows ? s->n_flows : 1) * sizeof *att);
    if (att == NULL) {
        free(times);
        return -1;
    }
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
        att[n].first = f->first_ts;
        att[n].last = f->last_ts;
        n++;
    }
    qsort(att, n, sizeof *att, cmp_a_port_b);

    size_t i = 0;
    while (i < n) {
        size_t j = i;
        uint32_t total = 0, incomplete = 0, sources = 0;
        while (j < n && addr_cmp(&att[j].a, &att[i].a) == 0 && att[j].port == att[i].port) {
            total++;
            if (att[j].failed)
                times[incomplete++] = att[j].first;   /* czas nieudanej próby */
            if (j == i || addr_cmp(&att[j].b, &att[j - 1].b) != 0)
                sources++;
            j++;
        }
        if ((int)incomplete >= t->synflood_min && incomplete * 2 >= total) {
            /* Okno ataku: od 1. do 99. percentyla czasów - pojedyncze próby
             * daleko od głównej fali (np. ze skanera) nie rozciągają okna. */
            qsort(times, incomplete, sizeof *times, cmp_double);
            double first = times[incomplete / 100];
            double last = times[incomplete - 1 - incomplete / 100];
            anomaly_t *an = add_anomaly(out, SEV_CRIT, "SYN flood", ADV_SYNFLOOD,
                    "%u prób połączenia TCP, z czego %u nie zostało dokończonych (%.0f%%), "
                    "z %u różnych adresów źródłowych. Tak wiele adresów sugeruje ich "
                    "fałszowanie (spoofing).",
                    total, incomplete, 100.0 * incomplete / total, sources);
            if (an == NULL) {
                free(att);
                free(times);
                return -1;
            }
            set_dst(an, &att[i].a, att[i].port);
            snprintf(an->source, sizeof an->source, "%u adresów%s", sources,
                     sources > 50 ? " (fałszowane)" : "");
            an->t_start = first;
            an->t_end = last;
        }
        i = j;
    }
    free(att);
    free(times);
    return 0;
}

static int detect_tcp_health(const stats_t *s, const thresholds_t *t, anomalies_t *out)
{
    if (s->tcp_pkts == 0)
        return 0;

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
            anomaly_t *an = add_anomaly(out, SEV_WARN, "Połączenia zrywane RST", ADV_RST,
                    "%.0f%% przepływów TCP (%llu z %llu) zawiera flagę RST. Typowe dla "
                    "skanowania portów, odrzucanych połączeń lub awarii usług.",
                    100.0 * r, (unsigned long long)rst_flows,
                    (unsigned long long)s->tcp_flows);
            if (an == NULL)
                return -1;
            snprintf(an->source, sizeof an->source, "różne");
            snprintf(an->target, sizeof an->target, "różne");
        }
    }

    /* Nietypowe kombinacje flag */
    uint64_t odd = s->f_null + s->f_xmas + s->f_synfin;
    if (odd > 0) {
        anomaly_t *an = add_anomaly(out, SEV_WARN, "Nietypowe flagi TCP", ADV_FLAGS,
                "Pakiety z flagami niespotykanymi w normalnym ruchu: NULL (brak flag): "
                "%llu, XMAS (FIN+PSH+URG): %llu, SYN+FIN: %llu. Wysyłają je skanery "
                "(np. nmap -sN/-sX), żeby rozpoznać system operacyjny i zaporę.",
                (unsigned long long)s->f_null, (unsigned long long)s->f_xmas,
                (unsigned long long)s->f_synfin);
        if (an == NULL)
            return -1;
        set_src(an, &s->odd_src);
        snprintf(an->target, sizeof an->target, "-");
        an->t_start = s->odd_first_ts;
        an->t_end = s->odd_last_ts;
    }
    return 0;
}

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
        uint64_t pkts = 0, top_pkts = 0, cur_pkts = 0;
        uint32_t sources = 0;
        size_t top_idx = i;
        double first = r[i].first, last = r[i].last;
        while (j < n && addr_cmp(&r[j].victim, &r[i].victim) == 0) {
            pkts += r[j].pkts;
            if (j == i || addr_cmp(&r[j].attacker, &r[j - 1].attacker) != 0) {
                sources++;
                cur_pkts = 0;
            }
            cur_pkts += r[j].pkts;
            if (cur_pkts > top_pkts) { top_pkts = cur_pkts; top_idx = j; }
            if (r[j].first < first) first = r[j].first;
            if (r[j].last > last)   last = r[j].last;
            j++;
        }
        double span = last - first;
        if (span < 1.0)
            span = 1.0;
        double pps = (double)pkts / span;
        if (pkts >= 1000 && pps >= t->udpflood_pps) {
            anomaly_t *an = add_anomaly(out, SEV_CRIT, "UDP flood", ADV_UDPFLOOD,
                    "%llu pakietów UDP w %.1f s (średnio %.0f pakietów/s) od %u nadawców. "
                    "Tak duże natężenie może oznaczać atak DoS.",
                    (unsigned long long)pkts, span, pps, sources);
            if (an == NULL) {
                free(r);
                return -1;
            }
            set_dst(an, &r[i].victim, -1);
            if (sources == 1) {
                set_src(an, &r[top_idx].attacker);
            } else {
                char a[ADDR_STR_LEN];
                addr_to_str(&r[top_idx].attacker, a);
                snprintf(an->source, sizeof an->source, "%u adresów (najwięcej %s)", sources, a);
                an->src_ip = r[top_idx].attacker;
                an->has_src_ip = 1;
            }
            an->t_start = first;
            an->t_end = last;
        }
        i = j;
    }
    free(r);
    return 0;
}

static int cmp_anomaly_sev(const void *x, const void *y)
{
    const anomaly_t *p = x, *q = y;
    if (p->severity != q->severity)
        return (int)q->severity - (int)p->severity;   /* najpierw najpoważniejsze */
    return (p->t_start > q->t_start) - (p->t_start < q->t_start);  /* potem wg czasu */
}

int anomalies_detect(const stats_t *s, const thresholds_t *t, anomalies_t *out)
{
    memset(out, 0, sizeof *out);
    if (detect_scans(s, t, out) != 0)      return -1;
    if (detect_synflood(s, t, out) != 0)   return -1;
    if (detect_tcp_health(s, t, out) != 0) return -1;
    if (detect_udpflood(s, t, out) != 0)   return -1;
    if (out->n > 1)
        qsort(out->items, out->n, sizeof *out->items, cmp_anomaly_sev);
    return 0;
}

/* Szuka adresu na liście; jeśli go nie ma - dopisuje. Zwraca wskaźnik na wpis. */
void anomalies_free(anomalies_t *a)
{
    free(a->items);
    free(a->fanout);
    memset(a, 0, sizeof *a);
}
