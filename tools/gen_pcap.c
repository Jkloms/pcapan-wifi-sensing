/*
 * gen_pcap.c - generator plików testowych dla pcapan.
 *
 * Buduje pakiety bajt po bajcie i zapisuje je przez libpcap (pcap_dump).
 * Pliki Wi-Fi mają nagłówek radiotap z RSSI i szumem, a "ruch człowieka"
 * symulujemy większymi wahaniami RSSI w wybranych okresach.
 *
 *   wifi_spokoj.pcap      - pusty pokój, normalny ruch sieciowy
 *   wifi_ruch.pcap        - 3 okresy ruchu
 *   wifi_zaklocenia.pcap  - zakłócenia radiowe, wolne łącze, przerwa
 *   wifi_mix.pcap         - wszystko naraz (przykładowy raport)
 *   eth_ataki.pcap        - Ethernet: skan portów, SYN flood, UDP flood
 *
 * Użycie: ./tools/gen_pcap KATALOG   albo   ./tools/gen_pcap KATALOG big
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <pcap/pcap.h>

/* Pakiety zbieramy w pamięci, sortujemy po czasie i dopiero zapisujemy. */

#define MAX_PKT 1600

typedef struct {
    double   ts;
    uint32_t len;
    uint8_t *data;     /* bufor o dokładnym rozmiarze pakietu (oszczędność pamięci) */
} rawpkt_t;

typedef struct {
    rawpkt_t *pkts;
    size_t n, cap;
    int wifi;          /* 1 = radiotap + 802.11 zamiast Ethernetu */
} capture_t;

static rawpkt_t *cap_new(capture_t *c, double ts)
{
    if (c->n == c->cap) {
        c->cap = c->cap ? c->cap * 2 : 1024;
        c->pkts = realloc(c->pkts, c->cap * sizeof *c->pkts);
        if (c->pkts == NULL) {
            fprintf(stderr, "brak pamięci\n");
            exit(1);
        }
    }
    rawpkt_t *p = &c->pkts[c->n++];
    p->ts = ts;
    p->len = 0;
    p->data = calloc(1, MAX_PKT);       /* na czas budowania - maksymalny rozmiar */
    if (p->data == NULL) {
        fprintf(stderr, "brak pamięci\n");
        exit(1);
    }
    return p;
}

/* Po zbudowaniu pakietu zmniejszamy bufor do faktycznej długości. */
static void cap_done(rawpkt_t *p, uint32_t len)
{
    p->len = len;
    uint8_t *tmp = realloc(p->data, len);
    if (tmp != NULL)
        p->data = tmp;
}

static void cap_free(capture_t *c)
{
    for (size_t i = 0; i < c->n; i++)
        free(c->pkts[i].data);
    free(c->pkts);
}

static int cmp_ts(const void *a, const void *b)
{
    double x = ((const rawpkt_t *)a)->ts, y = ((const rawpkt_t *)b)->ts;
    return (x > y) - (x < y);
}

static int cap_write(capture_t *c, const char *path)
{
    qsort(c->pkts, c->n, sizeof *c->pkts, cmp_ts);
    pcap_t *dead = pcap_open_dead(c->wifi ? DLT_IEEE802_11_RADIO : DLT_EN10MB, 65535);
    pcap_dumper_t *d = pcap_dump_open(dead, path);
    if (d == NULL) {
        fprintf(stderr, "%s: %s\n", path, pcap_geterr(dead));
        pcap_close(dead);
        return -1;
    }
    for (size_t i = 0; i < c->n; i++) {
        struct pcap_pkthdr h;
        h.ts.tv_sec = (time_t)c->pkts[i].ts;
        h.ts.tv_usec = (suseconds_t)((c->pkts[i].ts - (double)h.ts.tv_sec) * 1e6);
        h.caplen = h.len = c->pkts[i].len;
        pcap_dump((u_char *)d, &h, c->pkts[i].data);
    }
    pcap_dump_close(d);
    pcap_close(dead);
    printf("  %-22s %6zu pakietów\n", path, c->n);
    return 0;
}

/* Własny generator liczb losowych - stałe ziarno = powtarzalne pliki. */

static uint64_t rng_state = 0x9E3779B97F4A7C15ull;

static uint32_t rnd(void)            /* algorytm xorshift64 */
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (uint32_t)(rng_state >> 16);
}

static double rnd01(void) { return (rnd() & 0xFFFFFF) / (double)0x1000000; }

static double gauss(void)            /* rozkład normalny N(0,1), metoda Boxa-Mullera */
{
    double u = rnd01() + 1e-9, v = rnd01();
    return sqrt(-2 * log(u)) * cos(2 * M_PI * v);
}

static void wr16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xFF; }
static void wr32(uint8_t *p, uint32_t v) { wr16(p, v >> 16); wr16(p + 2, v & 0xFFFF); }

/* Adres IPv4 z czterech liczb, np. IP(10,0,0,1). */
#define IP(a, b, c, d) (((uint32_t)(a) << 24) | ((b) << 16) | ((c) << 8) | (d))

/* Suma kontrolna Internetu (RFC 1071): suma słów 16-bitowych z przeniesieniem. */
static uint32_t csum_add(uint32_t sum, const uint8_t *p, size_t len)
{
    for (size_t i = 0; i + 1 < len; i += 2)
        sum += (uint32_t)(p[i] << 8 | p[i + 1]);
    if (len & 1)
        sum += (uint32_t)p[len - 1] << 8;
    return sum;
}

static uint16_t csum_fold(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

/* Nagłówek Ethernet: MAC docelowy, MAC źródłowy, EtherType. */
static void eth_header(uint8_t *p, uint32_t src_ip, uint32_t dst_ip, uint16_t ethertype)
{
    uint8_t dst[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t src[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00 };
    wr32(dst + 2, dst_ip);           /* MAC "wyprowadzony" z adresu IP - wystarczy do testów */
    wr32(src + 2, src_ip);
    memcpy(p, dst, 6);
    memcpy(p + 6, src, 6);
    wr16(p + 12, ethertype);
}

/* ---- Wi-Fi: model otoczenia ---- */

typedef struct { double t0, t1; } period_t;

static struct {
    period_t motion[4];  int n_motion;     /* ktoś chodzi po pokoju */
    period_t interf[2];  int n_interf;     /* obce źródło sygnału na kanale */
    period_t slow;                         /* wolne, gubiące pakiety łącze */
    period_t gap;                          /* brak ruchu sieciowego */
} env;

static int in(const period_t *p, int n, double t)
{
    for (int i = 0; i < n; i++)
        if (t >= p[i].t0 && t < p[i].t1)
            return 1;
    return 0;
}

static const uint8_t BSSID[6] = { 0x02, 0xAA, 0x00, 0x00, 0x00, 0x01 };

/* Radiotap (16 B): flags, rate, channel, sygnał dBm, szum dBm. */
static void radiotap(uint8_t *p, double ts, int base_rssi)
{
    double rssi = base_rssi + 0.7 * gauss();
    if (in(env.motion, env.n_motion, ts))   /* ruch: odbicia od ciała zmieniają sygnał */
        rssi = base_rssi + 4 * sin(2 * M_PI * ts / 1.7) + 3 * gauss();
    int bad = in(env.interf, env.n_interf, ts);
    double noise = bad ? -80 + 2 * gauss() : -95 + gauss();

    memset(p, 0, 16);
    p[2] = 16;                                 /* długość nagłówka (LE) */
    p[4] = 0x6E;                               /* present: bity 1,2,3,5,6 */
    p[9] = 108;                                /* 54 Mb/s w jednostkach 500 kb/s */
    p[10] = 2437 & 0xFF; p[11] = 2437 >> 8;    /* kanał 6 */
    p[12] = 0xC0;                              /* 2,4 GHz, OFDM */
    p[14] = (uint8_t)(int8_t)lround(rssi);
    p[15] = (uint8_t)(int8_t)lround(noise);
}

static int retry_bit(double ts)
{
    double prob = in(env.interf, env.n_interf, ts) ? 0.4 : 0.03;
    return rnd01() < prob ? 0x08 : 0;
}

static void mac_of(uint8_t *m, uint32_t ip)
{
    m[0] = 0x02; m[1] = 0x00;
    wr32(m + 2, ip);
}

/* Warstwa łącza: Ethernet albo radiotap + 802.11 + LLC/SNAP. Zwraca długość. */
static size_t link_header(capture_t *c, uint8_t *p, double ts, uint32_t src, uint32_t dst,
                          uint16_t ethertype)
{
    if (!c->wifi) {
        eth_header(p, src, dst, ethertype);
        return 14;
    }
    int from_client = (src >> 24) == 10;       /* 10.x.x.x = sieć lokalna */
    uint32_t cli = from_client ? src : dst;
    radiotap(p, ts, from_client ? -56 - (int)(cli & 7) : -48);
    uint8_t *w = p + 16;
    w[0] = 0x08;                               /* ramka danych */
    w[1] = (from_client ? 0x01 : 0x02) | retry_bit(ts);   /* ToDS / FromDS */
    uint8_t a_cli[6], a_other[6];
    mac_of(a_cli, cli);
    mac_of(a_other, from_client ? dst : src);
    memcpy(w + 4,  from_client ? BSSID : a_cli, 6);        /* odbiorca */
    memcpy(w + 10, from_client ? a_cli : BSSID, 6);        /* nadawca */
    memcpy(w + 16, a_other, 6);
    uint8_t *llc = w + 24;
    llc[0] = 0xAA; llc[1] = 0xAA; llc[2] = 0x03;
    llc[3] = llc[4] = llc[5] = 0;
    wr16(llc + 6, ethertype);
    return 16 + 24 + 8;
}

/* Beacon punktu dostępowego (co 102,4 ms). */
static void add_beacon(capture_t *c, double ts)
{
    rawpkt_t *p = cap_new(c, ts);
    radiotap(p->data, ts, -48);
    uint8_t *w = p->data + 16;
    w[0] = 0x80;                               /* zarządzanie, beacon */
    memset(w + 4, 0xFF, 6);
    memcpy(w + 10, BSSID, 6);
    memcpy(w + 16, BSSID, 6);
    uint8_t *body = w + 24;                    /* timestamp(8) interval(2) capab(2) SSID */
    wr16(body + 8, 0x6400);
    body[12] = 0;
    body[13] = 7;
    memcpy(body + 14, "HackNet", 7);
    cap_done(p, 16 + 24 + 14 + 7);
}

/* Nagłówek IPv4 (20 bajtów) z sumą kontrolną. */
static void ipv4_header(uint8_t *p, uint32_t src, uint32_t dst, uint8_t proto,
                        uint16_t total_len, uint8_t ttl)
{
    p[0] = 0x45;                     /* wersja 4, długość nagłówka 5*4 = 20 B */
    p[1] = 0;
    wr16(p + 2, total_len);
    wr16(p + 4, (uint16_t)rnd());    /* identyfikator */
    wr16(p + 6, 0x4000);             /* flaga "Don't Fragment" */
    p[8] = ttl;
    p[9] = proto;
    wr16(p + 10, 0);
    wr32(p + 12, src);
    wr32(p + 16, dst);
    wr16(p + 10, csum_fold(csum_add(0, p, 20)));
}

/* Suma kontrolna TCP/UDP liczona z "pseudo-nagłówkiem" IPv4. */
static uint16_t l4_checksum_v4(uint32_t src, uint32_t dst, uint8_t proto,
                               const uint8_t *l4, uint16_t len)
{
    uint8_t ph[12];
    wr32(ph, src);
    wr32(ph + 4, dst);
    ph[8] = 0;
    ph[9] = proto;
    wr16(ph + 10, len);
    return csum_fold(csum_add(csum_add(0, ph, 12), l4, len));
}

/* Pakiet TCP. Dane wypełniamy literami, by były czytelne w Wiresharku. */
static void add_tcp(capture_t *c, double ts, uint32_t src, uint32_t dst,
                    uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack,
                    uint8_t flags, uint16_t payload, uint16_t window)
{
    if (payload > 1460) payload = 1460;
    rawpkt_t *p = cap_new(c, ts);
    size_t l2 = link_header(c, p->data, ts, src, dst, 0x0800);
    uint8_t *ip = p->data + l2, *tcp = ip + 20;
    uint16_t tcp_len = 20 + payload;

    ipv4_header(ip, src, dst, 6, 20 + tcp_len, 64);
    wr16(tcp, sport);
    wr16(tcp + 2, dport);
    wr32(tcp + 4, seq);
    wr32(tcp + 8, ack);
    tcp[12] = 5 << 4;                /* długość nagłówka 5*4 = 20 B */
    tcp[13] = flags;
    wr16(tcp + 14, window);
    for (int i = 0; i < payload; i++)
        tcp[20 + i] = 'a' + (i % 26);
    wr16(tcp + 16, l4_checksum_v4(src, dst, 6, tcp, tcp_len));
    cap_done(p, l2 + 20 + tcp_len);
}

static void add_udp(capture_t *c, double ts, uint32_t src, uint32_t dst,
                    uint16_t sport, uint16_t dport, uint16_t payload)
{
    if (payload > 1472) payload = 1472;
    rawpkt_t *p = cap_new(c, ts);
    size_t l2 = link_header(c, p->data, ts, src, dst, 0x0800);
    uint8_t *ip = p->data + l2, *udp = ip + 20;
    uint16_t udp_len = 8 + payload;

    ipv4_header(ip, src, dst, 17, 20 + udp_len, 64);
    wr16(udp, sport);
    wr16(udp + 2, dport);
    wr16(udp + 4, udp_len);
    for (int i = 0; i < payload; i++)
        udp[8 + i] = (uint8_t)rnd();
    wr16(udp + 6, l4_checksum_v4(src, dst, 17, udp, udp_len));
    cap_done(p, l2 + 20 + udp_len);
}

/* Pakiet UDP w IPv6 (adresy fe80::X), żeby przetestować obsługę IPv6. */
static void add_udp6(capture_t *c, double ts, uint8_t src_last, uint8_t dst_last,
                     uint16_t sport, uint16_t dport, uint16_t payload)
{
    rawpkt_t *p = cap_new(c, ts);
    size_t l2 = link_header(c, p->data, ts, IP(10, 0, 0, src_last), IP(10, 0, 0, dst_last), 0x86DD);
    uint8_t *ip = p->data + l2, *udp = ip + 40;
    uint16_t udp_len = 8 + payload;
    ip[0] = 0x60;                    /* wersja 6 */
    wr16(ip + 4, udp_len);
    ip[6] = 17;                      /* next header = UDP */
    ip[7] = 64;                      /* hop limit */
    ip[8] = 0xfe; ip[9] = 0x80; ip[23] = src_last;
    ip[24] = 0xfe; ip[25] = 0x80; ip[39] = dst_last;
    wr16(udp, sport);
    wr16(udp + 2, dport);
    wr16(udp + 4, udp_len);
    cap_done(p, l2 + 40 + udp_len);
}

/* Ramka ARP - nie jest IP, więc analizator policzy ją jako "inne". */
static void add_arp(capture_t *c, double ts, uint32_t src, uint32_t target)
{
    rawpkt_t *p = cap_new(c, ts);
    size_t l2 = link_header(c, p->data, ts, src, 0xFFFFFFFF, 0x0806);
    uint8_t *a = p->data + l2;
    wr16(a, 1); wr16(a + 2, 0x0800); a[4] = 6; a[5] = 4; wr16(a + 6, 1);
    wr32(a + 14, src);
    wr32(a + 24, target);
    cap_done(p, l2 + 28);
}

/* Sesja TCP: handshake, żądanie, odpowiedź w segmentach, FIN. "loss" = szansa
 * zgubienia segmentu (wtedy retransmisja). Zwraca czas końca sesji. */
static double tcp_session(capture_t *c, double t, uint32_t cli, uint16_t cport,
                          uint32_t srv, uint16_t sport, int req, int resp,
                          double rtt, double loss)
{
    uint32_t cs = rnd(), ss = rnd();    /* początkowe numery sekwencyjne */
    double h = rtt / 2;                  /* czas przelotu w jedną stronę */

    add_tcp(c, t, cli, srv, cport, sport, cs, 0, 0x02, 0, 64240);            /* SYN */
    add_tcp(c, t + h, srv, cli, sport, cport, ss, cs + 1, 0x12, 0, 65160);   /* SYN+ACK */
    t += rtt;
    add_tcp(c, t, cli, srv, cport, sport, cs + 1, ss + 1, 0x10, 0, 502);     /* ACK */
    cs++; ss++;

    add_tcp(c, t + 0.0002, cli, srv, cport, sport, cs, ss, 0x18, req, 502);  /* żądanie */
    cs += req;
    t += h + 0.002;                      /* czas "myślenia" serwera */

    int sent = 0;
    while (sent < resp) {
        int seg = resp - sent > 1460 ? 1460 : resp - sent;
        add_tcp(c, t, srv, cli, sport, cport, ss, cs, 0x10 | (sent + seg >= resp ? 0x08 : 0),
                seg, 509);
        if (rnd01() < loss)              /* zgubiony - wysyłamy jeszcze raz po timeout */
            add_tcp(c, t + 0.2 + rtt, srv, cli, sport, cport, ss, cs, 0x10, seg, 509);
        ss += seg;
        sent += seg;
        t += 0.0004;
        if ((sent / 1460) % 2 == 0)      /* klient potwierdza co drugi segment */
            add_tcp(c, t + h, cli, srv, cport, sport, cs, ss, 0x10, 0, 502);
    }
    t += h + 0.01;
    add_tcp(c, t, cli, srv, cport, sport, cs, ss, 0x11, 0, 502);             /* FIN+ACK */
    add_tcp(c, t + h, srv, cli, sport, cport, ss, cs + 1, 0x11, 0, 509);     /* FIN+ACK */
    add_tcp(c, t + rtt, cli, srv, cport, sport, cs + 1, ss + 1, 0x10, 0, 502);
    return t + rtt;
}

static const uint32_t DNS_SRV = IP(10, 0, 0, 1);

static void normal_traffic(capture_t *c, double t0, double dur, double loss)
{
    const uint32_t servers[] = { IP(93, 184, 216, 34), IP(142, 250, 74, 46),
                                 IP(151, 101, 1, 69), IP(104, 16, 132, 229),
                                 IP(10, 0, 0, 5) };
    const double rtts[] = { 0.025, 0.012, 0.040, 0.018, 0.0008 };
    const uint16_t ports[] = { 443, 443, 80, 443, 22 };

    double t = t0;
    while (t < t0 + dur) {
        if (t >= env.gap.t0 && t < env.gap.t1) {   /* przerwa - nic nie wysyłamy */
            t = env.gap.t1;
            continue;
        }
        int slow = t >= env.slow.t0 && t < env.slow.t1;
        uint32_t cli = IP(10, 0, 0, 10 + rnd() % 15);
        int s = rnd() % 5;
        static uint16_t next_port = 40000;
        uint16_t cport = next_port;
        next_port = next_port >= 59990 ? 40000 : next_port + 2;   /* bez powtórzeń portów */

        /* zapytanie DNS przed połączeniem */
        add_udp(c, t, cli, DNS_SRV, cport + 1, 53, 40);
        add_udp(c, t + 0.003, DNS_SRV, cli, 53, cport + 1, 120);

        int resp = 500 + rnd() % 15000;
        if (rnd() % 20 == 0)
            resp = 100000 + rnd() % 200000;     /* czasem większy transfer */
        tcp_session(c, t + 0.004, cli, cport, servers[s], ports[s], 200 + rnd() % 400,
                    resp, rtts[s] * (0.8 + 0.4 * rnd01()) * (slow ? 8 : 1) + (slow ? 0.15 : 0),
                    slow ? 0.25 : loss);

        if (rnd() % 8 == 0) {                    /* synchronizacja czasu NTP */
            add_udp(c, t + 0.1, cli, IP(162, 159, 200, 1), 123, 123, 48);
            add_udp(c, t + 0.12, IP(162, 159, 200, 1), cli, 123, 123, 48);
        }
        if (rnd() % 6 == 0)                      /* trochę ruchu nie-IP i IPv6 */
            add_arp(c, t + 0.05, cli, IP(10, 0, 0, 1));
        if (rnd() % 10 == 0)
            add_udp6(c, t + 0.07, 0x10, 0xfb, 5353, 5353, 80);

        t += 0.05 + rnd01() * 0.4;
    }
}

static void port_scan(capture_t *c, double t0)
{
    const uint32_t scanner = IP(10, 0, 0, 66), target = IP(10, 0, 0, 5);
    const uint16_t open[] = { 22, 80, 443, 3306 };
    double t = t0;
    for (uint16_t port = 1; port <= 1024; port++) {
        uint16_t sp = 54321;
        uint32_t seq = rnd();
        int is_open = 0;
        for (int i = 0; i < 4; i++)
            if (open[i] == port) is_open = 1;
        add_tcp(c, t, scanner, target, sp, port, seq, 0, 0x02, 0, 1024);          /* SYN */
        if (is_open) {
            add_tcp(c, t + 0.0005, target, scanner, port, sp, rnd(), seq + 1, 0x12, 0, 65160);
            add_tcp(c, t + 0.001, scanner, target, sp, port, seq + 1, 0, 0x04, 0, 0); /* RST */
        } else {
            add_tcp(c, t + 0.0005, target, scanner, port, sp, 0, seq + 1, 0x14, 0, 0); /* RST+ACK */
        }
        t += 0.004;
    }
    /* Kilka pakietów z "dziwnymi" flagami (NULL, XMAS, SYN+FIN) */
    for (int i = 0; i < 20; i++) {
        add_tcp(c, t, scanner, target, 54322, 20 + i, rnd(), 0, 0x00, 0, 1024);
        add_tcp(c, t + 0.001, scanner, target, 54323, 20 + i, rnd(), 0, 0x29, 0, 1024);
        add_tcp(c, t + 0.002, scanner, target, 54324, 20 + i, rnd(), 0, 0x03, 0, 1024);
        t += 0.01;
    }
}

static void syn_flood_n(capture_t *c, double t0, int count, double gap)
{
    const uint32_t victim = IP(10, 0, 0, 5);
    for (int i = 0; i < count; i++) {
        double t = t0 + i * gap;
        uint32_t spoofed = IP(1 + rnd() % 222, rnd() % 256, rnd() % 256, 1 + rnd() % 254);
        uint32_t seq = rnd();
        uint16_t sp = 1024 + rnd() % 60000;
        add_tcp(c, t, spoofed, victim, sp, 80, seq, 0, 0x02, 0, 512);
        if (i % 4 == 0)   /* serwer odpowiada tylko na część - reszta "ginie" */
            add_tcp(c, t + 0.0003, victim, spoofed, 80, sp, rnd(), seq + 1, 0x12, 0, 65160);
    }
}

static void syn_flood(capture_t *c, double t0) { syn_flood_n(c, t0, 4000, 0.001); }

static void udp_flood(capture_t *c, double t0)
{
    const uint32_t attacker = IP(203, 0, 113, 99), victim = IP(10, 0, 0, 20);
    for (int i = 0; i < 8000; i++)
        add_udp(c, t0 + i * 0.0005, attacker, victim, 40000 + rnd() % 2000,
                1 + rnd() % 65000, 512);
}

typedef void (*scenario_fn)(capture_t *);   /* wskaźnik na funkcję */

static const double T0 = 1763906400.0;      /* 2025-11-23 14:00:00 UTC */

static void wifi(capture_t *c, double dur)
{
    c->wifi = 1;
    for (double t = T0; t < T0 + dur; t += 0.1024)
        add_beacon(c, t);
    normal_traffic(c, T0, dur, 0.0);
}

#define P(a, b) (period_t){ T0 + (a), T0 + (b) }

static void sc_spokoj(capture_t *c) { wifi(c, 120); }
static void sc_ruch(capture_t *c)
{
    env.motion[0] = P(20, 35); env.motion[1] = P(60, 68); env.motion[2] = P(90, 110);
    env.n_motion = 3;
    wifi(c, 120);
}
static void sc_zaklocenia(capture_t *c)
{
    env.interf[0] = P(30, 50); env.n_interf = 1;
    env.slow = P(70, 80);
    env.gap = P(95, 100);
    wifi(c, 120);
}
static void sc_mix(capture_t *c)
{
    env.motion[0] = P(15, 30); env.motion[1] = P(100, 118); env.motion[2] = P(150, 160);
    env.n_motion = 3;
    env.interf[0] = P(45, 60); env.n_interf = 1;
    env.slow = P(75, 85);
    env.gap = P(128, 133);
    wifi(c, 180);
}
static void sc_ataki(capture_t *c)
{
    normal_traffic(c, T0, 120, 0.02);
    port_scan(c, T0 + 20);
    syn_flood(c, T0 + 55);
    udp_flood(c, T0 + 85);
}

/* Duży plik do testów wydajności: ok. 2 mln pakietów i ponad 1 mln przepływów. */
static void sc_big(capture_t *c)
{
    normal_traffic(c, T0, 300, 0.01);
    syn_flood_n(c, T0 + 10, 1500000, 0.0002);
    port_scan(c, T0 + 100);
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[2], "big") == 0) {
        /* tryb: ./tools/gen_pcap KATALOG big */
        capture_t c = { 0 };
        char path[512];
        snprintf(path, sizeof path, "%s/big.pcap", argv[1]);
        sc_big(&c);
        int rc = cap_write(&c, path);
        cap_free(&c);
        return rc ? 1 : 0;
    }
    if (argc != 2) {
        fprintf(stderr, "Użycie: %s KATALOG [big]\n", argv[0]);
        return 2;
    }
    const struct { const char *name; scenario_fn fn; } list[] = {
        { "wifi_spokoj.pcap", sc_spokoj }, { "wifi_ruch.pcap", sc_ruch },
        { "wifi_zaklocenia.pcap", sc_zaklocenia }, { "wifi_mix.pcap", sc_mix },
        { "eth_ataki.pcap", sc_ataki },
    };
    printf("Generowanie przykładowych plików:\n");
    for (size_t i = 0; i < sizeof list / sizeof list[0]; i++) {
        capture_t c = { 0 };
        memset(&env, 0, sizeof env);
        rng_state = 0x9E3779B97F4A7C15ull + i;
        list[i].fn(&c);
        char path[512];
        snprintf(path, sizeof path, "%s/%s", argv[1], list[i].name);
        if (cap_write(&c, path) != 0)
            return 1;
        cap_free(&c);
    }
    return 0;
}
