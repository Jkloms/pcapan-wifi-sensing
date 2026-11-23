/*
 * stats.c - implementacja zbierania statystyk (opis w stats.h).
 *
 * Najważniejsze techniki użyte w tym pliku:
 *   1. Tablica haszująca z łańcuchowaniem (chaining) - szybkie wyszukiwanie
 *      przepływu/hosta po kluczu. Funkcja haszująca zamienia klucz na numer
 *      kubełka; elementy o tym samym numerze tworzą listę jednokierunkową.
 *   2. Tablica dynamiczna (realloc) - tablica, która rośnie w miarę potrzeb
 *      (podwajamy pojemność, gdy się zapełni).
 */
#include <stdlib.h>
#include <string.h>
#include "stats.h"

const char *SIZE_BIN_LABELS[SIZE_BINS] = {
    "<64", "64-127", "128-255", "256-511", "512-1023", "1024-1518", ">1518"
};

/* Ograniczenie długości osi czasu (7 dni po 1 s) - chroni przed zużyciem
 * pamięci, gdy plik ma błędne znaczniki czasu. */
#define TL_MAX_SECONDS (7u * 24u * 3600u)

/* ------------------------------------------------------------------ */
/* Funkcje pomocnicze                                                  */
/* ------------------------------------------------------------------ */

/* Prosta funkcja haszująca FNV-1a: miesza bajty klucza w liczbę 32-bitową. */
static uint32_t fnv1a(const void *data, size_t len, uint32_t h)
{
    const uint8_t *p = data;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

#define FNV_INIT 2166136261u

static uint32_t hash_addr(const ip_addr_t *a)
{
    return fnv1a(a->b, sizeof a->b, fnv1a(&a->family, 1, FNV_INIT));
}

/* Hash "jednego końca" połączenia (adres + port). */
static uint32_t hash_endpoint(const ip_addr_t *a, uint16_t port)
{
    return fnv1a(&port, sizeof port, hash_addr(a));
}

/*
 * Hash przepływu musi być SYMETRYCZNY: pakiet A->B i odpowiedź B->A muszą
 * trafić do tego samego kubełka. Dlatego łączymy hashe obu końców
 * operacją XOR, która jest przemienna (x ^ y == y ^ x).
 */
static uint32_t hash_flow(uint8_t proto, const ip_addr_t *a, uint16_t pa,
                          const ip_addr_t *b, uint16_t pb)
{
    return (hash_endpoint(a, pa) ^ hash_endpoint(b, pb)) + proto;
}

/*
 * Generyczne dopisanie wskaźnika do tablicy dynamicznej.
 * 'void ***arr' to wskaźnik na zmienną typu 'void **' - musimy go przekazać,
 * bo realloc może przenieść tablicę w inne miejsce pamięci.
 */
static int push_ptr(void ***arr, size_t *n, size_t *cap, void *item)
{
    if (*n == *cap) {
        size_t new_cap = *cap ? *cap * 2 : 256;
        void **tmp = realloc(*arr, new_cap * sizeof **arr);
        if (tmp == NULL)
            return -1;
        *arr = tmp;
        *cap = new_cap;
    }
    (*arr)[(*n)++] = item;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Tworzenie i zwalnianie                                              */
/* ------------------------------------------------------------------ */

stats_t *stats_create(void)
{
    /* calloc = malloc + wyzerowanie pamięci. Wszystkie liczniki startują od 0. */
    stats_t *s = calloc(1, sizeof *s);
    if (s == NULL)
        return NULL;
    s->tcp_port_pkts = calloc(65536, sizeof(uint64_t));
    s->udp_port_pkts = calloc(65536, sizeof(uint64_t));
    s->flow_hash_size = FLOW_HASH_INIT;
    s->host_hash_size = HOST_HASH_INIT;
    s->flow_hash     = calloc(s->flow_hash_size, sizeof(flow_t *));
    s->host_hash     = calloc(s->host_hash_size, sizeof(host_t *));
    if (!s->tcp_port_pkts || !s->udp_port_pkts || !s->flow_hash || !s->host_hash) {
        stats_free(s);
        return NULL;
    }
    s->first_ts = -1.0;   /* -1 oznacza "jeszcze nie było pakietu" */
    return s;
}

void stats_free(stats_t *s)
{
    if (s == NULL)
        return;
    /* Każdy malloc/calloc musi mieć swoje free - inaczej wyciek pamięci. */
    for (size_t i = 0; i < s->n_flows; i++)
        free(s->flows[i]);
    for (size_t i = 0; i < s->n_hosts; i++)
        free(s->hosts[i]);
    free(s->flows);
    free(s->hosts);
    free(s->flow_hash);
    free(s->host_hash);
    free(s->tcp_port_pkts);
    free(s->udp_port_pkts);
    free(s->timeline);
    free(s);
}

/* ------------------------------------------------------------------ */
/* Liczniki ogólne, oś czasu, histogram                                */
/* ------------------------------------------------------------------ */

double stats_duration(const stats_t *s)
{
    if (s->first_ts < 0)
        return 0.0;
    return s->last_ts - s->first_ts;
}

/* Aktualizuje czas pierwszego/ostatniego pakietu oraz licznik globalny. */
static void count_global(stats_t *s, const packet_t *p)
{
    if (s->first_ts < 0 || p->ts < s->first_ts)
        s->first_ts = p->ts;
    if (p->ts > s->last_ts)
        s->last_ts = p->ts;
    s->total_pkts++;
    s->total_bytes += p->wire_len;
}

static int size_bin(uint32_t len)
{
    if (len < 64)    return 0;
    if (len < 128)   return 1;
    if (len < 256)   return 2;
    if (len < 512)   return 3;
    if (len < 1024)  return 4;
    if (len <= 1518) return 5;
    return 6;
}

/* Dodaje pakiet do osi czasu. Indeks = numer sekundy od początku pliku. */
static int timeline_add(stats_t *s, const packet_t *p, int proto_idx)
{
    double rel = p->ts - s->first_ts;
    size_t idx = (rel > 0) ? (size_t)rel : 0;   /* rzutowanie double -> size_t obcina ułamek */
    if (idx >= TL_MAX_SECONDS)
        idx = TL_MAX_SECONDS - 1;

    if (idx >= s->tl_cap) {                     /* trzeba powiększyć tablicę */
        size_t new_cap = s->tl_cap ? s->tl_cap : 64;
        while (new_cap <= idx)
            new_cap *= 2;
        tl_bucket_t *tmp = realloc(s->timeline, new_cap * sizeof *tmp);
        if (tmp == NULL)
            return -1;
        /* realloc nie zeruje nowej pamięci - robimy to sami */
        memset(tmp + s->tl_cap, 0, (new_cap - s->tl_cap) * sizeof *tmp);
        s->timeline = tmp;
        s->tl_cap = new_cap;
    }
    if (idx + 1 > s->tl_len)
        s->tl_len = idx + 1;

    s->timeline[idx].pkts[proto_idx]++;
    s->timeline[idx].bytes[proto_idx] += p->wire_len;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Hosty                                                               */
/* ------------------------------------------------------------------ */

/*
 * OPTYMALIZACJA: tablica haszująca, która rośnie.
 * Przy stałej liczbie kubełków (np. 4096) i milionie hostów każda lista
 * miałaby setki elementów, a wyszukiwanie byłoby bardzo wolne. Dlatego gdy
 * elementów jest więcej niż kubełków, podwajamy tablicę i rozkładamy
 * elementy na nowo ("rehash"). Średnia długość listy zostaje <= 1.
 * Każdy element pamięta swój hash, więc nie trzeba go liczyć ponownie.
 */
static int host_hash_grow(stats_t *s)
{
    size_t new_size = s->host_hash_size * 2;
    host_t **nb = calloc(new_size, sizeof *nb);
    if (nb == NULL)
        return -1;
    for (size_t i = 0; i < s->n_hosts; i++) {
        host_t *h = s->hosts[i];
        size_t b = h->hash & (new_size - 1);
        h->hnext = nb[b];
        nb[b] = h;
    }
    free(s->host_hash);
    s->host_hash = nb;
    s->host_hash_size = new_size;
    return 0;
}

static int flow_hash_grow(stats_t *s)
{
    size_t new_size = s->flow_hash_size * 2;
    flow_t **nb = calloc(new_size, sizeof *nb);
    if (nb == NULL)
        return -1;
    for (size_t i = 0; i < s->n_flows; i++) {
        flow_t *f = s->flows[i];
        size_t b = f->hash & (new_size - 1);
        f->hnext = nb[b];
        nb[b] = f;
    }
    free(s->flow_hash);
    s->flow_hash = nb;
    s->flow_hash_size = new_size;
    return 0;
}

/* Znajduje hosta o danym adresie albo tworzy nowego. */
static host_t *host_get(stats_t *s, const ip_addr_t *a)
{
    uint32_t hash = hash_addr(a);
    size_t bucket = hash & (s->host_hash_size - 1);
    for (host_t *h = s->host_hash[bucket]; h != NULL; h = h->hnext)
        if (h->hash == hash && addr_cmp(&h->addr, a) == 0)   /* najpierw tanie porównanie liczb */
            return h;

    host_t *h = calloc(1, sizeof *h);
    if (h == NULL)
        return NULL;
    h->addr = *a;                               /* kopiowanie całej struktury */
    h->hash = hash;
    if (push_ptr((void ***)&s->hosts, &s->n_hosts, &s->cap_hosts, h) != 0) {
        free(h);
        return NULL;
    }
    h->hnext = s->host_hash[bucket];            /* wstawiamy na początek listy */
    s->host_hash[bucket] = h;
    if (s->n_hosts > s->host_hash_size && host_hash_grow(s) != 0)
        return NULL;
    return h;
}

/* ------------------------------------------------------------------ */
/* Przepływy                                                           */
/* ------------------------------------------------------------------ */

/*
 * Decyduje, czy nadawca PIERWSZEGO pakietu przepływu jest klientem.
 * Reguły (heurystyka):
 *   - TCP SYN bez ACK  -> nadawca to klient (otwiera połączenie),
 *   - TCP SYN+ACK      -> nadawca to serwer (odpowiada),
 *   - jeśli tylko jedna strona ma port < 1024 ("dobrze znany"), to ona jest serwerem,
 *   - UDP: klientem jest nadawca pierwszego pakietu,
 *   - TCP bez SYN (nagranie zaczęło się w trakcie połączenia): klientem jest
 *     strona z wyższym portem.
 */
static int sender_is_client(const packet_t *p)
{
    if (p->proto == PROTO_TCP && (p->tcp_flags & TCP_SYN))
        return !(p->tcp_flags & TCP_ACK);
    if (p->sport < 1024 && p->dport >= 1024)
        return 0;
    if (p->dport < 1024 && p->sport >= 1024)
        return 1;
    if (p->proto == PROTO_UDP)
        return 1;      /* UDP nie ma handshake - inicjatorem jest ten, kto nadał pierwszy */
    return p->sport >= p->dport;
}

/*
 * Szuka przepływu pasującego do pakietu (w dowolnym kierunku).
 * Jeśli nie istnieje - tworzy nowy. W *dir zwraca kierunek pakietu.
 */
static flow_t *flow_get(stats_t *s, const packet_t *p, int *dir)
{
    uint32_t hash = hash_flow(p->proto, &p->src, p->sport, &p->dst, p->dport);
    size_t bucket = hash & (s->flow_hash_size - 1);

    for (flow_t *f = s->flow_hash[bucket]; f != NULL; f = f->hnext) {
        if (f->hash != hash || f->proto != p->proto)
            continue;
        if (f->cport == p->sport && f->sport == p->dport &&
            addr_cmp(&f->cli, &p->src) == 0 && addr_cmp(&f->srv, &p->dst) == 0) {
            *dir = DIR_C2S;
            return f;
        }
        if (f->sport == p->sport && f->cport == p->dport &&
            addr_cmp(&f->srv, &p->src) == 0 && addr_cmp(&f->cli, &p->dst) == 0) {
            *dir = DIR_S2C;
            return f;
        }
    }

    /* Nie znaleziono - nowy przepływ. */
    flow_t *f = calloc(1, sizeof *f);
    if (f == NULL)
        return NULL;
    f->proto = p->proto;
    f->hash = hash;
    f->first_ts = p->ts;
    f->rtt = -1.0;
    if (sender_is_client(p)) {
        f->cli = p->src; f->cport = p->sport;
        f->srv = p->dst; f->sport = p->dport;
        *dir = DIR_C2S;
    } else {
        f->cli = p->dst; f->cport = p->dport;
        f->srv = p->src; f->sport = p->sport;
        *dir = DIR_S2C;
    }
    if (push_ptr((void ***)&s->flows, &s->n_flows, &s->cap_flows, f) != 0) {
        free(f);
        return NULL;
    }
    f->hnext = s->flow_hash[bucket];
    s->flow_hash[bucket] = f;
    if (p->proto == PROTO_TCP) s->tcp_flows++;
    else                       s->udp_flows++;
    if (s->n_flows > s->flow_hash_size && flow_hash_grow(s) != 0)
        return NULL;
    return f;
}

/*
 * Analiza TCP w ramach przepływu: etapy handshake, RTT i retransmisje.
 *
 * Retransmisja (uproszczona metoda): każdy bajt danych TCP ma numer
 * sekwencyjny. Pamiętamy najwyższy "koniec" danych (next_seq) wysłanych
 * w danym kierunku. Jeśli przychodzi segment z danymi, którego koniec
 * NIE wychodzi poza next_seq, to te dane już widzieliśmy -> retransmisja.
 * (Pakiety, które przyszły w złej kolejności, też zostaną tak policzone -
 * to świadome uproszczenie.)
 */
static void flow_tcp_update(stats_t *s, flow_t *f, const packet_t *p, int dir)
{
    uint8_t fl = p->tcp_flags;
    f->flags[dir] |= fl;

    /* --- 3-way handshake: SYN -> SYN+ACK -> ACK --- */
    if (dir == DIR_C2S && (fl & TCP_SYN) && !(fl & TCP_ACK)) {
        if (!(f->handshake & HS_SYN))
            f->syn_ts = p->ts;
        f->handshake |= HS_SYN;
    } else if (dir == DIR_S2C && (fl & TCP_SYN) && (fl & TCP_ACK)) {
        if ((f->handshake & HS_SYN) && !(f->handshake & HS_SYNACK))
            f->rtt = p->ts - f->syn_ts;
        f->handshake |= HS_SYNACK;
    } else if (dir == DIR_C2S && (fl & TCP_ACK) && !(fl & TCP_SYN) &&
               (f->handshake & HS_SYNACK)) {
        f->handshake |= HS_ACK;
    }

    /* --- retransmisje --- */
    /* SYN i FIN "zajmują" jeden numer sekwencyjny, tak jak 1 bajt danych. */
    uint32_t seg_len = p->payload_len + ((fl & TCP_SYN) ? 1 : 0) + ((fl & TCP_FIN) ? 1 : 0);
    if (seg_len == 0 || (fl & TCP_RST))
        return;                              /* czyste ACK / RST nie niosą danych */

    uint32_t seg_end = p->seq + seg_len;     /* arytmetyka modulo 2^32 */
    if (!f->seq_valid[dir]) {
        f->next_seq[dir] = seg_end;
        f->seq_valid[dir] = 1;
        return;
    }
    /* Rzutowanie różnicy na int32_t poprawnie obsługuje "zawinięcie"
     * licznika sekwencyjnego po przekroczeniu 2^32. */
    int32_t diff = (int32_t)(seg_end - f->next_seq[dir]);
    if (diff <= 0) {
        f->retrans++;
        s->tcp_retrans++;
    } else {
        f->next_seq[dir] = seg_end;
    }
}

/* ------------------------------------------------------------------ */
/* Główne funkcje                                                      */
/* ------------------------------------------------------------------ */

void stats_add_other(stats_t *s, const packet_t *p, int bad)
{
    count_global(s, p);
    if (bad)
        s->bad_pkts++;
    else {
        s->other_pkts++;
        s->other_bytes += p->wire_len;
    }
}

int stats_add_packet(stats_t *s, const packet_t *p)
{
    count_global(s, p);
    s->size_hist[size_bin(p->wire_len)]++;
    s->payload_bytes += p->payload_len;
    if (p->src.family == 4) s->ipv4_pkts++;
    else                    s->ipv6_pkts++;

    int proto_idx;   /* 0 = TCP, 1 = UDP */
    if (p->proto == PROTO_TCP) {
        proto_idx = 0;
        s->tcp_pkts++;
        s->tcp_bytes += p->wire_len;

        uint8_t fl = p->tcp_flags;
        if ((fl & TCP_SYN) && !(fl & TCP_ACK)) s->f_syn++;
        if ((fl & TCP_SYN) && (fl & TCP_ACK))  s->f_synack++;
        if (fl & TCP_FIN) s->f_fin++;
        if (fl & TCP_RST) s->f_rst++;
        if (fl & TCP_PSH) s->f_psh++;
        if (fl == TCP_ACK && p->payload_len == 0) s->f_ack_only++;
        /* Kombinacje flag niewystępujące w normalnym ruchu: */
        int odd = 0;
        if (fl == 0) { s->f_null++; odd = 1; }                          /* NULL scan */
        if ((fl & (TCP_FIN | TCP_PSH | TCP_URG)) == (TCP_FIN | TCP_PSH | TCP_URG)) {
            s->f_xmas++; odd = 1;                                       /* XMAS scan */
        }
        if ((fl & (TCP_SYN | TCP_FIN)) == (TCP_SYN | TCP_FIN)) { s->f_synfin++; odd = 1; }
        if (odd) {
            if (s->odd_first_ts == 0) {                       /* pierwszy taki pakiet */
                s->odd_first_ts = p->ts;
                s->odd_src = p->src;
            }
            s->odd_last_ts = p->ts;
        }
    } else {
        proto_idx = 1;
        s->udp_pkts++;
        s->udp_bytes += p->wire_len;
    }

    if (timeline_add(s, p, proto_idx) != 0)
        return -1;

    /* Hosty: nadawca i odbiorca. */
    host_t *hs = host_get(s, &p->src);
    host_t *hd = host_get(s, &p->dst);
    if (hs == NULL || hd == NULL)
        return -1;
    hs->pkts_out++; hs->bytes_out += p->wire_len;
    hd->pkts_in++;  hd->bytes_in  += p->wire_len;

    /* Przepływ. */
    int dir;
    flow_t *f = flow_get(s, p, &dir);
    if (f == NULL)
        return -1;
    f->pkts[dir]++;
    f->bytes[dir] += p->wire_len;
    if (p->ts > f->last_ts)
        f->last_ts = p->ts;

    /* Port usługi to port serwera w przepływie. */
    if (p->proto == PROTO_TCP) {
        s->tcp_port_pkts[f->sport]++;
        flow_tcp_update(s, f, p, dir);
    } else {
        s->udp_port_pkts[f->sport]++;
    }
    return 0;
}

flow_state_t flow_state(const flow_t *f)
{
    if (f->proto != PROTO_TCP)
        return FS_UDP;
    int rst = (f->flags[0] | f->flags[1]) & TCP_RST;
    int fin = (f->flags[0] | f->flags[1]) & TCP_FIN;
    if (f->handshake & HS_ACK) {
        if (rst) return FS_EST_RST;
        if (fin) return FS_EST_FIN;
        return FS_EST_OPEN;
    }
    if ((f->handshake & HS_SYN) && rst)        return FS_REJECTED;
    if ((f->handshake & HS_SYN) && (f->handshake & HS_SYNACK))
        return FS_HALF_OPEN;
    if (f->handshake & HS_SYN)                 return FS_NO_REPLY;
    return FS_MIDSTREAM;
}

const char *flow_state_name(flow_state_t st)
{
    /* Tablica napisów indeksowana wartością enum - musi mieć tę samą kolejność. */
    static const char *names[FS_COUNT] = {
        "nawiązane, zamknięte FIN", "nawiązane, otwarte", "nawiązane, zerwane RST",
        "odrzucone (RST)", "brak odpowiedzi na SYN", "półotwarte (brak ACK)",
        "w trakcie (bez handshake)", "UDP"
    };
    return (st < FS_COUNT) ? names[st] : "?";
}

const char *flow_state_str(const flow_t *f)
{
    return flow_state_name(flow_state(f));
}

/* Tablica struktur zainicjalizowana "w miejscu" - wygodny sposób na słownik. */
static const struct { uint8_t proto; uint16_t port; const char *name; } SERVICES[] = {
    { PROTO_TCP, 20, "FTP-data" }, { PROTO_TCP, 21, "FTP" },   { PROTO_TCP, 22, "SSH" },
    { PROTO_TCP, 23, "Telnet" },   { PROTO_TCP, 25, "SMTP" },  { PROTO_TCP, 53, "DNS" },
    { PROTO_TCP, 80, "HTTP" },     { PROTO_TCP, 110, "POP3" }, { PROTO_TCP, 143, "IMAP" },
    { PROTO_TCP, 443, "HTTPS" },   { PROTO_TCP, 445, "SMB" },  { PROTO_TCP, 993, "IMAPS" },
    { PROTO_TCP, 995, "POP3S" },   { PROTO_TCP, 1433, "MSSQL" }, { PROTO_TCP, 3306, "MySQL" },
    { PROTO_TCP, 3389, "RDP" },    { PROTO_TCP, 5432, "PostgreSQL" }, { PROTO_TCP, 6379, "Redis" },
    { PROTO_TCP, 8080, "HTTP-alt" }, { PROTO_TCP, 8443, "HTTPS-alt" },
    { PROTO_UDP, 53, "DNS" },      { PROTO_UDP, 67, "DHCP" },  { PROTO_UDP, 68, "DHCP" },
    { PROTO_UDP, 123, "NTP" },     { PROTO_UDP, 137, "NetBIOS" }, { PROTO_UDP, 161, "SNMP" },
    { PROTO_UDP, 443, "QUIC" },    { PROTO_UDP, 514, "Syslog" }, { PROTO_UDP, 1900, "SSDP" },
    { PROTO_UDP, 5353, "mDNS" },
};

const char *port_service_name(uint8_t proto, uint16_t port)
{
    /* sizeof(tablica) / sizeof(element) = liczba elementów tablicy */
    for (size_t i = 0; i < sizeof SERVICES / sizeof SERVICES[0]; i++)
        if (SERVICES[i].proto == proto && SERVICES[i].port == port)
            return SERVICES[i].name;
    return NULL;
}
