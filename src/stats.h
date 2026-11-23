/*
 * stats.h - zbieranie statystyk ruchu.
 *
 * Moduł dostaje pakiety jeden po drugim (stats_add_packet) i aktualizuje:
 *   - liczniki globalne (pakiety, bajty, TCP/UDP),
 *   - oś czasu (ruch w każdej sekundzie),
 *   - rozkład rozmiarów pakietów,
 *   - statystyki hostów (kto ile wysłał / odebrał),
 *   - statystyki portów usług,
 *   - tabelę PRZEPŁYWÓW (flow) - czyli "rozmów" między dwoma gniazdami.
 *
 * Przepływ = (protokół, IP klienta, port klienta, IP serwera, port serwera).
 * Pakiety w obu kierunkach należą do tego samego przepływu.
 */
#ifndef PCAPAN_STATS_H
#define PCAPAN_STATS_H

#include "common.h"

/* Kierunki w przepływie - indeksy w tablicach [2]. */
#define DIR_C2S 0   /* klient -> serwer */
#define DIR_S2C 1   /* serwer -> klient */

/* Bity pola flow_t.handshake - które etapy 3-way handshake TCP widzieliśmy. */
#define HS_SYN    0x01   /* klient wysłał SYN */
#define HS_SYNACK 0x02   /* serwer odpowiedział SYN+ACK */
#define HS_ACK    0x04   /* klient potwierdził ACK -> połączenie nawiązane */

/* Przedziały histogramu rozmiarów pakietów. */
#define SIZE_BINS 7
extern const char *SIZE_BIN_LABELS[SIZE_BINS];

/* Jeden przepływ (połączenie TCP albo "sesja" UDP). */
typedef struct flow {
    uint8_t   proto;
    ip_addr_t cli, srv;          /* klient (inicjator) i serwer */
    uint16_t  cport, sport;      /* port klienta i port serwera (usługi) */
    double    first_ts, last_ts;
    uint64_t  pkts[2];           /* pakiety w kierunku [DIR_C2S] i [DIR_S2C] */
    uint64_t  bytes[2];

    /* Stan TCP: */
    uint8_t   flags[2];          /* suma (OR) flag TCP widzianych w danym kierunku */
    uint8_t   handshake;         /* bity HS_* */
    double    syn_ts;            /* czas pierwszego SYN */
    double    rtt;               /* czas SYN -> SYN+ACK (sek.), -1 gdy nieznany */
    uint32_t  next_seq[2];       /* najwyższy oczekiwany numer sekwencyjny */
    uint8_t   seq_valid[2];      /* czy next_seq jest już ustawione */
    uint32_t  retrans;           /* liczba retransmisji w tym przepływie */

    struct flow *hnext;          /* następny element w tym samym kubełku tablicy haszującej */
} flow_t;

/* Statystyki jednego hosta (adresu IP). */
typedef struct host {
    ip_addr_t addr;
    uint64_t  pkts_out, bytes_out;   /* wysłane */
    uint64_t  pkts_in,  bytes_in;    /* odebrane */
    struct host *hnext;
} host_t;

/* Ruch w jednej sekundzie (punkt na osi czasu). Indeks [0]=TCP, [1]=UDP. */
typedef struct {
    uint32_t pkts[2];
    uint64_t bytes[2];
} tl_bucket_t;

/* Rozmiary tablic haszujących (liczba kubełków). Potęga dwójki -> szybkie "& (N-1)". */
#define FLOW_HASH_SIZE (1u << 16)
#define HOST_HASH_SIZE (1u << 12)

/* Główna struktura ze wszystkimi statystykami. */
typedef struct {
    /* --- liczniki globalne --- */
    uint64_t total_pkts, total_bytes;   /* wszystkie pakiety z pliku */
    uint64_t tcp_pkts, tcp_bytes;
    uint64_t udp_pkts, udp_bytes;
    uint64_t other_pkts, other_bytes;   /* np. ARP, ICMP */
    uint64_t bad_pkts;                  /* uszkodzone / obcięte */
    uint64_t ipv4_pkts, ipv6_pkts;      /* tylko TCP/UDP */
    uint64_t payload_bytes;             /* suma danych aplikacji TCP+UDP */
    double   first_ts, last_ts;         /* czas pierwszego i ostatniego pakietu */

    /* --- flagi TCP (liczba pakietów) --- */
    uint64_t f_syn, f_synack, f_fin, f_rst, f_psh, f_ack_only;
    uint64_t f_null, f_xmas, f_synfin;  /* nietypowe kombinacje - typowe dla skanerów */
    uint64_t tcp_retrans;               /* suma retransmisji */

    /* --- histogram rozmiarów --- */
    uint64_t size_hist[SIZE_BINS];

    /* --- oś czasu: tablica dynamiczna, 1 element = 1 sekunda --- */
    tl_bucket_t *timeline;
    size_t       tl_len;     /* ile sekund jest używanych */
    size_t       tl_cap;     /* ile miejsca zaalokowano */

    /* --- porty usług: liczba pakietów na port serwera (tablice 65536 el.) --- */
    uint64_t *tcp_port_pkts;
    uint64_t *udp_port_pkts;

    /* --- hosty: tablica haszująca + lista do iteracji --- */
    host_t  **host_hash;
    host_t  **hosts;         /* tablica wskaźników na wszystkie hosty */
    size_t    n_hosts, cap_hosts;

    /* --- przepływy: tablica haszująca + lista do iteracji --- */
    flow_t  **flow_hash;
    flow_t  **flows;
    size_t    n_flows, cap_flows;
    uint64_t  tcp_flows, udp_flows;
} stats_t;

/* Tworzy pustą strukturę statystyk (NULL przy braku pamięci). */
stats_t *stats_create(void);

/* Dodaje pakiet TCP/UDP. Zwraca 0 przy sukcesie, -1 przy braku pamięci. */
int stats_add_packet(stats_t *s, const packet_t *p);

/* Rejestruje pakiet, który nie jest TCP/UDP ('bad' = 1 jeśli był uszkodzony). */
void stats_add_other(stats_t *s, const packet_t *p, int bad);

/* Czas trwania przechwytywania w sekundach. */
double stats_duration(const stats_t *s);

/* Krótki opis stanu przepływu TCP, np. "nawiązane, zamknięte FIN". */
const char *flow_state_str(const flow_t *f);

/* Nazwa popularnej usługi dla portu (np. 443 -> "HTTPS") albo NULL. */
const char *port_service_name(uint8_t proto, uint16_t port);

/* Zwalnia całą pamięć. */
void stats_free(stats_t *s);

#endif
