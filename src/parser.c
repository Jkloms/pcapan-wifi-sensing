/*
 * parser.c - odczyt pakietów z pliku .pcap (biblioteka libpcap) i ręczne
 * dekodowanie nagłówków: Ethernet -> IPv4/IPv6 -> TCP/UDP.
 *
 * Jak wygląda pakiet w pliku (dla zwykłego Ethernetu):
 *
 *   +-----------+-------------+--------------+------------------+
 *   | Ethernet  | IPv4 / IPv6 | TCP albo UDP |  dane aplikacji  |
 *   |  14 B     |  20+ / 40 B |  20+ / 8 B   |   (payload)      |
 *   +-----------+-------------+--------------+------------------+
 *
 * Dekodujemy bajty "ręcznie" (funkcje rd16/rd32), zamiast rzutować wskaźnik
 * na struktury systemowe. Jest to czytelniejsze i bezpieczne, bo:
 *   - liczby w sieci zapisane są w kolejności big-endian ("network order"),
 *     a procesory x86 używają little-endian - rd16/rd32 to uwzględniają,
 *   - zawsze sprawdzamy, czy pakiet nie jest za krótki (ochrona przed
 *     czytaniem poza tablicą - częsty błąd bezpieczeństwa w C).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include "parser.h"

/* Właściwa definicja struktury, którą parser.h tylko zapowiedział. */
struct parser {
    pcap_t *pcap;      /* uchwyt libpcap do otwartego pliku */
    int     linktype;  /* typ warstwy łącza (Ethernet, Linux SLL, surowe IP...) */
};

/* EtherType - informuje, co jest wewnątrz ramki Ethernet. */
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86DD
#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_QINQ 0x88A8

/* Odczyt liczby 16- i 32-bitowej zapisanej w kolejności sieciowej (big-endian).
 * 'static' = funkcja widoczna tylko w tym pliku.
 * 'inline' = podpowiedź dla kompilatora, by wkleił kod zamiast wywoływać funkcję. */
static inline uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static inline uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

parser_t *parser_open(const char *path, char *errbuf)
{
    /* pcap_open_offline obsługuje zarówno klasyczny .pcap, jak i .pcapng */
    char pcap_err[PCAP_ERRBUF_SIZE];
    pcap_t *pc = pcap_open_offline(path, pcap_err);
    if (pc == NULL) {
        snprintf(errbuf, 256, "%s", pcap_err);
        return NULL;
    }

    /* malloc rezerwuje pamięć na stercie; trzeba ją potem zwolnić free() */
    parser_t *p = malloc(sizeof *p);
    if (p == NULL) {
        snprintf(errbuf, 256, "brak pamięci");
        pcap_close(pc);
        return NULL;
    }
    p->pcap = pc;
    p->linktype = pcap_datalink(pc);
    return p;
}

const char *parser_linktype_name(const parser_t *p)
{
    const char *name = pcap_datalink_val_to_name(p->linktype);
    return name ? name : "nieznany";
}

void parser_close(parser_t *p)
{
    if (p == NULL)
        return;
    pcap_close(p->pcap);
    free(p);
}

/*
 * Dekoduje nagłówek TCP albo UDP.
 * 'l4' wskazuje początek nagłówka, 'len' to liczba bajtów do końca pakietu IP.
 */
static parse_result_t decode_l4(const uint8_t *l4, uint32_t len, packet_t *out)
{
    if (out->proto == PROTO_UDP) {
        if (len < 8)                       /* nagłówek UDP ma zawsze 8 bajtów */
            return PARSE_BAD;
        out->sport = rd16(l4);
        out->dport = rd16(l4 + 2);
        out->payload_len = len - 8;
        return PARSE_OK;
    }

    if (out->proto == PROTO_TCP) {
        if (len < 20)                      /* minimalny nagłówek TCP: 20 bajtów */
            return PARSE_BAD;
        /* Długość nagłówka TCP (data offset) to górne 4 bity bajtu nr 12,
         * wyrażona w słowach 4-bajtowych. ">> 4" przesuwa bity w prawo. */
        uint32_t hdr_len = (uint32_t)(l4[12] >> 4) * 4;
        if (hdr_len < 20 || hdr_len > len)
            return PARSE_BAD;
        out->sport     = rd16(l4);
        out->dport     = rd16(l4 + 2);
        out->seq       = rd32(l4 + 4);
        out->ack       = rd32(l4 + 8);
        out->tcp_flags = l4[13] & 0x3F;    /* "& 0x3F" zostawia 6 najniższych bitów */
        out->window    = rd16(l4 + 14);
        out->payload_len = len - hdr_len;
        return PARSE_OK;
    }

    return PARSE_SKIP;                     /* np. ICMP, GRE, ... */
}

/* Dekoduje pakiet IPv4 albo IPv6 zaczynający się pod adresem 'ip'. */
static parse_result_t decode_ip(const uint8_t *ip, uint32_t caplen, packet_t *out)
{
    if (caplen < 1)
        return PARSE_BAD;

    int version = ip[0] >> 4;              /* wersja IP: górne 4 bity pierwszego bajtu */

    if (version == 4) {
        if (caplen < 20)
            return PARSE_BAD;
        uint32_t ihl = (uint32_t)(ip[0] & 0x0F) * 4;   /* długość nagłówka IP */
        uint32_t total = rd16(ip + 2);                 /* długość całego pakietu IP */
        if (ihl < 20 || ihl > caplen)
            return PARSE_BAD;
        if (total > caplen || total < ihl)   /* pakiet obcięty przy przechwytywaniu */
            total = caplen;

        /* Fragmenty IP (poza pierwszym) nie zawierają nagłówka TCP/UDP. */
        uint16_t frag_off = rd16(ip + 6) & 0x1FFF;
        if (frag_off != 0)
            return PARSE_SKIP;

        out->src.family = out->dst.family = 4;
        memcpy(out->src.b, ip + 12, 4);   /* adres źródłowy: bajty 12-15 */
        memcpy(out->dst.b, ip + 16, 4);   /* adres docelowy: bajty 16-19 */
        out->ttl   = ip[8];
        out->proto = ip[9];
        return decode_l4(ip + ihl, total - ihl, out);
    }

    if (version == 6) {
        if (caplen < 40)                   /* nagłówek IPv6 ma stałe 40 bajtów */
            return PARSE_BAD;
        uint32_t payload = rd16(ip + 4);
        if (payload > caplen - 40)
            payload = caplen - 40;

        out->src.family = out->dst.family = 6;
        memcpy(out->src.b, ip + 8, 16);
        memcpy(out->dst.b, ip + 24, 16);
        out->ttl   = ip[7];
        out->proto = ip[6];                /* "next header"; nagłówków rozszerzeń
                                              nie analizujemy - to uproszczenie */
        return decode_l4(ip + 40, payload, out);
    }

    return PARSE_SKIP;
}

parse_result_t parser_next(parser_t *p, packet_t *out)
{
    struct pcap_pkthdr *hdr;   /* nagłówek rekordu: czas, długości */
    const uint8_t *data;       /* bajty pakietu */

    /* pcap_next_ex zwraca: 1 = OK, -2 = koniec pliku, -1 = błąd */
    int rc = pcap_next_ex(p->pcap, &hdr, &data);
    if (rc != 1)
        return PARSE_END;

    /* Zerujemy całą strukturę, żeby nie zostały śmieci z poprzedniego pakietu. */
    memset(out, 0, sizeof *out);
    out->ts = (double)hdr->ts.tv_sec + (double)hdr->ts.tv_usec / 1e6;
    out->wire_len = hdr->len;

    const uint8_t *pkt = data;
    uint32_t caplen = hdr->caplen;   /* ile bajtów faktycznie zapisano w pliku */
    uint16_t ethertype;

    /* Każdy typ łącza ma inny nagłówek przed pakietem IP. */
    switch (p->linktype) {
    case DLT_EN10MB:                           /* Ethernet */
        if (caplen < 14)
            return PARSE_BAD;
        ethertype = rd16(pkt + 12);
        pkt += 14;                             /* arytmetyka wskaźników: przesuwamy się o 14 B */
        caplen -= 14;
        /* Znaczniki VLAN (802.1Q) - może ich być kilka, każdy ma 4 bajty. */
        while (ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ) {
            if (caplen < 4)
                return PARSE_BAD;
            ethertype = rd16(pkt + 2);
            pkt += 4;
            caplen -= 4;
        }
        if (ethertype != ETHERTYPE_IPV4 && ethertype != ETHERTYPE_IPV6)
            return PARSE_SKIP;                 /* np. ARP */
        return decode_ip(pkt, caplen, out);

    case DLT_LINUX_SLL:                        /* "Linux cooked capture" (tcpdump -i any) */
        if (caplen < 16)
            return PARSE_BAD;
        ethertype = rd16(pkt + 14);
        if (ethertype != ETHERTYPE_IPV4 && ethertype != ETHERTYPE_IPV6)
            return PARSE_SKIP;
        return decode_ip(pkt + 16, caplen - 16, out);

#ifdef DLT_LINUX_SLL2
    case DLT_LINUX_SLL2:                       /* nowsza wersja "cooked capture" */
        if (caplen < 20)
            return PARSE_BAD;
        ethertype = rd16(pkt);
        if (ethertype != ETHERTYPE_IPV4 && ethertype != ETHERTYPE_IPV6)
            return PARSE_SKIP;
        return decode_ip(pkt + 20, caplen - 20, out);
#endif

    case DLT_NULL:                             /* loopback BSD/macOS: 4 B nagłówka */
    case DLT_LOOP:
        if (caplen < 4)
            return PARSE_BAD;
        return decode_ip(pkt + 4, caplen - 4, out);

    case DLT_RAW:                              /* surowe pakiety IP bez warstwy łącza */
#ifdef DLT_IPV4
    case DLT_IPV4:
    case DLT_IPV6:
#endif
        return decode_ip(pkt, caplen, out);

    default:
        return PARSE_SKIP;                     /* nieobsługiwany typ łącza */
    }
}
