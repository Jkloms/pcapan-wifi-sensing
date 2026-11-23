/*
 * parser.c - czytanie pakietów (libpcap) i ręczne dekodowanie nagłówków:
 * [Ethernet | SLL | radiotap+802.11] -> IPv4/IPv6 -> TCP/UDP.
 * Liczby w sieci są big-endian (rd16/rd32), a w radiotap little-endian (le16/le32).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include "parser.h"

struct parser {
    pcap_t *pcap;
    int     linktype;
};

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86DD
#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_QINQ 0x88A8

static inline uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static inline uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static inline uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static inline uint32_t le32(const uint8_t *p)
{
    return p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

parser_t *parser_open(const char *path, char *errbuf)
{

    char pcap_err[PCAP_ERRBUF_SIZE];
    pcap_t *pc = pcap_open_offline(path, pcap_err);
    if (pc == NULL) {
        snprintf(errbuf, 256, "%s", pcap_err);
        return NULL;
    }

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

static parse_result_t decode_l4(const uint8_t *l4, uint32_t len, packet_t *out)
{
    if (out->proto == PROTO_UDP) {
        if (len < 8)
            return PARSE_BAD;
        out->sport = rd16(l4);
        out->dport = rd16(l4 + 2);
        out->payload_len = len - 8;
        return PARSE_OK;
    }

    if (out->proto == PROTO_TCP) {
        if (len < 20)
            return PARSE_BAD;
        /* długość nagłówka TCP: górne 4 bity bajtu 12, w słowach po 4 B */
        uint32_t hdr_len = (uint32_t)(l4[12] >> 4) * 4;
        if (hdr_len < 20 || hdr_len > len)
            return PARSE_BAD;
        out->sport     = rd16(l4);
        out->dport     = rd16(l4 + 2);
        out->seq       = rd32(l4 + 4);
        out->ack       = rd32(l4 + 8);
        out->tcp_flags = l4[13] & 0x3F;
        out->window    = rd16(l4 + 14);
        out->payload_len = len - hdr_len;
        return PARSE_OK;
    }

    return PARSE_SKIP;
}

static parse_result_t decode_ip(const uint8_t *ip, uint32_t caplen, packet_t *out)
{
    if (caplen < 1)
        return PARSE_BAD;

    int version = ip[0] >> 4;

    if (version == 4) {
        if (caplen < 20)
            return PARSE_BAD;
        uint32_t ihl = (uint32_t)(ip[0] & 0x0F) * 4;
        uint32_t total = rd16(ip + 2);
        if (ihl < 20 || ihl > caplen)
            return PARSE_BAD;
        if (total > caplen || total < ihl)
            total = caplen;

        uint16_t frag_off = rd16(ip + 6) & 0x1FFF;   /* dalsze fragmenty nie mają TCP/UDP */
        if (frag_off != 0)
            return PARSE_SKIP;

        out->src.family = out->dst.family = 4;
        memcpy(out->src.b, ip + 12, 4);
        memcpy(out->dst.b, ip + 16, 4);
        out->ttl   = ip[8];
        out->proto = ip[9];
        return decode_l4(ip + ihl, total - ihl, out);
    }

    if (version == 6) {
        if (caplen < 40)
            return PARSE_BAD;
        uint32_t payload = rd16(ip + 4);
        if (payload > caplen - 40)
            payload = caplen - 40;

        out->src.family = out->dst.family = 6;
        memcpy(out->src.b, ip + 8, 16);
        memcpy(out->dst.b, ip + 24, 16);
        out->ttl   = ip[7];
        out->proto = ip[6];          /* bez nagłówków rozszerzeń (uproszczenie) */
        return decode_l4(ip + 40, payload, out);
    }

    return PARSE_SKIP;
}

/* Radiotap: nagłówek dodawany przez kartę Wi-Fi w trybie monitor.
 * Bity 'present' mówią, które pola są obecne; pola mają wyrównanie (align). */
#define RT_FLAGS    1
#define RT_CHANNEL  3
#define RT_SIGNAL   5
#define RT_NOISE    6
#define RT_FLAG_FCS 0x10

static parse_result_t decode_radiotap(const uint8_t *pkt, uint32_t caplen, packet_t *out)
{
    static const uint8_t align[7] = { 8, 1, 1, 2, 1, 1, 1 };
    static const uint8_t size[7]  = { 8, 1, 1, 4, 2, 1, 1 };

    if (caplen < 8)
        return PARSE_BAD;
    uint32_t rt_len = le16(pkt + 2);
    if (rt_len < 8 || rt_len > caplen)
        return PARSE_BAD;

    uint32_t present = le32(pkt + 4);
    uint32_t off = 8;
    for (uint32_t w = present; w & 0x80000000u; off += 4) {   /* kolejne słowa present */
        if (off + 4 > rt_len)
            return PARSE_BAD;
        w = le32(pkt + off);
    }

    out->has_radio = 1;
    uint8_t rt_flags = 0;
    for (int bit = 0; bit <= RT_NOISE; bit++) {
        if (!(present & (1u << bit)))
            continue;
        off = (off + align[bit] - 1) & ~(uint32_t)(align[bit] - 1);
        if (off + size[bit] > rt_len)
            break;
        const uint8_t *f = pkt + off;
        if (bit == RT_FLAGS)   rt_flags = f[0];
        if (bit == RT_CHANNEL) out->freq = le16(f);
        if (bit == RT_SIGNAL)  { out->rssi = (int8_t)f[0];  out->has_rssi = 1; }
        if (bit == RT_NOISE)   { out->noise = (int8_t)f[0]; out->has_noise = 1; }
        off += size[bit];
    }

    const uint8_t *w = pkt + rt_len;          /* ramka 802.11 */
    uint32_t len = caplen - rt_len;
    if (rt_flags & RT_FLAG_FCS)
        len = (len >= 4) ? len - 4 : 0;       /* suma kontrolna na końcu */
    if (len < 10)
        return PARSE_SKIP;

    uint8_t type = (w[0] >> 2) & 3;           /* 0 zarządzanie, 1 kontrolna, 2 dane */
    uint8_t subtype = w[0] >> 4;
    uint8_t fl = w[1];
    out->retry = (fl & 0x08) ? 1 : 0;
    if (type != 1 && len >= 16) {
        memcpy(out->tx_mac, w + 10, 6);       /* addr2 = nadawca */
        out->has_tx = 1;
    }
    if (type != 2 || (fl & 0x40) || (subtype & 0x04))
        return PARSE_SKIP;                    /* nie dane, zaszyfrowane albo "null data" */

    uint32_t hdr = 24;
    if ((fl & 0x03) == 0x03) hdr += 6;        /* ToDS i FromDS: 4. adres */
    if (subtype & 0x08) {                     /* QoS */
        hdr += 2;
        if (fl & 0x80) hdr += 4;              /* HT control */
    }
    if (len < hdr + 8)
        return PARSE_SKIP;
    const uint8_t *llc = w + hdr;             /* LLC/SNAP: AA AA 03 00 00 00 + EtherType */
    if (llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03)
        return PARSE_SKIP;
    uint16_t et = rd16(llc + 6);
    if (et != ETHERTYPE_IPV4 && et != ETHERTYPE_IPV6)
        return PARSE_SKIP;
    return decode_ip(llc + 8, len - hdr - 8, out);
}

parse_result_t parser_next(parser_t *p, packet_t *out)
{
    struct pcap_pkthdr *hdr;
    const uint8_t *data;

    int rc = pcap_next_ex(p->pcap, &hdr, &data);
    if (rc != 1)
        return PARSE_END;

    memset(out, 0, sizeof *out);
    out->ts = (double)hdr->ts.tv_sec + (double)hdr->ts.tv_usec / 1e6;
    out->wire_len = hdr->len;

    const uint8_t *pkt = data;
    uint32_t caplen = hdr->caplen;
    uint16_t ethertype;

    switch (p->linktype) {
    case DLT_EN10MB:                      /* Ethernet */
        if (caplen < 14)
            return PARSE_BAD;
        ethertype = rd16(pkt + 12);
        pkt += 14;
        caplen -= 14;
        while (ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ) {   /* VLAN: +4 B */
            if (caplen < 4)
                return PARSE_BAD;
            ethertype = rd16(pkt + 2);
            pkt += 4;
            caplen -= 4;
        }
        if (ethertype != ETHERTYPE_IPV4 && ethertype != ETHERTYPE_IPV6)
            return PARSE_SKIP;
        return decode_ip(pkt, caplen, out);

    case DLT_LINUX_SLL:                   /* tcpdump -i any */
        if (caplen < 16)
            return PARSE_BAD;
        ethertype = rd16(pkt + 14);
        if (ethertype != ETHERTYPE_IPV4 && ethertype != ETHERTYPE_IPV6)
            return PARSE_SKIP;
        return decode_ip(pkt + 16, caplen - 16, out);

#ifdef DLT_LINUX_SLL2
    case DLT_LINUX_SLL2:
        if (caplen < 20)
            return PARSE_BAD;
        ethertype = rd16(pkt);
        if (ethertype != ETHERTYPE_IPV4 && ethertype != ETHERTYPE_IPV6)
            return PARSE_SKIP;
        return decode_ip(pkt + 20, caplen - 20, out);
#endif

    case DLT_NULL:
    case DLT_LOOP:
        if (caplen < 4)
            return PARSE_BAD;
        return decode_ip(pkt + 4, caplen - 4, out);

    case DLT_IEEE802_11_RADIO:
        return decode_radiotap(pkt, caplen, out);

    case DLT_RAW:
#ifdef DLT_IPV4
    case DLT_IPV4:
    case DLT_IPV6:
#endif
        return decode_ip(pkt, caplen, out);

    default:
        return PARSE_SKIP;
    }
}
