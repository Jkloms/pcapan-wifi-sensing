/* common.h - wspólne typy: adres IP i zdekodowany pakiet. */
#ifndef PCAPAN_COMMON_H
#define PCAPAN_COMMON_H

#include <stdint.h>
#include <stddef.h>

#define PROTO_TCP 6
#define PROTO_UDP 17

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

#define ADDR_STR_LEN 46

/* IPv4 zajmuje 4 pierwsze bajty, reszta zera - można porównywać memcmp(). */
typedef struct {
    uint8_t family;   /* 4 albo 6 */
    uint8_t b[16];
} ip_addr_t;

typedef struct {
    double    ts;          /* sekundy od 1970 */
    uint32_t  wire_len;
    ip_addr_t src, dst;
    uint8_t   proto;       /* PROTO_TCP / PROTO_UDP, 0 = brak IP */
    uint8_t   ttl;
    uint16_t  sport, dport;
    uint32_t  payload_len;
    uint8_t   tcp_flags;
    uint32_t  seq, ack;
    uint16_t  window;

    /* Wi-Fi (radiotap) - tylko gdy has_radio = 1 */
    uint8_t   has_radio;
    uint8_t   has_rssi, has_noise, has_tx;
    int8_t    rssi;        /* siła sygnału, dBm */
    int8_t    noise;       /* poziom szumu, dBm */
    uint16_t  freq;        /* MHz */
    uint8_t   retry;       /* ramka powtórzona (flaga 802.11 Retry) */
    uint8_t   tx_mac[6];   /* nadawca ramki (addr2) */
} packet_t;

void addr_to_str(const ip_addr_t *a, char *out);
int  addr_cmp(const ip_addr_t *a, const ip_addr_t *b);
void mac_to_str(const uint8_t *m, char *out);   /* out: min. 18 B */

#endif
