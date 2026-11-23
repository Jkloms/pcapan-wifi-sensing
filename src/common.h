/*
 * common.h - wspólne typy danych używane przez wszystkie moduły.
 *
 * Plik nagłówkowy (.h) w C zawiera DEKLARACJE: opis struktur i funkcji.
 * Kod (definicje funkcji) jest w plikach .c. Każdy plik .c, który chce
 * użyć tych typów, robi #include "common.h".
 *
 * Konstrukcja #ifndef / #define / #endif to tzw. "include guard":
 * chroni przed dwukrotnym wklejeniem tego samego pliku przez kompilator.
 */
#ifndef PCAPAN_COMMON_H
#define PCAPAN_COMMON_H

#include <stdint.h>   /* typy o stałym rozmiarze: uint8_t, uint16_t, uint32_t, uint64_t */
#include <stddef.h>   /* size_t */

/* Numery protokołów z nagłówka IP (pole "protocol" / "next header"). */
#define PROTO_TCP 6
#define PROTO_UDP 17

/* Flagi TCP - każda flaga to jeden bit w bajcie flag nagłówka TCP. */
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

/* Maksymalna długość adresu IP zapisanego jako tekst (IPv6 to 45 znaków + '\0'). */
#define ADDR_STR_LEN 46

/*
 * Adres IP - wspólny typ dla IPv4 i IPv6.
 * Dla IPv4 używamy tylko pierwszych 4 bajtów tablicy 'b', reszta to zera.
 * Dzięki temu możemy porównywać adresy zwykłym memcmp().
 */
typedef struct {
    uint8_t family;   /* 4 albo 6 */
    uint8_t b[16];    /* bajty adresu w kolejności sieciowej */
} ip_addr_t;

/*
 * Jeden zdekodowany pakiet TCP lub UDP.
 * Parser (parser.c) wypełnia tę strukturę, a moduł statystyk (stats.c)
 * ją "konsumuje". Dzięki temu statystyki nie muszą nic wiedzieć
 * o formacie pliku pcap ani o bajtach nagłówków.
 */
typedef struct {
    double    ts;          /* znacznik czasu w sekundach (od 1970-01-01) */
    uint32_t  wire_len;    /* rozmiar pakietu w sieci (bajty) */
    ip_addr_t src, dst;    /* adres źródłowy i docelowy */
    uint8_t   proto;       /* PROTO_TCP albo PROTO_UDP */
    uint8_t   ttl;         /* TTL (IPv4) albo hop limit (IPv6) */
    uint16_t  sport, dport;/* port źródłowy i docelowy */
    uint32_t  payload_len; /* długość danych aplikacji (bez nagłówków) */

    /* Pola tylko dla TCP (dla UDP zostają zerami): */
    uint8_t   tcp_flags;   /* kombinacja TCP_SYN | TCP_ACK | ... */
    uint32_t  seq, ack;    /* numery sekwencyjne */
    uint16_t  window;      /* rozmiar okna odbiorczego */
} packet_t;

/* Zamienia adres na tekst, np. "192.168.1.10". 'out' musi mieć ADDR_STR_LEN bajtów. */
void addr_to_str(const ip_addr_t *a, char *out);

/* Porównuje dwa adresy: <0, 0 albo >0 (jak strcmp). */
int addr_cmp(const ip_addr_t *a, const ip_addr_t *b);

#endif /* PCAPAN_COMMON_H */
