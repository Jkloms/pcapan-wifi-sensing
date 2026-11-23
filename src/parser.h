/*
 * parser.h - odczyt pliku .pcap i dekodowanie nagłówków sieciowych.
 *
 * Użycie (schemat):
 *
 *     parser_t *p = parser_open("plik.pcap", errbuf);
 *     packet_t pkt;
 *     int r;
 *     while ((r = parser_next(p, &pkt)) != PARSE_END) {
 *         if (r == PARSE_OK) { ... pakiet TCP/UDP w 'pkt' ... }
 *         else               { ... inny pakiet (ARP, ICMP...) - pomijamy ... }
 *     }
 *     parser_close(p);
 */
#ifndef PCAPAN_PARSER_H
#define PCAPAN_PARSER_H

#include "common.h"

/* Wynik funkcji parser_next(). 'enum' to zestaw nazwanych stałych całkowitych. */
typedef enum {
    PARSE_OK    = 0,   /* zdekodowano pakiet TCP lub UDP */
    PARSE_SKIP  = 1,   /* pakiet poprawny, ale nie TCP/UDP (np. ARP, ICMP) */
    PARSE_BAD   = 2,   /* pakiet uszkodzony / obcięty */
    PARSE_END   = 3    /* koniec pliku (albo błąd odczytu) */
} parse_result_t;

/*
 * Typ "nieprzezroczysty" (opaque): w nagłówku mówimy tylko, że taka struktura
 * istnieje. Jej zawartość zna wyłącznie parser.c. Reszta programu posługuje
 * się jedynie wskaźnikiem parser_t*. To prosta forma enkapsulacji w C.
 */
typedef struct parser parser_t;

/* Otwiera plik. Przy błędzie zwraca NULL, a opis błędu wpisuje do errbuf (min. 256 B). */
parser_t *parser_open(const char *path, char *errbuf);

/* Czyta i dekoduje kolejny pakiet. */
parse_result_t parser_next(parser_t *p, packet_t *out);

/* Typ łącza z pliku pcap jako tekst, np. "EN10MB" (Ethernet). */
const char *parser_linktype_name(const parser_t *p);

/* Zamyka plik i zwalnia pamięć. */
void parser_close(parser_t *p);

#endif
