/* parser.h - odczyt pliku .pcap i dekodowanie nagłówków. */
#ifndef PCAPAN_PARSER_H
#define PCAPAN_PARSER_H

#include "common.h"

typedef enum {
    PARSE_OK,     /* pakiet TCP/UDP */
    PARSE_SKIP,   /* inny pakiet (ARP, ICMP, beacon Wi-Fi...) */
    PARSE_BAD,    /* uszkodzony / obcięty */
    PARSE_END     /* koniec pliku */
} parse_result_t;

typedef struct parser parser_t;   /* szczegóły tylko w parser.c */

parser_t      *parser_open(const char *path, char *errbuf /* min. 256 B */);
parse_result_t parser_next(parser_t *p, packet_t *out);
const char    *parser_linktype_name(const parser_t *p);
void           parser_close(parser_t *p);

#endif
