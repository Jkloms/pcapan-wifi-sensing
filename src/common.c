/*
 * common.c - drobne funkcje pomocnicze do pracy z adresami IP.
 */
#include <string.h>      /* memcmp */
#include <arpa/inet.h>   /* inet_ntop - zamiana adresu binarnego na tekst */
#include "common.h"

void addr_to_str(const ip_addr_t *a, char *out)
{
    /* inet_ntop to standardowa funkcja systemowa (POSIX).
     * AF_INET = IPv4, AF_INET6 = IPv6. */
    int af = (a->family == 6) ? AF_INET6 : AF_INET;
    if (inet_ntop(af, a->b, out, ADDR_STR_LEN) == NULL)
        strcpy(out, "?");
}

int addr_cmp(const ip_addr_t *a, const ip_addr_t *b)
{
    if (a->family != b->family)
        return (int)a->family - (int)b->family;
    /* memcmp porównuje bajt po bajcie - wynik jak w strcmp */
    return memcmp(a->b, b->b, sizeof a->b);
}
