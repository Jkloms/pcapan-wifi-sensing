/* common.c - zamiana adresów na tekst. */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "common.h"

void addr_to_str(const ip_addr_t *a, char *out)
{
    int af = (a->family == 6) ? AF_INET6 : AF_INET;
    if (inet_ntop(af, a->b, out, ADDR_STR_LEN) == NULL)
        strcpy(out, "?");
}

int addr_cmp(const ip_addr_t *a, const ip_addr_t *b)
{
    if (a->family != b->family)
        return (int)a->family - (int)b->family;
    return memcmp(a->b, b->b, sizeof a->b);
}

void mac_to_str(const uint8_t *m, char *out)
{
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}
