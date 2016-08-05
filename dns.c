/**
 * DNS processing functions.
 * Copyright (C) 2016 Peter Wu <peter@lekensteyn.nl>

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * Implementation notes:
 *  - Only QDCOUNT == 1 is accepted.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "dnsallow.h"

struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

struct dns_question {
    char *qname;
    uint16_t qtype;
    uint16_t qclass;
};

struct dns_answer {
    char *qname;
    uint16_t type;
    uint16_t data_class;
    uint16_t ttl;
    uint16_t rdlength;
    char *rdata;
};

static void parse_header(const unsigned char *buf, struct dns_header *hdr)
{
    hdr->id = (buf[0] << 8) | buf[1];
    hdr->flags = (buf[2] << 8) | buf[3];
    hdr->qdcount = (buf[4] << 8) | buf[5];
    hdr->ancount = (buf[6] << 8) | buf[7];
    hdr->nscount = (buf[8] << 8) | buf[9];
    hdr->arcount = (buf[10] << 8) | buf[11];
}

/* Tries to parse a name, returning the number of bytes that are consumed by
 * this name on the wire. (0 on failure). */
static unsigned parse_name(const unsigned char *buf, unsigned buflen,
        unsigned offset, char *name)
{
    unsigned label_length;
    unsigned namelen = 0, wirelen = 0;
    const unsigned orig_offset = offset;

    while (offset < buflen) {
        label_length = buf[offset];

        if (label_length == 0) {
            /* Reached the root, the last dot should be dropped later. */
            break;
        } else if ((label_length & 0xc0) == 0xc0) {  /* compressed name */
            if (buflen - offset < 2)
                return 0;

            offset = ((label_length & 0x3f) << 8) | buf[offset + 1];
            /* Pointers are invalid if they point to newer occurences. */
            if (offset >= orig_offset)
                return 0;

            if (wirelen == 0) {
                /* First pointer: account for the prefix and the pointer. */
                wirelen = namelen + 2;
            }
            continue;
        } else {
            offset++;  /* skip label length */
        }

        if (buflen - offset < label_length || namelen + label_length + 1 > 256)
            return 0;

        memcpy(name + namelen, buf + offset, label_length);
        name[namelen + label_length] = '.';
        namelen += label_length + 1;  /* label plus dot (or length plus name) */
        offset += label_length;
    }

    if (namelen > 0) {
        /* Drop trailing dot. */
        name[namelen - 1] = '\0';
        if (strlen(name) != namelen - 1) {
            /* Reject name with NUL byte which causes string truncation */
            return 0;
        }
        namelen++; /* Account for the zero in the wire format. */
    }
    return wirelen ? wirelen : namelen;
}

static int parse_dns(const unsigned char *buf, unsigned buflen, struct dns_info *result)
{
    struct dns_header hdr;
    char name[256];

    memset(result, 0, sizeof(*result));

    if (buflen <= 12)
        return 0;

    parse_header(buf, &hdr);

    /* Can only handle one question for now. */
    if (hdr.qdcount != 1)
        return 0;

    if (parse_name(buf, buflen, 12, name) == 0)
        return 0;

    strcpy(result->name, name);

    return 1;
}

int parse_ip_dns(const unsigned char *buf, unsigned buflen, struct dns_info *result)
{
    unsigned offset;
    uint8_t protocol;

    offset = parse_ip(buf, buflen, &protocol);
    if (offset == 0)
        return 0;

    switch (protocol) {
    case 17: /* UDP */
        if (offset + 8 >= buflen)
            return 0;

        offset += 8;
        break;
    default:
        return 0;
    }

    buf += offset;
    buflen -= offset;
    return parse_dns(buf, buflen, result);
}
