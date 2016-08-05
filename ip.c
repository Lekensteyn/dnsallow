/**
 * IP processing functions.
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

#include <stdint.h>
#include <stdbool.h>
#include "dnsallow.h"

static bool is_ipv6_extension_header_type(uint8_t type)
{
    /* The registry can be found at
     * http://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml */
    switch (type) {
    case 0:     /* IPv6 Hop-by-Hop Option */
    case 43:    /* Routing Header for IPv6 */
    case 44:    /* Fragment Header for IPv6 */
    case 50:    /* Encapsulating Security Payload */
    case 51:    /* Authentication Header */
    case 60:    /* Destination Options for IPv6 */
    case 135:   /* Mobility Header */
    case 139:   /* Host Identity Protocol */
    case 140:   /* Shim6 Protocol */
    case 253:   /* Use for experimentation and testing */
    case 254:   /* Use for experimentation and testing */
        return true;
    default:
        return false;
    }
}

/* Calculate size of IP header (returning 0 on failure). */
unsigned parse_ip(const unsigned char *buf, unsigned buflen, uint8_t *protocol)
{
    unsigned ip_version;

    if (buflen == 0)
        return 0;

    ip_version = buf[0] >> 4;
    if (ip_version == 4) { /* IPv4 */
        unsigned ip_header_size = (buf[0] & 0xf) * 4;
        if (ip_header_size < 20 || ip_header_size >= buflen)
            return 0;

        *protocol = buf[9];
        return ip_header_size;
    } else if (ip_version == 6) { /* IPv6 */
        if (buflen <= 40)
            return 0;

        uint8_t next_header = buf[6];
        unsigned offset = 40;
        /* skip headers as needed. */
        while (is_ipv6_extension_header_type(next_header)) {
            if (buflen - offset <= 2)
                return 0;

            /* Size of whole extended header. */
            unsigned header_ext_len = 8 + buf[offset + 1];
            if (buflen - offset <= header_ext_len)
                return 0;

            next_header = buf[offset];
            offset += header_ext_len;
        }

        *protocol = next_header;
        return offset;
    } else {
        return 0;
    }
}
