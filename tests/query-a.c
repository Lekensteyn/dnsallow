/**
 * Test for an DNS response to an A query.
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

#include <stdio.h>
#include <string.h>
#include "dnsallow.h"

static unsigned char ip_packet[] = {
    0x45, 0x00, 0x00, 0x49, 0xc7, 0xa0, 0x00, 0x00, 0x30, 0x11, 0xa8, 0xe9,
    0x08, 0x08, 0x08, 0x08, 0x0a, 0x09, 0x00, 0x02, 0x00, 0x35, 0xd0, 0xb2,
    0x00, 0x35, 0x9b, 0x1d, 0x77, 0x2c, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x52, 0xc4, 0x00, 0x04, 0x5d, 0xb8, 0xd8,
    0x22
};

static int address_matches(struct address *addr, const char *addrstr_expect)
{
    char addrstr[64];
    const char *dst;

    if (addr->family != AF_INET) {
        fprintf(stderr, "Failed: unexpected family %d\n", addr->family);
        return 1;
    }

    dst = inet_ntop(AF_INET, (void *)&addr->ip4_addr, addrstr, sizeof(addrstr));
    if (!dst) {
        fprintf(stderr, "Failed: missing address\n");
        return 1;
    }

    if (strcmp(addrstr, addrstr_expect)) {
        fprintf(stderr, "Failed: invalid address: \"%s\"\n", addrstr);
        return 1;
    }

    return 0;
}

int main(void)
{
    int r;
    struct dns_info info;

    r = parse_ip_dns(ip_packet, sizeof(ip_packet), &info);
    if (r != 1) {
        fprintf(stderr, "Failed: return code is %d\n", r);
        return 1;
    }

    if (strcmp(info.name, "example.com")) {
        fprintf(stderr, "Failed: name is \"%s\"\n", info.name);
        return 1;
    }

    if (info.count != 1) {
        fprintf(stderr, "Failed: invalid addresses count %d\n", info.count);
        return 1;
    }

    address_matches(&info.entries[0], "93.184.216.34");

    puts("Passed");
    return 0;
}
