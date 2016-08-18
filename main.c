/**
 * Main queue processing loop for dnsallow.
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
#include <stdio.h>
#include "dnsallow.h"
#include <signal.h>
#include <ctype.h>

void hexdump(const unsigned char *data, size_t len)
{
    size_t i, j, linelen;

    for (i = 0; i < len; i += 16) {
        linelen = len - i < 16 ? len - i : 16;

        printf("%03zx: ", i);

        for (j = 0; j < linelen; j++)
            printf("%02x ", data[i + j]);
        for (; j < 16; j++)
            printf("   ");
        putchar(' ');
        for (j = 0; j < linelen; j++) {
            unsigned char c = data[i + j];
            putchar(isprint(c) ? c : '.');
        }
        putchar('\n');
    }
}

static void pkt_callback(const unsigned char *buf, unsigned buflen)
{
    struct dns_info info;

    hexdump(buf, buflen);
    if (parse_ip_dns(buf, buflen, &info) == 0) {
        fprintf(stderr, "Parsing failed\n");
        return;
    }
}

static volatile int signalled = 0;

static void sighandler(int sig)
{
    signalled = sig;
}

static int set_signal_handlers(void)
{
    struct sigaction sa;

    sa.sa_handler = sighandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) < 0)
        return -1;
    if (sigaction(SIGTERM, &sa, NULL) < 0)
        return -1;

    return 0;
}

int main(int argc, const char *argv[])
{
    struct input_queue *iq;
    struct ipset_state *ipset_state;

    if (set_signal_handlers() < 0)
        return 1;

    iq = queue_init(pkt_callback);
    if (!iq)
        return 1;

    ipset_state = ipset_init();
    if (!ipset_state) {
        ipset_fini(ipset_state);
        return 1;
    }

    while (!signalled && queue_handle(iq))
        ;

    if (signalled)
        fprintf(stderr, "Exiting due to signal %d.\n", signalled);
    else
        fprintf(stderr, "Exiting.\n");

    ipset_fini(ipset_state);
    queue_fini(iq);
    return 0;
}
