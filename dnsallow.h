/**
 * Internal interfaces for dnsallow.
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

#include <arpa/inet.h>

/* queue.c */
struct input_queue;
typedef void packet_callback(const unsigned char *buf, unsigned buflen, void *data);

struct input_queue *queue_init(packet_callback *callback, void *callback_data);
int queue_handle(struct input_queue *iq);
void queue_fini(struct input_queue *iq);

/* ip.c */
unsigned parse_ip(const unsigned char *buf, unsigned buflen, uint8_t *protocol);

/* dns.c */
struct address {
    int family;
    union {
        struct in_addr ip4_addr;
        struct in6_addr ip6_addr;
    };
};
struct dns_info {
    /* RFC 1035 limits the name to 255 (add one for terminating zero). */
    char name[256];
    unsigned int count;  /* The number of valid entries. */
    /* In theory about 25 addresses fit in a single UDP/DNS answer, but in
     * practice we will limit ourselves. */
#define DNS_MAX_ENTRIES 16
    struct address entries[DNS_MAX_ENTRIES];
};

int parse_ip_dns(const unsigned char *buf, unsigned buflen, struct dns_info *result);

/* policy.c */
struct policy;
struct policy *policy_init(void);
int policy_check(struct policy *policy, const char *dnsname);
void policy_fini(struct policy *policy);

/* ipset.c */
struct ipset_state;
struct ipset_state *ipset_init(void);
void ipset_add_ip(struct ipset_state *state, struct address *addr);
void ipset_fini(struct ipset_state *state);
