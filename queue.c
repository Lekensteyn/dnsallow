/**
 * Interactiong with NFQUEUE for packet interception.
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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>  /* for NF_ACCEPT */
#include "dnsallow.h"

struct input_queue {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    packet_callback *pkt_callback;
};

static struct nfq_handle *init_nfq(void)
{
    struct nfq_handle *h;

    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        return NULL;
    }

    /* This seems unnecessary starting with Linux 3.7 (no-op).
     * Anyway, it will fail if you are not root. */
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf(AF_INET)\n");
        goto err_close;
    }

    if (nfq_unbind_pf(h, AF_INET6) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf(AF_INET6)\n");
        goto err_close;
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf(AF_INET)\n");
        goto err_close;
    }

    if (nfq_bind_pf(h, AF_INET6) < 0) {
        fprintf(stderr, "error during nfq_bind_pf(AF_INET6)\n");
        goto err_close;
    }

    return h;

err_close:
    nfq_close(h);
    return NULL;
}

static int queue_pkt_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
        struct nfq_data *nfa, void *data)
{
    struct input_queue *iq = data;
    unsigned char *pktdata;
    int pkt_id, pktlen;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);

    /* Should not happen, otherwise we cannot set a verdict. */
    if (!ph)
        return -1;

    pkt_id = ntohl(ph->packet_id);
    pktlen = nfq_get_payload(nfa, &pktdata);

    iq->pkt_callback(pktdata, pktlen);
    nfq_set_verdict(iq->qh, pkt_id, NF_ACCEPT, 0, NULL);
    return 0;
}

static struct nfq_q_handle *init_nfq_queue(struct nfq_handle *h, int queue_num,
        struct input_queue *iq)
{
    struct nfq_q_handle *qh;

    qh = nfq_create_queue(h, queue_num, &queue_pkt_callback, iq);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        fprintf(stderr, "Is the queue already being consumed?\n");
        return NULL;
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 1024) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        nfq_destroy_queue(qh);
        return NULL;
    }

    return qh;
}

struct input_queue *queue_init(packet_callback *callback)
{
    struct input_queue *iq;

    iq = malloc(sizeof(*iq));
    if (!iq)
        return NULL;

    iq->pkt_callback = callback;

    iq->h = init_nfq();
    if (!iq->h)
        goto err_init_nfq;

    iq->qh = init_nfq_queue(iq->h, 53, iq);
    if (!iq->qh)
        goto err_init_nfq_queue;

    return iq;

err_init_nfq_queue:
    nfq_close(iq->h);
err_init_nfq:
    free(iq);
    return NULL;
}

int queue_handle(struct input_queue *iq)
{
    int r;
    char buf[1024];

    r = recv(nfq_fd(iq->h), buf, sizeof(buf), 0);
    if (r < 0)
        return r;

    nfq_handle_packet(iq->h, buf, r);
    return r;
}

void queue_fini(struct input_queue *iq)
{
    nfq_destroy_queue(iq->qh);
    nfq_close(iq->h);
    free(iq);
}
