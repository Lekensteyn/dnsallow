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

#include <stddef.h>
#include <arpa/inet.h>

/* queue.c */
struct input_queue;
typedef void packet_callback(const unsigned char *buf, size_t buflen);

struct input_queue *queue_init(packet_callback *callback);
int queue_handle(struct input_queue *iq);
void queue_fini(struct input_queue *iq);
