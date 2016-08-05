
PROG := dnsallow
SRCS := main.c queue.c dns.c
OBJS := $(SRCS:.c=.o)

MYCFLAGS := $(shell pkg-config --cflags libnetfilter_queue)
MYCFLAGS += -Wall -Wextra
LIBS := $(shell pkg-config --libs libnetfilter_queue)

.c.o: dnsallow.h
	$(CC) -c $(MYCFLAGS) $(CFLAGS) -o $@ $<

$(PROG): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS) $(LIBS)
	sudo setcap cap_net_admin+ep dnsallow

clean:
	$(RM) $(OBJS) $(PROG)

.PHONY: clean
