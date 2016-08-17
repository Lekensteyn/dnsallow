
PROG := dnsallow
SRCS := main.c queue.c ip.c dns.c ipset.c
TESTS_SRCS := tests/query-a.c tests/query-aaaa.c

OBJS := $(SRCS:.c=.o)
TESTS := $(TESTS_SRCS:.c=)
TESTS_DEPS := $(filter-out main.o,$(OBJS))

MYCFLAGS := $(shell pkg-config --cflags libnetfilter_queue libipset)
MYCFLAGS += -Wall -Wextra
LIBS := $(shell pkg-config --libs libnetfilter_queue libipset)

.c.o: dnsallow.h
	$(CC) -c $(MYCFLAGS) $(CFLAGS) -o $@ $<

$(PROG): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS) $(LIBS)

clean:
	$(RM) $(OBJS) $(PROG)

$(TESTS): % : %.c $(TESTS_DEPS)
	$(CC) -o $@ -I. $< $(TESTS_DEPS) $(LDFLAGS) $(LIBS)

check: $(TESTS)
	@fail=false; for tst in $(TESTS); do \
		printf '%s: ' "$$tst" && "$$tst" || fail=true; \
	done; ! $$fail

.PHONY: clean check
