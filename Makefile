#
# Targets:
#   dnsallow    - main program
#   check       - basic unit tests
#   int         - integration test (needs root)
#   int-cap     - integration test (needs sudo and libcap newer than 2.25)

PROG := dnsallow
SRCS := main.c queue.c ip.c dns.c policy.c ipset.c
TESTS_SRCS := tests/query-a.c tests/query-aaaa.c
INTEGRATION_TEST := tests/int-test.sh

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

int: $(INTEGRATION_TEST)
	$(INTEGRATION_TEST)

int-cap: $(INTEGRATION_TEST)
	@caps=cap_net_admin,cap_net_raw,cap_net_bind_service; \
	sudo capsh --caps="cap_setuid,cap_setgid,cap_setpcap+ep $$caps+eip" \
		--keep=1 --user=$$USER --addamb="$$caps" -- $(INTEGRATION_TEST)

.PHONY: clean check int int-cap
