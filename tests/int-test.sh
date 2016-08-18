#!/bin/bash
# Integration test for queue + ipset functionality.
# Assumes that dnsallow is in ../dnsallow (override with DNSALLOW envvar).
#
# Resources that are modified during the test:
# - ipset: setnames dnsallow-ipv4 and dnsallow-ipv6
# - nfqueue: consumes queue 53
# - dnsmasq: binds to port 53
# - iptables: inserts a temporary rule
#
# Required capabilities:
# CAP_NET_ADMIN         - for ipset and dnsallow
# CAP_NET_RAW           - for iptables
# CAP_NET_BIND_SERVICE  - for dnsmasq binding to port 53

set -e -u
xcmds=(:)
cleanup() {
    local exitcode=$?
    echo "Exit code: $?"
    for cmd in "${xcmds[@]}"; do
        eval "$cmd" || echo "Failed: $cmd"
    done
    return $?
}
trap cleanup EXIT

fail() {
    echo "FAIL: $1" >&2
    exit 1
}


# Config
QUEUE_NUM=53
: "${DNSALLOW:=./dnsallow}"


# Sanity check
which "$DNSALLOW" >/dev/null || fail "dnsallow binary not found at $DNSALLOW"
ipset --version >/dev/null || fail "ipset binary unavailable"
ipset list -name &>/dev/null || fail "Cannot query ipset"
if ipset list -name | grep -qxE "dnsallow-ipv[46]"; then
    fail "ipsets already exist, try to run in a clean netns!"
fi

# Dnsmasq state configuration
tmpdir=$(mktemp -d)
hostsfile="$tmpdir/hosts"
dm_pidfile="$tmpdir/dnsmasq.pid"
xcmds+=("$(printf 'pkill -F %q' "$dm_pidfile")")
xcmds+=("$(printf 'rm -rf %q' "$tmpdir")")
cat >"$hostsfile" <<HOSTS
# Hosts file, used by integration tests
# A single IPv4 address, multiple IPv6 addresses
192.0.2.1   test-net-1.test
2001:db8::1 test-net-1.test
2001:db8::2 test-net-1.test
# An address that should be excluded by the policy.
2001:db8::3 example.test
HOSTS
# Start dnsmasq for serving a local configuration
dnsmasq \
    --log-facility=/dev/null --pid-file="$dm_pidfile" --no-hosts --no-resolv \
    --listen-address=127.0.0.53 --no-dhcp-interface= --bind-interfaces \
    --addn-hosts="$hostsfile" || fail "Failed to start dnsmasq"

# Start daemon under test
"$DNSALLOW" & xcmds+=("kill $!")
xcmds+=("ipset destroy dnsallow-ipv4")
xcmds+=("ipset destroy dnsallow-ipv6")
# Hopefully enough for the program to create ipsets and connect to the queue.
sleep .1

# Make sure DNS queries are logged.
ipt_add() {
    "$1" -I INPUT 1 $2 || fail "Failed to configure $1"
    xcmds+=("$1 -D INPUT $2")
}
ipt_rule="-p udp --sport 53 -j NFQUEUE --queue-bypass --queue-num $QUEUE_NUM"
ipt_add iptables "$ipt_rule"
#ipt_add ip6tables "$ipt_rule"  # Not needed for now, DNS server listens on IPv4


# Resolve IPs locally
resolve() {
    echo "Resolving $*..." >&2
    dig @127.0.0.53 "$@" +short | LC_ALL= sort
}
ipv4=($(resolve test-net-1.test A))
ipv6=($(resolve test-net-1.test AAAA))
ipv6_other=$(resolve example.test AAAA)

# Sanity check for expected responses
[[ "${ipv4[*]}" == 192.0.2.1 ]] || fail "Unexpected IPv4 result: ${ipv4[*]}"
[[ ${#ipv6[@]} == 2 ]] || fail "Unexpected IPv6 results count: ${#ipv6[@]}"
[[ "${ipv6[0]}" == 2001:db8::1 ]] || fail "Unexpected IPv6 result 1: ${ipv6[0]}"
[[ "${ipv6[1]}" == 2001:db8::2 ]] || fail "Unexpected IPv6 result 2: ${ipv6[1]}"
[[ "$ipv6_other" == 2001:db8::3 ]] || fail "Unexpected IPv6 (2) result: $ipv6"

# Check whether the daemon handled these correctly.
ipset test dnsallow-ipv4 $ipv4 || fail "Expected $ipv4 in set"
ipset test dnsallow-ipv6 ${ipv6[0]} || fail "Expected ${ipv6[0]} in set"
ipset test dnsallow-ipv6 ${ipv6[1]} || fail "Expected ${ipv6[1]} in set"

# TODO: reject address according to policy
#! ipset test dnsallow-ipv6 $ipv6_other || fail "Expected $ipv6_other not in set"

# Cleanup and show results
trap '' EXIT; cleanup
echo PASSED
