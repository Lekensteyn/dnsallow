dnsallow
========
dnsallow enables whitelisting of IP addresses based on DNS responses.

It involves these components:

 - NFQUEUE for intercepting IP packets.
 - Some code to parse relevant DNS details (name, type, address) from an IP
   packet.
 - Some code to handle the policy (allow / reject a DNS response).
 - ipset for storing whitelisted addresses.
 - iptables for whitelisting traffic based on the queries.

DNS responses are forwarded after checking against the policy, regardless of the
policy outcome. In combination with a default-deny policy for a firewall, this
technique allows non-disruption of normal whitelisted traffic. Assuming a
trustworthy DNS server and a sane policy, unwanted traffic is also blocked.

Ideas
-----
Ideas and TODO items

 - Argument processing:
    - Allow nfqueue queue number to be changed (currently hardcoded to 53).
    - Allow IPv4 and IPv6 ipset setnames to be changed (currently hardcoded to
      `dnsallow-ipv4` and `dnsallow-ipv6`).
    - Add `--help` option.
 - Decide on policy file format (currently all names are accepted).
 - Extend policy to further filter IP addresses?
 - Allow CNAME records to satisfy policies. If the policy allows X, and a
   response for X contains CNAME Y, then addresses in the answer for Y should
   also be accepted by the policy.
 - Accept TCP responses. Will likely not happen as TCP is often not used for
   simple DNS queries/responses and requires tracking of the TCP stream.
 - Rewrite the DNS response. Possibly out of scope for this packet since
   crafting valid DNS responses is more complex and might invalidate signatures.

License
-------
Copyright (c) 2016 Peter Wu <peter@lekensteyn.nl>
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version. See LICENSE.txt for details.
