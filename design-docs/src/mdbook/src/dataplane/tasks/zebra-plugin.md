# Zebra Plugin (basic)

The dataplane and control plane need to communicate with each other regarding

1. Full routing tables (for [state sync])
2. route updates (i.e. differential updates)
3. route offloading status (including failures)
4. Address assignments, to ensure the dataplane can configure [local delivery](./identify-local-traffic.md)

Keep in mind that route tables are, in general, notably more complex than a naive LPM trie, and may include like:

1. [ECMP]/WCMP
2. [encapsulation rules](https://www.man7.org/linux/man-pages/man8/ip-route.8.html),
3. [nexthop groups](https://man7.org/linux/man-pages/man8/ip-nexthop.8.html),
4. multicast routes (this is unlikely to be important in the near term).

We only expect to support basic IPv4 and IPv6 LPM routes in the near term, but feature evolution should be accounted for in the design.

## Likely dispatch

* [@Fredi-raspall]
* coordinate with: [@daniel-noland]

{{#include ../../links.md}}
