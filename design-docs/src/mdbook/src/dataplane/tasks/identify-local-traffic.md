# Identify local traffic

At its most basic level, the Hedgehog dataplane is a router.
While most traffic processed by the router will be directed _through_ the router, some traffic will be directed _to_ the router itself.

The primary classes of this traffic are:

1. [Control plane] traffic
   - e.g. BGP session traffic
   - (future) [IPsec] [IKE] traffic
2. [Management plane] traffic
   - traffic directed to the data plane from a management plane running on another machine.
   - traffic directed to the management plane from the end user (e.g., API calls).
3. Low-level network management protocol traffic
   - [ARP] requests and responses
   - [IPv6 ND] requests and responses
   - (possibly) [LACP] pdu frames (depending on client configuration)
   - [BFD] pdu frames
4. [state sync] traffic
   - traffic to maintain state synchronization between dataplane nodes

These types of traffic will need to be accounted for in the offload rules of the data plane to avoid:

1. forwarding such traffic
2. dropping such traffic

## Likely dispatch

- develop: [@daniel-noland]
- coordinate with [@Fredi-raspall] to ensure that needed control plane traffic makes it through.
- coordinate with [@sergeymatov] to ensure that needed dataplane control traffic makes it through.

{{#include ../../links.md}}
