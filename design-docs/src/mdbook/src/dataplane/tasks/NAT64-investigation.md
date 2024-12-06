# NAT64 (investigation)

Linux provides no implementation of [NAT64] so we don't have much in the way of reference implementation to fall back on without going full layer 7.

Getting the hardware offloads to work on this may be really challenging.
My understanding is that the ConnectX-7 cards are the only ones that support [NAT64] offload, and even then under limited conditions.

{{#include ../../links.md}}
