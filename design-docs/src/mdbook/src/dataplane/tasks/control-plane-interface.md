# Dataplane <-> Control Plane interface

We need to decide how the dataplane and the control plane will exchange information.

The obvious options for transport are

1. tcp socket
2. unix socket

Orthogonal to that decision is the protocol.

1. netlink messages (yuck)
2. directly serialize frr messages (very yuck)
3. manual json schema (less yuck but slow)
4. serde driven (lovely but requires rust to get involved)


My vote is for unix socket and serde!
