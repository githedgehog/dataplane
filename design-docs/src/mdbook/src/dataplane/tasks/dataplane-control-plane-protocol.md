# Dataplane / Control Plane communication protocol

We need some method of sending and receiving data between the [dataplane] and [control plane].

This may take the form of [serde] driven message serialization and deserialization.
Use of [serde] almost certainly requires the use of [bindgen] or [cbindgen].

Alternatives include schema-first method such as [protobuf] or [capnproto], or a bespoke binary protocol.

## Likely assignment

* [@Fredi-raspall]
* coordinate with: [@daniel-noland]

{{#include ../../links.md}}
