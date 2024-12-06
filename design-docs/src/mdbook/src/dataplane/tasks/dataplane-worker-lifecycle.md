# Dataplane worker lifecycle

This is mostly a design task at this point.

Things which need to be worked out and documented:

1. communication pattern between workers
2. communication pattern between workers and the control plane
3. communication pattern between workers and the management plane
4. communication pattern between workers and the telemetry / monitoring subsystems

In each case, we need to consider

1. performance impact,
2. thread safety,
3. design simplicity,
4. transactionality,
5. extensibility.

## Likely dispatch

- primary: [@daniel-noland]
- sync with: [@sergeymatov]

{{#include ../../links.md}}
