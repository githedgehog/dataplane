# Flow Table

The flow table uses `DashMap` for concurrent key→value storage and per-flow
tokio timers for expiration.

## Flow Table Implementation

The `DashMap` stores `Arc<FlowInfo>` values directly, so the table is the
primary strong-reference keeper for each flow entry.  Callers that need to
retain a flow (e.g. pipeline stages that tag packets) clone the `Arc` out of
`lookup()`.

When a flow is inserted, a `tokio::task` is spawned (if a tokio runtime is
present) that sleeps until the flow's deadline and then calls
`update_status(FlowStatus::Expired)`.  The DashMap entry is not removed by the
timer; instead, `lookup()` performs lazy cleanup: if a looked-up entry is
`Expired` or `Cancelled` it is removed from the map and `None` is returned.
The same lazy path covers the case where a deadline passes without a timer
firing (e.g. in non-tokio test contexts).

`FlowInfo::related` holds a `Weak<FlowInfo>` pointing to the reverse-direction
flow of a bidirectional pair.  This avoids reference cycles: the two entries
are independent `Arc`s in the table, and the `Weak` merely lets one side
observe the other without keeping it alive.

## Non-tokio contexts (shuttle / sync tests)

When no tokio runtime is present `Handle::try_current()` returns `Err` and no
timer is spawned.  Tests simulate expiration by calling
`flow_info.update_status(FlowStatus::Expired)` directly, after which the next
`lookup()` call performs the lazy removal.
