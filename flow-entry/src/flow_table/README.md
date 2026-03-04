# Flow Table

The flow table uses `DashMap` for concurrent key→value storage and per-flow
tokio timers for expiration.

## Structure

`FlowTable` wraps `Arc<RwLock<DashMap<FlowKey, Arc<FlowInfo>>>>`:

- The outer `RwLock` is write-locked only during resharding; all normal
  operations take a read lock.
- The `Arc` lets timer tasks hold a reference to the table without a
  back-reference to `FlowTable` itself.

## Expiration

When a flow is inserted, a tokio task is spawned holding `Arc<FlowInfo>`,
`Arc<RwLock<Table>>`, and the `FlowKey`. Each iteration the task sleeps until
`min(deadline, now + 30s)`, then checks the flow status and whether the
deadline was extended. The 30-second bound ensures that `Cancelled` or
externally `Expired` flows are collected promptly even if their original
deadline is far in the future. When the deadline elapses and the flow is still
`Active`, the task marks it `Expired` and removes its DashMap entry via
`remove_if + Arc::ptr_eq`, leaving any concurrent replacement intact.

`lookup()` provides a fallback: it lazily removes stale entries inline,
covering non-tokio contexts and timer scheduling lag.

## Non-tokio contexts (shuttle / sync tests)

No timer is spawned; a `debug!` is logged instead. Tests call
`flow_info.update_status(FlowStatus::Expired)` directly and rely on lazy
removal in `lookup()` or explicit `drain_stale()`.
