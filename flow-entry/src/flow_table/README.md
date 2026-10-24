# Flow Table

The flow table uses `DashMap` for concurrent key→value storage. Flows expire on
the timer wheel of the worker that created them.

## Structure

`FlowTable` wraps `Arc<RwLock<DashMap<FlowKey, Arc<FlowInfo>>>>`:

- Resharding and pair admission take the outer `RwLock` for writing. Pair
  admission checks both keys and installs both entries before releasing it.
  Lookups, single-entry insertion, removal, and iteration take a read lock.
- Flows are created only through a `WorkerFlowTable`: one worker's handle on
  the shared table, which derefs to it for everything else.

## Expiration

Each `WorkerFlowTable` owns a timer wheel (`timer-wheel` crate) on its thread.
Inserting a flow through the handle puts it on that wheel. The flow keeps a
`TimerRef`, which is how other threads reach the timer.

- **Refreshing** a flow (`extend_expiry` and friends) only stores the new
  deadline in the flow. The wheel reads the deadline when the timer's bucket
  comes due, and moves the timer if the deadline moved later.
- **Invalidating** (`invalidate`) or **detaching** (displacement, `remove`) a
  flow cancels its timer from whatever thread did it. The cancellation is queued
  for the owning worker.
- The worker calls `WorkerFlowTable::expire(now, budget)` from its loop. Each
  call looks at no more than `budget` due or cancelled timers. The flows they
  hand back are removed with `remove_if` + `Arc::ptr_eq`, so a replacement
  inserted under the same key since is left intact.
  - A due flow that is still `Active` is marked `Expired` first.
  - A detached flow is already out of the table.
  - A cancelled flow that is still `Active` was inserted again and has a newer
    timer, so it is left to that timer.

Flows expire no earlier than their deadline and, unless the worker is behind
(`ExpirySweep::behind`), within a tick (10 ms) of it. Nothing removes a flow
from the table between its deadline and the worker's sweep. Lookups do not look
at deadlines.

## Tests

Tests that need expiry insert through a `WorkerFlowTable` and call
`expire_all(clock::now())` after advancing the (paused) clock. Tests of the
table's own semantics can insert through `#[cfg(test)]` helpers on `FlowTable`.
Those helpers put flows on a throwaway wheel, so their flows never expire.
