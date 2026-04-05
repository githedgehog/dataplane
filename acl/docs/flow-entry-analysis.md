# Flow-entry data structure and concurrency analysis

## Current architecture

```
Arc<RwLock<DashMap<FlowKey, Arc<FlowInfo>, RandomState>>>
 │       │      │                │
 │       │      │                └─ Per-flow state (atomic status,
 │       │      │                   RwLock<NAT state>, Weak<related>)
 │       │      │
 │       │      └─ 1024 shards, ahash with deterministic seeds (0,0,0,0)
 │       │
 │       └─ OUTER LOCK: serializes reshard() against all other ops
 │
 └─ Shared across packet processing threads and tokio timer tasks
```

## The outer RwLock: corrected analysis

The outer `std::sync::RwLock` wrapping DashMap is **less dangerous
than it first appears** but still suboptimal.

### Who acquires what?

| Operation | Lock type | Concurrent with other reads? |
|---|---|---|
| `lookup()` | read | YES — multiple readers run concurrently |
| `insert()` | read | YES |
| `remove_if()` (timer) | try_read / read | YES |
| `drain_stale()` | read | YES (but see note on shard locks) |
| `reshard()` | **WRITE** | **NO — blocks everything** |

**Key correction:** `insert()`, `lookup()`, and timer tasks all
acquire the **read** lock.  `RwLock` allows multiple concurrent
readers.  These operations run in parallel with each other — the
RwLock does NOT serialize them.

**Only `reshard()`** acquires the write lock, which blocks all
other operations for its O(n) duration.  But `reshard()` is a
rare admin operation, not a hot-path concern.

### What the RwLock actually costs

Even with read-read concurrency, `std::sync::RwLock::read()` has
overhead: readers atomically increment a shared counter, which
causes cache line bouncing on multi-core systems.  Under high
throughput (millions of lookups/sec on many cores), this
contention is measurable.

### Why not use crossbeam's ShardedLock?

`crossbeam::sync::ShardedLock` is a **drop-in replacement** for
`std::sync::RwLock` — identical API (`read()`, `write()`,
`try_read()`) but internally shards the reader counter across
cache lines.  Each CPU core gets its own reader counter,
eliminating reader-reader cache bouncing entirely.

The write side still blocks all readers (same as RwLock), but
the read-read path has zero cross-core contention.

**This should be a one-line change:**
```rust
// Before
use std::sync::RwLock;

// After
use crossbeam::sync::ShardedLock as RwLock;
```

Plus a `crossbeam` dependency in Cargo.toml.  No API changes,
no structural changes.  The TODO in the code already identifies
this.  It should have been done from the start.

### The real concern: drain_stale's shard locks

`drain_stale()` acquires the RwLock read lock (fine — concurrent
with other readers) but then calls `DashMap::retain()`, which
internally acquires **per-shard write locks** as it scans.  While
a shard is write-locked by `retain()`, no other thread can
`insert()` or `remove_if()` on that shard.  Since `retain()`
scans ALL shards sequentially, each shard is briefly write-locked
in turn.  This is O(n) total but each shard is locked for only
O(n/shards) time.

With 1024 shards, this is ~1000 entries per shard on a 1M entry
table, each shard locked for microseconds.  Not great, but not
catastrophic.  The impact is brief per-shard stalls, not a global
halt.

### Tokio safety

`std::sync::RwLock::read()` is a blocking call.  On a tokio
worker thread, this means the thread is blocked while waiting.
However:

- Under normal operation, the read lock is uncontested (no write
  lock held), so `read()` returns immediately.
- The only scenario where `read()` blocks is if `reshard()` is
  in progress — which should never happen on a tokio worker
  thread (it's an admin operation).
- Timer tasks use `try_read()` + `yield_now()` to avoid blocking.

**Risk:** If someone calls `reshard()` on a tokio worker thread,
it acquires the write lock and blocks all worker threads trying
to `read()`.  This could deadlock the tokio runtime.  But this
is a misuse error, not a design flaw.

## Assessment: DashMap vs multi-index-map

### DashMap: right for the hot path

- Concurrent reads/writes without global lock (shard-level)
- O(1) exact-match lookup on FlowKey
- Well-tested, widely used

### multi-index-map: wrong for the hot path

- **Not concurrent.** Single-threaded only.  Wrapping in a lock
  is strictly worse than DashMap for concurrent access.
- Useful for admin/secondary lookups (e.g., "find all flows for
  VPC X") but not for per-packet classification.

### Recommendation

**Keep DashMap.  Replace `std::sync::RwLock` with
`crossbeam::sync::ShardedLock`.  This is a minimal, low-risk
change that eliminates reader cache contention.**

Consider `ArcSwap` for the table pointer only if we want to
eliminate the write lock for `reshard()` entirely (replacing it
with an atomic pointer swap to a new DashMap).  But ShardedLock
is the simpler fix.

## What needs fixing before ACL integration

### Minimal (should do)

1. **Replace RwLock with ShardedLock.**  One-line change.
   Eliminates reader cache contention on the hot path.

2. **Implement capacity management.**  The TODO for auto-drain
   is important.  Without it, the table grows unbounded.

### Important (should do before production scale)

3. **Timer wheel instead of per-flow tasks.**  At 1M+ flows,
   per-flow tokio tasks are unsustainable.  A `DelayQueue` or
   similar manages batches with one task.

4. **Ensure reshard() is never called from tokio.**  Either
   make it `!Send` or document the constraint.

### Future

5. **Generation-aware expiration** driven by the ACL update
   planner.

6. **Metrics** (flow count, insert/s, shard distribution).
