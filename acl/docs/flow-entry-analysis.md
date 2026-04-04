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
 │       └─ OUTER LOCK: serializes drain_stale/reshard against all ops
 │
 └─ Shared across packet processing threads and tokio timer tasks
```

## The double-locking problem

DashMap is already a concurrent hash map with per-shard locking.
The outer `RwLock` wrapping it is redundant for normal operations
(`insert`, `lookup`, `remove`) — DashMap handles those concurrently.

The RwLock exists for two reasons:
1. `reshard()` needs exclusive access to replace the entire DashMap
2. Timer tasks need a stable reference to the table

**The cost:** Every hot-path operation (`lookup` per-packet, `insert`
per-new-flow) acquires the RwLock read lock, even though DashMap
could handle the concurrency alone.  Under high throughput, this
is a bottleneck — all operations serialize through the RwLock
before reaching DashMap's fine-grained shards.

**What makes it worse:**
- `drain_stale()` holds the read lock for O(n) time (full scan)
- `reshard()` holds the WRITE lock for O(n) time (rebuilds table)
- Both block all hot-path operations for their duration

## Concurrency model

### Who reads and writes?

| Operation | Who | Lock | Frequency |
|---|---|---|---|
| `lookup()` | Packet processing (per-packet) | RwLock read + shard read | Very high |
| `insert()` | NF creating new flow | RwLock read + shard write | Per new flow |
| `remove_if()` | Timer task (per-flow expiry) | RwLock try_read + shard write | Per flow lifetime |
| `drain_stale()` | Admin / periodic cleanup | RwLock read + ALL shard writes | Rare but O(n) |
| `reshard()` | Admin (rare) | RwLock WRITE | Very rare, very disruptive |

### Timer model

One tokio task per flow.  Timer sleeps until deadline, then:
1. Marks flow as `Expired` (atomic status update)
2. Removes entry via `remove_if` with `Arc::ptr_eq` guard
3. Task completes and is freed

**Problem:** At 1M flows, 1M tokio tasks are sleeping.  Each wake
requires scheduler work + lock acquisition.  No backpressure —
insertion is fire-and-forget.

**Lazy expiration backup:** Every `lookup()` checks if the found
entry has passed its deadline.  If so, it marks expired and removes
inline.  This covers cases where the timer fires late.

### Arc::ptr_eq guard

Critical safety mechanism: when removing a flow entry (by timer
or by lazy expiry), the code checks that the Arc in the DashMap
is the SAME Arc that was examined.  Between the read and the
remove, another thread may have replaced the entry with a new
flow under the same key.  `ptr_eq` prevents removing the new
entry by mistake.

## Assessment: should we use DashMap or multi-index-map?

### DashMap strengths for this use case

- **Concurrent reads/writes without global lock.** The hot path
  (lookup per-packet, insert per-new-flow) is the main use case.
  DashMap's shard-level locking is ideal.
- **O(1) exact-match lookup.** Flow keys are 5-tuple hashes.
- **Familiar API.** `get`, `insert`, `remove_if`, `retain`.

### DashMap weaknesses

- **Single key only.** Can only look up by FlowKey.  If we ever
  need "find all flows for VPC X" or "find all flows to destination
  Y", DashMap requires a full scan.
- **No secondary indices.** `multi_index_map` supports this.
- **The RwLock wrapper.** Not DashMap's fault — the wrapper
  defeats DashMap's concurrency for reshard/drain operations.
- **No built-in expiration.** Timer management is bolted on.

### multi-index-map strengths

- **Multiple lookup keys.** Could index by (FlowKey, VPC, dst_ip)
  for O(1) lookup on any dimension.
- **Used in the tc module.** Already a workspace dependency with
  established patterns.

### multi-index-map weaknesses

- **Not concurrent.** `multi_index_map` is single-threaded.
  Concurrent access requires wrapping in `RwLock` or `Mutex`,
  which is the same problem we're trying to avoid.
- **No shard-level locking.** Under high throughput, a single
  lock around multi-index-map would be worse than DashMap.

### Recommendation

**Keep DashMap for the hot-path flow table.** It's the right tool
for concurrent exact-match lookup under high throughput.

**Remove the outer RwLock.** The TODO in the code already
identifies this.  Options:
1. **ArcSwap for the table pointer.** `reshard()` builds a new
   DashMap, publishes via `ArcSwap::store()`.  No write lock.
   Readers get the current table via `ArcSwap::load()`.
2. **Crossbeam sharded lock** (per the code's own TODO).
3. **Just remove it.** If we never reshard at runtime (configure
   shard count at startup), the RwLock serves no purpose.

**Consider multi-index-map for admin/secondary lookups only.**
If we need "find all flows for VPC X" for config invalidation,
maintain a separate non-concurrent `MultiIndexMap` that's updated
asynchronously (not on the hot path).

## What needs fixing before ACL integration

### Critical (blocks integration)

1. **Remove the outer RwLock.** The double-lock pattern will
   create contention with the ACL classifier (which also runs
   per-packet).  The `Cascade([FlowEntry, ACL])` model puts
   flow-entry on the critical path.

2. **Implement capacity management.** The TODO for auto-drain
   is essential.  Without it, the table grows unbounded and
   `drain_stale()` eventually takes seconds (blocking everything).

### Important (should fix before production)

3. **Timer wheel instead of per-flow tasks.** At scale (1M+
   flows), per-flow tokio tasks are unsustainable.  A shared
   timer wheel (e.g., `tokio-util`'s `DelayQueue`) manages
   batches of expirations with one task.

4. **Shard count tuning.** 1024 shards is reasonable for 100k
   flows but may cause cache pressure at lower counts.  Should
   be configurable per deployment.

### Nice to have (future optimization)

5. **Generation-aware expiration.** When the ACL table updates
   (new config generation), flow-entry should invalidate stale
   entries.  Currently uses `genid` on FlowInfo, checked by
   flow-filter.  This should be driven by the ACL update planner.

6. **Metrics.** Expose flow count, insert/s, expired/s, shard
   distribution, lock contention.  Essential for capacity planning.
