# Classifier concurrency and safe reclamation

## Problem

The `Classifier` is shared between:

- **DPDK poll threads** — classify millions of packets per second,
  pure hot path, cannot tolerate locks or significant atomic overhead
- **Tokio control plane tasks** — receive rule updates from k8s,
  build new classifiers, publish them

When the control plane publishes a new `Classifier`, in-flight
readers on the poll threads must finish using the old classifier
before it's freed.  This is a classic read-copy-update problem.

## Options

### 1. DPDK `rte_rcu_qsbr` (Quiescent State Based Reclamation)

DPDK's RCU implementation.  Readers report quiescent states at
natural idle points (end of poll loop).  The writer waits until
all readers have reported, then reclaims.

**Reader cost:** Zero on the classify path.  One store to a
per-thread counter at a natural boundary (after processing a
batch of 32 packets).  Amortized: ~0.03 atomics per packet.

**Writer cost:** Scan all registered threads' counters.  O(N)
where N = number of poll threads.

**Strengths:**
- Absolutely minimal reader overhead — a pointer dereference
  is the only cost on the hot path
- Designed for DPDK's poll-mode architecture
- No per-read atomic operations

**Weaknesses:**
- **Fundamentally incompatible with tokio.**  QSBR requires
  readers to explicitly declare quiescent states.  A tokio task
  can be suspended at any `.await` point while holding a
  reference.  The runtime can't distinguish "task yielded
  voluntarily" from "task is between quiescent states."
- Requires FFI to DPDK's C implementation
- Readers must be registered threads (not arbitrary tasks)

### 2. Epoch-Based Reclamation (`crossbeam-epoch`)

Readers "pin" the current epoch when entering a critical section
and "unpin" when leaving.  The writer advances the global epoch
and reclaims data that's two epochs old.

**Reader cost:** Two atomics per critical section (pin + unpin).
Can be amortized by holding a pin across a batch:

```rust
let guard = crossbeam_epoch::pin();
for packet in batch {
    let classifier = shared.load(Relaxed, &guard);
    classifier.classify(packet);
}
drop(guard); // unpin after whole batch
```

Amortized with batching: ~0.06 atomics per packet (two per
32-packet batch).

**Writer cost:** Atomic increment of global epoch + scan
thread-local flags.

**Strengths:**
- Pure Rust, no FFI
- Works with tokio: `Guard` is `!Send`, which prevents holding
  it across `.await` points — the compiler catches misuse
- Batch pinning amortizes to near-QSBR overhead
- Well-tested (crossbeam is foundational Rust infrastructure)

**Weaknesses:**
- Two atomics per critical section without batching (~5-20ns each
  on modern x86, potentially 1-4% of per-packet budget at 10Gbps)
- Holding a pin across a batch delays reclamation until the
  longest-running batch completes (microseconds — acceptable)
- More complex memory ordering semantics than ArcSwap

### 3. `ArcSwap`

The writer stores `Arc<Classifier>` in an `ArcSwap<Classifier>`.
Readers load an `Arc` (atomic increment), use it, drop it (atomic
decrement).

**Reader cost:** One atomic increment (clone Arc) + one atomic
decrement (drop Arc) per read.  Can be amortized by holding the
`Arc` across a batch (clone once, classify N packets, drop once).

**Writer cost:** Atomic swap of the Arc pointer.  Old classifier
freed when last reader drops its Arc.

**Strengths:**
- Simplest API — just `Arc` semantics
- Fully tokio compatible — `Arc` is `Send + Sync`
- Immediate reclamation (as soon as last reader drops)
- No registration, no epochs, no quiescent states
- Battle-tested crate

**Weaknesses:**
- One atomic increment + decrement per read (without batching)
- Without batching, slightly more overhead than epoch-based
  (though the difference is negligible for control-plane usage)

### 4. Hybrid: QSBR for poll threads + ArcSwap for tokio

Use the optimal mechanism for each context:

- **DPDK poll threads:** `rte_rcu_qsbr` for zero per-read overhead.
  Report quiescent state once per poll loop.
- **Tokio tasks:** `ArcSwap<Classifier>` for safe async access.
- **Writer:** Publishes to both simultaneously.

```
Writer (tokio):
  new_classifier = table.compile()
  arc_swap.store(Arc::new(new_classifier.clone()))
  rcu_pointer.store(new_classifier)
  rcu_synchronize()  // wait for poll threads to drain
  free(old_classifier)
```

**Strengths:**
- Optimal for both contexts
- Each mechanism used in its natural habitat

**Weaknesses:**
- Two publication paths, two sets of pointers
- Must ensure both paths are updated atomically (or the brief
  inconsistency window is acceptable)
- More complex implementation

## Comparison

| Property | QSBR | Epoch | ArcSwap | Hybrid |
|---|---|---|---|---|
| Per-read hot path cost | ~0 | 2 atomics (or batch) | 1 atomic (or batch) | ~0 on poll, 1 on tokio |
| Tokio compatible | No | Yes (`!Send` guard) | Yes | Yes |
| DPDK poll optimal | Yes | Good with batch | Adequate | Yes |
| Implementation complexity | Medium (FFI) | Low (crate) | Trivial | High |
| Reclamation latency | 1 QS cycle | 2 epoch advances | Immediate | Mixed |

## Recommendation

**V1 (software-only, tokio-based):** `ArcSwap` everywhere.

Simple, correct, fast enough.  The atomic overhead is irrelevant
for software classification.  The `Classifier` type is already
`Clone`, so wrapping in `Arc<Classifier>` is trivial:

```rust
use arc_swap::ArcSwap;

let classifier_handle = Arc::new(ArcSwap::from_pointee(
    table.compile()
));

// Reader (any thread, any async context)
let classifier = classifier_handle.load();
let outcome = classifier.classify(&headers);

// Writer (update path)
let new_classifier = new_table.compile();
classifier_handle.store(Arc::new(new_classifier));
// Old classifier freed when all readers drop their Arc
```

**Production (DPDK poll threads + tokio control plane):** Hybrid
(option 4).

DPDK poll threads get zero-overhead QSBR reads.  Tokio tasks get
`ArcSwap` reads.  The writer publishes to both.  This is the
optimal architecture but requires careful coordination between
the two publication paths.

**`crossbeam-epoch` as a middle ground:** If one mechanism for
both contexts is preferred (simpler than hybrid), epoch-based
with batch pinning is a reasonable choice.  The `!Send` guard
prevents async misuse at compile time.  Amortized overhead with
batching approaches QSBR.  The main risk is forgetting to batch,
which degrades to two atomics per packet.

## Interaction with two-tier classification

The reclamation mechanism applies to the root `Classifier` pointer.
When the compiler produces a `Tiered { delta, base }` classifier
during an update:

1. Build the new `Classifier` (with delta tier)
2. Publish via ArcSwap / QSBR
3. Readers atomically start seeing the tiered classifier
4. Background: build the merged single-tier classifier
5. Publish the merged classifier
6. Old tiered classifier reclaimed after readers drain

Each publication is an atomic pointer swap.  The reclamation
mechanism ensures the old classifier lives until all readers are
done with it.  The two-tier model and the reclamation model are
orthogonal — they compose without interference.
