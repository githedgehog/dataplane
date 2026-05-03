//! Property-based protocol tests for `dataplane_quiescent`.
//!
//! Generates random sequences of [`Op`]s and checks the
//! single-threaded protocol invariants after every step:
//!
//! 1. **Snapshot legality** — every value a Subscriber observes was
//!    actually published by the Publisher.
//! 2. **Per-Subscriber monotonicity** — successive snapshots from the
//!    same Subscriber return non-decreasing payloads (the Publisher
//!    publishes a strictly increasing counter, so this is a tight
//!    bound).
//! 3. **Conservation of `Versioned` allocations** — at every quiescent
//!    point, every `Versioned<Marker>` ever created is either:
//!    - the current publication (exactly 1),
//!    - retained in the Publisher's `retired` list
//!      (`publisher.pending_reclamation()` of them),
//!    - or already dropped (counted by the marker's `Drop` impl).
//!
//! The conservation invariant is the strongest single thing we can
//! check at this layer: if a `Versioned` is leaked, double-dropped, or
//! resurrected, this assertion fires.
//!
//! Multi-threaded tests (drop affinity, concurrent stress) live in
//! `tests/protocol.rs`; loom-modeled tests live in `tests/loom.rs`.

#![cfg(not(any(feature = "loom", feature = "shuttle")))]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bolero::TypeGenerator;
use dataplane_quiescent::channel;

// ---------- ops & state ----------

/// One step of an operation sequence.  Indices into `subscribers` are
/// taken modulo `subscribers.len()`, so the bolero driver doesn't need
/// to know how many Subscribers exist at any given step.
#[derive(Debug, TypeGenerator)]
enum Op {
    /// Publish the next sequential payload.
    Publish,
    /// Register a new Subscriber.
    AddSubscriber,
    /// Snapshot the Subscriber at index `idx % subscribers.len()`.
    /// No-op if no Subscribers are registered.
    Snapshot { idx: u8 },
    /// Drop the Subscriber at index `idx % subscribers.len()`.  No-op
    /// if no Subscribers are registered.
    DropSubscriber { idx: u8 },
    /// Force a reclaim pass on the Publisher.
    Reclaim,
}

/// Counts its own drops; payload doubles as a "what value is this?" tag.
struct Marker {
    payload: u32,
    drops: Arc<AtomicUsize>,
}

impl Drop for Marker {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}

fn marker(payload: u32, drops: &Arc<AtomicUsize>) -> Marker {
    Marker {
        payload,
        drops: Arc::clone(drops),
    }
}

// ---------- the property ----------

#[test]
fn protocol_invariants() {
    bolero::check!()
        .with_type::<Vec<Op>>()
        .for_each(|ops: &Vec<Op>| {
            let ops = ops.as_slice();
            let drops = Arc::new(AtomicUsize::new(0));
            let (mut publisher, factory) = channel(marker(0, &drops));
            let mut subscribers = Vec::new();
            let mut last_seen: Vec<u32> = Vec::new();
            // Initial publication counts as published, so we start at 1.
            let mut total_published: u32 = 1;
            let mut next_payload: u32 = 1;

            for op in ops {
                match op {
                    Op::Publish => {
                        // Bound the test even on adversarial generators.
                        if total_published >= 1 << 16 {
                            continue;
                        }
                        publisher.publish(marker(next_payload, &drops));
                        next_payload += 1;
                        total_published += 1;
                    }
                    Op::AddSubscriber => {
                        subscribers.push(factory.subscriber());
                        last_seen.push(0);
                    }
                    Op::Snapshot { idx } => {
                        if !subscribers.is_empty() {
                            let i = (*idx as usize) % subscribers.len();
                            let observed = subscribers[i].snapshot().payload;

                            assert!(
                                observed >= last_seen[i],
                                "Subscriber {i} regressed: saw {observed} after {last}",
                                last = last_seen[i],
                            );
                            assert!(
                                observed < total_published,
                                "snapshot {observed} but total_published = {total_published}",
                            );
                            last_seen[i] = observed;
                        }
                    }
                    Op::DropSubscriber { idx } => {
                        if !subscribers.is_empty() {
                            let i = (*idx as usize) % subscribers.len();
                            subscribers.swap_remove(i);
                            last_seen.swap_remove(i);
                        }
                    }
                    Op::Reclaim => {
                        publisher.reclaim();
                    }
                }

                // Conservation: every `Versioned` that was ever published
                // is either the current slot (1), in `retired`
                // (`pending_reclamation()` of them), or dropped.  A
                // Subscriber's `cached` Arc shares an allocation with one
                // of those; it does not introduce a fourth bucket.
                let alive = 1 + publisher.pending_reclamation();
                let dropped = drops.load(Ordering::Relaxed);
                assert_eq!(
                    dropped + alive,
                    total_published as usize,
                    "conservation: dropped {dropped} + alive {alive} != published {total_published}",
                );
            }

            // Tear-down: drop everything explicitly so the final-drops
            // assertion below has a well-defined point to fire at.
            drop(subscribers);
            drop(publisher);
            drop(factory);

            let final_drops = drops.load(Ordering::Relaxed);
            assert_eq!(
                final_drops, total_published as usize,
                "after tear-down, every Versioned should have been dropped exactly once",
            );
        });
}
