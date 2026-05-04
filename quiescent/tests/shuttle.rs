// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Bolero x shuttle property tests.
//!
//! Generates a [`Plan`] (Publisher ops + Subscriber ops, dispatched to
//! two separate threads) via bolero, then runs each plan once under
//! shuttle's random schedule controller.  Each bolero iteration
//! explores one shape x one interleaving; thousands of bolero
//! iterations widen both axes cheaply.
//!
//! This is the cheap-per-call counterpart to `tests/loom.rs`'s
//! exhaustive small-shape model checking.  Loom proves "no
//! interleaving of these shapes breaks"; shuttle says "we tried many
//! interleavings of many shapes and didn't see a break."  Together
//! they cover the protocol from two complementary angles.
//!
//! You can't really productively run this suite under loom because the
//! cost absolutely explodes with large plans.

#![cfg(not(feature = "loom"))]

use std::panic::RefUnwindSafe;

use bolero::TypeGenerator;
use concurrency::sync::Arc;
use concurrency::sync::atomic::{AtomicUsize, Ordering};
use concurrency::thread;

use dataplane_quiescent::{Subscriber, channel};

// ---------- ops & plan ----------

#[derive(Clone, Debug, TypeGenerator)]
enum PublisherOp {
    Publish,
    Reclaim,
}

#[derive(Clone, Debug, TypeGenerator)]
enum SubscriberOp {
    AddSubscriber,
    Snapshot { idx: u8 },
    DropSubscriber { idx: u8 },
}

#[derive(Clone, Debug, TypeGenerator)]
struct Plan {
    publisher_ops: Vec<PublisherOp>,
    subscriber_ops: Vec<SubscriberOp>,
}

struct Marker {
    payload: u32,
    drops: Arc<AtomicUsize>,
}

impl Drop for Marker {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}

fn run_plan(plan: &Plan) {
    let drops = Arc::new(AtomicUsize::new(0));
    // The initial publication counts as one published value.
    let total = Arc::new(AtomicUsize::new(1));
    let initial = Marker {
        payload: 0,
        drops: Arc::clone(&drops),
    };
    let publisher = channel(initial);

    // Subscriber ops run in a spawned scope thread; Publisher ops run
    // on this (calling) thread.  That gives shuttle two threads to
    // interleave (this one + the spawned one).
    thread::scope(|s| {
        let factory = publisher.factory();
        let total_for_sub = Arc::clone(&total);
        let subscriber_ops = plan.subscriber_ops.clone();
        s.spawn(move || {
            let mut subscribers: Vec<Subscriber<'_, Marker>> = Vec::new();
            let mut last_seen: Vec<u32> = Vec::new();
            for op in &subscriber_ops {
                match op {
                    SubscriberOp::AddSubscriber => {
                        subscribers.push(factory.subscriber());
                        last_seen.push(0);
                    }
                    SubscriberOp::Snapshot { idx } => {
                        if !subscribers.is_empty() {
                            let i = (*idx as usize) % subscribers.len();
                            let observed = subscribers[i].snapshot().payload;
                            let total_at = total_for_sub.load(Ordering::SeqCst);
                            assert!(
                                observed >= last_seen[i],
                                "Subscriber {i} regressed: saw {observed} after {prev}",
                                prev = last_seen[i],
                            );
                            assert!(
                                (observed as usize) < total_at,
                                "snapshot {observed} but total {total_at}",
                            );
                            last_seen[i] = observed;
                        }
                    }
                    SubscriberOp::DropSubscriber { idx } => {
                        if !subscribers.is_empty() {
                            let i = (*idx as usize) % subscribers.len();
                            subscribers.swap_remove(i);
                            last_seen.swap_remove(i);
                        }
                    }
                }
            }
            // subscribers drop here on the subscriber thread
        });

        let mut next_payload: u32 = 1;
        for op in &plan.publisher_ops {
            match op {
                PublisherOp::Publish => {
                    let p = next_payload;
                    next_payload += 1;
                    // Bump `total` BEFORE the publish so any Subscriber
                    // observing payload `p` is guaranteed to see
                    // `total >= p + 1` on the snapshot legality check.
                    // SeqCst keeps the ordering story simple under
                    // shuttle's model.
                    total.fetch_add(1, Ordering::SeqCst);
                    publisher.publish(Marker {
                        payload: p,
                        drops: Arc::clone(&drops),
                    });
                }
                PublisherOp::Reclaim => publisher.reclaim(),
            }
        }
    });
    // After scope: subscriber thread joined, factory dropped.

    drop(publisher);

    // After full tear-down, every Marker should have run its destructor
    // exactly once.
    let final_drops = drops.load(Ordering::SeqCst);
    let total_count = total.load(Ordering::SeqCst);
    assert_eq!(
        final_drops, total_count,
        "after tear-down, drops {final_drops} != total {total_count}",
    );
}

const TEST_TIME: std::time::Duration = std::time::Duration::from_secs(10);

fn fuzz_test<Arg: Clone + TypeGenerator + RefUnwindSafe + std::fmt::Debug>(
    test: impl Fn(Arg) + RefUnwindSafe,
) {
    bolero::check!()
        .with_type()
        .cloned()
        .with_test_time(TEST_TIME)
        .for_each(test);
}

#[test]
#[cfg(feature = "shuttle")]
fn protocol_under_shuttle() {
    fuzz_test(|plan: Plan| shuttle::check_random(move || run_plan(&plan), 1));
}

#[test]
#[cfg(feature = "shuttle")]
fn protocol_under_shuttle_pct() {
    fuzz_test(|plan: Plan| {
        // PCT requires both threads to actually do atomic ops; if
        // either side is effectively empty, shuttle's PCT scheduler
        // panics with "test closure did not exercise any concurrency".
        //
        // For the subscriber thread, "effectively empty" means no
        // `AddSubscriber` op: `Snapshot` and `DropSubscriber` are
        // no-ops until at least one Subscriber has been registered, so
        // the subscriber thread does no atomic work in that case.
        if plan.publisher_ops.is_empty()
            || !plan
                .subscriber_ops
                .iter()
                .any(|op| matches!(op, SubscriberOp::AddSubscriber))
        {
            return;
        }
        shuttle::check_pct(move || run_plan(&plan), 16, 3);
    });
}

#[test]
#[cfg(not(feature = "shuttle"))]
fn protocol_under_std() {
    fuzz_test(|plan: Plan| run_plan(&plan));
}
