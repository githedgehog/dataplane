//! Bolero × shuttle property tests.
//!
//! Generates a [`Plan`] (Publisher ops + Subscriber ops, dispatched to
//! two separate threads) via bolero, then runs each plan once under
//! shuttle's random schedule controller.  Each bolero iteration
//! explores one shape × one interleaving; thousands of bolero
//! iterations widen both axes cheaply.
//!
//! This is the cheap-per-call counterpart to `tests/loom.rs`'s
//! exhaustive small-shape model checking.  Loom proves "no
//! interleaving of these shapes breaks"; shuttle says "we tried many
//! interleavings of many shapes and didn't see a break."  Together
//! they cover the protocol from two complementary angles.
//!
//! Run with:
//!
//! ```sh
//! cargo test --profile=fuzz -p dataplane-quiescent --features shuttle --test shuttle
//! ```
//!
//! You can also run this test under the standard library
//!
//! ```sh
//! cargo test --profile=fuzz -p dataplane-quiescent --test shuttle
//! ```
//!
//! You can't really productively run this suite under loom because the cost absolutely
//! explodes with large plans.

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
    let (publisher, factory) = channel(initial);

    let publisher_handle = {
        let drops = Arc::clone(&drops);
        let total = Arc::clone(&total);
        let publisher_ops = plan.publisher_ops.clone();
        thread::spawn(move || {
            let mut publisher = publisher;
            let mut next_payload: u32 = 1;
            for op in &publisher_ops {
                match op {
                    PublisherOp::Publish => {
                        let p = next_payload;
                        next_payload += 1;
                        // Bump `total` BEFORE the publish so any
                        // Subscriber observing payload `p` is
                        // guaranteed to see `total >= p + 1` on the
                        // snapshot legality check.  SeqCst keeps the
                        // ordering story simple under shuttle's model.
                        total.fetch_add(1, Ordering::SeqCst);
                        publisher.publish(Marker {
                            payload: p,
                            drops: Arc::clone(&drops),
                        });
                    }
                    PublisherOp::Reclaim => publisher.reclaim(),
                }
            }
            // publisher drops here on the publisher thread
        })
    };

    let subscriber_handle = {
        let factory = factory.clone();
        let total = Arc::clone(&total);
        let subscriber_ops = plan.subscriber_ops.clone();
        thread::spawn(move || {
            let mut subscribers: Vec<Subscriber<Marker>> = Vec::new();
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
                            let total_at = total.load(Ordering::SeqCst);
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
        })
    };

    publisher_handle.join().unwrap();
    subscriber_handle.join().unwrap();
    drop(factory);

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
    fuzz_test(|plan: Plan| shuttle::check_pct(move || run_plan(&plan), 16, 3));
}

#[test]
#[cfg(not(feature = "shuttle"))]
fn protocol_under_std() {
    fuzz_test(|plan: Plan| run_plan(&plan));
}
