//! Bolero × shuttle property tests.
//!
//! Generates a [`Plan`] (writer ops + reader ops, dispatched to two
//! separate threads) via bolero, then runs each plan once under
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

use dataplane_quiescent::{Reader, channel};

// ---------- ops & plan ----------

#[derive(Clone, Debug, TypeGenerator)]
enum WriterOp {
    Publish,
    Reclaim,
}

#[derive(Clone, Debug, TypeGenerator)]
enum ReaderOp {
    AddReader,
    Snapshot { idx: u8 },
    DropReader { idx: u8 },
}

#[derive(Clone, Debug, TypeGenerator)]
struct Plan {
    writer_ops: Vec<WriterOp>,
    reader_ops: Vec<ReaderOp>,
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
    let (writer, publisher) = channel(initial);

    let writer_handle = {
        let drops = Arc::clone(&drops);
        let total = Arc::clone(&total);
        let writer_ops = plan.writer_ops.clone();
        thread::spawn(move || {
            let mut writer = writer;
            let mut next_payload: u32 = 1;
            for op in &writer_ops {
                match op {
                    WriterOp::Publish => {
                        let p = next_payload;
                        next_payload += 1;
                        // Bump `total` BEFORE the publish so any reader
                        // observing payload `p` is guaranteed to see
                        // `total >= p + 1` on the snapshot legality
                        // check.  SeqCst keeps the ordering story
                        // simple under shuttle's model.
                        total.fetch_add(1, Ordering::SeqCst);
                        writer.publish(Marker {
                            payload: p,
                            drops: Arc::clone(&drops),
                        });
                    }
                    WriterOp::Reclaim => writer.reclaim(),
                }
            }
            // writer drops here on the writer thread
        })
    };

    let reader_handle = {
        let publisher = publisher.clone();
        let total = Arc::clone(&total);
        let reader_ops = plan.reader_ops.clone();
        thread::spawn(move || {
            let mut readers: Vec<Reader<Marker>> = Vec::new();
            let mut last_seen: Vec<u32> = Vec::new();
            for op in &reader_ops {
                match op {
                    ReaderOp::AddReader => {
                        readers.push(publisher.reader());
                        last_seen.push(0);
                    }
                    ReaderOp::Snapshot { idx } => {
                        if !readers.is_empty() {
                            let i = (*idx as usize) % readers.len();
                            let observed = readers[i].snapshot().payload;
                            let total_at = total.load(Ordering::SeqCst);
                            assert!(
                                observed >= last_seen[i],
                                "reader {i} regressed: saw {observed} after {prev}",
                                prev = last_seen[i],
                            );
                            assert!(
                                (observed as usize) < total_at,
                                "snapshot {observed} but total {total_at}",
                            );
                            last_seen[i] = observed;
                        }
                    }
                    ReaderOp::DropReader { idx } => {
                        if !readers.is_empty() {
                            let i = (*idx as usize) % readers.len();
                            readers.swap_remove(i);
                            last_seen.swap_remove(i);
                        }
                    }
                }
            }
            // readers drop here on the reader thread
        })
    };

    writer_handle.join().unwrap();
    reader_handle.join().unwrap();
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
    fuzz_test(|plan: Plan| shuttle::check_pct(move || run_plan(&plan), 16, 3));
}

#[test]
#[cfg(not(feature = "shuttle"))]
fn protocol_under_std() {
    fuzz_test(|plan: Plan| run_plan(&plan));
}
