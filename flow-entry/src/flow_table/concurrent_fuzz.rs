// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Concurrent fuzz tests for [`FlowTable`].
//!
//! A single test, [`stress_test_concurrency_model`], drives one
//! bolero-generated [`Scenario`] through [`concurrency::stress`] on every
//! backend — the same dispatch `#[concurrency::test]` uses. This mirrors
//! the bolero x model-checker layout of the other concurrency primitives
//! (see `concurrency/tests/quiescent_shuttle.rs`). bolero is the *outer*
//! loop (it picks the shape: a key seed plus one op stream per worker
//! thread); the backend is the *inner* loop (it explores interleavings of
//! that fixed shape):
//!
//! * **default (std) backend** — `concurrency::stress` runs the body once
//!   on real OS threads. Build with `just test sanitize=thread` to surface
//!   data races inside the table.
//! * **`--features shuttle`** — the body runs under the full portfolio
//!   (Random + PCT [+ DFS]) on the workspace-standard config.
//!
//! Every generated [`Scenario`] is normalized at generation time (see the
//! [`bolero::TypeGenerator`] impl) to keep at least two worker threads
//! inserting, so the portfolio's PCT scheduler — which panics on a body
//! that never has two threads simultaneously runnable — always sees real
//! concurrency, without skipping any shape.
//!
//! The per-scenario stub status doubles as a model of `nat`'s shared NAT
//! pair status (`AtomicNatFlowStatus`, shared between a forward/reverse flow
//! pair in `MasqueradeState::new_pair`): `Op::AdvanceStatus` advances a
//! bounded `0..STATE_COUNT` state machine that multiple workers race on, and
//! every read asserts the byte never escapes that range.
//!
//! # No loom
//!
//! The whole module is `#[cfg(not(feature = "loom"))]`. [`FlowTable`] is
//! `DashMap`-backed, and `DashMap` synchronizes through its own `std`
//! atomics/locks that loom cannot instrument (see `table.rs`'s
//! shuttle-only `concurrency_tests` and the shim-limitation notes in the
//! `concurrency` crate root). Compiling this against loom would
//! type-check but not meaningfully model-check, so we exclude it. Loom
//! coverage, if wanted, belongs on an isolated primitive
//! (`AtomicFlowStatus`, `FlowInfoLocked`) with no `DashMap` in the picture.

#![cfg(test)]
#![cfg(not(feature = "loom"))]

use crate::flow_table::FlowTable;
use concurrency::sync::Arc;
use concurrency::sync::atomic::{AtomicU8, Ordering};
use concurrency::thread;
// `spawn_scoped` is inherent on std's `Builder`, but supplied by `BuilderExt` under shuttle
#[cfg_attr(not(feature = "shuttle"), allow(unused_imports))]
use concurrency::thread::BuilderExt;
use net::FlowKey;
use net::flows::{ExtractRef, FlowInfo};
use std::fmt;
use std::time::{Duration, Instant};

/// Stub [`FlowInfoItem`] payload: a single `Arc<AtomicU8>` that all flows
/// share within one scenario. The blanket
/// `impl<T> FlowInfoItem for T where T: Debug + Send + Sync + 'static + Display`
/// picks this up automatically — no explicit trait impl needed.
///
/// Purpose: exercise the `RwLock`-guarded `FlowInfoLocked` + `Box<dyn
/// FlowInfoItem>` plus `extract_ref` path. The shared inner atomic is a
/// `concurrency::sync` atomic, so it is the one piece of state a model
/// checker definitely sees regardless of which flow a worker hits — it
/// concentrates the race signal.
///
/// It also models `nat`'s [`AtomicNatFlowStatus`]: one status byte shared
/// between a forward/reverse flow pair (`MasqueradeState::new_pair`),
/// advanced as a bounded `0..STATE_COUNT` state machine by `Op::AdvanceStatus`.
/// Concurrent advances race exactly as the two directions of a NAT pair do.
#[derive(Debug)]
struct StubItem {
    status: Arc<AtomicU8>,
}
impl fmt::Display for StubItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "stub({})", self.status.load(Ordering::Relaxed))
    }
}

const STATE_COUNT: u8 = 10;

/// A single table operation. bolero generates op *streams*, so the
/// interleaving of ops across worker threads is the source of
/// nondeterminism the backends explore.
#[derive(Clone, Copy, Debug, bolero::TypeGenerator)]
enum Op {
    Insert,
    Lookup,
    Invalidate,
    ExtendExpiry,
    ReadStubStatus,
    AdvanceStatus,
}

/// One bolero-generated test shape: a key seed plus an op stream for
/// each of the three worker threads. Three workers is enough to expose
/// inserter/mutator/reader contention without blowing up the
/// interleaving space under the model checker.
#[derive(Clone, Debug)]
struct Scenario {
    seed_key: FlowKey,
    ops: [Vec<Op>; 3],
}

impl bolero::TypeGenerator for Scenario {
    /// Generate a scenario, then normalize it so the run always exercises
    /// real concurrency.
    ///
    /// shuttle's PCT scheduler panics ("test closure did not exercise any
    /// concurrency") unless at least two threads are simultaneously
    /// runnable at some scheduling point. Rather than skip degenerate
    /// shapes, we guarantee at least two of the three op streams contain
    /// an `Insert` — an `Insert` does model-visible work (writes
    /// `FlowInfoLocked` + the atomic status) *and* creates a flow for any
    /// `Read`/`Flip` ops to land on. Missing inserts are spliced in at a
    /// driver-chosen offset, so the normalization stays a deterministic
    /// function of the input and a failure still reproduces from its seed.
    fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
        let mut this = Self {
            seed_key: driver.produce()?,
            ops: driver.produce()?,
        };
        let has_insert = |s: &[Op]| s.iter().any(|op| matches!(op, Op::Insert));
        let mut need = 2usize.saturating_sub(this.ops.iter().filter(|s| has_insert(s)).count());
        for i in 0..this.ops.len() {
            if need == 0 {
                break;
            }
            if has_insert(&this.ops[i]) {
                continue;
            }
            let pos = driver.produce::<usize>()? % (this.ops[i].len() + 1);
            this.ops[i].insert(pos, Op::Insert);
            need -= 1;
        }
        Some(this)
    }
}

/// Build a small key set out of the seed [`FlowKey`]: the base key and
/// its reverse. Two distinct keys is enough to expose both same-key
/// contention (workers racing on one `DashMap` shard) and cross-key
/// races (different shards).
fn key_set(base: FlowKey) -> Vec<FlowKey> {
    let rev = base.reverse(None);
    if rev == base {
        vec![base]
    } else {
        vec![base, rev]
    }
}

/// Apply one [`Op`] across the whole key set.
fn apply_op(table: &FlowTable, keys: &[FlowKey], stub_status: &Arc<AtomicU8>, op: Op) {
    for k in keys {
        match op {
            Op::Insert => {
                // Far-future expiry so the per-flow timer never fires
                // inside the test window — we race the insert path, not
                // the expiry path. (The timer task is also cfg'd out
                // entirely under shuttle.)
                let fi = Arc::new(FlowInfo::new(*k, Instant::now() + Duration::from_hours(1)));
                // Stuff a stub item into the locked state so readers and
                // flippers have something to race on.
                {
                    let mut guard = fi.locked.write();
                    guard.nat_state = Some(Box::new(StubItem {
                        status: stub_status.clone(),
                    }));
                }
                let _ = table.insert_from_arc(&fi);
            }
            Op::Lookup => {
                // A returned entry must always carry a legal status;
                // AtomicFlowStatus::load panics on a corrupt u8, so the
                // load itself is the assertion against torn writes /
                // use-after-free.
                if let Some(fi) = table.lookup(k) {
                    let _ = fi.status();
                }
            }
            Op::Invalidate => {
                if let Some(fi) = table.lookup(k) {
                    fi.invalidate();
                }
            }
            Op::ExtendExpiry => {
                if let Some(fi) = table.lookup(k) {
                    let _ = fi.extend_expiry(Duration::from_mins(1));
                }
            }
            Op::ReadStubStatus => {
                if let Some(fi) = table.lookup(k)
                    && let Some(stub) = fi
                        .locked
                        .read()
                        .nat_state
                        .as_ref()
                        .extract_ref::<StubItem>()
                {
                    // The shared status is only ever advanced within
                    // 0..STATE_COUNT; an out-of-range byte means a torn write
                    // or corrupted nat_state.
                    let v = stub.status.load(Ordering::Relaxed);
                    assert!(v < STATE_COUNT, "stub status out of range: {v}");
                }
            }
            Op::AdvanceStatus => {
                if let Some(fi) = table.lookup(k)
                    && let Some(stub) = fi
                        .locked
                        .read()
                        .nat_state
                        .as_ref()
                        .extract_ref::<StubItem>()
                {
                    // Advance the shared status one step, modelling a packet
                    // driving the NAT state machine via this flow.
                    let cur = stub.status.load(Ordering::Relaxed);
                    stub.status
                        .store((cur + 1) % STATE_COUNT, Ordering::Relaxed);
                }
            }
        }
    }
}

impl Scenario {
    /// Run the scenario to completion: spawn a worker per op stream, run the
    /// streams concurrently, then sweep every surviving entry for a legal
    /// status.
    ///
    /// `rt` is the tokio handle the std backend needs: `FlowTable::insert`
    /// schedules a per-flow expiry timer via `tokio::task::spawn`, which
    /// panics outside a runtime context. Each worker enters the handle so
    /// the spawn succeeds; the queued timer tasks never run (far-future
    /// expiry) and are dropped with the runtime. Under shuttle the timer
    /// path is cfg'd out, so `rt` is `None`.
    fn run(&self, handle: Option<&tokio::runtime::Handle>) {
        let keys: Arc<Vec<FlowKey>> = Arc::new(key_set(self.seed_key));
        let table = Arc::new(FlowTable::default());
        // One atomic per scenario, cloned into every inserted stub. Every
        // read/flip across all flows hits this same atomic, so a racing
        // load/store is visible regardless of which flow a worker looks up.
        let stub_status = Arc::new(AtomicU8::new(0));

        concurrency::thread::scope(|scope| {
            let handles: Vec<_> = self
                .ops
                .iter()
                .enumerate()
                .map(|(i, ops)| {
                    let keys = keys.clone();
                    let table = table.clone();
                    let stub_status = stub_status.clone();
                    let ops = ops.clone();
                    thread::Builder::new()
                        .name(format!("worker-{i}"))
                        .spawn_scoped(scope, move || {
                            let _guard = handle.map(tokio::runtime::Handle::enter);
                            for op in ops {
                                apply_op(&table, &keys, &stub_status, op);
                                // Give the model checker a preemption point
                                // between ops; a cheap hint under std.
                                thread::yield_now();
                            }
                        })
                        .expect("spawn worker")
                })
                .collect();
            for h in handles {
                h.join().expect("worker panicked");
            }
        });

        // Whatever survives must still be a valid FlowStatus value;
        // AtomicFlowStatus::load panics on a corrupt u8, so touching
        // .status() here catches use-after-free / torn writes the sanitizer
        // itself might not flag. Also touch the stub atomic via extract_ref
        // to make sure the locked state isn't corrupted.
        table.for_each_flow(|_k, v| {
            let _ = v.status();
            let guard = v.locked.read();
            if let Some(stub) = guard.nat_state.as_ref().extract_ref::<StubItem>() {
                let s = stub.status.load(Ordering::Relaxed);
                assert!(s < STATE_COUNT, "stub status out of range: {s}");
            }
        });
    }
}

/// Drive one bolero shape per iteration through [`concurrency::stress`]:
/// a single direct run on the std backend (real OS threads — build with
/// `just test sanitize=thread`), or the full portfolio under shuttle.
#[test]
fn stress_test_concurrency_model() {
    // Single-threaded runtime is enough: we never need the timer task to
    // run, only a context for `insert`'s `tokio::task::spawn` to succeed.
    let rt = cfg_select! {
        feature = "shuttle" => None::<tokio::runtime::Runtime>,
        _ => Some(
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build tokio runtime")
             )
    };
    let handle = rt.as_ref().map(|rt| rt.handle().clone());
    bolero::check!()
        .with_type()
        .cloned()
        .for_each(|scenario: Scenario| {
            let handle = handle.clone();
            concurrency::stress(move || {
                scenario.run(handle.as_ref());
            });
        });
}
