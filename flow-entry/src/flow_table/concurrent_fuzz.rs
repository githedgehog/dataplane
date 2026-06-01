// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Concurrent fuzz tests for [`FlowTable`].
//!
//! Two complementary modules, both driven by the same operation universe
//! (insert / lookup / invalidate / extend-expiry / drain-stale) over a small
//! key set:
//!
//! * `sanitizer_fuzz` — compiled in the default (std) concurrency mode. Each
//!   bolero iteration generates a [`FlowKey`], derives a tiny key set from
//!   it, then spawns one real OS thread per operation. Built with
//!   `just test sanitize=thread`, this surfaces data races inside the table.
//!
//! * `shuttle_fuzz` — compiled with `--features shuttle`. Bolero is *not*
//!   used here: shuttle wants a deterministic initial state so it can
//!   explore interleavings. The key set is hand-built (matching the
//!   convention in `table.rs`'s existing shuttle suite) and we lean on
//!   [`shuttle::check_random`] to produce schedule variety.

#![cfg(test)]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::missing_panics_doc)]

use concurrency::concurrency_mode;

#[concurrency_mode(std)]
mod sanitizer_fuzz {
    use crate::flow_table::FlowTable;
    use concurrency::sync::Arc;
    use concurrency::sync::atomic::{AtomicU8, Ordering};
    use net::FlowKey;
    use net::flows::{ExtractRef, FlowInfo, FlowStatus};
    use std::fmt;
    use std::time::{Duration, Instant};

    /// Stub [`FlowInfoItem`] payload: a single `Arc<AtomicU8>` that all flows
    /// share within one bolero iteration. The blanket
    /// `impl<T> FlowInfoItem for T where T: Debug + Send + Sync + 'static + Display`
    /// picks this up automatically — no explicit trait impl needed.
    ///
    /// Purpose: exercise the RwLock-guarded `FlowInfoLocked` + `Box<dyn FlowInfoItem>`
    /// + `extract_ref` path. The shared inner atomic concentrates the race
    /// signal so the sanitizer flags contention regardless of which flow a
    /// worker hits.
    #[derive(Debug)]
    struct StubItem {
        status: Arc<AtomicU8>,
    }
    impl fmt::Display for StubItem {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "stub({})", self.status.load(Ordering::Relaxed))
        }
    }

    /// Operation issued by one worker thread. Each worker is bound to one op
    /// so the *interleaving* of ops across threads is the only source of
    /// nondeterminism — handy when triaging a sanitizer report.
    #[derive(Clone, Copy)]
    enum Op {
        Insert,
        Lookup,
        Invalidate,
        ExtendExpiry,
        DrainStale,
        ReadStubStatus,
        FlipStubStatus,
    }

    fn drive(
        table: &FlowTable,
        keys: &[FlowKey],
        stub_status: &Arc<AtomicU8>,
        seed_status: FlowStatus,
        op: Op,
    ) {
        const OPS_PER_KEY: usize = 8;
        for k in keys {
            for i in 0..OPS_PER_KEY {
                match op {
                    Op::Insert => {
                        // Far-future expiry so the per-flow timer never fires
                        // inside the test window — we race the insert path,
                        // not the expiry path.
                        //
                        // Seed the flow with the bolero-generated `seed_status`
                        // (rather than the implicit `Detached` of `FlowInfo::new`)
                        // so the brief in-DashMap-but-not-yet-Active window inside
                        // `insert_common` exposes a varied status to concurrent
                        // readers/drainers.
                        let fi = Arc::new(FlowInfo::new_with_status(
                            *k,
                            Instant::now() + Duration::from_hours(1),
                            seed_status,
                        ));
                        // Stuff a stub item into the locked state so readers
                        // and flippers have something to race on.
                        {
                            let mut guard = fi.locked.write();
                            guard.nat_state = Some(Box::new(StubItem {
                                status: stub_status.clone(),
                            }));
                        }
                        let _ = table.insert_from_arc(&fi);
                        // `insert_common` unconditionally promotes to Active, so
                        // re-apply the generated status here to land the table
                        // entry in a non-Active terminal state when generated.
                        // This feeds `drain_stale`'s stale predicate
                        // (status != Active) and the lookup/for_each_flow paths
                        // with flows the inserter itself parked as stale.
                        let _ = fi.update_status(seed_status);
                    }
                    Op::Lookup => {
                        let _ = table.lookup(k);
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
                    Op::DrainStale => {
                        // Don't hammer drain_stale — once per key is plenty
                        // and we want the race window to stay small enough
                        // that the inserter usually wins.
                        if i == 0 {
                            table.drain_stale();
                        }
                    }
                    Op::ReadStubStatus => {
                        if let Some(fi) = table.lookup(k) {
                            let guard = fi.locked.read();
                            if let Some(stub) = guard.nat_state.as_ref().extract_ref::<StubItem>() {
                                let _ = stub.status.load(Ordering::Relaxed);
                            }
                        }
                    }
                    Op::FlipStubStatus => {
                        if let Some(fi) = table.lookup(k) {
                            let guard = fi.locked.read();
                            if let Some(stub) = guard.nat_state.as_ref().extract_ref::<StubItem>() {
                                // Value is arbitrary; we only care that the store
                                // races with concurrent loads on the same atomic.
                                stub.status.store(0xA5, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Build a small key set out of one bolero-generated [`FlowKey`]: the
    /// base key and its reverse. Two distinct keys is enough to expose both
    /// same-key contention (workers racing on the same `FlowKey`, i.e. one
    /// `DashMap` shard) and cross-key races (different shards).
    fn key_set(base: FlowKey) -> Vec<FlowKey> {
        let rev = base.reverse(None);
        if rev == base {
            vec![base]
        } else {
            vec![base, rev]
        }
    }

    #[test]
    fn test_flow_table_concurrent_fuzz_sanitizer() {
        // Each bolero case spawns one OS thread per `Op` (7 threads), so a
        // *time*-based budget makes the total thread count vary with machine
        // speed — unpredictable CI cost. Bound it to a fixed iteration count
        // instead (deterministic: 7 threads x ITERATIONS). The default stays
        // low enough to keep the thread-sanitizer run (which builds native, so
        // it takes the `_` arm) bounded; QEMU emulation shrinks further. We
        // can't gate on `cfg(sanitize)` here — it needs the unstable
        // `cfg_sanitize` feature — so the default covers the sanitizer too.
        const ITERATIONS: usize = cfg_select! {
            emulated => 16,
            _ => 128,
        };

        // FlowTable::insert calls tokio::task::spawn to schedule the
        // per-flow expiry timer; that call panics if invoked outside a
        // runtime context. We never need the timer task to actually run —
        // far-future expiries see to that — so a single-threaded runtime is
        // enough. Each worker enters the runtime via Handle::enter() so the
        // spawn succeeds; queued timer tasks accumulate and are dropped
        // with the runtime at the end of the test.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        let handle = rt.handle().clone();

        bolero::check!()
            .with_type::<(FlowKey, FlowStatus)>()
            .with_iterations(ITERATIONS)
            .for_each(|(base, seed_status)| {
                let seed_status = *seed_status;
                let keys: Arc<Vec<FlowKey>> = Arc::new(key_set(*base));
                let table = Arc::new(FlowTable::default());
                // One atomic per iteration, cloned into every inserted stub.
                // Every read/flip across all flows hits this same atomic, so
                // the sanitizer sees the racing load/store regardless of which flow a
                // worker happens to look up.
                let stub_status = Arc::new(AtomicU8::new(0));
                let ops = [
                    Op::Insert,
                    Op::Lookup,
                    Op::Invalidate,
                    Op::ExtendExpiry,
                    Op::DrainStale,
                    Op::ReadStubStatus,
                    Op::FlipStubStatus,
                ];

                let handles: Vec<_> = ops
                    .into_iter()
                    .map(|op| {
                        let keys = keys.clone();
                        let table = table.clone();
                        let stub_status = stub_status.clone();
                        let handle = handle.clone();
                        std::thread::spawn(move || {
                            let _guard = handle.enter();
                            drive(&table, &keys, &stub_status, seed_status, op);
                        })
                    })
                    .collect();

                for h in handles {
                    h.join().expect("worker panicked");
                }

                // Whatever survives must still be a valid FlowStatus value;
                // AtomicFlowStatus::load panics on a corrupt u8, so touching
                // .status() here catches use-after-free / torn writes that
                // the sanitizer itself might not flag. Also touch the stub atomic via
                // extract_ref to make sure the locked state isn't corrupted.
                table.for_each_flow(|_k, v| {
                    let _ = v.status();
                    let guard = v.locked.read();
                    if let Some(stub) = guard.nat_state.as_ref().extract_ref::<StubItem>() {
                        let _ = stub.status.load(Ordering::Relaxed);
                    }
                });
            });
    }
}

#[concurrency_mode(shuttle)]
mod shuttle_fuzz {
    use crate::flow_table::FlowTable;
    use concurrency::sync::Arc;
    use concurrency::sync::atomic::{AtomicU8, Ordering};
    use concurrency::thread;
    use net::flows::{ExtractRef, FlowInfo, FlowStatus};
    use net::packet::VpcDiscriminant;
    use net::tcp::TcpPort;
    use net::vxlan::Vni;
    use net::{FlowKey, FlowKeyData, IpProtoKey, TcpProtoKey};
    use std::fmt;
    use std::net::IpAddr;
    use std::time::{Duration, Instant};

    fn make_keys() -> Vec<FlowKey> {
        (1u16..=4u16)
            .map(|i| {
                FlowKey::Unidirectional(FlowKeyData::new(
                    Some(VpcDiscriminant::VNI(
                        Vni::new_checked(u32::from(i) + 10).unwrap(),
                    )),
                    format!("10.{i}.0.1").parse::<IpAddr>().unwrap(),
                    format!("10.{i}.0.2").parse::<IpAddr>().unwrap(),
                    IpProtoKey::Tcp(TcpProtoKey {
                        src_port: TcpPort::new_checked(1000 + i).unwrap(),
                        dst_port: TcpPort::new_checked(2000 + i).unwrap(),
                    }),
                ))
            })
            .collect()
    }

    /// Three workers (insert / flip-status / lookup) race over a 4-key
    /// universe. `shuttle::check_random` explores 100 interleavings.
    ///
    /// No drainer thread: `FlowTable::drain_stale` has no production
    /// callers — it's only used in these fuzz tests — so exercising it
    /// under shuttle isn't worth the scheduling-space blowup (it
    /// write-locks every `DashMap` shard and touches every flow's atomics).
    #[test]
    fn test_flow_table_concurrent_fuzz_shuttle() {
        const N: usize = 4;
        let keys = make_keys();

        shuttle::check_random(
            move || {
                let table = Arc::new(FlowTable::default());
                let mut handles = vec![];

                handles.push(
                    thread::Builder::new()
                        .name("inserter".to_string())
                        .spawn({
                            let table = table.clone();
                            let keys = keys.clone();
                            move || {
                                for _ in 0..N {
                                    for k in &keys {
                                        let fi = FlowInfo::new(
                                            *k,
                                            Instant::now() + Duration::from_mins(1),
                                        );
                                        let _ = table.insert(fi);
                                        thread::yield_now();
                                    }
                                }
                            }
                        })
                        .unwrap(),
                );

                handles.push(
                    thread::Builder::new()
                        .name("flipper".to_string())
                        .spawn({
                            let table = table.clone();
                            let keys = keys.clone();
                            move || {
                                for _ in 0..N {
                                    for k in &keys {
                                        if let Some(fi) = table.lookup(k) {
                                            fi.invalidate();
                                        }
                                        thread::yield_now();
                                    }
                                }
                            }
                        })
                        .unwrap(),
                );

                handles.push(
                    thread::Builder::new()
                        .name("lookup".to_string())
                        .spawn({
                            let table = table.clone();
                            let keys = keys.clone();
                            move || {
                                for _ in 0..N {
                                    for k in &keys {
                                        if let Some(fi) = table.lookup(k) {
                                            // Status must always be one of
                                            // the four legal variants; the
                                            // load impl panics on a corrupt u8.
                                            let s = fi.status();
                                            assert!(matches!(
                                                s,
                                                FlowStatus::Active
                                                    | FlowStatus::Cancelled
                                                    | FlowStatus::Expired
                                                    | FlowStatus::Detached
                                            ));
                                        }
                                        thread::yield_now();
                                    }
                                }
                            }
                        })
                        .unwrap(),
                );

                for h in handles {
                    h.join().unwrap();
                }

                // Touch every surviving entry's status to flush any torn
                // atomic reads (AtomicFlowStatus::load panics on corrupt u8).
                table.for_each_flow(|_k, v| {
                    let _ = v.status();
                });
            },
            100,
        );
    }

    /// Mimics `nat::common::AtomicNatFlowStatus`: an `Arc<AtomicU8>` stuffed
    /// into `FlowInfoLocked.nat_state` and *shared* between a forward+reverse
    /// pair of flows. Production constructs these in `MasqueradeState::new_pair`
    /// (nat/src/stateful/state.rs); packets on either flow advance the shared
    /// state machine via `status.store(next)`.
    #[derive(Debug)]
    struct SharedStatus(Arc<AtomicU8>);

    impl fmt::Display for SharedStatus {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "ss({})", self.0.load(Ordering::Relaxed))
        }
    }

    // Mirrors NatFlowStatus 0..=9. NatFlowStatus::from(u8) calls
    // unreachable!() outside this range, so a torn write surfaces as a panic.
    const STATE_COUNT: u8 = 10;

    /// Two related flows share one `Arc<AtomicU8>` in their `nat_state`.
    /// Forward and reverse writers race transitions on that one atomic
    /// through two different `FlowInfo`s — the exact production race in
    /// `MasqueradeState::new_pair`. A reader thread asserts the observed
    /// byte stays in range mid-flight.
    #[test]
    fn test_flow_table_shared_status_transition_shuttle() {
        const N: usize = 4;
        let keys = make_keys();

        shuttle::check_random(
            move || {
                let table = Arc::new(FlowTable::default());

                // Build the pair sharing one Arc<AtomicU8>, then insert both.
                let shared = Arc::new(AtomicU8::new(0));
                let now = Instant::now();
                for k in keys.iter().take(2) {
                    let fi = FlowInfo::new(*k, now + Duration::from_mins(1));
                    fi.locked.write().nat_state = Some(Box::new(SharedStatus(shared.clone())));
                    table.insert(fi).unwrap();
                }

                let mut handles = vec![];

                // Forward direction: bump status by +1.
                handles.push(
                    thread::Builder::new()
                        .name("forward".to_string())
                        .spawn({
                            let table = table.clone();
                            let key = keys[0];
                            move || {
                                for _ in 0..N {
                                    if let Some(fi) = table.lookup(&key) {
                                        let g = fi.locked.read();
                                        if let Some(ss) =
                                            g.nat_state.as_ref().extract_ref::<SharedStatus>()
                                        {
                                            let cur = ss.0.load(Ordering::Relaxed);
                                            ss.0.store((cur + 1) % STATE_COUNT, Ordering::Relaxed);
                                        }
                                    }
                                    thread::yield_now();
                                }
                            }
                        })
                        .unwrap(),
                );

                // Reverse direction: bump status by +2 — different stride so
                // shuttle has more reason to interleave non-trivially.
                handles.push(
                    thread::Builder::new()
                        .name("reverse".to_string())
                        .spawn({
                            let table = table.clone();
                            let key = keys[1];
                            move || {
                                for _ in 0..N {
                                    if let Some(fi) = table.lookup(&key) {
                                        let g = fi.locked.read();
                                        if let Some(ss) =
                                            g.nat_state.as_ref().extract_ref::<SharedStatus>()
                                        {
                                            let cur = ss.0.load(Ordering::Relaxed);
                                            ss.0.store((cur + 2) % STATE_COUNT, Ordering::Relaxed);
                                        }
                                    }
                                    thread::yield_now();
                                }
                            }
                        })
                        .unwrap(),
                );

                // Reader: walks both flows and asserts the byte stays legal
                // mid-flight. Catches a torn or out-of-range value before the
                // post-join check below sees only the final state.
                handles.push(
                    thread::Builder::new()
                        .name("reader".to_string())
                        .spawn({
                            let table = table.clone();
                            let keys = keys.clone();
                            move || {
                                for _ in 0..N {
                                    for k in keys.iter().take(2) {
                                        if let Some(fi) = table.lookup(k) {
                                            let g = fi.locked.read();
                                            if let Some(ss) =
                                                g.nat_state.as_ref().extract_ref::<SharedStatus>()
                                            {
                                                let v = ss.0.load(Ordering::Relaxed);
                                                assert!(v < STATE_COUNT, "torn status: {v}");
                                            }
                                        }
                                        thread::yield_now();
                                    }
                                }
                            }
                        })
                        .unwrap(),
                );

                for h in handles {
                    h.join().unwrap();
                }

                let v = shared.load(Ordering::Relaxed);
                assert!(v < STATE_COUNT, "final shared status {v} out of range");
            },
            100,
        );
    }
}
