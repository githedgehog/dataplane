// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! End-to-end state-sync round trip between two simulated dataplanes.
//!
//! Wires together every piece that's been built so far:
//!
//! - Two [`ManagedCascade`] instances, one per fake dataplane.
//! - Two [`PolicyGenAllocator`]s.  These are *dataplane-local*; they
//!   do not share a counter.  See the design note below.
//! - A `ShipToPeer` subscriber on each side that serialises drain
//!   events into [`StateSyncMessage`]s and enqueues them on the
//!   peer's inbound wire.  Only entries that originated locally
//!   are shipped -- entries that arrived from the peer and got
//!   re-frozen on the next rotation are filtered to prevent
//!   amplification loops.
//! - A [`PeerDedup`] on each side that consumes inbound messages,
//!   applies dedup, classifies into Apply / Skip / Buffered, and
//!   feeds Apply outcomes back to the local cascade.
//!
//! The "wire" is an in-memory `Mutex<Vec>` that the test pumps
//! manually -- there is no transport layer here.
//!
//! # Design pressure surfaced
//!
//! The first version of this test failed because `PeerDedup::accept`
//! compares the entry's `policy_gen_at_create` (from the sender's
//! local allocator) against the receiver's `current_policy_gen`
//! (from the receiver's local allocator).  These are not the same
//! timeline -- two dataplanes with independent allocators have no
//! shared meaning for the integer comparison.
//!
//! The RFC originally posited a cross-dataplane `config_ref` (a
//! control-plane-supplied version like `(tenant_id, version)` or a
//! content hash) for exactly this purpose.  The current design
//! collapsed `config_ref` into `policy_gen` to fit metadata budget;
//! that collapse is provisionally incorrect for the buffer check
//! across dataplane boundaries.  Two reasonable resolutions:
//!
//!  1. Reintroduce a cross-dataplane `config_ref` field on
//!     [`FlowOrigin`] for buffer comparison; keep `policy_gen` for
//!     local lookup_at filtering only.
//!  2. Drop the buffer mechanism from `PeerDedup` and rely on the
//!     control plane to deliver flavor-A first; treat any peer
//!     entry as immediately applicable.
//!
//! Pending that resolution, the e2e tests below pass an explicit
//! "ignore the buffer" horizon (`Generation::new(u64::MAX)`) to
//! pump_inbound so the receive path always Applies.  The buffer
//! logic is still exercised in isolation by
//! `mat-state-sync/tests/dedup.rs`, where the policy_gen scale
//! is contrived for unit-test purposes.
//!
//! This open question is recorded as RFC known-unknown #10.

#![allow(clippy::expect_used)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex as StdMutex;

use cascade::{DrainEvent, Generation};
use concurrency::sync::Arc;
use dataplane_mat_runtime::{ManagedCascade, PolicyGenAllocator};
use mat::{MatSubscriber, OriginId, StateSyncMessage, TransportSeq};
use mat_state_sync::{AcceptOutcome, PeerDedup};

mod common;
use common::{entry, key1, key2, FlowFrozen, FlowHead, FlowOp, KeyedFlowEntry};

// ---------------------------------------------------------------------------
// Wire
// ---------------------------------------------------------------------------

type Wire = Arc<StdMutex<Vec<StateSyncMessage<KeyedFlowEntry>>>>;

fn new_wire() -> Wire {
    Arc::new(StdMutex::new(Vec::new()))
}

fn enqueue(wire: &Wire, msg: StateSyncMessage<KeyedFlowEntry>) {
    wire.lock().expect("wire poison").push(msg);
}

fn drain_wire(wire: &Wire) -> Vec<StateSyncMessage<KeyedFlowEntry>> {
    core::mem::take(&mut *wire.lock().expect("wire poison"))
}

/// "Effectively unbounded" horizon -- forces PeerDedup to never
/// buffer.  Use this in tests that don't want to exercise the
/// cross-dataplane policy_gen buffer comparison (see the module
/// docs for why that comparison is currently unsound).
fn no_buffer_horizon() -> Generation {
    Generation::new(u64::MAX).expect("nonzero")
}

// ---------------------------------------------------------------------------
// ShipToPeer subscriber
// ---------------------------------------------------------------------------

struct ShipToPeer {
    local_dp: OriginId,
    next_seq: AtomicU64,
    outbound: Wire,
    observed: StdMutex<Vec<Generation>>,
}

impl ShipToPeer {
    fn new(local_dp: OriginId, outbound: Wire) -> Self {
        Self {
            local_dp,
            next_seq: AtomicU64::new(0),
            outbound,
            observed: StdMutex::new(Vec::new()),
        }
    }

    fn observed(&self) -> Vec<Generation> {
        self.observed.lock().expect("poison").clone()
    }
}

impl MatSubscriber<FlowHead, FlowFrozen> for ShipToPeer {
    fn on_drain(&self, event: DrainEvent<FlowFrozen>) {
        self.observed
            .lock()
            .expect("poison")
            .push(event.generation);

        for (key, fe) in event.layer.inner.iter() {
            if fe.origin.origin_id != self.local_dp {
                // Skip echoed entries that originated at the peer.
                continue;
            }
            let raw = self.next_seq.fetch_add(1, Ordering::Relaxed);
            #[allow(
                clippy::cast_possible_truncation,
                reason = "TransportSeq is u32 and wraps; truncation is intentional"
            )]
            let seq = TransportSeq(core::num::Wrapping(raw as u32));
            let msg = StateSyncMessage {
                msg_seq: seq,
                entry: KeyedFlowEntry(*key, *fe),
            };
            enqueue(&self.outbound, msg);
        }
    }
}

// ---------------------------------------------------------------------------
// FakeDataplane fixture
// ---------------------------------------------------------------------------

struct FakeDataplane {
    dp: OriginId,
    cascade: ManagedCascade<FlowHead, FlowFrozen, FlowFrozen>,
    alloc: PolicyGenAllocator,
    inbound: Wire,
    dedup: PeerDedup<KeyedFlowEntry>,
    shipper: Arc<ShipToPeer>,
    next_origin_seq: AtomicU64,
}

impl FakeDataplane {
    fn new(dp_id: u32, peer_inbound: Wire) -> Self {
        let dp = OriginId::new(dp_id).expect("nonzero");
        let cascade = ManagedCascade::new(
            FlowHead::empty(),
            FlowFrozen::empty(),
            Box::new(FlowHead::empty),
        );
        let shipper = Arc::new(ShipToPeer::new(dp, peer_inbound));
        cascade.add_subscriber(shipper.clone() as Arc<dyn MatSubscriber<FlowHead, FlowFrozen>>);

        Self {
            dp,
            cascade,
            alloc: PolicyGenAllocator::new(),
            inbound: new_wire(),
            dedup: PeerDedup::new(),
            shipper,
            next_origin_seq: AtomicU64::new(1),
        }
    }

    fn next_origin_seq(&self) -> u64 {
        self.next_origin_seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Run a complete rollout: allocate gen, invoke `writes` with
    /// the allocated gen so callers can stamp entries with it,
    /// rotate, publish.  Returns the gen used.
    fn rollout(&self, writes: impl FnOnce(Generation)) -> Generation {
        let g = self.alloc.begin_rollout().expect("alloc");
        writes(g);
        self.cascade.rotate(g);
        self.alloc.publish(g);
        g
    }

    /// Write a flow with this dataplane as the origin, picking up
    /// the supplied generation.  Caller is inside a `rollout`
    /// closure.
    fn write_local(&self, policy_gen: Generation, key: common::FlowKey, payload: u32) {
        let seq = self.next_origin_seq();
        let e = entry(payload, self.dp.get(), seq, policy_gen);
        self.cascade.write(FlowOp { key, entry: e });
    }

    /// Pump inbound: drain wire, dedup, apply Apply outcomes via
    /// `cascade.write` (no rotation -- caller decides when to
    /// rotate).  Returns (apply, skip, buffered) counts.
    fn pump_inbound(&self, horizon: Generation) -> (usize, usize, usize) {
        let msgs = drain_wire(&self.inbound);
        let mut applied = 0;
        let mut skipped = 0;
        let mut buffered = 0;
        for m in msgs {
            match self.dedup.accept(m, horizon) {
                AcceptOutcome::Apply(KeyedFlowEntry(k, e)) => {
                    self.cascade.write(FlowOp { key: k, entry: e });
                    applied += 1;
                }
                AcceptOutcome::Skip => skipped += 1,
                AcceptOutcome::Buffered => buffered += 1,
            }
        }
        (applied, skipped, buffered)
    }

    /// Snapshot the cascade.
    fn snapshot(&self) -> cascade::Snapshot<FlowHead, FlowFrozen, FlowFrozen> {
        self.cascade.snapshot()
    }
}

/// Wire two fake dataplanes together with crossed inbound queues.
fn pair() -> (FakeDataplane, FakeDataplane) {
    let wire_1_to_2 = new_wire();
    let wire_2_to_1 = new_wire();
    let mut dp1 = FakeDataplane::new(1, wire_1_to_2.clone());
    let mut dp2 = FakeDataplane::new(2, wire_2_to_1.clone());
    dp1.inbound = wire_2_to_1;
    dp2.inbound = wire_1_to_2;
    (dp1, dp2)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn single_write_propagates_to_peer() {
    let (dp1, dp2) = pair();

    let g1 = dp1.rollout(|g| dp1.write_local(g, key1(), 100));
    assert_eq!(dp1.shipper.observed(), vec![g1]);

    // Wire has one message; DP2 pumps and applies.
    let (a, s, b) = dp2.pump_inbound(no_buffer_horizon());
    assert_eq!((a, s, b), (1, 0, 0));

    // Rotate so the received entry surfaces in a sealed layer.
    let _ = dp2.rollout(|_| {});

    let snap = dp2.snapshot();
    let found = snap.lookup_at(&key1(), dp2.alloc.current()).expect("present");
    assert_eq!(found.payload, 100);
    assert_eq!(found.origin.origin_id.get(), 1);
}

#[test]
fn replay_is_silently_absorbed_via_dedup() {
    let (dp1, dp2) = pair();

    let _ = dp1.rollout(|g| dp1.write_local(g, key1(), 100));

    // First pump: applies.
    let (a, _, _) = dp2.pump_inbound(no_buffer_horizon());
    assert_eq!(a, 1);

    // Synthesise a replay of the same message and shove it on DP2's
    // inbound wire.  Dedup should reject it.
    enqueue(
        &dp2.inbound,
        StateSyncMessage {
            msg_seq: TransportSeq(core::num::Wrapping(0)),
            entry: KeyedFlowEntry(
                key1(),
                entry(100, 1, 1, Generation::new(2).expect("nonzero")),
            ),
        },
    );

    let (a, s, b) = dp2.pump_inbound(no_buffer_horizon());
    assert_eq!((a, s, b), (0, 1, 0));
}

#[test]
fn concurrent_writes_for_same_key_converge_via_lww() {
    let (dp1, dp2) = pair();

    // Both DPs write the same key locally.  origin_id 1 vs 2 -> 2
    // wins on lexicographic LWW.
    let _ = dp1.rollout(|g| dp1.write_local(g, key1(), 111));
    let _ = dp2.rollout(|g| dp2.write_local(g, key1(), 222));

    // Pump in both directions.
    let _ = dp1.pump_inbound(no_buffer_horizon());
    let _ = dp2.pump_inbound(no_buffer_horizon());

    // Re-rotate to expose the just-applied peer entries.
    let _ = dp1.rollout(|_| {});
    let _ = dp2.rollout(|_| {});

    // Compact so MergeInto reconciles via LWW across layers (see
    // RFC unknown #9: the cascade walk does not LWW-reconcile).
    dp1.cascade.compact(0);
    dp2.cascade.compact(0);

    let snap1 = dp1.snapshot();
    let snap2 = dp2.snapshot();
    let f1 = snap1.lookup_at(&key1(), dp1.alloc.current()).expect("dp1");
    let f2 = snap2.lookup_at(&key1(), dp2.alloc.current()).expect("dp2");

    assert_eq!(f1.origin.origin_id.get(), 2);
    assert_eq!(f1.payload, 222);
    assert_eq!(f2.origin.origin_id.get(), 2);
    assert_eq!(f2.payload, 222);
}

#[test]
fn shipper_filter_prevents_amplification_loop() {
    let (dp1, dp2) = pair();

    // DP1 writes locally; DP2 receives and rotates.  Since DP2's
    // rotation contains an origin=DP1 entry, the shipper filter
    // should keep DP1's inbound queue empty (no echo).
    let _ = dp1.rollout(|g| dp1.write_local(g, key1(), 100));
    let (a, _, _) = dp2.pump_inbound(no_buffer_horizon());
    assert_eq!(a, 1);
    let _ = dp2.rollout(|_| {});

    assert_eq!(
        dp1.inbound.lock().expect("p").len(),
        0,
        "shipper filter should suppress origin=DP1 entries when DP2 ships"
    );

    // DP2 writes locally; that DOES get shipped to DP1.
    let _ = dp2.rollout(|g| dp2.write_local(g, key2(), 200));
    assert_eq!(dp1.inbound.lock().expect("p").len(), 1);

    let (a, _, _) = dp1.pump_inbound(no_buffer_horizon());
    assert_eq!(a, 1);
    let _ = dp1.rollout(|_| {});

    let snap = dp1.snapshot();
    let found = snap.lookup_at(&key2(), dp1.alloc.current()).expect("present");
    assert_eq!(found.origin.origin_id.get(), 2);
}

// ---------------------------------------------------------------------------
// The cross-dataplane policy_gen comparison is currently unsound
// (see module docs).  The buffer mechanism is still tested in
// isolation by mat-state-sync/tests/dedup.rs; here we just confirm
// the e2e wiring routes a Buffered outcome correctly without
// asserting policy_gen semantics across dataplanes.
// ---------------------------------------------------------------------------

#[test]
fn buffered_entries_can_be_drained_via_advance_policy_gen() {
    let (dp1, dp2) = pair();

    // Use a horizon below the actual entry's policy_gen so it
    // buffers.  We pass `Generation::FIRST` -- DP1's first write
    // uses gen >= FIRST+1, so all entries are "future" from this
    // horizon's perspective.
    let _ = dp1.rollout(|g| dp1.write_local(g, key1(), 100));

    let (a, s, b) = dp2.pump_inbound(Generation::FIRST);
    assert_eq!((a, s, b), (0, 0, 1));
    assert_eq!(dp2.dedup.buffered_count(), 1);

    // Advance the horizon (in reality, DP2's policy_gen catches up
    // -- the meaning of "catches up" across dataplanes is the open
    // design question; here we just exercise the mechanism).
    let released = dp2.dedup.advance_policy_gen(no_buffer_horizon());
    assert_eq!(released.len(), 1);

    // Apply released entries to the cascade and rotate.
    for KeyedFlowEntry(k, e) in released {
        dp2.cascade.write(FlowOp { key: k, entry: e });
    }
    let _ = dp2.rollout(|_| {});

    let snap = dp2.snapshot();
    let found = snap.lookup_at(&key1(), dp2.alloc.current()).expect("present");
    assert_eq!(found.payload, 100);
}
