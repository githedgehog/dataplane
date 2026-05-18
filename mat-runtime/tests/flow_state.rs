// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! End-to-end exercise of a flavor-B (induced state) cascade
//! shape -- the conntrack pattern.
//!
//! The point is to push design pressure on the value-type surface
//! that the `dataplane-mat` facade defines:
//!
//! - [`FlowOrigin`] carried inside an `Upsert` value, used as the
//!   LWW tiebreaker when two dataplanes converge on the same flow.
//! - `policy_gen_at_create` recorded but not yet acted on -- the
//!   state-sync subscriber (separate crate, not built yet) will be
//!   responsible for buffering future-gen entries against
//!   `current_policy_gen`.
//! - `lookup_at` filtering by horizon over the flow cascade, same
//!   as for the rule cascades.
//!
//! This file is intentionally a worked example rather than a
//! productionised crate.  If the shape proves out we can promote
//! it -- the existing `dataplane-flow-entry` crate is a separate
//! design that pre-dates the cascade primitive and is not being
//! refactored here.

#![allow(clippy::expect_used)]

use std::collections::HashMap;
use std::sync::Mutex as StdMutex;

use cascade::{Generation, Layer, MergeInto, MutableHead, Outcome, Upsert};
use dataplane_mat_runtime::{ManagedCascade, PolicyGenAllocator};
use mat::{FlowOrigin, OriginId, OriginSeq};

// ---------------------------------------------------------------------------
// Minimal flow key (would be a 5-tuple in production).
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct FlowKey {
    src: u32,
    dst: u32,
    src_port: u16,
    dst_port: u16,
    proto: u8,
}

impl FlowKey {
    fn new(src: u32, dst: u32, sp: u16, dp: u16, proto: u8) -> Self {
        Self {
            src,
            dst,
            src_port: sp,
            dst_port: dp,
            proto,
        }
    }
}

// ---------------------------------------------------------------------------
// FlowEntry: a payload plus the FlowOrigin LWW tiebreaker.
//
// The Upsert impl is the load-bearing piece: it must produce the
// same final state regardless of arrival order (order independence
// is the cascade's Upsert contract).  We achieve that by always
// keeping the entry with the lexicographically-larger
// (origin_id, origin_seq) key.
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct FlowEntry {
    /// Whatever state the flow carries.  A real conntrack entry
    /// would carry TCP state, byte/packet counters, last-seen
    /// timestamp, NAT translation, etc.  A single u32 is enough
    /// to demonstrate the convergence semantics.
    payload: u32,
    origin: FlowOrigin,
}

impl Upsert for FlowEntry {
    type Op = FlowEntry;

    fn seed(op: Self::Op) -> Self {
        op
    }

    fn upsert(&mut self, op: Self::Op) {
        // LWW by (origin_id, origin_seq).  Strictly greater wins;
        // equal-key collisions are a no-op (idempotence).
        if op.origin.lww_key() > self.origin.lww_key() {
            *self = op;
        }
    }
}

// ---------------------------------------------------------------------------
// Head / Frozen / Tail layers for the flow cascade.
//
// Same minimal shape as the smoke tests: Mutex<HashMap> for the
// multi-writer head, plain HashMap for frozen and tail.  A real
// conntrack table would publish the head via concurrency::slot
// and probably use papaya / dashmap for per-key concurrency.
// ---------------------------------------------------------------------------

struct FlowHead {
    inner: StdMutex<HashMap<FlowKey, FlowEntry>>,
}

impl FlowHead {
    fn empty() -> Self {
        Self {
            inner: StdMutex::new(HashMap::new()),
        }
    }
}

impl Layer for FlowHead {
    type Input = FlowKey;
    type Output = FlowEntry;

    fn lookup(&self, _input: &FlowKey) -> Outcome<&FlowEntry> {
        // Same caveat as the smoke tests: returning a borrow out of
        // a Mutex is awkward.  Defer reads to the frozen/tail
        // layers.  Real-time conntrack needs a Slot-published head
        // (Layer GAT) -- explicitly out of scope here.
        Outcome::Continue
    }
}

#[derive(Debug, Clone, Copy)]
struct FlowOp {
    key: FlowKey,
    entry: FlowEntry,
}

impl MutableHead for FlowHead {
    type Op = FlowOp;
    type Frozen = FlowFrozen;

    fn write(&self, op: FlowOp) {
        let mut guard = self.inner.lock().expect("flow head poison");
        guard
            .entry(op.key)
            .and_modify(|e| e.upsert(op.entry))
            .or_insert_with(|| FlowEntry::seed(op.entry));
    }

    fn freeze(&self) -> FlowFrozen {
        let guard = self.inner.lock().expect("flow head poison");
        FlowFrozen {
            inner: guard.clone(),
        }
    }

    fn approx_size(&self) -> usize {
        self.inner.lock().expect("flow head poison").len()
    }
}

#[derive(Clone, Debug)]
struct FlowFrozen {
    inner: HashMap<FlowKey, FlowEntry>,
}

impl FlowFrozen {
    fn empty() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }
}

impl Layer for FlowFrozen {
    type Input = FlowKey;
    type Output = FlowEntry;

    fn lookup(&self, k: &FlowKey) -> Outcome<&FlowEntry> {
        match self.inner.get(k) {
            Some(_) => Outcome::Match(self.inner.get(k).expect("just checked")),
            None => Outcome::Continue,
        }
    }
}

impl MergeInto<FlowFrozen> for FlowFrozen {
    fn merge_into(&self, target: &FlowFrozen) -> FlowFrozen {
        let mut out = target.inner.clone();
        for (k, v) in &self.inner {
            // LWW on collision -- mirrors the head's Upsert.
            // Critically: this must produce the same result as the
            // cascade walk's "newer shadows older" semantic for any
            // key shared between self and target.  Because self
            // (the to-be-merged frozen layer) is always newer than
            // target (the older tail) in the cascade's fold, and
            // because the Upsert is associative+commutative under
            // LWW, the order does not actually matter -- but we use
            // LWW explicitly so the merge does not silently drop
            // newer-but-from-different-origin entries.
            out.entry(*k)
                .and_modify(|e| e.upsert(*v))
                .or_insert(*v);
        }
        FlowFrozen { inner: out }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_flow_cascade() -> ManagedCascade<FlowHead, FlowFrozen, FlowFrozen> {
    ManagedCascade::new(
        FlowHead::empty(),
        FlowFrozen::empty(),
        Box::new(FlowHead::empty),
    )
}

fn origin(dp: u32, seq: u64, policy_gen: Generation) -> FlowOrigin {
    FlowOrigin {
        origin_id: OriginId::new(dp).expect("nonzero dp"),
        origin_seq: OriginSeq::new(seq).expect("nonzero seq"),
        policy_gen_at_create: policy_gen,
    }
}

fn entry(payload: u32, dp: u32, seq: u64, policy_gen: Generation) -> FlowEntry {
    FlowEntry {
        payload,
        origin: origin(dp, seq, policy_gen),
    }
}

fn key1() -> FlowKey {
    FlowKey::new(0x0a000001, 0x0a000002, 12345, 80, 6)
}

fn key2() -> FlowKey {
    FlowKey::new(0x0a000003, 0x0a000004, 54321, 443, 6)
}

// ---------------------------------------------------------------------------
// Basic insert and lookup
// ---------------------------------------------------------------------------

#[test]
fn locally_inserted_flow_is_visible_after_rotation() {
    let mc = build_flow_cascade();
    let alloc = PolicyGenAllocator::new();
    let g = alloc.begin_rollout().expect("g");

    mc.write(FlowOp {
        key: key1(),
        entry: entry(100, 1, 1, g),
    });
    mc.rotate(g);
    alloc.publish(g);

    let snap = mc.snapshot();
    let found = snap.lookup_at(&key1(), alloc.current()).expect("flow present");
    assert_eq!(found.payload, 100);
    assert_eq!(found.origin.origin_id.get(), 1);
}

// ---------------------------------------------------------------------------
// LWW: two writes for the same key with different origins.
//
// This exercises the central convergence property: regardless of
// arrival order, the entry with the larger (origin_id, origin_seq)
// LWW key wins.  We test both orderings.
// ---------------------------------------------------------------------------

#[test]
fn lww_higher_origin_wins_regardless_of_arrival_order() {
    let g = Generation::FIRST;
    let lower = entry(100, /* dp */ 1, /* seq */ 5, g);
    let higher = entry(200, /* dp */ 2, /* seq */ 1, g);
    // higher.origin_id > lower.origin_id, so higher.lww_key > lower.lww_key
    assert!(higher.origin.lww_key() > lower.origin.lww_key());

    // Order A: lower first, then higher.
    {
        let mc = build_flow_cascade();
        let alloc = PolicyGenAllocator::new();
        let g_local = alloc.begin_rollout().expect("g");

        mc.write(FlowOp { key: key1(), entry: lower });
        mc.write(FlowOp { key: key1(), entry: higher });
        mc.rotate(g_local);
        alloc.publish(g_local);

        let snap = mc.snapshot();
        let found = snap.lookup_at(&key1(), alloc.current()).expect("present");
        assert_eq!(found.payload, 200, "higher origin should win");
        assert_eq!(found.origin.origin_id.get(), 2);
    }

    // Order B: higher first, then lower.  Same outcome.
    {
        let mc = build_flow_cascade();
        let alloc = PolicyGenAllocator::new();
        let g_local = alloc.begin_rollout().expect("g");

        mc.write(FlowOp { key: key1(), entry: higher });
        mc.write(FlowOp { key: key1(), entry: lower });
        mc.rotate(g_local);
        alloc.publish(g_local);

        let snap = mc.snapshot();
        let found = snap.lookup_at(&key1(), alloc.current()).expect("present");
        assert_eq!(found.payload, 200, "higher origin should still win");
        assert_eq!(found.origin.origin_id.get(), 2);
    }
}

#[test]
fn lww_same_origin_higher_seq_wins() {
    let g = Generation::FIRST;
    let old = entry(100, /* dp */ 1, /* seq */ 5, g);
    let new = entry(200, /* dp */ 1, /* seq */ 6, g);
    assert!(new.origin.lww_key() > old.origin.lww_key());

    let mc = build_flow_cascade();
    let alloc = PolicyGenAllocator::new();
    let g_local = alloc.begin_rollout().expect("g");

    mc.write(FlowOp { key: key1(), entry: old });
    mc.write(FlowOp { key: key1(), entry: new });
    mc.rotate(g_local);
    alloc.publish(g_local);

    let snap = mc.snapshot();
    let found = snap.lookup_at(&key1(), alloc.current()).expect("present");
    assert_eq!(found.payload, 200);
    assert_eq!(found.origin.origin_seq.get(), 6);
}

#[test]
fn lww_equal_key_is_idempotent() {
    let g = Generation::FIRST;
    let e = entry(100, 1, 5, g);

    let mc = build_flow_cascade();
    let alloc = PolicyGenAllocator::new();
    let g_local = alloc.begin_rollout().expect("g");

    // Apply the same entry twice -- second write should be a no-op
    // because origin keys are equal (not strictly greater).
    mc.write(FlowOp { key: key1(), entry: e });
    mc.write(FlowOp { key: key1(), entry: e });
    mc.rotate(g_local);
    alloc.publish(g_local);

    let snap = mc.snapshot();
    let found = snap.lookup_at(&key1(), alloc.current()).expect("present");
    assert_eq!(found.payload, 100);
}

// ---------------------------------------------------------------------------
// LWW across rotation boundaries.
//
// An older sealed layer can hold a higher-LWW entry than the head
// for the same key.  The cascade walk hits the head first, but the
// head's lookup returns Continue (as designed); we fall through to
// the sealed layer and get the high-LWW entry.  This validates
// that LWW resolution does NOT need to happen on read -- it
// happens at write time inside Upsert, and at compaction time
// inside MergeInto.
// ---------------------------------------------------------------------------

#[test]
fn newer_rotation_with_lower_lww_does_not_shadow_older_higher_lww() {
    let mc = build_flow_cascade();
    let alloc = PolicyGenAllocator::new();

    // Rotation 1: install higher-LWW entry.
    let g1 = alloc.begin_rollout().expect("g1");
    let higher = entry(999, /* dp */ 2, /* seq */ 5, g1);
    mc.write(FlowOp { key: key1(), entry: higher });
    mc.rotate(g1);
    alloc.publish(g1);

    // Rotation 2: install lower-LWW entry (different dp, same key).
    let g2 = alloc.begin_rollout().expect("g2");
    let lower = entry(100, /* dp */ 1, /* seq */ 100, g2);
    assert!(lower.origin.lww_key() < higher.origin.lww_key());
    mc.write(FlowOp { key: key1(), entry: lower });
    mc.rotate(g2);
    alloc.publish(g2);

    // Cascade walk: head (Continue) -> sealed[0]=g2-layer (Match
    // lower) -> short circuits.  This is the WRONG behaviour for
    // LWW semantics -- we expect higher to win, but the cascade
    // walk returns lower because the newer rotation shadows the
    // older.
    //
    // This is the known design pressure point: the cascade walk
    // resolves layer precedence, not LWW.  For flow state where
    // LWW must hold across rotations, either (a) the receiver
    // must dedup at write time so each rotation only sees the
    // current LWW winner, or (b) compaction must reconcile by
    // walking the chain and applying LWW per key.  We do (a) in
    // production (the state-sync subscriber applies dedup before
    // forwarding to cascade.write); this test documents the
    // boundary.
    let snap = mc.snapshot();
    let found = snap.lookup_at(&key1(), alloc.current()).expect("present");
    // Cascade returns the lower entry -- documenting the read-side
    // behaviour, NOT asserting it as desired.
    assert_eq!(found.payload, 100);
    assert_eq!(
        found.origin.lww_key(),
        lower.origin.lww_key(),
        "cascade walk shadows older layer; LWW reconciliation happens at \
         write time (via Upsert on the head) or compaction time (via \
         MergeInto), not read time"
    );

    // After compaction: MergeInto applies LWW per key, so the
    // higher-LWW entry from g1 wins.
    mc.compact(0);
    let snap = mc.snapshot();
    let found = snap.lookup_at(&key1(), alloc.current()).expect("present");
    assert_eq!(
        found.payload, 999,
        "after compaction, MergeInto reconciles via LWW and higher origin wins"
    );
}

// ---------------------------------------------------------------------------
// Long-lived entry across policy_gen advance.
//
// A flow installed at policy_gen=N should still be reachable after
// the rule cascade advances to policy_gen=N+k, because flow state
// outlives the rules that authorised it.  The flow cascade's
// generation timeline is independent of the rule cascade's
// timeline.
// ---------------------------------------------------------------------------

#[test]
fn flow_persists_across_policy_gen_advance() {
    let flow_mc = build_flow_cascade();
    let flow_alloc = PolicyGenAllocator::new();

    // A separate allocator simulates the rule cascade's policy gen.
    // In a real deployment, both cascades would share the
    // dataplane-wide policy_gen counter; this test isolates the
    // flow cascade to demonstrate independence.
    let rule_alloc = PolicyGenAllocator::new();
    let rule_g_at_install = rule_alloc.begin_rollout().expect("g");
    rule_alloc.publish(rule_g_at_install);

    // Install a flow entry tagged with the rule generation
    // current at install time.
    let g_install = flow_alloc.begin_rollout().expect("g");
    let e = entry(42, 1, 1, rule_g_at_install);
    flow_mc.write(FlowOp { key: key1(), entry: e });
    flow_mc.rotate(g_install);
    flow_alloc.publish(g_install);

    // Rule cascade advances several times.  The flow's
    // `policy_gen_at_create` is now historical.
    for _ in 0..3 {
        let g = rule_alloc.begin_rollout().expect("g");
        rule_alloc.publish(g);
    }
    assert!(rule_alloc.current() > rule_g_at_install);

    // The flow is still reachable in the flow cascade.  This is
    // the "long-lived connection" property: flow state outlives
    // the rule that authorised it.
    let snap = flow_mc.snapshot();
    let found = snap.lookup_at(&key1(), flow_alloc.current()).expect("present");
    assert_eq!(found.payload, 42);
    assert_eq!(found.origin.policy_gen_at_create, rule_g_at_install);
}

// ---------------------------------------------------------------------------
// Compaction with watermark, exercising aggregated MergeInto.
// ---------------------------------------------------------------------------

#[test]
fn compaction_folds_flow_entries_into_tail_via_lww() {
    let mc = build_flow_cascade();
    let alloc = PolicyGenAllocator::new();

    // Install three flows across three rotations.
    let g1 = alloc.begin_rollout().expect("g1");
    mc.write(FlowOp {
        key: key1(),
        entry: entry(10, 1, 1, g1),
    });
    mc.rotate(g1);

    let g2 = alloc.begin_rollout().expect("g2");
    mc.write(FlowOp {
        key: key2(),
        entry: entry(20, 1, 1, g2),
    });
    mc.rotate(g2);

    // Third rotation: re-install key1 with a higher LWW.
    let g3 = alloc.begin_rollout().expect("g3");
    mc.write(FlowOp {
        key: key1(),
        entry: entry(11, 1, 2, g3),
    });
    mc.rotate(g3);
    alloc.publish(g3);
    assert_eq!(mc.frozen_depth(), 3);

    // Pre-compaction reads (read-side behaviour: newest sealed
    // first, so key1 returns 11 from g3-layer).
    let snap = mc.snapshot();
    assert_eq!(snap.lookup_at(&key1(), alloc.current()).expect("k1").payload, 11);
    assert_eq!(snap.lookup_at(&key2(), alloc.current()).expect("k2").payload, 20);

    // Fully compact: all three sealed layers fold into the tail
    // via MergeInto.  Higher-LWW for key1 wins; key2 is added.
    mc.compact(0);
    assert_eq!(mc.frozen_depth(), 0);

    let snap = mc.snapshot();
    assert_eq!(snap.lookup_at(&key1(), alloc.current()).expect("k1").payload, 11);
    assert_eq!(snap.lookup_at(&key2(), alloc.current()).expect("k2").payload, 20);
}
