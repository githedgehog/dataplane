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
//!   state-sync receiver (`mat-state-sync`) buffers future-gen
//!   entries against `current_policy_gen`; see `e2e_sync.rs` for
//!   that path exercised end-to-end.
//! - `lookup_at` filtering by horizon over the flow cascade, same
//!   as for the rule cascades.
//!
//! Data types live in `common/mod.rs` so this test and the e2e
//! sync test can share them without duplication.

#![allow(clippy::expect_used)]

use cascade::Generation;
use dataplane_mat_runtime::{ManagedCascade, PolicyGenAllocator};

mod common;
use common::{
    entry, key1, key2, FlowEntry, FlowFrozen, FlowHead, FlowOp,
};

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn build_flow_cascade() -> ManagedCascade<FlowHead, FlowFrozen, FlowFrozen> {
    ManagedCascade::new(
        FlowHead::empty(),
        FlowFrozen::empty(),
        Box::new(FlowHead::empty),
    )
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
// ---------------------------------------------------------------------------

#[test]
fn lww_higher_origin_wins_regardless_of_arrival_order() {
    let g = Generation::FIRST;
    let lower: FlowEntry = entry(100, 1, 5, g);
    let higher: FlowEntry = entry(200, 2, 1, g);
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
    let old = entry(100, 1, 5, g);
    let new = entry(200, 1, 6, g);
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
    let e: FlowEntry = entry(100, 1, 5, g);

    let mc = build_flow_cascade();
    let alloc = PolicyGenAllocator::new();
    let g_local = alloc.begin_rollout().expect("g");

    mc.write(FlowOp { key: key1(), entry: e });
    mc.write(FlowOp { key: key1(), entry: e });
    mc.rotate(g_local);
    alloc.publish(g_local);

    let snap = mc.snapshot();
    let found = snap.lookup_at(&key1(), alloc.current()).expect("present");
    assert_eq!(found.payload, 100);
}

// ---------------------------------------------------------------------------
// LWW across rotation boundaries -- documents the cascade walk's
// newer-shadows-older behaviour as a design boundary.
//
// See RFC known-unknown #9: the cascade walk does NOT reconcile
// LWW across layers.  The mitigation is to dedup at write time
// (which the state-sync receiver in `mat-state-sync` does); see
// `e2e_sync.rs` for that path.
// ---------------------------------------------------------------------------

#[test]
fn newer_rotation_with_lower_lww_does_not_shadow_older_higher_lww() {
    let mc = build_flow_cascade();
    let alloc = PolicyGenAllocator::new();

    let g1 = alloc.begin_rollout().expect("g1");
    let higher: FlowEntry = entry(999, 2, 5, g1);
    mc.write(FlowOp { key: key1(), entry: higher });
    mc.rotate(g1);
    alloc.publish(g1);

    let g2 = alloc.begin_rollout().expect("g2");
    let lower: FlowEntry = entry(100, 1, 100, g2);
    assert!(lower.origin.lww_key() < higher.origin.lww_key());
    mc.write(FlowOp { key: key1(), entry: lower });
    mc.rotate(g2);
    alloc.publish(g2);

    let snap = mc.snapshot();
    let found = snap.lookup_at(&key1(), alloc.current()).expect("present");
    // Cascade walk returns the lower entry from the newer layer.
    assert_eq!(found.payload, 100);
    assert_eq!(
        found.origin.lww_key(),
        lower.origin.lww_key(),
        "cascade walk shadows older layer; LWW reconciliation happens at \
         write time (via Upsert on the head) or compaction time (via \
         MergeInto), not read time"
    );

    // After compaction, MergeInto reconciles via LWW.
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
// ---------------------------------------------------------------------------

#[test]
fn flow_persists_across_policy_gen_advance() {
    let flow_mc = build_flow_cascade();
    let flow_alloc = PolicyGenAllocator::new();

    let rule_alloc = PolicyGenAllocator::new();
    let rule_g_at_install = rule_alloc.begin_rollout().expect("g");
    rule_alloc.publish(rule_g_at_install);

    let g_install = flow_alloc.begin_rollout().expect("g");
    let e = entry(42, 1, 1, rule_g_at_install);
    flow_mc.write(FlowOp { key: key1(), entry: e });
    flow_mc.rotate(g_install);
    flow_alloc.publish(g_install);

    for _ in 0..3 {
        let g = rule_alloc.begin_rollout().expect("g");
        rule_alloc.publish(g);
    }
    assert!(rule_alloc.current() > rule_g_at_install);

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

    let g3 = alloc.begin_rollout().expect("g3");
    mc.write(FlowOp {
        key: key1(),
        entry: entry(11, 1, 2, g3),
    });
    mc.rotate(g3);
    alloc.publish(g3);
    assert_eq!(mc.frozen_depth(), 3);

    let snap = mc.snapshot();
    assert_eq!(snap.lookup_at(&key1(), alloc.current()).expect("k1").payload, 11);
    assert_eq!(snap.lookup_at(&key2(), alloc.current()).expect("k2").payload, 20);

    mc.compact(0);
    assert_eq!(mc.frozen_depth(), 0);

    let snap = mc.snapshot();
    assert_eq!(snap.lookup_at(&key1(), alloc.current()).expect("k1").payload, 11);
    assert_eq!(snap.lookup_at(&key2(), alloc.current()).expect("k2").payload, 20);
}
