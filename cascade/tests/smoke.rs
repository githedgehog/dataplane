// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(clippy::expect_used)]

use dataplane_cascade::Cascade;

mod common;
use common::{Entry, FrozenMap, GenAlloc, Op, TestHead};

fn build_cascade(
    tail_pairs: impl IntoIterator<Item = (u32, Entry)>,
) -> Cascade<TestHead, FrozenMap, FrozenMap> {
    Cascade::new(TestHead::empty(), FrozenMap::from_pairs(tail_pairs))
}

#[test]
fn tail_hit_when_head_and_sealed_miss() {
    let c = build_cascade([(42, Entry::Value(100))]);
    assert_eq!(c.snapshot().lookup(&42), Some(&Entry::Value(100)));
}

#[test]
fn miss_in_all_layers_returns_none() {
    let c = build_cascade([(1, Entry::Value(10))]);
    assert_eq!(c.snapshot().lookup(&999), None);
}

#[test]
fn rotate_seals_head_into_sealed_layer() {
    let c = build_cascade([(42, Entry::Value(100))]);
    let mut g_alloc = GenAlloc::new();
    c.write((42, Op::Set(200)));
    c.rotate(g_alloc.next(), TestHead::empty);

    let snap = c.snapshot();
    assert_eq!(snap.frozen_depth(), 1);
    assert_eq!(snap.lookup(&42), Some(&Entry::Value(200)));
}

#[test]
fn rotated_tombstone_in_sealed_shadows_tail_value() {
    let c = build_cascade([(42, Entry::Value(100))]);
    let mut g_alloc = GenAlloc::new();
    c.write((42, Op::Tombstone));
    c.rotate(g_alloc.next(), TestHead::empty);

    let snap = c.snapshot();
    assert_eq!(snap.frozen_depth(), 1);
    assert_eq!(snap.lookup(&42), Some(&Entry::Tombstone));
}

#[test]
fn multiple_rotations_stack_in_newest_first_order() {
    let c = build_cascade([(42, Entry::Value(100))]);
    let mut g_alloc = GenAlloc::new();
    c.write((42, Op::Set(200)));
    c.rotate(g_alloc.next(), TestHead::empty);
    c.write((42, Op::Set(300)));
    c.rotate(g_alloc.next(), TestHead::empty);
    c.write((42, Op::Set(400)));
    c.rotate(g_alloc.next(), TestHead::empty);

    let snap = c.snapshot();
    assert_eq!(snap.frozen_depth(), 3);
    assert_eq!(snap.lookup(&42), Some(&Entry::Value(400)));
}

#[test]
fn compact_with_no_sealed_is_noop() {
    let c = build_cascade([(42, Entry::Value(100))]);
    c.compact(0);
    assert_eq!(c.frozen_depth(), 0);
    assert_eq!(c.snapshot().lookup(&42), Some(&Entry::Value(100)));
}

#[test]
fn compact_folds_oldest_sealed_into_tail() {
    let c = build_cascade([(1, Entry::Value(10))]);
    let mut g_alloc = GenAlloc::new();
    c.write((2, Op::Set(20)));
    c.rotate(g_alloc.next(), TestHead::empty);
    c.write((3, Op::Set(30)));
    c.rotate(g_alloc.next(), TestHead::empty);
    assert_eq!(c.frozen_depth(), 2);
    c.compact(1);
    assert_eq!(c.frozen_depth(), 1);

    let snap = c.snapshot();
    assert_eq!(snap.lookup(&1), Some(&Entry::Value(10)));
    assert_eq!(snap.lookup(&2), Some(&Entry::Value(20)));
    assert_eq!(snap.lookup(&3), Some(&Entry::Value(30)));
}

#[test]
fn compact_to_zero_keeps_no_sealed() {
    let c = build_cascade([]);
    let mut g_alloc = GenAlloc::new();
    for v in 1..=5 {
        c.write((v, Op::Set(v * 10)));
        c.rotate(g_alloc.next(), TestHead::empty);
    }
    assert_eq!(c.frozen_depth(), 5);

    c.compact(0);
    assert_eq!(c.frozen_depth(), 0);

    let snap = c.snapshot();
    for v in 1u32..=5 {
        assert_eq!(snap.lookup(&v), Some(&Entry::Value(v * 10)));
    }
}

#[test]
fn compact_applies_tombstones_to_tail() {
    let c = build_cascade([(42, Entry::Value(100))]);
    let mut g_alloc = GenAlloc::new();
    c.write((42, Op::Tombstone));
    c.rotate(g_alloc.next(), TestHead::empty);
    assert_eq!(c.snapshot().lookup(&42), Some(&Entry::Tombstone));
    c.compact(0);
    assert_eq!(c.frozen_depth(), 0);
    assert_eq!(c.snapshot().lookup(&42), None);
}

#[test]
fn snapshot_held_across_compact_keeps_old_layers_alive() {
    let c = build_cascade([(1, Entry::Value(10))]);
    let mut g_alloc = GenAlloc::new();
    c.write((2, Op::Set(20)));
    c.rotate(g_alloc.next(), TestHead::empty);
    let pre_compact = c.snapshot();
    c.compact(0);
    assert_eq!(c.frozen_depth(), 0);
    assert_eq!(pre_compact.lookup(&1), Some(&Entry::Value(10)));
    assert_eq!(pre_compact.lookup(&2), Some(&Entry::Value(20)));
    let post_compact = c.snapshot();
    assert_eq!(post_compact.frozen_depth(), 0);
    assert_eq!(post_compact.lookup(&1), Some(&Entry::Value(10)));
    assert_eq!(post_compact.lookup(&2), Some(&Entry::Value(20)));
}

#[test]
fn snapshot_held_across_rotation_keeps_old_state() {
    let c = build_cascade([(42, Entry::Value(100))]);
    let mut g_alloc = GenAlloc::new();
    c.write((42, Op::Set(200)));
    c.rotate(g_alloc.next(), TestHead::empty);
    let old_snap = c.snapshot();
    c.write((42, Op::Set(300)));
    c.rotate(g_alloc.next(), TestHead::empty);
    assert_eq!(old_snap.lookup(&42), Some(&Entry::Value(200)));
    assert_eq!(c.snapshot().lookup(&42), Some(&Entry::Value(300)));
}

#[test]
fn lookup_at_skips_layers_above_horizon() {
    let c = build_cascade([(1, Entry::Value(10))]);
    let mut g_alloc = GenAlloc::new();
    c.write((1, Op::Set(200)));
    let g_v200 = g_alloc.next();
    c.rotate(g_v200, TestHead::empty);

    c.write((1, Op::Set(300)));
    let g_v300 = g_alloc.next();
    c.rotate(g_v300, TestHead::empty);

    c.write((1, Op::Set(400)));
    let g_v400 = g_alloc.next();
    c.rotate(g_v400, TestHead::empty);

    let snap = c.snapshot();
    assert_eq!(snap.lookup_at(&1, g_v300), Some(&Entry::Value(300)));
    assert_eq!(snap.lookup_at(&1, g_v200), Some(&Entry::Value(200)));
    assert_eq!(snap.lookup(&1), Some(&Entry::Value(400)));
}

#[test]
fn lookup_at_falls_through_to_tail_when_all_frozen_above_horizon() {
    let c = build_cascade([(1, Entry::Value(10))]);
    let mut g_alloc = GenAlloc::new();
    let g_low = g_alloc.next();
    c.write((1, Op::Set(200)));
    c.rotate(g_alloc.next(), TestHead::empty);
    c.write((2, Op::Set(20)));
    c.rotate(g_alloc.next(), TestHead::empty);

    let snap = c.snapshot();
    assert_eq!(snap.lookup_at(&1, g_low), Some(&Entry::Value(10)));
    assert_eq!(snap.lookup_at(&2, g_low), None);
}
