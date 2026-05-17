// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! End-to-end smoke test exercising the cascade trait shape with a
//! trivial concrete implementation.
//!
//! Purpose: make sure the trait bounds line up and the lookup walk
//! produces the expected priority order (head shadows sealed shadows
//! tail, tombstones in the head suppress lower-layer hits).  Also
//! exercises [`Cascade::rotate`]'s seal-and-publish flow.
//!
//! This test is *not* an Absorb-laws property suite -- those will
//! live in their own test file once the property harness lands.

#![allow(clippy::expect_used)]

use std::collections::HashMap;
use std::sync::Mutex;

use dataplane_cascade::{Absorb, Cascade, Layer, MergeInto, MutableHead, Outcome};

// ---------------------------------------------------------------------------
// A trivial value type with two-position Absorb so we exercise both
// arms (replace and tombstone).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Set(u32),
    Tombstone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Entry {
    Value(u32),
    Tombstone,
}

impl Absorb for Entry {
    type Op = Op;

    fn absorb(&mut self, op: Self::Op) {
        *self = Self::seed(op);
    }

    fn seed(op: Self::Op) -> Self {
        match op {
            Op::Set(v) => Entry::Value(v),
            Op::Tombstone => Entry::Tombstone,
        }
    }
}

// ---------------------------------------------------------------------------
// A trivial head: Mutex<HashMap>.  No concurrency value; we just want
// the trait surface exercised.
// ---------------------------------------------------------------------------

struct TestHead {
    inner: Mutex<HashMap<u32, Entry>>,
}

impl TestHead {
    fn empty() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }
}

impl Layer for TestHead {
    type Input = u32;
    type Output = Entry;

    fn lookup(&self, _input: &u32) -> Outcome<&Entry> {
        // Borrowing through a Mutex is awkward.  For the smoke test
        // we deliberately defer the read to the sealed/tail path
        // by always returning Continue.  A real impl would publish an
        // Arc<HashMap<...>> via concurrency::slot::Slot for the read
        // path so that `lookup` can hand out a borrow without
        // holding the mutex.
        Outcome::Continue
    }
}

impl MutableHead for TestHead {
    type Op = (u32, Op);
    type Sealed = SealedMap;

    fn write(&self, op: (u32, Op)) {
        let mut guard = self.inner.lock().expect("test head mutex poisoned");
        let (k, op) = op;
        guard
            .entry(k)
            .and_modify(|e| e.absorb(op))
            .or_insert_with(|| Entry::seed(op));
    }

    fn seal(&self) -> SealedMap {
        let guard = self.inner.lock().expect("test head mutex poisoned");
        SealedMap {
            inner: guard.clone(),
        }
    }

    fn approx_size(&self) -> usize {
        self.inner.lock().expect("test head mutex poisoned").len()
    }
}

// ---------------------------------------------------------------------------
// A trivial sealed/tail layer: plain HashMap.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct SealedMap {
    inner: HashMap<u32, Entry>,
}

impl SealedMap {
    fn from_pairs<I: IntoIterator<Item = (u32, Entry)>>(it: I) -> Self {
        Self {
            inner: it.into_iter().collect(),
        }
    }
}

impl Layer for SealedMap {
    type Input = u32;
    type Output = Entry;

    fn lookup(&self, k: &u32) -> Outcome<&Entry> {
        match self.inner.get(k) {
            Some(Entry::Value(_)) => Outcome::Match(self.inner.get(k).expect("just checked")),
            Some(Entry::Tombstone) => Outcome::Forbid,
            None => Outcome::Continue,
        }
    }
}

// `merge_into` for SealedMap-on-SealedMap: walk self's entries and
// overlay them on a clone of target.  Value entries overwrite;
// tombstones remove (the merged tail does not carry tombstones, it
// just lacks the entry).  Newer-wins as required by the trait.
impl MergeInto<SealedMap> for SealedMap {
    fn merge_into(&self, target: &SealedMap) -> SealedMap {
        let mut out = target.inner.clone();
        for (k, v) in &self.inner {
            match v {
                Entry::Value(_) => {
                    out.insert(*k, *v);
                }
                Entry::Tombstone => {
                    out.remove(k);
                }
            }
        }
        SealedMap { inner: out }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn build_cascade(
    tail_pairs: impl IntoIterator<Item = (u32, Entry)>,
) -> Cascade<TestHead, SealedMap, SealedMap> {
    Cascade::new(TestHead::empty(), SealedMap::from_pairs(tail_pairs))
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

    // Write to head, then rotate.  The write should land in a
    // sealed layer and shadow the tail value.
    c.write((42, Op::Set(200)));
    c.rotate(TestHead::empty);

    let snap = c.snapshot();
    assert_eq!(snap.sealed_depth(), 1);
    assert_eq!(snap.lookup(&42), Some(&Entry::Value(200)));
}

#[test]
fn rotated_tombstone_in_sealed_suppresses_tail_hit() {
    let c = build_cascade([(42, Entry::Value(100))]);
    c.write((42, Op::Tombstone));
    c.rotate(TestHead::empty);

    let snap = c.snapshot();
    assert_eq!(snap.sealed_depth(), 1);
    // Sealed layer has a tombstone for 42; tail has a value.
    // Cascade walk hits the tombstone first -> Forbid -> None.
    assert_eq!(snap.lookup(&42), None);
}

#[test]
fn multiple_rotations_stack_in_newest_first_order() {
    let c = build_cascade([(42, Entry::Value(100))]);

    // Three rotations, each writing a different value for the same
    // key.  After all three, the most recent value should win.
    c.write((42, Op::Set(200)));
    c.rotate(TestHead::empty);
    c.write((42, Op::Set(300)));
    c.rotate(TestHead::empty);
    c.write((42, Op::Set(400)));
    c.rotate(TestHead::empty);

    let snap = c.snapshot();
    assert_eq!(snap.sealed_depth(), 3);
    // sealed[0] contains 400, sealed[1] contains 300, sealed[2]
    // contains 200, tail contains 100.  Newest-first order means
    // we hit 400 first.
    assert_eq!(snap.lookup(&42), Some(&Entry::Value(400)));
}

#[test]
fn compact_with_no_sealed_is_noop() {
    let c = build_cascade([(42, Entry::Value(100))]);
    c.compact(0);
    assert_eq!(c.sealed_depth(), 0);
    assert_eq!(c.snapshot().lookup(&42), Some(&Entry::Value(100)));
}

#[test]
fn compact_folds_oldest_sealed_into_tail() {
    let c = build_cascade([(1, Entry::Value(10))]);
    c.write((2, Op::Set(20)));
    c.rotate(TestHead::empty);
    c.write((3, Op::Set(30)));
    c.rotate(TestHead::empty);

    // Two sealed layers, tail has 1.
    assert_eq!(c.sealed_depth(), 2);

    // keep = 1 -> fold the oldest sealed (containing {2: 20}) into
    // the tail.  After compact: sealed has 1 layer ({3: 30}), tail
    // has {1: 10, 2: 20}.
    c.compact(1);
    assert_eq!(c.sealed_depth(), 1);

    let snap = c.snapshot();
    assert_eq!(snap.lookup(&1), Some(&Entry::Value(10)));
    assert_eq!(snap.lookup(&2), Some(&Entry::Value(20)));
    assert_eq!(snap.lookup(&3), Some(&Entry::Value(30)));
}

#[test]
fn compact_to_zero_keeps_no_sealed() {
    let c = build_cascade([]);
    for v in 1..=5 {
        c.write((v, Op::Set(v * 10)));
        c.rotate(TestHead::empty);
    }
    assert_eq!(c.sealed_depth(), 5);

    c.compact(0);
    assert_eq!(c.sealed_depth(), 0);

    let snap = c.snapshot();
    for v in 1u32..=5 {
        assert_eq!(snap.lookup(&v), Some(&Entry::Value(v * 10)));
    }
}

#[test]
fn compact_applies_tombstones_to_tail() {
    let c = build_cascade([(42, Entry::Value(100))]);
    c.write((42, Op::Tombstone));
    c.rotate(TestHead::empty);

    assert_eq!(c.snapshot().lookup(&42), None);

    // Compact the tombstone into the tail.  After compaction the
    // sealed vec is empty and the tail no longer contains 42 at
    // all (the merge removed it).
    c.compact(0);
    assert_eq!(c.sealed_depth(), 0);
    assert_eq!(c.snapshot().lookup(&42), None);
}

#[test]
fn snapshot_held_across_compact_keeps_old_layers_alive() {
    let c = build_cascade([(1, Entry::Value(10))]);
    c.write((2, Op::Set(20)));
    c.rotate(TestHead::empty);

    // Snapshot before compaction.  The snapshot's sealed-vec Arc
    // contains the (still-live) sealed layer with {2: 20}; its
    // tail Arc references the pre-compact tail with {1: 10}.
    let pre_compact = c.snapshot();

    // Compact: merges the sealed layer into the tail.
    c.compact(0);
    assert_eq!(c.sealed_depth(), 0);

    // pre_compact still sees the old composition because its Arcs
    // point at the pre-compact generations.  Both keys are visible.
    assert_eq!(pre_compact.lookup(&1), Some(&Entry::Value(10)));
    assert_eq!(pre_compact.lookup(&2), Some(&Entry::Value(20)));

    // Fresh snapshot sees the post-compact state -- same logical
    // contents, different physical layout.
    let post_compact = c.snapshot();
    assert_eq!(post_compact.sealed_depth(), 0);
    assert_eq!(post_compact.lookup(&1), Some(&Entry::Value(10)));
    assert_eq!(post_compact.lookup(&2), Some(&Entry::Value(20)));
}

#[test]
fn snapshot_held_across_rotation_keeps_old_state() {
    let c = build_cascade([(42, Entry::Value(100))]);

    // Take a snapshot.  Then rotate after writing a new value.
    // The snapshot should still see the old state because it
    // holds Arcs to the pre-rotate generations.
    c.write((42, Op::Set(200)));
    c.rotate(TestHead::empty);
    let old_snap = c.snapshot();

    // Rotate again with a new value.
    c.write((42, Op::Set(300)));
    c.rotate(TestHead::empty);

    // old_snap still sees 200 because its sealed-vec Arc pre-dates
    // the second rotate.
    assert_eq!(old_snap.lookup(&42), Some(&Entry::Value(200)));
    assert_eq!(c.snapshot().lookup(&42), Some(&Entry::Value(300)));
}
