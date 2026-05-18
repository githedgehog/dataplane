// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Integration tests for [`ManagedCascade`] and
//! [`PolicyGenAllocator`] interacting end-to-end.
//!
//! Uses the same trivial Mutex<HashMap> head / HashMap-backed
//! frozen-and-tail model the cascade crate's own smoke tests use,
//! so the test harness is intentionally minimal -- the focus is on
//! the runtime's wiring (allocator -> rotate -> subscriber fan-out
//! -> watermark aggregation), not on the cascade primitive itself.

#![allow(clippy::expect_used)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex as StdMutex;

use cascade::{DrainEvent, Generation, Layer, MergeInto, MutableHead, Outcome, Upsert};
use concurrency::sync::Arc;
use mat::{MatSubscriber, WatermarkReporter};
use dataplane_mat_runtime::{ManagedCascade, PolicyGenAllocator};

// ---------------------------------------------------------------------------
// Minimal data model (mirrors cascade/tests/smoke.rs)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Set(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Entry {
    Value(u32),
}

impl Upsert for Entry {
    type Op = Op;
    fn upsert(&mut self, op: Self::Op) {
        *self = Self::seed(op);
    }
    fn seed(op: Self::Op) -> Self {
        let Op::Set(v) = op;
        Entry::Value(v)
    }
}

struct TestHead {
    inner: StdMutex<HashMap<u32, Entry>>,
}

impl TestHead {
    fn empty() -> Self {
        Self {
            inner: StdMutex::new(HashMap::new()),
        }
    }
}

impl Layer for TestHead {
    type Input = u32;
    type Output = Entry;
    fn lookup(&self, _input: &u32) -> Outcome<&Entry> {
        Outcome::Continue
    }
}

impl MutableHead for TestHead {
    type Op = (u32, Op);
    type Frozen = FrozenMap;

    fn write(&self, op: (u32, Op)) {
        let mut guard = self.inner.lock().expect("head poison");
        let (k, op) = op;
        guard
            .entry(k)
            .and_modify(|e| e.upsert(op))
            .or_insert_with(|| Entry::seed(op));
    }

    fn freeze(&self) -> FrozenMap {
        let guard = self.inner.lock().expect("head poison");
        FrozenMap {
            inner: guard.clone(),
        }
    }

    fn approx_size(&self) -> usize {
        self.inner.lock().expect("head poison").len()
    }
}

#[derive(Clone, Debug)]
struct FrozenMap {
    inner: HashMap<u32, Entry>,
}

impl FrozenMap {
    fn empty() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }
}

impl Layer for FrozenMap {
    type Input = u32;
    type Output = Entry;
    fn lookup(&self, k: &u32) -> Outcome<&Entry> {
        match self.inner.get(k) {
            Some(_) => Outcome::Match(self.inner.get(k).expect("just checked")),
            None => Outcome::Continue,
        }
    }
}

impl MergeInto<FrozenMap> for FrozenMap {
    fn merge_into(&self, target: &FrozenMap) -> FrozenMap {
        let mut out = target.inner.clone();
        for (k, v) in &self.inner {
            out.insert(*k, *v);
        }
        FrozenMap { inner: out }
    }
}

fn build_managed() -> ManagedCascade<TestHead, FrozenMap, FrozenMap> {
    ManagedCascade::new(TestHead::empty(), FrozenMap::empty(), Box::new(TestHead::empty))
}

// ---------------------------------------------------------------------------
// PolicyGenAllocator + rotate integration
// ---------------------------------------------------------------------------

#[test]
fn rollout_commits_at_publish_time() {
    let mc = build_managed();
    let alloc = PolicyGenAllocator::new();

    // Before any rollout, current is FIRST.  No frozen layers
    // exist; lookup_at falls through to the (empty) tail.
    let snap_before = mc.snapshot();
    assert_eq!(snap_before.lookup_at(&42, alloc.current()), None);

    // Stage a rollout: allocate a gen, write, rotate.  Do NOT publish.
    let g = alloc.begin_rollout().expect("alloc");
    mc.write((42, Op::Set(100)));
    mc.rotate(g);

    // Workers still see the OLD current -- the new frozen layer is
    // invisible because its gen > horizon.
    let snap_staged = mc.snapshot();
    assert_eq!(snap_staged.lookup_at(&42, alloc.current()), None);

    // Publish: workers now see the new gen and the new content.
    alloc.publish(g);
    let snap_after = mc.snapshot();
    assert_eq!(
        snap_after.lookup_at(&42, alloc.current()),
        Some(&Entry::Value(100))
    );
}

// ---------------------------------------------------------------------------
// Subscriber fan-out
// ---------------------------------------------------------------------------

/// Subscriber that records every DrainEvent it sees.
struct RecordingSubscriber {
    events: StdMutex<Vec<Generation>>,
}

impl RecordingSubscriber {
    fn new() -> Self {
        Self {
            events: StdMutex::new(Vec::new()),
        }
    }

    fn seen(&self) -> Vec<Generation> {
        self.events.lock().expect("poison").clone()
    }
}

impl MatSubscriber<TestHead, FrozenMap> for RecordingSubscriber {
    fn on_drain(&self, event: DrainEvent<FrozenMap>) {
        self.events
            .lock()
            .expect("poison")
            .push(event.generation);
    }
}

#[test]
fn subscriber_receives_every_rotation_in_order() {
    let mc = build_managed();
    let alloc = PolicyGenAllocator::new();
    let sub = Arc::new(RecordingSubscriber::new());
    mc.add_subscriber(sub.clone() as Arc<dyn MatSubscriber<TestHead, FrozenMap>>);

    let g1 = alloc.begin_rollout().expect("g1");
    mc.write((1, Op::Set(10)));
    mc.rotate(g1);

    let g2 = alloc.begin_rollout().expect("g2");
    mc.write((2, Op::Set(20)));
    mc.rotate(g2);

    assert_eq!(sub.seen(), vec![g1, g2]);
}

#[test]
fn subscriber_added_after_rotation_misses_earlier_drains() {
    let mc = build_managed();
    let alloc = PolicyGenAllocator::new();

    // First rotation, no subscriber yet.
    let g1 = alloc.begin_rollout().expect("g1");
    mc.write((1, Op::Set(10)));
    mc.rotate(g1);

    // Now register a subscriber.
    let sub = Arc::new(RecordingSubscriber::new());
    mc.add_subscriber(sub.clone() as Arc<dyn MatSubscriber<TestHead, FrozenMap>>);

    // Second rotation: subscriber sees this one only.
    let g2 = alloc.begin_rollout().expect("g2");
    mc.write((2, Op::Set(20)));
    mc.rotate(g2);

    assert_eq!(sub.seen(), vec![g2]);
}

#[test]
fn multiple_subscribers_each_receive_each_rotation() {
    let mc = build_managed();
    let alloc = PolicyGenAllocator::new();

    let sub_a = Arc::new(RecordingSubscriber::new());
    let sub_b = Arc::new(RecordingSubscriber::new());
    mc.add_subscriber(sub_a.clone() as Arc<dyn MatSubscriber<TestHead, FrozenMap>>);
    mc.add_subscriber(sub_b.clone() as Arc<dyn MatSubscriber<TestHead, FrozenMap>>);
    assert_eq!(mc.subscriber_count(), 2);

    let g = alloc.begin_rollout().expect("g");
    mc.write((1, Op::Set(10)));
    mc.rotate(g);

    assert_eq!(sub_a.seen(), vec![g]);
    assert_eq!(sub_b.seen(), vec![g]);
}

// ---------------------------------------------------------------------------
// Watermark aggregation -> compact_through
// ---------------------------------------------------------------------------

/// Watermark reporter backed by an `AtomicU64`; the test bumps it
/// to simulate hardware-offload progress.
struct AtomicWatermark {
    value: AtomicU64,
}

impl AtomicWatermark {
    fn new(initial: u64) -> Self {
        Self {
            value: AtomicU64::new(initial),
        }
    }

    fn set(&self, g: Generation) {
        self.value.store(g.get(), Ordering::Release);
    }
}

impl WatermarkReporter for AtomicWatermark {
    fn current_watermark(&self) -> Option<Generation> {
        Generation::new(self.value.load(Ordering::Acquire))
    }
}

#[test]
fn compact_to_aggregated_watermark_uses_minimum_across_reporters() {
    let mc = build_managed();
    let alloc = PolicyGenAllocator::new();

    // Produce three rotations.
    let g1 = alloc.begin_rollout().expect("g1");
    mc.write((1, Op::Set(10)));
    mc.rotate(g1);

    let g2 = alloc.begin_rollout().expect("g2");
    mc.write((2, Op::Set(20)));
    mc.rotate(g2);

    let g3 = alloc.begin_rollout().expect("g3");
    mc.write((3, Op::Set(30)));
    mc.rotate(g3);
    alloc.publish(g3);
    assert_eq!(mc.frozen_depth(), 3);

    // Two reporters, one at g2, one at g3.  The aggregated min is g2.
    let rep_a = Arc::new(AtomicWatermark::new(g2.get()));
    let rep_b = Arc::new(AtomicWatermark::new(g3.get()));
    mc.add_watermark_reporter(rep_a.clone() as Arc<dyn WatermarkReporter>);
    mc.add_watermark_reporter(rep_b.clone() as Arc<dyn WatermarkReporter>);

    let used = mc.compact_to_aggregated_watermark().expect("watermark exists");
    assert_eq!(used, g2);

    // After compact: layers g1 and g2 folded into tail, g3 remains.
    assert_eq!(mc.frozen_depth(), 1);

    // Sanity: full lookup still finds all three keys.
    let snap = mc.snapshot();
    assert_eq!(snap.lookup_at(&1, g3), Some(&Entry::Value(10)));
    assert_eq!(snap.lookup_at(&2, g3), Some(&Entry::Value(20)));
    assert_eq!(snap.lookup_at(&3, g3), Some(&Entry::Value(30)));
}

#[test]
fn compact_returns_none_when_any_reporter_has_no_watermark() {
    let mc = build_managed();
    let alloc = PolicyGenAllocator::new();
    let g = alloc.begin_rollout().expect("g");
    mc.write((1, Op::Set(10)));
    mc.rotate(g);

    // Reporter with no watermark yet (initial 0 maps to None).
    let rep = Arc::new(AtomicWatermark::new(0));
    mc.add_watermark_reporter(rep.clone() as Arc<dyn WatermarkReporter>);

    let result = mc.compact_to_aggregated_watermark();
    assert!(result.is_none(), "should decline to compact");
    assert_eq!(mc.frozen_depth(), 1);

    // After the reporter advances, compaction proceeds.
    rep.set(g);
    let result = mc.compact_to_aggregated_watermark();
    assert_eq!(result, Some(g));
    assert_eq!(mc.frozen_depth(), 0);
}

#[test]
fn compact_returns_none_with_no_reporters_registered() {
    let mc = build_managed();
    let alloc = PolicyGenAllocator::new();
    let g = alloc.begin_rollout().expect("g");
    mc.write((1, Op::Set(10)));
    mc.rotate(g);

    let result = mc.compact_to_aggregated_watermark();
    assert!(result.is_none());
    assert_eq!(mc.frozen_depth(), 1);
}

// ---------------------------------------------------------------------------
// Cross-cutting: combined subscriber + watermark reporter (typical for the
// hardware-offload programmer)
// ---------------------------------------------------------------------------

struct OffloadStub {
    seen: StdMutex<Vec<Generation>>,
    watermark: AtomicU64,
}

impl OffloadStub {
    fn new() -> Self {
        Self {
            seen: StdMutex::new(Vec::new()),
            watermark: AtomicU64::new(0),
        }
    }

    /// Simulate "drained past this generation on the NIC."  In
    /// production this would be driven by RX-queue watermarks.
    fn confirm_drained(&self, g: Generation) {
        self.watermark.store(g.get(), Ordering::Release);
    }

    fn seen(&self) -> Vec<Generation> {
        self.seen.lock().expect("poison").clone()
    }
}

impl MatSubscriber<TestHead, FrozenMap> for OffloadStub {
    fn on_drain(&self, event: DrainEvent<FrozenMap>) {
        self.seen.lock().expect("poison").push(event.generation);
    }
}

impl WatermarkReporter for OffloadStub {
    fn current_watermark(&self) -> Option<Generation> {
        Generation::new(self.watermark.load(Ordering::Acquire))
    }
}

#[test]
fn combined_subscriber_and_reporter_drives_full_lifecycle() {
    let mc = build_managed();
    let alloc = PolicyGenAllocator::new();

    let stub = Arc::new(OffloadStub::new());
    mc.add_subscriber(stub.clone() as Arc<dyn MatSubscriber<TestHead, FrozenMap>>);
    mc.add_watermark_reporter(stub.clone() as Arc<dyn WatermarkReporter>);

    // Three rotations.
    let g1 = alloc.begin_rollout().expect("g1");
    mc.write((1, Op::Set(10)));
    mc.rotate(g1);
    let g2 = alloc.begin_rollout().expect("g2");
    mc.write((2, Op::Set(20)));
    mc.rotate(g2);
    let g3 = alloc.begin_rollout().expect("g3");
    mc.write((3, Op::Set(30)));
    mc.rotate(g3);
    alloc.publish(g3);

    // Stub has seen all three drains.
    assert_eq!(stub.seen(), vec![g1, g2, g3]);

    // Stub has not yet confirmed any draining -> watermark None
    // -> no compaction.
    let result = mc.compact_to_aggregated_watermark();
    assert!(result.is_none());
    assert_eq!(mc.frozen_depth(), 3);

    // Stub confirms drained past g2 -> compaction folds g1+g2 in.
    stub.confirm_drained(g2);
    let result = mc.compact_to_aggregated_watermark();
    assert_eq!(result, Some(g2));
    assert_eq!(mc.frozen_depth(), 1);

    // Stub confirms drained past g3 -> the remaining layer folds in.
    stub.confirm_drained(g3);
    let result = mc.compact_to_aggregated_watermark();
    assert_eq!(result, Some(g3));
    assert_eq!(mc.frozen_depth(), 0);
}
