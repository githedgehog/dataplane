// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! End-to-end smoke test exercising the cascade trait shape with a
//! trivial concrete implementation.
//!
//! Purpose: make sure the trait bounds line up and the lookup walk
//! produces the expected priority order (head shadows sealed shadows
//! tail, tombstones in the head suppress lower-layer hits).
//!
//! This test is *not* an Absorb-laws property suite -- those will
//! live in their own test file once the property harness lands.

#![allow(clippy::expect_used)]

use std::collections::HashMap;
use std::sync::Mutex;

use concurrency::sync::Arc;

use dataplane_cascade::{Absorb, Cascade, Layer, MutableHead, Outcome};

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
        // by always returning Miss.  A real impl would publish an
        // Arc<HashMap<...>> via concurrency::slot::Slot for the read
        // path so that `lookup` can hand out a borrow without
        // holding the mutex.
        Outcome::Miss
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

    fn seal(self) -> SealedMap {
        let map = self.inner.into_inner().expect("test head mutex poisoned");
        SealedMap { inner: map }
    }

    fn approx_size(&self) -> usize {
        self.inner.lock().expect("test head mutex poisoned").len()
    }
}

// ---------------------------------------------------------------------------
// A trivial sealed/tail layer: plain HashMap.
// ---------------------------------------------------------------------------

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
            None => Outcome::Miss,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn build_cascade(
    sealed: Vec<Arc<SealedMap>>,
    tail: Arc<SealedMap>,
) -> Cascade<TestHead, SealedMap, SealedMap> {
    let mut c = Cascade::new(TestHead::empty(), tail);
    c.sealed = sealed;
    c
}

#[test]
fn tail_hit_when_head_and_sealed_miss() {
    let tail = Arc::new(SealedMap::from_pairs([(42, Entry::Value(100))]));
    let c = build_cascade(vec![], tail);

    let got = c.lookup(&42);
    assert_eq!(got, Some(&Entry::Value(100)));
}

#[test]
fn sealed_shadows_tail() {
    let tail = Arc::new(SealedMap::from_pairs([(42, Entry::Value(100))]));
    let sealed = Arc::new(SealedMap::from_pairs([(42, Entry::Value(200))]));
    let c = build_cascade(vec![sealed], tail);

    let got = c.lookup(&42);
    assert_eq!(got, Some(&Entry::Value(200)));
}

#[test]
fn tombstone_in_sealed_suppresses_tail_hit() {
    let tail = Arc::new(SealedMap::from_pairs([(42, Entry::Value(100))]));
    let sealed = Arc::new(SealedMap::from_pairs([(42, Entry::Tombstone)]));
    let c = build_cascade(vec![sealed], tail);

    let got = c.lookup(&42);
    assert_eq!(got, None);
}

#[test]
fn miss_in_all_layers_returns_none() {
    let tail = Arc::new(SealedMap::from_pairs([(1, Entry::Value(10))]));
    let c = build_cascade(vec![], tail);

    assert_eq!(c.lookup(&999), None);
}

#[test]
fn head_write_then_seal_into_sealed_layer() {
    let head = TestHead::empty();
    head.write((7, Op::Set(70)));
    head.write((7, Op::Set(71))); // overwrites
    head.write((8, Op::Tombstone));

    let sealed = head.seal();
    assert_eq!(sealed.inner.get(&7), Some(&Entry::Value(71)));
    assert_eq!(sealed.inner.get(&8), Some(&Entry::Tombstone));
}
