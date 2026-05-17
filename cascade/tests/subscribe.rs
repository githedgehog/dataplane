// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Drain subscription integration tests.
//!
//! Exercises [`Cascade::subscribe`] under a tokio runtime.  Requires
//! the `subscribe` feature on the cascade crate (enabled via the
//! self-path dev-dep in `Cargo.toml`).

#![allow(clippy::expect_used)]

use std::collections::HashMap;
use std::sync::Mutex;

use dataplane_cascade::{Cascade, Layer, MergeInto, MutableHead, Outcome, Upsert};

// ---------------------------------------------------------------------------
// Reuse the smoke-test minimal data model: a Mutex<HashMap> head, a
// HashMap-backed sealed/tail, an Op enum that exercises both replace
// and tombstone.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Set(u32),
    #[allow(dead_code)] // exercised by the smoke test; not by the subscribe tests
    Tombstone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Entry {
    Value(u32),
    Tombstone,
}

impl Upsert for Entry {
    type Op = Op;
    fn upsert(&mut self, op: Self::Op) {
        *self = Self::seed(op);
    }
    fn seed(op: Self::Op) -> Self {
        match op {
            Op::Set(v) => Entry::Value(v),
            Op::Tombstone => Entry::Tombstone,
        }
    }
}

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
        Outcome::Continue
    }
}

impl MutableHead for TestHead {
    type Op = (u32, Op);
    type Frozen = FrozenMap;

    fn write(&self, op: (u32, Op)) {
        let mut guard = self.inner.lock().expect("test head mutex poisoned");
        let (k, op) = op;
        guard
            .entry(k)
            .and_modify(|e| e.upsert(op))
            .or_insert_with(|| Entry::seed(op));
    }

    fn freeze(&self) -> FrozenMap {
        let guard = self.inner.lock().expect("test head mutex poisoned");
        FrozenMap {
            inner: guard.clone(),
        }
    }

    fn approx_size(&self) -> usize {
        self.inner.lock().expect("test head mutex poisoned").len()
    }
}

#[derive(Clone, Debug)]
struct FrozenMap {
    inner: HashMap<u32, Entry>,
}

impl FrozenMap {
    fn from_pairs<I: IntoIterator<Item = (u32, Entry)>>(it: I) -> Self {
        Self {
            inner: it.into_iter().collect(),
        }
    }
}

impl Layer for FrozenMap {
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

impl MergeInto<FrozenMap> for FrozenMap {
    fn merge_into(&self, target: &FrozenMap) -> FrozenMap {
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
        FrozenMap { inner: out }
    }
}

// ---------------------------------------------------------------------------
// Tests.  Each uses #[tokio::test] for the async runtime; the cascade
// itself isn't async but subscribe()'s receiver is.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn rotate_emits_drain_event_to_subscriber() {
    let c = Cascade::new(TestHead::empty(), FrozenMap::from_pairs([]));
    let mut sub = c.subscribe();

    c.write((42, Op::Set(100)));
    c.rotate(TestHead::empty);

    let event = sub.recv().await.expect("recv");
    assert_eq!(event.inner.get(&42), Some(&Entry::Value(100)));
}

#[tokio::test(flavor = "current_thread")]
async fn multiple_subscribers_each_get_their_own_copy() {
    let c = Cascade::new(TestHead::empty(), FrozenMap::from_pairs([]));
    let mut sub_a = c.subscribe();
    let mut sub_b = c.subscribe();
    assert_eq!(c.subscriber_count(), 2);

    c.write((7, Op::Set(70)));
    c.rotate(TestHead::empty);

    let a = sub_a.recv().await.expect("a recv");
    let b = sub_b.recv().await.expect("b recv");
    // Same Arc<S> -- shared, both subscribers see identical contents.
    assert_eq!(a.inner.get(&7), Some(&Entry::Value(70)));
    assert_eq!(b.inner.get(&7), Some(&Entry::Value(70)));
}

#[tokio::test(flavor = "current_thread")]
async fn no_subscribers_does_not_panic_on_rotate() {
    // Sender::send returns Err when no receivers exist; we
    // explicitly swallow it inside rotate, so this should be a
    // clean no-op.
    let c = Cascade::new(TestHead::empty(), FrozenMap::from_pairs([]));
    c.write((1, Op::Set(1)));
    c.rotate(TestHead::empty);
    // No assertion needed -- we just verify it doesn't panic.
}

#[tokio::test(flavor = "current_thread")]
async fn subscriber_created_after_rotate_misses_that_drain() {
    let c = Cascade::new(TestHead::empty(), FrozenMap::from_pairs([]));

    c.write((1, Op::Set(1)));
    c.rotate(TestHead::empty); // happens before subscribe

    let mut sub = c.subscribe();

    // Subscriber receives nothing immediately -- the broadcast
    // channel does not backfill historical events.  Use try_recv
    // to assert without blocking.
    let res = sub.try_recv();
    assert!(matches!(
        res,
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));

    // But a future rotate IS delivered.
    c.write((2, Op::Set(2)));
    c.rotate(TestHead::empty);

    let event = sub.recv().await.expect("recv future rotate");
    assert_eq!(event.inner.get(&2), Some(&Entry::Value(2)));
    assert_eq!(event.inner.get(&1), None); // first rotate's content not in this layer
}

#[tokio::test(flavor = "current_thread")]
async fn slow_subscriber_sees_lagged_when_channel_overflows() {
    // Capacity 2; emit 5 events with no recv calls in between.
    let c = Cascade::with_drain_capacity(TestHead::empty(), FrozenMap::from_pairs([]), 2);
    let mut sub = c.subscribe();

    for i in 1..=5 {
        c.write((i, Op::Set(i * 10)));
        c.rotate(TestHead::empty);
    }

    // The first recv returns Lagged because we've fallen behind.
    let first = sub.recv().await;
    match first {
        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
            // expected
        }
        other => panic!("expected Lagged, got {other:?}"),
    }

    // After Lagged, subsequent recvs deliver the most recent events
    // that fit in the buffer.  We should be able to recv 2 more
    // events successfully (one of which will be the rotation that
    // wrote (5, 50)).
    let _ = sub.recv().await.expect("recv after lag");
}

#[tokio::test(flavor = "current_thread")]
async fn rotate_emitted_arc_is_the_same_as_in_sealed_vec() {
    // Confirms the Arc the subscriber gets is reference-equal to
    // the Arc the snapshot sees in the sealed vector.  This is
    // load-bearing for the consumer's "drop the Arc to release the
    // hold" reclamation discipline -- the subscriber's Arc shares
    // refcount with the cascade's own retention.
    let c = Cascade::new(TestHead::empty(), FrozenMap::from_pairs([]));
    let mut sub = c.subscribe();

    c.write((1, Op::Set(1)));
    c.rotate(TestHead::empty);

    let from_sub = sub.recv().await.expect("recv");
    let snap = c.snapshot();
    let from_snap = snap.frozen().first().expect("sealed has one entry");

    // Pointer-equal Arcs -- the broadcast emitted the same
    // allocation that's stored in the sealed vec.
    assert!(std::sync::Arc::ptr_eq(&from_sub, from_snap));
}
