// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(clippy::expect_used)]

use dataplane_cascade::Cascade;

mod common;
use common::{Entry, FrozenMap, GenAlloc, Op, TestHead};

#[tokio::test(flavor = "current_thread")]
async fn rotate_emits_drain_event_to_subscriber() {
    let c = Cascade::new(TestHead::empty(), FrozenMap::from_pairs([]));
    let mut g_alloc = GenAlloc::new();
    let mut sub = c.subscribe();

    c.write((42, Op::Set(100)));
    let g = g_alloc.next();
    c.rotate(g, TestHead::empty);

    let event = sub.recv().await.expect("recv");
    assert_eq!(event.generation, g);
    assert_eq!(event.layer.inner.get(&42), Some(&Entry::Value(100)));
}

#[tokio::test(flavor = "current_thread")]
async fn multiple_subscribers_each_get_their_own_copy() {
    let c = Cascade::new(TestHead::empty(), FrozenMap::from_pairs([]));
    let mut g_alloc = GenAlloc::new();
    let mut sub_a = c.subscribe();
    let mut sub_b = c.subscribe();
    assert_eq!(c.subscriber_count(), 2);

    c.write((7, Op::Set(70)));
    c.rotate(g_alloc.next(), TestHead::empty);

    let a = sub_a.recv().await.expect("a recv");
    let b = sub_b.recv().await.expect("b recv");
    assert_eq!(a.layer.inner.get(&7), Some(&Entry::Value(70)));
    assert_eq!(b.layer.inner.get(&7), Some(&Entry::Value(70)));
}

#[tokio::test(flavor = "current_thread")]
async fn no_subscribers_does_not_panic_on_rotate() {
    let c = Cascade::new(TestHead::empty(), FrozenMap::from_pairs([]));
    let mut g_alloc = GenAlloc::new();
    c.write((1, Op::Set(1)));
    c.rotate(g_alloc.next(), TestHead::empty);
}

#[tokio::test(flavor = "current_thread")]
async fn subscriber_created_after_rotate_misses_that_drain() {
    let c = Cascade::new(TestHead::empty(), FrozenMap::from_pairs([]));
    let mut g_alloc = GenAlloc::new();

    c.write((1, Op::Set(1)));
    c.rotate(g_alloc.next(), TestHead::empty);

    let mut sub = c.subscribe();
    let res = sub.try_recv();
    assert!(matches!(
        res,
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    c.write((2, Op::Set(2)));
    c.rotate(g_alloc.next(), TestHead::empty);

    let event = sub.recv().await.expect("recv future rotate");
    assert_eq!(event.layer.inner.get(&2), Some(&Entry::Value(2)));
    assert_eq!(event.layer.inner.get(&1), None);
}

#[tokio::test(flavor = "current_thread")]
async fn slow_subscriber_sees_lagged_when_channel_overflows() {
    let c = Cascade::with_drain_capacity(TestHead::empty(), FrozenMap::from_pairs([]), 2);
    let mut g_alloc = GenAlloc::new();
    let mut sub = c.subscribe();

    for i in 1..=5 {
        c.write((i, Op::Set(i * 10)));
        c.rotate(g_alloc.next(), TestHead::empty);
    }
    let first = sub.recv().await;
    match first {
        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
        other => panic!("expected Lagged, got {other:?}"),
    }
    let _ = sub.recv().await.expect("recv after lag");
}

#[tokio::test(flavor = "current_thread")]
async fn rotate_emitted_arc_is_the_same_as_in_sealed_vec() {
    let c = Cascade::new(TestHead::empty(), FrozenMap::from_pairs([]));
    let mut g_alloc = GenAlloc::new();
    let mut sub = c.subscribe();

    c.write((1, Op::Set(1)));
    let g = g_alloc.next();
    c.rotate(g, TestHead::empty);

    let from_sub = sub.recv().await.expect("recv");
    let snap = c.snapshot();
    let from_snap = snap.frozen().first().expect("sealed has one entry");
    assert_eq!(from_sub.generation, g);
    assert_eq!(from_snap.generation, g);
    assert!(concurrency::sync::Arc::ptr_eq(
        &from_sub.layer,
        &from_snap.layer,
    ));
}
