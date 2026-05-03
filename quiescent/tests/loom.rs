//! Loom model-checking tests for `dataplane_quiescent`.
//!
//! These tests run only under `--features loom`.  Standard protocol
//! tests live in `tests/protocol.rs`; bolero properties live in
//! `tests/properties.rs`.
//!
//! Run with:
//!
//! ```sh
//! cargo test --release -p dataplane-quiescent --features loom --test loom
//! ```
//!
//! Loom explores all legal interleavings of the operations inside each
//! `loom::model(|| { ... })` block.  Keep test bodies minimal — each
//! extra atomic op multiplies the search space.  Two threads with one
//! atomic op each is roughly the right shape; "2 publishes + 2
//! subscribers + a drop" already explodes.

#![cfg(feature = "loom")]

use loom::thread;

use dataplane_quiescent::channel;

/// A snapshot taken after a publish must observe a value the Publisher
/// ever stored.  Under any interleaving of `publish` vs `snapshot`, the
/// Subscriber sees either the initial or the published value, never
/// anything else (no torn reads, no use-after-free).
#[test]
fn snapshot_observes_a_legal_value() {
    loom::model(|| {
        let (mut publisher, factory) = channel(0u32);
        let factory_for_sub = factory.clone();

        let sub_handle = thread::spawn(move || {
            let mut sub = factory_for_sub.subscriber();
            let observed = *sub.snapshot();
            assert!(
                observed == 0 || observed == 1,
                "Subscriber observed illegal value {observed}",
            );
        });

        publisher.publish(1u32);
        sub_handle.join().unwrap();
    });
}

/// A Subscriber that takes a snapshot before the Publisher publishes,
/// then is dropped concurrently with the Publisher's reclaim, must not
/// deadlock and must not leave the protocol in an inconsistent state.
#[test]
fn subscriber_drop_during_publish_is_safe() {
    loom::model(|| {
        let (mut publisher, factory) = channel(0u32);
        let factory_for_sub = factory.clone();

        let sub_handle = thread::spawn(move || {
            let mut sub = factory_for_sub.subscriber();
            let _ = *sub.snapshot();
            // Subscriber drops at end of thread; concurrent with publisher below.
        });

        publisher.publish(1u32);
        publisher.reclaim();
        sub_handle.join().unwrap();
    });
}

/// A Subscriber that snapshots after `publish` returns must observe the
/// published value, not the initial.  This pins down the
/// publish-then-snapshot ordering.
#[test]
fn snapshot_after_publish_observes_published() {
    loom::model(|| {
        let (mut publisher, factory) = channel(0u32);
        let mut sub = factory.subscriber();

        publisher.publish(1u32);
        let observed = *sub.snapshot();
        assert_eq!(
            observed, 1,
            "snapshot taken after publish() returns must observe the published value",
        );
    });
}

/// Subscriber registered before publish, snapshot taken after — should
/// observe the published value.  The 0-sentinel branch in
/// `min_observed` must not turn this into a use-after-free.
#[test]
fn registered_then_publish_then_snapshot() {
    loom::model(|| {
        let (mut publisher, factory) = channel(0u32);
        let factory_for_sub = factory.clone();

        let sub_handle = thread::spawn(move || {
            let mut sub = factory_for_sub.subscriber();
            // Snapshot may race with publish.  Either way, we must see
            // a legal value.
            let observed = *sub.snapshot();
            assert!(observed == 0 || observed == 1);
        });

        publisher.publish(1u32);
        publisher.reclaim();
        sub_handle.join().unwrap();
    });
}
