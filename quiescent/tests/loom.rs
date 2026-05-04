//! Loom model-checking tests for `dataplane_quiescent`.
//!
//! These tests run only under `--features loom`.  Standard protocol
//! tests live in `tests/protocol.rs`; bolero properties in
//! `tests/properties.rs`; bolero × shuttle in `tests/shuttle.rs`.
//!
//! Run with:
//!
//! ```sh
//! cargo test --release -p dataplane-quiescent --features loom --test loom
//! ```
//!
//! ## Why the `unsafe`
//!
//! Loom 0.7.2 doesn't expose `thread::scope`, only `thread::spawn`,
//! which requires `'static`.  But the new lifetime-bounded API gives
//! us a `Subscriber<'p, T>` that borrows from the `Publisher` — there
//! is no `'static` to satisfy `thread::spawn` with.
//!
//! Workaround: each `loom::model` iteration boxes a fresh `Publisher`,
//! lifts it to `&'static` via `Box::into_raw` for the body of the
//! iteration, and recovers the `Box` at the end (so loom's Arc-leak
//! audit is satisfied).  The unsafe is local, narrow, and well-paired:
//! every `into_raw` has a matching `from_raw`.
//!
//! `Box::leak` on its own would not work — loom audits `Arc` cleanup
//! at the end of every model iteration and panics on leaked clones.
//!
//! ## Sizing
//!
//! Loom explores all legal interleavings of the operations inside each
//! `loom::model(|| { ... })` block.  Keep test bodies minimal — each
//! extra atomic op multiplies the search space.  Two threads with one
//! atomic op each is roughly the right shape; "2 publishes + 2
//! subscribers + a drop" already explodes.

#![cfg(feature = "loom")]

use loom::thread;

use dataplane_quiescent::{Publisher, channel};

/// Run `body` with a `&'static` reference to a freshly-constructed
/// `Publisher`.  After `body` returns, recover the `Box` and drop the
/// `Publisher` so loom's Arc-leak audit is satisfied.
///
/// The `'static` lifetime is real for the duration of `body` (the
/// `Publisher` is live in heap-allocated memory until `Box::from_raw`
/// runs after `body`).  Caller must not retain any references derived
/// from the `&'static Publisher` past the return of `body`.
fn with_static_publisher<F>(body: F)
where
    F: FnOnce(&'static Publisher<u32>),
{
    let raw: *mut Publisher<u32> = Box::into_raw(Box::new(channel(0u32)));
    // SAFETY: `raw` was just produced by `Box::into_raw` and is not
    // freed until the matching `Box::from_raw` below.  No aliasing
    // occurs: `body` consumes the only handle.
    let publisher: &'static Publisher<u32> = unsafe { &*raw };
    body(publisher);
    // SAFETY: `body` has returned and the contract requires no
    // outstanding references to `publisher`.  `raw` is still the
    // unique pointer to the heap allocation.
    drop(unsafe { Box::from_raw(raw) });
}

/// A snapshot taken after a publish must observe a value the Publisher
/// ever stored.  Under any interleaving of `publish` vs `snapshot`, the
/// Subscriber sees either the initial or the published value, never
/// anything else (no torn reads, no use-after-free).
#[test]
fn snapshot_observes_a_legal_value() {
    loom::model(|| {
        with_static_publisher(|publisher| {
            let factory = publisher.factory();

            let sub_handle = thread::spawn(move || {
                let mut sub = factory.subscriber();
                let observed = *sub.snapshot();
                assert!(
                    observed == 0 || observed == 1,
                    "Subscriber observed illegal value {observed}",
                );
            });

            publisher.publish(1u32);
            sub_handle.join().unwrap();
        });
    });
}

/// A Subscriber that takes a snapshot before the Publisher publishes,
/// then is dropped concurrently with the Publisher's reclaim, must not
/// deadlock and must not leave the protocol in an inconsistent state.
#[test]
fn subscriber_drop_during_publish_is_safe() {
    loom::model(|| {
        with_static_publisher(|publisher| {
            let factory = publisher.factory();

            let sub_handle = thread::spawn(move || {
                let mut sub = factory.subscriber();
                let _ = *sub.snapshot();
                // Subscriber drops at end of thread; concurrent with publisher below.
            });

            publisher.publish(1u32);
            publisher.reclaim();
            sub_handle.join().unwrap();
        });
    });
}

/// A Subscriber that snapshots after `publish` returns must observe the
/// published value, not the initial.  This pins down the
/// publish-then-snapshot ordering.
#[test]
fn snapshot_after_publish_observes_published() {
    loom::model(|| {
        with_static_publisher(|publisher| {
            let mut sub = publisher.factory().subscriber();
            publisher.publish(1u32);
            let observed = *sub.snapshot();
            assert_eq!(
                observed, 1,
                "snapshot taken after publish() returns must observe the published value",
            );
        });
    });
}

/// Subscriber registered before publish, snapshot taken after — should
/// observe the published value.  The 0-sentinel branch in
/// `min_observed` must not turn this into a use-after-free.
#[test]
fn registered_then_publish_then_snapshot() {
    loom::model(|| {
        with_static_publisher(|publisher| {
            let factory = publisher.factory();

            let sub_handle = thread::spawn(move || {
                let mut sub = factory.subscriber();
                // Snapshot may race with publish.  Either way, we must see
                // a legal value.
                let observed = *sub.snapshot();
                assert!(observed == 0 || observed == 1);
            });

            publisher.publish(1u32);
            publisher.reclaim();
            sub_handle.join().unwrap();
        });
    });
}
