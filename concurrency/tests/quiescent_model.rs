// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Model-checking tests for `dataplane_concurrency::quiescent`.
//!
//! Each test is marked `#[concurrency::test]`, which routes the body to
//! whichever backend is active:
//!
//! * default -- runs the body once directly (smoke test)
//! * `loom` -- exhaustive interleaving exploration via `loom::model`
//! * `shuttle` / `shuttle_pct` / `shuttle_dfs` -- randomized / PCT /
//!   DFS schedule exploration
//!
//! Run under loom (the headline use case) with:
//!
//! ```sh
//! cargo test --release -p dataplane-concurrency --features loom --test quiescent_model
//! ```
//!
//! Standard protocol tests (real OS threads + `thread::scope` + sleeps)
//! live in `tests/quiescent_protocol.rs`; bolero property tests in
//! `tests/quiescent_properties.rs`; bolero x shuttle in
//! `tests/quiescent_shuttle.rs`.
//!
//! ## Sizing
//!
//! Loom explores all legal interleavings of the operations inside each
//! invocation.  Keep test bodies minimal -- each extra atomic op
//! multiplies the search space.  Two threads with one atomic op each is
//! roughly the right shape; "2 publishes + 2 subscribers + a drop"
//! already explodes.

// The proc macro `#[concurrency::test]` expands to `::concurrency::stress(...)`.
// Inside the crate's own integration tests we don't have a `concurrency` Cargo
// alias (cargo rejects self-deps), so alias the crate manually.
extern crate dataplane_concurrency as concurrency;

use concurrency::quiescent::channel;
use concurrency::thread;

/// A snapshot taken after a publish must observe a value the Publisher
/// ever stored.  Under any interleaving of `publish` vs `snapshot`, the
/// Subscriber sees either the initial or the published value, never
/// anything else (no torn reads, no use-after-free).
#[concurrency::test]
fn snapshot_observes_a_legal_value() {
    let publisher = channel(0u32);
    thread::scope(|s| {
        let factory = publisher.factory();
        s.spawn(move || {
            let mut sub = factory.subscriber();
            let observed = *sub.snapshot();
            assert!(
                observed == 0 || observed == 1,
                "Subscriber observed illegal value {observed}",
            );
        });
        publisher.publish(1u32);
    });
}

/// A Subscriber that takes a snapshot before the Publisher publishes,
/// then is dropped concurrently with the Publisher's reclaim, must not
/// deadlock and must not leave the protocol in an inconsistent state.
#[concurrency::test]
fn subscriber_drop_during_publish_is_safe() {
    let publisher = channel(0u32);
    thread::scope(|s| {
        let factory = publisher.factory();
        s.spawn(move || {
            let mut sub = factory.subscriber();
            let _ = *sub.snapshot();
            // Subscriber drops at end of thread; concurrent with publisher below.
        });
        publisher.publish(1u32);
        publisher.reclaim();
    });
}

/// A Subscriber that snapshots after `publish` returns must observe the
/// published value, not the initial.  This pins down the
/// publish-then-snapshot ordering.
///
/// Skipped under `shuttle_pct`: this test is single-threaded by design
/// and PCT specifically panics on closures that don't exercise
/// concurrency.  The other backends accept it.
#[cfg(not(feature = "shuttle_pct"))]
#[concurrency::test]
fn snapshot_after_publish_observes_published() {
    let publisher = channel(0u32);
    let mut sub = publisher.factory().subscriber();
    publisher.publish(1u32);
    let observed = *sub.snapshot();
    assert_eq!(
        observed, 1,
        "snapshot taken after publish() returns must observe the published value",
    );
}

/// Subscriber registered before publish, snapshot taken after -- should
/// observe the published value.  The 0-sentinel branch in
/// `min_observed` must not turn this into a use-after-free.
#[concurrency::test]
fn registered_then_publish_then_snapshot() {
    let publisher = channel(0u32);
    thread::scope(|s| {
        let factory = publisher.factory();
        s.spawn(move || {
            let mut sub = factory.subscriber();
            // Snapshot may race with publish.  Either way, we must see
            // a legal value.
            let observed = *sub.snapshot();
            assert!(observed == 0 || observed == 1);
        });
        publisher.publish(1u32);
        publisher.reclaim();
    });
}

// =====================================================================
// Drop affinity: every `Versioned` destructor must run on the
// Publisher's thread.  This is the headline guarantee of the crate;
// the existing tests above check legality and absence of deadlocks but
// do not verify the drop-thread invariant under all interleavings.
// =====================================================================

/// Payload whose `Drop` records the thread on which it ran.  We use
/// `std::sync::Mutex` for the recording slot because the model checker
/// doesn't need to model contention on it (only one drop per
/// `Versioned`, and we only care about the thread id, not the order of
/// records).
struct DropMarker {
    drops: std::sync::Arc<std::sync::Mutex<Vec<thread::ThreadId>>>,
}

impl Drop for DropMarker {
    fn drop(&mut self) {
        self.drops
            .lock()
            .expect("recording mutex poisoned")
            .push(thread::current().id());
    }
}

/// Verifies the drop-affinity invariant under all interleavings the
/// active backend explores.
///
/// Setup: Publisher publishes a fresh marker (the initial goes into
/// `retired`) while a Subscriber thread snapshots and then drops.  Any
/// interleaving of those two threads must result in **all**
/// `Versioned` destructors running on the Publisher's thread.  In
/// particular: the race where Subscriber's `cached = None` decrement
/// of `Versioned`'s strong count and Publisher's `retired.clear()`
/// decrement of the same atomic could (on weak memory) reorder, is
/// enforced by the Acquire fence in `min_observed` after the
/// `Arc::strong_count == 1` check.
#[concurrency::test]
fn destructor_of_initial_runs_on_publisher_thread() {
    let drops: std::sync::Arc<std::sync::Mutex<Vec<thread::ThreadId>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

    let initial = DropMarker {
        drops: std::sync::Arc::clone(&drops),
    };
    let publisher = channel(initial);

    let publisher_thread = thread::current().id();

    thread::scope(|s| {
        // Subscriber thread: snapshot then drop.  Race against the
        // publisher's publish/reclaim below.
        let factory = publisher.factory();
        s.spawn(move || {
            let mut sub = factory.subscriber();
            let _ = sub.snapshot();
            // sub drops at end of thread; concurrent with publisher.
        });

        // Publisher publishes a new marker (initial goes into retired).
        publisher.publish(DropMarker {
            drops: std::sync::Arc::clone(&drops),
        });
    });

    // Force a final reclaim pass so retired drains deterministically.
    publisher.reclaim();
    drop(publisher);

    // Every recorded drop must have happened on the publisher
    // (main) thread.
    let recorded = drops.lock().expect("recording mutex poisoned");
    for (i, t) in recorded.iter().enumerate() {
        assert_eq!(
            *t, publisher_thread,
            "DropMarker {i} ran its destructor on {t:?}, \
             not the publisher thread {publisher_thread:?}",
        );
    }
}
