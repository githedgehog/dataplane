// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Direct coverage for `concurrency::thread::scope` -- the loom shim
//! in particular, but the tests pass under every backend.
//!
//! Loom 0.7 does not ship `thread::scope`. The crate provides one in
//! `concurrency/src/thread/loom_scope.rs` built on `loom::spawn` plus
//! an `Arc<Mutex<Option<T>>>` keepalive pattern that preserves the
//! drop-affinity guarantee `std::thread::scope` offers.
//!
//! The shim is exercised indirectly by `tests/quiescent_model.rs`, but
//! those tests would surface failures as quiescent-protocol bugs rather
//! than as localised shim bugs. The tests in this file pin the
//! `thread::scope` contract itself so a future regression in the shim
//! fails here loudly and at the right layer.
//!
//! The same source runs under every backend via `#[concurrency::test]`,
//! and on the default and shuttle backends it exercises the *real*
//! `std::thread::scope` / `shuttle::thread::scope` -- which is the
//! point: the contract is the same; only the *internals* differ.
//!
//! Run under loom (the headline use case) with:
//!
//! ```sh
//! cargo test --release -p dataplane-concurrency --features loom --test thread_scope
//! ```

extern crate dataplane_concurrency as concurrency;

use concurrency::sync::Arc;
use concurrency::sync::atomic::{AtomicUsize, Ordering};
use concurrency::thread;

// Several tests below have the spawn-and-wait shape ("main spawns,
// joins via the implicit auto-join, reads only after scope returns"),
// which PCT counts as "the main thread did no concurrent work" and
// panics on. Same approach `quiescent_model.rs` takes for its
// single-threaded `snapshot_after_publish_observes_published` test.
// Tests with two or more spawns issuing atomic ops (e.g.
// `multiple_spawns_all_join_before_return`) are PCT-compatible.

/// `scope()` returns the body's value.
#[cfg(not(feature = "shuttle_pct"))]
#[concurrency::test]
fn scope_returns_body_value() {
    let v = thread::scope(|_| 42u32);
    assert_eq!(v, 42);
}

/// A single spawned thread is joined before `scope()` returns; the
/// `AtomicUsize` it wrote is visible to the caller (Acquire on join).
#[cfg(not(feature = "shuttle_pct"))]
#[concurrency::test]
fn single_spawn_joins_before_return() {
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_for_thread = Arc::clone(&counter);
    thread::scope(|s| {
        s.spawn(move || {
            counter_for_thread.fetch_add(1, Ordering::SeqCst);
        });
    });
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

/// Multiple spawned threads all join before `scope()` returns.
#[concurrency::test]
fn multiple_spawns_all_join_before_return() {
    let counter = Arc::new(AtomicUsize::new(0));
    thread::scope(|s| {
        let c1 = Arc::clone(&counter);
        s.spawn(move || {
            c1.fetch_add(1, Ordering::SeqCst);
        });
        let c2 = Arc::clone(&counter);
        s.spawn(move || {
            c2.fetch_add(1, Ordering::SeqCst);
        });
    });
    assert_eq!(counter.load(Ordering::SeqCst), 2);
}

/// `ScopedJoinHandle::join` returns the spawned thread's value.
#[cfg(not(feature = "shuttle_pct"))]
#[concurrency::test]
fn explicit_join_returns_value() {
    thread::scope(|s| {
        let h = s.spawn(|| 99u32);
        let v = h.join().expect("spawned thread did not panic");
        assert_eq!(v, 99);
    });
}

/// Spawned closures may borrow data of any lifetime that outlives the
/// scope -- the headline `std::thread::scope` guarantee. Under loom
/// this is the shim's `mem::transmute` doing its job.
#[cfg(not(feature = "shuttle_pct"))]
#[concurrency::test]
fn spawn_can_borrow_from_enclosing_scope() {
    let counter = Arc::new(AtomicUsize::new(0));
    // `local` is owned by the test body; it lives in the enclosing
    // stack frame. The spawn closure borrows it by reference, which
    // would not compile on plain `thread::spawn` (no `'static`).
    let local = 7u32;
    let local_ref = &local;
    thread::scope(|s| {
        let c = Arc::clone(&counter);
        s.spawn(move || {
            c.store(*local_ref as usize, Ordering::SeqCst);
        });
    });
    assert_eq!(counter.load(Ordering::SeqCst), 7);
}

/// Two spawns in the same scope, each writing a distinct value, both
/// readable after `scope()` returns. Loom explores all interleavings of
/// the two stores; under any of them, both values are eventually
/// observed because both joins happen before `scope` returns.
#[concurrency::test]
fn two_spawns_independent_writes() {
    let a = Arc::new(AtomicUsize::new(0));
    let b = Arc::new(AtomicUsize::new(0));
    thread::scope(|s| {
        let a_for = Arc::clone(&a);
        s.spawn(move || {
            a_for.store(1, Ordering::SeqCst);
        });
        let b_for = Arc::clone(&b);
        s.spawn(move || {
            b_for.store(2, Ordering::SeqCst);
        });
    });
    assert_eq!(a.load(Ordering::SeqCst), 1);
    assert_eq!(b.load(Ordering::SeqCst), 2);
}

/// A scoped thread that itself calls `s.spawn(...)` on the parent
/// scope pushes new entries onto the scope's `pending` queue after
/// the parent thread has already entered the teardown drain. The
/// shim must keep draining until the queue stays empty across a full
/// pass; otherwise the nested spawn's `JoinHandle` is leaked and the
/// `'scope` -> `'static` transmute is unsound (the closure outlives
/// `'scope`).
#[concurrency::test]
fn nested_scoped_spawn_is_joined() {
    let outer_done = Arc::new(AtomicUsize::new(0));
    let inner_done = Arc::new(AtomicUsize::new(0));
    thread::scope(|s| {
        let outer_for_thread = Arc::clone(&outer_done);
        let inner_for_thread = Arc::clone(&inner_done);
        s.spawn(move || {
            // Re-enter `s` from inside an already-spawned scoped
            // thread. The handle for this inner spawn is registered
            // in the same `Scope`'s `pending` list, but it can land
            // there after the parent thread has already taken a
            // snapshot of `pending` to drain. The shim's teardown
            // must keep looping until `pending` is empty across a
            // full pass.
            s.spawn(move || {
                inner_for_thread.fetch_add(1, Ordering::SeqCst);
            });
            outer_for_thread.fetch_add(1, Ordering::SeqCst);
        });
    });
    assert_eq!(
        outer_done.load(Ordering::SeqCst),
        1,
        "outer scoped thread did not run to completion before scope returned",
    );
    assert_eq!(
        inner_done.load(Ordering::SeqCst),
        1,
        "nested scoped thread did not run to completion before scope returned",
    );
}

/// `Drop::drop` of a value moved into a spawned closure runs (at the
/// latest) when the spawned thread is joined -- i.e. before `scope()`
/// returns. Pinned via an `AtomicUsize` incremented from within the
/// payload's `Drop` impl.
#[cfg(not(feature = "shuttle_pct"))]
#[concurrency::test]
fn moved_value_drop_runs_before_scope_returns() {
    struct Bump(Arc<AtomicUsize>);
    impl Drop for Bump {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let bumps = Arc::new(AtomicUsize::new(0));
    thread::scope(|s| {
        let payload = Bump(Arc::clone(&bumps));
        s.spawn(move || {
            // Body consumes `payload` implicitly at end of scope.
            let _keep = payload;
        });
    });
    assert_eq!(bumps.load(Ordering::SeqCst), 1);
}
