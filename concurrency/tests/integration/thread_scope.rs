// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(clippy::disallowed_types)]

//! Direct coverage for `concurrency::thread::scope`, especially the
//! loom shim.

extern crate dataplane_concurrency as concurrency;

use concurrency::sync::Arc;
use concurrency::sync::atomic::{AtomicUsize, Ordering};
use concurrency::thread;

// PCT rejects spawn-and-wait bodies where the main thread does no
// concurrent work, so some scope contract tests are std/loom-only.

/// `scope()` returns the body's value.
#[cfg(not(feature = "shuttle"))]
#[concurrency::test]
fn scope_returns_body_value() {
    let v = thread::scope(|_| 42u32);
    assert_eq!(v, 42);
}

/// A single spawned thread is joined before `scope()` returns; the
/// `AtomicUsize` it wrote is visible to the caller (Acquire on join).
#[cfg(not(feature = "shuttle"))]
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
#[cfg(not(feature = "shuttle"))]
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
#[cfg(not(feature = "shuttle"))]
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

/// The loom shim must join nested scoped spawns before `scope` returns.
#[concurrency::test]
fn nested_scoped_spawn_is_joined() {
    let outer_done = Arc::new(AtomicUsize::new(0));
    let inner_done = Arc::new(AtomicUsize::new(0));
    thread::scope(|s| {
        let outer_for_thread = Arc::clone(&outer_done);
        let inner_for_thread = Arc::clone(&inner_done);
        s.spawn(move || {
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
#[cfg(not(feature = "shuttle"))]
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
