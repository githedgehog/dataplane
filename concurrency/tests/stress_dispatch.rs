// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Tests for `concurrency::stress` backend dispatch.
//!
//! `stress(body)` is the small router that `#[concurrency::test]`
//! expands to: it picks one of `loom::model`,
//! `shuttle::check_random` / `_pct` / `_dfs`, or direct `body()` based
//! on the active backend's feature. The dispatch table lives in
//! `concurrency/src/stress.rs`.
//!
//! This file pins two coarse but important properties:
//!
//! 1. On the default backend, `stress` invokes `body` exactly once.
//!    There is no scheduling exploration; the call should round-trip
//!    untouched.
//!
//! 2. On `loom` or `shuttle` (random scheduler), `stress` invokes
//!    `body` more than once -- the backend explores multiple
//!    schedules / interleavings. Exact counts depend on the backend's
//!    internal iteration budget and can change; the test only asserts
//!    the contract that exploration actually happens.
//!
//! PCT and DFS are skipped: PCT panics on test bodies that do no
//! concurrent work *on the main thread*, and DFS returns after a
//! single iteration in the schedule we hand it. Both are valid
//! shuttle schedulers but stricter than `check_random`; the dispatch
//! contract is the same for all three, so verifying it under
//! `shuttle` + `loom` is enough.

// With the `shuttle_dfs -> shuttle_pct -> shuttle` chain in
// `Cargo.toml`, `not(feature = "shuttle_pct")` is true exactly when
// neither PCT nor DFS is selected.
#![cfg(not(feature = "shuttle_pct"))]

extern crate dataplane_concurrency as concurrency;

use std::sync::atomic::{AtomicUsize, Ordering};

use concurrency::thread;

// The invocation counter is a plain `static AtomicUsize`, not a
// `concurrency::sync::*` primitive. Two reasons:
//
//   * Under loom / shuttle, `concurrency::sync::*` panics when accessed
//     from outside the model checker's execution context (which is
//     where the test body itself reads the counter, *after* stress
//     returns).
//   * A `static` is the simplest thing that works from inside and
//     outside the body. The test counts invocations *across* the
//     whole `stress()` call, not per-iteration, so contention is fine.
//
// Each test resets the counter to 0 before invoking `stress` so the
// tests don't have hidden coupling.

fn run_dispatch_check() -> usize {
    static INVOCATIONS: AtomicUsize = AtomicUsize::new(0);
    INVOCATIONS.store(0, Ordering::SeqCst);
    concurrency::stress(|| {
        INVOCATIONS.fetch_add(1, Ordering::SeqCst);
        // PCT panics on bodies that do no concurrent work, so spawn
        // one thread that performs one atomic op via the active
        // backend's primitives.
        let scratch = concurrency::sync::Arc::new(concurrency::sync::atomic::AtomicUsize::new(0));
        let scratch_for_thread = concurrency::sync::Arc::clone(&scratch);
        thread::scope(|s| {
            s.spawn(move || {
                scratch_for_thread.fetch_add(1, concurrency::sync::atomic::Ordering::SeqCst);
            });
        });
    });
    INVOCATIONS.load(Ordering::SeqCst)
}

#[test]
#[cfg(not(any(feature = "loom", feature = "shuttle")))]
fn default_backend_invokes_body_exactly_once() {
    let invocations = run_dispatch_check();
    assert_eq!(
        invocations, 1,
        "default-backend stress should invoke body exactly once",
    );
}

#[test]
#[cfg(any(feature = "loom", feature = "shuttle"))]
fn model_check_backend_invokes_body_more_than_once() {
    let invocations = run_dispatch_check();
    assert!(
        invocations > 1,
        "model-check backend stress should invoke body more than once \
         (exploring schedules); observed {invocations}",
    );
}

// `#[concurrency::test]` emits `#[::core::prelude::v1::test]` BEFORE
// the captured `#(#attrs)*`. These two tests pin that user-supplied
// `#[should_panic]` / `#[ignore]` attributes still attach to the
// synthesised function -- a future macro refactor that reorders the
// emitted attributes (or swallows them) breaks here loudly instead
// of silently turning real test signals into no-ops.

#[cfg(not(feature = "shuttle_pct"))]
#[concurrency::test]
#[should_panic(expected = "intentional")]
fn should_panic_attribute_attaches() {
    panic!("intentional");
}

#[cfg(not(any(feature = "loom", feature = "shuttle_pct")))]
#[concurrency::test]
#[ignore = "verifies #[ignore] threads through; not run by default"]
fn ignore_attribute_attaches() {
    panic!("test body must not run when #[ignore] is honoured");
}
