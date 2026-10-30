// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(clippy::disallowed_types)]

//! Tests for `concurrency::stress` backend dispatch.
//!
//! This file pins one coarse but important property: on the default
//! backend, `stress` invokes `body` exactly once.  There is no
//! scheduling exploration; the call should round-trip untouched.

#![cfg(not(feature = "shuttle"))]

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

#[concurrency::test]
#[should_panic(expected = "intentional")]
fn should_panic_attribute_attaches() {
    panic!("intentional");
}

#[cfg(not(feature = "loom"))]
#[concurrency::test]
#[ignore = "verifies #[ignore] threads through; not run by default"]
fn ignore_attribute_attaches() {
    panic!("test body must not run when #[ignore] is honoured");
}
