// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Bolero property test for `thread::scope`.
//!
//! Generates a [`Plan`] (a small number of spawned threads, each with a
//! small number of `fetch_add` ops on a shared counter) via bolero,
//! then runs each plan under the active backend.  Each bolero iteration
//! is one *shape* (spawn count, per-spawn op count); under shuttle each
//! shape gets exercised against one randomly chosen schedule.  Many
//! bolero iterations widen both axes cheaply.
//!
//! This is the cheap-per-call counterpart to `tests/loom_scope.rs`'s
//! hand-picked scenarios.  Loom-style exhaustive exploration of the
//! shim under a large random plan would blow up; bolero x shuttle gets
//! breadth where loom would only give depth on a tiny case.
//!
//! The headline property is conservation: at `scope()` return, the
//! shared counter must equal the sum of all increments the spawned
//! threads were instructed to perform.  If `scope()` returned without
//! joining a thread (loom shim bug), or if any `Drop` running outside
//! the scope clobbered the count, this assertion fires.
//!
//! Loom is deliberately excluded -- the search space explodes with
//! large plans.  Use `tests/loom_scope.rs` for loom coverage.

#![cfg(not(feature = "loom"))]

use std::panic::RefUnwindSafe;

use bolero::TypeGenerator;
use dataplane_concurrency::sync::Arc;
use dataplane_concurrency::sync::atomic::{AtomicUsize, Ordering};
use dataplane_concurrency::thread;

/// One spawned thread's program: a list of increments to perform on
/// the shared counter.  Each `u8` is masked to a small range so the
/// test stays cheap under shuttle.
#[derive(Clone, Debug, TypeGenerator)]
struct ThreadPlan {
    increments: Vec<u8>,
}

/// A scope's program: up to a few spawned threads.  Bolero generates
/// arbitrarily long `Vec<ThreadPlan>` but we clamp to keep search cost
/// bounded inside `run_plan`.
#[derive(Clone, Debug, TypeGenerator)]
struct Plan {
    threads: Vec<ThreadPlan>,
}

const MAX_THREADS: usize = 4;
const MAX_INCREMENTS_PER_THREAD: usize = 4;

fn expected_sum(plan: &Plan) -> usize {
    plan.threads
        .iter()
        .take(MAX_THREADS)
        .map(|tp| {
            tp.increments
                .iter()
                .take(MAX_INCREMENTS_PER_THREAD)
                .map(|i| (*i & 0x0f) as usize)
                .sum::<usize>()
        })
        .sum()
}

fn run_plan(plan: &Plan) {
    let counter = Arc::new(AtomicUsize::new(0));
    let expected = expected_sum(plan);

    thread::scope(|s| {
        for tp in plan.threads.iter().take(MAX_THREADS) {
            let counter_for_thread = Arc::clone(&counter);
            let increments: Vec<u8> = tp
                .increments
                .iter()
                .take(MAX_INCREMENTS_PER_THREAD)
                .copied()
                .collect();
            s.spawn(move || {
                for inc in &increments {
                    counter_for_thread.fetch_add((*inc & 0x0f) as usize, Ordering::SeqCst);
                }
            });
        }
    });

    let observed = counter.load(Ordering::SeqCst);
    assert_eq!(
        observed, expected,
        "scope conservation violated: observed {observed} != expected {expected}",
    );
}

const TEST_TIME: std::time::Duration = std::time::Duration::from_secs(10);

fn fuzz_test<Arg: Clone + TypeGenerator + RefUnwindSafe + std::fmt::Debug>(
    test: impl Fn(Arg) + RefUnwindSafe,
) {
    bolero::check!()
        .with_type()
        .cloned()
        .with_test_time(TEST_TIME)
        .for_each(test);
}

#[test]
#[cfg(feature = "shuttle")]
fn scope_conservation_under_shuttle() {
    fuzz_test(|plan: Plan| shuttle::check_random(move || run_plan(&plan), 1));
}

#[test]
#[cfg(feature = "shuttle")]
fn scope_conservation_under_shuttle_pct() {
    fuzz_test(|plan: Plan| {
        // PCT requires every thread to do at least one atomic op;
        // skip degenerate shapes that wouldn't exercise concurrency.
        let nontrivial = plan
            .threads
            .iter()
            .take(MAX_THREADS)
            .filter(|tp| !tp.increments.is_empty())
            .count();
        if nontrivial < 2 {
            return;
        }
        shuttle::check_pct(move || run_plan(&plan), 16, 3);
    });
}

#[test]
#[cfg(not(feature = "shuttle"))]
fn scope_conservation_under_std() {
    fuzz_test(|plan: Plan| run_plan(&plan));
}
