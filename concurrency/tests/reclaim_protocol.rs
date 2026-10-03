// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Protocol tests for `concurrency::reclaim`.
//!
//! These use real OS threads and a wall-clock deadline, so they only make sense under the default
//! backend -- the same reason `quiescent_protocol.rs` opts out of the model checkers.

#![cfg(not(any(feature = "loom", feature = "shuttle")))]

use dataplane_concurrency::reclaim::Reclaimer;
use dataplane_concurrency::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use dataplane_concurrency::sync::{Arc, Mutex};
use dataplane_concurrency::thread;
use std::time::{Duration, Instant};

/// Releases a gate flag however the scope body ends.
///
/// `thread::scope` joins its threads on unwind as well as on success, so a worker parked on a flag
/// that a panicking test body never sets deadlocks the run instead of failing it. Every gate below
/// is therefore held through this guard rather than stored and set by hand.
struct Gate {
    flag: Arc<AtomicBool>,
}

impl Drop for Gate {
    fn drop(&mut self) {
        self.flag.store(true, Ordering::Release);
    }
}

impl Gate {
    fn new(flag: &Arc<AtomicBool>) -> Gate {
        Gate {
            flag: Arc::clone(flag),
        }
    }
}

/// A tracked resource that records how often, and on which thread, it was released.
struct Marker {
    drops: Arc<AtomicUsize>,
    drop_threads: Arc<Mutex<Vec<thread::ThreadId>>>,
}

impl Drop for Marker {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
        self.drop_threads.lock().push(thread::current().id());
    }
}

/// Resources are tracked as `Arc<Marker>` -- `Clone`, as the reclaimer requires, with the
/// `Marker`'s destructor running when the last clone goes.
fn marker(drops: &Arc<AtomicUsize>, threads: &Arc<Mutex<Vec<thread::ThreadId>>>) -> Arc<Marker> {
    Arc::new(Marker {
        drops: Arc::clone(drops),
        drop_threads: Arc::clone(threads),
    })
}

fn counters() -> (Arc<AtomicUsize>, Arc<Mutex<Vec<thread::ThreadId>>>) {
    (
        Arc::new(AtomicUsize::new(0)),
        Arc::new(Mutex::new(Vec::new())),
    )
}

/// With nobody attending, retirement releases immediately: there is no worker that could still be
/// holding anything, so `min_observed` reports no constraint.
#[test]
fn retirement_with_no_attendants_releases_at_once() {
    let (drops, threads) = counters();
    let reclaimer: Reclaimer<Arc<Marker>> = Reclaimer::new();

    reclaimer.register(marker(&drops, &threads));
    assert_eq!(reclaimer.live(), 1);
    assert_eq!(drops.load(Ordering::Relaxed), 0);

    assert_eq!(reclaimer.retire_unless(|_| false), 1);
    reclaimer.reclaim();

    assert_eq!(reclaimer.live(), 0);
    assert_eq!(drops.load(Ordering::Relaxed), 1, "should be released");
    assert_eq!(reclaimer.pending(), 0);
}

/// The central property: a worker that has not passed a safe point since the retirement pins the
/// resource, and it is released only once that worker does.
#[test]
fn a_resource_is_pinned_until_every_attendant_passes_a_safe_point() {
    let (drops, threads) = counters();
    let reclaimer: Reclaimer<Arc<Marker>> = Reclaimer::new();
    reclaimer.register(marker(&drops, &threads));

    let attendants = reclaimer.attendants();
    let advance = Arc::new(AtomicBool::new(false));
    let advanced = Arc::new(AtomicBool::new(false));

    thread::scope(|scope| {
        let advance_worker = Arc::clone(&advance);
        let advanced_worker = Arc::clone(&advanced);
        scope.spawn(move || {
            let mut attendant = attendants.attend();
            // Enter the protocol before the retirement, and hold there.
            attendant.at_safe_point();
            advanced_worker.store(true, Ordering::Release);
            while !advance_worker.load(Ordering::Acquire) {
                thread::yield_now();
            }
            // Passing again is what permits release.
            attendant.at_safe_point();
            advanced_worker.store(false, Ordering::Release);
            while !advance_worker.load(Ordering::Acquire) {
                thread::yield_now();
            }
        });

        // Released on any exit from this block, panic included.
        let _gate = Gate::new(&advance);

        while !advanced.load(Ordering::Acquire) {
            thread::yield_now();
        }

        reclaimer.retire_unless(|_| false);
        // The worker observed the *previous* version, so the retired set is pinned.
        for _ in 0..100 {
            reclaimer.reclaim();
            assert_eq!(
                drops.load(Ordering::Relaxed),
                0,
                "released while a worker had not passed a safe point since retirement"
            );
            thread::yield_now();
        }
        assert_eq!(reclaimer.pending(), 1);

        // Let the worker through, then wait for it to have advanced.
        advance.store(true, Ordering::Release);
        while advanced.load(Ordering::Acquire) {
            thread::yield_now();
        }

        let deadline = Instant::now() + Duration::from_secs(10);
        while drops.load(Ordering::Relaxed) == 0 {
            reclaimer.reclaim();
            assert!(
                Instant::now() < deadline,
                "never released after a safe point"
            );
            thread::yield_now();
        }
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    });
}

/// A worker that exits stops blocking reclamation without any handshake: dropping its attendant
/// removes it from the domain. This is what makes `drain_until` terminate on a normal shutdown.
#[test]
fn an_exited_worker_stops_pinning() {
    let (drops, threads) = counters();
    let reclaimer: Reclaimer<Arc<Marker>> = Reclaimer::new();
    reclaimer.register(marker(&drops, &threads));

    let attendants = reclaimer.attendants();
    thread::scope(|scope| {
        scope
            .spawn(move || {
                let mut attendant = attendants.attend();
                attendant.at_safe_point();
                // and exit, dropping the attendant
            })
            .join()
            .expect("worker panicked");

        reclaimer
            .drain_until(Instant::now() + Duration::from_secs(10))
            .expect("drain should complete once the worker is gone");
    });
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}

/// The reason this is built on `quiescent` rather than a refcount: the destructor must run on the
/// owner's thread, never on a worker's. A worker holding the last reference would otherwise free a
/// DPDK resource from the wrong lcore.
#[test]
fn release_always_runs_on_the_owning_thread() {
    let (drops, threads) = counters();
    let owner = thread::current().id();
    let reclaimer: Reclaimer<Arc<Marker>> = Reclaimer::new();
    for _ in 0..8 {
        reclaimer.register(marker(&drops, &threads));
    }

    let attendants = reclaimer.attendants();
    thread::scope(|scope| {
        for _ in 0..4 {
            // `Attendants` is `Copy`, so each `move` closure takes its own copy.
            scope.spawn(move || {
                let mut attendant = attendants.attend();
                for _ in 0..50 {
                    attendant.at_safe_point();
                    thread::yield_now();
                }
            });
        }
        // Retire while the workers are churning, so a naive implementation has every chance to
        // drop the last reference on one of them.
        for _ in 0..50 {
            reclaimer.retire_unless(|_| false);
            reclaimer.reclaim();
            thread::yield_now();
        }
    });

    reclaimer
        .drain_until(Instant::now() + Duration::from_secs(10))
        .expect("drain should complete");

    assert_eq!(
        drops.load(Ordering::Relaxed),
        8,
        "each released exactly once"
    );
    let observed = threads.lock();
    assert_eq!(observed.len(), 8);
    for tid in observed.iter() {
        assert_eq!(
            *tid, owner,
            "a destructor ran on a worker thread instead of the owner's"
        );
    }
}

/// A worker that never passes another safe point and never exits cannot be waited out, so the
/// drain reports it rather than releasing memory the worker might still be reading.
#[test]
fn drain_reports_a_wedged_worker_instead_of_releasing() {
    let (drops, threads) = counters();
    let reclaimer: Reclaimer<Arc<Marker>> = Reclaimer::new();
    reclaimer.register(marker(&drops, &threads));

    let attendants = reclaimer.attendants();
    let release_worker = Arc::new(AtomicBool::new(false));
    let attending = Arc::new(AtomicBool::new(false));

    thread::scope(|scope| {
        let release = Arc::clone(&release_worker);
        let attending_worker = Arc::clone(&attending);
        scope.spawn(move || {
            let mut attendant = attendants.attend();
            attendant.at_safe_point();
            attending_worker.store(true, Ordering::Release);
            // Wedged: never passes another safe point, never exits, until the test says so.
            while !release.load(Ordering::Acquire) {
                thread::yield_now();
            }
        });

        // Released on any exit from this block, so an assertion failure below fails the test
        // instead of deadlocking the scope's join on a still-parked worker.
        let _gate = Gate::new(&release_worker);

        while !attending.load(Ordering::Acquire) {
            thread::yield_now();
        }

        let err = reclaimer
            .drain_until(Instant::now() + Duration::from_millis(200))
            .expect_err("a wedged worker must not be waited out");
        assert_eq!(err.pending, 1);
        assert_eq!(
            drops.load(Ordering::Relaxed),
            0,
            "must leak rather than release under a live worker"
        );
    });
}
