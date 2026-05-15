// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Multi-threaded protocol tests for `dataplane_concurrency::quiescent`.
//!
//! The single-threaded protocol invariants (snapshot legality,
//! reclamation gating, conservation of `Versioned` allocations) are
//! covered by the bolero property tests in
//! `tests/quiescent_properties.rs`.  This file holds only the tests
//! that genuinely need real OS threads:
//!
//! - **Drop affinity**: drops must run on the Publisher's
//!   thread, even when the last Subscriber drops concurrently with
//!   reclaim.
//! - **Concurrent stress**: Subscriber/Publisher interaction across
//!   realistic scheduling.
//!
//! Subscribers are spawned inside `thread::scope` because
//! `SubscriberFactory<'p>` and `Subscriber<'p>` borrow from the
//! `Publisher` and so cannot outlive it.  `thread::spawn` (which
//! requires `'static`) won't work; `thread::scope` matches the
//! lifetime exactly.
//!
//! Loom-modeled tests live in `tests/quiescent_loom.rs`.

// Protocol tests use real OS threads via `thread::scope` + `thread::sleep`,
// which only make sense under the default backend.  Under any model-checker
// backend (loom or any shuttle variant) the surrounding facade is rewired
// and the std-shaped types these tests use would either fail to compile or
// fault outside the corresponding runtime.
#![cfg(not(any(
    feature = "loom",
    feature = "shuttle",
    feature = "shuttle_pct",
    feature = "shuttle_dfs"
)))]

use dataplane_concurrency::quiescent::channel;
use dataplane_concurrency::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use dataplane_concurrency::sync::{Arc, Mutex};
use dataplane_concurrency::thread;
use std::time::Duration;

// ---------- helpers ----------

/// Payload that counts its own drops and (optionally) records the
/// thread on which its destructor ran.  Multiple markers can share a
/// single recording slot -- each push extends the `Vec`, so the test
/// can audit every drop's thread, not just the most recent one.
struct Marker {
    drop_counter: Arc<AtomicUsize>,
    drop_threads: Option<Arc<Mutex<Vec<thread::ThreadId>>>>,
    payload: u32,
}

impl Drop for Marker {
    fn drop(&mut self) {
        self.drop_counter.fetch_add(1, Ordering::Relaxed);
        if let Some(slot) = &self.drop_threads {
            slot.lock().push(thread::current().id());
        }
    }
}

fn marker(payload: u32, drops: &Arc<AtomicUsize>) -> Marker {
    Marker {
        drop_counter: Arc::clone(drops),
        drop_threads: None,
        payload,
    }
}

fn marker_threaded(
    payload: u32,
    drops: &Arc<AtomicUsize>,
    slot: &Arc<Mutex<Vec<thread::ThreadId>>>,
) -> Marker {
    Marker {
        drop_counter: Arc::clone(drops),
        drop_threads: Some(Arc::clone(slot)),
        payload,
    }
}

// ---------- drop affinity ----------

#[test]
fn destructor_of_initial_runs_on_publisher_thread() {
    let drops = Arc::new(AtomicUsize::new(0));
    let initial_drop_threads = Arc::new(Mutex::new(Vec::new()));
    let publisher_thread_id = thread::current().id();

    let publisher = channel(marker_threaded(0, &drops, &initial_drop_threads));

    thread::scope(|s| {
        let factory = publisher.factory();
        // Subscriber thread observes initial, then exits.
        s.spawn(move || {
            let mut sub = factory.subscriber();
            let _ = sub.snapshot();
        });
    });

    // Publisher publishes a new value and reclaims; the initial's destructor
    // should fire here on this (publisher) thread, NOT on the subscriber thread.
    publisher.publish(marker(1, &drops));
    publisher.reclaim();

    let observed = initial_drop_threads.lock();
    assert_eq!(
        observed.as_slice(),
        &[publisher_thread_id],
        "initial value's destructor must run exactly once on the Publisher's thread (recorded {observed:?})",
    );
}

#[test]
fn destructor_runs_on_publisher_when_last_subscriber_drops_concurrently() {
    // Stronger version: the Subscriber is dropped while the Publisher
    // is busy publishing.  With the `Drop` impl on `Subscriber`
    // ensuring `cached` dies before `epoch`, the destructor must still
    // resolve on the Publisher's thread -- for **every** marker, not
    // just the initial one.  Each iteration publishes tracked markers
    // so every destructor records its drop thread.
    let drops = Arc::new(AtomicUsize::new(0));
    let drop_threads = Arc::new(Mutex::new(Vec::new()));
    let publisher_thread_id = thread::current().id();

    let publisher = channel(marker_threaded(0, &drops, &drop_threads));

    // Repeat to expose the race window across timings.
    for _ in 0..8 {
        thread::scope(|s| {
            let factory = publisher.factory();
            s.spawn(move || {
                let mut sub = factory.subscriber();
                let _ = sub.snapshot();
                // sub drops at end of scope-thread
            });

            // Publisher churns concurrently with tracked markers.
            for i in 1..=4u32 {
                publisher.publish(marker_threaded(i, &drops, &drop_threads));
            }
        });
        publisher.reclaim();
    }

    let observed = drop_threads.lock();
    assert!(
        !observed.is_empty(),
        "no drops recorded; the test setup never exercised the Drop path",
    );
    for (i, t) in observed.iter().enumerate() {
        assert_eq!(
            *t, publisher_thread_id,
            "drop {i} ran on {t:?}, not the Publisher's thread {publisher_thread_id:?} \
             (full record: {observed:?})",
        );
    }
}

// ---------- concurrent stress ----------

#[test]
fn concurrent_subscriber_observes_monotone_sequence() {
    let drops = Arc::new(AtomicUsize::new(0));
    let publisher = channel(marker(0, &drops));
    let stop = Arc::new(AtomicBool::new(false));

    thread::scope(|s| {
        let factory = publisher.factory();
        let stop_for_sub = Arc::clone(&stop);
        s.spawn(move || {
            let mut sub = factory.subscriber();
            let mut last = 0u32;
            while !stop_for_sub.load(Ordering::Acquire) {
                let v = sub.snapshot().payload;
                assert!(v >= last, "snapshot regressed: saw {v} after {last}");
                last = v;
            }
        });

        for i in 1..=200u32 {
            publisher.publish(marker(i, &drops));
            thread::sleep(Duration::from_micros(5));
        }

        stop.store(true, Ordering::Release);
    });

    publisher.reclaim();
    let final_drops = drops.load(Ordering::Relaxed);
    // 201 markers were created (initial + 200 publishes).  After the
    // scope joins all subscribers and we run an explicit reclaim, the
    // retired list must be drained; only the current slot value
    // (marker 200) is still alive -- so exactly 200 destructors must
    // have run.
    assert_eq!(
        final_drops, 200,
        "expected exactly 200 markers reclaimed (initial + first 199 \
         publishes); current slot value (marker 200) is still alive in \
         the publisher",
    );
}

#[test]
fn many_subscribers_dropping_does_not_strand_retired() {
    // Spin up many short-lived Subscribers concurrent with steady
    // publishes; by the end, the retired list should not have grown
    // unboundedly.
    let drops = Arc::new(AtomicUsize::new(0));
    let publisher = channel(marker(0, &drops));

    thread::scope(|s| {
        for _ in 0..16 {
            let factory = publisher.factory();
            s.spawn(move || {
                let mut sub = factory.subscriber();
                for _ in 0..50 {
                    let _ = sub.snapshot();
                    thread::sleep(Duration::from_micros(1));
                }
            });
        }

        for i in 1..=100u32 {
            publisher.publish(marker(i, &drops));
            thread::sleep(Duration::from_micros(2));
        }
    });

    publisher.reclaim();

    // After the scope has joined all Subscribers and we've run an
    // explicit reclaim, retired must be empty.  `pending_reclamation`
    // counts only retired entries -- the current slot value isn't
    // included -- so 0 is the correct expectation.
    let pending = publisher.pending_reclamation();
    assert_eq!(
        pending, 0,
        "retired list should be fully drained after Subscribers exit \
         and reclaim runs: pending = {pending}",
    );
}
