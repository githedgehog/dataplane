//! Multi-threaded protocol tests for `dataplane_quiescent`.
//!
//! The single-threaded protocol invariants (snapshot legality,
//! reclamation gating, conservation of `Versioned` allocations) are
//! covered by the bolero property tests in `tests/properties.rs`.
//! This file holds only the tests that genuinely need real OS threads:
//!
//! - **Drop affinity**: destructors must run on the Publisher's
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
//! Loom-modeled tests live in `tests/loom.rs`.

#![cfg(not(any(feature = "loom", feature = "shuttle")))]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use dataplane_quiescent::channel;

// ---------- helpers ----------

/// Payload that counts its own drops and (optionally) records the
/// thread on which its destructor ran.
struct Marker {
    drop_counter: Arc<AtomicUsize>,
    drop_thread: Option<Arc<Mutex<Option<thread::ThreadId>>>>,
    payload: u32,
}

impl Drop for Marker {
    fn drop(&mut self) {
        self.drop_counter.fetch_add(1, Ordering::Relaxed);
        if let Some(slot) = &self.drop_thread {
            *slot.lock().unwrap() = Some(thread::current().id());
        }
    }
}

fn marker(payload: u32, drops: &Arc<AtomicUsize>) -> Marker {
    Marker {
        drop_counter: Arc::clone(drops),
        drop_thread: None,
        payload,
    }
}

fn marker_threaded(
    payload: u32,
    drops: &Arc<AtomicUsize>,
    slot: &Arc<Mutex<Option<thread::ThreadId>>>,
) -> Marker {
    Marker {
        drop_counter: Arc::clone(drops),
        drop_thread: Some(Arc::clone(slot)),
        payload,
    }
}

// ---------- drop affinity ----------

#[test]
fn destructor_of_initial_runs_on_publisher_thread() {
    let drops = Arc::new(AtomicUsize::new(0));
    let initial_thread = Arc::new(Mutex::new(None));
    let publisher_thread_id = thread::current().id();

    let publisher = channel(marker_threaded(0, &drops, &initial_thread));

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

    let observed = *initial_thread.lock().unwrap();
    assert_eq!(
        observed,
        Some(publisher_thread_id),
        "initial value's destructor must run on the Publisher's thread",
    );
}

#[test]
fn destructor_runs_on_publisher_when_last_subscriber_drops_concurrently() {
    // Stronger version: the Subscriber is dropped while the Publisher
    // is busy publishing.  With the `Drop` impl on `Subscriber`
    // ensuring `cached` dies before `epoch`, the destructor must still
    // resolve on the Publisher's thread.
    let drops = Arc::new(AtomicUsize::new(0));
    let initial_thread = Arc::new(Mutex::new(None));
    let publisher_thread_id = thread::current().id();

    let publisher = channel(marker_threaded(0, &drops, &initial_thread));

    // Repeat to expose the race window across timings.
    for _ in 0..8 {
        thread::scope(|s| {
            let factory = publisher.factory();
            s.spawn(move || {
                let mut sub = factory.subscriber();
                let _ = sub.snapshot();
                // sub drops at end of scope-thread
            });

            // Publisher churns concurrently.
            for i in 1..=4u32 {
                publisher.publish(marker(i, &drops));
            }
        });
        publisher.reclaim();
    }

    let observed = *initial_thread.lock().unwrap();
    assert_eq!(
        observed,
        Some(publisher_thread_id),
        "initial destructor must always resolve on the Publisher's thread",
    );
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
    // 201 markers were created (initial + 200 publishes).  The
    // Publisher's current and possibly one in-flight retired entry may
    // still be alive; everything else should be reclaimed.
    assert!(
        final_drops >= 199,
        "expected nearly all markers reclaimed, got {final_drops}",
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

    // Steady state should leave at most a small number of retired
    // entries (the current publication is held by the slot, not
    // retired).
    let pending = publisher.pending_reclamation();
    assert!(
        pending <= 1,
        "pending reclamation should drain after Subscribers exit: {pending}",
    );
}
