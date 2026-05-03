//! Multi-threaded protocol tests for `dataplane_quiescent`.
//!
//! The single-threaded protocol invariants (snapshot legality,
//! reclamation gating, conservation of `Versioned` allocations) are
//! covered by the bolero property tests in `tests/properties.rs`.
//! This file holds only the tests that genuinely need real OS threads:
//!
//! - **Drop affinity**: destructors must run on the writer thread,
//!   even when the last reader drops concurrently with reclaim.
//! - **Concurrent stress**: reader/writer interaction across realistic
//!   scheduling.
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
fn destructor_of_initial_runs_on_writer_thread() {
    let drops = Arc::new(AtomicUsize::new(0));
    let initial_thread = Arc::new(Mutex::new(None));
    let writer_thread_id = thread::current().id();

    let (mut writer, publisher) = channel(marker_threaded(0, &drops, &initial_thread));

    // Reader thread observes initial, then exits.
    let publisher_for_reader = publisher.clone();
    thread::spawn(move || {
        let mut reader = publisher_for_reader.reader();
        let _ = reader.snapshot();
    })
    .join()
    .unwrap();

    // Writer publishes a new value and reclaims; the initial's destructor
    // should fire here on this (writer) thread, NOT on the reader thread.
    writer.publish(marker(1, &drops));
    writer.reclaim();

    let observed = *initial_thread.lock().unwrap();
    assert_eq!(
        observed,
        Some(writer_thread_id),
        "initial value's destructor must run on the writer's thread",
    );
}

#[test]
fn destructor_runs_on_writer_when_last_reader_drops_concurrently() {
    // Stronger version: the reader is dropped while the writer is busy
    // publishing.  With the `Drop` impl on `Reader` ensuring `cached`
    // dies before `epoch`, the destructor must still resolve on the
    // writer's thread.
    let drops = Arc::new(AtomicUsize::new(0));
    let initial_thread = Arc::new(Mutex::new(None));
    let writer_thread_id = thread::current().id();

    let (mut writer, publisher) = channel(marker_threaded(0, &drops, &initial_thread));

    // Repeat to expose the race window across timings.
    for _ in 0..8 {
        let publisher_for_reader = publisher.clone();
        let reader_handle = thread::spawn(move || {
            let mut reader = publisher_for_reader.reader();
            let _ = reader.snapshot();
            // reader drops at end of thread
        });

        // Writer churns concurrently.
        for i in 1..=4u32 {
            writer.publish(marker(i, &drops));
        }
        reader_handle.join().unwrap();
        writer.reclaim();
    }

    let observed = *initial_thread.lock().unwrap();
    assert_eq!(
        observed,
        Some(writer_thread_id),
        "initial destructor must always resolve on the writer thread",
    );
}

// ---------- concurrent stress ----------

#[test]
fn concurrent_reader_observes_monotone_sequence() {
    let drops = Arc::new(AtomicUsize::new(0));
    let (mut writer, publisher) = channel(marker(0, &drops));
    let stop = Arc::new(AtomicBool::new(false));

    let stop_for_reader = Arc::clone(&stop);
    let publisher_for_reader = publisher.clone();
    let reader_handle = thread::spawn(move || {
        let mut reader = publisher_for_reader.reader();
        let mut last = 0u32;
        while !stop_for_reader.load(Ordering::Acquire) {
            let v = reader.snapshot().payload;
            assert!(v >= last, "snapshot regressed: saw {v} after {last}");
            last = v;
        }
    });

    for i in 1..=200u32 {
        writer.publish(marker(i, &drops));
        thread::sleep(Duration::from_micros(5));
    }

    stop.store(true, Ordering::Release);
    reader_handle.join().unwrap();

    writer.reclaim();
    let final_drops = drops.load(Ordering::Relaxed);
    // 201 markers were created (initial + 200 publishes).  The writer's
    // current and possibly one in-flight retired entry may still be alive;
    // everything else should be reclaimed.
    assert!(
        final_drops >= 199,
        "expected nearly all markers reclaimed, got {final_drops}",
    );
}

#[test]
fn many_readers_reader_drop_does_not_strand_retired() {
    // Spin up many short-lived readers concurrent with steady publishes;
    // by the end, the retired list should not have grown unboundedly.
    let drops = Arc::new(AtomicUsize::new(0));
    let (mut writer, publisher) = channel(marker(0, &drops));

    let mut handles = Vec::new();
    for _ in 0..16 {
        let publisher_for_reader = publisher.clone();
        handles.push(thread::spawn(move || {
            let mut reader = publisher_for_reader.reader();
            for _ in 0..50 {
                let _ = reader.snapshot();
                thread::sleep(Duration::from_micros(1));
            }
        }));
    }

    for i in 1..=100u32 {
        writer.publish(marker(i, &drops));
        thread::sleep(Duration::from_micros(2));
    }

    for h in handles {
        h.join().unwrap();
    }
    writer.reclaim();

    // Steady state should leave at most a small number of retired entries
    // (the current publication is held by the slot, not retired).
    let pending = writer.pending_reclamation();
    assert!(
        pending <= 1,
        "pending reclamation should drain after readers exit: {pending}",
    );
}
