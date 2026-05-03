//! Standard protocol tests for `dataplane_quiescent`.
//!
//! Covers:
//! - Snapshot semantics (observes latest, monotone non-decreasing).
//! - QSBR reclamation under various reader populations.
//! - Drop affinity: destructors run on the writer thread.
//! - Sentinel behavior for not-yet-observed readers.
//!
//! These tests use real OS threads.  Loom-modeled tests live in
//! `tests/loom.rs`.

#![cfg(not(loom))]

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

// ---------- snapshot semantics ----------

#[test]
fn snapshot_reflects_initial_value() {
    let drops = Arc::new(AtomicUsize::new(0));
    let (_writer, publisher) = channel(marker(42, &drops));
    let mut reader = publisher.reader();
    assert_eq!(reader.snapshot().payload, 42);
}

#[test]
fn snapshot_observes_published_updates() {
    let drops = Arc::new(AtomicUsize::new(0));
    let (mut writer, publisher) = channel(marker(0, &drops));
    let mut reader = publisher.reader();

    assert_eq!(reader.snapshot().payload, 0);

    writer.publish(marker(1, &drops));
    assert_eq!(reader.snapshot().payload, 1);

    writer.publish(marker(2, &drops));
    assert_eq!(reader.snapshot().payload, 2);
}

#[test]
fn multiple_readers_see_consistent_snapshots() {
    let drops = Arc::new(AtomicUsize::new(0));
    let (mut writer, publisher) = channel(marker(0, &drops));
    let mut reader_a = publisher.reader();
    let mut reader_b = publisher.reader();

    assert_eq!(reader_a.snapshot().payload, 0);
    assert_eq!(reader_b.snapshot().payload, 0);

    writer.publish(marker(7, &drops));
    assert_eq!(reader_a.snapshot().payload, 7);
    assert_eq!(reader_b.snapshot().payload, 7);
}

#[test]
fn publish_versions_increase_monotonically() {
    let drops = Arc::new(AtomicUsize::new(0));
    let (mut writer, _publisher) = channel(marker(0, &drops));

    let v1 = writer.publish(marker(1, &drops));
    let v2 = writer.publish(marker(2, &drops));
    let v3 = writer.publish(marker(3, &drops));

    assert!(v1 < v2);
    assert!(v2 < v3);
}

// ---------- QSBR reclamation ----------

#[test]
fn retired_drops_after_reader_advances_past() {
    let drops = Arc::new(AtomicUsize::new(0));
    let (mut writer, publisher) = channel(marker(0, &drops));
    let mut reader = publisher.reader();

    reader.snapshot(); // pin initial

    writer.publish(marker(1, &drops));
    // Reader still pinning the initial; nothing should drop yet.
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert_eq!(writer.pending_reclamation(), 1);

    reader.snapshot(); // advance past initial
    writer.publish(marker(2, &drops));
    // Initial is now reclaimable; its destructor should have run.
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}

#[test]
fn reclaim_blocked_until_all_readers_advance() {
    let drops = Arc::new(AtomicUsize::new(0));
    let (mut writer, publisher) = channel(marker(0, &drops));
    let mut reader_a = publisher.reader();
    let mut reader_b = publisher.reader();

    reader_a.snapshot();
    reader_b.snapshot();

    writer.publish(marker(1, &drops));
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert_eq!(writer.pending_reclamation(), 1);

    // Only A advances; B still pinning the initial.
    reader_a.snapshot();
    writer.reclaim();
    assert_eq!(drops.load(Ordering::Relaxed), 0);

    // Now B advances; reclamation can proceed.
    reader_b.snapshot();
    writer.reclaim();
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}

#[test]
fn dropping_reader_unblocks_reclaim() {
    let drops = Arc::new(AtomicUsize::new(0));
    let (mut writer, publisher) = channel(marker(0, &drops));
    let mut reader = publisher.reader();
    reader.snapshot();

    writer.publish(marker(1, &drops));
    assert_eq!(drops.load(Ordering::Relaxed), 0);

    drop(reader);
    writer.reclaim();
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert_eq!(writer.pending_reclamation(), 0);
}

#[test]
fn not_yet_observed_reader_does_not_block_reclaim() {
    // Regression for the 0-sentinel branch in `min_observed`: a registered
    // reader that has never called `snapshot` holds no pin and must not
    // constrain reclaim.
    let drops = Arc::new(AtomicUsize::new(0));
    let (mut writer, publisher) = channel(marker(0, &drops));

    let _reader = publisher.reader(); // registered, never snapshotted

    writer.publish(marker(1, &drops));
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert_eq!(writer.pending_reclamation(), 0);
}

#[test]
fn registered_then_publish_then_snapshot_observes_latest() {
    // Companion to the above: a reader that registers BEFORE a publish but
    // snapshots AFTER it should observe the latest value, not a
    // freed-then-resurrected initial.
    let drops = Arc::new(AtomicUsize::new(0));
    let (mut writer, publisher) = channel(marker(0, &drops));

    let mut reader = publisher.reader();
    writer.publish(marker(1, &drops));
    // Initial should have been reclaimed (reader hadn't observed it).
    assert_eq!(drops.load(Ordering::Relaxed), 1);

    assert_eq!(reader.snapshot().payload, 1);
}

#[test]
fn reclaim_with_no_readers_drains_retired() {
    let drops = Arc::new(AtomicUsize::new(0));
    let (mut writer, _publisher) = channel(marker(0, &drops));

    writer.publish(marker(1, &drops));
    writer.publish(marker(2, &drops));
    writer.reclaim();
    assert_eq!(drops.load(Ordering::Relaxed), 2);
    assert_eq!(writer.pending_reclamation(), 0);
}

// ---------- drop affinity ----------

#[test]
fn destructor_of_initial_runs_on_writer_thread() {
    let drops = Arc::new(AtomicUsize::new(0));
    let initial_thread = Arc::new(Mutex::new(None));
    let writer_thread_id = thread::current().id();

    let (mut writer, publisher) =
        channel(marker_threaded(0, &drops, &initial_thread));

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

    let (mut writer, publisher) =
        channel(marker_threaded(0, &drops, &initial_thread));

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

// ---------- concurrent smoke ----------

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
            assert!(
                v >= last,
                "snapshot regressed: saw {v} after {last}",
            );
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
    // (the current publication is held by ArcSwap, not retired).
    let pending = writer.pending_reclamation();
    assert!(
        pending <= 1,
        "pending reclamation should drain after readers exit: {pending}",
    );
}
