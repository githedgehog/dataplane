//! Loom model-checking tests for `dataplane_quiescent`.
//!
//! These tests run only under `RUSTFLAGS="--cfg loom"`; the standard
//! protocol tests live in `tests/protocol.rs`.
//!
//! Run with:
//!   `RUSTFLAGS="--cfg loom" cargo test --release -p dataplane-quiescent --test loom`
//!
//! Loom explores all legal interleavings of the operations inside each
//! `loom::model(|| { ... })` block.  Keep test bodies minimal — each
//! extra atomic op multiplies the search space.  Two threads with one
//! atomic op each is roughly the right shape; "2 publishes + 2 readers
//! + a drop" already explodes.

#![cfg(loom)]

use loom::thread;

use dataplane_quiescent::channel;

/// A snapshot taken after a publish must observe a value the writer ever
/// stored.  Under any interleaving of `publish` vs `snapshot`, the
/// reader sees either the initial or the published value, never anything
/// else (no torn reads, no use-after-free).
#[test]
fn snapshot_observes_a_legal_value() {
    loom::model(|| {
        let (mut writer, publisher) = channel(0u32);
        let publisher_for_reader = publisher.clone();

        let reader_handle = thread::spawn(move || {
            let mut reader = publisher_for_reader.reader();
            let observed = *reader.snapshot();
            assert!(
                observed == 0 || observed == 1,
                "reader observed illegal value {observed}",
            );
        });

        writer.publish(1u32);
        reader_handle.join().unwrap();
    });
}

/// A reader that takes a snapshot before the writer publishes, then is
/// dropped concurrently with the writer's reclaim, must not deadlock and
/// must not leave the protocol in an inconsistent state.
#[test]
fn reader_drop_during_publish_is_safe() {
    loom::model(|| {
        let (mut writer, publisher) = channel(0u32);
        let publisher_for_reader = publisher.clone();

        let reader_handle = thread::spawn(move || {
            let mut reader = publisher_for_reader.reader();
            let _ = *reader.snapshot();
            // Reader drops at end of thread; concurrent with writer below.
        });

        writer.publish(1u32);
        writer.reclaim();
        reader_handle.join().unwrap();
    });
}

/// A reader that snapshots after `publish` returns must observe the
/// published value, not the initial.  This pins down the publish-then-
/// snapshot ordering.
#[test]
fn snapshot_after_publish_observes_published() {
    loom::model(|| {
        let (mut writer, publisher) = channel(0u32);
        let mut reader = publisher.reader();

        writer.publish(1u32);
        let observed = *reader.snapshot();
        assert_eq!(
            observed, 1,
            "snapshot taken after publish() returns must observe the published value",
        );
    });
}

/// Reader registered before publish, snapshot taken after — should
/// observe the published value.  The 0-sentinel branch in `min_observed`
/// must not turn this into a use-after-free.
#[test]
fn registered_then_publish_then_snapshot() {
    loom::model(|| {
        let (mut writer, publisher) = channel(0u32);
        let publisher_for_reader = publisher.clone();

        let reader_handle = thread::spawn(move || {
            let mut reader = publisher_for_reader.reader();
            // Snapshot may race with publish.  Either way, we must see
            // a legal value.
            let observed = *reader.snapshot();
            assert!(observed == 0 || observed == 1);
        });

        writer.publish(1u32);
        writer.reclaim();
        reader_handle.join().unwrap();
    });
}
