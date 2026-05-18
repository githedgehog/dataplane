// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Behaviour tests for [`PeerDedup`].
//!
//! Exercises the receiver-side dedup + policy-gen buffer through
//! its full surface: first-receive, replay, out-of-order, future-
//! policy-gen buffer/release, and peer-eviction.

#![allow(clippy::expect_used)]

use cascade::Generation;
use mat::{FlowOrigin, HasOrigin, OriginId, OriginSeq, StateSyncMessage, TransportSeq};
use dataplane_mat_state_sync::{AcceptOutcome, PeerDedup};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TestEntry {
    payload: u32,
    origin: FlowOrigin,
}

impl HasOrigin for TestEntry {
    fn origin(&self) -> FlowOrigin {
        self.origin
    }
}

fn dp(id: u32) -> OriginId {
    OriginId::new(id).expect("nonzero")
}

fn seq(n: u64) -> OriginSeq {
    OriginSeq::new(n).expect("nonzero")
}

fn g(n: u64) -> Generation {
    Generation::new(n).expect("nonzero")
}

fn msg(payload: u32, dp_id: u32, sequence: u64, policy_gen: Generation) -> StateSyncMessage<TestEntry> {
    StateSyncMessage {
        msg_seq: TransportSeq::ZERO,
        entry: TestEntry {
            payload,
            origin: FlowOrigin {
                origin_id: dp(dp_id),
                origin_seq: seq(sequence),
                policy_gen_at_create: policy_gen,
            },
        },
    }
}

// ---------------------------------------------------------------------------
// Apply / Skip / Buffered
// ---------------------------------------------------------------------------

#[test]
fn first_message_from_origin_applies() {
    let dd = PeerDedup::<TestEntry>::new();
    let current = g(10);

    let out = dd.accept(msg(100, /* dp */ 1, /* seq */ 1, g(10)), current);
    match out {
        AcceptOutcome::Apply(entry) => {
            assert_eq!(entry.payload, 100);
        }
        other => panic!("expected Apply, got {other:?}"),
    }
    assert_eq!(dd.seen(dp(1)), Some(seq(1)));
}

#[test]
fn replay_of_same_seq_is_skipped() {
    let dd = PeerDedup::<TestEntry>::new();
    let current = g(10);

    let _ = dd.accept(msg(100, 1, 5, g(10)), current);
    let out = dd.accept(msg(999, 1, 5, g(10)), current);
    assert_eq!(out, AcceptOutcome::Skip);
}

#[test]
fn out_of_order_older_seq_is_skipped() {
    let dd = PeerDedup::<TestEntry>::new();
    let current = g(10);

    // First receive seq=10.
    let _ = dd.accept(msg(100, 1, 10, g(10)), current);
    // Now receive seq=5 -- older, should be dropped.
    let out = dd.accept(msg(999, 1, 5, g(10)), current);
    assert_eq!(out, AcceptOutcome::Skip);
    // seen high-water unchanged.
    assert_eq!(dd.seen(dp(1)), Some(seq(10)));
}

#[test]
fn higher_seq_from_same_origin_applies() {
    let dd = PeerDedup::<TestEntry>::new();
    let current = g(10);

    let _ = dd.accept(msg(100, 1, 5, g(10)), current);
    let out = dd.accept(msg(200, 1, 6, g(10)), current);
    match out {
        AcceptOutcome::Apply(e) => assert_eq!(e.payload, 200),
        other => panic!("expected Apply, got {other:?}"),
    }
    assert_eq!(dd.seen(dp(1)), Some(seq(6)));
}

#[test]
fn different_origins_dedup_independently() {
    let dd = PeerDedup::<TestEntry>::new();
    let current = g(10);

    let _ = dd.accept(msg(100, 1, 5, g(10)), current);
    let _ = dd.accept(msg(200, 2, 5, g(10)), current);
    // Each origin has its own high-water.
    assert_eq!(dd.seen(dp(1)), Some(seq(5)));
    assert_eq!(dd.seen(dp(2)), Some(seq(5)));

    // Replay of dp=1 seq=5 is skipped; dp=2 seq=5 already seen
    // would also be skipped.
    assert_eq!(
        dd.accept(msg(999, 1, 5, g(10)), current),
        AcceptOutcome::Skip
    );
}

// ---------------------------------------------------------------------------
// Policy-gen buffering
// ---------------------------------------------------------------------------

#[test]
fn entry_with_future_policy_gen_is_buffered() {
    let dd = PeerDedup::<TestEntry>::new();
    let current = g(10);

    let out = dd.accept(msg(100, 1, 1, g(15)), current);
    assert_eq!(out, AcceptOutcome::Buffered);
    assert_eq!(dd.buffered_count(), 1);

    // Dedup still tracks the message even though it's buffered.
    assert_eq!(dd.seen(dp(1)), Some(seq(1)));
}

#[test]
fn advance_policy_gen_releases_buffered_entries() {
    let dd = PeerDedup::<TestEntry>::new();
    let current = g(10);

    let _ = dd.accept(msg(100, 1, 1, g(11)), current);
    let _ = dd.accept(msg(200, 2, 1, g(13)), current);
    let _ = dd.accept(msg(300, 3, 1, g(15)), current);
    assert_eq!(dd.buffered_count(), 3);

    // Advance to 12: releases the gen-11 entry, leaves 13 and 15.
    let released = dd.advance_policy_gen(g(12));
    assert_eq!(released.len(), 1);
    assert_eq!(released[0].payload, 100);
    assert_eq!(dd.buffered_count(), 2);

    // Advance to 15: releases both remaining.
    let released = dd.advance_policy_gen(g(15));
    assert_eq!(released.len(), 2);
    let payloads: Vec<u32> = released.iter().map(|e| e.payload).collect();
    assert!(payloads.contains(&200));
    assert!(payloads.contains(&300));
    assert_eq!(dd.buffered_count(), 0);
}

#[test]
fn advance_policy_gen_with_no_buffered_returns_empty() {
    let dd = PeerDedup::<TestEntry>::new();
    let released = dd.advance_policy_gen(g(100));
    assert!(released.is_empty());
}

#[test]
fn advance_to_lower_gen_releases_nothing() {
    let dd = PeerDedup::<TestEntry>::new();
    let current = g(10);

    let _ = dd.accept(msg(100, 1, 1, g(20)), current);
    let released = dd.advance_policy_gen(g(15));
    assert!(released.is_empty());
    assert_eq!(dd.buffered_count(), 1);
}

// ---------------------------------------------------------------------------
// Peer eviction (k8s / health-probe says peer is dead)
// ---------------------------------------------------------------------------

#[test]
fn drop_buffered_from_peer_only_drops_that_peer() {
    let dd = PeerDedup::<TestEntry>::new();
    let current = g(10);

    let _ = dd.accept(msg(100, 1, 1, g(15)), current);
    let _ = dd.accept(msg(200, 1, 2, g(15)), current);
    let _ = dd.accept(msg(300, 2, 1, g(15)), current);
    assert_eq!(dd.buffered_count(), 3);

    let dropped = dd.drop_buffered_from_peer(dp(1));
    assert_eq!(dropped, 2);
    assert_eq!(dd.buffered_count(), 1);

    // The remaining entry is from dp=2.
    let released = dd.advance_policy_gen(g(15));
    assert_eq!(released.len(), 1);
    assert_eq!(released[0].payload, 300);
}

#[test]
fn drop_buffered_does_not_reset_seen_vector() {
    let dd = PeerDedup::<TestEntry>::new();
    let current = g(10);

    let _ = dd.accept(msg(100, 1, 5, g(15)), current);
    let dropped = dd.drop_buffered_from_peer(dp(1));
    assert_eq!(dropped, 1);

    // seen still records origin_seq=5; a replay would still skip.
    assert_eq!(dd.seen(dp(1)), Some(seq(5)));
    assert_eq!(
        dd.accept(msg(999, 1, 5, g(15)), current),
        AcceptOutcome::Skip
    );
    // A higher seq from the same dropped peer still passes dedup.
    let out = dd.accept(msg(123, 1, 6, g(10)), current);
    assert!(matches!(out, AcceptOutcome::Apply(_)));
}

// ---------------------------------------------------------------------------
// Mixed-mode lifecycle
// ---------------------------------------------------------------------------

#[test]
fn lifecycle_apply_then_buffer_then_release() {
    let dd = PeerDedup::<TestEntry>::new();
    let mut current = g(10);

    // First message: immediate apply.
    let out = dd.accept(msg(100, 1, 1, g(10)), current);
    assert!(matches!(out, AcceptOutcome::Apply(_)));

    // Second message: future gen, buffer.
    let out = dd.accept(msg(200, 1, 2, g(20)), current);
    assert_eq!(out, AcceptOutcome::Buffered);

    // Policy advances to 15: nothing released yet (200 needs gen 20).
    let released = dd.advance_policy_gen(g(15));
    assert!(released.is_empty());
    current = g(15);

    // Third message: future gen too, buffer.
    let out = dd.accept(msg(300, 2, 1, g(25)), current);
    assert_eq!(out, AcceptOutcome::Buffered);

    // Policy advances to 20: releases the gen=20 entry but not gen=25.
    let released = dd.advance_policy_gen(g(20));
    assert_eq!(released.len(), 1);
    assert_eq!(released[0].payload, 200);

    // Policy advances to 25: releases the rest.
    let released = dd.advance_policy_gen(g(25));
    assert_eq!(released.len(), 1);
    assert_eq!(released[0].payload, 300);

    assert_eq!(dd.buffered_count(), 0);
}
