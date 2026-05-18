// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Per-peer dedup vector and future-policy-gen buffer.
//!
//! The receiver side of state-sync.  Two responsibilities:
//!
//! 1. **Dedup.**  Track the highest `origin_seq` seen per
//!    `origin_id`; messages with `seq <= seen` are duplicates
//!    (either retransmissions or loops) and dropped.
//! 2. **Policy-gen buffering.**  Messages whose
//!    `policy_gen_at_create` is ahead of the local dataplane's
//!    `current_policy_gen` are stashed; they get released to the
//!    apply path when [`advance_policy_gen`](PeerDedup::advance_policy_gen)
//!    is called with a generation that catches up.
//!
//! The dedup tracker is updated *before* the buffer decision: a
//! message that gets buffered still marks its `origin_seq` as seen.
//! If the buffer entry is later dropped (TTL / peer-dead), the
//! tracker's view does not change -- the peer would need to resync
//! from a fresh snapshot to recover.  This matches the design
//! intent: long-lived buffered entries indicate a real problem
//! that warrants snapshot-fallback, not in-band retry.
//!
//! See `.scratch/mat-pipeline-rfc/` for the broader design.

use std::collections::{BTreeMap, HashMap};

use cascade::Generation;
use concurrency::sync::Mutex;
use mat::{HasOrigin, OriginId, OriginSeq, StateSyncMessage};

/// Outcome of [`PeerDedup::accept`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptOutcome<V> {
    /// The entry passed dedup and is ready to apply.  Caller
    /// should call `cascade.write` with it.
    Apply(V),
    /// The entry is a duplicate (`origin_seq <= seen`) and should
    /// be silently dropped.
    Skip,
    /// The entry's `policy_gen_at_create` is ahead of the local
    /// `current_policy_gen`; it has been stashed in the buffer.
    /// It will surface from a future
    /// [`advance_policy_gen`](PeerDedup::advance_policy_gen) call
    /// once the local policy gen catches up.
    Buffered,
}

/// Per-peer dedup vector with a policy-gen-keyed buffer for
/// future entries.
///
/// Shared across all incoming messages from the local dataplane's
/// peers.  Single shared instance per flavor-B cascade is the
/// expected usage -- the `origin_id` in each message distinguishes
/// which logical peer the message originated from.
pub struct PeerDedup<V> {
    seen: Mutex<HashMap<OriginId, OriginSeq>>,
    buffer: Mutex<BTreeMap<Generation, Vec<V>>>,
}

impl<V> PeerDedup<V>
where
    V: HasOrigin + Clone,
{
    /// Construct an empty dedup state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
            buffer: Mutex::new(BTreeMap::new()),
        }
    }

    /// Apply dedup and buffer policy to an incoming message.
    ///
    /// See [`AcceptOutcome`] for the three possible outcomes.
    /// `current_policy_gen` is the local dataplane's currently-
    /// published policy generation (typically
    /// `PolicyGenAllocator::current()`).
    pub fn accept(
        &self,
        msg: StateSyncMessage<V>,
        current_policy_gen: Generation,
    ) -> AcceptOutcome<V> {
        let origin = msg.entry.origin();

        // Dedup first.  Even messages that end up buffered are
        // recorded as seen -- see the module docs for the rationale.
        {
            let mut seen = self.seen.lock();
            if let Some(&high) = seen.get(&origin.origin_id)
                && origin.origin_seq <= high
            {
                return AcceptOutcome::Skip;
            }
            seen.insert(origin.origin_id, origin.origin_seq);
        }

        // Future policy-gen: stash for later.
        if origin.policy_gen_at_create > current_policy_gen {
            let mut buf = self.buffer.lock();
            buf.entry(origin.policy_gen_at_create)
                .or_default()
                .push(msg.entry);
            return AcceptOutcome::Buffered;
        }

        AcceptOutcome::Apply(msg.entry)
    }

    /// Release buffered entries whose `policy_gen_at_create` is
    /// at or below `new_policy_gen`.
    ///
    /// Called by the manager whenever `current_policy_gen` advances
    /// (i.e. a rollout was just published).  The returned entries
    /// are in arbitrary order; the caller writes them to the local
    /// cascade.
    pub fn advance_policy_gen(&self, new_policy_gen: Generation) -> Vec<V> {
        let mut buf = self.buffer.lock();
        let mut released = Vec::new();

        // BTreeMap is ordered, so split off everything > new_policy_gen.
        // Anything still in `buf` after split_off has gen > new -- not
        // yet ready.
        let split_key = new_policy_gen.get().saturating_add(1);
        let Some(split) = Generation::new(split_key) else {
            // Overflow at u64::MAX: every key in the buffer
            // qualifies.  Drain the whole thing.
            let drained: Vec<V> = buf.values().flatten().cloned().collect();
            buf.clear();
            return drained;
        };

        let still_buffered = buf.split_off(&split);
        // `buf` now contains entries with gen <= new; collect their
        // values.
        for (_, mut entries) in core::mem::take(&mut *buf) {
            released.append(&mut entries);
        }
        *buf = still_buffered;

        released
    }

    /// Drop all buffered entries originating from `peer`.  Called
    /// by the manager when k8s reports a peer dead, or when the
    /// active health probe fails the configured threshold.
    ///
    /// Returns the number of entries dropped (diagnostic).  Note
    /// this only drops *buffered* entries; the seen-tracker is
    /// not reset.  When the peer comes back online, the manager
    /// should orchestrate a fresh snapshot resync rather than
    /// rely on in-band retransmits.
    pub fn drop_buffered_from_peer(&self, peer: OriginId) -> usize {
        let mut buf = self.buffer.lock();
        let mut dropped: usize = 0;
        for entries in buf.values_mut() {
            let before = entries.len();
            entries.retain(|e| e.origin().origin_id != peer);
            dropped += before - entries.len();
        }
        // Trim empty bucket vectors so future drains do not waste
        // time over them.
        buf.retain(|_, v| !v.is_empty());
        dropped
    }

    /// Highest `origin_seq` seen from `peer`, or `None` if no
    /// message from that peer has been processed.  Diagnostic.
    #[must_use]
    pub fn seen(&self, peer: OriginId) -> Option<OriginSeq> {
        self.seen.lock().get(&peer).copied()
    }

    /// Number of entries currently held in the future-policy-gen
    /// buffer.  Diagnostic.
    #[must_use]
    pub fn buffered_count(&self) -> usize {
        self.buffer.lock().values().map(Vec::len).sum()
    }
}

impl<V> Default for PeerDedup<V>
where
    V: HasOrigin + Clone,
{
    fn default() -> Self {
        Self::new()
    }
}
