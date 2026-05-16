// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Consumer-side merged-pending state.
//!
//! `DiffBuffer<Op>` is the standard helper for cascade consumers
//! that need to accumulate drained ops between flushes.  The
//! replicator uses one per peer to buffer outgoing diffs; the
//! hardware backend uses one to batch `PCIe` operations; the software
//! classifier service may use one as the input to its next
//! recompile.
//!
//! The buffer is intentionally minimal at this sketch stage.  The
//! shape will fill out once we have a concrete consumer that
//! exercises it.
//!
//! # Discipline
//!
//! Consumers receive an `Arc<Sealed>` from the cascade's drain
//! subscription.  They are expected to walk the sealed layer
//! *promptly*, absorb its ops into a private `DiffBuffer`, and drop
//! the `Arc`.  Slow work (HW programming, wire serialization,
//! classifier compilation) happens after release, against the
//! buffer's owned state.  This keeps the cascade's reclamation
//! latency bounded by "time to take a snapshot", not "time to do
//! the work."

use core::marker::PhantomData;

/// Accumulates ops between consumer flushes.
///
/// The internal representation is intentionally left unspecified at
/// this stage.  The public surface is the minimum a consumer needs:
/// absorb new ops, iterate the accumulated content, clear on
/// completion, and report rough size.
///
/// `K` and `V` are *advisory* type parameters that document what the
/// buffer holds.  The concrete storage is a hashbrown table keyed
/// by `K` in the typical case; specialized consumers (queue-shaped
/// rule mutations for ACL, etc.) will likely sit alongside or
/// wrap this rather than reuse it directly.
pub struct DiffBuffer<K, V> {
    // Placeholder.  Will be backed by `hashbrown::HashMap<K, V>`
    // once we add the dep; for now keep the type parameters honest
    // via PhantomData so consumers can compile against the trait
    // surface.
    _phantom: PhantomData<fn() -> (K, V)>,
}

impl<K, V> DiffBuffer<K, V> {
    /// An empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }

    /// Approximate size in entries.  Used by consumers to compare
    /// against a discard threshold.
    #[must_use]
    pub fn approx_size(&self) -> usize {
        // Placeholder.
        0
    }

    /// Drop all accumulated state.  Called on successful flush
    /// (peer ack, HW programming complete, classifier published).
    pub fn clear(&mut self) {
        // Placeholder.
    }
}

impl<K, V> Default for DiffBuffer<K, V> {
    fn default() -> Self {
        Self::new()
    }
}
