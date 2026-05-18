// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Origin tagging for cross-dataplane state replication.
//!
//! Every flavor-B (induced / learned) state entry that may be
//! replicated across dataplanes carries a [`FlowOrigin`] in its
//! metadata.  The fields:
//!
//! - [`OriginId`]: which dataplane first observed this entry.
//! - [`OriginSeq`]: a monotonic counter per origin, used by the
//!   conflict-resolution `Upsert` impl as the LWW tiebreaker.
//! - [`Generation`]: the originating dataplane's policy generation
//!   at the moment the entry was created.  The receiver uses this
//!   to decide whether to apply, buffer (config not yet caught up),
//!   or drop (long-lived legacy entry whose authorising rule is
//!   gone).
//!
//! See `.scratch/mat-pipeline-rfc/` for the full design.

use core::num::NonZeroU32;
use core::num::NonZeroU64;

use cascade::Generation;

/// Identifies a dataplane in cross-dataplane replication metadata.
///
/// Non-zero so `Option<OriginId>` has niche-optimised layout.  The
/// concrete numbering scheme is the deployment's choice -- a stable
/// k8s-assigned identifier, a hash of the dataplane's node name, or
/// a configuration-supplied integer.  The pipeline manager treats
/// these as opaque labels.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct OriginId(NonZeroU32);

impl OriginId {
    /// Construct from a raw `u32`.  Returns `None` for zero.
    #[must_use]
    pub const fn new(raw: u32) -> Option<Self> {
        match NonZeroU32::new(raw) {
            Some(n) => Some(Self(n)),
            None => None,
        }
    }

    /// The raw `u32` value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// Per-origin monotonic sequence counter for flow-state entries.
///
/// Used by the value type's `Upsert` impl as the LWW tiebreaker:
/// for two entries with the same `OriginId`, the one with the
/// higher `OriginSeq` wins.  For two entries with different
/// `OriginId`s, the convention is to break ties on
/// `(OriginId, OriginSeq)` lexicographic order so the resolution is
/// deterministic at every receiver.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct OriginSeq(NonZeroU64);

impl OriginSeq {
    /// The smallest valid sequence value.
    pub const FIRST: Self = Self(NonZeroU64::MIN);

    /// Construct from a raw `u64`.  Returns `None` for zero.
    #[must_use]
    pub const fn new(raw: u64) -> Option<Self> {
        match NonZeroU64::new(raw) {
            Some(n) => Some(Self(n)),
            None => None,
        }
    }

    /// The raw `u64` value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// The next sequence after `self`, or `None` on `u64::MAX`
    /// overflow (operationally unreachable).
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(nz) => Some(Self(nz)),
            None => None,
        }
    }
}

/// Origin metadata attached to every replicable flavor-B entry.
///
/// Both the entry's `Upsert` impl (for conflict resolution) and the
/// state-sync subscriber (for dedup and config-gen gating) consult
/// this struct.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct FlowOrigin {
    /// Dataplane that first observed this entry.
    pub origin_id: OriginId,
    /// Per-origin monotonic counter.
    pub origin_seq: OriginSeq,
    /// Originating dataplane's policy generation at the moment of
    /// entry creation.
    pub policy_gen_at_create: Generation,
}

impl FlowOrigin {
    /// LWW tiebreak key: `(origin_id, origin_seq)` ordered
    /// lexicographically.  Used by `Upsert` impls on flow value
    /// types so all dataplanes converge to the same winner.
    #[must_use]
    pub fn lww_key(self) -> (OriginId, OriginSeq) {
        (self.origin_id, self.origin_seq)
    }
}

/// Trait for value types that carry a [`FlowOrigin`].
///
/// Required by the state-sync receiver's dedup/buffer machinery to
/// extract origin metadata from incoming entries.  Any value type
/// shipped between dataplanes must implement this.
///
/// The trait is intentionally minimal -- it does not require the
/// implementor to *store* a [`FlowOrigin`] by value, only that one
/// can be produced on demand.  This leaves room for value types
/// that pack the origin metadata into a smaller representation
/// (e.g. bit-stealing in a `u128`) and reconstruct on access.
pub trait HasOrigin {
    /// The flow origin attached to this value.
    fn origin(&self) -> FlowOrigin;
}

impl HasOrigin for FlowOrigin {
    fn origin(&self) -> FlowOrigin {
        *self
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::{FlowOrigin, OriginId, OriginSeq};
    use cascade::Generation;

    #[test]
    fn origin_id_rejects_zero() {
        assert!(OriginId::new(0).is_none());
        assert!(OriginId::new(1).is_some());
    }

    #[test]
    fn origin_seq_advances_monotonically() {
        let s1 = OriginSeq::FIRST;
        let s2 = s1.next().expect("not overflow");
        assert!(s2 > s1);
        assert_eq!(s2.get(), 2);
    }

    #[test]
    fn lww_key_breaks_ties_by_origin_then_seq() {
        let dp1 = OriginId::new(1).expect("nonzero");
        let dp2 = OriginId::new(2).expect("nonzero");
        let seq_a = OriginSeq::new(10).expect("nonzero");
        let seq_b = OriginSeq::new(20).expect("nonzero");
        let policy_gen = Generation::FIRST;

        let a = FlowOrigin {
            origin_id: dp1,
            origin_seq: seq_b,
            policy_gen_at_create: policy_gen,
        };
        let b = FlowOrigin {
            origin_id: dp2,
            origin_seq: seq_a,
            policy_gen_at_create: policy_gen,
        };

        // dp1 < dp2 so a's key is smaller regardless of seq.
        assert!(a.lww_key() < b.lww_key());
    }
}
