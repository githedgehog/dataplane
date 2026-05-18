// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Wire format for cross-dataplane state replication.
//!
//! The state-sync subscriber (in `dataplane-mat-state-sync`)
//! serialises flavor-B entries into [`StateSyncMessage`]s and ships
//! them over a per-pair FIFO transport.  This module defines the
//! framing -- the entry payload itself is the consumer's value
//! type, which must carry a [`FlowOrigin`](crate::FlowOrigin) in
//! its metadata to make replication semantics work.
//!
//! See `.scratch/mat-pipeline-rfc/` for the design.

use core::num::Wrapping;

/// Per-transport sequence number for ordered delivery and dedup.
///
/// Scoped per `(origin_dp_id, peer_dp_id)` pair.  Wraps as a `u32`
/// using two's-complement arithmetic; the receiver tracks the
/// highest seen value and uses wrap-aware comparison.
///
/// This is purely a transport-level concern -- it does NOT
/// participate in cascade `Generation` ordering or in `FlowOrigin`
/// LWW resolution.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TransportSeq(pub Wrapping<u32>);

impl TransportSeq {
    /// Initial value for a fresh `(origin, peer)` pair.
    pub const ZERO: Self = Self(Wrapping(0));

    /// Advance to the next sequence value, wrapping at `u32::MAX`.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(Wrapping(self.0.0.wrapping_add(1)))
    }

    /// The raw `u32`.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.0
    }
}

/// Framed state-sync message.
///
/// Generic over the consumer's value type `V` (typically a flow
/// entry).  `V` is expected to carry origin metadata internally
/// (see [`FlowOrigin`](crate::FlowOrigin)).
///
/// Concrete on-wire encoding (protobuf, bincode, custom) is the
/// transport implementation's choice and not pinned here.
#[derive(Clone, Debug)]
pub struct StateSyncMessage<V> {
    /// Transport-level sequence for this message.
    pub msg_seq: TransportSeq,
    /// The replicated entry.
    pub entry: V,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::TransportSeq;

    #[test]
    fn transport_seq_advances_and_wraps() {
        let s = TransportSeq::ZERO;
        assert_eq!(s.get(), 0);
        assert_eq!(s.next().get(), 1);

        // Wrap at u32::MAX -> 0.
        let max = TransportSeq(core::num::Wrapping(u32::MAX));
        assert_eq!(max.next().get(), 0);
    }
}
