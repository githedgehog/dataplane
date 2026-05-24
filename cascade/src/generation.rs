// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Generation tags for cascade rotations.
//!
//! Each rotation of a [`Cascade`](crate::Cascade) is tagged with a
//! [`Generation`] supplied by the caller (typically a pipeline
//! manager).  Generations enable Reitblatt-style per-packet
//! consistency: [`Snapshot::lookup_at`](crate::Snapshot::lookup_at)
//! filters the walk to frozen layers with `entry.generation <=
//! horizon`, so a hardware-classified packet stamped with generation
//! N walks only the rule set that existed when it was stamped.
//!
//! See `.scratch/mat-pipeline-rfc/0001-mat-pipeline.md` for the
//! full design discussion.
//!
//! # Wrap behaviour
//!
//! Internally a [`Generation`] is a `NonZeroU64`.  At any realistic
//! rotation rate the internal counter never wraps in an operational
//! lifetime (decades at thousands of rotations per second).  Wire
//! formats with narrower representations (e.g. NIC ACL stamps
//! limited to 24 bits) are derived via [`Generation::wire_stamp`];
//! the manager is responsible for ensuring no two simultaneously
//! in-flight packets share a stamp.
//!
//! # Allocation
//!
//! The cascade does **not** own a counter.  Allocation, reset, and
//! wrap handling all live at the manager level.  This module defines
//! the type and ergonomic helpers used by both tests and the
//! eventual manager.

use core::num::NonZeroU64;

/// A monotonic tag assigned to a frozen layer by the caller of
/// [`Cascade::rotate`](crate::Cascade::rotate).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Generation(NonZeroU64);

impl Generation {
    /// The smallest valid generation (raw value `1`).
    pub const FIRST: Self = Self(NonZeroU64::MIN);

    /// Construct a [`Generation`] from a raw `u64`.  Returns `None`
    /// for zero (generations are non-zero by construction so
    /// `Option<Generation>` has niche-optimised layout).
    #[must_use]
    pub const fn new(raw: u64) -> Option<Self> {
        match NonZeroU64::new(raw) {
            Some(n) => Some(Self(n)),
            None => None,
        }
    }

    /// The raw `u64` value of this generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// The next generation after `self`, or `None` on `u64::MAX`
    /// overflow (operationally unreachable).
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(nz) => Some(Self(nz)),
            None => None,
        }
    }

    /// Project this generation to a 24-bit wire stamp, suitable for
    /// stuffing into a NIC ACL classification result.  Discards the
    /// high 40 bits; the manager is responsible for arranging that
    /// no two simultaneously in-flight packets collide on this
    /// projection (via reset / wrap discipline).
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        reason = "masked to 24 bits before the cast; truncation is the intent"
    )]
    pub const fn wire_stamp(self) -> u32 {
        (self.0.get() & 0x00FF_FFFF) as u32
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::Generation;

    #[test]
    fn first_is_one() {
        assert_eq!(Generation::FIRST.get(), 1);
    }

    #[test]
    fn new_rejects_zero() {
        assert!(Generation::new(0).is_none());
        assert!(Generation::new(1).is_some());
    }

    #[test]
    fn next_advances_by_one() {
        let g = Generation::FIRST;
        let g2 = g.next().expect("not overflow");
        assert_eq!(g2.get(), 2);
        assert!(g2 > g);
    }

    #[test]
    fn next_at_max_is_none() {
        let g = Generation::new(u64::MAX).expect("nonzero");
        assert!(g.next().is_none());
    }

    #[test]
    fn wire_stamp_truncates_to_24_bits() {
        let g = Generation::new(0x0000_0000_0123_4567).expect("nonzero");
        assert_eq!(g.wire_stamp(), 0x0023_4567);

        let g = Generation::new(0xFFFF_FFFF_FFFF_FFFF).expect("nonzero");
        assert_eq!(g.wire_stamp(), 0x00FF_FFFF);
    }

    #[test]
    fn ordering_matches_raw_values() {
        let g1 = Generation::new(1).expect("nonzero");
        let g2 = Generation::new(2).expect("nonzero");
        let g100 = Generation::new(100).expect("nonzero");
        assert!(g1 < g2);
        assert!(g2 < g100);
    }
}
