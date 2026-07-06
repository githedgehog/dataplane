// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::num::NonZero;
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Generation(NonZero<u64>);

impl Generation {
    pub const FIRST: Self = Self(NonZero::<u64>::MIN);
    #[must_use]
    pub const fn new(raw: u64) -> Option<Self> {
        match NonZero::<u64>::new(raw) {
            Some(n) => Some(Self(n)),
            None => None,
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(nz) => Some(Self(nz)),
            None => None,
        }
    }
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
