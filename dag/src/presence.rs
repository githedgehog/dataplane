// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The runtime presence word: one bit per metadata kind.

use std::fmt;

/// Which metadata kinds a packet carries: one bit per [kind](crate::kind).
///
/// A `repr(transparent)` wrapper so that the set operations read as such, and so that each state
/// can compute its proven masks as associated consts.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Presence(u16);

impl Presence {
    /// No kind.
    pub const EMPTY: Presence = Presence(0);

    /// Every kind.
    pub const ALL: Presence = Presence(u16::MAX);

    /// The kind at `index` (its position in the closed list).
    #[must_use]
    pub const fn bit(index: u8) -> Presence {
        Presence(1 << index)
    }

    /// The raw bits.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Whether every kind in `other` is in `self`.
    #[must_use]
    pub const fn contains(self, other: Presence) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether no kind is in both.
    #[must_use]
    pub const fn disjoint(self, other: Presence) -> bool {
        self.0 & other.0 == 0
    }

    /// The kinds in either.
    #[must_use]
    pub const fn with(self, other: Presence) -> Presence {
        Presence(self.0 | other.0)
    }

    /// The kinds in `self` but not in `other`.
    #[must_use]
    pub const fn without(self, other: Presence) -> Presence {
        Presence(self.0 & !other.0)
    }

    /// `other` if `cond`, else nothing: for building masks in const context.
    #[must_use]
    pub const fn when(cond: bool, other: Presence) -> Presence {
        if cond { other } else { Presence::EMPTY }
    }
}

impl fmt::Debug for Presence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Presence({:#06b})", self.0)
    }
}
