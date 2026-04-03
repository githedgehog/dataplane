// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Generic match expression types for ACL fields.
//!
//! These are the building blocks for expressing match criteria on
//! arbitrary fields — both protocol headers and metadata.

/// Match a field against an exact value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExactMatch<T>(pub T);

/// Match a field against a value with a bitmask.
///
/// A bit set in `mask` means "this bit must match `value`."
/// A bit clear in `mask` means "don't care."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MaskedMatch<T> {
    /// The value to match.
    pub value: T,
    /// The bitmask.  Set bits are significant.
    pub mask: T,
}

/// Match a field against an inclusive range `[min, max]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RangeMatch<T> {
    /// Lower bound (inclusive).
    pub min: T,
    /// Upper bound (inclusive).
    pub max: T,
}

impl<T: Copy + Ord> RangeMatch<T> {
    /// Create a range match.
    ///
    /// Returns `None` if `min > max`.
    #[must_use]
    pub fn new(min: T, max: T) -> Option<Self> {
        if min > max {
            return None;
        }
        Some(Self { min, max })
    }

    /// A range matching exactly one value.
    #[must_use]
    pub fn exact(value: T) -> Self {
        Self {
            min: value,
            max: value,
        }
    }
}
