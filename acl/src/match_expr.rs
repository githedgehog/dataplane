// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Generic match expression types for ACL fields.
//!
//! These are the building blocks for expressing match criteria on
//! arbitrary fields — both protocol headers and metadata.

/// Whether a field participates in a table's match schema.
///
/// `Ignore` means the field is not part of this table — it doesn't
/// occupy a column and doesn't affect the table width.
///
/// `Select(T)` means the field is in the table and constrained to
/// the given value/range/prefix.  A "match anything" wildcard is
/// expressed as `Select` with a match-everything value (e.g.,
/// `Select(Ipv4Prefix::any())` for /0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldMatch<T> {
    /// Field not part of this table's schema.
    Ignore,
    /// Field in the table, constrained to this value.
    Select(T),
}

impl<T> FieldMatch<T> {
    /// Returns `true` if this field is [`Select`](FieldMatch::Select).
    #[must_use]
    pub fn is_select(&self) -> bool {
        matches!(self, Self::Select(_))
    }

    /// Returns `true` if this field is [`Ignore`](FieldMatch::Ignore).
    #[must_use]
    pub fn is_ignore(&self) -> bool {
        matches!(self, Self::Ignore)
    }

    /// Returns the selected value, if any.
    #[must_use]
    pub fn as_select(&self) -> Option<&T> {
        match self {
            Self::Select(v) => Some(v),
            Self::Ignore => None,
        }
    }

    /// Returns `true` if `Ignore`, or if `Select(v)` and `f(v)` is true.
    ///
    /// This is the matching semantic: `Ignore` always matches (the field
    /// is not constrained), `Select(v)` matches if `f(v)` holds.
    #[must_use]
    pub fn matches(&self, f: impl FnOnce(&T) -> bool) -> bool {
        match self {
            Self::Ignore => true,
            Self::Select(v) => f(v),
        }
    }
}

impl<T> Default for FieldMatch<T> {
    /// Default is `Ignore` — fields not mentioned are not in the table.
    fn default() -> Self {
        Self::Ignore
    }
}

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
