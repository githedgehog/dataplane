// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Generic match expression types for ACL fields.
//!
//! These are the building blocks for expressing match criteria on
//! arbitrary fields, both protocol headers and metadata.

/// Whether a field participates in a table's match schema.
///
/// `Ignore` means the field is not part of this table. It doesn't
/// occupy a column and doesn't affect the table width. An `Ignore`
/// field acts as an implicit wildcard: it matches any packet value.
///
/// `Select(T)` means the field is in the table and constrained to
/// the given value/range/prefix.  A "match anything" wildcard is
/// expressed as `Select` with a match-everything value (e.g.,
/// `Select(Ipv4Prefix::ROOT)` for /0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldMatch<T> {
    /// Field not part of this table's schema (implicit wildcard).
    Ignore,
    /// Field in the table, constrained to this value.
    Select(T),
}

impl<T> FieldMatch<T> {
    /// Returns `true` if this field is [`Select`](FieldMatch::Select).
    #[must_use]
    pub const fn is_select(&self) -> bool {
        matches!(self, Self::Select(_))
    }

    /// Returns `true` if this field is [`Ignore`](FieldMatch::Ignore).
    #[must_use]
    pub const fn is_ignore(&self) -> bool {
        matches!(self, Self::Ignore)
    }

    /// Returns the selected value, if any.
    #[must_use]
    pub const fn as_option(&self) -> Option<&T> {
        match self {
            Self::Select(v) => Some(v),
            Self::Ignore => None,
        }
    }

    /// Returns `true` if `Ignore` (wildcard), or if `Select(v)` and
    /// `predicate(v)` holds.
    ///
    /// This is the core matching semantic: `Ignore` matches any packet
    /// value (the field is unconstrained), while `Select(v)` matches
    /// only if the predicate is satisfied for the constrained value.
    #[must_use]
    pub fn matches(&self, predicate: impl FnOnce(&T) -> bool) -> bool {
        match self {
            Self::Ignore => true,
            Self::Select(v) => predicate(v),
        }
    }
}

impl<T> Default for FieldMatch<T> {
    /// Default is `Ignore`: fields not mentioned are not in the table.
    fn default() -> Self {
        Self::Ignore
    }
}

/// Match a field against an exact value.
///
/// The inner value is private to prevent mutation of values that
/// may be used as hash table keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExactMatch<T>(T);

impl<T> ExactMatch<T> {
    /// Create a new exact match.
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// The value to match against.
    #[must_use]
    pub const fn value(&self) -> &T {
        &self.0
    }
}

/// Match a field against a value with a bitmask.
///
/// A bit set in `mask` means "this bit must match `value`."
/// A bit clear in `mask` means "don't care."
///
/// Fields are private to prevent mutation of values that may be
/// used as hash table keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MaskedMatch<T> {
    value: T,
    mask: T,
}

impl<T> MaskedMatch<T> {
    /// Create a new masked match.
    #[must_use]
    pub const fn new(value: T, mask: T) -> Self {
        Self { value, mask }
    }

    /// The value to match.
    #[must_use]
    pub const fn value(&self) -> &T {
        &self.value
    }

    /// The bitmask. Set bits are significant.
    #[must_use]
    pub const fn mask(&self) -> &T {
        &self.mask
    }
}

