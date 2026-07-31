// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::{FieldKind, FixedSize, MaskBits};
pub trait RuleField {
    const KIND: FieldKind;
    type Value: FixedSize;
}
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ExactSpec<T: FixedSize> {
    pub value: T,
}

impl<T: FixedSize> From<T> for ExactSpec<T> {
    fn from(value: T) -> Self {
        ExactSpec { value }
    }
}

impl<T: FixedSize> ExactSpec<T> {
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self { value }
    }
}

impl<T: FixedSize> RuleField for ExactSpec<T> {
    const KIND: FieldKind = FieldKind::Exact;
    type Value = T;
}
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct PrefixSpec<T: FixedSize> {
    pub value: T,
    pub len: u8,
}

impl<T: FixedSize> PrefixSpec<T> {
    #[must_use]
    pub fn new(value: T, len: u8) -> Self {
        let bits = T::SIZE
            .checked_mul(8)
            .and_then(|b| u8::try_from(b).ok())
            .unwrap_or(u8::MAX);
        assert!(
            len <= bits,
            "prefix length {len} exceeds field width of {bits} bits",
        );
        Self { value, len }
    }
}

impl<T: FixedSize> RuleField for PrefixSpec<T> {
    const KIND: FieldKind = FieldKind::Prefix;
    type Value = T;
}
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct MaskSpec<T: FixedSize> {
    pub value: T,
    pub mask: T,
}

impl<T: FixedSize> From<(T, T)> for MaskSpec<T> {
    fn from(value: (T, T)) -> Self {
        Self {
            value: value.0,
            mask: value.1,
        }
    }
}

impl<T: FixedSize> From<(&T, &T)> for MaskSpec<T> {
    fn from(value: (&T, &T)) -> Self {
        Self {
            value: *value.0,
            mask: *value.1,
        }
    }
}

impl<T: FixedSize> MaskSpec<T> {
    #[must_use]
    pub const fn new(value: T, mask: T) -> Self {
        Self { value, mask }
    }
}

impl<T: MaskBits> MaskSpec<T> {
    /// Match `value` and nothing else: every bit significant.
    ///
    /// Prefer this to `new(value, all_ones)`, which requires the caller to spell an all-ones bit
    /// pattern as a `T` -- and for a domain newtype there is often no honest way to do that
    /// (`NextHeader::new(0xff)` is not a protocol).
    #[must_use]
    pub const fn exact(value: T) -> Self {
        Self {
            value,
            mask: T::ALL_BITS,
        }
    }

    /// Match anything: no bit significant. Renders as `*` and lets one key field express "any"
    /// without fanning rules across per-value tables.
    #[must_use]
    pub const fn wildcard() -> Self {
        Self {
            value: T::NO_BITS,
            mask: T::NO_BITS,
        }
    }
}

impl<T: FixedSize> RuleField for MaskSpec<T> {
    const KIND: FieldKind = FieldKind::Mask;
    type Value = T;
}
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct RangeSpec<T: FixedSize> {
    pub min: T,
    pub max: T,
}

impl<T: FixedSize> RangeSpec<T> {
    #[must_use]
    pub const fn new(min: T, max: T) -> Self {
        Self { min, max }
    }
    #[must_use]
    pub const fn exact(value: T) -> Self {
        Self {
            min: value,
            max: value,
        }
    }
}

impl<T: FixedSize> RuleField for RangeSpec<T> {
    const KIND: FieldKind = FieldKind::Range;
    type Value = T;
}
impl<T: FixedSize> From<core::ops::RangeInclusive<T>> for RangeSpec<T> {
    fn from(range: core::ops::RangeInclusive<T>) -> Self {
        let (min, max) = range.into_inner();
        Self { min, max }
    }
}
pub trait Backend {
    type Field;
}
pub trait IntoBackendField<B: Backend> {
    fn into_backend_field(self) -> B::Field;
}
pub trait Accepts<T> {
    fn accepts(&self, value: &T) -> bool;
}
pub trait IsUniversal {
    fn is_universal(&self) -> bool;
}

impl<T: FixedSize> IsUniversal for ExactSpec<T> {
    fn is_universal(&self) -> bool {
        false
    }
}

impl<T: FixedSize> IsUniversal for PrefixSpec<T> {
    fn is_universal(&self) -> bool {
        self.len == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{Ipv4Addr, Ipv6Addr};

    /// The constructors are defined by what they match, not by the bit patterns they happen to
    /// store: `exact` accepts its value and nothing else, `wildcard` accepts everything. Checked
    /// exhaustively over `u8` so "nothing else" is a claim about all 256 inputs, not a sample.
    #[test]
    fn exact_and_wildcard_match_what_they_claim() {
        let exact = MaskSpec::exact(6u8);
        let wildcard = MaskSpec::<u8>::wildcard();
        for probe in 0..=u8::MAX {
            assert_eq!(exact.accepts(&probe), probe == 6, "probe {probe}");
            assert!(wildcard.accepts(&probe), "probe {probe}");
        }
        assert!(wildcard.is_universal());
        assert!(!exact.is_universal());
    }

    #[test]
    fn prefix_spec_accepts_max_v4_length() {
        let _ = PrefixSpec::new(Ipv4Addr::UNSPECIFIED, 32);
    }

    #[test]
    #[should_panic(expected = "prefix length 33 exceeds field width of 32 bits")]
    fn prefix_spec_rejects_v4_over_32() {
        let _ = PrefixSpec::new(Ipv4Addr::UNSPECIFIED, 33);
    }

    #[test]
    fn prefix_spec_accepts_max_v6_length() {
        let _ = PrefixSpec::new(Ipv6Addr::UNSPECIFIED, 128);
    }

    #[test]
    #[should_panic(expected = "prefix length 129 exceeds field width of 128 bits")]
    fn prefix_spec_rejects_v6_over_128() {
        let _ = PrefixSpec::new(Ipv6Addr::UNSPECIFIED, 129);
    }
}
