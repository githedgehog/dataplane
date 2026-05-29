// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use arrayvec::ArrayVec;

use crate::field::FixedSize;
use crate::rule::{
    Accepts, Backend, ExactSpec, IntoBackendField, IsUniversal, MaskSpec, PrefixSpec, RangeSpec,
};
pub const MAX_FIELD_BYTES: usize = 16;
pub type FieldBytes = ArrayVec<u8, MAX_FIELD_BYTES>;
#[derive(Copy, Clone, Debug, Default)]
pub struct Erased;

impl Backend for Erased {
    type Field = FieldPredicate;
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exact {
    value: FieldBytes,
}

impl Exact {
    #[must_use]
    pub fn new(value: FieldBytes) -> Self {
        Self { value }
    }

    fn matches(&self, field: &[u8]) -> bool {
        assert_eq!(field.len(), self.value.len(), "field width mismatch");
        field == self.value.as_slice()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prefix {
    value: FieldBytes,
    len: u8,
}

impl Prefix {
    #[must_use]
    pub fn new(value: FieldBytes, len: u8) -> Self {
        assert!(
            usize::from(len) <= value.len() * 8,
            "prefix length {len} exceeds field width of {} bits",
            value.len() * 8,
        );
        Self { value, len }
    }
    fn matches(&self, field: &[u8]) -> bool {
        assert_eq!(field.len(), self.value.len(), "field width mismatch");
        mask_matches(field, &self.value, &prefix_mask(field.len(), self.len))
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mask {
    value: FieldBytes,
    mask: FieldBytes,
}

impl Mask {
    #[must_use]
    pub fn new(value: FieldBytes, mask: FieldBytes) -> Self {
        assert_eq!(value.len(), mask.len(), "mask width must equal value width");
        Self { value, mask }
    }
    fn matches(&self, field: &[u8]) -> bool {
        assert_eq!(field.len(), self.value.len(), "field width mismatch");
        mask_matches(field, &self.value, &self.mask)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Range {
    min: FieldBytes,
    max: FieldBytes,
}

impl Range {
    #[must_use]
    pub fn new(min: FieldBytes, max: FieldBytes) -> Self {
        assert_eq!(min.len(), max.len(), "range bounds must be equal width");
        Self { min, max }
    }
    fn matches(&self, field: &[u8]) -> bool {
        assert_eq!(field.len(), self.min.len(), "field width mismatch");
        field >= self.min.as_slice() && field <= self.max.as_slice()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldPredicate {
    Exact(Exact),
    Prefix(Prefix),
    Mask(Mask),
    Range(Range),
}

impl From<Exact> for FieldPredicate {
    fn from(p: Exact) -> Self {
        Self::Exact(p)
    }
}

impl From<Prefix> for FieldPredicate {
    fn from(p: Prefix) -> Self {
        Self::Prefix(p)
    }
}

impl From<Mask> for FieldPredicate {
    fn from(p: Mask) -> Self {
        Self::Mask(p)
    }
}

impl From<Range> for FieldPredicate {
    fn from(p: Range) -> Self {
        Self::Range(p)
    }
}

impl FieldPredicate {
    #[must_use]
    pub fn matches(&self, field: &[u8]) -> bool {
        match self {
            FieldPredicate::Exact(p) => p.matches(field),
            FieldPredicate::Prefix(p) => p.matches(field),
            FieldPredicate::Mask(p) => p.matches(field),
            FieldPredicate::Range(p) => p.matches(field),
        }
    }
    #[must_use]
    pub fn width(&self) -> usize {
        match self {
            FieldPredicate::Exact(p) => p.value.len(),
            FieldPredicate::Prefix(p) => p.value.len(),
            FieldPredicate::Mask(p) => p.value.len(),
            FieldPredicate::Range(p) => p.min.len(),
        }
    }

    #[must_use]
    pub fn as_exact(&self) -> Option<&[u8]> {
        match self {
            FieldPredicate::Exact(p) => Some(&p.value),
            _ => None,
        }
    }
    #[must_use]
    pub fn as_prefix(&self) -> Option<(&[u8], u8)> {
        match self {
            FieldPredicate::Prefix(p) => Some((&p.value, p.len)),
            _ => None,
        }
    }
    #[must_use]
    pub fn as_mask(&self) -> Option<(&[u8], &[u8])> {
        match self {
            FieldPredicate::Mask(p) => Some((&p.value, &p.mask)),
            _ => None,
        }
    }
    #[must_use]
    pub fn as_range(&self) -> Option<(&[u8], &[u8])> {
        match self {
            FieldPredicate::Range(p) => Some((&p.min, &p.max)),
            _ => None,
        }
    }
}
fn be_bytes<T: FixedSize>(value: &T) -> FieldBytes {
    let mut buf = [0u8; MAX_FIELD_BYTES];
    value.write_be(&mut buf);
    buf[..T::SIZE].iter().copied().collect()
}

impl<T: FixedSize> IntoBackendField<Erased> for ExactSpec<T> {
    fn into_backend_field(self) -> FieldPredicate {
        FieldPredicate::Exact(Exact::new(be_bytes(&self.value)))
    }
}

impl<T: FixedSize> IntoBackendField<Erased> for PrefixSpec<T> {
    fn into_backend_field(self) -> FieldPredicate {
        FieldPredicate::Prefix(Prefix::new(be_bytes(&self.value), self.len))
    }
}

impl<T: FixedSize> IntoBackendField<Erased> for MaskSpec<T> {
    fn into_backend_field(self) -> FieldPredicate {
        FieldPredicate::Mask(Mask::new(be_bytes(&self.value), be_bytes(&self.mask)))
    }
}

impl<T: FixedSize> IntoBackendField<Erased> for RangeSpec<T> {
    fn into_backend_field(self) -> FieldPredicate {
        FieldPredicate::Range(Range::new(be_bytes(&self.min), be_bytes(&self.max)))
    }
}
impl<T: FixedSize> Accepts<T> for ExactSpec<T> {
    fn accepts(&self, value: &T) -> bool {
        Exact::new(be_bytes(&self.value)).matches(&be_bytes(value))
    }
}

impl<T: FixedSize> Accepts<T> for PrefixSpec<T> {
    fn accepts(&self, value: &T) -> bool {
        Prefix::new(be_bytes(&self.value), self.len).matches(&be_bytes(value))
    }
}

impl<T: FixedSize> Accepts<T> for MaskSpec<T> {
    fn accepts(&self, value: &T) -> bool {
        Mask::new(be_bytes(&self.value), be_bytes(&self.mask)).matches(&be_bytes(value))
    }
}

impl<T: FixedSize> Accepts<T> for RangeSpec<T> {
    fn accepts(&self, value: &T) -> bool {
        Range::new(be_bytes(&self.min), be_bytes(&self.max)).matches(&be_bytes(value))
    }
}
impl<T: FixedSize> IsUniversal for MaskSpec<T> {
    fn is_universal(&self) -> bool {
        be_bytes(&self.mask).iter().all(|b| *b == 0)
    }
}

impl<T: FixedSize> IsUniversal for RangeSpec<T> {
    fn is_universal(&self) -> bool {
        let lo = be_bytes(&self.min);
        let hi = be_bytes(&self.max);
        lo.iter().all(|b| *b == 0) && hi.iter().all(|b| *b == u8::MAX)
    }
}
#[inline]
pub(crate) fn mask_matches(field: &[u8], value: &[u8], mask: &[u8]) -> bool {
    assert_eq!(field.len(), value.len());
    assert_eq!(field.len(), mask.len());
    field
        .iter()
        .zip(value)
        .zip(mask)
        .all(|((f, v), m)| (f & m) == (v & m))
}
#[inline]
fn prefix_mask(nbytes: usize, len: u8) -> FieldBytes {
    assert!(
        nbytes <= MAX_FIELD_BYTES,
        "field width {nbytes} exceeds MAX_FIELD_BYTES {MAX_FIELD_BYTES}",
    );
    assert!(
        usize::from(len) <= nbytes * 8,
        "prefix length {len} exceeds {nbytes}-byte field",
    );
    let mut out = FieldBytes::new();
    let mut remaining = usize::from(len);
    for _ in 0..nbytes {
        let bits = remaining.min(8);
        let byte = if bits == 0 { 0 } else { 0xFFu8 << (8 - bits) };
        out.push(byte);
        remaining -= bits;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::Ipv4Addr;

    fn bytes(slice: &[u8]) -> FieldBytes {
        slice.iter().copied().collect()
    }

    #[test]
    fn exact_matches_only_equal_bytes() {
        let f = ExactSpec::new(6u8).into_backend_field();
        assert!(f.matches(&[6]));
        assert!(!f.matches(&[7]));
    }

    #[test]
    fn prefix_mask_sets_top_bits() {
        assert_eq!(prefix_mask(4, 24).as_slice(), &[0xFF, 0xFF, 0xFF, 0x00]);
        assert_eq!(prefix_mask(4, 20).as_slice(), &[0xFF, 0xFF, 0xF0, 0x00]);
        assert_eq!(prefix_mask(4, 0).as_slice(), &[0x00, 0x00, 0x00, 0x00]);
        assert_eq!(prefix_mask(4, 32).as_slice(), &[0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    #[should_panic(expected = "prefix length")]
    fn prefix_mask_panics_on_over_long_len() {
        let _ = prefix_mask(4, 33);
    }

    #[test]
    #[should_panic(expected = "MAX_FIELD_BYTES")]
    fn prefix_mask_panics_on_oversized_field() {
        let _ = prefix_mask(MAX_FIELD_BYTES + 1, 8);
    }

    #[test]
    fn prefix_matches_on_high_bits_only() {
        let f = PrefixSpec::new(Ipv4Addr::new(10, 0, 0, 0), 8).into_backend_field();
        assert!(f.matches(&Ipv4Addr::new(10, 1, 2, 3).octets()));
        assert!(f.matches(&Ipv4Addr::new(10, 255, 255, 255).octets()));
        assert!(!f.matches(&Ipv4Addr::new(11, 0, 0, 0).octets()));
    }

    #[test]
    fn prefix_len_zero_is_wildcard() {
        let f = PrefixSpec::new(Ipv4Addr::new(10, 0, 0, 0), 0).into_backend_field();
        assert!(f.matches(&Ipv4Addr::new(1, 2, 3, 4).octets()));
        assert!(f.matches(&Ipv4Addr::UNSPECIFIED.octets()));
    }

    #[test]
    #[should_panic(expected = "prefix length")]
    fn over_long_prefix_len_panics() {
        let _ = Prefix::new(bytes(&[10, 0, 0, 1]), 200);
    }

    #[test]
    fn mask_matches_required_bits() {
        let f = MaskSpec::new(0xABu8, 0xF0u8).into_backend_field();
        assert!(f.matches(&[0xA0]));
        assert!(f.matches(&[0xAF]));
        assert!(!f.matches(&[0xB0]));
    }

    #[test]
    fn range_is_inclusive_both_ends() {
        let f = RangeSpec::new(80u16, 8080u16).into_backend_field();
        assert!(f.matches(&80u16.to_be_bytes()));
        assert!(f.matches(&8080u16.to_be_bytes()));
        assert!(f.matches(&443u16.to_be_bytes()));
        assert!(!f.matches(&79u16.to_be_bytes()));
        assert!(!f.matches(&8081u16.to_be_bytes()));
    }

    #[test]
    #[should_panic(expected = "field width")]
    fn exact_field_width_mismatch_panics() {
        let f = FieldPredicate::Exact(Exact::new(bytes(&[1, 2, 3, 4])));
        let _ = f.matches(&[1, 2]);
    }

    #[test]
    #[should_panic(expected = "field width")]
    fn range_field_width_mismatch_panics() {
        let r = FieldPredicate::Range(Range::new(bytes(&[0, 0]), bytes(&[255, 255])));
        let _ = r.matches(&[0, 0, 0]);
    }
}
