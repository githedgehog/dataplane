// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use core::net::{Ipv4Addr, Ipv6Addr};

use bolero::{Driver, ValueGenerator, generator::constant};

use crate::IsUniversal;
use crate::rule::{ExactSpec, MaskSpec, PrefixSpec, RangeSpec};
pub struct GuardedMisses<G> {
    inner: G,
    universal: bool,
}

impl<G: ValueGenerator> ValueGenerator for GuardedMisses<G> {
    type Output = G::Output;
    fn generate<D: Driver>(&self, d: &mut D) -> Option<G::Output> {
        if self.universal {
            return None;
        }
        self.inner.generate(d)
    }
}
pub trait FieldHit<T: 'static> {
    fn hits(&self) -> impl ValueGenerator<Output = T>;
}
pub trait FieldMiss<T: 'static> {
    fn misses(&self) -> impl ValueGenerator<Output = T>;
}
macro_rules! high_mask_fn {
    ($name:ident, $i:ty, $bits:expr) => {
        #[inline]
        fn $name(len: u32) -> $i {
            if len == 0 {
                0
            } else if len >= $bits {
                <$i>::MAX
            } else {
                !((1 as $i) << ($bits - len)).wrapping_sub(1)
            }
        }
    };
}
high_mask_fn!(high_mask_u8, u8, 8);
high_mask_fn!(high_mask_u16, u16, 16);
high_mask_fn!(high_mask_u32, u32, 32);
high_mask_fn!(high_mask_u64, u64, 64);
high_mask_fn!(high_mask_u128, u128, 128);
macro_rules! impl_specs_for {
    ($t:ty, $i:ty, $high_mask:ident) => {
        impl FieldHit<$t> for ExactSpec<$t> {
            fn hits(&self) -> impl ValueGenerator<Output = $t> {
                constant(self.value)
            }
        }
        impl FieldMiss<$t> for ExactSpec<$t> {
            fn misses(&self) -> impl ValueGenerator<Output = $t> {
                let target: $i = self.value.into();
                GuardedMisses {
                    inner: bolero::produce::<$i>()
                        .filter_gen(move |x| *x != target)
                        .map_gen(<$t>::from),
                    universal: IsUniversal::is_universal(self),
                }
            }
        }

        impl FieldHit<$t> for PrefixSpec<$t> {
            fn hits(&self) -> impl ValueGenerator<Output = $t> {
                let value: $i = self.value.into();
                let len = u32::from(self.len);
                bolero::produce::<$i>().map_gen(move |rand| {
                    let high = $high_mask(len);
                    <$t>::from((value & high) | (rand & !high))
                })
            }
        }
        impl FieldMiss<$t> for PrefixSpec<$t> {
            fn misses(&self) -> impl ValueGenerator<Output = $t> {
                let value: $i = self.value.into();
                let len = u32::from(self.len);
                GuardedMisses {
                    inner: bolero::produce::<$i>().filter_map_gen(move |rand| {
                        let high = $high_mask(len);
                        ((rand & high) != (value & high)).then(|| <$t>::from(rand))
                    }),
                    universal: IsUniversal::is_universal(self),
                }
            }
        }

        impl FieldHit<$t> for MaskSpec<$t> {
            fn hits(&self) -> impl ValueGenerator<Output = $t> {
                let v: $i = self.value.into();
                let m: $i = self.mask.into();
                bolero::produce::<$i>().map_gen(move |rand| <$t>::from((v & m) | (rand & !m)))
            }
        }
        impl FieldMiss<$t> for MaskSpec<$t> {
            fn misses(&self) -> impl ValueGenerator<Output = $t> {
                let v: $i = self.value.into();
                let m: $i = self.mask.into();
                GuardedMisses {
                    inner: bolero::produce::<$i>().filter_map_gen(move |rand| {
                        ((rand & m) != (v & m)).then(|| <$t>::from(rand))
                    }),
                    universal: IsUniversal::is_universal(self),
                }
            }
        }

        impl FieldHit<$t> for RangeSpec<$t> {
            fn hits(&self) -> impl ValueGenerator<Output = $t> {
                let min: $i = self.min.into();
                let max: $i = self.max.into();
                (min..=max).map_gen(<$t>::from)
            }
        }
        impl FieldMiss<$t> for RangeSpec<$t> {
            fn misses(&self) -> impl ValueGenerator<Output = $t> {
                let lo: $i = self.min.into();
                let hi: $i = self.max.into();
                GuardedMisses {
                    inner: bolero::produce::<$i>().filter_map_gen(move |rand| {
                        (rand < lo || rand > hi).then(|| <$t>::from(rand))
                    }),
                    universal: IsUniversal::is_universal(self),
                }
            }
        }
    };
}

impl_specs_for!(u8, u8, high_mask_u8);
impl_specs_for!(u16, u16, high_mask_u16);
impl_specs_for!(u32, u32, high_mask_u32);
impl_specs_for!(u64, u64, high_mask_u64);
impl_specs_for!(Ipv4Addr, u32, high_mask_u32);
impl_specs_for!(Ipv6Addr, u128, high_mask_u128);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Accepts, IsUniversal};

    #[test]
    fn exact_spec_hits_accepts() {
        let spec = ExactSpec::new(42u16);
        bolero::check!()
            .with_generator(spec.hits())
            .for_each(|v| assert!(spec.accepts(v)));
    }

    #[test]
    fn exact_spec_misses_rejected() {
        let spec = ExactSpec::new(42u16);
        bolero::check!()
            .with_generator(spec.misses())
            .for_each(|v| assert!(!spec.accepts(v)));
    }

    #[test]
    fn prefix_spec_u32_hits() {
        let spec = PrefixSpec::new(0x0A00_0000u32, 8);
        bolero::check!()
            .with_generator(spec.hits())
            .for_each(|v| assert_eq!(*v & 0xFF00_0000, 0x0A00_0000, "got {v:08x}"));
    }

    #[test]
    fn prefix_spec_u32_misses() {
        let spec = PrefixSpec::new(0x0A00_0000u32, 8);
        bolero::check!()
            .with_generator(spec.misses())
            .for_each(|v| assert_ne!(*v & 0xFF00_0000, 0x0A00_0000, "got {v:08x}"));
    }

    #[test]
    fn prefix_spec_zero_len_is_universal() {
        assert!(PrefixSpec::new(0xDEAD_BEEF_u32, 0).is_universal());
    }

    #[test]
    fn mask_spec_u16_hits_match_under_mask() {
        let spec = MaskSpec::new(0xABCDu16, 0xFF00u16);
        bolero::check!()
            .with_generator(spec.hits())
            .for_each(|v| assert_eq!(*v & 0xFF00, 0xAB00, "got {v:04x}"));
    }

    #[test]
    fn mask_spec_u16_misses_disagree_under_mask() {
        let spec = MaskSpec::new(0xABCDu16, 0xFF00u16);
        bolero::check!()
            .with_generator(spec.misses())
            .for_each(|v| assert_ne!(*v & 0xFF00, 0xAB00, "got {v:04x}"));
    }

    #[test]
    fn mask_spec_zero_mask_is_universal() {
        assert!(MaskSpec::new(0xDEADu16, 0u16).is_universal());
    }

    #[test]
    fn range_spec_u16_hits_in_range() {
        let spec = RangeSpec::new(100u16, 200u16);
        bolero::check!()
            .with_generator(spec.hits())
            .for_each(|v| assert!((100..=200).contains(v)));
    }

    #[test]
    fn range_spec_u16_misses_outside_range() {
        let spec = RangeSpec::new(100u16, 200u16);
        bolero::check!()
            .with_generator(spec.misses())
            .for_each(|v| assert!(!(100..=200).contains(v)));
    }

    #[test]
    fn range_spec_full_domain_is_universal() {
        assert!(RangeSpec::new(0u16, u16::MAX).is_universal());
    }

    #[test]
    fn ipv4_prefix_hits() {
        let spec = PrefixSpec::new(Ipv4Addr::new(10, 0, 0, 0), 8);
        bolero::check!()
            .with_generator(spec.hits())
            .for_each(|v| assert_eq!(v.octets()[0], 10, "got {v}"));
    }

    #[test]
    fn ipv4_prefix_misses() {
        let spec = PrefixSpec::new(Ipv4Addr::new(10, 0, 0, 0), 8);
        bolero::check!()
            .with_generator(spec.misses())
            .for_each(|v| assert_ne!(v.octets()[0], 10));
    }

    #[test]
    fn ipv6_prefix_hits_on_high_chunk() {
        let spec = PrefixSpec::new("2001:db8::".parse::<Ipv6Addr>().unwrap(), 32);
        bolero::check!()
            .with_generator(spec.hits())
            .for_each(|v| assert_eq!(&v.octets()[0..4], &[0x20, 0x01, 0x0d, 0xb8], "got {v}"));
    }
}

use crate::FieldPredicate;
use crate::predicate::mask_matches;
use core::ops::Bound;
#[must_use]
pub fn predicate_is_universal(pred: &FieldPredicate) -> bool {
    if let Some((_, len)) = pred.as_prefix() {
        len == 0
    } else if let Some((_, mask)) = pred.as_mask() {
        mask.iter().all(|&b| b == 0)
    } else if let Some((min, max)) = pred.as_range() {
        min.iter().all(|&b| b == 0) && max.iter().all(|&b| b == u8::MAX)
    } else {
        false
    }
}
#[must_use]
pub fn predicate_hits_bytes(pred: FieldPredicate) -> PredicateHitsBytes {
    PredicateHitsBytes { pred }
}
#[must_use]
pub fn predicate_misses_bytes(pred: FieldPredicate) -> PredicateMissesBytes {
    let universal = predicate_is_universal(&pred);
    PredicateMissesBytes { pred, universal }
}

pub struct PredicateHitsBytes {
    pred: FieldPredicate,
}

impl ValueGenerator for PredicateHitsBytes {
    type Output = Vec<u8>;
    fn generate<D: Driver>(&self, d: &mut D) -> Option<Vec<u8>> {
        if let Some(value) = self.pred.as_exact() {
            Some(value.to_vec())
        } else if let Some((value, prefix_len)) = self.pred.as_prefix() {
            let mut buf = draw_bytes(d, value.len())?;
            splat_prefix(&mut buf, value, prefix_len);
            Some(buf)
        } else if let Some((value, mask)) = self.pred.as_mask() {
            let mut buf = draw_bytes(d, value.len())?;
            splat_under_mask(&mut buf, value, mask);
            Some(buf)
        } else if let Some((min, max)) = self.pred.as_range() {
            let lo = be_to_u32(min);
            let hi = be_to_u32(max);
            let v = (lo..=hi).generate(d)?;
            Some(u32_to_be(v, min.len()))
        } else {
            None
        }
    }
}

pub struct PredicateMissesBytes {
    pred: FieldPredicate,
    universal: bool,
}

impl ValueGenerator for PredicateMissesBytes {
    type Output = Vec<u8>;
    fn generate<D: Driver>(&self, d: &mut D) -> Option<Vec<u8>> {
        if self.universal {
            return None;
        }
        if let Some(value) = self.pred.as_exact() {
            let buf = draw_bytes(d, value.len())?;
            (buf.as_slice() != value).then_some(buf)
        } else if let Some((value, prefix_len)) = self.pred.as_prefix() {
            let buf = draw_bytes(d, value.len())?;
            (!prefix_matches(&buf, value, prefix_len)).then_some(buf)
        } else if let Some((value, mask)) = self.pred.as_mask() {
            let buf = draw_bytes(d, value.len())?;
            (!mask_matches(&buf, value, mask)).then_some(buf)
        } else if let Some((min, max)) = self.pred.as_range() {
            let buf = draw_bytes(d, min.len())?;
            (buf.as_slice() < min || buf.as_slice() > max).then_some(buf)
        } else {
            None
        }
    }
}

fn draw_bytes<D: Driver>(d: &mut D, width: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; width];
    for byte in &mut buf {
        *byte = d.gen_u8(Bound::Unbounded, Bound::Unbounded)?;
    }
    Some(buf)
}
fn splat_prefix(buf: &mut [u8], value: &[u8], len: u8) {
    debug_assert_eq!(buf.len(), value.len());
    let full_bytes = usize::from(len / 8);
    let trailing_bits = u32::from(len % 8);
    buf[..full_bytes].copy_from_slice(&value[..full_bytes]);
    if trailing_bits > 0 && full_bytes < buf.len() {
        let mask: u8 = !((1u8 << (8 - trailing_bits)) - 1);
        buf[full_bytes] = (value[full_bytes] & mask) | (buf[full_bytes] & !mask);
    }
}
fn splat_under_mask(buf: &mut [u8], value: &[u8], mask: &[u8]) {
    debug_assert_eq!(buf.len(), value.len());
    debug_assert_eq!(buf.len(), mask.len());
    for ((b, &v), &m) in buf.iter_mut().zip(value).zip(mask) {
        *b = (*b & !m) | (v & m);
    }
}
fn prefix_matches(field: &[u8], value: &[u8], len: u8) -> bool {
    let full_bytes = usize::from(len / 8);
    if field[..full_bytes] != value[..full_bytes] {
        return false;
    }
    let trailing_bits = u32::from(len % 8);
    if trailing_bits == 0 {
        return true;
    }
    let mask: u8 = !((1u8 << (8 - trailing_bits)) - 1);
    (field[full_bytes] & mask) == (value[full_bytes] & mask)
}
fn be_to_u32(bytes: &[u8]) -> u32 {
    assert!(
        bytes.len() <= 4,
        "be_to_u32: width {} exceeds 4 bytes",
        bytes.len(),
    );
    let mut buf = [0u8; 4];
    let off = 4 - bytes.len();
    buf[off..].copy_from_slice(bytes);
    u32::from_be_bytes(buf)
}
fn u32_to_be(value: u32, width: usize) -> Vec<u8> {
    assert!(width <= 4, "u32_to_be: width {width} exceeds 4 bytes");
    let buf = value.to_be_bytes();
    buf[4 - width..].to_vec()
}

#[cfg(test)]
mod byte_tests {
    use super::*;
    use crate::predicate::{Exact, FieldBytes, Mask, Prefix, Range};

    fn fb(bytes: &[u8]) -> FieldBytes {
        bytes.iter().copied().collect()
    }

    #[test]
    fn is_universal_classifies_each_kind() {
        assert!(!predicate_is_universal(&FieldPredicate::Exact(Exact::new(
            fb(&[0])
        ))));
        assert!(predicate_is_universal(&FieldPredicate::Prefix(
            Prefix::new(fb(&[0xAB, 0xCD]), 0)
        )));
        assert!(!predicate_is_universal(&FieldPredicate::Prefix(
            Prefix::new(fb(&[0xAB, 0xCD]), 4)
        )));
        assert!(predicate_is_universal(&FieldPredicate::Mask(Mask::new(
            fb(&[0xAB, 0xCD]),
            fb(&[0, 0])
        ))));
        assert!(!predicate_is_universal(&FieldPredicate::Mask(Mask::new(
            fb(&[0xAB, 0xCD]),
            fb(&[0xFF, 0])
        ))));
        assert!(predicate_is_universal(&FieldPredicate::Range(Range::new(
            fb(&[0, 0]),
            fb(&[0xFF, 0xFF])
        ))));
        assert!(!predicate_is_universal(&FieldPredicate::Range(Range::new(
            fb(&[0, 1]),
            fb(&[0xFF, 0xFF])
        ))));
    }

    #[test]
    fn exact_hits_returns_value_bytes() {
        let pred = FieldPredicate::Exact(Exact::new(fb(&[1, 2, 3, 4])));
        bolero::check!()
            .with_generator(predicate_hits_bytes(pred.clone()))
            .for_each(|v| assert_eq!(v.as_slice(), &[1, 2, 3, 4]));
    }

    #[test]
    fn exact_misses_avoid_value() {
        let pred = FieldPredicate::Exact(Exact::new(fb(&[1, 2])));
        bolero::check!()
            .with_generator(predicate_misses_bytes(pred.clone()))
            .for_each(|v| assert_ne!(v.as_slice(), &[1, 2]));
    }

    #[test]
    fn prefix_hits_preserve_top_bits() {
        let pred = FieldPredicate::Prefix(Prefix::new(fb(&[0xAB, 0xCD]), 12));
        bolero::check!()
            .with_generator(predicate_hits_bytes(pred.clone()))
            .for_each(|v| {
                assert_eq!(v[0], 0xAB);
                assert_eq!(v[1] & 0xF0, 0xC0);
            });
    }

    #[test]
    fn prefix_misses_differ_in_top_bits() {
        let pred = FieldPredicate::Prefix(Prefix::new(fb(&[0xAB, 0xCD]), 12));
        bolero::check!()
            .with_generator(predicate_misses_bytes(pred.clone()))
            .for_each(|v| {
                let top_matches = v[0] == 0xAB && (v[1] & 0xF0) == 0xC0;
                assert!(!top_matches);
            });
    }

    #[test]
    fn mask_hits_match_under_mask() {
        let pred = FieldPredicate::Mask(Mask::new(fb(&[0xAB, 0xCD]), fb(&[0xFF, 0x00])));
        bolero::check!()
            .with_generator(predicate_hits_bytes(pred.clone()))
            .for_each(|v| {
                assert_eq!(v[0], 0xAB);
            });
    }

    #[test]
    fn mask_misses_disagree_under_mask() {
        let pred = FieldPredicate::Mask(Mask::new(fb(&[0xAB, 0xCD]), fb(&[0xFF, 0x00])));
        bolero::check!()
            .with_generator(predicate_misses_bytes(pred.clone()))
            .for_each(|v| {
                assert_ne!(v[0], 0xAB);
            });
    }

    #[test]
    fn range_hits_in_range() {
        let pred = FieldPredicate::Range(Range::new(
            fb(&100u16.to_be_bytes()),
            fb(&200u16.to_be_bytes()),
        ));
        bolero::check!()
            .with_generator(predicate_hits_bytes(pred.clone()))
            .for_each(|v| {
                let x = u16::from_be_bytes([v[0], v[1]]);
                assert!((100..=200).contains(&x));
            });
    }

    #[test]
    fn range_misses_outside_range() {
        let pred = FieldPredicate::Range(Range::new(
            fb(&100u16.to_be_bytes()),
            fb(&200u16.to_be_bytes()),
        ));
        bolero::check!()
            .with_generator(predicate_misses_bytes(pred.clone()))
            .for_each(|v| {
                let x = u16::from_be_bytes([v[0], v[1]]);
                assert!(!(100..=200).contains(&x));
            });
    }
}
