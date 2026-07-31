// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! `Display` for the field specs, so that a rule can be rendered from its *typed* form.
//!
//! Rendering a rule from its erased [`FieldPredicate`](crate::FieldPredicate) bytes forces the
//! renderer to guess what each field means -- by byte width, or worse by field position. Printing
//! the typed spec instead means every field is formatted by the domain type that owns it (a VNI
//! prints as a VNI, an IP protocol as `TCP`), and reordering a key's fields can no longer silently
//! mislabel the output.

use core::fmt::{self, Display, Formatter};

use crate::IsUniversal;
use crate::field::FixedSize;
use crate::predicate::be_bytes;
use crate::rule::{ExactSpec, MaskSpec, PrefixSpec, RangeSpec};

impl<T: FixedSize + Display> Display for ExactSpec<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.value, f)
    }
}

impl<T: FixedSize + Display> Display for PrefixSpec<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.value, self.len)
    }
}

impl<T: FixedSize + Display + PartialEq> Display for RangeSpec<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.is_universal() {
            f.write_str("*")
        } else if self.min == self.max {
            Display::fmt(&self.min, f)
        } else {
            write!(f, "{}..={}", self.min, self.max)
        }
    }
}

/// A mask with every bit significant prints as the bare value (`TCP`); one with no significant bit
/// prints as a wildcard (`*`).
///
/// A *partial* mask prints as `0x<value & mask>/0x<mask>`. Neither operand is a meaningful value of
/// `T` there, so neither is passed through `T`'s `Display`: a `NextHeader` of `TCP` under mask
/// `0xf0` matches every protocol `0x00..=0x0f`, and rendering it `TCP/0xf0` would name one
/// arbitrary member of the matched set as though it were the whole set.
///
/// The value is masked before rendering because that is precisely what both backends match on:
/// `rte_acl` ANDs the value with the mask when it builds the trie (`acl_gen_mask_trie`), and
/// [`Accepts`](crate::Accepts) compares `(field & mask)` against `(value & mask)`. Bits of `value`
/// outside the mask cannot change a lookup, so rendering them would show a distinction the
/// classifier does not make.
impl<T: FixedSize + Display> Display for MaskSpec<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mask = be_bytes(&self.mask);
        if mask.iter().all(|byte| *byte == 0) {
            f.write_str("*")
        } else if mask.iter().all(|byte| *byte == u8::MAX) {
            Display::fmt(&self.value, f)
        } else {
            let value = be_bytes(&self.value);
            f.write_str("0x")?;
            value
                .iter()
                .zip(mask.iter())
                .try_for_each(|(value, mask)| write!(f, "{:02x}", value & mask))?;
            f.write_str("/0x")?;
            mask.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Accepts;
    use core::net::Ipv4Addr;

    #[test]
    fn exact_prints_the_value() {
        assert_eq!(ExactSpec::new(42u16).to_string(), "42");
    }

    #[test]
    fn prefix_prints_value_slash_length() {
        assert_eq!(
            PrefixSpec::new(Ipv4Addr::new(10, 0, 0, 0), 8).to_string(),
            "10.0.0.0/8"
        );
    }

    #[test]
    fn range_collapses_wildcard_and_singleton() {
        assert_eq!(RangeSpec::new(0u16, u16::MAX).to_string(), "*");
        assert_eq!(RangeSpec::exact(443u16).to_string(), "443");
        assert_eq!(RangeSpec::new(80u16, 8080u16).to_string(), "80..=8080");
    }

    #[test]
    fn mask_collapses_full_and_empty() {
        assert_eq!(MaskSpec::new(6u8, 0xffu8).to_string(), "6");
        assert_eq!(MaskSpec::new(0u8, 0x00u8).to_string(), "*");
        assert_eq!(MaskSpec::new(0xabu8, 0xf0u8).to_string(), "0xa0/0xf0");
    }

    /// A partial mask renders both operands as the bit patterns they are, over the field's full
    /// width, with the value's don't-care bits cleared.
    #[test]
    fn partial_mask_renders_as_bit_patterns() {
        assert_eq!(
            MaskSpec::new(0xabcdu16, 0xff00u16).to_string(),
            "0xab00/0xff00"
        );
    }

    /// Bits of `value` outside the mask cannot change a lookup, so two specs differing only in
    /// those bits accept exactly the same inputs -- asserted here rather than assumed -- and must
    /// therefore render identically. Were they to differ, the CLI dump would show an operator a
    /// distinction the classifier does not make.
    #[test]
    fn render_ignores_value_bits_outside_the_mask() {
        bolero::check!()
            .with_type::<(u8, u8)>()
            .for_each(|&(value, mask)| {
                let raw = MaskSpec::new(value, mask);
                let normalized = MaskSpec::new(value & mask, mask);
                for probe in 0..=u8::MAX {
                    assert_eq!(
                        raw.accepts(&probe),
                        normalized.accepts(&probe),
                        "masked-off bits changed what {raw:?} accepts"
                    );
                }
                assert_eq!(raw.to_string(), normalized.to_string());
            });
    }
}
