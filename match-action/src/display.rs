// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! `Display` for the field specs, so a rule renders from its *typed* form.
//!
//! Typed specs let each field's domain type control its formatting, keeping values coupled to their
//! key fields.

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

/// A full mask prints the bare value (`TCP`), an empty mask a wildcard (`*`), and a partial mask
/// `value/0x<mask>`.
///
/// The mask is rendered as the bit pattern it is rather than through `T`'s `Display`, which would
/// print a protocol keyword for a bitmask.
impl<T: FixedSize + Display> Display for MaskSpec<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mask = be_bytes(&self.mask);
        if mask.iter().all(|byte| *byte == 0) {
            f.write_str("*")
        } else if mask.iter().all(|byte| *byte == u8::MAX) {
            Display::fmt(&self.value, f)
        } else {
            write!(f, "{}/0x", self.value)?;
            mask.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert_eq!(MaskSpec::new(0xabu8, 0xf0u8).to_string(), "171/0xf0");
    }
}
