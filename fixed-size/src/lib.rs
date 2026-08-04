// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![no_std]
#![deny(
    unsafe_code,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use core::net::{Ipv4Addr, Ipv6Addr};
pub trait FixedSize: Copy {
    const SIZE: usize;
    fn write_be(&self, out: &mut [u8]);
}

/// The two bit patterns a bitmask match field is built from: every bit significant, or none.
///
/// A mask is a bit pattern, not a value of the domain type it constrains, so without these a
/// caller has to mint a fake `Self` to say "match every bit" (`NextHeader::new(0xff)`).
///
/// # Implementing
///
/// Only for types where every bit pattern of the type's width is a valid inhabitant, since both
/// constants must be legal values.
/// That is also the condition for being sound to mask at all, so a type that cannot implement this
/// is one that should never be a masked field (`Vni` is non-zero and 24-bit: it has neither
/// constant).
pub trait MaskBits: FixedSize {
    /// Every bit significant: the field matches only if it equals the value exactly.
    const ALL_BITS: Self;
    /// No bit significant: the field is a wildcard and matches anything.
    const NO_BITS: Self;
}

macro_rules! impl_mask_bits_for_uint {
    ($($ty:ty),* $(,)?) => {$(
        impl MaskBits for $ty {
            const ALL_BITS: Self = <$ty>::MAX;
            const NO_BITS: Self = 0;
        }
    )*};
}

// The unsigned integers are the natural bitmask carriers: every bit pattern is a valid value, and
// `MAX` / `0` are unambiguous. Domain newtypes implement `MaskBits` next to their `FixedSize` impl.
impl_mask_bits_for_uint!(u8, u16, u32, u64, u128);

impl FixedSize for u8 {
    const SIZE: usize = 1;
    fn write_be(&self, out: &mut [u8]) {
        out[0] = *self;
    }
}

impl FixedSize for u16 {
    const SIZE: usize = 2;
    fn write_be(&self, out: &mut [u8]) {
        out[..Self::SIZE].copy_from_slice(&self.to_be_bytes());
    }
}

impl FixedSize for u32 {
    const SIZE: usize = 4;
    fn write_be(&self, out: &mut [u8]) {
        out[..Self::SIZE].copy_from_slice(&self.to_be_bytes());
    }
}

impl FixedSize for u64 {
    const SIZE: usize = 8;
    fn write_be(&self, out: &mut [u8]) {
        out[..Self::SIZE].copy_from_slice(&self.to_be_bytes());
    }
}

impl FixedSize for u128 {
    const SIZE: usize = 16;
    fn write_be(&self, out: &mut [u8]) {
        out[..Self::SIZE].copy_from_slice(&self.to_be_bytes());
    }
}

impl FixedSize for Ipv4Addr {
    const SIZE: usize = 4;
    fn write_be(&self, out: &mut [u8]) {
        out[..Self::SIZE].copy_from_slice(&self.octets());
    }
}

impl FixedSize for Ipv6Addr {
    const SIZE: usize = 16;
    fn write_be(&self, out: &mut [u8]) {
        out[..Self::SIZE].copy_from_slice(&self.octets());
    }
}
