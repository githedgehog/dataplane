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
