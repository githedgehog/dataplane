// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::super::NatIp;
use super::super::allocator::AllocatorError;
use crate::stateful::ippalloc::alloc::{map_address, map_offset};
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

pub trait NatIpWithBitmap: NatIp {
    fn try_from_offset(
        offset: u32,
        bitmap_mapping: &BTreeMap<u32, u128>,
    ) -> Result<Self, AllocatorError>;

    fn try_to_offset(
        address: Self,
        bitmap_mapping: &BTreeMap<u128, u32>,
    ) -> Result<u32, AllocatorError>;
}

impl NatIpWithBitmap for Ipv4Addr {
    fn try_from_offset(
        offset: u32,
        _bitmap_mapping: &BTreeMap<u32, u128>,
    ) -> Result<Self, AllocatorError> {
        Ok(Ipv4Addr::from(offset))
    }

    fn try_to_offset(
        address: Self,
        _bitmap_mapping: &BTreeMap<u128, u32>,
    ) -> Result<u32, AllocatorError> {
        Ok(u32::from(address))
    }
}

impl NatIpWithBitmap for Ipv6Addr {
    fn try_from_offset(
        offset: u32,
        bitmap_mapping: &BTreeMap<u32, u128>,
    ) -> Result<Self, AllocatorError> {
        // For IPv6, the offset does not directly convert to an IP address because the bitmap space
        // is lower than the IPv6 addressing space. Instead, we need to map the offset to the
        // corresponding address within our list of prefixes.
        map_offset(offset, bitmap_mapping)
    }

    fn try_to_offset(
        address: Self,
        bitmap_mapping: &BTreeMap<u128, u32>,
    ) -> Result<u32, AllocatorError> {
        // Reverse operation of map_offset()
        map_address(address, bitmap_mapping)
    }
}
