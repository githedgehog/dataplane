// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! `NatIpWithBitmap` is a trait to augment [`NatIp`] with bitmap operations. Our default,
//! bitmap-based NAT allocator requires this trait to be implementated for the type parameters
//! (`Ipv4Addr` and `Ipv6Addr`) that it works with.

use super::super::NatIp;
use super::super::allocator::{AllocationResult, AllocatorError, NatAllocator};
use super::AllocatedIpPort;
use crate::stateful::apalloc::alloc::{map_address, map_offset};
use concurrency::sync::Arc;
use pkt_meta::flow_table::FlowKey;
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

/// `NatIpWithBitmap` is a trait to augment [`NatIp`] with bitmap operations.
pub trait NatIpWithBitmap: NatIp {
    // Convert a u32 offset into an IP address, if possible.
    fn try_from_offset(
        offset: u32,
        bitmap_mapping: &BTreeMap<u32, u128>,
    ) -> Result<Self, AllocatorError>;

    // Convert an IP address into a u32 offset, if possible.
    fn try_to_offset(
        address: Self,
        bitmap_mapping: &BTreeMap<u128, u32>,
    ) -> Result<u32, AllocatorError>;

    // Allocate a new IP address from the allocator
    fn allocate<A: NatAllocator<AllocatedIpPort<Ipv4Addr>, AllocatedIpPort<Ipv6Addr>>>(
        allocator: Arc<A>,
        flow_key: &FlowKey,
    ) -> Result<AllocationResult<AllocatedIpPort<Self>>, AllocatorError>;
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

    fn allocate<A: NatAllocator<AllocatedIpPort<Ipv4Addr>, AllocatedIpPort<Ipv6Addr>>>(
        allocator: Arc<A>,
        flow_key: &FlowKey,
    ) -> Result<AllocationResult<AllocatedIpPort<Self>>, AllocatorError> {
        allocator.allocate_v4(flow_key)
    }
}

impl NatIpWithBitmap for Ipv6Addr {
    fn try_from_offset(
        offset: u32,
        bitmap_mapping: &BTreeMap<u32, u128>,
    ) -> Result<Self, AllocatorError> {
        // For IPv6, the offset does not directly convert to an IP address because the bitmap space
        // is lower than the IPv6 addressing space. Instead, we need to map the offset to the
        // corresponding address within our list of prefixes. This means we may end up using fewer
        // IPv6 addresses that what the user-specificed prefixes contain, but it's fine because
        // we'll hit memory limitations before we allocate 4 billion addresses anyway.
        map_offset(offset, bitmap_mapping)
    }

    fn try_to_offset(
        address: Self,
        bitmap_mapping: &BTreeMap<u128, u32>,
    ) -> Result<u32, AllocatorError> {
        // Reverse operation of map_offset()
        map_address(address, bitmap_mapping)
    }

    fn allocate<A: NatAllocator<AllocatedIpPort<Ipv4Addr>, AllocatedIpPort<Ipv6Addr>>>(
        allocator: Arc<A>,
        flow_key: &FlowKey,
    ) -> Result<AllocationResult<AllocatedIpPort<Self>>, AllocatorError> {
        allocator.allocate_v6(flow_key)
    }
}
