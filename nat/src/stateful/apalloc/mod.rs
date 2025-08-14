// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Apalloc: Address and port allocator for stateful NAT
//!
//! The allocator is safe to access concurrently between threads.
//!
//! Here is an attempt to visualize the allocator structure:
//!
//! ```text
//! ┌───────────────────┐
//! │NatDefaultAllocator├─────────────────────┬──────┬──────┐
//! └────────┬──────────┘                     │      │      │
//!          │                                │      │      │
//! ┌────────▼────────┐         ┌─────────────▼──────▼──────▼───┐
//! │PoolTable (src44)│         │PoolTable (src66, dst44, dst66)│
//! └───────┬─────────┘         └───────────────────────────────┘
//!         │
//! ┌───────▼────┐  associates  ┌───────────┐
//! │PoolTableKey┼──────────────►IpAllocator◄────────────────┐
//! └────────────┘              └────┬──────┘                │
//!                                  │                       │
//!                             ┌────▼──┐                    │
//!       ┌─────────────────────┤NatPool├───┐                │
//!       │                     └───────┘   │                │
//!       │                                 │                │
//! ┌─────────────────┐           ┌─────────▼──────────┐     │
//! │<collection>     │           │PoolBitmap          │     │
//! │(weak references)│           │(map free addresses)│     │
//! └─────────────────┘           └────────────────────┘     │
//!       │                                                  │
//! ┌─────▼─────┐                                            │
//! │AllocatedIp│────────────────────────────────────────────┘
//! └─▲─────────┘           back-reference, for deallocation
//!   │       │
//!   │ ┌─────▼───────┐
//!   │ │PortAllocator│
//!   │ └─────┬───────┘
//!  *│       │
//!   │ ┌─────▼───────────────┐           ┌─────────────────────┐
//!   │ │AllocatedPortBlockMap├───────────►AllocatorPortBlock   │
//!   │ │(weak references)    │           │(metadata for blocks)│
//!   │ └─────────────────────┘           └─────────────────────┘
//!   │       │
//! ┌─┴───────▼────────┐              ┌──────────────────────────┐
//! │AllocatedPortBlock├──────────────►Bitmap256                 │
//! └─▲───────┬────────┘              │(map ports within a block)│
//!  *│       │                       └──────────────────────────┘
//! ┌─┴───────▼─────┐
//! │┌─────────────┐│
//! ││AllocatedPort││                           *: back references
//! │└─────────────┘│
//! └───────────────┘
//! Returned object
//! ```
//!
//! The [`AllocatedPort`](port_alloc::AllocatedPort) has a back-reference to [`AllocatedPortBlock`],
//! to deallocate the ports when the [`AllocatedPort`](port_alloc::AllocatedPort) is dropped;
//! [`AllocatedPortBlock`](port_alloc::AllocatedPortBlock) has a back reference to
//! [`AllocatedIp`](alloc::AllocatedIp), and then the [`IpAllocator`](alloc::IpAllocator), to
//! deallocate the IP address when they are dropped.

#![allow(clippy::ip_constant)]

use super::NatVpcId;
use super::allocator::{AllocationResult, AllocatorError};
use super::{NatAllocator, NatIp, NatTuple};
use crate::stateful::apalloc::natip_with_bitmap::NatIpWithBitmap;
use net::ip::NextHeader;
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

mod alloc;
mod natip_with_bitmap;
mod port_alloc;

///////////////////////////////////////////////////////////////////////////////
// PoolTableKey
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct PoolTableKey<I: NatIp> {
    protocol: NextHeader,
    src_id: NatVpcId,
    dst_id: NatVpcId,
    dst: I,
    dst_range_end: I,
}

impl<I: NatIp> PoolTableKey<I> {
    fn new(
        protocol: NextHeader,
        src_id: NatVpcId,
        dst_id: NatVpcId,
        dst: I,
        dst_range_end: I,
    ) -> Self {
        Self {
            protocol,
            src_id,
            dst_id,
            dst,
            dst_range_end,
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// PoolTable
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
struct PoolTable<I: NatIp, J: NatIpWithBitmap>(BTreeMap<PoolTableKey<I>, alloc::IpAllocator<J>>);

impl<I: NatIp, J: NatIpWithBitmap> PoolTable<I, J> {
    fn new() -> Self {
        Self(BTreeMap::new())
    }

    fn get(&self, key: &PoolTableKey<I>) -> Option<&alloc::IpAllocator<J>> {
        // We need to find the entry with the ID, and the prefix for the corresponding address.
        // Get the range of "lower" entries, the one with the address before ours is the prefix we
        // need, if the ID also matches.
        match self.0.range(..=key).next_back() {
            Some((k, v))
                if k.dst_range_end >= key.dst
                    && k.src_id == key.src_id
                    && k.dst_id == key.dst_id
                    && k.protocol == key.protocol =>
            {
                Some(v)
            }
            _ => None,
        }
    }

    fn add_entry(&mut self, key: PoolTableKey<I>, allocator: alloc::IpAllocator<J>) {
        self.0.insert(key, allocator);
    }
}

///////////////////////////////////////////////////////////////////////////////
// NatDefaultAllocator
///////////////////////////////////////////////////////////////////////////////

/// [`AllocatedIpPort`] is the public type for the object returned by our allocator.
pub type AllocatedIpPort<I> = port_alloc::AllocatedPort<I>;
type AllocationMapping<I> = (Option<AllocatedIpPort<I>>, Option<AllocatedIpPort<I>>);

/// [`NatDefaultAllocator`] is our default IP addresses and ports allocator for stateful NAT,
/// implementing the [`NatAllocator`] trait.
///
/// Internally, it contains various bitmap-based IP pools, and each IP address allocated from these
/// pools contains a port allocator.
#[allow(clippy::struct_field_names)]
#[derive(Debug)]
pub struct NatDefaultAllocator {
    pools_src44: PoolTable<Ipv4Addr, Ipv4Addr>,
    pools_dst44: PoolTable<Ipv4Addr, Ipv4Addr>,
    pools_src66: PoolTable<Ipv6Addr, Ipv6Addr>,
    pools_dst66: PoolTable<Ipv6Addr, Ipv6Addr>,
}

impl NatAllocator<AllocatedIpPort<Ipv4Addr>, AllocatedIpPort<Ipv6Addr>> for NatDefaultAllocator {
    fn new() -> Self {
        Self {
            pools_src44: PoolTable::new(),
            pools_dst44: PoolTable::new(),
            pools_src66: PoolTable::new(),
            pools_dst66: PoolTable::new(),
        }
    }

    fn allocate_v4(
        &self,
        tuple: &NatTuple<Ipv4Addr>,
    ) -> Result<AllocationResult<AllocatedIpPort<Ipv4Addr>>, AllocatorError> {
        Self::check_proto(tuple.next_header)?;

        // Get address pools for source and destination
        let pool_src_opt = self.pools_src44.get(&PoolTableKey::new(
            tuple.next_header,
            tuple.src_vpc_id,
            tuple.dst_vpc_id,
            tuple.src_ip,
            // FIXME: This is ugly and will likely go away after reworking lookups from the PoolTable
            Ipv4Addr::new(255, 255, 255, 255),
        ));
        let pool_dst_opt = self.pools_dst44.get(&PoolTableKey::new(
            tuple.next_header,
            tuple.src_vpc_id,
            tuple.dst_vpc_id,
            tuple.dst_ip,
            Ipv4Addr::new(255, 255, 255, 255),
        ));

        // Allocate IP and ports from pools, for source and destination NAT
        let (src_mapping, dst_mapping) = Self::get_mapping(pool_src_opt, pool_dst_opt)?;

        Ok(AllocationResult {
            src: src_mapping,
            dst: dst_mapping,
        })
    }

    // See allocate_v4 for comments.
    fn allocate_v6(
        &self,
        tuple: &NatTuple<Ipv6Addr>,
    ) -> Result<AllocationResult<AllocatedIpPort<Ipv6Addr>>, AllocatorError> {
        Self::check_proto(tuple.next_header)?;

        let pool_src_opt = self.pools_src66.get(&PoolTableKey::new(
            tuple.next_header,
            tuple.src_vpc_id,
            tuple.dst_vpc_id,
            tuple.dst_ip,
            Ipv6Addr::new(255, 255, 255, 255, 255, 255, 255, 255),
        ));
        let pool_dst_opt = self.pools_dst66.get(&PoolTableKey::new(
            tuple.next_header,
            tuple.src_vpc_id,
            tuple.dst_vpc_id,
            tuple.dst_ip,
            Ipv6Addr::new(255, 255, 255, 255, 255, 255, 255, 255),
        ));

        let (src_mapping, dst_mapping) = Self::get_mapping(pool_src_opt, pool_dst_opt)?;

        Ok(AllocationResult {
            src: src_mapping,
            dst: dst_mapping,
        })
    }
}

impl NatDefaultAllocator {
    fn check_proto(next_header: NextHeader) -> Result<(), AllocatorError> {
        match next_header {
            NextHeader::TCP | NextHeader::UDP => Ok(()),
            _ => Err(AllocatorError::UnsupportedProtocol(next_header)),
        }
    }

    fn get_mapping<I: NatIpWithBitmap>(
        pool_src_opt: Option<&alloc::IpAllocator<I>>,
        pool_dst_opt: Option<&alloc::IpAllocator<I>>,
    ) -> Result<AllocationMapping<I>, AllocatorError> {
        let src_mapping = match pool_src_opt {
            Some(pool_src) => Some(pool_src.allocate()?),
            None => None,
        };

        let dst_mapping = match pool_dst_opt {
            Some(pool_dst) => Some(pool_dst.allocate()?),
            None => None,
        };

        Ok((src_mapping, dst_mapping))
    }
}

///////////////////////////////////////////////////////////////////////////////
// Tests
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use net::vxlan::Vni;

    // Ensure that keys are sorted first by L4 protocol type, then by VPC IDs, and then by IP
    // address. This is essential to make sure we can lookup for entries associated with prefixes
    // for a given ID in the pool tables.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn test_key_order() {
        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            Vni::new_checked(1).unwrap(),
            Vni::new_checked(2).unwrap(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            Vni::new_checked(1).unwrap(),
            Vni::new_checked(2).unwrap(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        assert!(key1 == key2);

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            Vni::new_checked(1).unwrap(),
            Vni::new_checked(2).unwrap(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            Vni::new_checked(1).unwrap(),
            Vni::new_checked(2).unwrap(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        assert!(key1 < key2);

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            Vni::new_checked(1).unwrap(),
            Vni::new_checked(2).unwrap(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            Vni::new_checked(1).unwrap(),
            Vni::new_checked(2).unwrap(),
            Ipv4Addr::new(1, 1, 1, 2),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        assert!(key1 < key2);

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            Vni::new_checked(1).unwrap(),
            Vni::new_checked(2).unwrap(),
            Ipv4Addr::new(2, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            Vni::new_checked(1).unwrap(),
            Vni::new_checked(2).unwrap(),
            Ipv4Addr::new(1, 255, 255, 255),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        assert!(key1 > key2);

        // Mixing IDs

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            Vni::new_checked(2).unwrap(),
            Vni::new_checked(3).unwrap(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            Vni::new_checked(1).unwrap(),
            Vni::new_checked(3).unwrap(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        assert!(key1 > key2);

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            Vni::new_checked(1).unwrap(),
            Vni::new_checked(3).unwrap(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            Vni::new_checked(2).unwrap(),
            Vni::new_checked(3).unwrap(),
            Ipv4Addr::new(1, 1, 1, 2),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        assert!(key1 < key2);

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            Vni::new_checked(2).unwrap(),
            Vni::new_checked(3).unwrap(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            Vni::new_checked(1).unwrap(),
            Vni::new_checked(3).unwrap(),
            Ipv4Addr::new(2, 2, 2, 2),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        assert!(key1 > key2);

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            Vni::new_checked(2).unwrap(),
            Vni::new_checked(3).unwrap(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            Vni::new_checked(1).unwrap(),
            Vni::new_checked(3).unwrap(),
            Ipv4Addr::new(255, 255, 255, 255),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        assert!(key1 > key2);

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            Vni::new_checked(2).unwrap(),
            Vni::new_checked(3).unwrap(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            Vni::new_checked(1).unwrap(),
            Vni::new_checked(4).unwrap(),
            Ipv4Addr::new(255, 255, 255, 255),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        assert!(key1 > key2);

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            Vni::new_checked(1).unwrap(),
            Vni::new_checked(3).unwrap(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            Vni::new_checked(1).unwrap(),
            Vni::new_checked(4).unwrap(),
            Ipv4Addr::new(255, 255, 255, 255),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        assert!(key1 < key2);

        // Mixing protocols

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            Vni::new_checked(1).unwrap(),
            Vni::new_checked(2).unwrap(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        let key2 = PoolTableKey::new(
            NextHeader::UDP,
            Vni::new_checked(1).unwrap(),
            Vni::new_checked(2).unwrap(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        assert!(key1 < key2);

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            Vni::new_checked(2).unwrap(),
            Vni::new_checked(3).unwrap(),
            Ipv4Addr::new(2, 2, 2, 2),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        let key2 = PoolTableKey::new(
            NextHeader::UDP,
            Vni::new_checked(1).unwrap(),
            Vni::new_checked(2).unwrap(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        assert!(key1 < key2);
    }
}
