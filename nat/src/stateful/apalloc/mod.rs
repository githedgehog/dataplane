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
//! The [`AllocatedPort`](port_alloc::AllocatedPort) has a back-reference to
//! [`AllocatedPortBlock`](port_alloc::AllocatedPortBlock), to deallocate the ports when the
//! [`AllocatedPort`](port_alloc::AllocatedPort) is dropped;
//! [`AllocatedPortBlock`](port_alloc::AllocatedPortBlock) has a back reference to
//! [`AllocatedIp`](alloc::AllocatedIp), and then the [`IpAllocator`](alloc::IpAllocator), to
//! deallocate the IP address when they are dropped.

#![allow(clippy::ip_constant)]
#![allow(rustdoc::private_intra_doc_links)]

use super::allocator::{AllocationResult, AllocatorError};
use super::{NatAllocator, NatIp};
use crate::port::NatPort;
pub use crate::stateful::apalloc::natip_with_bitmap::NatIpWithBitmap;
use net::ip::NextHeader;
use net::packet::VpcDiscriminant;
use pkt_meta::flow_table::FlowKey;
use pkt_meta::flow_table::IpProtoKey;
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

mod alloc;
mod natip_with_bitmap;
mod port_alloc;
mod setup;
mod test_alloc;

///////////////////////////////////////////////////////////////////////////////
// PoolTableKey
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct PoolTableKey<I: NatIp> {
    protocol: NextHeader,
    src_id: VpcDiscriminant,
    dst_id: VpcDiscriminant,
    addr: I,
    addr_range_end: I,
}

impl<I: NatIp> PoolTableKey<I> {
    fn new(
        protocol: NextHeader,
        src_id: VpcDiscriminant,
        dst_id: VpcDiscriminant,
        addr: I,
        addr_range_end: I,
    ) -> Self {
        Self {
            protocol,
            src_id,
            dst_id,
            addr,
            addr_range_end,
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// PoolTable
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
struct PoolTable<I: NatIpWithBitmap, J: NatIpWithBitmap>(
    BTreeMap<PoolTableKey<I>, alloc::IpAllocator<J>>,
);

impl<I: NatIpWithBitmap, J: NatIpWithBitmap> PoolTable<I, J> {
    fn new() -> Self {
        Self(BTreeMap::new())
    }

    fn get(&self, key: &PoolTableKey<I>) -> Option<&alloc::IpAllocator<J>> {
        // We need to find the entry with the ID, and the prefix for the corresponding address.
        // Get the range of "lower" entries, the one with the address before ours is the prefix we
        // need, if the ID also matches.
        match self.0.range(..=key).next_back() {
            Some((k, v))
                if k.addr_range_end >= key.addr
                    && k.src_id == key.src_id
                    && k.dst_id == key.dst_id
                    && k.protocol == key.protocol =>
            {
                Some(v)
            }
            _ => None,
        }
    }

    fn get_entry(
        &self,
        protocol: NextHeader,
        src_id: VpcDiscriminant,
        dst_id: VpcDiscriminant,
        addr: I,
    ) -> Option<&alloc::IpAllocator<J>> {
        let key = PoolTableKey::new(
            protocol,
            src_id,
            dst_id,
            addr,
            // This field is not usually relevant for the lookup. The only case it's considered is
            // when all other fields match exactly with the fields from a key in the PoolTable. To
            // make sure we pick the entry in this case, we need to ensure the value is always
            // greater or equal to the one of the key from the PoolTable. So we set it to the
            // largest possible value.
            I::try_from_bits(u128::MAX)
                .or(I::try_from_bits(u32::MAX.into()))
                .ok()?, // Cannot fail - IPv6 and IPv4 can always be built from u32::MAX
        );
        self.get(&key)
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
        flow_key: &FlowKey,
    ) -> Result<AllocationResult<AllocatedIpPort<Ipv4Addr>>, AllocatorError> {
        Self::allocate_from_tables(flow_key, &self.pools_src44, &self.pools_dst44)
    }

    fn allocate_v6(
        &self,
        flow_key: &FlowKey,
    ) -> Result<AllocationResult<AllocatedIpPort<Ipv6Addr>>, AllocatorError> {
        Self::allocate_from_tables(flow_key, &self.pools_src66, &self.pools_dst66)
    }
}

impl NatDefaultAllocator {
    fn allocate_from_tables<I: NatIpWithBitmap>(
        flow_key: &FlowKey,
        pools_src: &PoolTable<I, I>,
        pools_dst: &PoolTable<I, I>,
    ) -> Result<AllocationResult<AllocatedIpPort<I>>, AllocatorError> {
        let next_header = Self::get_next_header(flow_key);
        Self::check_proto(next_header)?;
        let (src_vpc_id, dst_vpc_id) = Self::check_and_get_discriminants(flow_key)?;

        // Get address pools for source and destination
        let pool_src_opt = pools_src.get_entry(
            next_header,
            src_vpc_id,
            dst_vpc_id,
            NatIp::try_from_addr(*flow_key.data().src_ip()).map_err(|()| {
                AllocatorError::InternalIssue(
                    "Failed to convert IP address to Ipv4Addr".to_string(),
                )
            })?,
        );
        let pool_dst_opt = pools_dst.get_entry(
            next_header,
            src_vpc_id,
            dst_vpc_id,
            NatIp::try_from_addr(*flow_key.data().dst_ip()).map_err(|()| {
                AllocatorError::InternalIssue(
                    "Failed to convert IP address to Ipv4Addr".to_string(),
                )
            })?,
        );

        // Allocate IP and ports from pools, for source and destination NAT
        let (src_mapping, dst_mapping) = Self::get_mapping(pool_src_opt, pool_dst_opt)?;

        // Now based on the previous allocation, we need to "reserve" IP and ports for the reverse
        // path for the flow. First retrieve the relevant address pools.

        let reverse_pool_src_opt = if let Some(mapping) = &dst_mapping {
            pools_src.get_entry(next_header, dst_vpc_id, src_vpc_id, mapping.ip())
        } else {
            None
        };

        let reverse_pool_dst_opt = if let Some(mapping) = &src_mapping {
            pools_dst.get_entry(next_header, dst_vpc_id, src_vpc_id, mapping.ip())
        } else {
            None
        };

        // Reserve IP and ports for the reverse path for the flow.
        let (reverse_src_mapping, reverse_dst_mapping) =
            Self::get_reverse_mapping(flow_key, reverse_pool_src_opt, reverse_pool_dst_opt)?;

        Ok(AllocationResult {
            src: src_mapping,
            dst: dst_mapping,
            return_src: reverse_src_mapping,
            return_dst: reverse_dst_mapping,
        })
    }

    fn check_proto(next_header: NextHeader) -> Result<(), AllocatorError> {
        match next_header {
            NextHeader::TCP | NextHeader::UDP => Ok(()),
            _ => Err(AllocatorError::UnsupportedProtocol(next_header)),
        }
    }

    fn get_next_header(flow_key: &FlowKey) -> NextHeader {
        match flow_key.data().proto_key_info() {
            IpProtoKey::Tcp(_) => NextHeader::TCP,
            IpProtoKey::Udp(_) => NextHeader::UDP,
            IpProtoKey::Icmp(_) => NextHeader::ICMP,
        }
    }

    fn check_and_get_discriminants(
        flow_key: &FlowKey,
    ) -> Result<(VpcDiscriminant, VpcDiscriminant), AllocatorError> {
        let src_vpc_id = flow_key
            .data()
            .src_vpcd()
            .ok_or(AllocatorError::MissingDiscriminant)?;
        let dst_vpc_id = flow_key
            .data()
            .dst_vpcd()
            .ok_or(AllocatorError::MissingDiscriminant)?;

        // We only support VNIs at the moment
        #[allow(unreachable_patterns)]
        match (src_vpc_id, dst_vpc_id) {
            (VpcDiscriminant::VNI(_), VpcDiscriminant::VNI(_)) => Ok((src_vpc_id, dst_vpc_id)),
            _ => Err(AllocatorError::UnsupportedDiscriminant),
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

    fn get_reverse_mapping<I: NatIpWithBitmap>(
        flow_key: &FlowKey,
        reverse_pool_src_opt: Option<&alloc::IpAllocator<I>>,
        reverse_pool_dst_opt: Option<&alloc::IpAllocator<I>>,
    ) -> Result<AllocationMapping<I>, AllocatorError> {
        let reverse_src_mapping = match reverse_pool_src_opt {
            Some(pool_src) => {
                let reverse_src_port_number = match flow_key.data().proto_key_info() {
                    IpProtoKey::Tcp(tcp) => tcp.dst_port.into(),
                    IpProtoKey::Udp(udp) => udp.dst_port.into(),
                    IpProtoKey::Icmp(_) => return Err(AllocatorError::PortNotFound),
                };
                let reserve_src_port_number = NatPort::new_checked(reverse_src_port_number)
                    .map_err(|_| {
                        AllocatorError::InternalIssue("Invalid source port number".to_string())
                    })?;

                Some(pool_src.reserve(
                    NatIp::try_from_addr(*flow_key.data().dst_ip()).map_err(|()| {
                        AllocatorError::InternalIssue(
                            "Failed to convert IP address to Ipv4Addr".to_string(),
                        )
                    })?,
                    reserve_src_port_number,
                )?)
            }
            None => None,
        };

        let reverse_dst_mapping = match reverse_pool_dst_opt {
            Some(pool_dst) => {
                let reverse_dst_port_number = match flow_key.data().proto_key_info() {
                    IpProtoKey::Tcp(tcp) => tcp.src_port.into(),
                    IpProtoKey::Udp(udp) => udp.src_port.into(),
                    IpProtoKey::Icmp(_) => return Err(AllocatorError::PortNotFound),
                };
                let reserve_dst_port_number = NatPort::new_checked(reverse_dst_port_number)
                    .map_err(|_| {
                        AllocatorError::InternalIssue("Invalid destination port number".to_string())
                    })?;

                Some(pool_dst.reserve(
                    NatIp::try_from_addr(*flow_key.data().src_ip()).map_err(|()| {
                        AllocatorError::InternalIssue(
                            "Failed to convert IP address to Ipv4Addr".to_string(),
                        )
                    })?,
                    reserve_dst_port_number,
                )?)
            }
            None => None,
        };

        Ok((reverse_src_mapping, reverse_dst_mapping))
    }
}

///////////////////////////////////////////////////////////////////////////////
// Tests
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use net::vxlan::Vni;

    fn vpcd(vpc_id: u32) -> VpcDiscriminant {
        VpcDiscriminant::VNI(Vni::new_checked(vpc_id).unwrap())
    }
    fn vpcd1() -> VpcDiscriminant {
        vpcd(1)
    }
    fn vpcd2() -> VpcDiscriminant {
        vpcd(2)
    }
    fn vpcd3() -> VpcDiscriminant {
        vpcd(3)
    }
    fn vpcd4() -> VpcDiscriminant {
        vpcd(4)
    }

    // Ensure that keys are sorted first by L4 protocol type, then by VPC IDs, and then by IP
    // address. This is essential to make sure we can lookup for entries associated with prefixes
    // for a given ID in the pool tables.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn test_key_order() {
        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd1(),
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd1(),
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        assert!(key1 == key2);

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd1(),
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd1(),
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        assert!(key1 < key2);

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd1(),
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd1(),
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 2),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        assert!(key1 < key2);

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd1(),
            vpcd2(),
            Ipv4Addr::new(2, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd1(),
            vpcd2(),
            Ipv4Addr::new(1, 255, 255, 255),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        assert!(key1 > key2);

        // Mixing IDs

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd2(),
            vpcd3(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd1(),
            vpcd3(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        assert!(key1 > key2);

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd1(),
            vpcd3(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd2(),
            vpcd3(),
            Ipv4Addr::new(1, 1, 1, 2),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        assert!(key1 < key2);

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd2(),
            vpcd3(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd1(),
            vpcd3(),
            Ipv4Addr::new(2, 2, 2, 2),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        assert!(key1 > key2);

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd2(),
            vpcd3(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd1(),
            vpcd3(),
            Ipv4Addr::new(255, 255, 255, 255),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        assert!(key1 > key2);

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd2(),
            vpcd3(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd1(),
            vpcd4(),
            Ipv4Addr::new(255, 255, 255, 255),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        assert!(key1 > key2);

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd1(),
            vpcd3(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd1(),
            vpcd4(),
            Ipv4Addr::new(255, 255, 255, 255),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        assert!(key1 < key2);

        // Mixing protocols

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd1(),
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        let key2 = PoolTableKey::new(
            NextHeader::UDP,
            vpcd1(),
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        assert!(key1 < key2);

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd2(),
            vpcd3(),
            Ipv4Addr::new(2, 2, 2, 2),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        let key2 = PoolTableKey::new(
            NextHeader::UDP,
            vpcd1(),
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        assert!(key1 < key2);
    }
}
