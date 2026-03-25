// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Apalloc: Address and port allocator for stateful NAT
//!
//! The allocator is safe to access concurrently between threads.
//!
//! Here is an attempt to visualize the allocator structure:
//!
//! ```text
//! ┌────────────┐
//! │NatAllocator├────────────────────────────┬──────┬──────┐
//! └────────┬───┘                            │      │      │
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
//! [`AllocatedIp`](alloc::AllocatedIp), and then the [`IpAllocator`], to deallocate the IP address
//! when they are dropped.

#![allow(clippy::ip_constant)]
#![allow(rustdoc::private_intra_doc_links)]

use super::NatIp;
use super::allocator::{AllocationResult, AllocatorError};
use crate::NatPort;
use crate::stateful::apalloc::alloc::IpAllocator;
pub use crate::stateful::apalloc::natip_with_bitmap::NatIpWithBitmap;
use net::IcmpProtoKey;
use net::IpProtoKey;
use net::ip::NextHeader;
use net::packet::VpcDiscriminant;
use net::{ExtendedFlowKey, FlowKey};
use std::collections::BTreeMap;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::error;

mod alloc;
mod display;
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
    dst_id: VpcDiscriminant,
    addr: I,
    addr_range_end: I,
}

impl<I: NatIp> PoolTableKey<I> {
    fn new(protocol: NextHeader, dst_id: VpcDiscriminant, addr: I, addr_range_end: I) -> Self {
        Self {
            protocol,
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
        dst_id: VpcDiscriminant,
        addr: I,
    ) -> Option<&alloc::IpAllocator<J>> {
        let key = PoolTableKey::new(protocol, dst_id, addr, max_range::<I>());
        self.get(&key)
    }

    fn add_entry(&mut self, key: PoolTableKey<I>, allocator: alloc::IpAllocator<J>) {
        self.0.insert(key, allocator);
    }
}

///////////////////////////////////////////////////////////////////////////////
// NatAllocator
///////////////////////////////////////////////////////////////////////////////

/// [`AllocatedIpPort`] is the public type for the object returned by our allocator.
pub type AllocatedIpPort<I> = port_alloc::AllocatedPort<I>;

impl<I: NatIpWithBitmap> Display for AllocatedIpPort<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.port() {
            NatPort::Port(port) => write!(f, "{}:{}", self.ip(), port.get()),
            NatPort::Identifier(id) => write!(f, "{}<id:{id}>", self.ip()),
        }
    }
}

/// [`NatAllocator`] is the IP addresses and ports allocator for stateful NAT.
///
/// Internally, it contains various bitmap-based IP pools, and each IP address allocated from these
/// pools contains a port allocator.
#[allow(clippy::struct_field_names)]
#[derive(Debug)]
pub struct NatAllocator {
    pools_src44: PoolTable<Ipv4Addr, Ipv4Addr>,
    pools_src66: PoolTable<Ipv6Addr, Ipv6Addr>,
    #[cfg(test)]
    disable_randomness: bool,
}

impl NatAllocator {
    fn new() -> Self {
        Self {
            pools_src44: PoolTable::new(),
            pools_src66: PoolTable::new(),
            #[cfg(test)]
            disable_randomness: false,
        }
    }

    fn allocate_v4(
        &self,
        eflow_key: &ExtendedFlowKey,
    ) -> Result<AllocationResult<AllocatedIpPort<Ipv4Addr>>, AllocatorError> {
        Self::allocate_from_tables(eflow_key, &self.pools_src44, self.must_disable_randomness())
    }

    fn allocate_v6(
        &self,
        eflow_key: &ExtendedFlowKey,
    ) -> Result<AllocationResult<AllocatedIpPort<Ipv6Addr>>, AllocatorError> {
        Self::allocate_from_tables(eflow_key, &self.pools_src66, self.must_disable_randomness())
    }

    fn allocate_from_tables<I: NatIpWithBitmap>(
        eflow_key: &ExtendedFlowKey,
        pools_src: &PoolTable<I, I>,
        disable_randomness: bool,
    ) -> Result<AllocationResult<AllocatedIpPort<I>>, AllocatorError> {
        // get flow key from extended flow key
        let flow_key = eflow_key.flow_key();
        let next_header = Self::get_next_header(flow_key);
        Self::check_proto(next_header)?;
        let dst_vpc_id = eflow_key
            .dst_vpcd()
            .ok_or(AllocatorError::MissingDiscriminant)?;

        // Get address pools for source
        let pool_src_opt = pools_src.get_entry(
            next_header,
            dst_vpc_id,
            NatIp::try_from_addr(*flow_key.data().src_ip()).map_err(|()| {
                AllocatorError::InternalIssue(
                    "Failed to convert IP address to Ipv4Addr".to_string(),
                )
            })?,
        );

        // If we could not find an address pool for the source address, this means that the user has
        // not exposed and configured NAT for the source address currently in use. In this case, we
        // do not want to create a new session, even if destination NAT for that packet were valid:
        // we need to drop the packet instead.
        if pool_src_opt.is_none() {
            // Given that we mark packets that require NAT, this case should never happen. Log an error.
            error!(
                "No address pool found for source address {}. Did we hit a bug when building the stateful NAT allocator?",
                flow_key.data().src_ip()
            );
            return Err(AllocatorError::Denied);
        }

        // Allocate IP and ports from pools, for source and destination NAT
        let allow_null = matches!(flow_key.data().proto_key_info(), IpProtoKey::Icmp(_));
        let src_mapping = Self::get_mapping(pool_src_opt, allow_null, disable_randomness)?;
        let reverse_dst_mapping = Self::get_reverse_mapping(flow_key)?;

        Ok(AllocationResult {
            src: src_mapping,
            return_dst: reverse_dst_mapping,
            idle_timeout: pool_src_opt.and_then(IpAllocator::idle_timeout),
        })
    }

    #[cfg(test)]
    const fn must_disable_randomness(&self) -> bool {
        self.disable_randomness
    }
    #[cfg(not(test))]
    #[allow(clippy::unused_self)]
    const fn must_disable_randomness(&self) -> bool {
        false
    }

    fn check_proto(next_header: NextHeader) -> Result<(), AllocatorError> {
        match next_header {
            NextHeader::TCP | NextHeader::UDP | NextHeader::ICMP | NextHeader::ICMP6 => Ok(()),
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

    fn get_mapping<I: NatIpWithBitmap>(
        pool_src_opt: Option<&alloc::IpAllocator<I>>,
        allow_null: bool,
        disable_randomness: bool,
    ) -> Result<Option<AllocatedIpPort<I>>, AllocatorError> {
        // Allocate IP and ports for source and destination NAT.
        //
        // In the case of ICMP Query messages, use dst_mapping to hold an allocated identifier
        // instead of ports.
        //
        // FIXME: In the case of ICMP, we're only interested in the IP allocated for src_mapping,
        // not the port. We need to translate a single value (the identifier), and we're using the
        // dst_mapping to hold it. However, both source and destination IP need to come with a
        // "port" with the current architecture of the allocator, which means we also allocate a
        // port/identifier value for the src_mapping, even though we'll never use it. (This does not
        // apply to TCP or UDP, for which we need and use both ports).
        let src_mapping = match pool_src_opt {
            Some(pool_src) => Some(pool_src.allocate(allow_null, disable_randomness)?),
            None => None,
        };

        Ok(src_mapping)
    }

    fn get_reverse_mapping(
        flow_key: &FlowKey,
    ) -> Result<Option<(IpAddr, NatPort)>, AllocatorError> {
        let reverse_target_ip = *flow_key.data().src_ip();
        let reverse_target_port = match flow_key.data().proto_key_info() {
            IpProtoKey::Tcp(tcp) => tcp.src_port.into(),
            IpProtoKey::Udp(udp) => udp.src_port.into(),
            IpProtoKey::Icmp(icmp) => NatPort::Identifier(Self::get_icmp_query_id(icmp)?),
        };
        Ok(Some((reverse_target_ip, reverse_target_port)))
    }

    fn get_icmp_query_id(key: &IcmpProtoKey) -> Result<u16, AllocatorError> {
        match key {
            IcmpProtoKey::QueryMsgData(id) => Ok(*id),
            IcmpProtoKey::ErrorMsgData(_) => Err(AllocatorError::InternalIssue(
                "ICMP Error message should have been processed without allocating new mappings"
                    .to_string(),
            )),
            IcmpProtoKey::Unsupported => Err(AllocatorError::UnsupportedIcmpCategory),
        }
    }

    #[cfg(test)]
    #[must_use]
    pub fn set_disable_randomness(mut self, disable_randomness: bool) -> Self {
        self.disable_randomness = disable_randomness;
        self
    }
}

// This method is for setting a range end field that is not usually relevant for table lookups, for
// example for PoolTable lookups. The only case the resulting field is considered is when all other
// fields from the lookup key match exactly with the fields from a key in a table. To make sure we
// pick the entry in this case, we need to ensure the value is always greater or equal to the one of
// the key from the PoolTable. So we set it to the largest possible value.
fn max_range<I: NatIp>() -> I {
    I::try_from_bits(u128::MAX)
        .or(I::try_from_bits(u32::MAX.into()))
        .unwrap_or_else(|()| unreachable!()) // IPv4/IPv6 can always be built from u32::MAX
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
    fn vpcd2() -> VpcDiscriminant {
        vpcd(2)
    }
    fn vpcd3() -> VpcDiscriminant {
        vpcd(3)
    }

    // Ensure that keys are sorted first by L4 protocol type, then by VPC IDs, and then by IP
    // address. This is essential to make sure we can lookup for entries associated with prefixes
    // for a given ID in the pool tables.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn test_key_order() {
        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        assert!(key1 == key2);

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        assert!(key1 < key2);

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 2),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        assert!(key1 < key2);

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd2(),
            Ipv4Addr::new(2, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd2(),
            Ipv4Addr::new(1, 255, 255, 255),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        assert!(key1 > key2);

        // Mixing protocols

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        let key2 = PoolTableKey::new(
            NextHeader::UDP,
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        assert!(key1 < key2);

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd3(),
            Ipv4Addr::new(2, 2, 2, 2),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        let key2 = PoolTableKey::new(
            NextHeader::UDP,
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        assert!(key1 < key2);
    }
}
