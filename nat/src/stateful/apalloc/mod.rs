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
//! [`AllocatedIp`](alloc::AllocatedIp), and then the [`IpAllocator`](alloc::IpAllocator), to
//! deallocate the IP address when they are dropped.

#![allow(rustdoc::private_intra_doc_links)]

use super::allocation::{AllocationResult, AllocatorError};
use crate::NatPort;
pub use crate::stateful::apalloc::natip_with_bitmap::NatIpWithBitmap;
use crate::stateful::natip::NatIp;
use net::ip::NextHeader;
use net::packet::VpcDiscriminant;
use std::collections::BTreeMap;
use std::fmt::{Debug, Display};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::{debug, error};

mod alloc;
mod display;
mod natip_with_bitmap;
mod port_alloc;
mod setup;
mod test_alloc;

pub use port_alloc::AllocatedPort;

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

/// [`Allocation`] is the non-generic object representing an allocation, be it IPv4 or IPv6
#[derive(Debug)]
pub enum Allocation {
    V4(AllocatedPort<Ipv4Addr>),
    V6(AllocatedPort<Ipv6Addr>),
}

impl Allocation {
    #[must_use]
    pub fn ip(&self) -> IpAddr {
        match self {
            Self::V4(a) => IpAddr::V4(a.ip()),
            Self::V6(a) => IpAddr::V6(a.ip()),
        }
    }

    #[must_use]
    pub fn port(&self) -> NatPort {
        match self {
            Self::V4(a) => a.port(),
            Self::V6(a) => a.port(),
        }
    }
}

impl Display for Allocation {
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
    randomize: bool,
}

impl NatAllocator {
    fn new() -> Self {
        Self {
            pools_src44: PoolTable::new(),
            pools_src66: PoolTable::new(),
            randomize: true,
        }
    }

    fn allocate_v4(
        &self,
        dst_vpcd: VpcDiscriminant,
        src_ip: Ipv4Addr,
        next_header: NextHeader,
    ) -> Result<AllocationResult<AllocatedPort<Ipv4Addr>>, AllocatorError> {
        Self::allocate_from_tables(src_ip.into(), dst_vpcd, next_header, &self.pools_src44)
    }

    fn allocate_v6(
        &self,
        dst_vpcd: VpcDiscriminant,
        src_ip: Ipv6Addr,
        next_header: NextHeader,
    ) -> Result<AllocationResult<AllocatedPort<Ipv6Addr>>, AllocatorError> {
        Self::allocate_from_tables(src_ip.into(), dst_vpcd, next_header, &self.pools_src66)
    }

    /// Allocate an IP address and port for the given source IP, dispatching on IP version.
    pub fn allocate(
        &self,
        dst_vpcd: VpcDiscriminant,
        src_ip: IpAddr,
        next_header: NextHeader,
    ) -> Result<AllocationResult<Allocation>, AllocatorError> {
        match src_ip {
            IpAddr::V4(ip) => {
                self.allocate_v4(dst_vpcd, ip, next_header)
                    .map(|r| AllocationResult {
                        src: Allocation::V4(r.src),
                        idle_timeout: r.idle_timeout,
                    })
            }
            IpAddr::V6(ip) => {
                self.allocate_v6(dst_vpcd, ip, next_header)
                    .map(|r| AllocationResult {
                        src: Allocation::V6(r.src),
                        idle_timeout: r.idle_timeout,
                    })
            }
        }
    }

    /// Re-reserve a specific IP and port in the new allocator during a config change
    /// depending on the ip version of the address
    pub(crate) fn reserve_port(
        &self,
        protocol: NextHeader,
        dst_vpcd: VpcDiscriminant,
        src_ip: IpAddr,
        ip: IpAddr,
        port: NatPort,
    ) -> Result<Allocation, AllocatorError> {
        match (src_ip, ip) {
            (IpAddr::V4(src), IpAddr::V4(allocated)) => self
                .reserve_ipv4_port(protocol, dst_vpcd, src, allocated, port)
                .map(Allocation::V4),
            (IpAddr::V6(src), IpAddr::V6(allocated)) => self
                .reserve_ipv6_port(protocol, dst_vpcd, src, allocated, port)
                .map(Allocation::V6),
            _ => Err(AllocatorError::InternalIssue(format!(
                "IP version mismatch: src={src_ip} allocated={ip}"
            ))),
        }
    }

    fn allocate_from_tables<I: NatIpWithBitmap>(
        src_ip: IpAddr,
        dst_vpcd: VpcDiscriminant,
        next_header: NextHeader,
        pools_src: &PoolTable<I, I>,
    ) -> Result<AllocationResult<AllocatedPort<I>>, AllocatorError> {
        Self::check_proto(next_header)?;

        // If we could not find an address pool for the source address, the user has not exposed
        // and configured NAT for that source address. Drop the packet instead of creating a session.
        let pool = pools_src
            .get_entry(
                next_header,
                dst_vpcd,
                NatIp::try_from_addr(src_ip).map_err(|()| {
                    AllocatorError::InternalIssue("Failed to convert src IP address".to_string())
                })?,
            )
            .ok_or_else(|| {
                // Given that we mark packets that require NAT, this case should never happen.
                error!("No address pool found for src ip {src_ip}. This is a bug");
                AllocatorError::Denied
            })?;

        let allow_null = next_header == NextHeader::ICMP || next_header == NextHeader::ICMP6;
        let src = pool.allocate(allow_null)?;
        let idle_timeout = pool.idle_timeout().unwrap_or_else(|| unreachable!());

        Ok(AllocationResult { src, idle_timeout })
    }

    fn check_proto(next_header: NextHeader) -> Result<(), AllocatorError> {
        match next_header {
            NextHeader::TCP | NextHeader::UDP | NextHeader::ICMP | NextHeader::ICMP6 => Ok(()),
            _ => Err(AllocatorError::UnsupportedProtocol(next_header)),
        }
    }

    fn reserve_ipv4_port(
        &self,
        protocol: NextHeader,
        dst_vpcd: VpcDiscriminant,
        src_ip: Ipv4Addr,
        ip: Ipv4Addr,
        port: NatPort,
    ) -> Result<AllocatedPort<Ipv4Addr>, AllocatorError> {
        let port_u16 = port.as_u16();
        debug!("Re-reserving {ip} port/Id {port_u16} for ({protocol}), dst_vpcd: {dst_vpcd}");
        let pool = self
            .pools_src44
            .get_entry(protocol, dst_vpcd, src_ip)
            .ok_or(AllocatorError::InternalIssue("No ip allocator".to_string()))?;

        debug!("Pool found for {protocol} {dst_vpcd} {src_ip}");
        pool.reserve(ip, port)
            .inspect_err(|e| error!("Failed to reserve ip {ip} port {}: {e}", port.as_u16()))
    }

    fn reserve_ipv6_port(
        &self,
        protocol: NextHeader,
        dst_vpcd: VpcDiscriminant,
        src_ip: Ipv6Addr,
        ip: Ipv6Addr,
        port: NatPort,
    ) -> Result<AllocatedPort<Ipv6Addr>, AllocatorError> {
        let port_u16 = port.as_u16();
        debug!("Re-reserving {ip} port/Id {port_u16} for ({protocol}), dst_vpcd: {dst_vpcd}");
        let pool = self
            .pools_src66
            .get_entry(protocol, dst_vpcd, src_ip)
            .ok_or(AllocatorError::InternalIssue("No ip allocator".to_string()))?;

        debug!("Pool found for {protocol} {dst_vpcd} {src_ip}");
        pool.reserve(ip, port)
            .inspect_err(|e| error!("Failed to reserve ip {ip} port {}: {e}", port.as_u16()))
    }

    #[must_use]
    pub fn set_randomize(mut self, randomize: bool) -> Self {
        self.randomize = randomize;
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
    #![allow(clippy::ip_constant)]

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
