// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Default IP and port allocator for stateful NAT

use super::NatVpcId;
use super::allocator::{AllocationResult, AllocatorError};
use super::port::NatPort;
use super::{NatAllocator, NatIp, NatTuple};
pub use crate::stateful::ippalloc::natipwithbitmap::NatIpWithBitmap;
use net::ip::NextHeader;
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

mod alloc;
mod natipwithbitmap;
mod port_alloc;
mod setup;
mod test_alloc;

///////////////////////////////////////////////////////////////////////////////
// PoolTableKey
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PoolTableKey<I: NatIp> {
    protocol: NextHeader,
    src_id: NatVpcId,
    dst_id: NatVpcId,
    dst: I,
    dst_range_end: I,
}

impl<I: NatIp> PoolTableKey<I> {
    pub fn new(
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
pub struct PoolTable<I: NatIpWithBitmap, J: NatIpWithBitmap>(
    BTreeMap<PoolTableKey<I>, alloc::IpAllocator<J>>,
);

impl<I: NatIpWithBitmap, J: NatIpWithBitmap> PoolTable<I, J> {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub(crate) fn get_mut(&mut self, key: &PoolTableKey<I>) -> Option<&mut alloc::IpAllocator<J>> {
        // We need to find the entry with the ID, and the prefix for the corresponding address.
        // Get the range of "lower" entries, the one with the address before ours is the prefix we
        // need, if the ID also matches.
        match self.0.range_mut(..=key).next_back() {
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

    pub fn add_entry(&mut self, key: PoolTableKey<I>, allocator: alloc::IpAllocator<J>) {
        self.0.insert(key, allocator);
    }
}

///////////////////////////////////////////////////////////////////////////////
// NatDefaultAllocator
///////////////////////////////////////////////////////////////////////////////

pub type AllocatedIpPort<I> = port_alloc::AllocatedPort<I>;
type AllocationMapping<I> = (Option<AllocatedIpPort<I>>, Option<AllocatedIpPort<I>>);

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
        &mut self,
        tuple: &NatTuple<Ipv4Addr>,
    ) -> Result<AllocationResult<AllocatedIpPort<Ipv4Addr>>, AllocatorError> {
        Self::check_proto(tuple.next_header)?;

        let pool_src_opt = self.pools_src44.get_mut(&PoolTableKey::new(
            tuple.next_header,
            tuple.src_vpc_id,
            tuple.dst_vpc_id,
            tuple.src_ip,
            Ipv4Addr::new(255, 255, 255, 255),
        ));
        let pool_dst_opt = self.pools_dst44.get_mut(&PoolTableKey::new(
            tuple.next_header,
            tuple.src_vpc_id,
            tuple.dst_vpc_id,
            tuple.dst_ip,
            Ipv4Addr::new(255, 255, 255, 255),
        ));

        let (src_mapping, dst_mapping) = Self::get_mapping(pool_src_opt, pool_dst_opt)?;

        let reverse_pool_src_opt = if let Some(mapping) = &dst_mapping {
            self.pools_src44.get_mut(&PoolTableKey::new(
                tuple.next_header,
                tuple.dst_vpc_id,
                tuple.src_vpc_id,
                mapping.ip(),
                Ipv4Addr::new(255, 255, 255, 255),
            ))
        } else {
            None
        };

        let reverse_pool_dst_opt = if let Some(mapping) = &src_mapping {
            self.pools_dst44.get_mut(&PoolTableKey::new(
                tuple.next_header,
                tuple.dst_vpc_id,
                tuple.src_vpc_id,
                mapping.ip(),
                Ipv4Addr::new(255, 255, 255, 255),
            ))
        } else {
            None
        };

        let (reverse_src_mapping, reverse_dst_mapping) =
            Self::get_reverse_mapping(tuple, reverse_pool_src_opt, reverse_pool_dst_opt)?;

        Ok(AllocationResult {
            src: src_mapping,
            dst: dst_mapping,
            return_src: reverse_src_mapping,
            return_dst: reverse_dst_mapping,
        })
    }

    fn allocate_v6(
        &mut self,
        tuple: &NatTuple<Ipv6Addr>,
    ) -> Result<AllocationResult<AllocatedIpPort<Ipv6Addr>>, AllocatorError> {
        Self::check_proto(tuple.next_header)?;

        let pool_src_opt = self.pools_src66.get_mut(&PoolTableKey::new(
            tuple.next_header,
            tuple.src_vpc_id,
            tuple.dst_vpc_id,
            tuple.dst_ip,
            Ipv6Addr::new(255, 255, 255, 255, 255, 255, 255, 255),
        ));
        let pool_dst_opt = self.pools_dst66.get_mut(&PoolTableKey::new(
            tuple.next_header,
            tuple.src_vpc_id,
            tuple.dst_vpc_id,
            tuple.dst_ip,
            Ipv6Addr::new(255, 255, 255, 255, 255, 255, 255, 255),
        ));

        let (src_mapping, dst_mapping) = Self::get_mapping(pool_src_opt, pool_dst_opt)?;

        let reverse_pool_src_opt = self.pools_src66.get_mut(&PoolTableKey::new(
            tuple.next_header,
            tuple.src_vpc_id,
            tuple.dst_vpc_id,
            tuple.src_ip,
            Ipv6Addr::new(255, 255, 255, 255, 255, 255, 255, 255),
        ));
        let reverse_pool_dst_opt = self.pools_dst66.get_mut(&PoolTableKey::new(
            tuple.next_header,
            tuple.src_vpc_id,
            tuple.dst_vpc_id,
            tuple.src_ip,
            Ipv6Addr::new(255, 255, 255, 255, 255, 255, 255, 255),
        ));

        let (reverse_src_mapping, reverse_dst_mapping) =
            Self::get_reverse_mapping(tuple, reverse_pool_src_opt, reverse_pool_dst_opt)?;

        Ok(AllocationResult {
            src: src_mapping,
            dst: dst_mapping,
            return_src: reverse_src_mapping,
            return_dst: reverse_dst_mapping,
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
        pool_src_opt: Option<&mut alloc::IpAllocator<I>>,
        pool_dst_opt: Option<&mut alloc::IpAllocator<I>>,
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
        tuple: &NatTuple<I>,
        reverse_pool_src_opt: Option<&mut alloc::IpAllocator<I>>,
        reverse_pool_dst_opt: Option<&mut alloc::IpAllocator<I>>,
    ) -> Result<AllocationMapping<I>, AllocatorError> {
        let reverse_src_mapping = match reverse_pool_src_opt {
            Some(pool_src) => Some(pool_src.reserve(
                tuple.dst_ip,
                match tuple.dst_port {
                    Some(port) => NatPort::new_checked(port).map_err(|_| {
                        AllocatorError::InternalIssue("Invalid destination port number".to_string())
                    })?,
                    None => return Err(AllocatorError::PortNotFound),
                },
            )?),
            None => None,
        };

        let reverse_dst_mapping = match reverse_pool_dst_opt {
            Some(pool_dst) => Some(pool_dst.reserve(
                tuple.src_ip,
                match tuple.src_port {
                    Some(port) => NatPort::new_checked(port).map_err(|_| {
                        AllocatorError::InternalIssue("Invalid source port number".to_string())
                    })?,
                    None => return Err(AllocatorError::PortNotFound),
                },
            )?),
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

    // Ensure that keys are sorted first by VRF ID, and then by IP address. This is essential to
    // make sure we can lookup for entries associated with prefixes for a given ID in the pool
    // tables.
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
