// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::NatAllocator;
use super::NatIp;
use super::NatTuple;
use super::allocator::AllocatorError;
use crate::stateful::port::NatPort;
use net::ip::NextHeader;
use routing::rib::vrf::VrfId;
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

mod ip_alloc;
mod port_alloc;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PoolTableKey<I: NatIp> {
    protocol: NextHeader,
    id: VrfId,
    dst: I,
}

impl<I: NatIp> PoolTableKey<I> {
    pub fn new(protocol: NextHeader, id: VrfId, dst: I) -> Self {
        Self { protocol, id, dst }
    }
}

#[derive(Debug)]
pub struct PoolTable<I: NatIp, J: NatIp>(BTreeMap<PoolTableKey<I>, ip_alloc::NatPool<J>>);

impl<I: NatIp, J: NatIp> PoolTable<I, J> {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    fn get_mut(&mut self, key: &PoolTableKey<I>) -> Option<&mut ip_alloc::NatPool<J>> {
        // We need to find the entry with the ID, and the prefix for the corresponding address.
        // Get the range of "lower" entries, the one with the address before ours is the prefix we
        // need, if the ID also matches.
        match self.0.range_mut(..=key).next_back() {
            Some((k, v)) if k.id == key.id && k.protocol == key.protocol => Some(v),
            _ => None,
        }
    }
}

#[allow(clippy::struct_field_names)]
#[derive(Debug)]
pub struct NatDefaultAllocator {
    pools_src44: PoolTable<Ipv4Addr, Ipv4Addr>,
    pools_dst44: PoolTable<Ipv4Addr, Ipv4Addr>,
    pools_src66: PoolTable<Ipv6Addr, Ipv6Addr>,
    pools_dst66: PoolTable<Ipv6Addr, Ipv6Addr>,
}

impl NatAllocator for NatDefaultAllocator {
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
    ) -> Result<(Option<(Ipv4Addr, NatPort)>, Option<(Ipv4Addr, NatPort)>), AllocatorError> {
        Self::check_proto(tuple.next_header)?;

        let pool_src_opt = self.pools_src44.get_mut(&PoolTableKey::new(
            tuple.next_header,
            tuple.vrf_id,
            tuple.dst_ip,
        ));
        let pool_dst_opt = self.pools_dst44.get_mut(&PoolTableKey::new(
            tuple.next_header,
            tuple.vrf_id,
            tuple.dst_ip,
        ));

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

    fn allocate_v6(
        &mut self,
        tuple: &NatTuple<Ipv6Addr>,
    ) -> Result<(Option<(Ipv6Addr, NatPort)>, Option<(Ipv6Addr, NatPort)>), AllocatorError> {
        Self::check_proto(tuple.next_header)?;

        let pool_src_opt = self.pools_src66.get_mut(&PoolTableKey::new(
            tuple.next_header,
            tuple.vrf_id,
            tuple.dst_ip,
        ));
        let pool_dst_opt = self.pools_dst66.get_mut(&PoolTableKey::new(
            tuple.next_header,
            tuple.vrf_id,
            tuple.dst_ip,
        ));

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

impl NatDefaultAllocator {
    pub fn update(
        &mut self,
        pools_src44: PoolTable<Ipv4Addr, Ipv4Addr>,
        pools_dst44: PoolTable<Ipv4Addr, Ipv4Addr>,
        pools_src66: PoolTable<Ipv6Addr, Ipv6Addr>,
        pools_dst66: PoolTable<Ipv6Addr, Ipv6Addr>,
    ) {
        self.pools_src44 = pools_src44;
        self.pools_dst44 = pools_dst44;
        self.pools_src66 = pools_src66;
        self.pools_dst66 = pools_dst66;
    }

    fn check_proto(next_header: NextHeader) -> Result<(), AllocatorError> {
        match next_header {
            NextHeader::TCP | NextHeader::UDP => Ok(()),
            _ => Err(AllocatorError::UnsupportedProtocol(next_header)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ensure that keys are sorted first by VRF ID, and then by IP address. This is essential to
    // make sure we can lookup for entries associated with prefixes for a given ID in the pool
    // tables.
    #[test]
    fn test_key_order() {
        let key1 = PoolTableKey::new(NextHeader::TCP, 1, Ipv4Addr::new(1, 1, 1, 1));
        let key2 = PoolTableKey::new(NextHeader::TCP, 1, Ipv4Addr::new(1, 1, 1, 1));
        assert!(key1 == key2);

        let key1 = PoolTableKey::new(NextHeader::TCP, 1, Ipv4Addr::new(1, 1, 1, 1));
        let key2 = PoolTableKey::new(NextHeader::TCP, 1, Ipv4Addr::new(1, 1, 1, 2));
        assert!(key1 < key2);

        let key1 = PoolTableKey::new(NextHeader::TCP, 1, Ipv4Addr::new(2, 1, 1, 1));
        let key2 = PoolTableKey::new(NextHeader::TCP, 1, Ipv4Addr::new(1, 255, 255, 255));
        assert!(key1 > key2);

        // Mixing IDs

        let key1 = PoolTableKey::new(NextHeader::TCP, 2, Ipv4Addr::new(1, 1, 1, 1));
        let key2 = PoolTableKey::new(NextHeader::TCP, 1, Ipv4Addr::new(1, 1, 1, 1));
        assert!(key1 > key2);

        let key1 = PoolTableKey::new(NextHeader::TCP, 1, Ipv4Addr::new(1, 1, 1, 1));
        let key2 = PoolTableKey::new(NextHeader::TCP, 2, Ipv4Addr::new(1, 1, 1, 2));
        assert!(key1 < key2);

        let key1 = PoolTableKey::new(NextHeader::TCP, 2, Ipv4Addr::new(1, 1, 1, 1));
        let key2 = PoolTableKey::new(NextHeader::TCP, 1, Ipv4Addr::new(2, 2, 2, 2));
        assert!(key1 > key2);

        let key1 = PoolTableKey::new(NextHeader::TCP, 2, Ipv4Addr::new(1, 1, 1, 1));
        let key2 = PoolTableKey::new(NextHeader::TCP, 1, Ipv4Addr::new(255, 255, 255, 255));
        assert!(key1 > key2);

        // Mixing protocols

        let key1 = PoolTableKey::new(NextHeader::TCP, 1, Ipv4Addr::new(1, 1, 1, 1));
        let key2 = PoolTableKey::new(NextHeader::UDP, 1, Ipv4Addr::new(1, 1, 1, 1));
        assert!(key1 < key2);

        let key1 = PoolTableKey::new(NextHeader::TCP, 2, Ipv4Addr::new(2, 2, 2, 2));
        let key2 = PoolTableKey::new(NextHeader::UDP, 1, Ipv4Addr::new(1, 1, 1, 1));
        assert!(key1 < key2);
    }
}
