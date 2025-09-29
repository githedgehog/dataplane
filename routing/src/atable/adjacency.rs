// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! State objects to keep adjacency information

use ahash::RandomState;
use net::eth::mac::Mac;
use net::interface::InterfaceIndex;
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Clone)]
/// Object that represents an adjacency or ARP/ND entry
pub struct Adjacency {
    address: IpAddr,
    ifindex: InterfaceIndex,
    mac: Mac,
}

impl Adjacency {
    /// Create an [`Adjacency`] object
    #[must_use]
    pub fn new(address: IpAddr, ifindex: InterfaceIndex, mac: Mac) -> Self {
        Self {
            address,
            ifindex,
            mac,
        }
    }
    /// Get the Ifindex of an [`Adjacency`] object
    #[must_use]
    pub fn get_ifindex(&self) -> InterfaceIndex {
        self.ifindex
    }

    /// Get the MAC of an [`Adjacency`] object
    #[must_use]
    pub fn get_mac(&self) -> Mac {
        self.mac
    }

    /// Get the IP address of an [`Adjacency`] object
    #[must_use]
    pub fn get_ip(&self) -> IpAddr {
        self.address
    }
}

/// A table of [`Adjacency`]ies
#[derive(Default, Clone)]
pub struct AdjacencyTable(HashMap<(InterfaceIndex, IpAddr), Adjacency, RandomState>);

impl AdjacencyTable {
    #[must_use]
    pub fn new() -> Self {
        Self(HashMap::with_hasher(RandomState::with_seed(0)))
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = (&(InterfaceIndex, IpAddr), &Adjacency)> {
        self.0.iter()
    }
    pub fn values(&self) -> impl Iterator<Item = &Adjacency> {
        self.0.values()
    }
    pub fn add_adjacency(&mut self, adjacency: Adjacency) {
        self.0
            .insert((adjacency.ifindex, adjacency.address), adjacency);
    }
    pub fn del_adjacency(&mut self, address: IpAddr, ifindex: InterfaceIndex) {
        self.0.remove(&(ifindex, address));
    }
    #[must_use]
    pub fn get_adjacency(&self, address: IpAddr, ifindex: InterfaceIndex) -> Option<&Adjacency> {
        self.0.get(&(ifindex, address))
    }
    pub fn clear(&mut self) {
        self.0.clear();
    }
}

#[cfg(test)]
#[rustfmt::skip]
pub mod tests {
use super::*;
use crate::rib::vrf::tests::mk_addr;
use net::interface::InterfaceIndex;

    pub fn build_test_atable() -> AdjacencyTable {
        let mut atable = AdjacencyTable::new();
        {
            let ip = mk_addr("10.0.0.1");
            let mac = Mac::from([0x0, 0x0, 0x0, 0x0 ,0xaa, 0x1]);
            atable.add_adjacency(Adjacency::new(ip, InterfaceIndex::try_new(2).unwrap(), mac));
        }
        {
            let ip = mk_addr("10.0.0.5");
            let mac = Mac::from([0x0, 0x0, 0x0, 0x0 ,0xaa, 0x5]);
            atable.add_adjacency(Adjacency::new(ip, InterfaceIndex::try_new(3).unwrap(), mac));
        }
        {
            let ip = mk_addr("10.0.0.9");
            let mac = Mac::from([0x0, 0x0, 0x0, 0x0 ,0xaa, 0x9]);
            atable.add_adjacency(Adjacency::new(ip, InterfaceIndex::try_new(4).unwrap(), mac ));
        }
        atable
    }

    #[test]
    fn test_adj_table_minimal() {
        let mut atable = AdjacencyTable::new();
        let ip = mk_addr("10.0.0.1");
        let mac = Mac::from([0x0, 0x0, 0x0, 0x0 ,0x0, 0x1]);

        let a1 = Adjacency::new(ip, InterfaceIndex::try_new(10).unwrap(), mac);
        atable.add_adjacency(a1);
        assert_eq!(atable.get_adjacency(ip, InterfaceIndex::try_new(10).unwrap()).unwrap().mac, mac);

        atable.del_adjacency(ip, InterfaceIndex::try_new(10).unwrap());
        assert!(atable.get_adjacency(ip, InterfaceIndex::try_new(10).unwrap()).is_none());
    }
}
