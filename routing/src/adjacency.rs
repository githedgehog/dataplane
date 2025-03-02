// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! State objects to keep adjacency information

use crate::interface::IfIndex;
use net::eth::mac::Mac;
use std::collections::HashMap;
use std::net::IpAddr;

#[allow(dead_code)]
pub struct Adjacency {
    address: IpAddr,
    ifindex: IfIndex,
    mac: Mac,
}

#[allow(dead_code)]
impl Adjacency {
    fn new(address: IpAddr, ifindex: IfIndex, mac: Mac) -> Self {
        Self {
            address,
            ifindex,
            mac,
        }
    }
}

pub struct AdjacencyTable(HashMap<(IfIndex, IpAddr), Adjacency>);

#[allow(dead_code)]
impl AdjacencyTable {
    pub(crate) fn new() -> Self {
        Self(HashMap::new())
        // Todo: use a fast hasher
    }
}

#[allow(dead_code)]
impl AdjacencyTable {
    pub(crate) fn add_adjacency(&mut self, adjacency: Adjacency) {
        self.0
            .insert((adjacency.ifindex, adjacency.address), adjacency);
    }
    pub fn del_adjacency(&mut self, address: IpAddr, ifindex: IfIndex) {
        self.0.remove(&(ifindex, address));
    }
    pub fn get_adjacency(&self, address: IpAddr, ifindex: IfIndex) -> Option<&Adjacency> {
        self.0.get(&(ifindex, address))
    }
}

#[cfg(test)]
#[allow(dead_code)]
#[rustfmt::skip]
pub mod test {
    use super::*;
    use std::{net::IpAddr, str::FromStr};

    #[test]
    fn test_adj_table_minimal() {
        let mut atable = AdjacencyTable::new();
        let ip = IpAddr::from_str("10.0.0.1").unwrap();
        let mac = Mac::from([0x0, 0x0, 0x0, 0x0 ,0x0, 0x1]);

        let a1 = Adjacency::new(ip, 10, mac);
        atable.add_adjacency(a1);
        assert_eq!(atable.get_adjacency(ip, 10).unwrap().mac, mac);

        atable.del_adjacency(ip, 10);
        assert!(atable.get_adjacency(ip, 10).is_none());
    }
}
