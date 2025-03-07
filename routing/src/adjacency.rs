// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! State objects to keep adjacency information

use crate::interface::IfIndex;
use dplane_rpc::msg::Ifindex;
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
    pub fn new(address: IpAddr, ifindex: IfIndex, mac: Mac) -> Self {
        Self {
            address,
            ifindex,
            mac,
        }
    }
    pub fn get_ifindex(&self) -> Ifindex {
        self.ifindex
    }
    pub fn get_mac(&self) -> Mac {
        self.mac
    }
    pub fn get_ip(&self) -> IpAddr {
        self.address
    }
}

#[derive(Default)]
pub struct AdjacencyTable(HashMap<(IfIndex, IpAddr), Adjacency>);

#[allow(dead_code)]
impl AdjacencyTable {
    pub fn new() -> Self {
        Self(HashMap::new())
        // Todo: use a fast hasher
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = (&(IfIndex, IpAddr), &Adjacency)> {
        self.0.iter()
    }
    pub fn values(&self) -> impl Iterator<Item = &Adjacency> {
        self.0.values()
    }
    pub fn add_adjacency(&mut self, adjacency: Adjacency) {
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
pub mod tests {
    use super::*;
    use crate::vrf::tests::mk_addr;

    pub fn build_test_atable() -> AdjacencyTable {
        let mut atable = AdjacencyTable::new();
        {
            let ip = mk_addr("10.0.0.1");
            let mac = Mac::from([0x0, 0x0, 0x0, 0x0 ,0x0, 0x1]);
            atable.add_adjacency(Adjacency::new(ip, 1, mac));
        }
        {
            let ip = mk_addr("10.0.0.5");
            let mac = Mac::from([0x0, 0x0, 0x0, 0x0 ,0x0, 0x5]);
            atable.add_adjacency(Adjacency::new(ip, 2, mac));
        }
        {
            let ip = mk_addr("10.0.0.9");
            let mac = Mac::from([0x0, 0x0, 0x0, 0x0 ,0x0, 0x9]);
            atable.add_adjacency(Adjacency::new(ip, 3, mac ));
        }
        atable
    }

    #[test]
    fn test_adj_table_minimal() {
        let mut atable = AdjacencyTable::new();
        let ip = mk_addr("10.0.0.1");
        let mac = Mac::from([0x0, 0x0, 0x0, 0x0 ,0x0, 0x1]);

        let a1 = Adjacency::new(ip, 10, mac);
        atable.add_adjacency(a1);
        assert_eq!(atable.get_adjacency(ip, 10).unwrap().mac, mac);

        atable.del_adjacency(ip, 10);
        assert!(atable.get_adjacency(ip, 10).is_none());
    }
}
