// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! State objects to keep adjacency information

use crate::interface::IfIndex;
use net::eth::mac::Mac;
use std::collections::HashMap;
use std::net::IpAddr;

#[allow(dead_code)]
pub struct Adjacency {
    pub address: IpAddr,
    pub mac: Mac,
    pub ifindex: IfIndex,
}
pub struct AdjacencyTable(HashMap<IpAddr, Adjacency>);

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
        self.0.insert(adjacency.address, adjacency);
    }
    pub fn del_adjacency(&mut self, address: &IpAddr) {
        self.0.remove(address);
    }
    pub fn get_adjacency(&self, address: &IpAddr) -> Option<&Adjacency> {
        self.0.get(address)
    }
}
