// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: OSPF (minimal)

use std::net::Ipv4Addr;

#[derive(Clone, Debug)]
pub struct Ospf {
    pub router_id: Ipv4Addr,
    pub vrf: Option<String>,
}

impl Ospf {
    #[must_use]
    pub fn new(router_id: Ipv4Addr) -> Self {
        Self {
            router_id,
            vrf: None,
        }
    }
    pub fn set_vrf_name(&mut self, vrf_name: String) {
        self.vrf = Some(vrf_name);
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub enum OspfNetwork {
    Broadcast,
    NonBroadcast,
    #[default]
    Point2Point,
    Point2Multipoint,
}

#[derive(Clone, Debug, PartialEq)]
pub struct OspfInterface {
    pub passive: bool,
    pub area: Ipv4Addr,
    pub cost: Option<u32>,
    pub network: Option<OspfNetwork>,
}

impl OspfInterface {
    #[must_use]
    pub fn new(area: Ipv4Addr) -> Self {
        Self {
            passive: false,
            area,
            cost: None,
            network: None,
        }
    }
    #[must_use]
    pub fn set_passive(mut self, value: bool) -> Self {
        self.passive = value;
        self
    }
    #[must_use]
    pub fn set_cost(mut self, cost: u32) -> Self {
        self.cost = Some(cost);
        self
    }
    #[must_use]
    pub fn set_network(mut self, network: OspfNetwork) -> Self {
        self.network = Some(network);
        self
    }
}
