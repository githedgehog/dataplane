// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: static routes

use routing::prefix::Prefix;
use std::net::IpAddr;

#[derive(Clone, Debug, Ord, Eq, PartialEq, PartialOrd)]
pub enum StaticRouteNhop {
    Unset,
    Interface(String),
    Address(IpAddr),
    Null0,
    Blackhole,
    Reject,
}

#[derive(Clone, Debug, Ord, Eq, PartialEq, PartialOrd)]
pub struct StaticRoute {
    pub prefix: Prefix,
    pub next_hop: StaticRouteNhop,
    pub next_hop_vrf: Option<String>,
    pub tag: Option<u32>,
}

impl StaticRoute {
    pub fn new(prefix: Prefix) -> Self {
        Self {
            prefix,
            next_hop: StaticRouteNhop::Unset,
            next_hop_vrf: None,
            tag: None,
        }
    }
    pub fn nhop_addr(mut self, addr: IpAddr) -> Self {
        self.next_hop = StaticRouteNhop::Address(addr);
        self
    }
    pub fn nhop_iface(mut self, ifname: String) -> Self {
        self.next_hop = StaticRouteNhop::Interface(ifname);
        self
    }
    pub fn nhop_blackhole(mut self) -> Self {
        self.next_hop = StaticRouteNhop::Blackhole;
        self
    }
    pub fn nhop_null0(mut self) -> Self {
        self.next_hop = StaticRouteNhop::Null0;
        self
    }
    pub fn nhop_reject(mut self) -> Self {
        self.next_hop = StaticRouteNhop::Reject;
        self
    }
    pub fn nhop_vrf(mut self, vrfname: String) -> Self {
        self.next_hop_vrf = Some(vrfname);
        self
    }
    pub fn tag(mut self, tag: u32) -> Self {
        self.tag = Some(tag);
        self
    }
}
