// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(private_bounds)]

#[cfg(feature = "ecmp")]
use arrayvec::ArrayVec;
use interface_manager::InterfaceIndex;
use net::eth::mac::SourceMac;
use net::vlan::Vid;
use net::vxlan::Vni;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const MAX_ECMP: usize = 4;

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct EthernetNeighbor {
    interface: InterfaceIndex,
    mac: SourceMac,
}

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct VlanTunnel {
    vid: Vid,
    native: bool,
    egress_untagged: bool,
}

pub enum VxlanNextHop {
    Ip(IpAddr),
    Group(L2NextHopGroup),
}

pub struct L2NextHopGroup {}

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct VxlanNeighbor {
    eth: EthernetNeighbor,
    vlan_tunnel: VlanTunnel,
    vni: Vni,
    remote: IpAddr,
}

pub enum Neighbor {
    Eth(EthernetNeighbor),
    Vxlan(VxlanNeighbor),
}

trait IpLike: Into<IpAddr> {}

impl IpLike for IpAddr {}
impl IpLike for Ipv4Addr {}
impl IpLike for Ipv6Addr {}

// impl<Ip: IpLike> AsRef<EthernetNeighbor> for VxlanNeighbor<Ip> {
//     fn as_ref(&self) -> &EthernetNeighbor {
//         &self.eth
//     }
// }

pub enum RouteStep {
    Via(IpAddr),
    Dev(EthernetNeighbor),
}

pub enum Route {
    Drop,
    Step(RouteStep),
    #[cfg(feature = "ecmp")] // TODO: support ECMP
    Ecmp(ArrayVec<RouteStep, MAX_ECMP>),
}

#[derive(Debug, Default, Copy, Clone, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub enum ForwardingAction {
    #[default]
    Forward = 0,
    Drop = 1,
}
