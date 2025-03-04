// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(private_bounds)]

#[cfg(feature = "ecmp")]
use arrayvec::ArrayVec;
use interface_manager::IfIndex;
use net::eth::mac::SourceMac;
use net::vxlan::Vni;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const MAX_ECMP: usize = 4;

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct EthernetNeighbor {
    interface: IfIndex,
    mac: SourceMac,
}

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub enum EthernetNeighborState {
    Failed,
    Reachable,
    Delay,
}

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct VxlanNeighbor<Ip: IpLike = IpAddr> {
    eth: EthernetNeighbor,
    vni: Vni,
    remote: Ip,
}

pub enum Neighbor {
    Eth(EthernetNeighbor),
    Vxlan(VxlanNeighbor),
}

pub struct Via {
    address: Option<IpAddr>,
    interface: Option<IfIndex>,
}

trait IpLike: Into<IpAddr> {}

impl IpLike for IpAddr {}
impl IpLike for Ipv4Addr {}
impl IpLike for Ipv6Addr {}

impl<Ip: IpLike> AsRef<EthernetNeighbor> for VxlanNeighbor<Ip> {
    fn as_ref(&self) -> &EthernetNeighbor {
        &self.eth
    }
}

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
