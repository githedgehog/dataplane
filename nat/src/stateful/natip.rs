// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use net::headers::Net;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

mod private {
    pub trait Sealed {}
}
pub trait NatIp: private::Sealed + Clone + Eq + Hash {
    fn to_ip_addr(&self) -> IpAddr;
    fn from_src_addr(net: &Net) -> Option<Self>;
    fn from_dst_addr(net: &Net) -> Option<Self>;
}
impl private::Sealed for Ipv4Addr {}
impl private::Sealed for Ipv6Addr {}
impl NatIp for Ipv4Addr {
    fn to_ip_addr(&self) -> IpAddr {
        IpAddr::V4(*self)
    }
    fn from_src_addr(net: &Net) -> Option<Self> {
        if let IpAddr::V4(addr) = net.src_addr() {
            Some(addr)
        } else {
            None
        }
    }
    fn from_dst_addr(net: &Net) -> Option<Self> {
        if let IpAddr::V4(addr) = net.dst_addr() {
            Some(addr)
        } else {
            None
        }
    }
}
impl NatIp for Ipv6Addr {
    fn to_ip_addr(&self) -> IpAddr {
        IpAddr::V6(*self)
    }
    fn from_src_addr(net: &Net) -> Option<Self> {
        if let IpAddr::V6(addr) = net.src_addr() {
            Some(addr)
        } else {
            None
        }
    }
    fn from_dst_addr(net: &Net) -> Option<Self> {
        if let IpAddr::V6(addr) = net.dst_addr() {
            Some(addr)
        } else {
            None
        }
    }
}
