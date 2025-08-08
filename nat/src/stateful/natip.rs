// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use net::headers::Net;
use std::fmt::Debug;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

mod private {
    pub trait Sealed {}
}
pub trait NatIp: private::Sealed + Debug + Clone + Copy + Eq + Ord + Hash {
    fn to_ip_addr(&self) -> IpAddr;
    fn from_src_addr(net: &Net) -> Option<Self>;
    fn from_dst_addr(net: &Net) -> Option<Self>;
    fn to_bits(&self) -> u128;
    fn try_from_bits(bits: u128) -> Result<Self, ()>;
    fn try_from_addr(addr: IpAddr) -> Result<Self, ()>;
    fn try_from_ipv4_addr(addr: Ipv4Addr) -> Result<Self, ()>;
    fn try_from_ipv6_addr(addr: Ipv6Addr) -> Result<Self, ()>;
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
    fn to_bits(&self) -> u128 {
        u128::from(u32::from(*self))
    }
    fn try_from_bits(bits: u128) -> Result<Self, ()> {
        Ok(Self::from(u32::try_from(bits).map_err(|_| ())?))
    }
    fn try_from_addr(addr: IpAddr) -> Result<Self, ()> {
        if let IpAddr::V4(addr) = addr {
            Ok(addr)
        } else {
            Err(())
        }
    }
    fn try_from_ipv4_addr(addr: Ipv4Addr) -> Result<Self, ()> {
        Ok(addr)
    }
    fn try_from_ipv6_addr(addr: Ipv6Addr) -> Result<Self, ()> {
        Err(())
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
    fn to_bits(&self) -> u128 {
        u128::from(*self)
    }
    fn try_from_bits(bits: u128) -> Result<Self, ()> {
        Ok(Self::from(bits))
    }
    fn try_from_addr(addr: IpAddr) -> Result<Self, ()> {
        if let IpAddr::V6(addr) = addr {
            Ok(addr)
        } else {
            Err(())
        }
    }
    fn try_from_ipv4_addr(addr: Ipv4Addr) -> Result<Self, ()> {
        Err(())
    }
    fn try_from_ipv6_addr(addr: Ipv6Addr) -> Result<Self, ()> {
        Ok(addr)
    }
}
