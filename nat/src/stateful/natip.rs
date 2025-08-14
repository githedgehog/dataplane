// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! NAT IP address trait: a sealed trait to represent either IPv4 or IPv6 in IP-version-generic
//! code.

use net::headers::Net;
use std::fmt::Debug;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// Keeping this module private provides a "sealed" trait: only types defined in this crate can
// implement it, external types cannot implement `Sealed`.
mod private {
    pub trait Sealed {}
}

/// `NatIp` is a sealed trait to represent either IPv4 or IPv6.
pub trait NatIp: private::Sealed + Debug + Clone + Copy + Eq + Ord + Hash {
    // Convert to `IpAddr` object
    fn to_ip_addr(&self) -> IpAddr;

    // Extract the source IP address from a Net object as a `NatIp`
    fn from_src_addr(net: &Net) -> Option<Self>;

    // Extract the destination IP address from a Net object as a `NatIp`
    fn from_dst_addr(net: &Net) -> Option<Self>;

    // Convert from a 128-bit integer to a `NatIp`, if possible
    fn try_from_bits(bits: u128) -> Result<Self, ()>;

    // Convert from an `IpAddr` object to a `NatIp`, if possible
    fn try_from_addr(addr: IpAddr) -> Result<Self, ()>;

    // Convert from an `Ipv4Addr` object to a `NatIp`, if possible
    fn try_from_ipv4_addr(addr: Ipv4Addr) -> Result<Self, ()>;

    // Convert from an `Ipv6Addr` object to a `NatIp`, if possible
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
    fn try_from_ipv6_addr(_addr: Ipv6Addr) -> Result<Self, ()> {
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
    fn try_from_ipv4_addr(_addr: Ipv4Addr) -> Result<Self, ()> {
        Err(())
    }
    fn try_from_ipv6_addr(addr: Ipv6Addr) -> Result<Self, ()> {
        Ok(addr)
    }
}
