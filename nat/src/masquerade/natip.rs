// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! NAT IP address trait: a sealed trait to represent either IPv4 or IPv6 in IP-version-generic
//! code.

use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// Keeping this module private provides a "sealed" trait: only types defined in this crate can
// implement it, external types cannot implement `Sealed`.
mod private {
    pub trait Sealed {}
}

/// `NatIp` is a sealed trait to represent either IPv4 or IPv6.
pub trait NatIp:
    private::Sealed + Debug + Display + Clone + Copy + Eq + Ord + Hash + Send + Sync + 'static
{
    // Convert to `IpAddr` object
    fn to_ip_addr(&self) -> IpAddr;

    // Convert from a 128-bit integer to a `NatIp`, if possible
    fn try_from_bits(bits: u128) -> Result<Self, ()>;

    // Convert to a 128-bit integer. Named to avoid colliding with the inherent `to_bits` of
    // `Ipv4Addr`, which yields a `u32` and would silently win method resolution.
    fn to_addr_bits(&self) -> u128;

    // Convert from an `IpAddr` object to a `NatIp`, if possible
    fn try_from_addr(addr: IpAddr) -> Result<Self, ()>;
}

impl private::Sealed for Ipv4Addr {}
impl private::Sealed for Ipv6Addr {}

impl NatIp for Ipv4Addr {
    fn to_ip_addr(&self) -> IpAddr {
        IpAddr::V4(*self)
    }
    fn try_from_bits(bits: u128) -> Result<Self, ()> {
        Ok(Self::from(u32::try_from(bits).map_err(|_| ())?))
    }
    fn to_addr_bits(&self) -> u128 {
        u128::from(self.to_bits())
    }
    fn try_from_addr(addr: IpAddr) -> Result<Self, ()> {
        if let IpAddr::V4(addr) = addr {
            Ok(addr)
        } else {
            Err(())
        }
    }
}

impl NatIp for Ipv6Addr {
    fn to_ip_addr(&self) -> IpAddr {
        IpAddr::V6(*self)
    }
    fn try_from_bits(bits: u128) -> Result<Self, ()> {
        Ok(Self::from(bits))
    }
    fn to_addr_bits(&self) -> u128 {
        self.to_bits()
    }
    fn try_from_addr(addr: IpAddr) -> Result<Self, ()> {
        if let IpAddr::V6(addr) = addr {
            Ok(addr)
        } else {
            Err(())
        }
    }
}
