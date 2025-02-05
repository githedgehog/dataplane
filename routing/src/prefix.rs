// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Type to represent IP-version neutral network prefixes.

use ipnet::{Ipv4Net, Ipv6Net};
use iptrie::{IpPrefix, Ipv4Prefix, Ipv6Prefix};
use std::fmt::Display;
pub use std::net::IpAddr;
#[cfg(test)]
use std::str::FromStr;

/// Type to represent both IPv4 and IPv6 prefixes to expose an IP version-independent API.
/// Since we will not store prefixes, putting Ipv6 on the same basket as IPv4 will not penalize the
/// memory requirements of Ipv4
#[derive(Debug, Clone, PartialEq)]
pub enum Prefix {
    IPV4(Ipv4Prefix),
    IPV6(Ipv6Prefix),
}

#[allow(dead_code)]
impl Prefix {
    /// Build 0.0.0.0/0. "Default" is a very overloaded term. Calling this root_v4 instead of default_v4.
    pub fn root_v4() -> Prefix {
        Prefix::IPV4(Ipv4Prefix::default())
    }
    /// Build ::/0.
    pub fn root_v6() -> Prefix {
        Prefix::IPV6(Ipv6Prefix::default())
    }
    /// Tell if a prefix is a root prefix
    pub fn is_root(&self) -> bool {
        match self {
            Prefix::IPV4(_) => *self == Prefix::root_v4(),
            Prefix::IPV6(_) => *self == Prefix::root_v6(),
        }
    }
    /// Get the inner Ipv4Prefix from a Prefix
    pub(crate) fn get_v4(&self) -> &Ipv4Prefix {
        match self {
            Prefix::IPV4(p) => p,
            Prefix::IPV6(_) => panic!("Not an IPv4 prefix!"),
        }
    }
    /// Get the inner Ipv6Prefix from a Prefix
    pub(crate) fn get_v6(&self) -> &Ipv6Prefix {
        match self {
            Prefix::IPV4(_) => panic!("Not an IPv6 prefix!"),
            Prefix::IPV6(p) => p,
        }
    }
    /// Build an IpAddr from a prefix
    pub fn as_address(&self) -> IpAddr {
        match *self {
            Prefix::IPV4(p) => p.network().into(),
            Prefix::IPV6(p) => p.network().into(),
        }
    }
}
impl From<(&IpAddr, u8)> for Prefix {
    fn from(tuple: (&IpAddr, u8)) -> Self {
        match *tuple.0 {
            IpAddr::V4(a) => Prefix::IPV4(Ipv4Prefix::new(a, tuple.1).unwrap()),
            IpAddr::V6(a) => Prefix::IPV6(Ipv6Prefix::new(a, tuple.1).unwrap()),
        }
    }
}
impl From<&Ipv4Net> for Prefix {
    fn from(value: &Ipv4Net) -> Self {
        Prefix::IPV4(Ipv4Prefix::from(*value))
    }
}
impl From<&Ipv6Net> for Prefix {
    fn from(value: &Ipv6Net) -> Self {
        Prefix::IPV6(Ipv6Prefix::from(*value))
    }
}
impl<'a> From<&'a Prefix> for &'a Ipv4Prefix {
    fn from(value: &Prefix) -> &Ipv4Prefix {
        match value {
            Prefix::IPV4(p) => p,
            Prefix::IPV6(_) => panic!("Not an IPv4 prefix!"),
        }
    }
}
impl<'a> From<&'a Prefix> for &'a Ipv6Prefix {
    fn from(value: &Prefix) -> &Ipv6Prefix {
        match value {
            Prefix::IPV4(_) => panic!("Not an IPv6 prefix!"),
            Prefix::IPV6(p) => p,
        }
    }
}
impl From<&Ipv4Prefix> for Prefix {
    fn from(value: &Ipv4Prefix) -> Self {
        Self::IPV4(*value)
    }
}
impl From<&Ipv6Prefix> for Prefix {
    fn from(value: &Ipv6Prefix) -> Self {
        Self::IPV6(*value)
    }
}

#[cfg(test)]
/// Only for testing. Will panic with badly formed address strings
impl From<(&str, u8)> for Prefix {
    fn from(tuple: (&str, u8)) -> Self {
        let a = IpAddr::from_str(tuple.0).expect("Bad address");
        Prefix::from((&a, tuple.1))
    }
}

impl Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Prefix::IPV4(p) => write!(f, "{}", p),
            Prefix::IPV6(p) => write!(f, "{}", p),
        }
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use crate::prefix::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_prefix_v4() {
        let ipv4_addr: Ipv4Addr = "1.2.3.0".parse().expect("Bad address");
        let ipv4_pfx = Ipv4Prefix::new(ipv4_addr, 24).expect("Should succeed");
        let _prefix: Prefix = (&ipv4_pfx).into();
        let prefix = Prefix::from(&ipv4_pfx);
        let ipv4_pfx_back: &Ipv4Prefix = (&prefix).into();
        assert_eq!(*ipv4_pfx_back, ipv4_pfx);

        let prefv4 = prefix.get_v4();
        assert_eq!(*prefv4, ipv4_pfx, "Conversion mismatch");

        // default - root
        let address: Ipv4Addr = "0.0.0.0".parse().unwrap();
        let iptrie_pfx = Ipv4Prefix::new(address, 0).unwrap();
        let prefix = Prefix::from(&iptrie_pfx);
        assert_eq!(prefix, Prefix::root_v4());
    }

    #[test]
    fn test_prefix_v6() {
        let ipv6_addr: Ipv6Addr = "2001:a:b:c::".parse().expect("Bad address");
        let ipv6_pfx = Ipv6Prefix::new(ipv6_addr, 64).expect("Should succeed");
        let _prefix: Prefix = (&ipv6_pfx).into();
        let prefix = Prefix::from(&ipv6_pfx);
        let ipv6_pfx_back: &Ipv6Prefix = (&prefix).into();
        assert_eq!(*ipv6_pfx_back, ipv6_pfx);

        let prefv6 = prefix.get_v6();
        assert_eq!(*prefv6, ipv6_pfx, "Conversion mismatch");

        // default - root
        let address: Ipv6Addr = "::".parse().unwrap();
        let iptrie_pfx = Ipv6Prefix::new(address, 0).unwrap();
        let prefix = Prefix::from(&iptrie_pfx);
        assert_eq!(prefix, Prefix::root_v6());
    }
}
