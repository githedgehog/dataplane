// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use ipnet::{Ipv4Net, Ipv6Net};
use num_traits::{CheckedShr, PrimInt, Unsigned, Zero};

use crate::prefix::PrefixError;

pub trait Representable {
    type Repr: Unsigned + PrimInt + Zero + CheckedShr;

    fn to_bits(&self) -> Self::Repr;
    fn from_bits(repr: Self::Repr) -> Self;
}

impl Representable for Ipv4Addr {
    type Repr = u32;

    fn to_bits(&self) -> Self::Repr {
        Ipv4Addr::to_bits(*self)
    }

    fn from_bits(repr: Self::Repr) -> Self {
        Ipv4Addr::from_bits(repr)
    }
}

impl Representable for Ipv6Addr {
    type Repr = u128;

    fn to_bits(&self) -> Self::Repr {
        Ipv6Addr::to_bits(*self)
    }

    fn from_bits(repr: Self::Repr) -> Self {
        Ipv6Addr::from_bits(repr)
    }
}

#[allow(clippy::len_without_is_empty)]
pub trait IpPrefix:
    Sized + Debug + Display + Clone + From<Self::Addr> + Default + PartialEq
{
    type Repr: Debug + Unsigned + PrimInt + Zero + CheckedShr;
    type Addr: Display + Debug + Clone + Eq + Hash + Representable<Repr = Self::Repr>;
    const MAX_LEN: u8;

    /// # Errors
    ///
    /// Returns an error if the length is greater than `Self::MAX_LEN`
    fn new(addr: Self::Addr, len: u8) -> Result<Self, PrefixError>;
    fn network(&self) -> Self::Addr;
    fn len(&self) -> u8;
}

pub trait IpPrefixCovering<Other> {
    fn covers(&self, other: &Other) -> bool;
}

////////////////////////////////////////////////////////////
// IPv4 Prefix
////////////////////////////////////////////////////////////

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv4Prefix(Ipv4Net);

impl Debug for Ipv4Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

impl Default for Ipv4Prefix {
    fn default() -> Self {
        Self(Ipv4Net::new(Ipv4Addr::new(0, 0, 0, 0), 0).unwrap())
    }
}

impl Display for Ipv4Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl IpPrefix for Ipv4Prefix {
    type Repr = u32;
    const MAX_LEN: u8 = 32;
    type Addr = Ipv4Addr;

    /// # Errors
    ///
    /// Returns an error if the length is greater than `Self::MAX_LEN`
    fn new(addr_in: Ipv4Addr, len: u8) -> Result<Self, PrefixError> {
        if len > Self::MAX_LEN {
            return Err(PrefixError::InvalidLength(len));
        }
        let addr = Ipv4Addr::from_bits(
            addr_in.to_bits() & u32::MAX.unbounded_shl(u32::from(Self::MAX_LEN - len)),
        );
        Ok(Self(
            Ipv4Net::new(addr, len).map_err(|e| PrefixError::Invalid(e.to_string()))?,
        ))
    }

    fn network(&self) -> Self::Addr {
        self.0.network()
    }
    fn len(&self) -> u8 {
        self.0.prefix_len()
    }
}

impl IpPrefixCovering<Ipv4Addr> for Ipv4Prefix {
    fn covers(&self, other: &Ipv4Addr) -> bool {
        self.0.contains(other)
    }
}

impl IpPrefixCovering<Ipv4Prefix> for Ipv4Prefix {
    fn covers(&self, other: &Ipv4Prefix) -> bool {
        self.0.contains(&other.0)
    }
}

impl From<Ipv4Addr> for Ipv4Prefix {
    fn from(addr: Ipv4Addr) -> Self {
        Self::new(addr, Self::MAX_LEN).unwrap()
    }
}

impl From<Ipv4Net> for Ipv4Prefix {
    fn from(value: Ipv4Net) -> Self {
        Self::new(value.network(), value.prefix_len())
            .unwrap_or_else(|_| unreachable!("Invalid IPv6 prefix: {:?}", value))
    }
}

impl FromStr for Ipv4Prefix {
    type Err = PrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, len) = s
            .split_once('/')
            .ok_or(PrefixError::Invalid(s.to_string()))?;
        let addr = addr
            .parse::<Ipv4Addr>()
            .map_err(|_| PrefixError::Invalid(s.to_string()))?;
        let len = len
            .parse::<u8>()
            .map_err(|_| PrefixError::Invalid(s.to_string()))?;
        Self::new(addr, len)
    }
}

////////////////////////////////////////////////////////////
// IPv6 Prefix
////////////////////////////////////////////////////////////

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv6Prefix(Ipv6Net);

impl Debug for Ipv6Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

impl Default for Ipv6Prefix {
    fn default() -> Self {
        Self(Ipv6Net::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0).unwrap())
    }
}

impl Display for Ipv6Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl IpPrefix for Ipv6Prefix {
    type Repr = u128;
    type Addr = Ipv6Addr;
    const MAX_LEN: u8 = 128;

    /// # Errors
    ///
    /// Returns an error if the length is greater than `Self::MAX_LEN`
    fn new(addr: Ipv6Addr, len: u8) -> Result<Self, PrefixError> {
        if len > Self::MAX_LEN {
            return Err(PrefixError::InvalidLength(len));
        }
        let addr = Ipv6Addr::from_bits(
            addr.to_bits() & u128::MAX.unbounded_shl(u32::from(Self::MAX_LEN - len)),
        );
        Ok(Self(
            Ipv6Net::new(addr, len).map_err(|e| PrefixError::Invalid(e.to_string()))?,
        ))
    }
    fn network(&self) -> Self::Addr {
        self.0.network()
    }
    fn len(&self) -> u8 {
        self.0.prefix_len()
    }
}

impl IpPrefixCovering<Ipv6Addr> for Ipv6Prefix {
    fn covers(&self, other: &Ipv6Addr) -> bool {
        self.0.contains(other)
    }
}

impl IpPrefixCovering<Ipv6Prefix> for Ipv6Prefix {
    fn covers(&self, other: &Ipv6Prefix) -> bool {
        self.0.contains(&other.0)
    }
}

impl From<Ipv6Addr> for Ipv6Prefix {
    fn from(addr: Ipv6Addr) -> Self {
        Self::new(addr, Self::MAX_LEN).unwrap()
    }
}

impl From<Ipv6Net> for Ipv6Prefix {
    fn from(value: Ipv6Net) -> Self {
        Self::new(value.network(), value.prefix_len())
            .unwrap_or_else(|_| unreachable!("Invalid IPv6 prefix: {:?}", value))
    }
}

impl FromStr for Ipv6Prefix {
    type Err = PrefixError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, len) = s
            .split_once('/')
            .ok_or(PrefixError::Invalid(s.to_string()))?;
        let addr = addr
            .parse::<Ipv6Addr>()
            .map_err(|_| PrefixError::Invalid(s.to_string()))?;
        let len = len
            .parse::<u8>()
            .map_err(|_| PrefixError::Invalid(s.to_string()))?;

        Self::new(addr, len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_prefix_from_str() {
        let prefix = "192.168.1.0/24".parse::<Ipv4Prefix>().unwrap();
        assert_eq!(prefix.network(), Ipv4Addr::new(192, 168, 1, 0));
    }

    #[test]
    fn test_ipv4_covers() {
        // IP Address is covered by prefix
        let prefix = "192.168.1.0/24".parse::<Ipv4Prefix>().unwrap();
        assert!(prefix.covers(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!prefix.covers(&Ipv4Addr::new(192, 168, 2, 1)));

        // Prefix is covered by prefix
        assert!(prefix.covers(&prefix));
        assert!(prefix.covers(&Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 25).unwrap()));
        assert!(!prefix.covers(&Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 23).unwrap()));

        // Big prefix covers small prefix
        let big_prefix = "128.0.0.0/1".parse::<Ipv4Prefix>().unwrap();
        assert!(big_prefix.covers(&prefix));
        assert!(!prefix.covers(&big_prefix));

        // Prefixes with same length but different network are not covered
        let p1 = "192.168.1.0/24".parse::<Ipv4Prefix>().unwrap();
        let p2 = "192.168.2.0/24".parse::<Ipv4Prefix>().unwrap();
        assert!(!p1.covers(&p2));
        assert!(!p2.covers(&p1));
    }

    #[test]
    fn test_ipv6_prefix_from_str() {
        let prefix = "2001:db8::/32".parse::<Ipv6Prefix>().unwrap();
        assert_eq!(
            prefix.network(),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)
        );
    }

    #[test]
    fn test_ipv6_covers() {
        // IP Address is covered by prefix
        let prefix = "2001:db8::/32".parse::<Ipv6Prefix>().unwrap();
        assert!(prefix.covers(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
        assert!(prefix.covers(&Ipv6Addr::new(0x2001, 0xdb8, 0xabcd, 0, 0, 0, 0, 0)));
        assert!(!prefix.covers(&Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 0)));

        // Prefix is covered by prefix
        assert!(prefix.covers(&prefix));
        assert!(
            prefix.covers(
                &Ipv6Prefix::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 48).unwrap()
            )
        );
        assert!(
            !prefix.covers(
                &Ipv6Prefix::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 16).unwrap()
            )
        );

        // Big prefix covers small prefix
        let big_prefix = "::/2".parse::<Ipv6Prefix>().unwrap();
        assert!(big_prefix.covers(&prefix));
        assert!(!prefix.covers(&big_prefix));

        // Prefixes with same length but different network are not covered
        let p1 = "2001:db8::/32".parse::<Ipv6Prefix>().unwrap();
        let p2 = "2001:db9::/32".parse::<Ipv6Prefix>().unwrap();
        assert!(!p1.covers(&p2));
        assert!(!p2.covers(&p1));
    }
}
