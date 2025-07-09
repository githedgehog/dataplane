// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Type to represent IP-version neutral network prefixes.

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use iptrie::{IpPrefix, IpPrefixCovering, Ipv4Prefix, Ipv6Prefix};
use serde::ser::SerializeStructVariant;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt::{Debug, Display};
use std::iter::Sum;
pub use std::net::IpAddr;
pub use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::{Add, AddAssign, Sub};
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PrefixError {
    #[error("Invalid Prefix: {0}")]
    Invalid(String),
    #[error("Mask length {0} is invalid")]
    InvalidLength(u8),
}

/// Type to represent both IPv4 and IPv6 prefixes to expose an IP version-independent API.
/// Since we will not store prefixes, putting Ipv6 on the same basket as IPv4 will not penalize the
/// memory requirements of Ipv4
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub enum Prefix {
    IPV4(Ipv4Prefix),
    IPV6(Ipv6Prefix),
}

impl Prefix {
    pub const MAX_LEN_IPV4: u8 = 32;
    pub const MAX_LEN_IPV6: u8 = 128;

    /// Build 224.0.0.0/4 - Ideally this would be const
    #[must_use]
    pub fn ipv4_link_local_mcast_prefix() -> Prefix {
        Prefix::IPV4(Ipv4Prefix::new(Ipv4Addr::new(224, 0, 0, 0), 8).expect("Bad prefix")) // FIXME(fredi)
    }
    /// Build 0.0.0.0/0. "Default" is a very overloaded term. Calling this `root_v4`.
    #[must_use]
    pub fn root_v4() -> Prefix {
        Prefix::IPV4(Ipv4Prefix::default())
    }
    /// Build `::/0`.
    #[must_use]
    pub fn root_v6() -> Prefix {
        Prefix::IPV6(Ipv6Prefix::default())
    }
    /// Tell if a prefix is a root prefix
    #[must_use]
    pub fn is_root(&self) -> bool {
        match self {
            Prefix::IPV4(_) => *self == Prefix::root_v4(),
            Prefix::IPV6(_) => *self == Prefix::root_v6(),
        }
    }
    /// Get the inner `Ipv4Prefix` from a Prefix
    /// # Panics
    /// This method panics if the Prefix does not contain an IPv4 prefix
    #[allow(unused)]
    pub(crate) fn get_v4(&self) -> &Ipv4Prefix {
        match self {
            Prefix::IPV4(p) => p,
            Prefix::IPV6(_) => unreachable!("Not an IPv4 prefix!"),
        }
    }
    /// Get the inner `Ipv6Prefix` from a Prefix
    /// # Panics
    /// This method panics if the Prefix does not contain an IPv6 prefix
    #[allow(unused)]
    pub(crate) fn get_v6(&self) -> &Ipv6Prefix {
        match self {
            Prefix::IPV4(_) => unreachable!("Not an IPv6 prefix!"),
            Prefix::IPV6(p) => p,
        }
    }

    /// Check whether the prefix is IPv4
    #[must_use]
    pub fn is_ipv4(&self) -> bool {
        matches!(self, Prefix::IPV4(_))
    }

    /// Check whether the prefix is IPv6
    #[must_use]
    pub fn is_ipv6(&self) -> bool {
        matches!(self, Prefix::IPV6(_))
    }

    /// Build an `IpAddr` from a prefix
    #[must_use]
    pub fn as_address(&self) -> IpAddr {
        match *self {
            Prefix::IPV4(p) => p.network().into(),
            Prefix::IPV6(p) => p.network().into(),
        }
    }

    /// Get prefix length
    #[must_use]
    pub fn length(&self) -> u8 {
        match *self {
            Prefix::IPV4(p) => p.len(),
            Prefix::IPV6(p) => p.len(),
        }
    }

    /// Get number of covered IP addresses
    #[must_use]
    pub fn size(&self) -> PrefixSize {
        match *self {
            Prefix::IPV4(p) => PrefixSize::U128(2u128.pow(32 - u32::from(p.len()))),
            Prefix::IPV6(p) if p.len() == 0 => PrefixSize::Ipv6MaxAddrs,
            Prefix::IPV6(p) => PrefixSize::U128(2u128.pow(128 - u32::from(p.len()))),
        }
    }

    /// Check whether prefix covers a given address
    #[must_use]
    pub fn covers_addr(&self, addr: &IpAddr) -> bool {
        match (self, addr) {
            (Prefix::IPV4(p), IpAddr::V4(a)) => p.covers(a),
            (Prefix::IPV6(p), IpAddr::V6(a)) => p.covers(a),
            _ => false,
        }
    }

    /// Check whether prefix covers another prefix
    #[must_use]
    pub fn covers(&self, other: &Prefix) -> bool {
        match (self, other) {
            (Prefix::IPV4(p1), Prefix::IPV4(p2)) => p1.covers(p2),
            (Prefix::IPV6(p1), Prefix::IPV6(p2)) => p1.covers(p2),
            _ => false,
        }
    }

    /// Build a [`Prefix`] from (&str, u8)
    /// For a mysterious reason the compiler complains about a conflicting implementation in
    /// crate core when implementing this as `TryFrom`<(&str, u8)> for Prefix.
    ///
    /// # Errors
    /// Fails if the address bits are invalid or the prefix exceeds the maximum allowed.
    pub fn try_from_tuple(tuple: (&str, u8)) -> Result<Self, PrefixError> {
        let a = IpAddr::from_str(tuple.0).map_err(|e| PrefixError::Invalid(e.to_string()))?;
        let max_len = match a {
            IpAddr::V4(_) => Prefix::MAX_LEN_IPV4,
            IpAddr::V6(_) => Prefix::MAX_LEN_IPV6,
        };
        if tuple.1 > max_len {
            Err(PrefixError::InvalidLength(tuple.1))
        } else {
            Prefix::try_from((a, tuple.1))
        }
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn expect_from<T>(val: T) -> Self
    where
        T: TryInto<Prefix>,
        T::Error: Debug,
    {
        val.try_into().expect("Invalid prefix")
    }

    /// Tell if prefix is a host
    #[must_use]
    pub fn is_host(&self) -> bool {
        match self {
            Prefix::IPV4(_) => self.length() == 32,
            Prefix::IPV6(_) => self.length() == 128,
        }
    }
}

impl TryFrom<(IpAddr, u8)> for Prefix {
    type Error = PrefixError;

    fn try_from(tuple: (IpAddr, u8)) -> Result<Self, Self::Error> {
        match tuple.0 {
            IpAddr::V4(a) => Ok(Prefix::IPV4(
                Ipv4Prefix::new(a, tuple.1).map_err(|e| PrefixError::Invalid(e.to_string()))?,
            )),
            IpAddr::V6(a) => Ok(Prefix::IPV6(
                Ipv6Prefix::new(a, tuple.1).map_err(|e| PrefixError::Invalid(e.to_string()))?,
            )),
        }
    }
}
impl From<Ipv4Net> for Prefix {
    fn from(value: Ipv4Net) -> Self {
        Prefix::IPV4(Ipv4Prefix::from(value))
    }
}
impl From<Ipv6Net> for Prefix {
    fn from(value: Ipv6Net) -> Self {
        Prefix::IPV6(Ipv6Prefix::from(value))
    }
}
impl From<Ipv4Prefix> for Prefix {
    fn from(value: Ipv4Prefix) -> Self {
        Self::IPV4(value)
    }
}
impl From<Ipv6Prefix> for Prefix {
    fn from(value: Ipv6Prefix) -> Self {
        Self::IPV6(value)
    }
}

impl From<Prefix> for IpNet {
    fn from(value: Prefix) -> Self {
        let Ok(net) = IpNet::new(value.as_address(), value.length()) else {
            // The length is checked in the construction of Prefix
            unreachable!("Invalid prefix length");
        };
        net
    }
}

#[derive(Debug)]
#[repr(transparent)]
pub struct PrefixString<'a>(pub &'a str);

impl<'a> TryFrom<PrefixString<'a>> for Prefix {
    type Error = PrefixError;

    fn try_from(value: PrefixString<'a>) -> Result<Self, Self::Error> {
        let PrefixString(s) = value;
        if let Ok(p) = Ipv4Net::from_str(s) {
            Ok(Prefix::IPV4(Ipv4Prefix::from(p)))
        } else if let Ok(p) = Ipv6Net::from_str(s) {
            Ok(Prefix::IPV6(Ipv6Prefix::from(p)))
        } else {
            Err(PrefixError::Invalid(s.to_string()))
        }
    }
}

impl TryFrom<(&str, u8)> for Prefix {
    type Error = PrefixError;

    fn try_from((addr_str, mask_len): (&str, u8)) -> Result<Self, Self::Error> {
        let addr = IpAddr::from_str(addr_str)
            .map_err(|_| PrefixError::Invalid("Invalid address format".to_string()))?;

        let max_len = match addr {
            IpAddr::V4(_) => Ipv4Prefix::MAX_LEN,
            IpAddr::V6(_) => Ipv6Prefix::MAX_LEN,
        };
        if mask_len > max_len {
            return Err(PrefixError::InvalidLength(mask_len));
        }
        Prefix::try_from((addr, mask_len))
    }
}
/// Only for testing. Will panic with non-IPv4 prefixes
#[cfg(any(test, feature = "testing"))]
impl<'a> From<&'a Prefix> for &'a Ipv4Prefix {
    fn from(value: &Prefix) -> &Ipv4Prefix {
        match value {
            Prefix::IPV4(p) => p,
            Prefix::IPV6(_) => panic!("Not an IPv4 prefix!"),
        }
    }
}
/// Only for testing. Will panic with non-IPv6 prefixes
#[cfg(any(test, feature = "testing"))]
impl<'a> From<&'a Prefix> for &'a Ipv6Prefix {
    fn from(value: &Prefix) -> &Ipv6Prefix {
        match value {
            Prefix::IPV4(_) => panic!("Not an IPv6 prefix!"),
            Prefix::IPV6(p) => p,
        }
    }
}
/// Only for testing. Will panic with badly formatted prefix strings
#[cfg(any(test, feature = "testing"))]
impl From<&str> for Prefix {
    fn from(s: &str) -> Self {
        Prefix::try_from(PrefixString(s)).unwrap()
    }
}

impl Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Prefix::IPV4(p) => write!(f, "{p}"),
            Prefix::IPV6(p) => write!(f, "{p}"),
        }
    }
}

impl Serialize for Prefix {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match *self {
            Prefix::IPV4(_) => {
                let mut s = serializer.serialize_struct_variant("Prefix", 0, "IPV4", 2)?;
                s.serialize_field("address", &self.as_address())?;
                s.serialize_field("length", &self.length())?;
                s.end()
            }
            Prefix::IPV6(_) => {
                let mut s = serializer.serialize_struct_variant("Prefix", 1, "IPV6", 2)?;
                s.serialize_field("address", &self.as_address())?;
                s.serialize_field("length", &self.length())?;
                s.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Prefix {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Debug, Deserialize)]
        struct Ipv4PrefixSerialized {
            address: Ipv4Addr,
            length: u8,
        }
        #[derive(Debug, Deserialize)]
        struct Ipv6PrefixSerialized {
            address: Ipv6Addr,
            length: u8,
        }
        #[derive(Debug, Deserialize)]
        enum PrefixSerialized {
            IPV4(Ipv4PrefixSerialized),
            IPV6(Ipv6PrefixSerialized),
        }

        let prefix = PrefixSerialized::deserialize(deserializer)?;
        match prefix {
            PrefixSerialized::IPV4(ps) => {
                let p = Ipv4Prefix::new(ps.address, ps.length).map_err(serde::de::Error::custom)?;
                Ok(Prefix::IPV4(p))
            }
            PrefixSerialized::IPV6(ps) => {
                let p = Ipv6Prefix::new(ps.address, ps.length).map_err(serde::de::Error::custom)?;
                Ok(Prefix::IPV6(p))
            }
        }
    }
}

#[derive(Debug, Copy, Clone)]
#[cfg_attr(test, derive(bolero::generator::TypeGenerator))]
pub enum PrefixSize {
    U128(u128),
    Ipv6MaxAddrs,
    Overflow,
}

impl PrefixSize {
    pub fn is_overflow(&self) -> bool {
        matches!(self, PrefixSize::Overflow)
    }
}

impl PartialEq<PrefixSize> for PrefixSize {
    fn eq(&self, other: &PrefixSize) -> bool {
        match (self, other) {
            (PrefixSize::U128(size), PrefixSize::U128(other_size)) => size == other_size,
            (PrefixSize::Ipv6MaxAddrs, PrefixSize::Ipv6MaxAddrs) => true,
            (PrefixSize::U128(_), PrefixSize::Ipv6MaxAddrs) => false,
            (PrefixSize::Ipv6MaxAddrs, PrefixSize::U128(_)) => false,
            (PrefixSize::Overflow, _) => false,
            (_, PrefixSize::Overflow) => false,
        }
    }
}

impl PartialOrd<PrefixSize> for PrefixSize {
    fn partial_cmp(&self, other: &PrefixSize) -> Option<Ordering> {
        match (self, other) {
            (PrefixSize::U128(size), PrefixSize::U128(other_size)) => size.partial_cmp(other_size),
            (PrefixSize::U128(_), PrefixSize::Ipv6MaxAddrs) => Some(Ordering::Less),
            (PrefixSize::Ipv6MaxAddrs, PrefixSize::U128(_)) => Some(Ordering::Greater),
            (PrefixSize::Overflow, PrefixSize::U128(_)) => Some(Ordering::Greater),
            (PrefixSize::U128(_), PrefixSize::Overflow) => Some(Ordering::Less),
            (PrefixSize::Ipv6MaxAddrs, PrefixSize::Overflow) => Some(Ordering::Less),
            (PrefixSize::Overflow, PrefixSize::Ipv6MaxAddrs) => Some(Ordering::Greater),
            (PrefixSize::Ipv6MaxAddrs, PrefixSize::Ipv6MaxAddrs) => Some(Ordering::Equal),
            (PrefixSize::Overflow, PrefixSize::Overflow) => None,
        }
    }
}

impl Add<u128> for PrefixSize {
    type Output = Self;

    fn add(self, int: u128) -> Self {
        match (self, int) {
            // Returning early in the case the integer is 0 ensures that we always have int >= 1 in
            // the next cases. We rely on it to avoid overflow.
            (_, 0) => self,
            (PrefixSize::U128(size), _) => {
                // We want to compare (size + int) to (u128::MAX + 1), but to avoid overflow we swap
                // the members. We exited early if int was 0, so we have int >= 1 and can safely
                // subtract 1.
                if int - 1 == u128::MAX - size {
                    PrefixSize::Ipv6MaxAddrs
                } else if int - 1 > u128::MAX - size {
                    PrefixSize::Overflow
                } else {
                    PrefixSize::U128(size + int)
                }
            }
            (PrefixSize::Ipv6MaxAddrs, _) => PrefixSize::Overflow,
            (PrefixSize::Overflow, _) => PrefixSize::Overflow,
        }
    }
}

impl Add<u128> for &PrefixSize {
    type Output = PrefixSize;

    fn add(self, int: u128) -> PrefixSize {
        *self + int
    }
}

impl Add<PrefixSize> for u128 {
    type Output = PrefixSize;

    fn add(self, other: PrefixSize) -> PrefixSize {
        other + self
    }
}

impl Add<&PrefixSize> for u128 {
    type Output = PrefixSize;

    fn add(self, other: &PrefixSize) -> PrefixSize {
        *other + self
    }
}

impl Add<PrefixSize> for PrefixSize {
    type Output = Self;

    fn add(self, other: PrefixSize) -> Self {
        match (self, other) {
            // This case is necessary to avoid returning PrefixSize::Overflow for
            // PrefixSize::U128(0) + PrefixSize::Ipv6MaxAddrs
            (PrefixSize::U128(0), _) => other,
            (_, PrefixSize::U128(int)) => self + int,
            (_, PrefixSize::Ipv6MaxAddrs) | (_, PrefixSize::Overflow) => PrefixSize::Overflow,
        }
    }
}

impl Add<&PrefixSize> for PrefixSize {
    type Output = Self;

    fn add(self, other: &PrefixSize) -> Self {
        self + *other
    }
}

impl Add<PrefixSize> for &PrefixSize {
    type Output = PrefixSize;

    fn add(self, other: PrefixSize) -> PrefixSize {
        *self + other
    }
}

impl Add<&PrefixSize> for &PrefixSize {
    type Output = PrefixSize;

    fn add(self, other: &PrefixSize) -> PrefixSize {
        *self + *other
    }
}

impl AddAssign<PrefixSize> for PrefixSize {
    fn add_assign(&mut self, other: PrefixSize) {
        *self = *self + other;
    }
}

impl AddAssign<&PrefixSize> for PrefixSize {
    fn add_assign(&mut self, other: &PrefixSize) {
        *self = *self + other;
    }
}

impl AddAssign<u128> for PrefixSize {
    fn add_assign(&mut self, int: u128) {
        *self = *self + int;
    }
}

impl Sum<PrefixSize> for PrefixSize {
    fn sum<I: Iterator<Item = PrefixSize>>(iter: I) -> Self {
        iter.fold(PrefixSize::U128(0), |a, b| a + b)
    }
}

impl<'a> Sum<&'a PrefixSize> for PrefixSize {
    fn sum<I: Iterator<Item = &'a PrefixSize>>(iter: I) -> Self {
        iter.fold(PrefixSize::U128(0), |a, b| a + b)
    }
}

impl Sub<u128> for PrefixSize {
    type Output = Self;

    fn sub(self, int: u128) -> Self {
        self - PrefixSize::U128(int)
    }
}

impl Sub<u128> for &PrefixSize {
    type Output = PrefixSize;

    fn sub(self, int: u128) -> PrefixSize {
        *self - int
    }
}

impl Sub<PrefixSize> for PrefixSize {
    type Output = Self;

    fn sub(self, other: PrefixSize) -> Self {
        match (self, other) {
            (_, PrefixSize::U128(0)) => self,
            (PrefixSize::U128(size_self), PrefixSize::U128(size_other)) => {
                // May panic, just like a regular subtraction
                PrefixSize::U128(size_self - size_other)
            }
            (PrefixSize::Ipv6MaxAddrs, PrefixSize::U128(size_other)) => {
                PrefixSize::U128(u128::MAX - size_other + 1)
            }
            (PrefixSize::Ipv6MaxAddrs, PrefixSize::Ipv6MaxAddrs) => PrefixSize::U128(0),
            (PrefixSize::U128(size_self), PrefixSize::Ipv6MaxAddrs) => {
                // WILL panic, just like a regular subtraction
                PrefixSize::U128(size_self - u128::MAX - 1)
            }
            _ => PrefixSize::Overflow,
        }
    }
}

impl Sub<&PrefixSize> for PrefixSize {
    type Output = Self;

    fn sub(self, other: &PrefixSize) -> Self {
        self - *other
    }
}

impl Sub<PrefixSize> for &PrefixSize {
    type Output = PrefixSize;

    fn sub(self, other: PrefixSize) -> PrefixSize {
        *self - other
    }
}

impl Sub<&PrefixSize> for &PrefixSize {
    type Output = PrefixSize;

    fn sub(self, other: &PrefixSize) -> PrefixSize {
        *self - *other
    }
}

impl PartialEq<u128> for PrefixSize {
    fn eq(&self, other: &u128) -> bool {
        match self {
            PrefixSize::U128(size) => size == other,
            _ => false,
        }
    }
}

impl PartialEq<PrefixSize> for u128 {
    fn eq(&self, other: &PrefixSize) -> bool {
        match other {
            PrefixSize::U128(size) => size == self,
            _ => false,
        }
    }
}

impl PartialOrd<u128> for PrefixSize {
    fn partial_cmp(&self, other: &u128) -> Option<Ordering> {
        match self {
            PrefixSize::U128(size) => size.partial_cmp(other),
            _ => Some(Ordering::Greater),
        }
    }
}

impl PartialOrd<PrefixSize> for u128 {
    fn partial_cmp(&self, other: &PrefixSize) -> Option<Ordering> {
        match other {
            PrefixSize::U128(size) => self.partial_cmp(size),
            _ => Some(Ordering::Less),
        }
    }
}

impl From<u128> for PrefixSize {
    fn from(value: u128) -> Self {
        PrefixSize::U128(value)
    }
}

impl TryFrom<PrefixSize> for u128 {
    type Error = PrefixError;

    fn try_from(value: PrefixSize) -> Result<Self, Self::Error> {
        match value {
            PrefixSize::U128(size) => Ok(size),
            _ => Err(PrefixError::Invalid("Invalid prefix size".to_string())),
        }
    }
}

impl TryFrom<&PrefixSize> for u128 {
    type Error = PrefixError;

    fn try_from(value: &PrefixSize) -> Result<Self, Self::Error> {
        u128::try_from(*value)
    }
}

#[cfg(test)]
mod tests {
    use crate::prefix::*;
    use serde_yml;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_prefix_v4() {
        let ipv4_addr: Ipv4Addr = "1.2.3.0".parse().expect("Bad address");
        let ipv4_pfx = Ipv4Prefix::new(ipv4_addr, 24).expect("Should succeed");
        let _prefix: Prefix = ipv4_pfx.into();
        let prefix = Prefix::from(ipv4_pfx);
        let ipv4_pfx_back: &Ipv4Prefix = (&prefix).into();
        assert_eq!(*ipv4_pfx_back, ipv4_pfx);

        let prefv4 = prefix.get_v4();
        assert_eq!(*prefv4, ipv4_pfx, "Conversion mismatch");

        assert!(prefix.covers_addr(&"1.2.3.10".parse::<IpAddr>().expect("Bad address")));
        assert!(!prefix.covers_addr(&"1.2.9.10".parse::<IpAddr>().expect("Bad address")));

        assert_eq!(prefix.size(), PrefixSize::U128(2u128.pow(32 - 24)));

        // default - root
        let address: Ipv4Addr = "0.0.0.0".parse().unwrap();
        let iptrie_pfx = Ipv4Prefix::new(address, 0).unwrap();
        let prefix = Prefix::from(iptrie_pfx);
        assert_eq!(prefix, Prefix::root_v4());
    }

    #[test]
    fn test_prefix_v6() {
        let ipv6_addr: Ipv6Addr = "2001:a:b:c::".parse().expect("Bad address");
        let ipv6_pfx = Ipv6Prefix::new(ipv6_addr, 64).expect("Should succeed");
        let _prefix: Prefix = ipv6_pfx.into();
        let prefix = Prefix::from(ipv6_pfx);
        let ipv6_pfx_back: &Ipv6Prefix = (&prefix).into();
        assert_eq!(*ipv6_pfx_back, ipv6_pfx);

        let prefv6 = prefix.get_v6();
        assert_eq!(*prefv6, ipv6_pfx, "Conversion mismatch");

        assert!(prefix.covers_addr(&"2001:a:b:c::10".parse::<IpAddr>().expect("Bad address")));
        assert!(!prefix.covers_addr(&"2001:a:b:9::10".parse::<IpAddr>().expect("Bad address")));

        assert_eq!(prefix.size(), PrefixSize::U128(2u128.pow(128 - 64)));

        // default - root
        let address: Ipv6Addr = "::".parse().unwrap();
        let iptrie_pfx = Ipv6Prefix::new(address, 0).unwrap();
        let prefix = Prefix::from(iptrie_pfx);
        assert_eq!(prefix, Prefix::root_v6());
    }

    #[test]
    fn test_prefix_try_from() {
        let prefix_v4_1 = Prefix::expect_from(("1.2.3.0", 24));
        let prefix_v4_2: Prefix = "1.2.3.0/24".into();
        let prefix_v4_3: Prefix = Prefix::expect_from(PrefixString("1.2.3.0/24"));
        let prefix_v4_4: Prefix = Ipv4Prefix::from_str("1.2.3.0/24")
            .expect("Invalid IPv4 prefix")
            .into();
        let prefix_v4_5 = Prefix::expect_from(("1.2.3.0", 24));
        let prefix_v4_6: Prefix = Ipv4Net::from_str("1.2.3.0/24")
            .expect("Invalid IPv4 prefix")
            .into();
        assert_eq!(prefix_v4_1, prefix_v4_2);
        assert_eq!(prefix_v4_1, prefix_v4_3);
        assert_eq!(prefix_v4_1, prefix_v4_4);
        assert_eq!(prefix_v4_1, prefix_v4_5);
        assert_eq!(prefix_v4_1, prefix_v4_6);

        let prefix_v6_1 = Prefix::expect_from(("2001:a:b:c::", 64));
        let prefix_v6_2: Prefix = "2001:a:b:c::/64".into();
        let prefix_v6_3: Prefix = Prefix::expect_from(PrefixString("2001:a:b:c::/64"));
        let prefix_v6_4: Prefix = Ipv6Prefix::from_str("2001:a:b:c::/64")
            .expect("Invalid IPv6 prefix")
            .into();
        let prefix_v6_5 = Prefix::expect_from(("2001:a:b:c::", 64));
        let prefix_v6_6: Prefix = Ipv6Net::from_str("2001:a:b:c::/64")
            .expect("Invalid IPv6 prefix")
            .into();
        assert_eq!(prefix_v6_1, prefix_v6_2);
        assert_eq!(prefix_v6_1, prefix_v6_3);
        assert_eq!(prefix_v6_1, prefix_v6_4);
        assert_eq!(prefix_v6_1, prefix_v6_5);
        assert_eq!(prefix_v6_1, prefix_v6_6);
    }

    #[test]
    fn test_prefix_try_from_addr_fail() {
        let prefix_v4 = Prefix::try_from(("1.2.3.X", 24));
        let prefix_v6 = Prefix::try_from(("2001:a:b:c::X", 60));
        assert!(prefix_v4.is_err());
        assert!(prefix_v6.is_err());
    }

    #[test]
    fn test_prefix_try_from_mask_fail() {
        let prefix_v4 = Prefix::try_from(("1.2.3.0", 33));
        let prefix_v6 = Prefix::try_from(("2001:a:b:c::0", 129));
        assert!(prefix_v4.is_err());
        assert!(prefix_v6.is_err());
    }

    #[test]
    fn test_serde() {
        let ipv4_addr: Ipv4Addr = "1.2.3.0".parse().expect("Bad address");
        let ipv4_pfx = Ipv4Prefix::new(ipv4_addr, 24).expect("Should succeed");
        let prefix = Prefix::from(ipv4_pfx);

        // serialize prefix as YAML
        let yaml = serde_yml::to_string(&prefix).unwrap();
        assert_eq!(yaml, "!IPV4\naddress: '1.2.3.0'\nlength: 24\n");
        let deserialized_yaml: Prefix = serde_yml::from_str(&yaml).unwrap();
        assert_eq!(prefix, deserialized_yaml);

        let ipv6_addr: Ipv6Addr = "f00:baa::".parse().expect("Bad address");
        let ipv6_pfx = Ipv6Prefix::new(ipv6_addr, 64).expect("Should succeed");
        let prefix = Prefix::from(ipv6_pfx);

        // serialize prefix as YAML
        let yaml = serde_yml::to_string(&prefix).unwrap();
        assert_eq!(yaml, "!IPV6\naddress: 'f00:baa::'\nlength: 64\n");
        let deserialized_yaml: Prefix = serde_yml::from_str(&yaml).unwrap();
        assert_eq!(prefix, deserialized_yaml);
    }

    #[test]
    fn test_prefix_size() {
        let prefix = Prefix::expect_from(("1.2.3.0", 24));
        let prefix_size1 = prefix.size();
        assert_eq!(prefix_size1, PrefixSize::U128(2u128.pow(32 - 24)));

        let prefix_size0 = PrefixSize::U128(0);
        let prefix_size_u128max = PrefixSize::U128(u128::MAX);
        let prefix_size_max = PrefixSize::Ipv6MaxAddrs;
        let prefix_size_overflow = PrefixSize::Overflow;

        assert!(prefix_size0 < prefix_size1);
        assert!(prefix_size1 < prefix_size_u128max);
        assert!(prefix_size1 < prefix_size_max);
        assert!(prefix_size1 < prefix_size_overflow);
        assert!(prefix_size_u128max < prefix_size_max);
        assert!(prefix_size_max < prefix_size_overflow);
        // Overflow is like NaN, not equal to itself
        assert!(prefix_size_overflow != prefix_size_overflow);

        assert_eq!(prefix_size0 + prefix_size1, PrefixSize::U128(2u128.pow(8)));
        assert_eq!(prefix_size_u128max + 1, prefix_size_max);
        assert!((prefix_size_max + 1).is_overflow());
        assert!((prefix_size_overflow + prefix_size1).is_overflow());

        assert_eq!(
            prefix_size_max - prefix_size1,
            PrefixSize::U128(u128::MAX - 2u128.pow(8) + 1)
        );
        assert_eq!(prefix_size_max - prefix_size_u128max, PrefixSize::U128(1));
        assert_eq!(prefix_size_max - prefix_size_max, PrefixSize::U128(0));

        assert!(prefix_size1 > 2u128.pow(8) - 1);
        assert!(prefix_size1 == 2u128.pow(8));
        assert!(prefix_size1 < 2u128.pow(8) + 1);

        assert_eq!(u128::try_from(prefix_size1).unwrap(), 2u128.pow(8));
    }

    #[test]
    fn test_bolero_prefixsize_compare() {
        bolero::check!()
            .with_generator(bolero::generator::produce::<(
                PrefixSize,
                PrefixSize,
                PrefixSize,
            )>())
            .for_each(|(one, two, three)| {
                // Transitivity for PartialOrd
                if one < two && two < three {
                    assert!(one < three);
                }

                // Duality for PartialOrd
                if one < two {
                    assert!(two > one);
                }

                if one == two {
                    // Consitency between PartialEq and PartialOrd
                    assert!(one.partial_cmp(two) == Some(Ordering::Equal));
                    // PartialEq is symmetric
                    assert!(two == one);
                }

                if let (Ok(one_int), Ok(two_int)) = (u128::try_from(one), u128::try_from(two)) {
                    if one < two {
                        assert!(one_int < two_int);
                    } else if one == two {
                        assert!(one_int == two_int);
                    } else {
                        assert!(one_int > two_int);
                    }
                };

                assert!((one + two) + three >= 0);
                assert!(vec![*one, *two, *three].iter().sum::<PrefixSize>() >= 0);
            });
    }
}
