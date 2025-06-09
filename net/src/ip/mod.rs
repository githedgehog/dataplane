// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Helper methods and types which are common between IPv4 and IPv6

use crate::ipv4::UnicastIpv4Addr;
use crate::ipv6::UnicastIpv6Addr;
use etherparse::IpNumber;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Thin wrapper around [`IpNumber`]
///
/// This exists to allow us to implement `TypeGenerator` without violating rust's orphan rules.
#[repr(transparent)]
#[derive(PartialEq, Eq, Clone, Copy, Hash, Ord, PartialOrd)]
pub struct NextHeader(pub(crate) IpNumber);

impl From<NextHeader> for IpNumber {
    fn from(value: NextHeader) -> Self {
        value.0
    }
}

impl NextHeader {
    /// TCP next header
    pub const TCP: NextHeader = NextHeader(IpNumber::TCP);

    /// UDP next header
    pub const UDP: NextHeader = NextHeader(IpNumber::UDP);

    /// ICMP next header
    pub const ICMP: NextHeader = NextHeader(IpNumber::ICMP);

    /// ICMP6 next header
    pub const ICMP6: NextHeader = NextHeader(IpNumber::IPV6_ICMP);

    /// Get the inner (wrapped) `etherparse` [`IpNumber`] type
    pub(crate) fn inner(self) -> IpNumber {
        self.0
    }

    /// Generate a new [`NextHeader`]
    #[must_use]
    pub fn new(inner: u8) -> Self {
        Self(IpNumber::from(inner))
    }

    /// Return the [`NextHeader`] represented as a `u8`
    #[must_use]
    pub fn as_u8(&self) -> u8 {
        self.0.0
    }

    /// Set the value of this [`NextHeader`] to an arbitrary `u8`
    pub fn set_u8(&mut self, inner: u8) {
        self.0 = IpNumber::from(inner);
    }
}

/// A union type for IPv4 and IPv6 unicast addresses
///
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, serde::Serialize, serde::Deserialize,
)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub enum UnicastIpAddr {
    /// A unicast Ipv4 address
    V4(UnicastIpv4Addr),
    /// A unicast Ipv6 address
    V6(UnicastIpv6Addr),
}

impl UnicastIpAddr {
    /// Get the inner (wrapped) [`IpAddr`] type
    #[must_use]
    pub fn inner(&self) -> IpAddr {
        match self {
            UnicastIpAddr::V4(ip) => IpAddr::V4(ip.inner()),
            UnicastIpAddr::V6(ip) => IpAddr::V6(ip.inner()),
        }
    }
}

impl TryFrom<IpAddr> for UnicastIpAddr {
    type Error = IpAddr;

    fn try_from(value: IpAddr) -> Result<UnicastIpAddr, IpAddr> {
        match value {
            IpAddr::V4(ip) => Ok(UnicastIpAddr::V4(
                UnicastIpv4Addr::new(ip).map_err(IpAddr::V4)?,
            )),
            IpAddr::V6(ip) => Ok(UnicastIpAddr::V6(
                UnicastIpv6Addr::new(ip).map_err(IpAddr::V6)?,
            )),
        }
    }
}

impl From<UnicastIpAddr> for IpAddr {
    fn from(value: UnicastIpAddr) -> Self {
        match value {
            UnicastIpAddr::V4(ip) => IpAddr::V4(ip.inner()),
            UnicastIpAddr::V6(ip) => IpAddr::V6(ip.inner()),
        }
    }
}

impl From<UnicastIpv4Addr> for UnicastIpAddr {
    fn from(value: UnicastIpv4Addr) -> Self {
        UnicastIpAddr::V4(value)
    }
}

impl From<UnicastIpv6Addr> for UnicastIpAddr {
    fn from(value: UnicastIpv6Addr) -> Self {
        UnicastIpAddr::V6(value)
    }
}

impl TryFrom<Ipv4Addr> for UnicastIpAddr {
    type Error = Ipv4Addr;

    fn try_from(value: Ipv4Addr) -> Result<Self, Self::Error> {
        Ok(UnicastIpAddr::V4(UnicastIpv4Addr::new(value)?))
    }
}

impl TryFrom<Ipv6Addr> for UnicastIpAddr {
    type Error = Ipv6Addr;

    fn try_from(value: Ipv6Addr) -> Result<Self, Self::Error> {
        Ok(UnicastIpAddr::V6(UnicastIpv6Addr::new(value)?))
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::ip::NextHeader;
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for NextHeader {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(NextHeader::new(driver.produce()?))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ip::UnicastIpAddr;
    use crate::ipv4::UnicastIpv4Addr;
    use crate::ipv6::UnicastIpv6Addr;
    use std::net::IpAddr;

    #[test]
    fn generated_unicast_ip_address_is_unicast() {
        bolero::check!()
            .with_type()
            .for_each(|ip: &UnicastIpAddr| match ip {
                UnicastIpAddr::V4(ip) => assert!(!ip.inner().is_multicast()),
                UnicastIpAddr::V6(ip) => assert!(!ip.inner().is_multicast()),
            });
    }

    #[test]
    fn unicast_ipv4_is_unicast_ip() {
        bolero::check!()
            .with_type()
            .cloned()
            .for_each(|ipv4: UnicastIpv4Addr| {
                let ip: UnicastIpAddr = ipv4.inner().try_into().unwrap();
                match ip {
                    UnicastIpAddr::V4(ip) => assert_eq!(ip, ipv4),
                    UnicastIpAddr::V6(_) => unreachable!(),
                }
            });
    }

    #[test]
    fn unicast_ipv6_is_unicast_ip() {
        bolero::check!()
            .with_type()
            .cloned()
            .for_each(|ipv6: UnicastIpv6Addr| {
                let ip: UnicastIpAddr = ipv6.inner().try_into().unwrap();
                match ip {
                    UnicastIpAddr::V4(_) => unreachable!(),
                    UnicastIpAddr::V6(ip) => assert_eq!(ip, ipv6),
                }
            });
    }

    #[test]
    fn try_from_obeys_contract() {
        bolero::check!()
            .with_type()
            .cloned()
            .for_each(|ip: IpAddr| {
                if ip.is_multicast() {
                    let multicast_ip = UnicastIpAddr::try_from(ip).unwrap_err();
                    assert!(multicast_ip.is_multicast());
                    assert_eq!(ip, multicast_ip);
                } else {
                    let unicast_ip = UnicastIpAddr::try_from(ip).unwrap();
                    assert!(!unicast_ip.inner().is_multicast());
                    assert_eq!(ip, IpAddr::from(unicast_ip));
                }
            });
    }
}
