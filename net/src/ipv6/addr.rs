// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! IPv6 address subclasses

#[allow(unused_imports)] // deliberate re-export
#[cfg(any(test, feature = "bolero"))]
pub use contract::*;
use std::fmt::{Debug, Display, Formatter};
use std::net::{IpAddr, Ipv6Addr};

/// A type representing the set of unicast ipv6 addresses.
#[non_exhaustive]
#[repr(transparent)]
#[derive(
    Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct UnicastIpv6Addr(Ipv6Addr);

impl Debug for UnicastIpv6Addr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Display for UnicastIpv6Addr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl UnicastIpv6Addr {
    /// Returns the supplied [`Ipv6Addr`] as a [`UnicastIpv6Addr`]
    /// after confirming that it is in fact unicast.
    ///
    /// # Errors
    ///
    /// Returns the supplied [`Ipv6Addr`] in the [`Err`] case if the supplied address is multicast.
    pub fn new(addr: Ipv6Addr) -> Result<UnicastIpv6Addr, Ipv6Addr> {
        if addr.is_multicast() {
            Err(addr)
        } else {
            Ok(UnicastIpv6Addr(addr))
        }
    }

    /// Return the inner (unqualified) [`Ipv6Addr`]
    #[must_use]
    pub const fn inner(self) -> Ipv6Addr {
        self.0
    }
}

impl From<UnicastIpv6Addr> for Ipv6Addr {
    fn from(value: UnicastIpv6Addr) -> Self {
        value.inner()
    }
}

impl TryFrom<IpAddr> for UnicastIpv6Addr {
    type Error = IpAddr;
    fn try_from(value: IpAddr) -> Result<Self, Self::Error> {
        match value {
            IpAddr::V6(addr) => Ok(UnicastIpv6Addr(addr)),
            IpAddr::V4(_) => Err(value),
        }
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::ipv6::addr::UnicastIpv6Addr;
    use bolero::{Driver, TypeGenerator};
    use std::net::Ipv6Addr;

    impl TypeGenerator for UnicastIpv6Addr {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let ip = Ipv6Addr::from(driver.produce::<u128>()?);
            // multicast ipv6 addresses begin with 0xFF
            // map back to unicast space if we hit a multicast address
            if ip.is_multicast() {
                let mut octets = ip.octets();
                octets[0] ^= 1;
                return Some(UnicastIpv6Addr(Ipv6Addr::from(octets)));
            }
            Some(UnicastIpv6Addr(ip))
        }
    }
}

#[cfg(test)]
mod test {
    use crate::ipv4::addr::UnicastIpv4Addr;

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn generated_unicast_ipv4_address_is_unicast() {
        bolero::check!()
            .with_type()
            .for_each(|unicast: &UnicastIpv4Addr| assert!(!unicast.inner().is_multicast()));
    }
}
