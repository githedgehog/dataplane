//! Ipv6 Address type and manipulation

use core::net::Ipv6Addr;
#[cfg(any(test, feature = "bolero", kani))]
use bolero::Driver;

/// Thin wrapper around [`Ipv6Addr`].
///
/// The functionality in the base [`Ipv6Addr`] is sufficient, but we need
/// to wrap this class to allow bolero to generate ip addresses.
#[must_use]
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Ipv6Address {
    /// inner (wrapped) std library [`Ipv6Addr`]
    pub addr: Ipv6Addr,
}

#[cfg(any(test, feature = "bolero", kani))]
impl bolero::TypeGenerator for Ipv6Address {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        Some(Ipv6Address {
            addr: Ipv6Addr::from(driver.gen::<u128>()?),
        })
    }
}

impl From<Ipv6Address> for Ipv6Addr {
    fn from(value: Ipv6Address) -> Self {
        value.addr
    }
}

impl From<Ipv6Addr> for Ipv6Address {
    fn from(value: Ipv6Addr) -> Self {
        Ipv6Address { addr: value }
    }
}

impl AsRef<Ipv6Addr> for Ipv6Address {
    fn as_ref(&self) -> &Ipv6Addr {
        &self.addr
    }
}

impl From<[u8; 16]> for Ipv6Address {
    fn from(value: [u8; 16]) -> Self {
        Ipv6Address { addr: value.into() }
    }
}

impl From<Ipv6Address> for [u8; 16] {
    fn from(value: Ipv6Address) -> Self {
        value.addr.octets()
    }
}
