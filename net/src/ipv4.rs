//! Ipv4 Address type and manipulation

use core::net::Ipv4Addr;
#[cfg(any(test, feature = "bolero", kani))]
use bolero::Driver;

/// Thin wrapper around [`Ipv4Addr`].
///
/// The functionality in the base [`Ipv4Addr`] is sufficient, but we need
/// to wrap this class to allow bolero to generate ip addresses.
#[must_use]
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Ipv4Address {
    /// inner (wrapped) std library [`Ipv4Addr`]
    pub addr: Ipv4Addr,
}

#[cfg(any(test, feature = "bolero", kani))]
impl bolero::TypeGenerator for Ipv4Address {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        Some(Ipv4Address {
            addr: Ipv4Addr::from(driver.gen::<u32>()?),
        })
    }
}

impl From<Ipv4Address> for Ipv4Addr {
    fn from(value: Ipv4Address) -> Self {
        value.addr
    }
}

impl From<Ipv4Addr> for Ipv4Address {
    fn from(value: Ipv4Addr) -> Self {
        Ipv4Address { addr: value }
    }
}

impl AsRef<Ipv4Addr> for Ipv4Address {
    fn as_ref(&self) -> &Ipv4Addr {
        &self.addr
    }
}

impl From<[u8; 4]> for Ipv4Address {
    fn from(value: [u8; 4]) -> Self {
        Ipv4Address { addr: value.into() }
    }
}

impl From<Ipv4Address> for [u8; 4] {
    fn from(value: Ipv4Address) -> Self {
        value.addr.octets()
    }
}
