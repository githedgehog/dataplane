//! IPv4 address type

use std::net::Ipv4Addr;

/// Thin wrapper around [`Ipv4Addr`].
///
/// The functionality in the base [`Ipv4Addr`] is sufficient, but we need
/// to wrap this class to allow proptest to generate ip addresses.
#[must_use]
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Ipv4Address {
    /// inner (wrapped) std library [`Ipv4Addr`]
    pub addr: Ipv4Addr,
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
