//! IPv6 addressing
use std::net::Ipv6Addr;

/// Thin wrapper around [`Ipv6Addr`].
///
/// The functionality in the base [`Ipv6Addr`] is sufficient, but we need
/// to wrap this class to allow proptest to generate ip addresses.
#[must_use]
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Ipv6Address {
    /// inner (wrapped) std library [`Ipv6Addr`]
    pub addr: Ipv6Addr,
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
