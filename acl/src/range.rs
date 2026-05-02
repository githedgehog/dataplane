// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Range and prefix types for ACL match fields.

use std::net::{Ipv4Addr, Ipv6Addr};

/// An inclusive port range `[min, max]`.
///
/// Generic over the port type (`TcpPort` or `UdpPort`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortRange<P> {
    /// Lower bound (inclusive).
    pub min: P,
    /// Upper bound (inclusive).
    pub max: P,
}

impl<P: Copy + Ord> PortRange<P> {
    /// Create a port range.
    ///
    /// Returns `None` if `min > max`.
    #[must_use]
    pub fn new(min: P, max: P) -> Option<Self> {
        if min > max {
            return None;
        }
        Some(Self { min, max })
    }

    /// A range matching exactly one port.
    #[must_use]
    pub fn exact(port: P) -> Self {
        Self {
            min: port,
            max: port,
        }
    }
}

/// An IPv4 address prefix (network + prefix length).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Prefix {
    addr: Ipv4Addr,
    prefix_len: u8,
}

/// Error constructing an [`Ipv4Prefix`].
#[derive(Debug, thiserror::Error)]
pub enum Ipv4PrefixError {
    /// Prefix length exceeds 32.
    #[error("IPv4 prefix length {0} exceeds 32")]
    LengthTooLong(u8),
    /// Host bits are set beyond the prefix length.
    #[error("host bits set in address {addr} for /{prefix_len}")]
    HostBitsSet {
        /// The address with host bits set.
        addr: Ipv4Addr,
        /// The prefix length that was requested.
        prefix_len: u8,
    },
}

impl Ipv4Prefix {
    /// Create a new prefix, validating length and that host bits are zero.
    ///
    /// # Errors
    ///
    /// Returns [`Ipv4PrefixError::LengthTooLong`] if `prefix_len > 32`,
    /// or [`Ipv4PrefixError::HostBitsSet`] if any bits beyond the prefix
    /// are non-zero in `addr`.
    pub fn new(addr: Ipv4Addr, prefix_len: u8) -> Result<Self, Ipv4PrefixError> {
        if prefix_len > 32 {
            return Err(Ipv4PrefixError::LengthTooLong(prefix_len));
        }
        let mask = if prefix_len == 0 {
            0u32
        } else {
            u32::MAX << (32 - prefix_len)
        };
        let bits = u32::from(addr);
        if bits & !mask != 0 {
            return Err(Ipv4PrefixError::HostBitsSet { addr, prefix_len });
        }
        Ok(Self { addr, prefix_len })
    }

    /// A /32 prefix matching a single host.
    #[must_use]
    pub fn host(addr: Ipv4Addr) -> Self {
        Self {
            addr,
            prefix_len: 32,
        }
    }

    /// The default route prefix `0.0.0.0/0` (matches everything).
    #[must_use]
    pub fn any() -> Self {
        Self {
            addr: Ipv4Addr::UNSPECIFIED,
            prefix_len: 0,
        }
    }

    /// The network address.
    #[must_use]
    pub fn addr(&self) -> Ipv4Addr {
        self.addr
    }

    /// The prefix length in bits.
    #[must_use]
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// The prefix mask as a 32-bit integer.
    #[must_use]
    pub fn mask(&self) -> u32 {
        if self.prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix_len)
        }
    }
}

/// An IPv6 address prefix (network + prefix length).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6Prefix {
    addr: Ipv6Addr,
    prefix_len: u8,
}

/// Error constructing an [`Ipv6Prefix`].
#[derive(Debug, thiserror::Error)]
pub enum Ipv6PrefixError {
    /// Prefix length exceeds 128.
    #[error("IPv6 prefix length {0} exceeds 128")]
    LengthTooLong(u8),
    /// Host bits are set beyond the prefix length.
    #[error("host bits set in address {addr} for /{prefix_len}")]
    HostBitsSet {
        /// The address with host bits set.
        addr: Ipv6Addr,
        /// The prefix length that was requested.
        prefix_len: u8,
    },
}

impl Ipv6Prefix {
    /// Create a new prefix, validating length and that host bits are zero.
    ///
    /// # Errors
    ///
    /// Returns [`Ipv6PrefixError::LengthTooLong`] if `prefix_len > 128`,
    /// or [`Ipv6PrefixError::HostBitsSet`] if any bits beyond the prefix
    /// are non-zero in `addr`.
    pub fn new(addr: Ipv6Addr, prefix_len: u8) -> Result<Self, Ipv6PrefixError> {
        if prefix_len > 128 {
            return Err(Ipv6PrefixError::LengthTooLong(prefix_len));
        }
        let mask = if prefix_len == 0 {
            0u128
        } else {
            u128::MAX << (128 - prefix_len)
        };
        let bits = u128::from(addr);
        if bits & !mask != 0 {
            return Err(Ipv6PrefixError::HostBitsSet { addr, prefix_len });
        }
        Ok(Self { addr, prefix_len })
    }

    /// A /128 prefix matching a single host.
    #[must_use]
    pub fn host(addr: Ipv6Addr) -> Self {
        Self {
            addr,
            prefix_len: 128,
        }
    }

    /// The default route prefix `::/0` (matches everything).
    #[must_use]
    pub fn any() -> Self {
        Self {
            addr: Ipv6Addr::UNSPECIFIED,
            prefix_len: 0,
        }
    }

    /// The network address.
    #[must_use]
    pub fn addr(&self) -> Ipv6Addr {
        self.addr
    }

    /// The prefix length in bits.
    #[must_use]
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// The prefix mask as a 128-bit integer.
    #[must_use]
    pub fn mask(&self) -> u128 {
        if self.prefix_len == 0 {
            0
        } else {
            u128::MAX << (128 - self.prefix_len)
        }
    }
}
