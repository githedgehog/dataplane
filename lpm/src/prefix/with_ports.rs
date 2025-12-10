// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::prefix::{Prefix, PrefixSize};
use bnum::BUint;
use std::fmt::Display;

/// A type for the size of IP/port combinations for IP prefixes with associated port ranges.
/// We need something larger than u128 to cover all possible combinations: the maximum value is
/// `(u128::MAX + 1) * (u16::MAX + 1)`.
pub type PrefixWithPortsSize = BUint<3>;

/// Trait for IP ranges (CIDR prefix or simple ranges) with associated port ranges.
pub trait IpRangeWithPorts {
    /// Returns the address range length.
    fn addr_range_len(&self) -> PrefixSize;
    /// Returns the port range length.
    fn port_range_len(&self) -> usize;
    /// Returns true if the range fully covers (contains) the given other range.
    fn covers(&self, other: &Self) -> bool;
    /// Returns true if the range overlaps with the given other range.
    fn overlaps(&self, other: &Self) -> bool;
    /// Returns the total number of (IP, port) combinations covered by the IP and port ranges.
    fn size(&self) -> PrefixWithPortsSize {
        let ip_len = match self.addr_range_len() {
            PrefixSize::U128(len) => PrefixWithPortsSize::from(len),
            PrefixSize::Ipv6MaxAddrs => PrefixWithPortsSize::from(u128::MAX) + 1,
            PrefixSize::Overflow => unreachable!(),
        };
        ip_len * PrefixWithPortsSize::from(self.port_range_len())
    }
}

/// A structure containing a prefix and a port range.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrefixWithPorts {
    prefix: Prefix,
    ports: PortRange,
}

impl PrefixWithPorts {
    /// Creates a new [`PrefixWithPorts`] from a prefix and a port range.
    #[must_use]
    pub fn new(prefix: Prefix, ports: PortRange) -> Self {
        Self { prefix, ports }
    }

    /// Returns the prefix.
    #[must_use]
    pub fn prefix(&self) -> Prefix {
        self.prefix
    }

    /// Returns the port range.
    #[must_use]
    pub fn ports(&self) -> PortRange {
        self.ports
    }
}

impl IpRangeWithPorts for PrefixWithPorts {
    fn addr_range_len(&self) -> PrefixSize {
        self.prefix.size()
    }

    fn port_range_len(&self) -> usize {
        self.ports.len()
    }

    fn covers(&self, other: &Self) -> bool {
        self.prefix.covers(&other.prefix) && self.ports.covers(other.ports)
    }

    fn overlaps(&self, other: &Self) -> bool {
        self.prefix.collides_with(&other.prefix) && self.ports.overlaps(other.ports)
    }
}

/// A structure containing a prefix and an optional port range.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrefixWithOptionalPorts {
    prefix: Prefix,
    ports: Option<PortRange>,
}

impl PrefixWithOptionalPorts {
    /// Creates a new `PrefixWithOptionalPorts` from a prefix and an optional port range.
    #[must_use]
    pub fn new(prefix: Prefix, ports: Option<PortRange>) -> Self {
        Self { prefix, ports }
    }

    /// Returns the prefix.
    #[must_use]
    pub fn prefix(&self) -> Prefix {
        self.prefix
    }

    /// Returns the optional port range.
    #[must_use]
    pub fn ports(&self) -> Option<PortRange> {
        self.ports
    }
}

impl IpRangeWithPorts for PrefixWithOptionalPorts {
    fn addr_range_len(&self) -> PrefixSize {
        self.prefix.size()
    }

    fn port_range_len(&self) -> usize {
        self.ports
            .as_ref()
            .map_or(PortRange::MAX_LENGTH, PortRange::len)
    }

    fn covers(&self, other: &Self) -> bool {
        match (self.ports, other.ports) {
            (Some(self_ports), Some(other_ports)) => {
                self.prefix.covers(&other.prefix) && self_ports.covers(other_ports)
            }
            (Some(self_ports), None) if self_ports.len() == PortRange::MAX_LENGTH => {
                // All ports contained in both instances, so we only check prefixes
                self.prefix.covers(&other.prefix)
            }
            (Some(_), None) => false, // Other ranges has ports not covered
            _ => {
                // We necessarily cover all prefixes from the other instance, only check prefixes
                self.prefix.covers(&other.prefix)
            }
        }
    }

    fn overlaps(&self, other: &Self) -> bool {
        match (self.ports, other.ports) {
            (Some(self_ports), Some(other_ports)) => {
                self.prefix.collides_with(&other.prefix) && self_ports.overlaps(other_ports)
            }
            _ => self.prefix.collides_with(&other.prefix),
        }
    }
}

/// Error type for [`PortRange`] operations.
#[derive(Debug, thiserror::Error)]
pub enum PortRangeError {
    /// The start port is greater than the end port.
    #[error("Invalid port range: {0} > {1}")]
    InvalidRange(u16, u16),
    /// The port range is not empty, but should be.
    #[error("Non-empty port range (expected empty)")]
    SomePortRange,
}

impl From<PrefixWithPorts> for PrefixWithOptionalPorts {
    fn from(value: PrefixWithPorts) -> Self {
        PrefixWithOptionalPorts {
            prefix: value.prefix,
            ports: Some(value.ports),
        }
    }
}

impl From<PrefixWithOptionalPorts> for PrefixWithPorts {
    fn from(p: PrefixWithOptionalPorts) -> Self {
        match p.ports {
            Some(ports) => PrefixWithPorts {
                prefix: p.prefix,
                ports,
            },
            None => PrefixWithPorts {
                prefix: p.prefix,
                ports: PortRange::new_max_range(),
            },
        }
    }
}

impl<T> From<T> for PrefixWithOptionalPorts
where
    T: Into<Prefix>,
{
    fn from(value: T) -> Self {
        PrefixWithOptionalPorts {
            prefix: value.into(),
            ports: None,
        }
    }
}

impl TryFrom<PrefixWithOptionalPorts> for Prefix {
    type Error = PortRangeError;

    fn try_from(p: PrefixWithOptionalPorts) -> Result<Self, Self::Error> {
        match p.ports {
            Some(_) => Err(PortRangeError::SomePortRange),
            None => Ok(p.prefix),
        }
    }
}

/// A port range, with a start and an end port (both included in the range).
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PortRange {
    start: u16,
    end: u16,
}

impl PortRange {
    /// Maximum length of a port range (65536 ports).
    pub const MAX_LENGTH: usize = u16::MAX as usize + 1;

    /// Creates a new `PortRange` from a start and an end port.
    ///
    /// # Errors
    ///
    /// Returns `PortRangeError::InvalidRange` if the start port is greater than the end port.
    pub fn new(start: u16, end: u16) -> Result<Self, PortRangeError> {
        if start > end {
            return Err(PortRangeError::InvalidRange(start, end));
        }
        Ok(Self { start, end })
    }

    /// Creates a new `PortRange` that covers all ports.
    #[must_use]
    pub const fn new_max_range() -> Self {
        Self {
            start: 0,
            end: u16::MAX,
        }
    }

    /// Checks if the port range covers another port range.
    #[must_use]
    pub fn covers(&self, other: Self) -> bool {
        self.start <= other.start && other.end <= self.end
    }

    /// Checks if two port ranges overlap.
    #[must_use]
    pub fn overlaps(&self, other: Self) -> bool {
        self.start <= other.start && other.start <= self.end
            || self.start <= other.end && other.end <= self.end
            || other.start <= self.start && self.end <= other.end
    }

    /// Returns the start port of the range.
    #[must_use]
    pub fn start(&self) -> u16 {
        self.start
    }

    /// Returns the end port of the range.
    #[must_use]
    pub fn end(&self) -> u16 {
        self.end
    }

    /// Returns the number of ports in the range.
    #[must_use]
    #[allow(clippy::len_without_is_empty)] // Never empty by construction
    pub fn len(&self) -> usize {
        usize::from(self.end - self.start) + 1
    }

    /// Returns the port at the given offset in the range.
    #[must_use]
    pub fn get_entry(self, offset: u16) -> Option<u16> {
        if usize::from(offset) >= self.len() {
            return None;
        }
        Some(self.start + offset)
    }
}

impl Display for PortRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.start, self.end)
    }
}

impl Display for PrefixWithPorts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} <{}>", self.prefix, self.ports)
    }
}

impl Display for PrefixWithOptionalPorts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.ports() {
            Some(ports) => write!(f, "({} <{}>)", self.prefix, ports),
            None => write!(f, "({} </>)", self.prefix),
        }
    }
}
