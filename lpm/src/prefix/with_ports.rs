// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::prefix::range_map::UpperBoundFrom;
use crate::prefix::{Prefix, PrefixSize};
use bnum::BUint;
use std::fmt::Display;
use std::ops::{Bound, RangeBounds};

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
    /// Returns the intersection of the two ranges, if any.
    fn intersection(&self, other: &Self) -> Option<Self>
    where
        Self: Sized;
    /// Returns the subtraction of the two ranges, if any.
    fn subtract(&self, other: &Self) -> Vec<Self>
    where
        Self: Sized;
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

    fn intersection(&self, other: &Self) -> Option<Self> {
        Some(Self::new(
            self.prefix.intersection(&other.prefix)?,
            self.ports.intersection(other.ports)?,
        ))
    }

    fn subtract(&self, other: &Self) -> Vec<Self> {
        let mut result = Vec::new();
        if !self.overlaps(other) {
            return result;
        }

        // Keep all ports for self.prefix() that are not excluded
        for ports in self.ports.subtract(other.ports) {
            result.push(Self::new(self.prefix(), ports));
        }
        // Then for IPs that are not covered by other.prefix, add other.ports
        for prefix in self.prefix.subtract(&other.prefix) {
            if let Some(ports) = self.ports().intersection(other.ports) {
                result.push(Self::new(prefix, ports));
            }
        }
        result
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

    fn intersection(&self, other: &Self) -> Option<Self> {
        match (self.ports, other.ports) {
            (Some(self_ports), Some(other_ports)) => Some(Self::new(
                self.prefix.intersection(&other.prefix)?,
                Some(self_ports.intersection(other_ports)?),
            )),
            (Some(ports), None) | (None, Some(ports)) => Some(Self::new(
                self.prefix.intersection(&other.prefix)?,
                Some(ports),
            )),
            (None, None) => Some(Self::new(self.prefix.intersection(&other.prefix)?, None)),
        }
    }

    fn subtract(&self, other: &Self) -> Vec<Self> {
        fn convert_result_type<P>(
            vector: Vec<P>,
            convert_ports: bool,
        ) -> Vec<PrefixWithOptionalPorts>
        where
            P: Into<PrefixWithOptionalPorts>,
        {
            vector
                .into_iter()
                .map(Into::into)
                .map(|p| {
                    if convert_ports
                        && let Some(ports) = p.ports()
                        && ports.is_max_range()
                    {
                        PrefixWithOptionalPorts::new(p.prefix(), None)
                    } else {
                        p
                    }
                })
                .collect()
        }

        if !self.overlaps(other) {
            return Vec::new();
        }

        match (self.ports, other.ports) {
            (Some(self_ports), Some(other_ports)) => convert_result_type(
                PrefixWithPorts::new(self.prefix, self_ports)
                    .subtract(&PrefixWithPorts::new(other.prefix, other_ports)),
                false,
            ),
            (Some(self_ports), None) => convert_result_type(
                PrefixWithPorts::new(self.prefix, self_ports).subtract(&PrefixWithPorts::new(
                    other.prefix,
                    PortRange::new(0, u16::MAX).unwrap_or_else(|_| unreachable!()),
                )),
                false,
            ),
            (None, Some(other_ports)) => convert_result_type(
                PrefixWithPorts::new(
                    self.prefix,
                    PortRange::new(0, u16::MAX).unwrap_or_else(|_| unreachable!()),
                )
                .subtract(&PrefixWithPorts::new(other.prefix, other_ports)),
                true,
            ),
            (None, None) => convert_result_type(self.prefix.subtract(&other.prefix), false),
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

    /// Checks if the port range covers all existing ports.
    #[must_use]
    pub fn is_max_range(&self) -> bool {
        *self == Self::new_max_range()
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

    /// Returns the intersection of two port ranges.
    #[must_use]
    pub fn intersection(&self, other: Self) -> Option<Self> {
        if !self.overlaps(other) {
            return None;
        }
        let start = self.start.max(other.start);
        let end = self.end.min(other.end);
        Some(Self { start, end })
    }

    /// Returns the subtraction of two port ranges.
    #[must_use]
    pub fn subtract(&self, other: Self) -> Vec<Self> {
        let mut result = Vec::new();
        if self.start < other.start {
            result.push(Self::new(self.start, other.start - 1).unwrap_or_else(|_| unreachable!()));
        }
        if self.end > other.end {
            result.push(Self::new(other.end + 1, self.end).unwrap_or_else(|_| unreachable!()));
        }
        result
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

// Used for DisjointRangesBTreeMap
impl UpperBoundFrom<u16> for PortRange {
    fn upper_bound_from(port: u16) -> Self {
        Self {
            start: port,
            end: u16::MAX,
        }
    }
}

// Used for DisjointRangesBTreeMap
impl RangeBounds<u16> for PortRange {
    fn start_bound(&self) -> Bound<&u16> {
        Bound::Included(&self.start)
    }
    fn end_bound(&self) -> Bound<&u16> {
        Bound::Included(&self.end)
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
