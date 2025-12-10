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

    /// Merges the given range into this range if possible.
    ///
    /// # Returns
    ///
    /// Returns `Some(())` if the ranges were merged, `None` otherwise.
    pub fn merge(&mut self, next: PortRange) -> Option<()> {
        if self.start > next.start || self.end >= next.start {
            return None;
        }
        if self.end + 1 == next.start {
            self.end = next.end;
            return Some(());
        }
        None
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prefix::{Ipv4Prefix, Ipv6Prefix};
    use std::str::FromStr;

    fn prefix_v4(s: &str) -> Prefix {
        Prefix::from(Ipv4Prefix::from_str(s).unwrap())
    }

    fn prefix_v6(s: &str) -> Prefix {
        Prefix::from(Ipv6Prefix::from_str(s).unwrap())
    }

    // PrefixWithPorts - intersection

    #[test]
    fn test_prefix_with_ports_intersection_overlapping() {
        let prefix1 = prefix_v4("192.168.0.0/24");
        let prefix2 = prefix_v4("192.168.0.0/25");
        let ports1 = PortRange::new(80, 100).unwrap();
        let ports2 = PortRange::new(90, 110).unwrap();

        let pwp1 = PrefixWithPorts::new(prefix1, ports1);
        let pwp2 = PrefixWithPorts::new(prefix2, ports2);

        let intersection = pwp1.intersection(&pwp2).expect("Should have intersection");
        assert_eq!(intersection.prefix(), prefix2);
        assert_eq!(intersection.ports(), PortRange::new(90, 100).unwrap());
    }

    #[test]
    fn test_prefix_with_ports_intersection_no_prefix_overlap() {
        let prefix1 = prefix_v4("192.168.0.0/24");
        let prefix2 = prefix_v4("10.0.0.0/24");
        let ports = PortRange::new(80, 100).unwrap();

        let pwp1 = PrefixWithPorts::new(prefix1, ports);
        let pwp2 = PrefixWithPorts::new(prefix2, ports);

        let intersection = pwp1.intersection(&pwp2);
        assert!(intersection.is_none());
    }

    #[test]
    fn test_prefix_with_ports_intersection_no_port_overlap() {
        let prefix = prefix_v4("192.168.0.0/24");
        let ports1 = PortRange::new(80, 100).unwrap();
        let ports2 = PortRange::new(200, 300).unwrap();

        let pwp1 = PrefixWithPorts::new(prefix, ports1);
        let pwp2 = PrefixWithPorts::new(prefix, ports2);

        let intersection = pwp1.intersection(&pwp2);
        assert!(intersection.is_none());
    }

    #[test]
    fn test_prefix_with_ports_intersection_identical() {
        let prefix = prefix_v4("192.168.0.0/24");
        let ports = PortRange::new(80, 100).unwrap();

        let pwp = PrefixWithPorts::new(prefix, ports);

        let intersection = pwp.intersection(&pwp).expect("Should have intersection");
        assert_eq!(intersection, pwp);
    }

    #[test]
    fn test_prefix_with_ports_intersection_ipv6() {
        let prefix1 = prefix_v6("2001:db8::/32");
        let prefix2 = prefix_v6("2001:db8::/48");
        let ports = PortRange::new(443, 8443).unwrap();

        let pwp1 = PrefixWithPorts::new(prefix1, ports);
        let pwp2 = PrefixWithPorts::new(prefix2, ports);

        let intersection = pwp1.intersection(&pwp2).expect("Should have intersection");
        assert_eq!(intersection.prefix(), prefix2);
        assert_eq!(intersection.ports(), ports);
    }

    // PrefixWithPorts - subtract

    #[test]
    fn test_prefix_with_ports_subtract_no_overlap() {
        let prefix1 = prefix_v4("192.168.0.0/24");
        let prefix2 = prefix_v4("10.0.0.0/24");
        let ports = PortRange::new(80, 100).unwrap();

        let pwp1 = PrefixWithPorts::new(prefix1, ports);
        let pwp2 = PrefixWithPorts::new(prefix2, ports);

        let result = pwp1.subtract(&pwp2);
        assert!(result.is_empty());
    }

    #[test]
    fn test_prefix_with_ports_subtract_identical() {
        let prefix = prefix_v4("192.168.0.0/24");
        let ports = PortRange::new(80, 100).unwrap();

        let pwp = PrefixWithPorts::new(prefix, ports);

        let result = pwp.subtract(&pwp);
        assert!(result.is_empty());
    }

    #[test]
    fn test_prefix_with_ports_subtract_port_split() {
        let prefix = prefix_v4("192.168.0.0/24");
        let ports1 = PortRange::new(80, 200).unwrap();
        let ports2 = PortRange::new(100, 150).unwrap();

        let pwp1 = PrefixWithPorts::new(prefix, ports1);
        let pwp2 = PrefixWithPorts::new(prefix, ports2);

        let result = pwp1.subtract(&pwp2);
        // Should split into two port ranges: [80-99] and [151-200]
        assert_eq!(result.len(), 2);
        assert!(result.contains(&PrefixWithPorts::new(
            prefix,
            PortRange::new(80, 99).unwrap()
        )));
        assert!(result.contains(&PrefixWithPorts::new(
            prefix,
            PortRange::new(151, 200).unwrap()
        )));
    }

    #[test]
    fn test_prefix_with_ports_subtract_prefix_split() {
        let prefix1 = prefix_v4("192.168.0.0/23");
        let prefix2 = prefix_v4("192.168.0.0/24");
        let ports = PortRange::new(80, 100).unwrap();

        let pwp1 = PrefixWithPorts::new(prefix1, ports);
        let pwp2 = PrefixWithPorts::new(prefix2, ports);

        let result = pwp1.subtract(&pwp2);
        // Should have one remaining prefix: 192.168.1.0/24
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].prefix(), prefix_v4("192.168.1.0/24"));
        assert_eq!(result[0].ports(), ports);
    }

    #[test]
    fn test_prefix_with_ports_subtract_both_split() {
        let prefix1 = prefix_v4("192.168.0.0/23");
        let prefix2 = prefix_v4("192.168.0.0/24");
        let ports1 = PortRange::new(80, 200).unwrap();
        let ports2 = PortRange::new(100, 150).unwrap();

        let pwp1 = PrefixWithPorts::new(prefix1, ports1);
        let pwp2 = PrefixWithPorts::new(prefix2, ports2);

        let result = pwp1.subtract(&pwp2);
        // Expected result: 3 PrefixWithPorts
        // - 192.168.0.0/23 [80-99]
        // - 192.168.1.0/24 [100-150]
        // - 192.168.0.0/23 [151-200]
        assert_eq!(result.len(), 3);
        assert!(result.contains(&PrefixWithPorts::new(
            prefix1,
            PortRange::new(80, 99).unwrap()
        )));
        assert!(result.contains(&PrefixWithPorts::new(
            prefix_v4("192.168.1.0/24"),
            PortRange::new(100, 150).unwrap()
        )));
        assert!(result.contains(&PrefixWithPorts::new(
            prefix1,
            PortRange::new(151, 200).unwrap()
        )));
    }

    #[test]
    fn test_prefix_with_ports_subtract_partial_port_overlap_lower() {
        let prefix = prefix_v4("192.168.0.0/24");
        let ports1 = PortRange::new(80, 150).unwrap();
        let ports2 = PortRange::new(50, 100).unwrap();

        let pwp1 = PrefixWithPorts::new(prefix, ports1);
        let pwp2 = PrefixWithPorts::new(prefix, ports2);

        let result = pwp1.subtract(&pwp2);
        // Should have remaining port range [101-150]
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            PrefixWithPorts::new(prefix, PortRange::new(101, 150).unwrap())
        );
    }

    #[test]
    fn test_prefix_with_ports_subtract_partial_port_overlap_upper() {
        let prefix = prefix_v4("192.168.0.0/24");
        let ports1 = PortRange::new(80, 150).unwrap();
        let ports2 = PortRange::new(120, 200).unwrap();

        let pwp1 = PrefixWithPorts::new(prefix, ports1);
        let pwp2 = PrefixWithPorts::new(prefix, ports2);

        let result = pwp1.subtract(&pwp2);
        // Should have remaining port range [80-119]
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            PrefixWithPorts::new(prefix, PortRange::new(80, 119).unwrap())
        );
    }

    // PrefixWithOptionalPorts - intersection

    #[test]
    fn test_prefix_with_optional_ports_intersection_both_some() {
        let prefix1 = prefix_v4("192.168.0.0/24");
        let prefix2 = prefix_v4("192.168.0.0/25");
        let ports1 = PortRange::new(80, 100).unwrap();
        let ports2 = PortRange::new(90, 110).unwrap();

        let pwop1 = PrefixWithOptionalPorts::new(prefix1, Some(ports1));
        let pwop2 = PrefixWithOptionalPorts::new(prefix2, Some(ports2));

        let intersection = pwop1
            .intersection(&pwop2)
            .expect("Should have intersection");
        assert_eq!(intersection.prefix(), prefix2);
        assert_eq!(intersection.ports(), Some(PortRange::new(90, 100).unwrap()));
    }

    #[test]
    fn test_prefix_with_optional_ports_intersection_one_none() {
        let prefix1 = prefix_v4("192.168.0.0/24");
        let prefix2 = prefix_v4("192.168.0.0/25");
        let ports = PortRange::new(80, 100).unwrap();

        let pwop1 = PrefixWithOptionalPorts::new(prefix1, Some(ports));
        let pwop2 = PrefixWithOptionalPorts::new(prefix2, None);

        let intersection = pwop1
            .intersection(&pwop2)
            .expect("Should have intersection");
        assert_eq!(intersection.prefix(), prefix2);
        assert_eq!(intersection.ports(), Some(ports));
    }

    #[test]
    fn test_prefix_with_optional_ports_intersection_both_none() {
        let prefix1 = prefix_v4("192.168.0.0/24");
        let prefix2 = prefix_v4("192.168.0.0/25");

        let pwop1 = PrefixWithOptionalPorts::new(prefix1, None);
        let pwop2 = PrefixWithOptionalPorts::new(prefix2, None);

        let intersection = pwop1
            .intersection(&pwop2)
            .expect("Should have intersection");
        assert_eq!(intersection.prefix(), prefix2);
        assert_eq!(intersection.ports(), None);
    }

    #[test]
    fn test_prefix_with_optional_ports_intersection_no_prefix_overlap() {
        let prefix1 = prefix_v4("192.168.0.0/24");
        let prefix2 = prefix_v4("10.0.0.0/24");

        let pwop1 = PrefixWithOptionalPorts::new(prefix1, None);
        let pwop2 = PrefixWithOptionalPorts::new(prefix2, None);

        let intersection = pwop1.intersection(&pwop2);
        assert!(intersection.is_none());
    }

    #[test]
    fn test_prefix_with_optional_ports_intersection_no_port_overlap() {
        let prefix = prefix_v4("192.168.0.0/24");
        let ports1 = PortRange::new(80, 100).unwrap();
        let ports2 = PortRange::new(200, 300).unwrap();

        let pwop1 = PrefixWithOptionalPorts::new(prefix, Some(ports1));
        let pwop2 = PrefixWithOptionalPorts::new(prefix, Some(ports2));

        let intersection = pwop1.intersection(&pwop2);
        assert!(intersection.is_none());
    }

    #[test]
    fn test_prefix_with_optional_ports_intersection_symmetry() {
        let prefix1 = prefix_v4("192.168.0.0/24");
        let prefix2 = prefix_v4("192.168.0.0/25");
        let ports = PortRange::new(80, 100).unwrap();

        let pwop1 = PrefixWithOptionalPorts::new(prefix1, Some(ports));
        let pwop2 = PrefixWithOptionalPorts::new(prefix2, None);

        let intersection1 = pwop1
            .intersection(&pwop2)
            .expect("Should have intersection");
        let intersection2 = pwop2
            .intersection(&pwop1)
            .expect("Should have intersection");

        assert_eq!(intersection1, intersection2);
    }

    // PrefixWithOptionalPorts - subtract

    #[test]
    fn test_prefix_with_optional_ports_subtract_no_overlap() {
        let prefix1 = prefix_v4("192.168.0.0/24");
        let prefix2 = prefix_v4("10.0.0.0/24");

        let pwop1 = PrefixWithOptionalPorts::new(prefix1, None);
        let pwop2 = PrefixWithOptionalPorts::new(prefix2, None);

        let result = pwop1.subtract(&pwop2);
        assert!(result.is_empty());
    }

    #[test]
    fn test_prefix_with_optional_ports_subtract_identical_both_none() {
        let prefix = prefix_v4("192.168.0.0/24");

        let pwop = PrefixWithOptionalPorts::new(prefix, None);

        let result = pwop.subtract(&pwop);
        assert!(result.is_empty());
    }

    #[test]
    fn test_prefix_with_optional_ports_subtract_both_some() {
        let prefix = prefix_v4("192.168.0.0/24");
        let ports1 = PortRange::new(80, 200).unwrap();
        let ports2 = PortRange::new(100, 150).unwrap();

        let pwop1 = PrefixWithOptionalPorts::new(prefix, Some(ports1));
        let pwop2 = PrefixWithOptionalPorts::new(prefix, Some(ports2));

        let result = pwop1.subtract(&pwop2);
        // Should split into two port ranges
        assert_eq!(result.len(), 2);
        assert!(result.contains(&PrefixWithOptionalPorts::new(
            prefix,
            Some(PortRange::new(80, 99).unwrap())
        )));
        assert!(result.contains(&PrefixWithOptionalPorts::new(
            prefix,
            Some(PortRange::new(151, 200).unwrap())
        )));
    }

    #[test]
    fn test_prefix_with_optional_ports_subtract_self_some_other_none() {
        let prefix1 = prefix_v4("192.168.0.0/23");
        let prefix2 = prefix_v4("192.168.0.0/24");
        let ports = PortRange::new(80, 100).unwrap();

        let pwop1 = PrefixWithOptionalPorts::new(prefix1, Some(ports));
        let pwop2 = PrefixWithOptionalPorts::new(prefix2, None);

        let result = pwop1.subtract(&pwop2);
        // Should subtract all ports in the overlapping prefix
        // Remaining: 192.168.1.0/24 with ports 80-100
        assert_eq!(result.len(), 1);
        assert!(result.contains(&PrefixWithOptionalPorts::new(
            prefix_v4("192.168.1.0/24"),
            Some(PortRange::new(80, 100).unwrap())
        )));
    }

    #[test]
    fn test_prefix_with_optional_ports_subtract_self_none_other_some() {
        let prefix1 = prefix_v4("192.168.0.0/23");
        let prefix2 = prefix_v4("192.168.0.0/24");
        let ports = PortRange::new(80, 100).unwrap();

        let pwop1 = PrefixWithOptionalPorts::new(prefix1, None);
        let pwop2 = PrefixWithOptionalPorts::new(prefix2, Some(ports));

        let result = pwop1.subtract(&pwop2);
        // Should remove the specified port range from the overlapping prefix
        assert_eq!(result.len(), 3);
        assert!(result.contains(&PrefixWithOptionalPorts::new(
            prefix_v4("192.168.0.0/23"),
            Some(PortRange::new(0, 79).unwrap())
        )));
        assert!(result.contains(&PrefixWithOptionalPorts::new(
            prefix_v4("192.168.0.0/23"),
            Some(PortRange::new(101, u16::MAX).unwrap())
        )));
        assert!(result.contains(&PrefixWithOptionalPorts::new(
            prefix_v4("192.168.1.0/24"),
            Some(PortRange::new(80, 100).unwrap())
        )));
    }

    #[test]
    fn test_prefix_with_optional_ports_subtract_prefix_split() {
        let prefix1 = prefix_v4("192.168.0.0/23");
        let prefix2 = prefix_v4("192.168.0.0/24");

        let pwop1 = PrefixWithOptionalPorts::new(prefix1, None);
        let pwop2 = PrefixWithOptionalPorts::new(prefix2, None);

        let result = pwop1.subtract(&pwop2);
        // Should have one remaining prefix
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].prefix(), prefix_v4("192.168.1.0/24"));
        assert_eq!(result[0].ports(), None);
    }

    #[test]
    fn test_prefix_with_optional_ports_subtract_ipv6() {
        let prefix1 = prefix_v6("2001:db8::/32");
        let prefix2 = prefix_v6("2001:db8::/33");
        let ports = PortRange::new(443, 8443).unwrap();

        let pwop1 = PrefixWithOptionalPorts::new(prefix1, Some(ports));
        let pwop2 = PrefixWithOptionalPorts::new(prefix2, Some(ports));

        let result = pwop1.subtract(&pwop2);
        // Should have remaining prefixes after subtraction
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            PrefixWithOptionalPorts::new(prefix_v6("2001:db8:8000::/33"), Some(ports))
        );
    }
}
