// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::prefix::range_map::UpperBoundFrom;
use crate::prefix::{Prefix, PrefixSize};
use bnum::cast::CastFrom;
use bnum::{n, t};
use std::collections::BTreeSet;
use std::fmt::Display;
use std::ops::{Bound, RangeBounds};
use std::str::FromStr;

/// A type for the size of IP/port combinations for IP prefixes with associated port ranges.
/// We need something larger than u128 to cover all possible combinations: the maximum value is
/// `(u128::MAX + 1) * (u16::MAX + 1)`.
pub type PrefixWithPortsSize = t!(U145w); // 'w' for "wrapped" because "saturated" mode has a bug

pub fn ppsize_from<T>(val: T) -> PrefixWithPortsSize
where
    PrefixWithPortsSize: CastFrom<T>,
{
    PrefixWithPortsSize::cast_from(val)
}

#[must_use]
pub const fn ppsize_zero() -> PrefixWithPortsSize {
    n!(0)
}

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
    /// Returns the merge of the two ranges, if any.
    fn merge(&self, other: &Self) -> Option<Self>
    where
        Self: Sized;
    /// Returns the total number of (IP, port) combinations covered by the IP and port ranges.
    fn size(&self) -> PrefixWithPortsSize {
        let ip_len = match self.addr_range_len() {
            PrefixSize::U128(len) => ppsize_from(len),
            PrefixSize::Ipv6MaxAddrs => ppsize_from(u128::MAX) + ppsize_from(1u8),
            PrefixSize::Overflow => unreachable!(),
        };
        ip_len * ppsize_from(self.port_range_len())
    }
}

/// A structure containing a prefix and a port range.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
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

    fn merge(&self, other: &Self) -> Option<Self> {
        if self.prefix == other.prefix {
            Some(PrefixWithPorts::new(
                self.prefix,
                self.ports.merge(other.ports)?,
            ))
        } else if self.ports == other.ports {
            Some(PrefixWithPorts::new(
                self.prefix.merge(&other.prefix)?,
                self.ports,
            ))
        } else {
            None
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub struct PrefixPortsSet(BTreeSet<PrefixWithOptionalPorts>);

impl PrefixPortsSet {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn root_v4() -> Self {
        let mut empty = Self::new();
        let root_v4 = PrefixWithOptionalPorts::new(Prefix::root_v4(), None);
        empty.insert(root_v4);
        empty
    }

    #[must_use]
    pub fn root_v6() -> Self {
        let mut empty = Self::new();
        let root_v6 = PrefixWithOptionalPorts::new(Prefix::root_v6(), None);
        empty.insert(root_v6);
        empty
    }

    /// Given two [`PrefixPortsSet`] objects, returns the set containing the intersection of
    /// prefixes and ports. This new set may contain overlapping prefixes (within the set), if any
    /// of the two initial sets contains overlapping prefixes (within that set) that also overlap
    /// with prefixes from the other set.
    ///
    /// Returns an empty set if the first set contains no prefix overlapping with any of the
    /// prefixes from the second set.
    ///
    /// Not to be confused with `intersection`, inherited from the inner [`BTreeSet`], which returns
    /// the entries that are in both sets only if they are equal in both sets (and not in the case
    /// of partial overlap).
    #[must_use]
    pub fn intersection_prefixes_and_ports(&self, other: &PrefixPortsSet) -> PrefixPortsSet {
        let mut result = PrefixPortsSet::new();
        for prefix_left in self {
            for prefix_right in other {
                if let Some(intersection) = prefix_left.intersection(prefix_right) {
                    result.insert(intersection);
                }
            }
        }
        result
    }

    /// Return the total "size" of all prefixes in the set.
    ///
    /// The "size" is the number of IP addresses in the IP prefix, multiplied by the number of ports
    /// in the associated port range, if any.
    #[must_use]
    pub fn total_prefixes_size(&self) -> PrefixWithPortsSize {
        self.0
            .iter()
            .map(PrefixWithOptionalPorts::size)
            .sum::<PrefixWithPortsSize>()
    }
}

impl IntoIterator for PrefixPortsSet {
    type Item = PrefixWithOptionalPorts;
    type IntoIter = std::collections::btree_set::IntoIter<PrefixWithOptionalPorts>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
impl<'a> IntoIterator for &'a PrefixPortsSet {
    type Item = &'a PrefixWithOptionalPorts;
    type IntoIter = std::collections::btree_set::Iter<'a, PrefixWithOptionalPorts>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}
impl FromIterator<PrefixWithOptionalPorts> for PrefixPortsSet {
    fn from_iter<T: IntoIterator<Item = PrefixWithOptionalPorts>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}
impl<const N: usize> From<[PrefixWithOptionalPorts; N]> for PrefixPortsSet {
    fn from(value: [PrefixWithOptionalPorts; N]) -> Self {
        Self(value.into_iter().collect())
    }
}
// Implement Deref and DerefMut to directly expose all methods from the inner BTreeSet
impl std::ops::Deref for PrefixPortsSet {
    type Target = BTreeSet<PrefixWithOptionalPorts>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for PrefixPortsSet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// A structure containing a prefix and an optional port range.
///
/// There is some ambiguity in this type in that a None port range may be
/// understood as all ports, meaning that two distinct instances of this
/// type would be semantically equivalent. To avoid this, the constructor
/// of this type guarantees that `max_range` is mapped to None, without
/// needing to call an additional simplify method.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrefixWithOptionalPorts {
    prefix: Prefix,
    ports: Option<PortRange>,
}

impl PrefixWithOptionalPorts {
    /// Creates a new `PrefixWithOptionalPorts` from a prefix and an optional port range.
    /// If the port range is `Some(max_range)`, the value is normalized to None.
    #[must_use]
    pub fn new(prefix: Prefix, ports: Option<PortRange>) -> Self {
        let ports = ports.filter(|range| !range.is_max_range());
        Self { prefix, ports }
    }

    /// Returns the prefix.
    #[must_use]
    pub fn prefix(&self) -> Prefix {
        self.prefix
    }

    /// Returns the optional port range (`None` means "all ports").
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
            .map_or(PortRange::MAX_LENGTH, |ports| ports.len())
    }

    fn covers(&self, other: &Self) -> bool {
        // Since portrange = None means all ports, represent both self and other
        // as `PrefixWithPorts` and use its `covers` implementation
        PrefixWithPorts::from(*self).covers(&(*other).into())
    }

    fn overlaps(&self, other: &Self) -> bool {
        PrefixWithPorts::from(*self).overlaps(&(*other).into())
    }

    fn intersection(&self, other: &Self) -> Option<Self> {
        PrefixWithPorts::from(*self)
            .intersection(&(*other).into())
            .map(Self::from)
    }

    fn subtract(&self, other: &Self) -> Vec<Self> {
        PrefixWithPorts::from(*self)
            .subtract(&(*other).into())
            .into_iter()
            .map(Self::from)
            .collect()
    }

    fn merge(&self, other: &Self) -> Option<Self> {
        PrefixWithPorts::from(*self)
            .merge(&(*other).into())
            .map(Self::from)
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
    /// Invalid port number format.
    #[error("Invalid port number format: {0}")]
    ParseError(String),
    /// Too many ports in string.
    #[error("Expected start and end port, found: {0}")]
    TooManyPorts(String),
}

impl From<PrefixWithPorts> for PrefixWithOptionalPorts {
    fn from(value: PrefixWithPorts) -> Self {
        Self::new(value.prefix(), Some(value.ports()))
    }
}

impl From<PrefixWithOptionalPorts> for PrefixWithPorts {
    fn from(p: PrefixWithOptionalPorts) -> Self {
        PrefixWithPorts::new(p.prefix, p.ports.unwrap_or_else(PortRange::new_max_range))
    }
}

impl<T> From<T> for PrefixWithPorts
where
    T: Into<Prefix>,
{
    fn from(value: T) -> Self {
        PrefixWithPorts::new(value.into(), PortRange::new_max_range())
    }
}

impl<T> From<T> for PrefixWithOptionalPorts
where
    T: Into<Prefix>,
{
    fn from(value: T) -> Self {
        PrefixWithOptionalPorts::new(value.into(), None)
    }
}

/// A port range, with a start and an end port (both included in the range).
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

    /// Merges the given disjoint range into this range if possible.
    ///
    /// # Returns
    ///
    /// Returns `Some(())` if the ranges were merged, `None` otherwise.
    pub fn extend_right(&mut self, next: PortRange) -> Option<()> {
        if self.start > next.start || self.end >= next.start {
            return None;
        }
        if self.end + 1 == next.start {
            self.end = next.end;
            return Some(());
        }
        None
    }

    // Return a merged `PortRange` if the two ranges overlap or are adjacent
    #[must_use]
    pub fn merge(&self, other: Self) -> Option<Self> {
        // determine which range begins first
        let (left, right) = if self.start <= other.start {
            (self, &other)
        } else {
            (&other, self)
        };
        if u32::from(left.end) + 1 < u32::from(right.start) {
            // range do not overlap (nor are adjacent)
            None
        } else {
            // left has the smaller start value, but the union ends at the larger of the two ends
            // since left could contain right. So we have to take the highest of the two.
            Some(
                PortRange::new(left.start, left.end.max(right.end))
                    .unwrap_or_else(|_| unreachable!()),
            )
        }
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

impl FromStr for PortRange {
    type Err = PortRangeError;

    fn from_str(ports: &str) -> Result<Self, Self::Err> {
        let parsed_ports = ports
            // Split start port / end port on '-'.
            // Spaces are not allowed, so we don't trim.
            .split('-')
            .map(str::parse::<u16>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| PortRangeError::ParseError(e.to_string()))?;
        match parsed_ports.len() {
            0 => unreachable!("splitting string always produce at least one string"),
            1 => Ok(PortRange::new(parsed_ports[0], parsed_ports[0])?),
            2 => Ok(PortRange::new(parsed_ports[0], parsed_ports[1])?),
            _ => Err(PortRangeError::TooManyPorts(ports.to_string())),
        }
    }
}

impl Display for PortRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.start, self.end)
    }
}

impl Display for PrefixWithPorts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:[{}]", self.prefix, self.ports)
    }
}

impl Display for PrefixWithOptionalPorts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.ports {
            None => write!(f, "{}:[all]", self.prefix),
            Some(ports) => write!(f, "{}:[{}]", self.prefix, ports),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum L4Protocol {
    Tcp,
    Udp,
    #[default]
    Any,
}

impl L4Protocol {
    #[must_use]
    pub fn intersection(&self, other: &L4Protocol) -> Option<L4Protocol> {
        match (self, other) {
            (L4Protocol::Any, other_proto) => Some(*other_proto),
            (self_proto, L4Protocol::Any) => Some(*self_proto),
            (self_proto, other_proto) if self_proto == other_proto => Some(*self_proto),
            _ => None,
        }
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use super::{PortRange, Prefix, PrefixWithOptionalPorts};
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for PortRange {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let start: u16 = driver.produce()?;
            let end: u16 = driver.produce()?;
            Some(PortRange::new(start.min(end), start.max(end)).unwrap_or_else(|_| unreachable!()))
        }
    }

    impl TypeGenerator for PrefixWithOptionalPorts {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let prefix: Prefix = driver.produce()?;
            let ports: Option<PortRange> = driver.produce()?;
            Some(PrefixWithOptionalPorts::new(prefix, ports))
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

    // PrefixWithOptionalPorts - merge

    #[test]
    fn test_prefix_with_optional_ports_merge_both_prefix_adjacent() {
        // Two adjacent prefixes without ports should merge
        let pwop1 = PrefixWithOptionalPorts::new(prefix_v4("10.0.0.0/25"), None);
        let pwop2 = PrefixWithOptionalPorts::new(prefix_v4("10.0.0.128/25"), None);

        let merged = pwop1.merge(&pwop2).expect("Should merge");
        assert_eq!(merged.prefix(), prefix_v4("10.0.0.0/24"));
        assert_eq!(merged.ports(), None);
    }

    #[test]
    fn test_prefix_with_optional_ports_merge_both_prefix_not_adjacent() {
        // Two non-adjacent prefixes without ports should not merge
        let pwop1 = PrefixWithOptionalPorts::new(prefix_v4("10.0.0.0/24"), None);
        let pwop2 = PrefixWithOptionalPorts::new(prefix_v4("10.0.2.0/24"), None);

        let merged = pwop1.merge(&pwop2);
        assert!(merged.is_none());
    }

    #[test]
    fn test_prefix_with_optional_ports_merge_both_prefix_identical() {
        // Two identical prefixes without ports should merge
        let pwop = PrefixWithOptionalPorts::new(prefix_v4("10.0.0.0/24"), None);

        let merged = pwop.merge(&pwop).expect("Should merge");
        assert_eq!(merged, pwop);
    }

    #[test]
    fn test_prefix_with_optional_ports_merge_both_prefix_ports_same_prefix() {
        // Same prefix with adjacent port ranges should merge
        let prefix = prefix_v4("10.0.0.0/24");
        let pwop1 = PrefixWithOptionalPorts::new(prefix, Some(PortRange::new(80, 100).unwrap()));
        let pwop2 = PrefixWithOptionalPorts::new(prefix, Some(PortRange::new(101, 200).unwrap()));

        let merged = pwop1.merge(&pwop2).expect("Should merge");
        assert_eq!(merged.prefix(), prefix);
        assert_eq!(merged.ports(), Some(PortRange::new(80, 200).unwrap()));
    }

    #[test]
    fn test_prefix_with_optional_ports_merge_both_prefix_ports_same_ports() {
        // Adjacent prefixes with same port range should merge
        let ports = PortRange::new(80, 100).unwrap();
        let pwop1 = PrefixWithOptionalPorts::new(prefix_v4("10.0.0.0/25"), Some(ports));
        let pwop2 = PrefixWithOptionalPorts::new(prefix_v4("10.0.0.128/25"), Some(ports));

        let merged = pwop1.merge(&pwop2).expect("Should merge");
        assert_eq!(merged.prefix(), prefix_v4("10.0.0.0/24"));
        assert_eq!(merged.ports(), Some(ports));
    }

    #[test]
    fn test_prefix_with_optional_ports_merge_both_prefix_ports_different_both() {
        // Different prefixes and different port ranges should not merge
        let pwop1 = PrefixWithOptionalPorts::new(
            prefix_v4("10.0.0.0/24"),
            Some(PortRange::new(80, 100).unwrap()),
        );
        let pwop2 = PrefixWithOptionalPorts::new(
            prefix_v4("10.0.1.0/24"),
            Some(PortRange::new(101, 300).unwrap()),
        );

        let merged = pwop1.merge(&pwop2);
        assert!(merged.is_none());
    }

    #[test]
    fn test_prefix_with_optional_ports_merge_both_prefix_ports_identical() {
        // Two identical PrefixWithPorts should merge to themselves
        let pwop = PrefixWithOptionalPorts::new(
            prefix_v4("10.0.0.0/24"),
            Some(PortRange::new(80, 100).unwrap()),
        );

        let merged = pwop.merge(&pwop).expect("Should merge");
        assert_eq!(merged, pwop);
    }

    #[test]
    fn test_prefix_with_optional_ports_merge_prefix_and_prefix_ports_same_prefix() {
        // Same prefix, one with ports and one without (covers all ports)
        // Should merge to prefix without ports (all ports)
        let prefix = prefix_v4("10.0.0.0/24");
        let pwop1 = PrefixWithOptionalPorts::new(prefix, None);
        let pwop2 = PrefixWithOptionalPorts::new(prefix, Some(PortRange::new(80, 100).unwrap()));

        let merged = pwop1.merge(&pwop2).expect("Should merge");
        assert_eq!(merged.prefix(), prefix);
        assert_eq!(merged.ports(), None);

        // Test symmetry
        let merged2 = pwop2.merge(&pwop1).expect("Should merge");
        assert_eq!(merged2, merged);
    }

    #[test]
    fn test_prefix_with_optional_ports_merge_prefix_and_prefix_ports_max_range() {
        // Different prefixes but PrefixPorts has max port range (equivalent to no ports)
        let pwop1 = PrefixWithOptionalPorts::new(prefix_v4("10.0.0.0/25"), None);
        let pwop2 = PrefixWithOptionalPorts::new(
            prefix_v4("10.0.0.128/25"),
            Some(PortRange::new_max_range()),
        );

        let merged = pwop1.merge(&pwop2).expect("Should merge");
        assert_eq!(merged.prefix(), prefix_v4("10.0.0.0/24"));
        assert_eq!(merged.ports(), None);
    }

    #[test]
    fn test_prefix_with_optional_ports_merge_prefix_and_prefix_ports_different_prefix_limited_ports()
     {
        // Different prefixes and PrefixPorts has limited port range
        let pwop1 = PrefixWithOptionalPorts::new(prefix_v4("10.0.0.0/24"), None);
        let pwop2 = PrefixWithOptionalPorts::new(
            prefix_v4("10.0.1.0/24"),
            Some(PortRange::new(80, 100).unwrap()),
        );

        let merged = pwop1.merge(&pwop2);
        assert!(merged.is_none());
    }

    #[test]
    fn test_prefix_with_optional_ports_merge_ipv6() {
        // Test merging with IPv6 prefixes
        let pwop1 = PrefixWithOptionalPorts::new(prefix_v6("2001:db8::/33"), None);
        let pwop2 = PrefixWithOptionalPorts::new(prefix_v6("2001:db8:8000::/33"), None);

        let merged = pwop1.merge(&pwop2).expect("Should merge");
        assert_eq!(merged.prefix(), prefix_v6("2001:db8::/32"));
        assert_eq!(merged.ports(), None);
    }

    #[test]
    fn test_prefix_with_optional_ports_merge_overlapping_port_ranges() {
        // Overlapping (not just adjacent) port ranges should merge
        let prefix = prefix_v4("10.0.0.0/24");
        let pwop1 = PrefixWithOptionalPorts::new(prefix, Some(PortRange::new(80, 150).unwrap()));
        let pwop2 = PrefixWithOptionalPorts::new(prefix, Some(PortRange::new(100, 200).unwrap()));

        let merged = pwop1.merge(&pwop2).expect("Should merge");
        assert_eq!(merged.prefix(), prefix);
        assert_eq!(merged.ports(), Some(PortRange::new(80, 200).unwrap()));
    }

    #[test]
    fn test_prefix_with_optional_ports_merge_non_adjacent_port_ranges() {
        // Non-adjacent port ranges should not merge
        let prefix = prefix_v4("10.0.0.0/24");
        let pwop1 = PrefixWithOptionalPorts::new(prefix, Some(PortRange::new(80, 100).unwrap()));
        let pwop2 = PrefixWithOptionalPorts::new(prefix, Some(PortRange::new(200, 300).unwrap()));

        let merged = pwop1.merge(&pwop2);
        assert!(merged.is_none());
    }

    #[test]
    fn test_prefix_with_optional_ports_merge_containing_port_ranges() {
        // With same prefix, a port range containing another must merge to the container
        let prefix = prefix_v4("10.0.0.0/24");
        let pwop1 = PrefixWithOptionalPorts::new(prefix, Some(PortRange::new(80, 200).unwrap()));
        let pwop2 = PrefixWithOptionalPorts::new(prefix, Some(PortRange::new(100, 150).unwrap()));

        let merged = pwop1.merge(&pwop2).expect("Should merge");
        assert_eq!(merged.prefix(), prefix);
        assert_eq!(merged.ports(), Some(PortRange::new(80, 200).unwrap()));

        // Symmetry
        assert_eq!(pwop2.merge(&pwop1).expect("Should merge"), merged);
    }

    // PortRange - merge

    #[test]
    fn test_port_range_merge_containment() {
        // The larger range fully contains the smaller one: the union is the larger range.
        let outer = PortRange::new(0, 65535).unwrap();
        let inner = PortRange::new(80, 100).unwrap();
        assert_eq!(outer.merge(inner), Some(outer));
        assert_eq!(inner.merge(outer), Some(outer));

        let a = PortRange::new(80, 200).unwrap();
        let b = PortRange::new(100, 150).unwrap();
        assert_eq!(a.merge(b), Some(a));
        assert_eq!(b.merge(a), Some(a));
    }

    // PortRange - FromStr

    #[test]
    fn test_port_range_from_str_single_port() {
        let result = PortRange::from_str("80").unwrap();
        assert_eq!(result.start(), 80);
        assert_eq!(result.end(), 80);
    }

    #[test]
    fn test_port_range_from_str_valid_range() {
        let result = "8000-8080".parse::<PortRange>().unwrap();
        assert_eq!(result.start(), 8000);
        assert_eq!(result.end(), 8080);
    }

    #[test]
    fn test_port_range_from_str_same_start_end() {
        let result = PortRange::from_str("443-443").unwrap();
        assert_eq!(result.start(), 443);
        assert_eq!(result.end(), 443);
    }

    #[test]
    fn test_port_range_from_str_empty_string() {
        let result = PortRange::from_str("");
        assert!(result.is_err());
        assert!(matches!(result, Err(PortRangeError::ParseError(_))));
    }

    #[test]
    fn test_port_range_from_str_invalid_format() {
        let result = PortRange::from_str("abc");
        assert!(result.is_err());
        assert!(matches!(result, Err(PortRangeError::ParseError(_))));
    }

    #[test]
    fn test_port_range_from_str_too_many_parts() {
        let result = PortRange::from_str("80-90-100");
        assert!(result.is_err());
        assert!(matches!(result, Err(PortRangeError::TooManyPorts(_))));
    }

    #[test]
    fn test_port_range_from_str_invalid_range() {
        // PortRange::new should fail if start > end
        let result = PortRange::from_str("8080-8000");
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(PortRangeError::InvalidRange(8080, 8000))
        ));
    }

    #[test]
    fn test_port_range_from_str_zero_port() {
        let result = PortRange::from_str("0").unwrap();
        assert_eq!(result.start(), 0);
        assert_eq!(result.end(), 0);
    }

    #[test]
    fn test_port_range_from_str_max_port() {
        let result = PortRange::from_str("65535").unwrap();
        assert_eq!(result.start(), 65535);
        assert_eq!(result.end(), 65535);
    }

    #[test]
    fn test_port_range_from_str_overflow() {
        let result = PortRange::from_str("65536");
        assert!(result.is_err());
        assert!(matches!(result, Err(PortRangeError::ParseError(_))));
    }

    #[test]
    fn test_port_range_from_str_negative() {
        let result = PortRange::from_str("-1");
        assert!(result.is_err());
        assert!(matches!(result, Err(PortRangeError::ParseError(_))));
    }

    #[test]
    fn test_port_range_from_str_with_spaces() {
        let result = PortRange::from_str("80 - 90");
        assert!(result.is_err());
        assert!(matches!(result, Err(PortRangeError::ParseError(_))));
    }

    // PrefixPortsSet intersection tests

    fn prefix_with_ports(s: &str, start: u16, end: u16) -> PrefixWithOptionalPorts {
        PrefixWithOptionalPorts::new(s.into(), Some(PortRange::new(start, end).unwrap()))
    }

    #[test]
    fn test_intersection_list_prefixes_both_empty() {
        let result = PrefixPortsSet::new().intersection_prefixes_and_ports(&PrefixPortsSet::new());
        assert!(result.is_empty());
    }

    #[test]
    fn test_intersection_list_prefixes_left_empty() {
        let right = PrefixPortsSet::from(["10.0.0.0/24".into()]);
        let result = PrefixPortsSet::new().intersection_prefixes_and_ports(&right);
        assert!(result.is_empty());
    }

    #[test]
    fn test_intersection_list_prefixes_right_empty() {
        let left = PrefixPortsSet::from(["10.0.0.0/24".into()]);
        let result = left.intersection_prefixes_and_ports(&PrefixPortsSet::new());
        assert!(result.is_empty());
    }

    #[test]
    fn test_intersection_list_prefixes_no_overlap() {
        let left = PrefixPortsSet::from(["10.0.0.0/24".into()]);
        let right = PrefixPortsSet::from(["192.168.0.0/24".into()]);
        let result = left.intersection_prefixes_and_ports(&right);
        assert!(result.is_empty());
    }

    #[test]
    fn test_intersection_list_prefixes_identical() {
        let left = PrefixPortsSet::from(["10.0.0.0/24".into()]);
        let right = PrefixPortsSet::from(["10.0.0.0/24".into()]);
        let result = left.intersection_prefixes_and_ports(&right);
        assert_eq!(result, PrefixPortsSet::from(["10.0.0.0/24".into()]));
    }

    #[test]
    fn test_intersection_list_prefixes_subset() {
        // /24 is a subset of /16
        let left = PrefixPortsSet::from(["10.0.0.0/16".into()]);
        let right = PrefixPortsSet::from(["10.0.1.0/24".into()]);
        let result = left.intersection_prefixes_and_ports(&right);
        assert_eq!(result, PrefixPortsSet::from(["10.0.1.0/24".into()]));
    }

    #[test]
    fn test_intersection_list_prefixes_multiple_overlaps() {
        let left = PrefixPortsSet::from(["10.0.0.0/16".into(), "172.16.0.0/16".into()]);
        let right = PrefixPortsSet::from(["10.0.1.0/24".into(), "172.16.5.0/24".into()]);
        let result = left.intersection_prefixes_and_ports(&right);
        assert_eq!(
            result,
            PrefixPortsSet::from(["10.0.1.0/24".into(), "172.16.5.0/24".into()])
        );
    }

    #[test]
    fn test_intersection_list_prefixes_partial_overlap_multiple_left() {
        let left = PrefixPortsSet::from(["10.0.0.0/24".into(), "192.168.0.0/24".into()]);
        let right = PrefixPortsSet::from(["10.0.0.0/16".into()]);
        // Only 10.0.0.0/24 overlaps with 10.0.0.0/16, resulting in 10.0.0.0/24
        let result = left.intersection_prefixes_and_ports(&right);
        assert_eq!(result, PrefixPortsSet::from(["10.0.0.0/24".into()]));
    }

    #[test]
    fn test_intersection_list_prefixes_with_ports() {
        let left = PrefixPortsSet::from([prefix_with_ports("10.0.0.0/24", 80, 100)]);
        let right = PrefixPortsSet::from(["10.0.0.0/24".into()]);
        let result = left.intersection_prefixes_and_ports(&right);
        assert_eq!(
            result,
            PrefixPortsSet::from([prefix_with_ports("10.0.0.0/24", 80, 100)])
        );
    }

    #[test]
    fn test_intersection_list_prefixes_with_overlapping_ports() {
        let left = PrefixPortsSet::from([prefix_with_ports("10.0.0.0/24", 80, 200)]);
        let right = PrefixPortsSet::from([prefix_with_ports("10.0.0.0/24", 150, 300)]);
        let result = left.intersection_prefixes_and_ports(&right);
        assert_eq!(
            result,
            PrefixPortsSet::from([prefix_with_ports("10.0.0.0/24", 150, 200)])
        );
    }

    #[test]
    fn test_intersection_list_prefixes_with_disjoint_ports() {
        let left = PrefixPortsSet::from([prefix_with_ports("10.0.0.0/24", 80, 100)]);
        let right = PrefixPortsSet::from([prefix_with_ports("10.0.0.0/24", 200, 300)]);
        let result = left.intersection_prefixes_and_ports(&right);
        assert!(result.is_empty());
    }
}
