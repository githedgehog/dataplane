// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use bnum::cast::CastFrom;
use lpm::prefix::range_map::UpperBoundFrom;
use lpm::prefix::{IpRangeWithPorts, PortRange, Prefix, PrefixSize, PrefixWithPortsSize};
use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::{Bound, RangeBounds};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct IpPortRange {
    pub ip_range: IpRange,
    pub port_range: PortRange,
}

impl IpPortRange {
    #[must_use]
    pub fn get_entry(&self, offset: PrefixWithPortsSize) -> Option<(IpAddr, u16)> {
        if offset >= self.size() {
            return None;
        }

        let port_range_len = PrefixWithPortsSize::from(self.port_range.len());
        let ip_offset_tmp = offset / port_range_len;
        debug_assert!(ip_offset_tmp <= PrefixWithPortsSize::from(u128::MAX));
        let ip_offset = u128::cast_from(ip_offset_tmp);
        let port_offset = (offset % port_range_len)
            .try_into()
            .unwrap_or_else(|_| unreachable!()); // Modulo using a u128::from(u16)

        self.ip_range
            .get_entry(ip_offset)
            .zip(self.port_range.get_entry(port_offset))
    }

    // Merges the current IP address and port ranges with the next ranges, if possible.
    //
    // Merging is possible if:
    // - both ranges are of the same IP version, and
    // - either:
    //   - case 1:
    //     - port ranges are identical, and
    //     - the next IP range starts right after the current IP range ends
    //     - example: 1.0.1.0/24 (1-100) and 1.0.2.0/24 (1-100) -> 1.0.1.0 to 1.0.2.255 (1-100)
    //   - case 2:
    //     - IP ranges are identical, and
    //     - the next port range starts right after the current port range ends
    //     - example: 1.0.1.0/24 (1-100) and 1.0.1.0/24 (101-300) -> 1.0.1.0/24 (1-300)
    //
    // # Returns
    //
    // Returns `Some(())` if the ranges were merged, or `None` otherwise.
    pub fn extend_right(&mut self, next: &IpPortRange) -> Option<()> {
        // Always merge on the "right side". This is because we call this method assuming that
        // ranges are ordered (by IP range start, then port range start values), and we process the
        // smaller ones first; if we try to merge a new one into an existing one, it's a "bigger"
        // one, so we merge on the right side.

        // Case 1: port ranges are identical
        if self.port_range == next.port_range {
            return self.ip_range.extend_right(&next.ip_range);
        }

        // Case 2: IP ranges are identical
        if self.ip_range == next.ip_range {
            return self.port_range.extend_right(next.port_range);
        }
        None
    }
}

// This type is private, so we only implement the methods we use. The trait gives us the .size()
// method, without having to duplicate it across similar types.
impl IpRangeWithPorts for IpPortRange {
    fn addr_range_len(&self) -> PrefixSize {
        self.ip_range.len()
    }

    fn port_range_len(&self) -> usize {
        self.port_range.len()
    }

    fn covers(&self, _other: &Self) -> bool {
        unimplemented!()
    }

    fn overlaps(&self, _other: &Self) -> bool {
        unimplemented!()
    }

    fn intersection(&self, _other: &Self) -> Option<Self> {
        unimplemented!()
    }

    fn subtract(&self, _other: &Self) -> Vec<Self> {
        unimplemented!()
    }

    fn merge(&self, _other: &Self) -> Option<Self> {
        unimplemented!()
    }
}

// Represents an IP address range, with a start and an end address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct IpRange {
    start: IpAddr,
    end: IpAddr,
}

impl IpRange {
    #[must_use]
    pub fn new(start: IpAddr, end: IpAddr) -> Self {
        debug_assert!(start <= end, "start: {start}, end: {end}");
        debug_assert!(
            start.is_ipv4() == end.is_ipv4(),
            "start: {start}, end: {end}"
        );
        Self { start, end }
    }

    #[must_use]
    pub fn start(&self) -> IpAddr {
        self.start
    }

    #[must_use]
    pub fn end(&self) -> IpAddr {
        self.end
    }

    #[cfg(test)]
    #[must_use]
    pub fn contains(&self, addr: &IpAddr) -> bool {
        self.start <= *addr && *addr <= self.end
    }

    // Returns the number of IP addresses covered by the range.
    pub fn len(&self) -> PrefixSize {
        match (self.start, self.end) {
            (IpAddr::V4(start), IpAddr::V4(end)) => {
                PrefixSize::U128(u128::from(end.to_bits().saturating_sub(start.to_bits())) + 1)
            }
            (IpAddr::V6(start), IpAddr::V6(end))
                if start.to_bits() == 0 && end.to_bits() == u128::MAX =>
            {
                PrefixSize::Ipv6MaxAddrs
            }
            (IpAddr::V6(start), IpAddr::V6(end)) => {
                PrefixSize::U128(end.to_bits().saturating_sub(start.to_bits()) + 1)
            }
            _ => unreachable!(),
        }
    }

    pub fn get_entry(&self, offset: u128) -> Option<IpAddr> {
        // This check also ensures that offset <= u32::MAX in the case of IPv4
        if offset >= self.len() {
            return None;
        }

        match self.start {
            IpAddr::V4(start) => {
                Some(IpAddr::V4(Ipv4Addr::from(start.to_bits().saturating_add(
                    u32::try_from(offset).unwrap_or_else(|_| unreachable!()),
                ))))
            }
            IpAddr::V6(start) => Some(IpAddr::V6(Ipv6Addr::from(
                start.to_bits().saturating_add(offset),
            ))),
        }
    }

    // Merges the current IP address range with the next range, if possible.
    //
    // Merging is possible if both ranges are of the same IP version and the next range starts right
    // after the current range ends.
    //
    // # Returns
    //
    // Returns `Some(())` if the ranges were merged, or `None` otherwise.
    fn extend_right(&mut self, next: &IpRange) -> Option<()> {
        // Always merge on the "right side". This is because we call this method when processing
        // ranges obtained from prefixes in a BTreeSet, so they are ordered, and we process the
        // smaller ones first; if we try to merge a new one into an existing one, it's a "bigger"
        // one, so we merge on the right side.
        if self.start > next.start || self.end >= next.start {
            return None;
        }
        match (self.end, next.start) {
            (IpAddr::V4(self_end), IpAddr::V4(next_start)) => {
                // No overflow because we checked self.end < other.start
                if self_end.to_bits() + 1 == next_start.to_bits() {
                    self.end = next.end;
                    return Some(());
                }
            }
            (IpAddr::V6(self_end), IpAddr::V6(next_start)) => {
                // No overflow because we checked self.end < other.start
                if self_end.to_bits() + 1 == next_start.to_bits() {
                    self.end = next.end;
                    return Some(());
                }
            }
            _ => return None,
        }
        None
    }
}

// Used for DisjointRangesBTreeMap
impl UpperBoundFrom<IpAddr> for IpRange {
    fn upper_bound_from(addr: IpAddr) -> Self {
        let end_addr = match addr {
            IpAddr::V4(_) => IpAddr::V4(u32::MAX.into()),
            IpAddr::V6(_) => IpAddr::V6(u128::MAX.into()),
        };
        Self::new(addr, end_addr)
    }
}

// Used for DisjointRangesBTreeMap
impl RangeBounds<IpAddr> for IpRange {
    fn start_bound(&self) -> Bound<&IpAddr> {
        Bound::Included(&self.start)
    }
    fn end_bound(&self) -> Bound<&IpAddr> {
        Bound::Included(&self.end)
    }
}

impl From<Prefix> for IpRange {
    fn from(prefix: Prefix) -> Self {
        Self::new(prefix.as_address(), prefix.last_address())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct IpPort {
    pub ip: IpAddr,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct IpPortRangeBounds {
    pub start: IpPort,
    pub end: IpPort,
}

impl IpPortRangeBounds {
    #[must_use]
    pub fn new(start: IpPort, end: IpPort) -> Self {
        Self { start, end }
    }
}

// Used for DisjointRangesBTreeMap
impl UpperBoundFrom<IpPort> for IpPortRangeBounds {
    fn upper_bound_from(value: IpPort) -> Self {
        let end_addr = match value.ip {
            IpAddr::V4(_) => IpAddr::V4(u32::MAX.into()),
            IpAddr::V6(_) => IpAddr::V6(u128::MAX.into()),
        };
        Self::new(
            value,
            IpPort {
                ip: end_addr,
                port: u16::MAX,
            },
        )
    }
}

// Used for DisjointRangesBTreeMap
impl RangeBounds<IpPort> for IpPortRangeBounds {
    fn start_bound(&self) -> Bound<&IpPort> {
        Bound::Included(&self.start)
    }
    fn end_bound(&self) -> Bound<&IpPort> {
        Bound::Included(&self.end)
    }
}
