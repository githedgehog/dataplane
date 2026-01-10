// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use ahash::RandomState;
use bnum::cast::CastFrom;
use lpm::prefix::range_map::{DisjointRangesBTreeMap, UpperBoundFrom};
use lpm::prefix::{IpPrefix, IpRangeWithPorts, PortRange, Prefix, PrefixSize, PrefixWithPortsSize};
use lpm::trie::IpPrefixTrie;
use net::vxlan::Vni;
use std::collections::{BTreeSet, HashMap};
use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::{Bound, RangeBounds};
use tracing::debug;

/// Error type for [`NatTables`] operations.
#[derive(thiserror::Error, Debug)]
pub enum NatTablesError {
    #[error("entry already exists")]
    EntryExists,
    #[error("bad IP version")]
    BadIpVersion,
    #[error("cannot discard port range")]
    NeedsPortRange,
}

/// An object containing the rules for the NAT pipeline stage, not in terms of states for the
/// different connections established, but instead holding the base rules for stateful or static
/// NAT.
#[derive(Debug, Clone)]
pub struct NatTables(HashMap<u32, PerVniTable, RandomState>);

impl NatTables {
    /// Creates a new empty [`NatTables`]
    #[must_use]
    pub fn new() -> Self {
        Self(HashMap::with_hasher(RandomState::with_seed(0)))
    }

    /// Adds a new table for the given `Vni`
    pub fn add_table(&mut self, table: PerVniTable, vni: Vni) {
        self.0.insert(vni.into(), table);
    }

    /// Provide a reference to a `PerVniTable` for the given `Vni` if it exists
    #[must_use]
    pub fn get_table(&self, vni: Vni) -> Option<&PerVniTable> {
        self.0.get(&vni.as_u32())
    }
}

impl Default for NatTables {
    fn default() -> Self {
        Self::new()
    }
}

/// A table containing all rules for both source and destination static NAT, for packets with a
/// given source VNI.
#[derive(Debug, Clone)]
pub struct PerVniTable {
    pub dst_nat: NatRuleTable,
    pub src_nat: HashMap<Vni, NatRuleTable>,
}

impl PerVniTable {
    /// Creates a new empty [`PerVniTable`]
    #[must_use]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            dst_nat: NatRuleTable::new(),
            src_nat: HashMap::new(),
        }
    }

    #[must_use]
    pub fn find_src_mapping(
        &self,
        addr: &IpAddr,
        port: Option<u16>,
        dst_vni: Vni,
    ) -> Option<(IpAddr, Option<u16>)> {
        debug!("Looking up source mapping for address: {addr}, port: {port:?}, dst_vni: {dst_vni}");
        Self::find_mapping(addr, port, self.src_nat.get(&dst_vni)?)
    }

    #[must_use]
    pub fn find_dst_mapping(
        &self,
        addr: &IpAddr,
        port: Option<u16>,
    ) -> Option<(IpAddr, Option<u16>)> {
        debug!("Looking up destination mapping for address: {addr}, port: {port:?}");
        Self::find_mapping(addr, port, &self.dst_nat)
    }

    fn find_mapping(
        addr: &IpAddr,
        port_opt: Option<u16>,
        table: &NatRuleTable,
    ) -> Option<(IpAddr, Option<u16>)> {
        let (prefix, value) = table.lookup(addr, port_opt)?;
        match value {
            NatTableValue::Nat(ranges) => {
                let offset = addr_offset_in_prefix(&prefix, addr)?;
                debug!(
                    "Mapping {addr} from prefix {prefix} to ranges {ranges:?}: found offset {offset}"
                );
                ranges.get_entry(addr, offset).map(|addr| (addr, None))
            }
            NatTableValue::Pat(ranges) => {
                let port = port_opt?; // We expect a port for PAT; no mapping if we have none
                let offset = addr_offset_in_prefix_with_ports(
                    &prefix,
                    *ranges
                        .prefix_port_ranges
                        .iter()
                        .find(|pr| pr.contains(&port))
                        .unwrap_or_else(|| unreachable!()),
                    addr,
                    port,
                )?;
                debug!(
                    "Mapping {addr}:{port:?} from prefix {prefix} to ranges {ranges:?}: found offset {offset}"
                );
                ranges
                    .get_entry(addr, port, offset)
                    .map(|(new_addr, new_port)| (new_addr, Some(new_port)))
            }
        }
    }
}

fn addr_offset_in_prefix(prefix: &Prefix, addr: &IpAddr) -> Option<u128> {
    if !prefix.covers_addr(addr) {
        return None;
    }
    match (prefix, addr) {
        (Prefix::IPV4(p), IpAddr::V4(a)) => Some(u128::from(a.to_bits() - p.network().to_bits())),
        (Prefix::IPV6(p), IpAddr::V6(a)) => Some(a.to_bits() - p.network().to_bits()),
        _ => None,
    }
}

fn addr_offset_in_prefix_with_ports(
    prefix: &Prefix,
    port_range: PortRange,
    addr: &IpAddr,
    port: u16,
) -> Option<PrefixWithPortsSize> {
    if !port_range.contains(&port) {
        return None;
    }
    let ip_offset = addr_offset_in_prefix(prefix, addr)?;
    let port_offset = port - port_range.start();
    Some(PrefixWithPortsSize::from(
        ip_offset
            * u128::try_from(port_range.len()).unwrap_or_else(|_| {
                // Assume conversion from usize to u128 never fails
                unreachable!()
            })
            + u128::from(port_offset),
    ))
}

/// From a current address prefix, find the target address prefix.
#[derive(Debug, Default, Clone)]
pub struct NatRuleTable(IpPrefixTrie<NatTableValue>);

impl NatRuleTable {
    #[must_use]
    /// Creates a new empty [`NatRuleTable`]
    pub fn new() -> Self {
        Self(IpPrefixTrie::new())
    }

    /// Inserts a new entry in the table
    ///
    /// # Returns
    ///
    /// Returns the previous value associated with the prefix if it existed, or `None` otherwise.
    pub fn insert(&mut self, prefix: Prefix, value: NatTableValue) -> Option<NatTableValue> {
        self.0.insert(prefix, value)
    }

    /// Looks up for the value associated with the given address.
    ///
    /// # Returns
    ///
    /// Returns the value associated with the longest prefix match for the given address.
    /// If the address does not match any prefix, it returns `None`.
    #[must_use]
    pub fn lookup(&self, addr: &IpAddr, port_opt: Option<u16>) -> Option<(Prefix, &NatTableValue)> {
        // If we have a matching NatTableValue::Nat for the address, return it
        let result = self.0.lookup(*addr);
        if matches!(result, Some((_prefix, NatTableValue::Nat(_value)))) {
            return result;
        }

        // Else, we need to check all matching IP prefixes (not necessarily the longest), and their
        // port ranges. We expect the trie to contain only one matching IP prefix matching the
        // address and associated to a port range matching the port, so we return the first we find.
        let port = port_opt?;
        let matching_entries = self.0.matching_entries(*addr);
        for (prefix, value) in matching_entries {
            if let NatTableValue::Pat(pat_value) = value
                && pat_value
                    .prefix_port_ranges
                    .iter()
                    .any(|pr| pr.contains(&port))
            {
                return Some((prefix, value));
            }
        }
        None
    }
}

/// This is the struct used as a value for the LPM trie lookup that we use to store the NAT ranges.
/// For a given prefix used as a key in the trie, this struct associates a list of ranges to map to.
/// The total number of IP addresses covered by the ranges is supposed to be equal to the addresses
/// in the prefix, so that we can establish a one-to-one mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatTableValue {
    Nat(AddrTranslationValue),
    Pat(PortAddrTranslationValue),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrTranslationValue {
    ranges_tree: DisjointRangesBTreeMap<IpRange, (IpRange, u128)>,
}

impl AddrTranslationValue {
    #[must_use]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            ranges_tree: DisjointRangesBTreeMap::new(),
        }
    }

    #[cfg(test)]
    #[must_use]
    pub fn ranges(&self) -> Vec<IpRange> {
        self.ranges_tree
            .iter()
            .map(|(_, (range, _))| *range)
            .collect()
    }

    /// Returns the total number of IP addresses covered by the ranges in this value.
    #[must_use]
    pub fn ip_len(&self) -> PrefixSize {
        let sum = self
            .ranges_tree
            .iter()
            .map(|(_, (range, _))| range.len())
            .sum();
        debug_assert!(sum < PrefixSize::Overflow);
        sum
    }

    /// Returns the IP address at the given offset in the ranges in this value.
    ///
    /// # Returns
    ///
    /// Returns `Some(addr)` if the offset is valid within the total number of elements covered by
    /// the ranges, or `None` otherwise.
    fn get_entry(&self, addr: &IpAddr, entry_offset: u128) -> Option<IpAddr> {
        if entry_offset >= self.ip_len() {
            return None;
        }

        self.ranges_tree
            .lookup(addr)
            .and_then(|(_, (range, range_offset))| range.get_entry(entry_offset - range_offset))
    }
}

/// Store IP prefix/ranges and port ranges in such a way that we can efficiently proceed to a 1:1
/// mapping between an original and a target couple {IP address, port}.
///
/// The structure contains:
///
/// - a port range to associate to an IP prefix, to check that this IP prefix returned from a parent
///   LPM lookup has the right port range for the processed packet.
/// - a `BTreeMap` that associates, to portions of the IP/port ranges, the corresponding target
///   IP/port ranges.
///
/// For example:
///
/// - 1.0.0.0/24, ports 4001-5000
/// - mapping to 2.0.0.0/25, ports 6001-7000, and 3.0.0.0/26, ports 8001-10000
///
/// The overall LPM entry is constructed like this:
///
/// - key: 1.0.0.0/24 (key for LPM lookup, of which `PortAddrTranslationValue` is the value)
/// - value (this is what is built in this function):
///     - associated port range: 4001-5000
///     - `BTreeMap` of associated port ranges to corresponding IP and port ranges
///         - entry 1
///             - key: ips 1.0.0.0:4001 to 1.0.0.127:5000
///             - associated IP range: 2.0.0.0/25
///             - associated port range: 6001-7000
///         - entry 2
///             - key: 1.0.0.128:4001 to 1.0.0.255:5000
///             - associated IP range: 3.0.0.0/26
///             - associated port range: 8001-10000
///
/// When translating IP 10.0.0.142, port 4003, we first look for the unique corresponding matching
/// prefix with a matching port range (combinations of IP and port ranges are not overlapping), and
/// we find the entry above. We refine the search by looking up in the `BTreeMap`, and find entry 2.
/// From there, we take the offset of (10.0.0.142, 4003) within the ranges (1.0.0.128:4001 to
/// 1.0.0.255:5000): 14 * 1000 + 3 = 14003, and we map it to the corresponding IP and port in the
/// target range (3.0.0.0/26, 8001-10000), which gives us IP 3.0.0.7, port 3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortAddrTranslationValue {
    prefix_port_ranges: BTreeSet<PortRange>,
    ranges_tree: DisjointRangesBTreeMap<IpPortRangeBounds, (IpPortRange, PrefixWithPortsSize)>,
}

impl PortAddrTranslationValue {
    #[must_use]
    #[allow(clippy::new_without_default)]
    pub fn new(prefix_port_ranges: BTreeSet<PortRange>) -> Self {
        Self {
            prefix_port_ranges,
            ranges_tree: DisjointRangesBTreeMap::new(),
        }
    }

    pub fn insert_and_merge(
        &mut self,
        key: IpPortRangeBounds,
        value: (IpPortRange, PrefixWithPortsSize),
    ) {
        self.insert(key, value);

        if let Some((previous_key, previous_value)) = self
            .ranges_tree
            .range((Bound::Unbounded, Bound::Excluded(&key)))
            .last()
        {
            // Copy entry
            let (key_copy, previous_key_copy) = (key, *previous_key);
            let (_, mut merge_value) = (*previous_key, *previous_value);
            // Try merging keys and values
            if let Some(merge_key) = Self::merge_ip_port_range_bounds(
                *previous_key,
                key,
                *self
                    .prefix_port_ranges
                    .iter()
                    .find(|pr| pr.contains(&key.start.port))
                    .unwrap_or_else(|| unreachable!()),
            ) && merge_value.0.extend_right(&value.0).is_some()
            {
                // Merge was successful, insert new value
                self.ranges_tree.insert(merge_key, merge_value);
                // Remove the two original entries that were merged
                self.ranges_tree.remove(&key_copy);
                self.ranges_tree.remove(&previous_key_copy);
            }
        }
    }

    fn merge_ip_port_range_bounds(
        left: IpPortRangeBounds,
        right: IpPortRangeBounds,
        ports: PortRange,
    ) -> Option<IpPortRangeBounds> {
        // Same IP, contiguous ports
        if left.end.ip == right.start.ip && left.end.port.saturating_add(1) == right.start.port {
            return Some(IpPortRangeBounds::new(left.start, right.end));
        }

        // Contiguous IPs, ports wrapping around port range
        match (left.end.ip, right.start.ip) {
            (IpAddr::V4(left_end_ip), IpAddr::V4(right_start_ip)) => {
                if left_end_ip.to_bits().saturating_add(1) != right_start_ip.to_bits()
                    || left.end.port != ports.end()
                    || right.start.port != ports.start()
                {
                    return None;
                }
            }
            (IpAddr::V6(left_end_ip), IpAddr::V6(right_start_ip)) => {
                if left_end_ip.to_bits().saturating_add(1) != right_start_ip.to_bits()
                    || left.end.port != ports.end()
                    || right.start.port != ports.start()
                {
                    return None;
                }
            }
            _ => return None,
        }
        Some(IpPortRangeBounds::new(left.start, right.end))
    }

    fn insert(
        &mut self,
        key: IpPortRangeBounds,
        value: (IpPortRange, PrefixWithPortsSize),
    ) -> Option<(IpPortRange, PrefixWithPortsSize)> {
        self.ranges_tree.insert(key, value)
    }

    fn size(&self) -> PrefixWithPortsSize {
        self.ranges_tree
            .iter()
            .map(|(_, (range, _))| range.size())
            .sum()
    }

    fn get_entry(
        &self,
        addr: &IpAddr,
        port: u16,
        entry_offset: PrefixWithPortsSize,
    ) -> Option<(IpAddr, u16)> {
        if entry_offset >= self.size() {
            return None;
        }

        let bounds = IpPort::new(*addr, port);
        self.ranges_tree
            .lookup(&bounds)
            .and_then(|(_, (range, range_offset))| range.get_entry(entry_offset - range_offset))
    }
}

impl From<AddrTranslationValue> for PortAddrTranslationValue {
    fn from(value: AddrTranslationValue) -> Self {
        Self {
            prefix_port_ranges: BTreeSet::from([PortRange::new_max_range()]),
            ranges_tree: value
                .ranges_tree
                .iter()
                .map(|(bounds, (range, offset))| {
                    (
                        // Complete port ranges with full available range (0-65535)
                        IpPortRangeBounds::new(
                            IpPort::new(bounds.start, 0),
                            IpPort::new(bounds.end, u16::MAX),
                        ),
                        (
                            // Complete target port ranges with full range, too
                            IpPortRange::new(*range, PortRange::new_max_range()),
                            // The offset from AddrTranslationValue was for counting IP, here we
                            // count IP multiplied by the number of ports covered by the associated
                            // port range. We use the full space of ports everywhere, so just
                            // multiply accordingly to obtain the new offset.
                            PrefixWithPortsSize::from(*offset)
                                * PrefixWithPortsSize::from(PortRange::new_max_range().len()),
                        ),
                    )
                })
                .collect(),
        }
    }
}

impl TryFrom<PortAddrTranslationValue> for AddrTranslationValue {
    type Error = NatTablesError;

    fn try_from(value: PortAddrTranslationValue) -> Result<Self, Self::Error> {
        // If we use ports (other than full 0-65535), we can't convert
        if value.prefix_port_ranges.len() != 1
            || !value
                .prefix_port_ranges
                .first()
                .unwrap_or_else(|| unreachable!())
                .is_max_range()
        {
            return Err(NatTablesError::NeedsPortRange);
        }

        let size_max_port_range = PortRange::MAX_LENGTH as u64;
        if value.ranges_tree.iter().any(|(bounds, (range, offset))| {
            bounds.start.port != 0
                || bounds.end.port != u16::MAX
                || !range.port_range.is_max_range()
                || *offset % (size_max_port_range) != 0
        }) {
            return Err(NatTablesError::NeedsPortRange);
        }

        Ok(Self {
            ranges_tree: value
                .ranges_tree
                .iter()
                .map(|(bounds, (range, offset))| {
                    let addr_offset_big = *offset / size_max_port_range;
                    debug_assert!(addr_offset_big <= u128::MAX.into());
                    let addr_offset = u128::cast_from(addr_offset_big);
                    (
                        // Keep only IPs, discard port ranges
                        IpRange::new(bounds.start.ip, bounds.end.ip),
                        (range.ip_range, addr_offset),
                    )
                })
                .collect(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct IpPortRange {
    ip_range: IpRange,
    port_range: PortRange,
}

impl IpPortRange {
    #[must_use]
    pub fn new(ip_range: IpRange, port_range: PortRange) -> Self {
        Self {
            ip_range,
            port_range,
        }
    }

    #[must_use]
    pub fn port_range(&self) -> PortRange {
        self.port_range
    }

    fn get_entry(&self, offset: PrefixWithPortsSize) -> Option<(IpAddr, u16)> {
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
    fn extend_right(&mut self, next: &IpPortRange) -> Option<()> {
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

    #[cfg(test)]
    #[must_use]
    pub fn contains(&self, addr: &IpAddr) -> bool {
        self.start <= *addr && *addr <= self.end
    }

    // Returns the number of IP addresses covered by the range.
    fn len(&self) -> PrefixSize {
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

    fn get_entry(&self, offset: u128) -> Option<IpAddr> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct IpPort {
    ip: IpAddr,
    port: u16,
}

impl IpPort {
    #[must_use]
    pub fn new(ip: IpAddr, port: u16) -> Self {
        Self { ip, port }
    }
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
        Self::new(value, IpPort::new(end_addr, u16::MAX))
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
