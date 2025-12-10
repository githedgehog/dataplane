// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use ahash::RandomState;
use bnum::cast::CastFrom;
use lpm::prefix::{IpPrefix, IpRangeWithPorts, PortRange, Prefix, PrefixSize, PrefixWithPortsSize};
use lpm::trie::IpPrefixTrie;
use net::vxlan::Vni;
use std::collections::{BTreeSet, HashMap};
use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::RangeBounds;
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
                ranges.get_entry(offset).map(|addr| (addr, None))
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
                    .get_entry(offset)
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
    ranges: Vec<IpRange>,
}

impl AddrTranslationValue {
    #[must_use]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    /// Adds a new range to the structure.
    ///
    /// Note: When possible, the new range is merged with the latest range in the list; so there is
    /// no guarantee, when calling this method, that the new range is added as a separate range, and
    /// that `self.ranges.len()` will be incremented.
    pub fn add_range(&mut self, range: IpRange) {
        if self.ranges.is_empty() {
            self.push(range);
            return;
        }

        let last_range = self.ranges.last_mut().unwrap_or_else(|| {
            // We checked ranges vector is not empty
            unreachable!()
        });
        last_range.merge(&range).unwrap_or_else(|| self.push(range));
    }

    #[cfg(test)]
    #[must_use]
    pub fn ranges(&self) -> &Vec<IpRange> {
        &self.ranges
    }

    fn push(&mut self, range: IpRange) {
        self.ranges.push(range);
    }

    /// Returns the total number of IP addresses covered by the ranges in this value.
    pub fn ip_len(&self) -> PrefixSize {
        let sum = self.ranges.iter().map(IpRange::len).sum();
        debug_assert!(sum < PrefixSize::Overflow);
        sum
    }

    /// Returns the IP address at the given offset in the ranges in this value.
    ///
    /// # Returns
    ///
    /// Returns `Some(addr)` if the offset is valid within the total number of elements covered by
    /// the ranges, or `None` otherwise.
    fn get_entry(&self, entry_offset: u128) -> Option<IpAddr> {
        if entry_offset >= self.ip_len() {
            return None;
        }

        let mut offset = PrefixSize::U128(entry_offset);
        for range in &self.ranges {
            if offset < range.len() {
                // We never grow offset, it cannot overflow a u128
                return range.get_entry(offset.try_into().unwrap_or_else(|_| unreachable!()));
            }
            offset -= range.len();
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortAddrTranslationValue {
    prefix_port_ranges: BTreeSet<PortRange>,
    ranges: Vec<IpPortRange>,
}

impl PortAddrTranslationValue {
    #[must_use]
    #[allow(clippy::new_without_default)]
    pub fn new(prefix_port_ranges: BTreeSet<PortRange>) -> Self {
        Self {
            prefix_port_ranges,
            ranges: Vec::new(),
        }
    }

    /// Adds a new range to the structure.
    ///
    /// Note: When possible, the new range is merged with the latest range in the list; so there is
    /// no guarantee, when calling this method, that the new range is added as a separate range, and
    /// that `self.ranges.len()` will be incremented.
    pub fn add_ranges(&mut self, new_ranges: Vec<IpPortRange>) {
        for range in new_ranges {
            if self.is_empty() {
                self.push(range);
                return;
            }

            let last_range = self.ranges.last_mut().unwrap_or_else(|| {
                // We checked ranges vector is not empty
                unreachable!()
            });
            last_range.merge(&range).unwrap_or_else(|| self.push(range));
        }
    }

    fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    fn push(&mut self, range: IpPortRange) {
        self.ranges.push(range);
    }

    fn size(&self) -> PrefixWithPortsSize {
        self.ranges.iter().map(IpPortRange::size).sum()
    }

    fn get_entry(&self, entry_offset: PrefixWithPortsSize) -> Option<(IpAddr, u16)> {
        if entry_offset >= self.size() {
            return None;
        }

        let mut offset = entry_offset;
        for range in &self.ranges {
            if offset < range.size() {
                return range.get_entry(offset);
            }
            offset -= range.size();
        }
        None
    }
}

impl From<AddrTranslationValue> for PortAddrTranslationValue {
    fn from(value: AddrTranslationValue) -> Self {
        Self {
            prefix_port_ranges: BTreeSet::from([PortRange::new_max_range()]),
            ranges: value
                .ranges
                .iter()
                .map(|range| IpPortRange::new(range.clone(), PortRange::new_max_range()))
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
        if value
            .ranges
            .iter()
            .any(|range| !range.port_range.is_max_range())
        {
            return Err(NatTablesError::NeedsPortRange);
        }
        Ok(Self {
            ranges: value
                .ranges
                .iter()
                .map(|range| range.ip_range.clone())
                .collect(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    fn merge(&mut self, next: &IpPortRange) -> Option<()> {
        // Always merge on the "right side". This is because we call this method assuming that
        // ranges are ordered (by IP range start, then port range start values), and we process the
        // smaller ones first; if we try to merge a new one into an existing one, it's a "bigger"
        // one, so we merge on the right side.

        // Case 1: port ranges are identical
        if self.port_range == next.port_range {
            return self.ip_range.merge(&next.ip_range);
        }

        // Case 2: IP ranges are identical
        if self.ip_range == next.ip_range {
            return self.port_range.merge(next.port_range);
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    fn merge(&mut self, next: &IpRange) -> Option<()> {
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
