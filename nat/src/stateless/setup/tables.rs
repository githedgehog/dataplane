// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use ahash::RandomState;
use net::vxlan::Vni;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::debug;

/// Error type for [`NatTables`] operations.
#[derive(thiserror::Error, Debug)]
pub enum NatTablesError {
    #[error("entry already exists")]
    EntryExists,
    #[error("bad IP version")]
    BadIpVersion,
}

/// An object containing the rules for the NAT pipeline stage, not in terms of states for the
/// different connections established, but instead holding the base rules for stateful or static
/// NAT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatTables(HashMap<u32, PerVniTable, RandomState>);

impl NatTables {
    /// Creates a new empty [`NatTables`]
    #[must_use]
    pub fn new() -> Self {
        Self(HashMap::with_hasher(RandomState::with_seed(0)))
    }

    /// Adds a new table for the given `Vni`
    pub fn add_table(&mut self, table: PerVniTable) {
        self.0.insert(table.vni.into(), table);
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerVniTable {
    pub vni: Vni,
    pub dst_nat: NatRuleTable,
    pub src_nat: HashMap<Vni, NatRuleTable>,
}

impl PerVniTable {
    /// Creates a new empty [`PerVniTable`]
    #[must_use]
    pub fn new(vni: Vni) -> Self {
        Self {
            vni,
            dst_nat: NatRuleTable::new(),
            src_nat: HashMap::new(),
        }
    }

    /// Search for the NAT ranges information for source NAT associated to the given address.
    ///
    /// # Returns
    ///
    /// Returns the NAT ranges information associated with the given address if it is present in the
    /// table. If the address is not present, it returns `None`.
    #[must_use]
    pub fn lookup_src_prefixes(&self, addr: &IpAddr, dst_vni: Vni) -> Option<NatTableValue> {
        debug!("Looking up src prefixes for address: {addr}, dst_vni: {dst_vni}...");
        self.src_nat.get(&dst_vni)?.lookup(addr)
    }

    /// Search for the NAT ranges information for destination NAT associated to the given address.
    ///
    /// # Returns
    ///
    /// Returns the NAT ranges information associated with the given address if it is present in the
    /// table. If the address is not present, it returns `None`.
    #[must_use]
    pub fn lookup_dst_prefixes(&self, addr: &IpAddr) -> Option<NatTableValue> {
        debug!("Looking up dst prefixes for address: {addr}...");
        self.dst_nat.lookup(addr)
    }

    /// Calls `lookup_src_prefixes` and `lookup_dst_prefixes` for the given pair of src/dst addresses.
    pub(crate) fn find_nat_ranges(
        &self,
        src: IpAddr,
        dst: IpAddr,
        dst_vni: Vni,
    ) -> (Option<NatTableValue>, Option<NatTableValue>) {
        let src_nat_ranges = self.lookup_src_prefixes(&src, dst_vni);
        let dst_nat_ranges = self.lookup_dst_prefixes(&dst);
        (src_nat_ranges, dst_nat_ranges)
    }
}

/// From a current address prefix, find the target address prefix.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NatRuleTable {
    pub rules_v4: BTreeMap<Ipv4Addr, (Ipv4Addr, Ipv4Addr)>,
    pub rules_v6: BTreeMap<Ipv6Addr, (Ipv6Addr, Ipv6Addr)>,
}

impl NatRuleTable {
    #[must_use]
    /// Creates a new empty [`NatRuleTable`]
    pub fn new() -> Self {
        Self {
            rules_v4: BTreeMap::new(),
            rules_v6: BTreeMap::new(),
        }
    }

    /// Inserts a new entry in the table
    ///
    /// # Errors
    ///
    /// Returns an error if the IP version of the address does not match the IP version of the IP
    /// addresses in the value.
    pub fn insert(&mut self, value: &NatTableValue) -> Result<(), NatTablesError> {
        match (
            value.orig_range_start,
            value.orig_range_end,
            value.target_range_start,
        ) {
            (IpAddr::V4(start), IpAddr::V4(end), IpAddr::V4(target)) => {
                if self.rules_v4.insert(start, (end, target)).is_some() {
                    return Err(NatTablesError::EntryExists);
                }
            }
            (IpAddr::V6(start), IpAddr::V6(end), IpAddr::V6(target)) => {
                if self.rules_v6.insert(start, (end, target)).is_some() {
                    return Err(NatTablesError::EntryExists);
                }
            }
            _ => {
                return Err(NatTablesError::BadIpVersion);
            }
        }
        Ok(())
    }

    /// Looks up for the value associated with the given address.
    ///
    /// # Returns
    ///
    /// Returns the value associated with the given address if it is present in the table. If the
    /// address is not present, it returns `None`.
    #[must_use]
    pub fn lookup(&self, addr: &IpAddr) -> Option<NatTableValue> {
        match addr {
            IpAddr::V4(ip) => {
                let value = self
                    .rules_v4
                    .range(..=ip)
                    .next_back()
                    .map(|v| NatTableValue {
                        orig_range_start: IpAddr::V4(*v.0),
                        orig_range_end: IpAddr::V4(v.1.0),
                        target_range_start: IpAddr::V4(v.1.1),
                    });
                match value {
                    Some(v) if v.orig_range_end < *ip => None,
                    Some(v) => Some(v),
                    None => None,
                }
            }
            IpAddr::V6(ip) => {
                let value = self
                    .rules_v6
                    .range(..=ip)
                    .next_back()
                    .map(|v| NatTableValue {
                        orig_range_start: IpAddr::V6(*v.0),
                        orig_range_end: IpAddr::V6(v.1.0),
                        target_range_start: IpAddr::V6(v.1.1),
                    });
                match value {
                    Some(v) if v.orig_range_end < *ip => None,
                    Some(v) => Some(v),
                    None => None,
                }
            }
        }
    }
}

/// A value associated with a prefix in the table, and that encapsulates all information required to
/// perform the address mapping for stateless NAT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatTableValue {
    pub orig_range_start: IpAddr,
    pub orig_range_end: IpAddr,
    pub target_range_start: IpAddr,
}
