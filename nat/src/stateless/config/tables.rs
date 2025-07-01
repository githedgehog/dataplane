// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::stateless::config::prefixtrie::{PrefixTrie, TrieError};

use ahash::RandomState;
use net::vxlan::Vni;
use routing::prefix::Prefix;
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use tracing::debug;

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
    pub dst_nat: NatPrefixRuleTable,
    pub src_nat_peers: NatPeerRuleTable,
    pub src_nat_prefixes: Vec<NatPrefixRuleTable>,
}

impl PerVniTable {
    /// Creates a new empty [`PerVniTable`]
    #[must_use]
    pub fn new(vni: Vni) -> Self {
        Self {
            vni,
            dst_nat: NatPrefixRuleTable::new(),
            src_nat_peers: NatPeerRuleTable::new(),
            src_nat_prefixes: Vec::new(),
        }
    }

    /// Search for the list of prefixes for source NAT associated to the given address.
    ///
    /// # Returns
    ///
    /// Returns the value associated with the given address if it is present in the trie. If the
    /// address is not present, it returns `None`.
    #[must_use]
    fn lookup_src_prefixes(&self, saddr: &IpAddr, daddr: &IpAddr) -> Option<&TrieValue> {
        debug!("Looking up src prefixes for src: {saddr} dst: {daddr}...");
        // Find relevant prefix table for involved peer
        let peer_indices = self.src_nat_peers.lookup(daddr)?;

        // Look up for the NAT prefix in that table
        for peer_index in peer_indices {
            let prefix_table = self.src_nat_prefixes.get(*peer_index)?;
            if let Some((_, value)) = prefix_table.lookup(saddr) {
                return value.as_ref();
            }
        }
        None
    }

    /// Search for the list of prefixes for destination NAT associated to the given address.
    ///
    /// # Returns
    ///
    /// Returns the value associated with the given address if it is present in the trie. If the
    /// address is not present, it returns `None`.
    #[must_use]
    fn lookup_dst_prefixes(&self, addr: &IpAddr) -> Option<&TrieValue> {
        debug!("Looking up dst prefixes for address: {addr}...");
        // Look up for the NAT prefix in the table
        let (_, value) = self.dst_nat.lookup(addr)?;

        value.as_ref()
    }

    /// Calls `lookup_src_prefixes` and `lookup_dst_prefixes` for the given pair of src/dst addresses.
    pub(crate) fn find_nat_ranges(
        &self,
        src: IpAddr,
        dst: IpAddr,
    ) -> (Option<&TrieValue>, Option<&TrieValue>) {
        let src_nat_ranges = self.lookup_src_prefixes(&src, &dst);
        let dst_nat_ranges = self.lookup_dst_prefixes(&dst);
        (src_nat_ranges, dst_nat_ranges)
    }
}

/// From a current address prefix, find the target address prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatPrefixRuleTable {
    pub rules: PrefixTrie<Option<TrieValue>>,
}

/// From a current address prefix, find the relevant [`NatPrefixRuleTable`] for the target prefix
/// lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatPeerRuleTable {
    pub rules: PrefixTrie<Vec<usize>>,
}

impl NatPrefixRuleTable {
    #[must_use]
    /// Creates a new empty [`NatPrefixRuleTable`]
    pub fn new() -> Self {
        Self {
            rules: PrefixTrie::new(),
        }
    }

    /// Inserts a new entry in the table
    ///
    /// # Errors
    ///
    /// Returns an error if the prefix is already in the table
    pub fn insert(&mut self, key: &Prefix, value: TrieValue) -> Result<(), TrieError> {
        self.rules.insert(key, Some(value))
    }

    /// Inserts a new entry in the table, with no value
    ///
    /// # Errors
    ///
    /// Returns an error if the prefix is already in the table
    pub fn insert_none(&mut self, key: &Prefix) -> Result<(), TrieError> {
        self.rules.insert(key, None)
    }

    /// Looks up for the value associated with the given address.
    ///
    /// # Returns
    ///
    /// Returns the value associated with the given address if it is present in the trie. If the
    /// address is not present, it returns `None`.
    #[must_use]
    pub fn lookup(&self, addr: &IpAddr) -> Option<(Prefix, &Option<TrieValue>)> {
        self.rules.lookup(addr)
    }
}

impl Default for NatPrefixRuleTable {
    fn default() -> Self {
        Self::new()
    }
}

impl NatPeerRuleTable {
    /// Creates a new empty [`NatPeerRuleTable`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: PrefixTrie::new(),
        }
    }

    /// Inserts a new entry in the table
    ///
    /// # Errors
    ///
    /// Returns an error if the prefix is already in the table
    pub fn insert(&mut self, prefix: &Prefix, target_index: usize) -> Result<(), TrieError> {
        let rule_opt = self.rules.get_mut(prefix);
        if let Some(rule) = rule_opt {
            rule.push(target_index);
            Ok(())
        } else {
            self.rules.insert(prefix, vec![target_index])
        }
    }

    /// Looks up for the value associated with the given address.
    ///
    /// # Returns
    ///
    /// Returns the value associated with the given address if it is present in the trie. If the
    /// address is not present, it returns `None`.
    #[must_use]
    pub fn lookup(&self, addr: &IpAddr) -> Option<&Vec<usize>> {
        self.rules.lookup(addr).map(|(_, v)| v)
    }
}

impl Default for NatPeerRuleTable {
    fn default() -> Self {
        Self::new()
    }
}

/// A value associated with a prefix in the trie, and that encapsulates all information required to
/// perform the address mapping for static NAT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrieValue {
    vni: Option<Vni>,
    orig_prefix: Prefix,
    orig_prefix_offset: u128,
    target: BTreeSet<Prefix>,
}

impl TrieValue {
    /// Creates a new [`TrieValue`]
    #[must_use]
    pub fn new(
        vni: Vni,
        orig_prefix: Prefix,
        orig_prefix_offset: u128,
        target: BTreeSet<Prefix>,
    ) -> Self {
        Self {
            vni: Some(vni),
            orig_prefix,
            orig_prefix_offset,
            target,
        }
    }
    /// Get the `Vni` associated to this [`TrieValue`]
    #[must_use]
    pub fn get_vni(&self) -> Option<Vni> {
        self.vni
    }

    /// Accessor for original prefix offset
    #[must_use]
    pub fn orig_prefix_offset(&self) -> u128 {
        self.orig_prefix_offset
    }

    /// Accessor for original prefix
    #[must_use]
    pub fn orig_prefix(&self) -> &Prefix {
        &self.orig_prefix
    }

    /// Accessor for target prefixes
    #[must_use]
    pub fn target_prefixes(&self) -> &BTreeSet<Prefix> {
        &self.target
    }

    /// Iterates over the target prefixes
    pub fn target_prefixes_iter(&self) -> impl Iterator<Item = &Prefix> {
        self.target.iter()
    }
}
