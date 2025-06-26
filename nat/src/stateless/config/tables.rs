// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::stateless::config::prefixtrie::{PrefixTrie, TrieError};

use net::vxlan::Vni;
use routing::prefix::Prefix;
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

/// An object containing the rules for the NAT pipeline stage, not in terms of states for the
/// different connections established, but instead holding the base rules for stateful or static
/// NAT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatTables {
    pub tables: HashMap<u32, PerVniTable>,
}

impl NatTables {
    /// Creates a new empty [`NatTables`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            tables: HashMap::new(),
        }
    }

    /// Adds a new table for the given VNI
    pub fn add_table(&mut self, vni: Vni, table: PerVniTable) {
        self.tables.insert(vni.as_u32(), table);
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
    pub dst_nat: NatPrefixRuleTable,
    pub src_nat_peers: NatPeerRuleTable,
    pub src_nat_prefixes: Vec<NatPrefixRuleTable>,
}

impl PerVniTable {
    /// Creates a new empty [`PerVniTable`]
    #[must_use]
    pub fn new() -> Self {
        Self {
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
    pub fn lookup_src_prefixes(&self, addr: &IpAddr) -> Option<&TrieValue> {
        // Find relevant prefix table for involved peer
        let peer_index = self.src_nat_peers.lookup(addr)?;

        // Look up for the NAT prefix in that table
        let prefix_table = self.src_nat_prefixes.get(peer_index)?;
        let (_, value) = prefix_table.lookup(addr)?;

        value.as_ref()
    }

    /// Search for the list of prefixes for destination NAT associated to the given address.
    ///
    /// # Returns
    ///
    /// Returns the value associated with the given address if it is present in the trie. If the
    /// address is not present, it returns `None`.
    #[must_use]
    pub fn lookup_dst_prefixes(&self, addr: &IpAddr) -> Option<&TrieValue> {
        // Look up for the NAT prefix in the table
        let (_, value) = self.dst_nat.lookup(addr)?;

        value.as_ref()
    }
}

impl Default for PerVniTable {
    fn default() -> Self {
        Self::new()
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
    pub rules: PrefixTrie<usize>,
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
        self.rules.insert(prefix, target_index)
    }

    /// Looks up for the value associated with the given address.
    ///
    /// # Returns
    ///
    /// Returns the value associated with the given address if it is present in the trie. If the
    /// address is not present, it returns `None`.
    #[must_use]
    pub fn lookup(&self, addr: &IpAddr) -> Option<usize> {
        self.rules.lookup(addr).map(|(_, v)| v).copied()
    }
}

impl Default for NatPeerRuleTable {
    fn default() -> Self {
        Self::new()
    }
}

/// A value associated with a prefix in the trie, and that encapsulates all information required to
/// perform the address mapping for static NAT.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrieValue {
    orig: BTreeSet<Prefix>,
    orig_excludes: BTreeSet<Prefix>,
    target: BTreeSet<Prefix>,
    target_excludes: BTreeSet<Prefix>,
}

impl TrieValue {
    /// Creates a new [`TrieValue`]
    #[must_use]
    pub fn new(
        orig: BTreeSet<Prefix>,
        orig_excludes: BTreeSet<Prefix>,
        target: BTreeSet<Prefix>,
        target_excludes: BTreeSet<Prefix>,
    ) -> Self {
        Self {
            orig,
            orig_excludes,
            target,
            target_excludes,
        }
    }

    /// Accessor for original prefixes
    #[must_use]
    pub fn orig_prefixes(&self) -> &BTreeSet<Prefix> {
        &self.orig
    }

    /// Accessor for original exclusion prefixes
    #[must_use]
    pub fn orig_excludes(&self) -> &BTreeSet<Prefix> {
        &self.orig_excludes
    }

    /// Accessor for target prefixes
    #[must_use]
    pub fn target_prefixes(&self) -> &BTreeSet<Prefix> {
        &self.target
    }

    /// Accessor for target exclusion prefixes
    #[must_use]
    pub fn target_excludes(&self) -> &BTreeSet<Prefix> {
        &self.target_excludes
    }

    /// Iterates over the original prefixes
    pub fn orig_prefixes_iter(&self) -> impl Iterator<Item = &Prefix> {
        self.orig.iter()
    }

    /// Iterates over the original exclusion prefixes
    pub fn orig_excludes_iter(&self) -> impl Iterator<Item = &Prefix> {
        self.orig_excludes.iter()
    }

    /// Iterates over the target prefixes
    pub fn target_prefixes_iter(&self) -> impl Iterator<Item = &Prefix> {
        self.target.iter()
    }

    /// Iterates over the target exclusion prefixes
    pub fn target_excludes_iter(&self) -> impl Iterator<Item = &Prefix> {
        self.target_excludes.iter()
    }
}
