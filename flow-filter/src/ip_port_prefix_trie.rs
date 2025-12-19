// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::tables::AssociatedRanges;
use crate::tables::ConnectionTableValue;
use lpm::prefix::{PortRange, Prefix};
use lpm::trie::IpPrefixTrie;
use std::fmt::Debug;
use std::net::IpAddr;
use std::ops::RangeBounds;

pub trait ValueWithAssociatedRanges {
    fn covers_all_ports(&self) -> bool;
    fn covers_port(&self, port: u16) -> bool;
}

impl ValueWithAssociatedRanges for AssociatedRanges {
    fn covers_all_ports(&self) -> bool {
        match self {
            AssociatedRanges::AnyPort => true,
            AssociatedRanges::Ranges(ranges) => {
                ranges.iter().fold(0, |sum, range| sum + range.len()) == PortRange::MAX_LENGTH
            }
        }
    }

    fn covers_port(&self, port: u16) -> bool {
        match self {
            AssociatedRanges::AnyPort => true,
            AssociatedRanges::Ranges(ranges) => ranges.iter().any(|range| range.contains(&port)),
        }
    }
}

impl ValueWithAssociatedRanges for ConnectionTableValue {
    fn covers_all_ports(&self) -> bool {
        match self {
            ConnectionTableValue::AnyPort(_) => true,
            ConnectionTableValue::Ranges(connection_data) => {
                connection_data
                    .keys()
                    .fold(0, |sum, range| sum + range.len())
                    == PortRange::MAX_LENGTH
            }
        }
    }

    fn covers_port(&self, port: u16) -> bool {
        match self {
            ConnectionTableValue::AnyPort(_) => true,
            ConnectionTableValue::Ranges(ranges) => {
                ranges.iter().any(|(range, _)| range.contains(&port))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct IpPortPrefixTrie<V>(IpPrefixTrie<V>)
where
    V: Debug + Clone + ValueWithAssociatedRanges;

impl<V> IpPortPrefixTrie<V>
where
    V: Debug + Clone + ValueWithAssociatedRanges,
{
    #[must_use]
    pub fn new() -> Self {
        Self(IpPrefixTrie::new())
    }

    #[must_use]
    pub fn from(prefix: Prefix, value: V) -> Self {
        let mut trie = Self::new();
        trie.0.insert(prefix, value);
        trie
    }

    pub fn insert(&mut self, prefix: Prefix, value: V) {
        self.0.insert(prefix, value);
    }

    pub fn get_mut(&mut self, prefix: Prefix) -> Option<&mut V> {
        self.0.get_mut(prefix)
    }

    pub fn lookup(&self, addr: &IpAddr, port_opt: Option<u16>) -> Option<(Prefix, &V)> {
        // If the longest matching prefix has no associated port range, we assume it matches any
        // port, so the lookup is successful
        if let Some((prefix, value)) = self.0.lookup(*addr)
            && value.covers_all_ports()
        {
            return Some((prefix, value));
        }

        // Else, we need to check all matching IP prefixes (not necessarily the longest), and their
        // port ranges. We expect the trie to contain only one matching IP prefix matching the
        // address and associated to a port range matching the port, so we return the first we find.
        let port = port_opt?;
        let matching_entries = self.0.matching_entries(*addr);
        for (prefix, value) in matching_entries {
            if value.covers_port(port) {
                return Some((prefix, value));
            }
        }
        None
    }
}

impl<V> Default for IpPortPrefixTrie<V>
where
    V: Debug + Clone + ValueWithAssociatedRanges,
{
    fn default() -> Self {
        Self::new()
    }
}
