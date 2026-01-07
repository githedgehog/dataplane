// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! [`IpPortPrefixTrie`] is an [`IpPrefixTrie`] variant with support for port ranges.
//!
//! The struct provides a way to look up a tuple (IP address, port) in a trie of IP prefixes with
//! associated (optional) port ranges.

use crate::prefix::Prefix;
use crate::trie::IpPrefixTrie;
use std::fmt::Debug;
use std::net::IpAddr;

/// Trait for trie values to associate with IP prefixes. This values contain a port range. How the
/// port range is implemented does not matter, but it must implement the methods in this trait, for
/// the lookup to work correctly.
pub trait ValueWithAssociatedRanges {
    // Return true if the port range in the value covers all existing port values.
    // This is typically the case if the port range is optional and empty, in which case the IP
    // prefix is assumed to apply to all ports.
    fn covers_all_ports(&self) -> bool;
    // Return true if the port range in the value covers the given port.
    fn covers_port(&self, port: u16) -> bool;
}

/// An [`IpPrefixTrie`] variant with support for port ranges, for disjoint combinations of IP
/// prefixes and port ranges.
///
/// The struct provides a way to look up a tuple (IP address, port) in a trie of IP prefixes with
/// associated (optional) port ranges.
///
/// Internally, it is a LPM trie with IP prefixes as keys. Each key is associated with a value that
/// contains a port range. The lookup is more complex than a simple LPM lookup: we need to find the
/// prefix, but also the port range associated to an (IP address, port) tuple. All prefixes with
/// their associated port range are disjoint, but we can have colliding or identical prefixes, with
/// disjoint port ranges. So the lookup works this way:
///
/// - Iterate over all IP prefixes matching the given IP address
/// - For each matching prefix, check if the port range associated with it covers the given port
/// - Return the first match we find: as the combinations (IP prefix, port range) are disjoint,
///   there can be no more than one match.
#[derive(Debug, Clone)]
pub struct IpPortPrefixTrie<V>(IpPrefixTrie<V>)
where
    V: Debug + Clone + ValueWithAssociatedRanges;

impl<V> IpPortPrefixTrie<V>
where
    V: Debug + Clone + ValueWithAssociatedRanges,
{
    /// Create a new empty [`IpPortPrefixTrie`].
    #[must_use]
    pub fn new() -> Self {
        Self(IpPrefixTrie::new())
    }

    /// Create a new [`IpPortPrefixTrie`] with a single prefix and value.
    #[must_use]
    pub fn from(prefix: Prefix, value: V) -> Self {
        let mut trie = Self::new();
        trie.0.insert(prefix, value);
        trie
    }

    /// Insert a prefix and value into the trie.
    pub fn insert(&mut self, prefix: Prefix, value: V) {
        self.0.insert(prefix, value);
    }

    /// Get a mutable reference to the value associated with a prefix.
    pub fn get_mut(&mut self, prefix: Prefix) -> Option<&mut V> {
        self.0.get_mut(prefix)
    }

    /// Look up an IP address and optional port in the trie.
    ///
    /// Returns the longest matching prefix and its associated value, if any.
    ///
    /// See the documentation of [`IpPortPrefixTrie`] for details on the lookup logic.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prefix::{PortRange, Prefix};
    use std::collections::BTreeSet;
    use std::ops::RangeBounds;

    #[derive(Debug, Clone)]
    enum TestValue {
        AnyPort,
        Ranges(BTreeSet<PortRange>),
    }

    impl ValueWithAssociatedRanges for TestValue {
        fn covers_all_ports(&self) -> bool {
            match self {
                TestValue::AnyPort => true,
                TestValue::Ranges(ranges) => {
                    ranges.iter().fold(0, |sum, range| sum + range.len()) == PortRange::MAX_LENGTH
                }
            }
        }

        fn covers_port(&self, port: u16) -> bool {
            match self {
                TestValue::AnyPort => true,
                TestValue::Ranges(ranges) => ranges.iter().any(|range| range.contains(&port)),
            }
        }
    }

    #[test]
    fn test_new() {
        let trie: IpPortPrefixTrie<TestValue> = IpPortPrefixTrie::new();
        assert!(trie.lookup(&"192.168.1.1".parse().unwrap(), None).is_none());
    }

    #[test]
    fn test_from() {
        let prefix = Prefix::from("192.168.1.0/24");
        let value = TestValue::AnyPort;
        let trie = IpPortPrefixTrie::from(prefix, value);

        let result = trie.lookup(&"192.168.1.5".parse().unwrap(), None);
        assert!(result.is_some());
        let (matched_prefix, _) = result.unwrap();
        assert_eq!(matched_prefix, prefix);
    }

    #[test]
    fn test_insert_and_lookup_any_port() {
        let mut trie = IpPortPrefixTrie::new();
        let prefix = Prefix::from("10.0.0.0/16");
        let value = TestValue::AnyPort;

        trie.insert(prefix, value);

        // Should match with any port
        let result = trie.lookup(&"10.0.1.5".parse().unwrap(), Some(80));
        assert!(result.is_some());
        let (matched_prefix, matched_value) = result.unwrap();
        assert_eq!(matched_prefix, prefix);
        assert!(matches!(matched_value, TestValue::AnyPort));

        // Should match without port
        let result = trie.lookup(&"10.0.1.5".parse().unwrap(), None);
        assert!(result.is_some());
    }

    #[test]
    fn test_insert_and_lookup_with_port_ranges() {
        let mut trie = IpPortPrefixTrie::new();
        let prefix = Prefix::from("172.16.0.0/12");
        let ranges = BTreeSet::from([PortRange::new(80, 90).unwrap()]);
        let value = TestValue::Ranges(ranges);

        trie.insert(prefix, value);

        // Should match port in range
        let result = trie.lookup(&"172.16.5.10".parse().unwrap(), Some(85));
        assert!(result.is_some());
        let (matched_prefix, _) = result.unwrap();
        assert_eq!(matched_prefix, prefix);

        // Should not match port outside range
        let result = trie.lookup(&"172.16.5.10".parse().unwrap(), Some(100));
        assert!(result.is_none());

        // Should not match without port
        let result = trie.lookup(&"172.16.5.10".parse().unwrap(), None);
        assert!(result.is_none());
    }

    #[test]
    fn test_lookup_longest_prefix_match_no_ports() {
        let mut trie = IpPortPrefixTrie::new();

        // Insert prefix with port range
        let prefix_with_ports = Prefix::from("192.168.0.0/24");
        let ranges = BTreeSet::from([PortRange::new(80, 90).unwrap()]);
        trie.insert(prefix_with_ports, TestValue::Ranges(ranges));

        // Insert prefix covering all ports
        let prefix_alone = Prefix::from("192.168.1.0/24");
        trie.insert(prefix_alone, TestValue::AnyPort);

        // Match wihout port
        let result = trie.lookup(&"192.168.1.5".parse().unwrap(), None);
        assert!(result.is_some());
        let (matched_prefix, _) = result.unwrap();
        assert_eq!(matched_prefix, prefix_alone);

        // Match with a port
        let result = trie.lookup(&"192.168.1.5".parse().unwrap(), Some(443));
        assert!(result.is_some());
        let (matched_prefix, _) = result.unwrap();
        assert_eq!(matched_prefix, prefix_alone);

        // Fail to match prefix_with_ports without a port
        let result = trie.lookup(&"192.168.0.5".parse().unwrap(), None);
        assert!(result.is_none());

        // Match with a port
        let result = trie.lookup(&"192.168.0.5".parse().unwrap(), Some(80));
        assert!(result.is_some());
        let (matched_prefix, _) = result.unwrap();
        assert_eq!(matched_prefix, prefix_with_ports);
    }

    #[test]
    fn test_lookup_longest_prefix_match_with_ports() {
        let mut trie = IpPortPrefixTrie::new();

        // Insert broader prefix
        let prefix_16 = Prefix::from("192.168.0.0/16");
        let ranges = BTreeSet::from([PortRange::new(80, 90).unwrap()]);
        trie.insert(prefix_16, TestValue::Ranges(ranges));

        // Insert more specific prefix
        let prefix_24 = Prefix::from("192.168.1.0/24");
        let ranges = BTreeSet::from([PortRange::new(443, 443).unwrap()]);
        trie.insert(prefix_24, TestValue::Ranges(ranges));

        // Without port, there is not match
        let result = trie.lookup(&"192.168.1.5".parse().unwrap(), None);
        assert!(result.is_none());

        // Based on port, we match the more specific prefix
        let result = trie.lookup(&"192.168.1.5".parse().unwrap(), Some(443));
        assert!(result.is_some());
        let (matched_prefix, _) = result.unwrap();
        assert_eq!(matched_prefix, prefix_24);

        // Based on port, we match the broader prefix
        let result = trie.lookup(&"192.168.1.5".parse().unwrap(), Some(80));
        assert!(result.is_some());
        let (matched_prefix, _) = result.unwrap();
        assert_eq!(matched_prefix, prefix_16);
    }

    #[test]
    fn test_get_mut() {
        let mut trie = IpPortPrefixTrie::new();
        let prefix = Prefix::from("203.0.113.0/24");
        let ranges = BTreeSet::from([PortRange::new(8080, 8090).unwrap()]);
        trie.insert(prefix, TestValue::Ranges(ranges));

        // Modify the value
        if let Some(value) = trie.get_mut(prefix) {
            *value = TestValue::AnyPort;
        }

        // Should now match with any port
        let result = trie.lookup(&"203.0.113.5".parse().unwrap(), Some(9999));
        assert!(result.is_some());
        let (_, matched_value) = result.unwrap();
        assert!(matches!(matched_value, TestValue::AnyPort));
    }

    #[test]
    fn test_ipv6_lookup() {
        let mut trie = IpPortPrefixTrie::new();
        let prefix = Prefix::from("2001:db8::/32");
        trie.insert(prefix, TestValue::AnyPort);

        let result = trie.lookup(&"2001:db8::1".parse().unwrap(), None);
        assert!(result.is_some());
        let (matched_prefix, _) = result.unwrap();
        assert_eq!(matched_prefix, prefix);

        let result = trie.lookup(&"2001:db9::1".parse().unwrap(), None);
        assert!(result.is_none());
    }

    #[test]
    fn test_covers_all_ports() {
        let any_port = TestValue::AnyPort;
        assert!(any_port.covers_all_ports());

        let mut ranges = BTreeSet::new();
        ranges.insert(PortRange::new(0, 32767).unwrap());
        ranges.insert(PortRange::new(32768, 65535).unwrap());
        let full_range = TestValue::Ranges(ranges);
        assert!(full_range.covers_all_ports());

        let partial_ranges = BTreeSet::from([PortRange::new(80, 443).unwrap()]);
        let partial_range = TestValue::Ranges(partial_ranges);
        assert!(!partial_range.covers_all_ports());
    }

    #[test]
    fn test_covers_port() {
        let any_port = TestValue::AnyPort;
        assert!(any_port.covers_port(80));
        assert!(any_port.covers_port(65535));

        let mut ranges = BTreeSet::new();
        ranges.insert(PortRange::new(80, 80).unwrap());
        ranges.insert(PortRange::new(443, 443).unwrap());
        let specific_ports = TestValue::Ranges(ranges);
        assert!(specific_ports.covers_port(80));
        assert!(specific_ports.covers_port(443));
        assert!(!specific_ports.covers_port(8080));
    }
}
