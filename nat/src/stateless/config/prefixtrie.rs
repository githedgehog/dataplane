// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! This submodule provides an IP version-independent trie data structure, to associate values to IP
//! prefixes.

#![allow(clippy::missing_errors_doc)]

use iptrie::map::RTrieMap;
use iptrie::{Ipv4Prefix, Ipv6Prefix};
use routing::prefix::Prefix;
use std::fmt::Debug;
use std::net::IpAddr;

/// Error type for [`PrefixTrie`] operations.
#[derive(thiserror::Error, Debug)]
pub enum TrieError {
    #[error("entry already exists")]
    EntryExists,
}

/// A [`PrefixTrie`] is a data structure that stores a set of IP prefixes and their associated
/// [`String`] values, independent of the IP address family.
///
/// It is used to efficiently look up the value associated with a given IP address.
///
/// Internally, it relies on two different tries, one for IPv4 and one for IPv6.
#[derive(Default, Clone)]
pub struct PrefixTrie<T> {
    trie_ipv4: RTrieMap<Ipv4Prefix, T>,
    trie_ipv6: RTrieMap<Ipv6Prefix, T>,
}

impl<T> PrefixTrie<T>
where
    T: Default + Debug,
{
    /// Creates a new [`PrefixTrie`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            trie_ipv4: RTrieMap::new(),
            trie_ipv6: RTrieMap::new(),
        }
    }
}

impl<T> PrefixTrie<T>
where
    T: Debug,
{
    /// Creates a new [`PrefixTrie`].
    pub fn with_roots(root_v4: T, root_v6: T) -> Self {
        Self {
            trie_ipv4: RTrieMap::with_root(root_v4),
            trie_ipv6: RTrieMap::with_root(root_v6),
        }
    }

    /// Inserts a new IPv4 prefix and its associated value into the trie.
    ///
    /// Note: This method is not thread-safe.
    pub fn insert_ipv4(&mut self, prefix: Ipv4Prefix, value: T) -> Result<(), TrieError> {
        // Insertion always succeeds even if the key already in the map.
        // So we first need to ensure the key is not already in use.
        //
        // TODO: This is not thread-safe.
        if self.trie_ipv4.get(&prefix).is_some() {
            return Err(TrieError::EntryExists);
        }
        self.trie_ipv4.insert(prefix, value);
        Ok(())
    }

    /// Inserts a new IPv6 prefix and its associated value into the trie.
    ///
    /// Note: This method is not thread-safe.
    pub fn insert_ipv6(&mut self, prefix: Ipv6Prefix, value: T) -> Result<(), TrieError> {
        // See comment for IPv4
        if self.trie_ipv6.get(&prefix).is_some() {
            return Err(TrieError::EntryExists);
        }
        self.trie_ipv6.insert(prefix, value);
        Ok(())
    }

    /// Inserts a new prefix and its associated value into the trie.
    ///
    /// Note: This method is not thread-safe.
    pub fn insert(&mut self, prefix: &Prefix, value: T) -> Result<(), TrieError> {
        match prefix {
            Prefix::IPV4(p) => self.insert_ipv4(*p, value),
            Prefix::IPV6(p) => self.insert_ipv6(*p, value),
        }
    }

    /// Looks up for the value associated with the given address.
    ///
    /// This function returns the value associated with the given address if it is present in the
    /// trie. If the address is not present, it will return `None`.
    #[must_use]
    pub fn lookup(&self, addr: &IpAddr) -> Option<(Prefix, &T)> {
        match addr {
            IpAddr::V4(ip) => {
                let (&k, v) = self.trie_ipv4.lookup(&Ipv4Prefix::from(*ip));
                // The RTrieMap lookup always return an entry; if no better match, it returns the
                // root of the map, which always exists.  This means that to check if the result is
                // "empty", we need to check whether the returned entry is the root for the map.
                if Prefix::IPV4(k).is_root() {
                    None
                } else {
                    Some((Prefix::IPV4(k), v))
                }
            }
            IpAddr::V6(ip) => {
                let (&k, v) = self.trie_ipv6.lookup(&Ipv6Prefix::from(*ip));
                // The RTrieMap lookup always return an entry; if no better match, it returns the
                // root of the map, which always exists.  This means that to check if the result is
                // "empty", we need to check whether the returned entry is the root for the map.
                if Prefix::IPV6(k).is_root() {
                    None
                } else {
                    Some((Prefix::IPV6(k), v))
                }
            }
        }
    }
}

impl<T> Debug for PrefixTrie<T>
where
    T: Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_map()
            .entries(self.trie_ipv4.iter())
            .entries(self.trie_ipv6.iter())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    fn prefix_v4(s: &str) -> Ipv4Prefix {
        Ipv4Prefix::from_str(s).expect("Invalid IPv4 prefix")
    }

    fn prefix_v6(s: &str) -> Ipv6Prefix {
        Ipv6Prefix::from_str(s).expect("Invalid IPv6 prefix")
    }

    fn addr_v4(s: &str) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from_str(s).expect("Invalid IPv4 address"))
    }

    fn addr_v6(s: &str) -> IpAddr {
        IpAddr::V6(Ipv6Addr::from_str(s).expect("Invalid IPv6 address"))
    }

    fn build_prefixtrie() -> PrefixTrie<String> {
        let mut pt = PrefixTrie::new();

        pt.insert_ipv4(prefix_v4("10.0.1.0/24"), "prefix_10.0.1.0/24".to_string())
            .expect("Failed to insert prefix");

        pt.insert_ipv4(prefix_v4("10.0.2.0/24"), "prefix_10.0.2.0/24".to_string())
            .expect("Failed to insert prefix");

        pt.insert_ipv6(
            prefix_v6("aa:bb:cc:dd::/32"),
            "prefix_aa:bb:cc:dd::/32".to_string(),
        )
        .expect("Failed to insert prefix");

        pt.insert_ipv4(prefix_v4("10.1.0.0/16"), "prefix_10.1.0.0/16".to_string())
            .expect("Failed to insert prefix");

        pt
    }

    #[test]
    fn test_prefixtrie() {
        let pt = build_prefixtrie();

        // Look for a single IPv4 address
        assert_eq!(
            pt.lookup(&addr_v4("10.1.1.1")),
            Some((
                Prefix::IPV4(prefix_v4("10.1.0.0/16")),
                &"prefix_10.1.0.0/16".to_string()
            ))
        );

        // Look for a single IPv6 address
        assert_eq!(
            pt.lookup(&addr_v6("aa:bb:cc:dd::1")),
            Some((
                Prefix::IPV6(prefix_v6("aa:bb:cc:dd::/32")),
                &"prefix_aa:bb:cc:dd::/32".to_string()
            ))
        );

        // Look for a single IPv4 address that is not in the trie
        assert_eq!(pt.lookup(&addr_v4("10.2.1.1")), None);

        // Look for a single IPv6 address that is not in the trie
        assert_eq!(pt.lookup(&addr_v6("aa::1")), None);

        // Clone the prefix trie
        let cloned_pt = pt.clone();
        assert_eq!(
            cloned_pt.lookup(&addr_v4("10.0.1.5")),
            Some((
                Prefix::IPV4(prefix_v4("10.0.1.0/24")),
                &"prefix_10.0.1.0/24".to_string()
            ))
        );
    }
}
