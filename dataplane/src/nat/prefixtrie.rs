// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use iptrie::map::RTrieMap;
use iptrie::{Ipv4Prefix, Ipv6Prefix};
use routing::prefix::Prefix;
use std::fmt::Debug;
use std::net::IpAddr;

#[derive(thiserror::Error, Debug)]
pub enum TrieError {
    #[error("entry already exists")]
    EntryExists,
}

#[derive(Default, Clone)]
pub struct PrefixTrie {
    trie_ipv4: RTrieMap<Ipv4Prefix, String>,
    trie_ipv6: RTrieMap<Ipv6Prefix, String>,
}

impl PrefixTrie {
    #[tracing::instrument(level = "trace")]
    pub fn new() -> Self {
        Self {
            trie_ipv4: RTrieMap::new(),
            trie_ipv6: RTrieMap::new(),
        }
    }

    pub fn insert_ipv4(&mut self, prefix: Ipv4Prefix, value: String) -> Result<(), TrieError> {
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

    pub fn insert_ipv6(&mut self, prefix: Ipv6Prefix, value: String) -> Result<(), TrieError> {
        // See comment for IPv4
        if self.trie_ipv6.get(&prefix).is_some() {
            return Err(TrieError::EntryExists);
        }
        self.trie_ipv6.insert(prefix, value);
        Ok(())
    }

    #[tracing::instrument(level = "trace")]
    pub fn insert(&mut self, prefix: &Prefix, value: String) -> Result<(), TrieError> {
        match prefix {
            Prefix::IPV4(p) => self.insert_ipv4(*p, value),
            Prefix::IPV6(p) => self.insert_ipv6(*p, value),
        }
    }

    #[tracing::instrument(level = "trace")]
    pub fn find(&self, prefix: &Prefix) -> Option<String> {
        match prefix {
            Prefix::IPV4(p) => {
                let (k, v) = self.trie_ipv4.lookup(p);
                // The RTrieMap lookup always return an entry; if no better
                // match, it returns the root of the map, which always exists.
                // This means that to check if the result is "empty", we need to
                // check whether the returned entry is the root for the map.
                if Prefix::IPV4(*k).is_root() {
                    None
                } else {
                    Some(v.to_string())
                }
            }
            Prefix::IPV6(p) => {
                let (k, v) = self.trie_ipv6.lookup(p);
                if Prefix::IPV6(*k).is_root() {
                    None
                } else {
                    Some(v.to_string())
                }
            }
        }
    }

    #[tracing::instrument(level = "trace")]
    pub fn find_ip(&self, ip: &IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(_) => self.find(&Prefix::from((*ip, 32))),
            IpAddr::V6(_) => self.find(&Prefix::from((*ip, 128))),
        }
    }
}

impl Debug for PrefixTrie {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_map()
            .entries(self.trie_ipv4.iter())
            .entries(self.trie_ipv6.iter())
            .finish()
    }
}
