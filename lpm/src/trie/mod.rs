// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::prefix::{IpPrefix, Ipv4Prefix, Ipv6Prefix, Prefix};
use std::borrow::Borrow;
use std::net::IpAddr;

mod prefix_map_impl;
pub use prefix_map_impl::*;

mod trie_with_default;
pub use trie_with_default::TrieMapWithDefault;

pub trait TrieMapFactory<T: TrieMap> {
    fn create() -> T;
    fn with_capacity(capacity: usize) -> T;
    fn with_root(value: T::Value) -> T;
}

pub trait TrieMap {
    type Prefix: IpPrefix;
    type Value;
    type Error;

    /// This function gets a reference to the prefix entry installed in the map (if any).
    ///
    /// <div class="warning">
    /// This method does not do an LPM lookup!
    /// </div>
    fn get<B>(&self, prefix: B) -> Option<&Self::Value>
    where
        B: Borrow<Self::Prefix>;

    /// This function gets a mutable reference to the prefix entry installed in the map (if any).
    ///
    /// <div class="warning">
    /// This method does not do an LPM lookup!
    /// </div>
    fn get_mut<B>(&mut self, prefix: B) -> Option<&mut Self::Value>
    where
        B: Borrow<Self::Prefix>;

    fn iter(&self) -> impl Iterator<Item = (&Self::Prefix, &Self::Value)>;
    fn iter_mut(&mut self) -> impl Iterator<Item = (&Self::Prefix, &mut Self::Value)>;
    fn is_empty(&self) -> bool;

    fn insert(&mut self, prefix: Self::Prefix, value: Self::Value) -> Option<Self::Value>;

    fn len(&self) -> usize;

    /// Gets the prefix with the longest match
    fn lookup<A>(&self, addr: A) -> Option<(&Self::Prefix, &Self::Value)>
    where
        A: Into<Self::Prefix>;

    fn remove<B>(&mut self, prefix: B) -> Option<Self::Value>
    where
        B: Borrow<Self::Prefix>;
}

#[derive(Debug, Clone)]
pub struct IpPrefixTrie<V> {
    ipv4: PrefixMapTrie<Ipv4Prefix, V>,
    ipv6: PrefixMapTrie<Ipv6Prefix, V>,
}

impl<V: Clone> IpPrefixTrie<V> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            ipv4: PrefixMapTrie::create(),
            ipv6: PrefixMapTrie::create(),
        }
    }

    pub fn insert(&mut self, prefix: Prefix, value: V) -> Option<V> {
        match prefix {
            Prefix::IPV4(prefix) => self.ipv4.insert(prefix, value),
            Prefix::IPV6(prefix) => self.ipv6.insert(prefix, value),
        }
    }

    pub fn remove(&mut self, prefix: &Prefix) -> Option<V> {
        match prefix {
            Prefix::IPV4(prefix) => self.ipv4.remove(prefix),
            Prefix::IPV6(prefix) => self.ipv6.remove(prefix),
        }
    }

    pub fn lookup<Q>(&self, addr: Q) -> Option<(Prefix, &V)>
    where
        Q: Into<IpAddr>,
    {
        match addr.into() {
            IpAddr::V4(ip) => self.ipv4.lookup(ip).map(|(k, v)| (Prefix::IPV4(*k), v)),
            IpAddr::V6(ip) => self.ipv6.lookup(ip).map(|(k, v)| (Prefix::IPV6(*k), v)),
        }
    }

    pub fn len(&self) -> usize {
        self.ipv4.len() + self.ipv6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ipv4.is_empty() && self.ipv6.is_empty()
    }
}

impl<V: Clone> Default for IpPrefixTrie<V> {
    fn default() -> Self {
        Self::new()
    }
}
