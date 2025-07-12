// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::prefix::{IpPrefix, Ipv4Prefix, Ipv6Prefix, Prefix};

mod prefix_map_impl;
pub use prefix_map_impl::*;

mod trie_with_default;
pub use trie_with_default::TrieMapWithDefault;

pub trait TrieMapNew {
    type Prefix: IpPrefix;
    type Value: Clone;

    fn new() -> Self;
    fn with_capacity(capacity: usize) -> Self;
    fn with_root(value: Self::Value) -> Self;
}

pub trait TrieMap: Clone {
    type Prefix: IpPrefix;
    type Value;
    type Error;

    /// This function gets the prefix, with exact match, it does not do LPM
    fn get(&self, prefix: &Self::Prefix) -> Option<&Self::Value>;
    /// This function gets the prefix, with exact match, it does not do LPM
    fn get_mut(&mut self, prefix: &Self::Prefix) -> Option<&mut Self::Value>;

    fn iter(&self) -> impl Iterator<Item = (&Self::Prefix, &Self::Value)>;
    fn is_empty(&self) -> bool;
    fn insert(&mut self, prefix: Self::Prefix, value: Self::Value) -> Option<Self::Value>;
    fn len(&self) -> usize;

    /// This function gets the prefix, with longest prefix match
    fn lookup<Q>(&self, addr: &Q) -> Option<(&Self::Prefix, &Self::Value)>
    where
        Q: Into<Self::Prefix> + Clone;

    fn remove(&mut self, prefix: &Self::Prefix) -> Option<Self::Value>;
}

pub struct IpPrefixTrie<V: Clone> {
    ipv4: PrefixMapTrie<Ipv4Prefix, V>,
    ipv6: PrefixMapTrie<Ipv6Prefix, V>,
}

impl<V: Clone> IpPrefixTrie<V> {
    #[allow(clippy::new_without_default)]
    #[must_use]
    pub fn new() -> Self {
        Self {
            ipv4: PrefixMapTrie::new(),
            ipv6: PrefixMapTrie::new(),
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
        Q: Into<Prefix> + Clone,
    {
        match addr.into() {
            Prefix::IPV4(prefix) => self
                .ipv4
                .lookup(&prefix)
                .map(|(k, v)| (Prefix::IPV4(*k), v)),
            Prefix::IPV6(prefix) => self
                .ipv6
                .lookup(&prefix)
                .map(|(k, v)| (Prefix::IPV6(*k), v)),
        }
    }
}
