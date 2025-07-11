// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::prefix::IpPrefix;

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
