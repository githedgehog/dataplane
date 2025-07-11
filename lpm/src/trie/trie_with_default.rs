// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use tracing::warn;

use crate::trie::{TrieMap, TrieMapNew};

#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct TrieMapWithDefault<T: TrieMap + TrieMapNew>(T);

impl<T: TrieMap + TrieMapNew> TrieMapWithDefault<T> {
    pub fn with_root(value: <T as TrieMap>::Value) -> Self {
        let mut ret = T::new();
        ret.insert(<T as TrieMap>::Prefix::default(), value);
        Self(ret)
    }

    pub fn with_root_and_capacity(value: <T as TrieMap>::Value, capacity: usize) -> Self {
        let mut ret = T::with_capacity(capacity);
        ret.insert(<T as TrieMap>::Prefix::default(), value);
        Self(ret)
    }

    /// Create an empty trie so that default can be set later
    ///
    /// # Safety
    /// This function is unsafe because it creates an empty trie, which may panic
    /// in `lookup_wd` if the default value is not set before using the trie.
    ///
    /// The caller must ensure that the default value is set before using the trie.
    #[must_use]
    pub unsafe fn new() -> Self {
        Self(T::new())
    }

    /// Create an empty trie with a given capacity so that default can be set later
    ///
    /// # Safety
    /// This function is unsafe because it creates an empty trie, which may panic
    /// in `lookup_wd` if the default value is not set before using the trie.
    ///
    /// The caller must ensure that the default value is set before using the trie.
    #[must_use]
    pub unsafe fn with_capacity(capacity: usize) -> Self {
        Self(T::with_capacity(capacity))
    }

    /// This function gets the prefix, with longest prefix match
    ///
    /// Returns:
    ///
    /// This function is different from `lookup` in that it will always return
    /// a result since there is a default prefix in the trie.  `lookup` will
    /// may return None.  As a result, the return type here is just `&Value`
    /// not `Option<&Value>`
    pub fn lookup_wd<Q>(&self, addr: &Q) -> (&<T as TrieMap>::Prefix, &<T as TrieMap>::Value)
    where
        Q: Into<<T as TrieMap>::Prefix> + Clone,
    {
        self.0
            .lookup(addr)
            .unwrap_or_else(|| unreachable!("No default value in trie with default!"))
    }
}

impl<T: TrieMap + TrieMapNew> TrieMap for TrieMapWithDefault<T> {
    type Prefix = <T as TrieMap>::Prefix;
    type Value = <T as TrieMap>::Value;
    type Error = <T as TrieMap>::Error;

    fn iter(&self) -> impl Iterator<Item = (&Self::Prefix, &Self::Value)> {
        self.0.iter()
    }

    fn get(&self, prefix: &Self::Prefix) -> Option<&Self::Value> {
        self.0.get(prefix)
    }

    fn get_mut(&mut self, prefix: &Self::Prefix) -> Option<&mut Self::Value> {
        self.0.get_mut(prefix)
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn insert(&mut self, prefix: Self::Prefix, value: Self::Value) -> Option<Self::Value> {
        self.0.insert(prefix, value)
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn lookup<Q>(&self, addr: &Q) -> Option<(&Self::Prefix, &Self::Value)>
    where
        Q: Into<Self::Prefix> + Clone,
    {
        self.0.lookup(addr)
    }

    fn remove(&mut self, prefix: &Self::Prefix) -> Option<Self::Value> {
        if *prefix == Self::Prefix::default() {
            warn!("Removing default prefix from trie with default!");
            return None;
        }
        self.0.remove(prefix)
    }
}
