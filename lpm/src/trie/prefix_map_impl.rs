// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::prefix::IpPrefix;
use crate::prefix::ip::Representable;
use prefix_trie::PrefixMap;
use std::default::Default;

use crate::trie::{TrieMap, TrieMapNew, TrieMapWithDefault};

#[derive(Debug, Clone)]
struct IpPrefixW<P: IpPrefix>(P);
impl<P: IpPrefix> prefix_trie::Prefix for IpPrefixW<P> {
    type R = P::Repr;

    fn repr(&self) -> Self::R {
        self.0.network().to_bits()
    }

    fn prefix_len(&self) -> u8 {
        self.0.len()
    }

    fn from_repr_len(repr: Self::R, len: u8) -> Self {
        assert!(
            (len <= P::MAX_LEN),
            "Invalid length in from_repr_len: {repr:?} {len}",
        );
        let addr = P::Addr::from_bits(repr);
        IpPrefixW(
            P::new(addr, len)
                .unwrap_or_else(|_| panic!("Invalid prefix in from_repr_len: {repr:?} {len}")),
        )
    }
}

#[derive(Default, Clone)]
pub struct PrefixMapTrie<P, V>(PrefixMap<IpPrefixW<P>, V>)
where
    P: IpPrefix,
    V: Clone;

impl<P, V> TrieMapNew for PrefixMapTrie<P, V>
where
    P: IpPrefix,
    V: Clone,
{
    type Prefix = P;
    type Value = V;

    fn new() -> Self {
        Self(PrefixMap::new())
    }

    fn with_capacity(_capacity: usize) -> Self {
        // PrefixMap has no with_capacity method
        Self(PrefixMap::new())
    }

    fn with_root(value: V) -> Self {
        let mut ret = Self::new();
        ret.insert(P::default(), value);
        ret
    }
}

impl<P, V> TrieMap for PrefixMapTrie<P, V>
where
    P: IpPrefix,
    V: Clone,
{
    type Prefix = P;
    type Value = V;
    type Error = std::convert::Infallible;

    fn iter(&self) -> impl Iterator<Item = (&P, &V)> {
        self.0.iter().map(|(p, v)| (&p.0, v))
    }

    fn get(&self, prefix: &P) -> Option<&V> {
        self.0.get(&IpPrefixW(prefix.clone()))
    }

    fn get_mut(&mut self, prefix: &P) -> Option<&mut V> {
        self.0.get_mut(&IpPrefixW(prefix.clone()))
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn insert(&mut self, prefix: P, value: V) -> Option<V> {
        self.0.insert(IpPrefixW(prefix.clone()), value)
    }

    fn remove(&mut self, prefix: &P) -> Option<V> {
        self.0.remove(&IpPrefixW(prefix.clone()))
    }

    fn lookup<Q>(&self, addr: &Q) -> Option<(&P, &V)>
    where
        Q: Into<P> + Clone,
    {
        self.0
            .get_lpm(&IpPrefixW(addr.clone().into()))
            .map(|x| (&x.0.0, x.1))
    }
}

pub type PrefixMapTrieWithDefault<P, V> = TrieMapWithDefault<PrefixMapTrie<P, V>>;
