// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::prefix::IpPrefix;
use crate::prefix::ip::Representable;
use prefix_trie::PrefixMap;
use std::borrow::Borrow;
use std::default::Default;
use std::fmt::{Debug, Display};

use crate::trie::{TrieMap, TrieMapFactory, TrieMapWithDefault};

#[derive(Clone)]
#[repr(transparent)]
struct IpPrefixW<P: IpPrefix>(P);

impl<P: IpPrefix> Debug for IpPrefixW<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

impl<P: IpPrefix> Display for IpPrefixW<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.0.network(), self.0.len())
    }
}

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
            len <= P::MAX_LEN,
            "Invalid length in from_repr_len: {repr:?} {len}",
        );
        let addr = P::Addr::from_bits(repr);
        IpPrefixW(
            P::new(addr, len)
                .unwrap_or_else(|_| panic!("Invalid prefix in from_repr_len: {repr:?} {len}")),
        )
    }
}

#[derive(Debug, Default, Clone)]
pub struct PrefixMapTrie<P, V>(PrefixMap<IpPrefixW<P>, V>)
where
    P: IpPrefix;

impl<P, V> TrieMapFactory<PrefixMapTrie<P, V>> for PrefixMapTrie<P, V>
where
    P: IpPrefix,
{
    fn create() -> Self {
        Self(PrefixMap::new())
    }

    fn with_capacity(_capacity: usize) -> Self {
        // PrefixMap has no with_capacity method
        Self(PrefixMap::new())
    }

    fn with_root(value: V) -> Self {
        let mut ret = Self::create();
        ret.insert(P::ROOT, value);
        ret
    }
}

impl<P, V> TrieMap for PrefixMapTrie<P, V>
where
    P: IpPrefix,
{
    type Prefix = P;
    type Value = V;
    type Error = std::convert::Infallible;

    fn iter(&self) -> impl Iterator<Item = (&P, &V)> {
        self.0.iter().map(|(p, v)| (&p.0, v))
    }

    fn get<B>(&self, prefix: B) -> Option<&V>
    where
        B: Borrow<P>,
    {
        self.0.get(&IpPrefixW(prefix.borrow().clone()))
    }

    fn get_mut<B>(&mut self, prefix: B) -> Option<&mut V>
    where
        B: Borrow<P>,
    {
        self.0.get_mut(&IpPrefixW(prefix.borrow().clone()))
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn insert(&mut self, prefix: P, value: V) -> Option<V> {
        self.0.insert(IpPrefixW(prefix), value)
    }

    fn remove<B>(&mut self, prefix: B) -> Option<V>
    where
        B: Borrow<P>,
    {
        self.0.remove(&IpPrefixW(prefix.borrow().clone()))
    }

    fn lookup<A>(&self, addr: A) -> Option<(&P, &V)>
    where
        A: Into<Self::Prefix>,
    {
        self.0
            .get_lpm(&IpPrefixW(addr.into()))
            .map(|(p, v)| (&p.0, v))
    }
}

pub type PrefixMapTrieWithDefault<P, V> = TrieMapWithDefault<PrefixMapTrie<P, V>>;
