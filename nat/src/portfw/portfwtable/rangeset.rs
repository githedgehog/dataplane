// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Object and utils to represent non-overlapping prefixes for
//! port forwarding.

#![allow(unused)]

use crate::portfw::PortFwTableError;
use lpm::prefix::ip::Representable;
use lpm::prefix::{IpPrefix, IpPrefixCovering, Ipv4Prefix, Ipv6Prefix, Prefix};
use std::collections::BTreeMap;
use std::default;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::debug;

/// A type that represents a set of disjoint ranges. This type allows determining
/// if a certain value (type `A`, e.g. an address or a port) falls within some range
/// (e.g. a prefix or a port range) and, if so, retrieving a certain value `V`.
/// This can be used to compactly encode sets of non-overlapping prefixes or port ranges
/// to determine if an address or port falls in one of them. E.g:
///    [10.0.1.0/24]   -> Value
///    [10.0.2.0/24]   -> Value
///    [10.1.0.0/16]   -> Value
///    [10.2.1.128/25] -> Value
/// or
///    [80 - 128]      -> Value
/// For a given range and value [first, last] -> V, with first and last the range bounds,
/// this type encodes them in a binary tree map as
///    [first] -> (last, value)
///
/// For the particular case of prefixes (and not arbitrary contiguous sets of addresses),
/// instead of storing "last", we could store the prefix length, because given the first
/// address and the prefix length, the last address can be computed. So, for a mapping like
/// 10.0.3.0/24 -> Value, instead of storing
///    [10.0.3.0] -> (10.0.3.255, Value)
/// we could store
///    [10.0.3.0] -> (24, Value)
///
/// which is storing the prefix and the value. For Ipv6 this would mean storing a u8 instead
/// of a u128. However, we don't do that since that representation would not allow using this
/// type for other types of ranges like port ranges.
///
/// The type has two generics:
///     A: the elements we query for (addresses, ports, etc.)
///     V: the value
///
/// And only supports two operations:
///     - inserting a range and the corresponding value
///     - querying for a value
///
#[derive(Clone, Debug)] // clone needed by IpPrefixTrie
pub struct RangeSet<A, V>(BTreeMap<A, (A, V)>);
impl<A, V> Default for RangeSet<A, V> {
    fn default() -> Self {
        Self(BTreeMap::new())
    }
}
impl<A, V> RangeSet<A, V>
where
    A: Ord + Copy + std::fmt::Display,
{
    #[allow(unused)]
    pub fn lookup(&self, sought: A) -> Option<(A, A, &V)> {
        let (first, (last, value)) = self.0.range(..=sought).next_back()?;
        if sought > *last {
            return None; // sought does not fall in [first, last]
        }
        Some((*first, *last, value)) // sought falls within [first, last]
    }

    /// insert a value for a range. Overlap is forbidden
    pub fn insert_range(&mut self, first: A, last: A, value: V) -> Result<(), RangeSetError> {
        if self.overlaps(first, last).is_some() {
            return Err(RangeSetError::OverlapErr(format!("[{first}-{last}]")));
        }
        self.0.insert(first, (last, value));
        Ok(())
    }

    /// insert a value for a range. Overlap is forbidden, except if the range matches, in which case
    /// the value is replaced.
    pub fn insert_range_allow_replace(
        &mut self,
        first: A,
        last: A,
        value: V,
    ) -> Result<(), RangeSetError> {
        if let Some((ov_first, ov_last, ov_value)) = self.overlaps(first, last)
            && (ov_first != first || ov_last != last)
        {
            return Err(RangeSetError::OverlapErr(format!("[{first}-{last}]")));
        }
        self.0.insert(first, (last, value));
        Ok(())
    }

    /// Tell if inserting a new range [first-last] would overlap with any of the existing ones
    fn overlaps(&self, first: A, last: A) -> Option<(A, A, &V)> {
        if let Some((prev_first, (prev_last, value))) = self.0.range(..first).next_back()
            && *prev_last >= first
        {
            return Some((*prev_first, *prev_last, value));
        }
        if let Some((next_first, (next_last, value))) = self.0.range(first..).next()
            && *next_first <= last
        {
            return Some((*next_first, *next_last, value));
        }
        None
    }

    pub fn iter(&self) -> impl Iterator<Item = (A, A, &V)> {
        self.0
            .iter()
            .map(|(first, (last, value))| (*first, *last, value))
    }
    pub fn get_mut(&mut self, first: A, last: A) -> Option<&mut V> {
        let (end, value) = self.0.get_mut(&first)?;
        if last == *end { Some(value) } else { None }
    }
    pub fn get(&self, first: A, last: A) -> Option<&V> {
        let (end, value) = self.0.get(&first)?;
        if last == *end { Some(value) } else { None }
    }
    pub fn remove(&mut self, first: A, last: A) -> Option<V> {
        self.get(first, last)?; // we get first to ensure that range is exact
        self.0.remove(&first).map(|(_, v)| v)
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum RangeSetError {
    #[error("Range {0} overlaps with some other range")]
    OverlapErr(String),
}

/// Implementation for Ipv4 prefixes and addresses, which implement Ord & Copy.
impl<V> RangeSet<Ipv4Addr, V> {
    pub fn insert(&mut self, prefix: Ipv4Prefix, value: V) -> Result<(), RangeSetError> {
        let first = prefix.network();
        let last = prefix.last_address();
        self.insert_range(first, last, value)
    }
}

/// Implementation for Ipv6 prefixes and addresses, which implement Ord & Copy
/// (This may be unified with traits `IpPrefix` and `Representable`)
impl<V> RangeSet<Ipv6Addr, V> {
    pub fn insert(&mut self, prefix: Ipv6Prefix, value: V) -> Result<(), RangeSetError> {
        let first = prefix.network();
        let last = prefix.last_address();
        self.insert_range(first, last, value)
    }
}

/// A type that allows storing both IPv4 and IPv6 disjoint sets of prefixes
/// and associate a value of arbitrary type `V` to each prefix. A lookup for an address
/// returns the `Prefix` that contains the address and the value `V`.
pub struct PrefixMap<V> {
    v4: RangeSet<Ipv4Addr, V>,
    v6: RangeSet<Ipv6Addr, V>,
}
impl<V> Default for PrefixMap<V> {
    #[must_use]
    fn default() -> Self {
        Self {
            v4: RangeSet::default(),
            v6: RangeSet::default(),
        }
    }
}
impl<V> PrefixMap<V> {
    /// Insert a value `V` for the given `Prefix`
    pub fn insert(&mut self, prefix: Prefix, value: V) -> Result<(), RangeSetError> {
        match prefix {
            Prefix::IPV4(p) => self.v4.insert(p, value),
            Prefix::IPV6(p) => self.v6.insert(p, value),
        }
    }
    /// Remove the `Prefix` and value registered in this `PrefixMap`
    pub fn remove(&mut self, prefix: Prefix) -> Option<V> {
        match prefix {
            Prefix::IPV4(p) => self.v4.remove(p.network(), p.last_address()),
            Prefix::IPV6(p) => self.v6.remove(p.network(), p.last_address()),
        }
    }

    fn as_ipv4_prefix(first: Ipv4Addr, last: Ipv4Addr) -> Ipv4Prefix {
        #[allow(clippy::cast_possible_truncation)]
        let len = (Ipv4Addr::BITS - (last.to_bits() - first.to_bits() + 1).trailing_zeros()) as u8;
        Ipv4Prefix::new(first, len).unwrap_or_else(|_| unreachable!())
    }

    fn as_ipv6_prefix(first: Ipv6Addr, last: Ipv6Addr) -> Ipv6Prefix {
        #[allow(clippy::cast_possible_truncation)]
        let len = (Ipv6Addr::BITS - (last.to_bits() - first.to_bits() + 1).trailing_zeros()) as u8;
        Ipv6Prefix::new(first, len).unwrap_or_else(|_| unreachable!())
    }

    /// Get the value stored for a given `Prefix` prefix. Note: the prefix must match exactly
    pub fn get(&self, prefix: Prefix) -> Option<&V> {
        match prefix {
            Prefix::IPV4(p) => self.v4.get(p.network(), p.last_address()),
            Prefix::IPV6(p) => self.v6.get(p.network(), p.last_address()),
        }
    }

    /// Get the value stored for a given `Prefix` prefix mutably. Note: the prefix must match exactly
    pub fn get_mut(&mut self, prefix: Prefix) -> Option<&mut V> {
        match prefix {
            Prefix::IPV4(p) => self.v4.get_mut(p.network(), p.last_address()),
            Prefix::IPV6(p) => self.v6.get_mut(p.network(), p.last_address()),
        }
    }

    #[must_use]
    /// Given an `IpAddr`, returns the `Prefix` and value `V` that contains it, if any.
    pub fn lookup(&self, address: IpAddr) -> Option<(Prefix, &V)> {
        match address {
            IpAddr::V4(a) => self
                .v4
                .lookup(a)
                .map(|(first, last, value)| (Self::as_ipv4_prefix(first, last).into(), value)),
            IpAddr::V6(a) => self
                .v6
                .lookup(a)
                .map(|(first, last, value)| (Self::as_ipv6_prefix(first, last).into(), value)),
        }
    }

    pub fn iter_v4(&self) -> impl Iterator<Item = (Ipv4Prefix, &V)> {
        self.v4
            .iter()
            .map(|(first, last, value)| (Self::as_ipv4_prefix(first, last), value))
    }

    pub fn iter_v6(&self) -> impl Iterator<Item = (Ipv6Prefix, &V)> {
        self.v6
            .iter()
            .map(|(first, last, value)| (Self::as_ipv6_prefix(first, last), value))
    }

    pub fn iter(&self) -> impl Iterator<Item = (Prefix, &V)> {
        let v4 = self
            .v4
            .iter()
            .map(|(first, last, value)| (Self::as_ipv4_prefix(first, last).into(), value));
        let v6 = self
            .v6
            .iter()
            .map(|(first, last, value)| (Self::as_ipv6_prefix(first, last).into(), value));
        v4.chain(v6)
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

#[cfg(test)]
mod test {
    use super::PrefixMap;
    use lpm::prefix::Prefix;
    use std::net::IpAddr;
    use std::str::FromStr;
    use tracing_test::traced_test;

    #[test]
    fn test_prefix_map_deny_overlaps() {
        let mut pmap: PrefixMap<()> = PrefixMap::default();

        let from = Prefix::from_str("192.168.1.0/24").unwrap();
        pmap.insert(from, ()).unwrap();

        let from = Prefix::from_str("192.168.2.0/27").unwrap();
        pmap.insert(from, ()).unwrap();

        let from = Prefix::from_str("192.168.3.1/32").unwrap();
        pmap.insert(from, ()).unwrap();

        let from = Prefix::from_str("192.168.3.2/32").unwrap();
        pmap.insert(from, ()).unwrap();

        let from = Prefix::from_str("4000:ff:ff:ff:ff:ff:ff::/120").unwrap();
        pmap.insert(from, ()).unwrap();

        let from = Prefix::from_str("4000:ff:ff:ff:ff:ff:fe::/120").unwrap();
        pmap.insert(from, ()).unwrap();

        let from = Prefix::from_str("4000:ff:ff:ff:ff:ff::/120").unwrap();
        pmap.insert(from, ()).unwrap();

        // overlaps

        let from = Prefix::from_str("192.168.0.0/16").unwrap();
        assert!(pmap.insert(from, ()).is_err());

        let from = Prefix::from_str("192.168.1.0/27").unwrap();
        assert!(pmap.insert(from, ()).is_err());

        let from = Prefix::from_str("192.168.1.1/32").unwrap();
        assert!(pmap.insert(from, ()).is_err());

        let from = Prefix::from_str("192.168.1.255/32").unwrap();
        assert!(pmap.insert(from, ()).is_err());

        let from = Prefix::from_str("4000:ff:ff:ff:ff:ff::/104").unwrap();
        assert!(pmap.insert(from, ()).is_err());

        let from = Prefix::from_str("192.168.1.128/25").unwrap();
        assert!(pmap.insert(from, ()).is_err());

        let from = Prefix::from_str("192.168.1.1/25").unwrap();
        assert!(pmap.insert(from, ()).is_err());

        let from = Prefix::from_str("192.168.1.0/27").unwrap();
        assert!(pmap.insert(from, ()).is_err());

        for (prefix, _value) in pmap.iter() {
            println!("{prefix}");
        }
    }
}
