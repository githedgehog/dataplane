// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::collections::BTreeMap;
use std::ops::{Bound, RangeBounds};

/// Trait for types that can be used as upper bounds for a range lookup. The generated bound is used
/// as the upper bound for creating a range over a `BTreeMap` containing disjoint ranges: this way,
/// we can retrieve the closest, lower range for the item we consider.
///
/// The objective of `upper_bound_from()` is to turn an item, for example an IP address, into an IP
/// range of the form (IP address, max IP address for IP version): 1.0.0.12 becomes (1.0.0.12,
/// 255.255.255.255).
///
/// If we look up for 1.0.0.12 in a `BTreeMap` containing ranges such as:
/// [ (0.0.1.0, 0.0.255.255), (1.0.0.0, 1.0.0.255), (3.0.0.0, 3.2.0.255) ],
/// then we can create a bound (1.0.0.12, 255.255.255.255), create a range from the first entry of
/// the map to this bound, and look for the latest value: this gives us (1.0.0.0, 1.0.0.255), that
/// 1.0.0.12 belongs to (a further check of the max value for the range is necessary to make sure
/// 1.0.0.12 is indeed covered by one range in the map).
///
/// The reason we use 255.255.255.255 as the upper limit for the range in our bound is that if we
/// were to look up for 1.0.0.0 in the example above, a bound such as (1.0.0.0, 1.0.0.0) would
/// exclude range (1.0.0.0, 1.0.0.255) when creating the map entries range. We pick the highest
/// value to make sure we look right "after" a range that might have the same start value.
pub trait UpperBoundFrom<K> {
    fn upper_bound_from(key: K) -> Self;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisjointRangesBTreeMap<R, V>(BTreeMap<R, V>);

impl<R, V> DisjointRangesBTreeMap<R, V>
where
    R: Ord,
{
    #[must_use]
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn insert(&mut self, range: R, value: V) -> Option<V> {
        self.0.insert(range, value)
    }

    pub fn remove(&mut self, range: &R) -> Option<V> {
        self.0.remove(range)
    }

    pub fn get(&self, range: &R) -> Option<&V> {
        self.0.get(range)
    }

    pub fn lookup<K>(&self, key: &K) -> Option<(&R, &V)>
    where
        R: UpperBoundFrom<K> + RangeBounds<K>,
        K: Copy + Ord,
    {
        self.0
            .range(..=R::upper_bound_from(*key))
            .next_back()
            .filter(|(range, _)| match range.end_bound() {
                Bound::Included(&end) => *key <= end,
                Bound::Excluded(&end) => *key < end,
                Bound::Unbounded => true,
            })
    }

    pub fn iter(&self) -> impl Iterator<Item = (&R, &V)> {
        self.0.iter()
    }
}

impl<R, V> Default for DisjointRangesBTreeMap<R, V> {
    fn default() -> Self {
        Self(BTreeMap::default())
    }
}
