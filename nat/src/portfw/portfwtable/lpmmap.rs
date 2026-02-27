// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use lpm::prefix::Prefix;
use lpm::trie::IpPrefixTrie;

use super::rangeset::RangeSet;
use std::fmt::Debug;
use std::net::IpAddr;
use std::num::NonZero;

use crate::portfw::PortRange;
use crate::portfw::portfwtable::rangeset::RangeSetError;

#[derive(Debug, Clone)]
pub struct LpmMap<V: Clone>(IpPrefixTrie<RangeSet<NonZero<u16>, V>>);

impl<V: Clone> Default for LpmMap<V> {
    fn default() -> Self {
        Self(IpPrefixTrie::default())
    }
}

impl<V: Clone + Debug> LpmMap<V> {
    #[must_use]
    #[allow(unused)]
    pub fn new() -> Self {
        Self(IpPrefixTrie::new())
    }

    pub fn insert(&mut self, p: Prefix, r: PortRange, v: V) -> Result<(), RangeSetError> {
        if let Some(rangeset) = self.0.get_mut(p) {
            rangeset.insert_range(r.first(), r.last(), v)
        } else {
            let mut rangeset = RangeSet::default();
            rangeset.insert_range(r.first(), r.last(), v)?;
            self.0.insert(p, rangeset);
            Ok(())
        }
    }

    /// Modify the `LpmMap` so that the port ranges for prefixes are inherited from shorter prefixes containing them.
    /// This clones the value for each inherited range into the rangeset of the children prefix. As such, it is expected to
    /// use this where V = Arc<_> so that the clone is cheap and refers to the same data. After calling this method, a simple
    /// lpm lookup suffices to match an address and a port within a range: this method precomputes what otherwise would be
    /// computed by `lookup_cumulative()` on each lookup, such that `lookup()` can be called instead.
    #[allow(unused)]
    pub fn resolve_overlaps(&mut self) -> Result<(), RangeSetError> {
        let mut original = self.clone();
        for (prefix, rangeset) in self.iter_mut() {
            for (matched, matched_rangeset) in original.0.matching_entries(prefix.network()) {
                if matched.length() < prefix.length() {
                    for (first, last, value) in matched_rangeset.iter() {
                        rangeset.insert_range_allow_replace(first, last, value.clone())?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Remove the value associated to a prefix and port range
    pub fn remove(&mut self, prefix: Prefix, range: PortRange) -> Option<V> {
        let rangeset = self.0.get_mut(prefix)?;
        let value = rangeset.remove(range.first(), range.last())?;
        if rangeset.is_empty() {
            self.0.remove(&prefix);
        }
        Some(value)
    }

    /// This is like remove. However, it will also remove the values (and ranges) in those longer prefixes that `prefix` covered.
    /// This assumes that `resolve_overlaps()` was called and that those ranges were inherited by the ancestor.
    /// Beware: if those ranges were not inherited, they will be removed too, since this type has no way of knowing where the
    /// ranges came from; direct call of `insert()` (which can be called multiple times for the same prefix) or `resolve_overlaps()`.
    #[allow(unused)]
    pub fn remove_with_overlaps(&mut self, prefix: Prefix, range: PortRange) -> Option<V> {
        let value = self.remove(prefix, range)?;
        for (child, child_rangeset) in self.iter_mut().filter(|(p, rangeset)| prefix.covers(p)) {
            child_rangeset.remove(range.first(), range.last());
        }
        Some(value)
    }

    #[must_use]
    pub fn get(&self, prefix: Prefix, range: PortRange) -> Option<&V> {
        self.0
            .get(prefix)
            .and_then(|rangeset| rangeset.get(range.first(), range.last()))
    }

    #[must_use]
    /// Provide the value matching address and port. This method does a vanilla LPM and will work if all of the
    /// the port-ranges for a given prefix (and those of its ancestors) are `insert()`ed for THAT prefix.
    #[allow(unused)]
    pub fn lookup(&self, address: IpAddr, port: NonZero<u16>) -> Option<&V> {
        self.0
            .lookup(address)
            .and_then(|(prefix, range)| range.lookup(port))
            .map(|(_, _, rule)| rule)
    }

    #[must_use]
    /// Provide the value matching address and port. This method checks all of the prefixes containing address
    /// and, out of those, returns the (first) one that includes the port. This is intended to be used if prefixes
    /// are not indicated the full set of port ranges and they logically inherit those of containing prefixes.
    /// By calling `resolve_overlaps()` this method may be avoided.
    pub fn lookup_cumulative(&self, address: IpAddr, port: NonZero<u16>) -> Option<&V> {
        // this is short-circuiting. If ranges do not overlap, it will work fine.
        // If prefixes overlap and ports too, more than a match could happen. This
        // function will provide only one match, for the longest prefix.
        self.0
            .matching_entries(address)
            .find_map(|(_prefix, range)| range.lookup(port))
            .map(|(_prefix, _rangeset, value)| value)
    }

    #[cfg(test)]
    pub fn lookup_match_all(
        &self,
        address: IpAddr,
        port: NonZero<u16>,
    ) -> impl Iterator<Item = (Prefix, &V)> {
        let x: Vec<_> = self
            .0
            .matching_entries(address)
            .filter_map(|(prefix, range)| {
                let (_, _, value) = range.lookup(port)?;
                Some((prefix, value))
            })
            .collect();
        x.into_iter()
    }

    #[must_use]
    #[allow(unused)]
    pub fn len(&self) -> usize {
        self.0.iter().map(|(_, rangeset)| rangeset.len()).sum()
    }

    #[must_use]
    #[allow(unused)]
    pub fn is_empty(&self) -> bool {
        !self.0.iter().any(|(_, rangeset)| !rangeset.is_empty())
    }

    pub fn iter(&self) -> impl Iterator<Item = (Prefix, &RangeSet<NonZero<u16>, V>)> {
        self.0.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (Prefix, &mut RangeSet<NonZero<u16>, V>)> {
        self.0.iter_mut()
    }
}

#[cfg(test)]
mod test {
    use super::LpmMap;
    use crate::portfw::PortRange;
    use lpm::prefix::Prefix;
    use std::num::NonZero;
    use std::{net::IpAddr, str::FromStr};

    fn rule(prefix: &str, first: u16, last: u16) -> (Prefix, PortRange) {
        let prefix = Prefix::from_str(prefix).unwrap();
        let range = PortRange::new(first, last).unwrap();
        (prefix, range)
    }
    fn addr_port(address: &str, port: u16) -> (IpAddr, NonZero<u16>) {
        let ip = IpAddr::from_str(address).unwrap();
        let port = NonZero::try_from(port).unwrap();
        (ip, port)
    }

    fn check_lpm_map_non_cumulative(map: &LpmMap<&str>) {
        // checks (non-cumulative case): this is LPM. Only the ports for the longest prefix matched will be returned
        let (a, p) = addr_port("192.168.0.1", 22);
        assert_eq!(map.lookup(a, p), Some("A").as_ref());

        let (a, p) = addr_port("192.168.0.1", 79);
        assert_eq!(map.lookup(a, p), Some("A").as_ref());

        let (a, p) = addr_port("192.168.0.255", 22);
        assert_eq!(map.lookup(a, p), Some("A").as_ref());

        let (a, p) = addr_port("192.168.0.255", 79);
        assert_eq!(map.lookup(a, p), Some("A").as_ref());

        let (a, p) = addr_port("192.168.0.1", 80);
        assert_eq!(map.lookup(a, p), None);

        let (a, p) = addr_port("192.168.0.1", 21);
        assert_eq!(map.lookup(a, p), None);

        let (a, p) = addr_port("192.168.1.1", 79);
        assert_eq!(map.lookup(a, p), None);

        let (a, p) = addr_port("192.168.1.1", 80);
        assert_eq!(map.lookup(a, p), None);

        let (a, p) = addr_port("192.168.1.1", 130);
        assert_eq!(map.lookup(a, p), None);

        let (a, p) = addr_port("192.168.1.1", 100);
        assert_eq!(map.lookup(a, p), None);

        let (a, p) = addr_port("192.168.1.1", 22);
        assert_eq!(map.lookup(a, p), None);

        let (a, p) = addr_port("192.168.1.1", 79);
        assert_eq!(map.lookup(a, p), None);

        let (a, p) = addr_port("192.168.1.1", 140);
        assert_eq!(map.lookup(a, p), Some("E").as_ref());

        let (a, p) = addr_port("192.168.1.255", 120);
        assert_eq!(map.lookup(a, p), Some("D").as_ref());

        let (a, p) = addr_port("192.168.1.255", 100);
        assert_eq!(map.lookup(a, p), None);

        let (a, p) = addr_port("192.168.1.255", 22);
        assert_eq!(map.lookup(a, p), None);
    }
    fn check_cumul_api(map: &LpmMap<&str>, address: &str, port: u16, expected: Option<&str>) {
        let (a, p) = addr_port(address, port);
        assert_eq!(
            map.lookup_cumulative(a, p),
            expected.as_ref(),
            "for {a} {p}"
        );
    }
    fn check_lpm_map_cumulative(map: &LpmMap<&str>) {
        check_cumul_api(map, "192.168.0.1", 22, Some("A"));
        check_cumul_api(map, "192.168.0.1", 80, None);
        check_cumul_api(map, "192.168.1.1", 22, Some("A"));
        check_cumul_api(map, "192.168.1.1", 80, Some("B"));
        check_cumul_api(map, "192.168.1.1", 100, Some("B"));
        check_cumul_api(map, "192.168.1.1", 130, Some("C"));
        check_cumul_api(map, "192.168.1.1", 139, None);
        check_cumul_api(map, "192.168.1.1", 120, None);
        check_cumul_api(map, "192.168.1.1", 140, Some("E"));
        //        check_with_prec(map, "192.168.1.1", 141, Some("E"));
    }
    fn check_with_prec(map: &LpmMap<&str>, address: &str, port: u16, expected: Option<&str>) {
        let (a, p) = addr_port(address, port);
        assert_eq!(map.lookup(a, p), expected.as_ref(), "for {a} {p}");

        let results = map.lookup_match_all(a, p);
        println!("address: {a} port: {p} matches:");
        for (prefix, rule) in results {
            println!("    {prefix} -> {rule}");
        }
    }
    fn check_lpm_map_cumulative_precomputed(map: &mut LpmMap<&str>) {
        map.resolve_overlaps().unwrap();

        check_with_prec(map, "192.168.0.1", 22, Some("A"));
        check_with_prec(map, "192.168.0.1", 80, None);
        check_with_prec(map, "192.168.1.1", 22, Some("A"));
        check_with_prec(map, "192.168.1.1", 80, Some("B"));
        check_with_prec(map, "192.168.1.1", 100, Some("B"));
        check_with_prec(map, "192.168.1.1", 130, Some("C"));
        check_with_prec(map, "192.168.1.1", 139, None);
        check_with_prec(map, "192.168.1.1", 120, None);
        check_with_prec(map, "192.168.1.1", 140, Some("E"));
        //        check_with_prec(map, "192.168.1.1", 141, Some("F"));
    }

    fn dump_map(map: &LpmMap<&str>) {
        println!("====== MAP ======");
        for (prefix, rangeset) in map.iter() {
            println!("{prefix}:");
            for (first, last, value) in rangeset.iter() {
                println!("        [{first}-{last}] {value}");
            }
        }
    }

    #[test]
    fn test_lpm_map() {
        let mut map = LpmMap::<&str>::new();

        let (prefix, range) = rule("192.168.0.0/16", 22, 79);
        map.insert(prefix, range, "A").unwrap();

        let (prefix, range) = rule("192.168.1.0/24", 80, 100);
        map.insert(prefix, range, "B").unwrap();

        let (prefix, range) = rule("192.168.1.0/27", 130, 130);
        map.insert(prefix, range, "C").unwrap();

        let (prefix, range) = rule("192.168.1.224/27", 120, 120);
        map.insert(prefix, range, "D").unwrap();

        let (prefix, range) = rule("192.168.1.1/32", 140, 140);
        map.insert(prefix, range, "E").unwrap();

        let (prefix, range) = rule("192.168.1.0/30", 141, 141);
        map.insert(prefix, range, "F").unwrap();

        check_lpm_map_non_cumulative(&map);
        check_lpm_map_cumulative(&map);
        check_lpm_map_cumulative_precomputed(&mut map);

        //println!("{map:#?}");
        dump_map(&map);
    }

    #[test]
    fn test_lpm_map_build() {
        let mut map = LpmMap::<&str>::new();

        let (prefix, range) = rule("192.168.1.0/24", 20, 29);
        map.insert(prefix, range, "A").unwrap();

        // we forbid re-insertions ?
        let (prefix, range) = rule("192.168.1.0/24", 20, 29);
        assert!(map.insert(prefix, range, "X").is_err());

        let (prefix, range) = rule("192.168.1.0/24", 30, 39);
        map.insert(prefix, range, "B").unwrap();

        let (prefix, range) = rule("192.168.1.0/24", 40, 49);
        map.insert(prefix, range, "C").unwrap();

        let (prefix, range) = rule("192.168.1.0/23", 10, 19);
        map.insert(prefix, range, "D").unwrap();

        let (prefix, range) = rule("192.168.1.1/32", 400, 500);
        map.insert(prefix, range, "E").unwrap();

        dump_map(&map);
        map.resolve_overlaps().unwrap();

        let (prefix, range) = rule("192.168.1.0/22", 100, 110);
        map.insert(prefix, range, "F").unwrap();

        // idempotence (achieved because of using RangeSet::insert_range_allow_replace)
        map.resolve_overlaps().unwrap();
        map.resolve_overlaps().unwrap();
        map.resolve_overlaps().unwrap();
        dump_map(&map);

        println!("Removing prefixes...");

        // remove largest prefix
        let (prefix, range) = rule("192.168.1.0/22", 100, 110);
        map.remove_with_overlaps(prefix, range);
        dump_map(&map);

        let (prefix, range) = rule("192.168.1.0/23", 10, 19);
        map.remove_with_overlaps(prefix, range);
        dump_map(&map);

        let (prefix, range) = rule("192.168.1.0/24", 40, 49);
        map.remove_with_overlaps(prefix, range);
        dump_map(&map);

        let (prefix, range) = rule("192.168.1.0/24", 20, 29);
        map.remove_with_overlaps(prefix, range);
        dump_map(&map);

        let (prefix, range) = rule("192.168.1.0/24", 20, 29);
        map.insert(prefix, range, "A").unwrap();
        map.resolve_overlaps().unwrap();
        dump_map(&map);

        let (prefix, range) = rule("192.168.1.0/24", 20, 29);
        map.remove_with_overlaps(prefix, range);
        dump_map(&map);
    }
}
