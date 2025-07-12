// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::NatPeeringError;
use crate::models::external::overlay::vpc::Peering;
use lpm::prefix::Prefix;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::error;

// Collapse prefixes and exclusion prefixes in a Peering object: for each expose object, "apply"
// exclusion prefixes to split allowed prefixes into smaller chunks, and remove exclusion prefixes
// from the expose object.
//
// For example, for a given expose with "ips" as 1.0.0.0/16 and "nots" as 1.0.0.0/18, the resulting
// expose will contain 1.0.128.0/17 and 1.0.64.0/18 as "ips" prefixes, and an empty "nots" list.
pub fn collapse_prefixes_peering(peering: &Peering) -> Result<Peering, NatPeeringError> {
    let mut clone = peering.clone();
    for expose in &mut clone
        .local
        .exposes
        .iter_mut()
        .chain(&mut clone.remote.exposes.iter_mut())
    {
        let ips = collapse_prefix_lists(&expose.ips, &expose.nots)?;
        let as_range = collapse_prefix_lists(&expose.as_range, &expose.not_as)?;
        expose.ips = ips;
        expose.as_range = as_range;
        expose.nots = BTreeSet::new();
        expose.not_as = BTreeSet::new();
    }
    Ok(clone)
}

// Collapse prefixes (first set) and exclusion prefixes (second set), by "applying" exclusion
// prefixes to the allowed prefixes and split them into smaller allowed segments, to express the
// same IP ranges without any exclusion prefixes.
fn collapse_prefix_lists(
    prefixes: &BTreeSet<Prefix>,
    excludes: &BTreeSet<Prefix>,
) -> Result<BTreeSet<Prefix>, NatPeeringError> {
    let mut result = prefixes.clone();
    // Sort the exclusion prefixes by length in ascending order (meaning a /16 is _smaller_ than a
    // /24, and comes first). If there are some exclusion prefixes with overlap, this ensures that
    // we take out the biggest chunk from the allowed prefix first (and don't need to process the
    // smaller exclusion prefix at all).
    let mut excludes_sorted = excludes.iter().collect::<Vec<_>>();
    excludes_sorted.sort_by_key(|p| p.length());

    // Iterate over all exclusion prefixes
    for exclude in &excludes_sorted {
        let result_clone = result.clone();
        for prefix in &result_clone {
            // Only bother with prefixes of the same IP version. We should reject distinct versions
            // at validation time for the expose anyway.
            if prefix.is_ipv4() != exclude.is_ipv4() {
                continue;
            }
            // If exclusion prefix is bigger or equal to the allowed prefix, remove the allowed
            // prefix. Given that we remove it, there's no need to compare it with the remaining
            // exclusion prefixes.
            if exclude.covers(prefix) {
                result.remove(prefix);
                continue;
            }

            // If allowed prefix covers the exclusion prefix, then it means the exclusion prefix
            // excludes a portion of this allowed prefix. We need to remove the allowed prefix, and
            // add instead the smaller fragments resulting from the application of the exclusion
            // prefix.
            if prefix.covers(exclude) {
                let mut apply_exclude_result = apply_exclude(prefix, exclude)?;
                result.remove(prefix);
                result.append(&mut apply_exclude_result);
            }
        }
    }

    Ok(result)
}

// Split a given allowed prefix into smaller allowed prefixes, taking into account exclusion
// prefixes, to express the same range of allowed IP addresses without the need for exclusion
// prefixes.
fn apply_exclude(prefix: &Prefix, exclude: &Prefix) -> Result<BTreeSet<Prefix>, NatPeeringError> {
    let mut result = BTreeSet::new();
    let mut prefix_covering_exclude = *prefix;
    let len_diff = exclude.length() - prefix.length();

    for _ in 0..len_diff {
        let (subprefix_low, subprefix_high) = prefix_split(&prefix_covering_exclude)?;

        if subprefix_low.covers(exclude) {
            result.insert(subprefix_high);
            prefix_covering_exclude = subprefix_low;
        } else {
            result.insert(subprefix_low);
            prefix_covering_exclude = subprefix_high;
        }
    }

    Ok(result)
}

// Split a prefix into two smaller prefixes of equal size, by adding one bit to the prefix length.
//
// # Errors
//
// Returns an error if the prefix is a /32 (for IPv4) or /128 (for IPv6)
fn prefix_split(prefix: &Prefix) -> Result<(Prefix, Prefix), NatPeeringError> {
    let prefix_len = prefix.length();
    let prefix_address = prefix.as_address();

    // Compute the address of the second prefix.
    //
    //     1.0.0.0/16 splits as 1.0.0.0/17 and 1.0.128.0/17
    //     1.0.0.0/24 splits as 1.0.0.0/25 and 1.0.0.128/25
    //     1.0.0.0/31 splits as 1.0.0.0/32 and 1.0.0.1/32
    //
    // So we do (for IPv4): base_address + (1 << (32 - prefix_len - 1))
    let split_address = match prefix_address {
        IpAddr::V4(addr) => {
            if prefix_len == Prefix::MAX_LEN_IPV4 {
                error!("Cannot split IPv4 prefix of length {prefix_len}");
                return Err(NatPeeringError::SplitPrefixError(*prefix));
            }
            let new_addr = addr | Ipv4Addr::from_bits(1 << (32 - prefix_len - 1));
            IpAddr::V4(new_addr)
        }
        IpAddr::V6(addr) => {
            if prefix_len == Prefix::MAX_LEN_IPV6 {
                error!("Cannot split IPv6 prefix of length {prefix_len}");
                return Err(NatPeeringError::SplitPrefixError(*prefix));
            }
            let new_addr = addr | Ipv6Addr::from_bits(1 << (128 - prefix_len - 1));
            IpAddr::V6(new_addr)
        }
    };

    let Ok(subprefix_low) = Prefix::try_from((prefix_address, prefix_len + 1)) else {
        // We should never reach this, we returned early if dealing with a /32
        error!("Bug in apply_exclude logics (/32)");
        return Err(NatPeeringError::SplitPrefixError(*prefix));
    };
    let Ok(subprefix_high) = Prefix::try_from((split_address, prefix_len + 1)) else {
        error!("Bug in apply_exclude logics (/128)");
        return Err(NatPeeringError::SplitPrefixError(*prefix));
    };

    Ok((subprefix_low, subprefix_high))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::external::overlay::vpcpeering::{VpcExpose, VpcManifest};
    use ipnet::IpNet;
    use lpm::prefix::{Ipv4Prefix, Ipv6Prefix};
    use lpm::trie::IpPrefixTrie;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_prefix_split() {
        assert_eq!(
            prefix_split(&"1.0.0.0/16".into()).expect("Failed to split prefix"),
            ("1.0.0.0/17".into(), "1.0.128.0/17".into())
        );
        assert_eq!(
            prefix_split(&"1.0.0.0/17".into()).expect("Failed to split prefix"),
            ("1.0.0.0/18".into(), "1.0.64.0/18".into())
        );
        assert_eq!(
            prefix_split(&"1.0.128.0/17".into()).expect("Failed to split prefix"),
            ("1.0.128.0/18".into(), "1.0.192.0/18".into())
        );
        assert_eq!(
            prefix_split(&"1.0.0.0/24".into()).expect("Failed to split prefix"),
            ("1.0.0.0/25".into(), "1.0.0.128/25".into())
        );
        assert_eq!(
            prefix_split(&"1.0.0.0/31".into()).expect("Failed to split prefix"),
            ("1.0.0.0/32".into(), "1.0.0.1/32".into())
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_collapse_prefix_lists() {
        fn btree_from(prefixes: Vec<&str>) -> BTreeSet<Prefix> {
            prefixes.into_iter().map(Into::into).collect()
        }

        // Empty sets
        let prefixes = BTreeSet::new();
        let excludes = BTreeSet::new();
        let expected = prefixes.clone();
        assert_eq!(
            collapse_prefix_lists(&prefixes, &excludes).unwrap(),
            expected
        );

        // Empty prefixes, non-empty excludes
        let prefixes = BTreeSet::new();
        let excludes = btree_from(vec!["1.0.0.0/16", "2.0.0.0/24"]);
        let expected = prefixes.clone();
        assert_eq!(
            collapse_prefix_lists(&prefixes, &excludes).unwrap(),
            expected
        );

        // Excludes outside prefix
        let prefixes = btree_from(vec!["10.0.0.0/16"]);
        let excludes = btree_from(vec!["1.0.0.0/16", "2.0.0.0/24"]);
        let expected = prefixes.clone();
        assert_eq!(
            collapse_prefix_lists(&prefixes, &excludes).unwrap(),
            expected
        );

        // Non-empty prefixes, empty excludes
        let prefixes = btree_from(vec!["1.0.0.0/16", "2.0.0.0/16"]);
        let excludes = BTreeSet::new();
        let expected = prefixes.clone();
        assert_eq!(
            collapse_prefix_lists(&prefixes, &excludes).unwrap(),
            expected
        );

        // Differing IP versions
        let prefixes = btree_from(vec!["1.0.0.0/16"]);
        let excludes = btree_from(vec!["1::/112"]);
        let expected = prefixes.clone();
        assert_eq!(
            collapse_prefix_lists(&prefixes, &excludes).unwrap(),
            expected
        );

        // Longer exclude that does not cover the prefixes
        let prefixes = btree_from(vec!["128.0.0.0/2"]);
        let excludes = btree_from(vec!["0.0.0.0/1"]);
        let expected = prefixes.clone();
        assert_eq!(
            collapse_prefix_lists(&prefixes, &excludes).unwrap(),
            expected
        );

        // Actual collapsing

        let prefixes = btree_from(vec!["1.0.0.0/16"]);
        let excludes = btree_from(vec!["1.0.0.0/16"]);
        let expected = btree_from(vec![]);
        assert_eq!(
            collapse_prefix_lists(&prefixes, &excludes).unwrap(),
            expected
        );

        let prefixes = btree_from(vec!["1.0.0.0/16"]);
        let excludes = btree_from(vec!["1.0.0.0/17"]);
        let expected = btree_from(vec!["1.0.128.0/17"]);
        assert_eq!(
            collapse_prefix_lists(&prefixes, &excludes).unwrap(),
            expected
        );

        let prefixes = btree_from(vec!["1.0.0.0/16"]);
        let excludes = btree_from(vec!["1.0.128.0/17"]);
        let expected = btree_from(vec!["1.0.0.0/17"]);
        assert_eq!(
            collapse_prefix_lists(&prefixes, &excludes).unwrap(),
            expected
        );

        let prefixes = btree_from(vec!["1.0.0.0/16"]);
        let excludes = btree_from(vec!["1.0.1.0/24"]);
        let expected = btree_from(vec![
            "1.0.128.0/17",
            "1.0.64.0/18",
            "1.0.32.0/19",
            "1.0.16.0/20",
            "1.0.8.0/21",
            "1.0.4.0/22",
            "1.0.2.0/23",
            "1.0.0.0/24",
        ]);
        assert_eq!(
            collapse_prefix_lists(&prefixes, &excludes).unwrap(),
            expected
        );

        // Edge cases on sizes
        let prefixes = btree_from(vec!["1.1.1.1/32"]);
        let excludes = btree_from(vec!["1.1.1.1/32"]);
        let expected = btree_from(vec![]);
        assert_eq!(
            collapse_prefix_lists(&prefixes, &excludes).unwrap(),
            expected
        );

        let prefixes = btree_from(vec!["0.0.0.0/0"]);
        let excludes = btree_from(vec!["0.0.0.0/32"]);
        let expected = btree_from(vec![
            "128.0.0.0/1",
            "64.0.0.0/2",
            "32.0.0.0/3",
            "16.0.0.0/4",
            "8.0.0.0/5",
            "4.0.0.0/6",
            "2.0.0.0/7",
            "1.0.0.0/8",
            "0.128.0.0/9",
            "0.64.0.0/10",
            "0.32.0.0/11",
            "0.16.0.0/12",
            "0.8.0.0/13",
            "0.4.0.0/14",
            "0.2.0.0/15",
            "0.1.0.0/16",
            "0.0.128.0/17",
            "0.0.64.0/18",
            "0.0.32.0/19",
            "0.0.16.0/20",
            "0.0.8.0/21",
            "0.0.4.0/22",
            "0.0.2.0/23",
            "0.0.1.0/24",
            "0.0.0.128/25",
            "0.0.0.64/26",
            "0.0.0.32/27",
            "0.0.0.16/28",
            "0.0.0.8/29",
            "0.0.0.4/30",
            "0.0.0.2/31",
            "0.0.0.1/32",
        ]);
        assert_eq!(
            collapse_prefix_lists(&prefixes, &excludes).unwrap(),
            expected
        );

        let prefixes = btree_from(vec!["1.1.1.1/32"]);
        let excludes = btree_from(vec!["0.0.0.0/0"]);
        let expected = btree_from(vec![]);
        assert_eq!(
            collapse_prefix_lists(&prefixes, &excludes).unwrap(),
            expected
        );

        // Multiple prefixes
        let prefixes = btree_from(vec!["1.0.0.0/16", "2.0.17.0/24"]);
        let excludes = btree_from(vec!["1.0.1.0/24", "2.0.17.64/26"]);
        let expected = btree_from(vec![
            "1.0.128.0/17",
            "1.0.64.0/18",
            "1.0.32.0/19",
            "1.0.16.0/20",
            "1.0.8.0/21",
            "1.0.4.0/22",
            "1.0.2.0/23",
            "1.0.0.0/24",
            "2.0.17.128/25",
            "2.0.17.0/26",
        ]);
        assert_eq!(
            collapse_prefix_lists(&prefixes, &excludes).unwrap(),
            expected
        );

        // Multiple excludes on one prefix
        let prefixes = btree_from(vec!["1.0.0.0/16"]);
        let excludes = btree_from(vec!["1.0.1.0/24", "1.0.3.0/24", "1.0.8.0/21"]);
        let expected = btree_from(vec![
            "1.0.128.0/17",
            "1.0.64.0/18",
            "1.0.32.0/19",
            "1.0.16.0/20",
            "1.0.4.0/22",
            "1.0.2.0/24",
            "1.0.0.0/24",
        ]);
        assert_eq!(
            collapse_prefix_lists(&prefixes, &excludes).unwrap(),
            expected
        );

        // Overlapping excludes
        let prefixes = btree_from(vec!["1.0.0.0/16"]);
        let excludes = btree_from(vec!["1.0.0.0/17", "1.0.0.0/24"]);
        let expected = btree_from(vec!["1.0.128.0/17"]);
        assert_eq!(
            collapse_prefix_lists(&prefixes, &excludes).unwrap(),
            expected
        );

        // Full peering
        let expose = VpcExpose::empty()
            .ip("1.0.0.0/16".into())
            .ip("2.0.0.0/24".into())
            .ip("2.0.2.0/24".into())
            .ip("3.0.0.0/16".into())
            .not("1.0.0.0/17".into())
            .not("2.0.2.128/25".into())
            .not("3.0.128.0/17".into());
        let mut manifest = VpcManifest::new("VPC-1");
        manifest.add_expose(expose).expect("Failed to add expose");
        let mut manifest_empty = VpcManifest::new("VPC-2");
        let peering = Peering {
            name: "test_peering".into(),
            local: manifest,
            remote: manifest_empty.clone(),
            remote_id: "12345".try_into().expect("Failed to create VPC ID"),
        };

        let expected_expose = VpcExpose::empty()
            .ip("1.0.128.0/17".into())
            .ip("2.0.0.0/24".into())
            .ip("2.0.2.0/25".into())
            .ip("3.0.0.0/17".into());

        let collapsed_peering =
            collapse_prefixes_peering(&peering).expect("Failed to collapse prefixes");

        assert_eq!(collapsed_peering.local.exposes[0], expected_expose);
    }

    use bolero::{Driver, TypeGenerator, ValueGenerator};
    use std::ops::Bound;
    struct RandomPrefixSetGenerator {
        is_ipv4: bool,
        count: u32,
    }

    impl ValueGenerator for RandomPrefixSetGenerator {
        type Output = BTreeSet<Prefix>;

        fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
            let mut prefixes = BTreeSet::new();
            let is_ipv4 = self.is_ipv4;
            let max_prefix_len = if is_ipv4 { 32 } else { 128 };

            for _ in 0..self.count {
                let prefix_len = d.gen_u8(Bound::Included(&1), Bound::Included(&max_prefix_len))?;
                let addr = if is_ipv4 {
                    IpAddr::from(d.produce::<Ipv4Addr>()?)
                } else {
                    IpAddr::from(d.produce::<Ipv6Addr>()?)
                };
                if let Ok(prefix) = Prefix::try_from((addr, prefix_len)) {
                    prefixes.insert(prefix);
                } else {
                    unreachable!()
                }
            }
            Some(prefixes)
        }
    }

    struct PrefixExcludeAddrsGenerator {
        prefix_max: u32,
        exclude_max: u32,
        addr_count: u32,
    }

    #[derive(Debug)]
    struct PrefixExcludeAddrs {
        prefixes: BTreeSet<Prefix>,
        excludes: BTreeSet<Prefix>,
        addrs: Vec<IpAddr>,
    }

    impl ValueGenerator for PrefixExcludeAddrsGenerator {
        type Output = PrefixExcludeAddrs;

        fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
            let is_ipv4 = d.produce::<bool>()?;
            let prefixes = RandomPrefixSetGenerator {
                count: d.gen_u32(Bound::Included(&1), Bound::Included(&self.prefix_max))?,
                is_ipv4,
            }
            .generate(d)?;
            let excludes = RandomPrefixSetGenerator {
                count: d.gen_u32(Bound::Included(&0), Bound::Included(&self.exclude_max))?,
                is_ipv4,
            }
            .generate(d)?;

            let mut addrs = Vec::with_capacity(usize::try_from(self.addr_count).unwrap());
            for _ in 0..self.addr_count {
                let addr = if is_ipv4 {
                    IpAddr::V4(d.produce::<Ipv4Addr>()?)
                } else {
                    IpAddr::V6(d.produce::<Ipv6Addr>()?)
                };
                addrs.push(addr);
            }
            Some(PrefixExcludeAddrs {
                prefixes,
                excludes,
                addrs,
            })
        }
    }

    fn prefix_oracle(
        addr: &IpAddr,
        prefixes: &IpPrefixTrie<()>,
        excludes: &IpPrefixTrie<()>,
    ) -> bool {
        excludes.lookup(*addr).is_none() && prefixes.lookup(*addr).is_some()
    }

    #[test]
    fn test_bolero_collapse_prefix_lists() {
        let generator = PrefixExcludeAddrsGenerator {
            prefix_max: 100,
            exclude_max: 100,
            addr_count: 1000,
        };
        bolero::check!()
            .with_generator(generator)
            .for_each(|data: &PrefixExcludeAddrs| {
                let PrefixExcludeAddrs {
                    prefixes,
                    excludes,
                    addrs,
                } = data;
                let mut prefixes_trie = IpPrefixTrie::<()>::new();
                let mut excludes_trie = IpPrefixTrie::<()>::new();
                let mut collapsed_prefixes_trie = IpPrefixTrie::<()>::new();
                for prefix in prefixes {
                    prefixes_trie.insert(*prefix, ());
                }
                for exclude in excludes {
                    excludes_trie.insert(*exclude, ());
                }
                let collapsed_prefixes = collapse_prefix_lists(prefixes, excludes).unwrap();
                for prefix in collapsed_prefixes.clone() {
                    collapsed_prefixes_trie.insert(prefix, ());
                }
                for addr in addrs {
                    let oracle_result = prefix_oracle(addr, &prefixes_trie, &excludes_trie);
                    let collapsed_result = collapsed_prefixes_trie.lookup(*addr).is_some();
                    assert_eq!(
                        oracle_result, collapsed_result,
                        "addr: {addr:?}, collapsed={collapsed_prefixes_trie:#?}, collapsed_prefixes={collapsed_prefixes:#?}"
                    );
                }
            });
    }
}
