// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::external::overlay::vpc::Peering;
use crate::utils::ConfigUtilError;
use lpm::prefix::{IpRangeWithPorts, PrefixWithOptionalPorts};
use std::collections::BTreeSet;

// Collapse prefixes and exclusion prefixes in a Peering object: for each expose object, "apply"
// exclusion prefixes to split allowed prefixes into smaller chunks, and remove exclusion prefixes
// from the expose object.
//
// For example, for a given expose with "ips" as 1.0.0.0/16 and "nots" as 1.0.0.0/18, the resulting
// expose will contain 1.0.128.0/17 and 1.0.64.0/18 as "ips" prefixes, and an empty "nots" list.
//
// Another example would be "ips" as 1.0.0.0/16, with associated port range 4000-5000, and "nots" as
// 1.0.0.0/17, with associated port range 4000-4500. The resulting expose will contain (1.0.0.0/16,
// 0-3999), (1.0.0.0/16, 4501-5000), and (1.0.128.0/17, 4000-4500) as "ips" prefixes, and again, an
// empty "nots" list.
pub fn collapse_prefixes_peering(peering: &Peering) -> Result<Peering, ConfigUtilError> {
    let mut clone = peering.clone();
    for expose in &mut clone
        .local
        .exposes
        .iter_mut()
        .chain(&mut clone.remote.exposes.iter_mut())
    {
        let ips = collapse_prefix_lists(&expose.ips, &expose.nots);
        expose.ips = ips;
        expose.nots = BTreeSet::new();

        let Some(nat) = expose.nat.as_mut() else {
            continue;
        };
        let as_range = collapse_prefix_lists(&nat.as_range, &nat.not_as);
        nat.as_range = as_range;
        nat.not_as = BTreeSet::new();
    }
    Ok(clone)
}

// Collapse prefixes (first set) and exclusion prefixes (second set), by "applying" exclusion
// prefixes to the allowed prefixes and split them into smaller allowed segments, to express the
// same IP ranges without any exclusion prefixes.
fn collapse_prefix_lists(
    prefixes: &BTreeSet<PrefixWithOptionalPorts>,
    excludes: &BTreeSet<PrefixWithOptionalPorts>,
) -> BTreeSet<PrefixWithOptionalPorts> {
    let mut result = prefixes.clone();
    // Iterate over all exclusion prefixes
    for exclude in excludes {
        for prefix in result.clone() {
            // If the allowed prefix overlaps with the exclusion prefix, then it means the exclusion
            // prefix excludes a portion of this allowed prefix. We need to remove the allowed
            // prefix, and add instead the smaller fragments resulting from the application of the
            // exclusion prefix.
            if prefix.overlaps(exclude) {
                result.remove(&prefix);
                for p in prefix.subtract(exclude) {
                    result.insert(p);
                }
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external::overlay::vpcpeering::{VpcExpose, VpcManifest};
    use ipnet::IpNet;
    use lpm::prefix::Prefix;
    use lpm::trie::IpPrefixTrie;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_collapse_prefix_lists() {
        fn btree_from(prefixes: Vec<&str>) -> BTreeSet<PrefixWithOptionalPorts> {
            prefixes.into_iter().map(Into::into).collect()
        }

        // Empty sets
        let prefixes = BTreeSet::new();
        let excludes = BTreeSet::new();
        let expected = prefixes.clone();
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Empty prefixes, non-empty excludes
        let prefixes = BTreeSet::new();
        let excludes = btree_from(vec!["1.0.0.0/16", "2.0.0.0/24"]);
        let expected = prefixes.clone();
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Excludes outside prefix
        let prefixes = btree_from(vec!["10.0.0.0/16"]);
        let excludes = btree_from(vec!["1.0.0.0/16", "2.0.0.0/24"]);
        let expected = prefixes.clone();
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Non-empty prefixes, empty excludes
        let prefixes = btree_from(vec!["1.0.0.0/16", "2.0.0.0/16"]);
        let excludes = BTreeSet::new();
        let expected = prefixes.clone();
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Differing IP versions
        let prefixes = btree_from(vec!["1.0.0.0/16"]);
        let excludes = btree_from(vec!["1::/112"]);
        let expected = prefixes.clone();
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Longer exclude that does not cover the prefixes
        let prefixes = btree_from(vec!["128.0.0.0/2"]);
        let excludes = btree_from(vec!["0.0.0.0/1"]);
        let expected = prefixes.clone();
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Actual collapsing

        let prefixes = btree_from(vec!["1.0.0.0/16"]);
        let excludes = btree_from(vec!["1.0.0.0/16"]);
        let expected = btree_from(vec![]);
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        let prefixes = btree_from(vec!["1.0.0.0/16"]);
        let excludes = btree_from(vec!["1.0.0.0/17"]);
        let expected = btree_from(vec!["1.0.128.0/17"]);
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        let prefixes = btree_from(vec!["1.0.0.0/16"]);
        let excludes = btree_from(vec!["1.0.128.0/17"]);
        let expected = btree_from(vec!["1.0.0.0/17"]);
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

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
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Edge cases on sizes
        let prefixes = btree_from(vec!["1.1.1.1/32"]);
        let excludes = btree_from(vec!["1.1.1.1/32"]);
        let expected = btree_from(vec![]);
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

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
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        let prefixes = btree_from(vec!["1.1.1.1/32"]);
        let excludes = btree_from(vec!["0.0.0.0/0"]);
        let expected = btree_from(vec![]);
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

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
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

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
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Overlapping excludes
        let prefixes = btree_from(vec!["1.0.0.0/16"]);
        let excludes = btree_from(vec!["1.0.0.0/17", "1.0.0.0/24"]);
        let expected = btree_from(vec!["1.0.128.0/17"]);
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

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
        let manifest_empty = VpcManifest::new("VPC-2");
        let peering = Peering {
            name: "test_peering".into(),
            local: manifest,
            remote: manifest_empty.clone(),
            remote_id: "12345".try_into().expect("Failed to create VPC ID"),
            gwgroup: None,
            adv_communities: vec![],
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

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_collapse_prefixes_with_ports() {
        use lpm::prefix::PortRange;

        fn btree_from(prefixes: Vec<&str>) -> BTreeSet<PrefixWithOptionalPorts> {
            prefixes.into_iter().map(Into::into).collect()
        }

        fn btree_from_ports(
            prefixes_with_ports: Vec<(&str, Option<(u16, u16)>)>,
        ) -> BTreeSet<PrefixWithOptionalPorts> {
            prefixes_with_ports
                .into_iter()
                .map(|(prefix_str, port_opt)| {
                    let prefix = Prefix::from(prefix_str);
                    let ports = port_opt.map(|(start, end)| {
                        PortRange::new(start, end).expect("Invalid port range")
                    });
                    PrefixWithOptionalPorts::new(prefix, ports)
                })
                .collect()
        }

        fn no_overlap(prefix_list: &BTreeSet<PrefixWithOptionalPorts>) -> bool {
            prefix_list.iter().all(|prefix| {
                prefix_list
                    .iter()
                    .all(|other| prefix == other || !prefix.overlaps(other))
            })
        }

        // Empty sets
        let prefixes = BTreeSet::new();
        let excludes = BTreeSet::new();
        let expected = prefixes.clone();
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Empty prefixes, non-empty excludes with ports
        let prefixes = BTreeSet::new();
        let excludes = btree_from_ports(vec![
            ("1.0.0.0/16", Some((80, 443))),
            ("2.0.0.0/24", Some((22, 22))),
        ]);
        let expected = prefixes.clone();
        assert!(no_overlap(&expected));
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Excludes outside prefix with ports
        let prefixes = btree_from_ports(vec![("10.0.0.0/16", Some((80, 100)))]);
        let excludes = btree_from_ports(vec![
            ("1.0.0.0/16", Some((80, 100))),
            ("2.0.0.0/24", Some((22, 22))),
        ]);
        let expected = prefixes.clone();
        assert!(no_overlap(&expected));
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Non-empty prefixes with ports, empty excludes
        let prefixes = btree_from_ports(vec![
            ("1.0.0.0/16", Some((80, 443))),
            ("2.0.0.0/16", Some((8000, 9000))),
        ]);
        let excludes = BTreeSet::new();
        let expected = prefixes.clone();
        assert!(no_overlap(&expected));
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Differing IP versions with ports
        let prefixes = btree_from_ports(vec![("1.0.0.0/16", Some((80, 443)))]);
        let excludes = btree_from_ports(vec![("1::/112", Some((80, 443)))]);
        let expected = prefixes.clone();
        assert!(no_overlap(&expected));
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Port range collapsing - non-overlapping port ranges
        let prefixes = btree_from_ports(vec![("1.0.0.0/16", Some((4000, 5000)))]);
        let excludes = btree_from_ports(vec![("1.0.0.0/16", Some((6000, 7000)))]);
        let expected = prefixes.clone();
        assert!(no_overlap(&expected));
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Port range collapsing - exclude covers entire port range
        let prefixes = btree_from_ports(vec![("1.0.0.0/16", Some((4000, 5000)))]);
        let excludes = btree_from_ports(vec![("1.0.0.0/16", Some((4000, 5000)))]);
        let expected = btree_from_ports(vec![]);
        assert!(no_overlap(&expected));
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Port range collapsing - exclude covers part of port range
        let prefixes = btree_from_ports(vec![("1.0.0.0/16", Some((4000, 5000)))]);
        let excludes = btree_from_ports(vec![("1.0.0.0/16", Some((4000, 4500)))]);
        let expected = btree_from_ports(vec![("1.0.0.0/16", Some((4501, 5000)))]);
        assert!(no_overlap(&expected));
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Port range collapsing - exclude in middle of port range
        let prefixes = btree_from_ports(vec![("1.0.0.0/16", Some((4000, 5000)))]);
        let excludes = btree_from_ports(vec![("1.0.0.0/16", Some((4200, 4800)))]);
        let expected = btree_from_ports(vec![
            ("1.0.0.0/16", Some((4000, 4199))),
            ("1.0.0.0/16", Some((4801, 5000))),
        ]);
        assert!(no_overlap(&expected));
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Prefix and port range collapsing combined
        let prefixes = btree_from_ports(vec![("1.0.0.0/16", Some((4000, 5000)))]);
        let excludes = btree_from_ports(vec![("1.0.0.0/17", Some((4000, 4500)))]);
        let expected = btree_from_ports(vec![
            ("1.0.0.0/16", Some((4501, 5000))),
            ("1.0.128.0/17", Some((4000, 4500))),
        ]);
        assert!(no_overlap(&expected));
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Prefix exclusion with port range - exclude smaller prefix
        let prefixes = btree_from_ports(vec![("1.0.0.0/16", Some((4000, 5000)))]);
        let excludes = btree_from_ports(vec![("1.0.0.0/17", Some((4000, 5000)))]);
        let expected = btree_from_ports(vec![("1.0.128.0/17", Some((4000, 5000)))]);
        assert!(no_overlap(&expected));
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Multiple excludes with different port ranges
        let prefixes = btree_from_ports(vec![("1.0.0.0/16", Some((1000, 2000)))]);
        let excludes = btree_from_ports(vec![
            ("1.0.0.0/17", Some((1000, 1500))),
            ("1.0.0.0/16", Some((1800, 1900))),
        ]);
        let expected = btree_from_ports(vec![
            ("1.0.0.0/16", Some((1501, 1799))),
            ("1.0.0.0/16", Some((1901, 2000))),
            ("1.0.128.0/17", Some((1000, 1500))),
        ]);
        assert!(no_overlap(&expected));
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Prefix without ports, exclude with ports
        let prefixes = btree_from(vec!["1.0.0.0/16"]);
        let excludes = btree_from_ports(vec![("1.0.0.0/17", Some((4000, 5000)))]);
        let expected = btree_from_ports(vec![
            ("1.0.0.0/16", Some((0, 3999))),
            ("1.0.0.0/16", Some((5001, 65535))),
            ("1.0.128.0/17", Some((4000, 5000))),
        ]);
        assert!(no_overlap(&expected));
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Prefix with ports, exclude without ports
        let prefixes = btree_from_ports(vec![("1.0.0.0/16", Some((80, 443)))]);
        let excludes = btree_from(vec!["1.0.0.0/17"]);
        let expected = btree_from_ports(vec![("1.0.128.0/17", Some((80, 443)))]);
        assert!(no_overlap(&expected));
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Edge case: single port
        let prefixes = btree_from_ports(vec![("1.0.0.0/16", Some((80, 80)))]);
        let excludes = btree_from_ports(vec![("1.0.0.0/16", Some((80, 80)))]);
        let expected = btree_from_ports(vec![]);
        assert!(no_overlap(&expected));
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Edge case: full port range
        let prefixes = btree_from_ports(vec![("1.0.0.0/16", Some((0, 65535)))]);
        let excludes = btree_from_ports(vec![("1.0.0.0/17", Some((0, 32767)))]);
        let expected = btree_from_ports(vec![
            ("1.0.0.0/16", Some((32768, 65535))),
            ("1.0.128.0/17", Some((0, 32767))),
        ]);
        assert!(no_overlap(&expected));
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // IPv6 with ports
        let prefixes = btree_from_ports(vec![("2001:db8::/32", Some((4000, 5000)))]);
        let excludes = btree_from_ports(vec![("2001:db8::/33", Some((4000, 4500)))]);
        let expected = btree_from_ports(vec![
            ("2001:db8::/32", Some((4501, 5000))),
            ("2001:db8:8000::/33", Some((4000, 4500))),
        ]);
        assert!(no_overlap(&expected));
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);

        // Multiple prefixes with ports, multiple excludes with ports
        let prefixes = btree_from_ports(vec![
            ("1.0.0.0/16", Some((4000, 5000))),
            ("2.0.0.0/24", Some((6000, 9000))),
        ]);
        let excludes = btree_from_ports(vec![
            ("1.0.0.0/17", Some((4500, 5000))),
            ("2.0.0.0/25", Some((7000, 8000))),
        ]);
        let expected = btree_from_ports(vec![
            ("1.0.0.0/16", Some((4000, 4499))),
            ("1.0.128.0/17", Some((4500, 5000))),
            ("2.0.0.0/24", Some((6000, 6999))),
            ("2.0.0.0/24", Some((8001, 9000))),
            ("2.0.0.128/25", Some((7000, 8000))),
        ]);
        assert!(no_overlap(&expected));
        assert_eq!(collapse_prefix_lists(&prefixes, &excludes), expected);
    }

    use bolero::{Driver, ValueGenerator};
    use std::ops::Bound;
    struct RandomPrefixSetGenerator {
        is_ipv4: bool,
        count: u32,
    }

    impl ValueGenerator for RandomPrefixSetGenerator {
        type Output = BTreeSet<PrefixWithOptionalPorts>;

        fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
            let mut prefixes = BTreeSet::new();
            let is_ipv4 = self.is_ipv4;
            let max_prefix_len = if is_ipv4 { 32 } else { 128 };

            for _ in 0..self.count {
                let prefix_len = d.gen_u8(Bound::Included(&1), Bound::Included(&max_prefix_len))?;
                let addr = if is_ipv4 {
                    let bits: u32 = d.produce()?;
                    IpAddr::from(Ipv4Addr::from_bits(bits))
                } else {
                    let bits: u128 = d.produce()?;
                    IpAddr::from(Ipv6Addr::from_bits(bits))
                };
                // TODO: Also add port ranges
                let prefix = PrefixWithOptionalPorts::new(
                    Prefix::from(IpNet::new_assert(addr, prefix_len)),
                    None,
                );
                prefixes.insert(prefix);
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
        prefixes: BTreeSet<PrefixWithOptionalPorts>,
        excludes: BTreeSet<PrefixWithOptionalPorts>,
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
                    prefixes_trie.insert(prefix.prefix(), ());
                }
                for exclude in excludes {
                    excludes_trie.insert(exclude.prefix(), ());
                }
                let collapsed_prefixes = collapse_prefix_lists(prefixes, excludes);
                for prefix in collapsed_prefixes.clone() {
                    collapsed_prefixes_trie.insert(prefix.prefix(), ());
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
