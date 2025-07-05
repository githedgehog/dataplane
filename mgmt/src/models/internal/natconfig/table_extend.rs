// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! NAT rule tables entries creation

use crate::models::external::overlay::vpc::{Peering, VpcTable};
use crate::models::external::overlay::vpcpeering::{VpcExpose, VpcManifest};
use nat::stateless::config::prefixtrie::{PrefixTrie, TrieError};
use nat::stateless::config::tables::{NatPrefixRuleTable, PerVniTable, TrieValue};
use net::vxlan::Vni;
use routing::prefix::Prefix;
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::error;

/// Error type for NAT peering table extension operations.
#[derive(thiserror::Error, Debug)]
pub enum NatPeeringError {
    #[error("entry already exists")]
    EntryExists,
    #[error("failed to split prefix {0}")]
    SplitPrefixError(Prefix),
}

/// Create a [`TrieValue`] from the public side of a [`VpcExpose`], for a given prefix in this
/// [`VpcExpose`]
fn get_public_trie_value(vni: Vni, expose: &VpcExpose, prefix: &Prefix) -> TrieValue {
    let orig = expose.ips.clone();
    let target = expose.as_range.clone();

    TrieValue::new(vni, orig, target)
}

/// Create a [`TrieValue`] from the private side of a [`VpcExpose`], for a given prefix in this
/// [`VpcExpose`]
fn get_private_trie_value(vni: Vni, expose: &VpcExpose, prefix: &Prefix) -> TrieValue {
    let orig = expose.ips.clone();
    let target = expose.as_range.clone();

    TrieValue::new(vni, orig, target)
}

// Note: add_peering(table, peering) should be part of PerVniTable, but we prefer to keep it in a
// separate submodule because it relies on definitions from the external models, unlike the rest of
// the PerVniTable implementation.
//
/// Add a [`Peering`] to a [`PerVniTable`]
///
/// # Errors
///
/// Returns an error if some lists of prefixes contain duplicates
pub fn add_peering(
    table: &mut PerVniTable,
    peering: &Peering,
    vpc_table: &VpcTable,
) -> Result<(), NatPeeringError> {
    let new_peering = collapse_prefixes_peering(peering)?;

    let mut local_expose_indices = vec![];

    new_peering.local.exposes.iter().try_for_each(|expose| {
        if expose.as_range.is_empty() {
            // Nothing to do for source NAT, get out of here
            return Ok(());
        }
        // Create new peering table for source NAT
        let mut peering_table = NatPrefixRuleTable::new();

        // For each private prefix, add an entry containing the set of public prefixes
        expose.ips.iter().try_for_each(|prefix| {
            let pub_value = get_public_trie_value(table.vni, expose, prefix);
            peering_table
                .insert(prefix, pub_value)
                .map_err(|_| NatPeeringError::EntryExists)
        })?;

        // Add peering table to PerVniTable
        table.src_nat_prefixes.push(peering_table);
        local_expose_indices.push(table.src_nat_prefixes.len() - 1);
        Ok(())
    })?;

    /* get vni for remote manifest */
    let remote_vni = vpc_table
        .get_vpc_by_vpcid(new_peering.remote_id)
        .unwrap_or_else(|| unreachable!())
        .vni;

    // Update table for destination NAT
    new_peering.remote.exposes.iter().try_for_each(|expose| {
        // For each public prefix, add an entry containing the set of private prefixes
        expose.as_range.iter().try_for_each(|prefix| {
            let priv_value = get_private_trie_value(remote_vni, expose, prefix);
            table
                .dst_nat
                .insert(prefix, priv_value)
                .map_err(|_| NatPeeringError::EntryExists)
        })?;

        // Update peering table to make relevant prefixes point to the new peering table, for each
        // private prefix.
        //
        // Note that the public IPs are not always from the as_range list: if this list is empty,
        // then there's no NAT required for the expose, meaning that the public IPs are those from
        // the "ips" list.
        let remote_public_prefixes = expose.public_ips();
        remote_public_prefixes.iter().try_for_each(|prefix| {
            table
                .src_nat_peers
                .rules
                .insert(prefix, local_expose_indices.clone())
                .map_err(|_| NatPeeringError::EntryExists)
        })
    })?;

    Ok(())
}

// Collapse prefixes and exclusion prefixes in a Peering object: for each expose object, "apply"
// exclusion prefixes to split allowed prefixes into smaller chunks, and remove exclusion prefixes
// from the expose object.
//
// For example, for a given expose with "ips" as 1.0.0.0/16 and "nots" as 1.0.0.0/18, the resulting
// expose will contain 1.0.128.0/17 and 1.0.64.0/18 as "ips" prefixes, and an empty "nots" list.
fn collapse_prefixes_peering(peering: &Peering) -> Result<Peering, NatPeeringError> {
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
                break;
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
    use crate::models::external::overlay::vpc::Vpc;
    use ipnet::IpNet;
    use iptrie::{IpRTrieSet, Ipv4Prefix, Ipv6Prefix};
    use nat::stateless::config::tables::NatTables;
    use net::vxlan::Vni;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    #[test]
    fn test_fabric() {
        let expose1 = VpcExpose::empty()
            .ip("1.1.0.0/16".into())
            .not("1.1.5.0/24".into())
            .not("1.1.3.0/24".into())
            .not("1.1.1.0/24".into())
            .ip("1.2.0.0/16".into())
            .not("1.2.2.0/24".into())
            .as_range("2.2.0.0/16".into())
            .not_as("2.1.10.0/24".into())
            .not_as("2.1.1.0/24".into())
            .not_as("2.1.8.0/24".into())
            .not_as("2.1.2.0/24".into())
            .as_range("2.1.0.0/16".into());
        let expose2 = VpcExpose::empty()
            .ip("3.0.0.0/16".into())
            .as_range("4.0.0.0/16".into());

        let mut manifest1 = VpcManifest::new("VPC-1");
        manifest1.add_expose(expose1).expect("Failed to add expose");
        manifest1.add_expose(expose2).expect("Failed to add expose");

        let expose3 = VpcExpose::empty()
            .ip("1::/64".into())
            .not("1::/128".into())
            .as_range("1:1::/64".into())
            .not_as("1:2::/128".into());
        let expose4 = VpcExpose::empty()
            .ip("2::/64".into())
            .not("2::/128".into())
            .as_range("2:4::/64".into())
            .not_as("2:9::/128".into());

        let mut manifest2 = VpcManifest::new("VPC-2");
        manifest2.add_expose(expose3).expect("Failed to add expose");
        manifest2.add_expose(expose4).expect("Failed to add expose");

        let peering: Peering = Peering {
            name: "test_peering".into(),
            local: manifest1,
            remote: manifest2,
            remote_id: "12345".try_into().expect("Failed to create VPC ID"),
        };

        let vni = Vni::new_checked(100).unwrap();
        let mut vpctable = VpcTable::new();
        let mut vpc = Vpc::new("VPC", "12345", vni.as_u32()).unwrap();
        vpc.peerings.push(peering.clone());
        vpctable.add(vpc);

        let mut vni_table = PerVniTable::new(vni);
        add_peering(&mut vni_table, &peering, &vpctable).expect("Failed to build NAT tables");
    }

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

    fn prefix_oracle(addr: &IpNet, prefixes: &IpRTrieSet, excludes: &IpRTrieSet) -> bool {
        !excludes.contains(addr) && prefixes.contains(addr)
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
                let mut prefixes_trie = IpRTrieSet::new();
                let mut excludes_trie = IpRTrieSet::new();
                let mut collapsed_prefixes_trie = IpRTrieSet::new();
                for prefix in prefixes {
                    prefixes_trie.insert(IpNet::from(*prefix));
                }
                for exclude in excludes {
                    excludes_trie.insert(IpNet::from(*exclude));
                }
                let collapsed_prefixes = collapse_prefix_lists(prefixes, excludes).unwrap();
                for prefix in collapsed_prefixes {
                    collapsed_prefixes_trie.insert(IpNet::from(prefix));
                }
                for addr in addrs {
                    let addr_net = IpNet::from(*addr);
                    let oracle_result = prefix_oracle(&addr_net, &prefixes_trie, &excludes_trie);
                    let collapsed_result = collapsed_prefixes_trie.contains(&addr_net);
                    assert_eq!(oracle_result, collapsed_result);
                }
            });
    }
}
