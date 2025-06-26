// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! NAT rule tables entries creation

use crate::models::external::overlay::vpc::Peering;
use crate::models::external::overlay::vpcpeering::{VpcExpose, VpcManifest};
use nat::stateless::config::prefixtrie::{PrefixTrie, TrieError};
use nat::stateless::config::tables::{NatPrefixRuleTable, PerVniTable, TrieValue};
use routing::prefix::Prefix;
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Create a [`TrieValue`] from the public side of a [`VpcExpose`], for a given prefix in this
/// [`VpcExpose`]
fn get_public_trie_value(expose: &VpcExpose, prefix: &Prefix) -> TrieValue {
    let orig = expose.ips.clone();
    let orig_excludes = expose.nots.clone();
    let target = expose.as_range.clone();
    let target_excludes = expose.not_as.clone();

    TrieValue::new(orig, orig_excludes, target, target_excludes)
}

/// Create a [`TrieValue`] from the private side of a [`VpcExpose`], for a given prefix in this
/// [`VpcExpose`]
fn get_private_trie_value(expose: &VpcExpose, prefix: &Prefix) -> TrieValue {
    let orig = expose.ips.clone();
    let orig_excludes = expose.nots.clone();
    let target = expose.as_range.clone();
    let target_excludes = expose.not_as.clone();

    TrieValue::new(orig, orig_excludes, target, target_excludes)
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
pub fn add_peering(table: &mut PerVniTable, peering: &Peering) -> Result<(), TrieError> {
    let new_peering = optimize_peering(peering);

    new_peering.local.exposes.iter().try_for_each(|expose| {
        // Create new peering table for source NAT
        let mut peering_table = NatPrefixRuleTable::new();

        // For each private prefix, add an entry containing the exclusion prefixes and the set of
        // public prefixes
        expose.ips.iter().try_for_each(|prefix| {
            let pub_value = get_public_trie_value(expose, prefix);
            peering_table.insert(prefix, pub_value)
        })?;
        // Add "None" entries for excluded prefixes
        expose
            .nots
            .iter()
            .try_for_each(|prefix| peering_table.insert_none(prefix))?;

        // Add peering table to PerVniTable
        table.src_nat_prefixes.push(peering_table);

        // Update peering table to make relevant prefixes point to the new peering table, for each
        // private prefix
        let peering_index = table.src_nat_prefixes.len() - 1;
        expose
            .ips
            .iter()
            .try_for_each(|prefix| table.src_nat_peers.rules.insert(prefix, peering_index))
    })?;

    // Update table for destination NAT
    new_peering.remote.exposes.iter().try_for_each(|expose| {
        // For each public prefix, add an entry containing the exclusion prefixes and the set of
        // private prefixes
        expose.as_range.iter().try_for_each(|prefix| {
            let priv_value = get_private_trie_value(expose, prefix);
            table.dst_nat.insert(prefix, priv_value)
        })?;
        // Add "None" entries for excluded prefixes
        expose
            .not_as
            .iter()
            .try_for_each(|prefix| table.dst_nat.insert_none(prefix))
    })?;

    Ok(())
}

/// Optimizes a list of prefixes and their exclusions:
///
/// - Remove mutually-excluding prefixes/exclusion prefixes pairs
/// - Collapse prefixes and exclusion prefixes when possible
fn optimize_expose(
    prefixes: &BTreeSet<Prefix>,
    excludes: &BTreeSet<Prefix>,
) -> (BTreeSet<Prefix>, BTreeSet<Prefix>) {
    let mut clone = prefixes.clone();
    let mut clone_not = excludes.clone();
    // Sort excludes by mask length, ascending (/16 comes before /24, for example).
    let mut excludes_sorted = excludes.iter().collect::<Vec<_>>();
    excludes_sorted.sort_by_key(|p| p.length());

    for prefix in prefixes {
        for exclude in &excludes_sorted {
            if !prefix.covers(exclude) {
                continue;
            }
            if prefix.length() == exclude.length() {
                // Prefix and exclusion prefix are the same. We can remove both.
                clone.remove(prefix);
                clone_not.remove(exclude);
            } else if prefix.length() == 2 * exclude.length() {
                // Exclusion prefixes is half of the prefix. We can transform the prefix by
                // extending its mask and keeping only the relevant portion, and discard the
                // exclusion prefix entirely.
                //
                // We want to try biggest exclusion prefixes first, to avoid "missing" optimization
                // for smaller exclusion prefixes before the one for bigger exclusion prefixes has
                // been applied. This is why we sorted the exclusion prefixes by mask length,
                // at the beginning of the function.
                let new_length = prefix.length() + 1;
                let mut new_address;
                if prefix.as_address() == exclude.as_address() {
                    // Exclusion prefix covers the first half of the prefix.
                    // Here we need to update the address to keep the second half of the prefix.
                    new_address = match prefix.as_address() {
                        IpAddr::V4(addr) => {
                            let Ok(exclude_size) = u32::try_from(exclude.size()) else {
                                unreachable!(
                                    "Exclude size too big ({}), bug in IpList",
                                    exclude.size()
                                )
                            };
                            IpAddr::V4(Ipv4Addr::from(addr.to_bits() + exclude_size))
                        }
                        IpAddr::V6(addr) => {
                            IpAddr::V6(Ipv6Addr::from(addr.to_bits() + exclude.size()))
                        }
                        // Prefix cannot cover exclusion prefix of a different IP version
                        _ => unreachable!(
                            "Prefix and exclusion prefix are not of the same IP version"
                        ),
                    }
                } else {
                    // Exclusion prefix is the second half of the prefix; keep the first half.
                    new_address = prefix.as_address();
                }
                let Ok(new_prefix) = Prefix::try_from((new_address, new_length)) else {
                    unreachable!("Failed to create new prefix from ({new_address}, {new_length})");
                };

                clone.remove(prefix);
                clone_not.remove(exclude);
                clone.insert(new_prefix);
            }
        }
    }
    (clone, clone_not)
}

/// Optimize a Peering object: collapse prefixes and exclusion prefixes when possible
fn optimize_peering(peering: &Peering) -> Peering {
    // Collapse prefixes and exclusion prefixes
    let mut clone = peering.clone();
    for expose in &mut clone.local.exposes {
        let (ips, nots) = optimize_expose(&expose.ips, &expose.nots);
        expose.ips = ips;
        expose.nots = nots;
    }
    for expose in &mut clone.remote.exposes {
        let (as_range, not_as) = optimize_expose(&expose.as_range, &expose.not_as);
        expose.as_range = as_range;
        expose.not_as = not_as;
    }
    clone
}

#[cfg(test)]
mod tests {
    use super::*;
    use iptrie::{Ipv4Prefix, Ipv6Prefix};
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

        let mut vni_table = PerVniTable::new();
        add_peering(&mut vni_table, &peering).expect("Failed to build NAT tables");
    }
}
