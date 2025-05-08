// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: vpc peering

use routing::prefix::Prefix;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ops::Bound::{Excluded, Unbounded};

use crate::models::external::{ConfigError, ConfigResult};
#[derive(Clone, Debug, Default, PartialEq)]
pub struct VpcExpose {
    pub ips: BTreeSet<Prefix>,
    pub nots: BTreeSet<Prefix>,
    pub as_range: BTreeSet<Prefix>,
    pub not_as: BTreeSet<Prefix>,
}
impl VpcExpose {
    pub fn empty() -> Self {
        Self::default()
    }
    pub fn ip(mut self, prefix: Prefix) -> Self {
        self.ips.insert(prefix);
        self
    }
    pub fn not(mut self, prefix: Prefix) -> Self {
        self.nots.insert(prefix);
        self
    }
    pub fn as_range(mut self, prefix: Prefix) -> Self {
        self.as_range.insert(prefix);
        self
    }
    pub fn not_as(mut self, prefix: Prefix) -> Self {
        self.not_as.insert(prefix);
        self
    }
    /// Validate the [`VpcExpose`]:
    ///
    /// 1. Make sure that all prefixes and exclusion prefixes for this [`VpcExpose`] are of the same
    ///    IP version.
    /// 2. Make sure that all prefixes (or exclusion prefixes) in each list
    ///    (ips/nots/as_range/not_as) don't overlap with other prefixes (or exclusion prefixes,
    ///    respectively) of this list.
    /// 3. Make sure that all exclusion prefixes are contained within existing prefixes, unless the
    ///    list of allowed prefixes is empty.
    /// 4. Make sure exclusion prefixes in a list don't exclude all of the prefixes in the
    ///    associated prefixes list.
    /// 5. Make sure we have the same number of addresses available on each side (public/private),
    ///    taking exclusion prefixes into account.
    pub fn validate(&self) -> ConfigResult {
        // 1. Static NAT: Check that all prefixes in a list are of the same IP version, as we don't
        // support NAT46 or NAT64 at the moment.
        //
        // TODO: We can loosen this restriction in the future. When we do, some additional
        //       considerations might be required to validate independently the IPv4 and the IPv6
        //       prefixes and exclusion prefixes in the rest of this function.
        let mut is_ipv4_opt = None;
        for prefixes in [&self.ips, &self.nots, &self.as_range, &self.not_as] {
            if prefixes.iter().any(|p| {
                if let Some(is_ipv4) = is_ipv4_opt {
                    p.is_ipv4() != is_ipv4
                } else {
                    is_ipv4_opt = Some(p.is_ipv4());
                    false
                }
            }) {
                return Err(ConfigError::InconsistentIpVersion(self.clone()));
            }
        }

        // 2. Check that items in prefix lists of each kind don't overlap
        for prefixes in [&self.ips, &self.nots, &self.as_range, &self.not_as] {
            for prefix in prefixes.iter() {
                // Loop over the remaining prefixes in the tree
                for other_prefix in prefixes.range((Excluded(prefix), Unbounded)) {
                    if prefix.covers(other_prefix) || other_prefix.covers(prefix) {
                        return Err(ConfigError::OverlappingPrefixes(
                            prefix.clone(),
                            other_prefix.clone(),
                        ));
                    }
                }
            }
        }

        // 3. Ensure all exclusion prefixes are contained within existing allowed prefixes,
        // unless the list of allowed prefixes is empty.
        for (prefixes, excludes) in [(&self.ips, &self.nots), (&self.as_range, &self.not_as)] {
            if prefixes.is_empty() {
                continue;
            }
            for exclude in excludes.iter() {
                if !prefixes.iter().any(|p| p.covers(exclude)) {
                    return Err(ConfigError::OutOfRangeExclusionPrefix(exclude.clone()));
                }
            }
        }

        fn prefixes_size(prefixes: &BTreeSet<Prefix>) -> u128 {
            prefixes.iter().map(|p| p.size()).sum()
        }

        // 4. Ensure we don't exclude all of the allowed prefixes
        let ips_sizes = prefixes_size(&self.ips);
        let nots_sizes = prefixes_size(&self.nots);
        if ips_sizes > 0 && ips_sizes <= nots_sizes {
            return Err(ConfigError::ExcludedAllPrefixes(self.clone()));
        }

        let as_range_sizes = prefixes_size(&self.as_range);
        let not_as_sizes = prefixes_size(&self.not_as);
        if as_range_sizes > 0 && as_range_sizes <= not_as_sizes {
            return Err(ConfigError::ExcludedAllPrefixes(self.clone()));
        }

        // 5. Static NAT: Ensure that, if the list of publicly-exposed addresses is not empty, then
        //    we have the same number of address on each side
        //
        // TODO: We need a way to disable this check (or move it elsewhere) when we add support
        //       for stateful NAT.
        if as_range_sizes > 0 && ips_sizes - nots_sizes != as_range_sizes - not_as_sizes {
            return Err(ConfigError::MismatchedPrefixSizes(
                ips_sizes - nots_sizes,
                as_range_sizes - not_as_sizes,
            ));
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct VpcManifest {
    pub name: String, /* key: name of vpc */
    pub exposes: Vec<VpcExpose>,
}
impl VpcManifest {
    pub fn new(vpc_name: &str) -> Self {
        Self {
            name: vpc_name.to_owned(),
            ..Default::default()
        }
    }
    fn validate_expose_collisions(&self) -> ConfigResult {
        // Check that prefixes in each expose don't overlap with prefixes in other exposes
        for (index, expose_left) in self.exposes.iter().enumerate() {
            // Loop over the remaining exposes in the list
            for expose_right in self.exposes.iter().skip(index + 1) {
                validate_overlapping(
                    &expose_left.ips,
                    &expose_left.nots,
                    &expose_right.ips,
                    &expose_right.nots,
                )?;
                validate_overlapping(
                    &expose_left.as_range,
                    &expose_left.not_as,
                    &expose_right.as_range,
                    &expose_right.not_as,
                )?;
            }
        }
        Ok(())
    }
    pub fn add_expose(&mut self, expose: VpcExpose) -> ConfigResult {
        self.exposes.push(expose);
        Ok(())
    }
    pub fn validate(&self) -> ConfigResult {
        if self.name.is_empty() {
            return Err(ConfigError::MissingIdentifier("Manifest name"));
        }
        if self.exposes.is_empty() {
            return Err(ConfigError::IncompleteConfig("Empty manifest".to_string()));
        }
        for expose in &self.exposes {
            expose.validate()?;
        }
        self.validate_expose_collisions()?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct VpcPeering {
    pub name: String,       /* name of peering (key in table) */
    pub left: VpcManifest,  /* manifest for one side of the peering */
    pub right: VpcManifest, /* manifest for the other side */
}
impl VpcPeering {
    pub fn new(name: &str, left: VpcManifest, right: VpcManifest) -> Self {
        Self {
            name: name.to_owned(),
            left,
            right,
        }
    }
    pub fn validate(&self) -> ConfigResult {
        if self.name.is_empty() {
            return Err(ConfigError::MissingIdentifier("Peering name"));
        }
        self.left.validate()?;
        self.right.validate()?;
        Ok(())
    }
    /// Given a peering fetch the manifests, orderly depending on the provided vpc name
    pub fn get_peering_manifests(&self, vpc: &str) -> (&VpcManifest, &VpcManifest) {
        if self.left.name == vpc {
            (&self.left, &self.right)
        } else {
            (&self.right, &self.left)
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct VpcPeeringTable(BTreeMap<String, VpcPeering>);
impl VpcPeeringTable {
    /// Create a new, empty [`VpcPeeringTable`]
    pub fn new() -> Self {
        Self::default()
    }
    /// Number of peerings in [`VpcPeeringTable`]
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Tells if [`VpcPeeringTable`] contains peerings or not
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Add a [`VpcPeering`] to a [`VpcPeeringTable`]
    pub fn add(&mut self, peering: VpcPeering) -> ConfigResult {
        peering.validate()?;

        // First look for an existing entry, to avoid inserting a duplicate peering
        if self.0.contains_key(&peering.name) {
            return Err(ConfigError::DuplicateVpcPeeringId(peering.name.clone()));
        }

        if self.0.insert(peering.name.to_owned(), peering).is_some() {
            // We should have prevented this case by checking for duplicates just above.
            // This should never happen, unless we have another thread modifying the table.
            unreachable!()
        } else {
            Ok(())
        }
    }
    /// Iterate over all [`VpcPeering`]s in a [`VpcPeeringTable`]
    pub fn values(&self) -> impl Iterator<Item = &VpcPeering> {
        self.0.values()
    }
    /// Produce iterator of [`VpcPeering`]s that involve the vpc with the provided name
    pub fn peerings_vpc(&self, vpc: &str) -> impl Iterator<Item = &VpcPeering> {
        self.0
            .values()
            .filter(move |p| p.left.name == vpc || p.right.name == vpc)
    }
}

// Validate that two sets of prefixes, with their exclusion prefixes applied, don't overlap
fn validate_overlapping(
    prefixes_left: &BTreeSet<Prefix>,
    excludes_left: &BTreeSet<Prefix>,
    prefixes_right: &BTreeSet<Prefix>,
    excludes_right: &BTreeSet<Prefix>,
) -> Result<(), ConfigError> {
    // Find colliding prefixes
    let mut colliding = Vec::new();
    for prefix_left in prefixes_left.iter() {
        for prefix_right in prefixes_right.iter() {
            if prefix_left.covers(prefix_right) || prefix_right.covers(prefix_left) {
                colliding.push((prefix_left.clone(), prefix_right.clone()));
            }
        }
    }
    // If not prefixes collide, we're good - exit.
    if colliding.is_empty() {
        return Ok(());
    }

    // How do we determine whether there is a collision between the set of available addresses on
    // the left side, and the set of available addresses on the right side? A collision means:
    //
    // - Prefixes collide, in other words, they have a non-empty intersection (we've checked that
    //   earlier)
    //
    // - This intersection is not fully covered by exclusion prefixes
    //
    // The idea in the loop below is that for each pair of colliding prefixes:
    //
    // - We retrieve the size of the intersection of the colliding prefixes. This is easy, because
    //   they're "prefixes", so if they collide we have necessarily one that is contained within the
    //   other, and the size of the intersection is the size of the smallest one.
    //
    // - We retrieve the size of the union of all the exclusion prefixes (from left and right sides)
    //   covering part of this intersection (which we know is the smallest of the two colliding
    //   prefixes). The union of the exclusion prefixes is the set of non-overlapping exclusion
    //   prefixes that cover the intersection of allowed prefixes, such that if exclusion prefixes
    //   collide, we always keep the largest prefix.
    //
    // - If the size of the intersection of colliding allowed prefixes is bigger than the size of
    //   the union of the exclusion prefixes applying to them, then it needs that some addresses are
    //   effectively allowed in both the left-side and the right-side set of available addresses,
    //   and this is an error. If the sizes are identical, then all addresses in the intersection of
    //   the prefixes are excluded on at least one side, so it's all good.
    for (prefix_left, prefix_right) in colliding {
        // If prefixes collide, there's necessarily one prefix that is contained inside of the
        // other. Find the intersection of the two colliding prefixes, which is the smallest of the
        // two prefixes.
        let intersection_prefix = if prefix_left.covers(&prefix_right) {
            &prefix_right
        } else {
            &prefix_left
        };

        // Retrieve the union of all exclusion prefixes covering the intersection of the colliding
        // prefixes
        let mut union_excludes = BTreeSet::new();

        // Consider exclusion prefixes from excludes_left
        'outer: for exclude_left in excludes_left.iter().filter(|exclude| {
            exclude.covers(intersection_prefix) || intersection_prefix.covers(exclude)
        }) {
            for exclude_right in excludes_right.iter().filter(|exclude| {
                exclude.covers(intersection_prefix) || intersection_prefix.covers(exclude)
            }) {
                if exclude_left.covers(exclude_right) {
                    // exclude_left contains exclude_right, and given that exclusion prefixes in
                    // list excludes_right don't overlap there's no exclusion prefix containing
                    // exclude_left. We want to keep exclude_left as part of the union.
                    union_excludes.insert(exclude_left.clone());
                    continue 'outer;
                } else if exclude_right.covers(exclude_left) {
                    // exclude_left is contained within exclude_right, don't keep it as part of the
                    // union. Process next exclusion prefix from list excludes_left.
                    continue 'outer;
                }
            }
            // No collision for this exclude_left, add it to the union
            union_excludes.insert(exclude_left.clone());
        }
        // Consider exclusion prefixes from excludes_right
        'outer: for exclude_right in excludes_right.iter().filter(|exclude| {
            exclude.covers(intersection_prefix) || intersection_prefix.covers(exclude)
        }) {
            for exclude_left in excludes_left.iter().filter(|exclude| {
                exclude.covers(intersection_prefix) || intersection_prefix.covers(exclude)
            }) {
                if exclude_right.covers(exclude_left) {
                    // exclude_right contains exclude_left, and given that exclusions prefixes in
                    // list excludes_left don't overlap there's no exclusion prefix containing
                    // exclude_right. We want to keep exclude_right as part of the union.
                    union_excludes.insert(exclude_right.clone());
                    continue 'outer;
                } else if exclude_left.covers(exclude_right) {
                    // exclude_right is contained within exclude_left, don't keep it as part of the
                    // union. Process next exclusion prefix from list excludes_right.
                    continue 'outer;
                }
            }
            // No collision for this exclude_right, add it to the union
            union_excludes.insert(exclude_right.clone());
        }

        let union_size = union_excludes
            .iter()
            .map(|exclude| exclude.size())
            .sum::<u128>();
        if union_size < intersection_prefix.size() {
            // Some addresses at the intersection of both prefixes are not covered by the union of
            // all exclusion prefixes, in other words, they are available from both prefixes. This
            // is an error.
            return Err(ConfigError::OverlappingPrefixes(prefix_left, prefix_right));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iptrie::{Ipv4Prefix, Ipv6Prefix};
    use std::str::FromStr;

    fn prefix_v4(s: &str) -> Prefix {
        Ipv4Prefix::from_str(s).expect("Invalid IPv4 prefix").into()
    }

    fn prefix_v6(s: &str) -> Prefix {
        Ipv6Prefix::from_str(s).expect("Invalid IPv6 prefix").into()
    }

    #[test]
    fn test_manifest_expose() {
        let expose1 = VpcExpose::empty()
            .ip(prefix_v4("1.1.0.0/16"))
            .not(prefix_v4("1.1.5.0/24"))
            .not(prefix_v4("1.1.3.0/24"))
            .not(prefix_v4("1.1.1.0/24"))
            .ip(prefix_v4("1.2.0.0/16"))
            .not(prefix_v4("1.2.2.0/24"))
            .as_range(prefix_v4("2.2.0.0/16"))
            .not_as(prefix_v4("2.1.10.0/24"))
            .not_as(prefix_v4("2.1.1.0/24"))
            .not_as(prefix_v4("2.1.8.0/24"))
            .not_as(prefix_v4("2.1.2.0/24"))
            .as_range(prefix_v4("2.1.0.0/16"));
        let expose2 = VpcExpose::empty()
            .ip(prefix_v4("3.0.0.0/16"))
            .as_range(prefix_v4("4.0.0.0/16"));

        let mut manifest1 = VpcManifest::new("test_manifest1");
        manifest1.add_expose(expose1).expect("Failed to add expose");
        manifest1.add_expose(expose2).expect("Failed to add expose");

        let expose3 = VpcExpose::empty()
            .ip(prefix_v4("8.0.0.0/17"))
            .not(prefix_v4("8.0.0.0/24"))
            .ip(prefix_v4("9.0.0.0/17"))
            .as_range(prefix_v4("3.0.0.0/16"))
            .not_as(prefix_v4("3.0.1.0/24"));
        let expose4 = VpcExpose::empty()
            .ip(prefix_v4("10.0.0.0/16"))
            .not(prefix_v4("10.0.1.0/24"))
            .not(prefix_v4("10.0.2.0/24"))
            .as_range(prefix_v4("1.1.0.0/17"))
            .as_range(prefix_v4("1.2.0.0/17"))
            .not_as(prefix_v4("1.2.0.0/24"))
            .not_as(prefix_v4("1.2.8.0/24"));

        let mut manifest2 = VpcManifest::new("test_manifest2");
        manifest2.add_expose(expose3).expect("Failed to add expose");
        manifest2.add_expose(expose4).expect("Failed to add expose");

        let peering = VpcPeering::new("test_peering", manifest1.clone(), manifest2.clone());

        assert_eq!(
            peering.get_peering_manifests("test_manifest1"),
            (&manifest1, &manifest2)
        );
    }

    #[test]
    fn test_validate_expose() {
        let test_data = [
            (VpcExpose::empty(), Ok(())),
            (VpcExpose::empty().ip(prefix_v4("10.0.0.0/16")), Ok(())),
            (VpcExpose::empty().not(prefix_v4("10.0.1.0/24")), Ok(())),
            (VpcExpose::empty().not_as(prefix_v4("2.0.1.0/24")), Ok(())),
            (
                VpcExpose::empty()
                    .ip(prefix_v4("10.0.0.0/16"))
                    .as_range(prefix_v4("2.0.0.0/16")),
                Ok(()),
            ),
            (
                VpcExpose::empty()
                    .ip(prefix_v4("10.0.0.0/16"))
                    .as_range(prefix_v4("2.0.0.0/16")),
                Ok(()),
            ),
            (
                VpcExpose::empty()
                    .ip(prefix_v4("10.0.0.0/16"))
                    .not(prefix_v4("10.0.0.0/24"))
                    .as_range(prefix_v4("2.0.0.0/16"))
                    .not_as(prefix_v4("2.0.0.0/24")),
                Ok(()),
            ),
            (
                VpcExpose::empty()
                    .ip(prefix_v6("1::/64"))
                    .as_range(prefix_v6("2::/64")),
                Ok(()),
            ),
            (
                VpcExpose::empty()
                    .not(prefix_v4("10.0.0.0/16"))
                    .not_as(prefix_v4("2.0.0.0/16")),
                Ok(()),
            ),
            // Incorrect: Mixed IP versions
            (
                VpcExpose::empty()
                    .ip(prefix_v4("10.0.0.0/16"))
                    .ip(prefix_v6("1::/64"))
                    .as_range(prefix_v4("2.0.0.0/16"))
                    .as_range(prefix_v6("2::/64")),
                Err(ConfigError::InconsistentIpVersion(
                    VpcExpose::empty()
                        .ip(prefix_v4("10.0.0.0/16"))
                        .ip(prefix_v6("1::/64"))
                        .as_range(prefix_v4("2.0.0.0/16"))
                        .as_range(prefix_v6("2::/64")),
                )),
            ),
            // Incorrect: Mixed IP versions
            (
                VpcExpose::empty()
                    .ip(prefix_v4("10.0.0.0/16"))
                    .as_range(prefix_v6("1::/112")),
                Err(ConfigError::InconsistentIpVersion(
                    VpcExpose::empty()
                        .ip(prefix_v4("10.0.0.0/16"))
                        .as_range(prefix_v6("1::/112")),
                )),
            ),
            // Incorrect: Mixed IP versions
            (
                VpcExpose::empty()
                    .ip(prefix_v4("10.0.0.0/16"))
                    .not(prefix_v6("1::/64"))
                    .as_range(prefix_v4("2.0.0.0/16"))
                    .not_as(prefix_v6("2::/64")),
                Err(ConfigError::InconsistentIpVersion(
                    VpcExpose::empty()
                        .ip(prefix_v4("10.0.0.0/16"))
                        .not(prefix_v6("1::/64"))
                        .as_range(prefix_v4("2.0.0.0/16"))
                        .not_as(prefix_v6("2::/64")),
                )),
            ),
            // Incorrect: prefix overlapping
            (
                VpcExpose::empty()
                    .ip(prefix_v4("10.0.0.0/16"))
                    .ip(prefix_v4("10.0.0.0/17"))
                    .as_range(prefix_v4("2.0.0.0/16"))
                    .as_range(prefix_v4("3.0.0.0/17")),
                Err(ConfigError::OverlappingPrefixes(
                    prefix_v4("10.0.0.0/16"),
                    prefix_v4("10.0.0.0/17"),
                )),
            ),
            // Incorrect: out-of-range exclusion prefix
            (
                VpcExpose::empty()
                    .ip(prefix_v4("10.0.0.0/16"))
                    .not(prefix_v4("8.0.0.0/24"))
                    .as_range(prefix_v4("2.0.0.0/16"))
                    .not_as(prefix_v4("2.0.1.0/24")),
                Err(ConfigError::OutOfRangeExclusionPrefix(prefix_v4(
                    "8.0.0.0/24",
                ))),
            ),
            // Incorrect: all prefixes excluded
            (
                VpcExpose::empty()
                    .ip(prefix_v4("10.0.0.0/16"))
                    .not(prefix_v4("10.0.0.0/17"))
                    .not(prefix_v4("10.0.128.0/17"))
                    .as_range(prefix_v4("2.0.0.0/16"))
                    .not_as(prefix_v4("2.0.0.0/17"))
                    .not_as(prefix_v4("2.0.128.0/17")),
                Err(ConfigError::ExcludedAllPrefixes(
                    VpcExpose::empty()
                        .ip(prefix_v4("10.0.0.0/16"))
                        .not(prefix_v4("10.0.0.0/17"))
                        .not(prefix_v4("10.0.128.0/17"))
                        .as_range(prefix_v4("2.0.0.0/16"))
                        .not_as(prefix_v4("2.0.0.0/17"))
                        .not_as(prefix_v4("2.0.128.0/17")),
                )),
            ),
            // Incorrect: mismatched prefix lists sizes
            (
                VpcExpose::empty()
                    .ip(prefix_v4("10.0.0.0/16"))
                    .not(prefix_v4("10.0.1.0/24"))
                    .as_range(prefix_v4("2.0.0.0/24")),
                Err(ConfigError::MismatchedPrefixSizes(65536 - 256, 256)),
            ),
        ];

        for (index, (expose, expected)) in test_data.iter().enumerate() {
            println!("Test case {index}, expose: {expose:?}");
            assert_eq!(expose.validate(), *expected);
        }
    }

    #[test]
    fn test_validate_peering() {
        let mut manifest1 = VpcManifest::new("test_manifest1");
        manifest1
            .add_expose(
                VpcExpose::empty()
                    .ip(prefix_v4("10.0.0.0/16"))
                    .as_range(prefix_v4("2.0.0.0/16")),
            )
            .expect("Failed to add expose");
        let mut manifest2 = VpcManifest::new("test_manifest2");
        manifest2
            .add_expose(
                VpcExpose::empty()
                    .ip(prefix_v4("192.168.1.0/24"))
                    .as_range(prefix_v4("192.168.8.0/24")),
            )
            .expect("Failed to add expose");
        let peering = VpcPeering::new("test_peering", manifest1.clone(), manifest2.clone());
        assert_eq!(peering.validate(), Ok(()));
        assert_eq!(peering.name, "test_peering");
        assert_eq!(peering.left.name, "test_manifest1");
        assert_eq!(peering.right.name, "test_manifest2");

        // Incorrect: Missing peering name
        let peering = VpcPeering::new("", manifest1.clone(), manifest2.clone());
        assert_eq!(
            peering.validate(),
            Err(ConfigError::MissingIdentifier("Peering name"))
        );
    }

    #[test]
    fn test_peering_table_add() {
        let mut manifest1 = VpcManifest::new("VPC-1");
        manifest1
            .add_expose(
                VpcExpose::empty()
                    .ip(prefix_v4("10.0.0.0/16"))
                    .as_range(prefix_v4("2.0.0.0/16")),
            )
            .expect("Failed to add expose");
        let mut manifest2 = VpcManifest::new("VPC-2");
        manifest2
            .add_expose(
                VpcExpose::empty()
                    .ip(prefix_v4("192.168.1.0/24"))
                    .as_range(prefix_v4("192.168.8.0/24")),
            )
            .expect("Failed to add expose");
        let mut table = VpcPeeringTable::new();
        let peering = VpcPeering::new("test_peering1", manifest1.clone(), manifest2.clone());
        assert_eq!(table.add(peering.clone()), Ok(()));
        assert_eq!(table.len(), 1);

        // Incorrect: Duplicate peering name
        let mut manifest3 = VpcManifest::new("VPC-3");
        manifest3
            .add_expose(
                VpcExpose::empty()
                    .ip(prefix_v4("3.0.0.0/16"))
                    .as_range(prefix_v4("4.0.0.0/16")),
            )
            .expect("Failed to add expose");
        let mut manifest4 = VpcManifest::new("VPC-4");
        manifest4
            .add_expose(
                VpcExpose::empty()
                    .ip(prefix_v4("5.0.0.0/16"))
                    .as_range(prefix_v4("6.0.0.0/16")),
            )
            .expect("Failed to add expose");

        let peering3 = VpcPeering::new("test_peering1", manifest3.clone(), manifest4.clone());
        assert_eq!(
            table.add(peering3),
            Err(ConfigError::DuplicateVpcPeeringId(
                "test_peering1".to_string()
            ))
        );

        let peering4 = VpcPeering::new("test_peering4", manifest3.clone(), manifest4.clone());
        assert_eq!(table.add(peering4), Ok(()));
        assert_eq!(table.len(), 2);
    }
}
