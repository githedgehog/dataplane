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
    pub fn add_expose(&mut self, expose: VpcExpose) -> ConfigResult {
        expose.validate()?;
        self.exposes.push(expose);
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
        if let Some(peering) = self.0.insert(peering.name.to_owned(), peering) {
            Err(ConfigError::DuplicateVpcPeeringId(peering.name.clone()))
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
