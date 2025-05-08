// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: vpc peering

use routing::prefix::Prefix;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ops::Bound::{Excluded, Unbounded};
use tracing::debug;

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
                        return Err(ConfigError::OverlappingPrefixes(*prefix, *other_prefix));
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
                    return Err(ConfigError::OutOfRangeExclusionPrefix(*exclude));
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
        self.exposes.push(expose);
        Ok(())
    }
    pub fn validate(&self) -> ConfigResult {
        if self.name.is_empty() {
            return Err(ConfigError::MissingIdentifier("Manifest name"));
        }
        for expose in &self.exposes {
            expose.validate()?;
        }
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
        debug!("Validating VPC peering '{}'...", &self.name);
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
    /// Empty a [`VpcPeeringTable`]
    pub fn clear(&mut self) {
        debug!("Emptying peering table...");
        self.0.clear();
    }
    /// Add a [`VpcPeering`] to a [`VpcPeeringTable`]
    pub fn add(&mut self, peering: VpcPeering) -> ConfigResult {
        if peering.name.is_empty() {
            return Err(ConfigError::MissingIdentifier("Peering name"));
        }
        /* no validations here please, since this gets called directly by the gRPC
        server, which makes logs very confusing */
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
