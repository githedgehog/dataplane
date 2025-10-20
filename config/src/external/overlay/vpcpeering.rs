// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: vpc peering

use lpm::prefix::{Prefix, PrefixSize};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ops::Bound::{Excluded, Unbounded};
use std::time::Duration;
use tracing::debug;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct VpcExposeStatelessNat;

#[derive(Clone, Debug, PartialEq)]
pub struct VpcExposeStatefulNat {
    pub idle_timeout: Duration,
}

impl Default for VpcExposeStatefulNat {
    fn default() -> Self {
        VpcExposeStatefulNat {
            idle_timeout: Duration::from_secs(120),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum VpcExposeNatConfig {
    Stateful(VpcExposeStatefulNat),
    Stateless(VpcExposeStatelessNat),
}

impl Default for VpcExposeNatConfig {
    fn default() -> Self {
        #[allow(clippy::default_constructed_unit_structs)]
        VpcExposeNatConfig::Stateless(VpcExposeStatelessNat::default())
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct VpcExposeNat {
    pub as_range: BTreeSet<Prefix>,
    pub not_as: BTreeSet<Prefix>,
    pub config: VpcExposeNatConfig,
}

impl VpcExposeNat {
    #[must_use]
    pub fn is_stateful(&self) -> bool {
        matches!(self.config, VpcExposeNatConfig::Stateful(_))
    }

    #[must_use]
    pub fn is_stateless(&self) -> bool {
        matches!(self.config, VpcExposeNatConfig::Stateless(_))
    }
}

fn empty_btreeset() -> &'static BTreeSet<Prefix> {
    static EMPTY_SET: std::sync::LazyLock<BTreeSet<Prefix>> =
        std::sync::LazyLock::new(BTreeSet::new);
    &EMPTY_SET
}

use crate::{ConfigError, ConfigResult};
#[derive(Clone, Debug, Default, PartialEq)]
pub struct VpcExpose {
    pub ips: BTreeSet<Prefix>,
    pub nots: BTreeSet<Prefix>,
    pub nat: Option<VpcExposeNat>,
}
impl VpcExpose {
    #[must_use]
    pub fn make_nat(mut self) -> Self {
        if self.nat.is_none() {
            self.nat = Some(VpcExposeNat::default());
        }
        self
    }

    // Make the [`VpcExpose`] use stateless NAT.
    //
    // # Errors
    //
    // Returns an error if the [`VpcExpose`] is in stateful mode.
    pub fn make_stateless_nat(mut self) -> Result<Self, ConfigError> {
        match self.nat.as_mut() {
            Some(nat) if nat.is_stateless() => Ok(self),
            Some(_) => Err(ConfigError::Invalid(format!(
                "refusing to overwrite stateful NAT mode with stateless NAT mode for VpcExpose {self}"
            ))),
            None => {
                self.nat = Some(VpcExposeNat {
                    config: VpcExposeNatConfig::Stateless(VpcExposeStatelessNat {}),
                    ..VpcExposeNat::default()
                });
                Ok(self)
            }
        }
    }

    // Make the [`VpcExpose`] use stateful NAT, with the given idle timeout, if provided.
    // If the [`VpcExpose`] is already in stateful mode, the idle timeout is overwritten.
    //
    // # Errors
    //
    // Returns an error if the [`VpcExpose`] is in stateless mode.
    pub fn make_stateful_nat(
        mut self,
        idle_timeout: Option<Duration>,
    ) -> Result<Self, ConfigError> {
        match self.nat.as_mut() {
            Some(nat) if nat.is_stateful() => {
                nat.config = VpcExposeNatConfig::Stateful(VpcExposeStatefulNat {
                    idle_timeout: idle_timeout.unwrap_or_default(),
                });
                Ok(self)
            }
            Some(_) => Err(ConfigError::Invalid(format!(
                "refusing to overwrite stateless NAT mode with stateful NAT mode for VpcExpose {self}"
            ))),
            None => {
                self.nat = Some(VpcExposeNat {
                    config: VpcExposeNatConfig::Stateful(VpcExposeStatefulNat {
                        idle_timeout: idle_timeout.unwrap_or_default(),
                    }),
                    ..VpcExposeNat::default()
                });
                Ok(self)
            }
        }
    }

    #[must_use]
    pub fn as_range_or_empty(&self) -> &BTreeSet<Prefix> {
        self.nat
            .as_ref()
            .map_or(empty_btreeset(), |nat| &nat.as_range)
    }

    #[must_use]
    pub fn not_as_or_empty(&self) -> &BTreeSet<Prefix> {
        self.nat
            .as_ref()
            .map_or(empty_btreeset(), |nat| &nat.not_as)
    }

    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }
    #[must_use]
    pub fn ip(mut self, prefix: Prefix) -> Self {
        self.ips.insert(prefix);
        self
    }
    #[must_use]
    pub fn not(mut self, prefix: Prefix) -> Self {
        self.nots.insert(prefix);
        self
    }
    #[must_use]
    pub fn as_range(self, prefix: Prefix) -> Self {
        let mut ret = self.make_nat();
        let Some(nat) = ret.nat.as_mut() else {
            unreachable!()
        };
        nat.as_range.insert(prefix);
        ret
    }
    #[must_use]
    pub fn not_as(self, prefix: Prefix) -> Self {
        let mut ret = self.make_nat();
        let Some(nat) = ret.nat.as_mut() else {
            unreachable!()
        };
        nat.not_as.insert(prefix);
        ret
    }
    #[must_use]
    pub fn has_host_prefixes(&self) -> bool {
        self.ips.iter().filter(|p| p.is_host()).count() > 0
    }
    // If the as_range list is empty, then there's no NAT required for the expose, meaning that the
    // public IPs are those from the "ips" list. This method returns the current list of public IPs
    // for the VpcExpose.
    #[must_use]
    pub fn public_ips(&self) -> &BTreeSet<Prefix> {
        let Some(nat) = self.nat.as_ref() else {
            return &self.ips;
        };
        if nat.as_range.is_empty() {
            &self.ips
        } else {
            &nat.as_range
        }
    }
    // Same as public_ips, but returns the list of excluded prefixes
    #[must_use]
    pub fn public_excludes(&self) -> &BTreeSet<Prefix> {
        let Some(nat) = self.nat.as_ref() else {
            return &self.nots;
        };
        if nat.as_range.is_empty() {
            &self.nots
        } else {
            &nat.not_as
        }
    }
    #[must_use]
    pub fn has_nat(&self) -> bool {
        self.nat
            .as_ref()
            .is_some_and(|nat| !nat.as_range.is_empty())
    }

    pub fn has_stateful_nat(&self) -> bool {
        self.nat.as_ref().is_some_and(VpcExposeNat::is_stateful)
    }

    pub fn has_stateless_nat(&self) -> bool {
        self.nat.as_ref().is_some_and(VpcExposeNat::is_stateless)
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
        let prefix_sets = [
            &self.ips,
            &self.nots,
            self.as_range_or_empty(),
            self.not_as_or_empty(),
        ];
        for prefixes in prefix_sets {
            if prefixes.iter().any(|p| {
                if let Some(is_ipv4) = is_ipv4_opt {
                    p.is_ipv4() != is_ipv4
                } else {
                    is_ipv4_opt = Some(p.is_ipv4());
                    false
                }
            }) {
                return Err(ConfigError::InconsistentIpVersion(Box::new(self.clone())));
            }
        }

        // 2. Check that items in prefix lists of each kind don't overlap
        for prefixes in prefix_sets {
            for prefix in prefixes {
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
        for (prefixes, excludes) in [
            (prefix_sets[0], prefix_sets[1]),
            (prefix_sets[2], prefix_sets[3]),
        ] {
            if prefixes.is_empty() {
                continue;
            }
            for exclude in excludes {
                if !prefixes.iter().any(|p| p.covers(exclude)) {
                    return Err(ConfigError::OutOfRangeExclusionPrefix(*exclude));
                }
            }
        }

        #[allow(clippy::items_after_statements)]
        fn prefixes_size(prefixes: &BTreeSet<Prefix>) -> PrefixSize {
            prefixes.iter().map(|p| p.size()).sum()
        }

        // 4. Ensure we don't exclude all of the allowed prefixes
        let ips_sizes = prefixes_size(&self.ips);
        let nots_sizes = prefixes_size(&self.nots);
        if ips_sizes > 0 && ips_sizes <= nots_sizes {
            return Err(ConfigError::ExcludedAllPrefixes(Box::new(self.clone())));
        }
        let as_range_sizes = prefixes_size(self.as_range_or_empty());
        let not_as_sizes = prefixes_size(self.not_as_or_empty());

        if as_range_sizes > 0 && as_range_sizes <= not_as_sizes {
            return Err(ConfigError::ExcludedAllPrefixes(Box::new(self.clone())));
        }

        // 5. Forbid empty ips list if not is non-empty.
        //    Forbid empty as_range list if not_as is non-empty.
        //    These configurations are allowed by the user API, but we don't currently support them,
        //    so we reject them during validation.
        //    https://github.com/githedgehog/dataplane/issues/650
        if !self.nots.is_empty() && self.ips.is_empty() {
            return Err(ConfigError::Forbidden(
                "Empty 'ips' with non-empty 'nots' is currently not supported",
            ));
        }
        if self.as_range_or_empty().is_empty() && !self.not_as_or_empty().is_empty() {
            return Err(ConfigError::Forbidden(
                "Empty 'as_range' with non-empty 'not_as' is currently not supported",
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
    #[must_use]
    pub fn new(vpc_name: &str) -> Self {
        Self {
            name: vpc_name.to_owned(),
            ..Default::default()
        }
    }
    #[must_use]
    pub fn has_host_prefixes(&self) -> bool {
        self.exposes
            .iter()
            .filter(|expose| expose.has_host_prefixes())
            .count()
            > 0
    }
    fn validate_expose_collisions(&self) -> ConfigResult {
        // Check that prefixes in each expose don't overlap with prefixes in other exposes
        for (index, expose_left) in self.exposes.iter().enumerate() {
            // Loop over the remaining exposes in the list
            for expose_right in self.exposes.iter().skip(index + 1) {
                // Always check for overlap for the lists of private IPs - these are not allowed to
                // overlap inside of a given expose.
                validate_overlapping(
                    &expose_left.ips,
                    &expose_left.nots,
                    &expose_right.ips,
                    &expose_right.nots,
                )?;
                // If any of the expose requires NAT, then check for overlap for the lists of
                // public prefixes. Depending on the case, this can be:
                // - expose_left.as_range / expose_right.as_range
                // - expose_left.ips      / expose_right.as_range
                // - expose_left.as_range / expose_right.ips
                // (along with the respective exclusion prefixes).
                if expose_left.has_nat() || expose_right.has_nat() {
                    validate_overlapping(
                        expose_left.public_ips(),
                        expose_left.public_excludes(),
                        expose_right.public_ips(),
                        expose_right.public_excludes(),
                    )?;
                }
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
        for expose in &self.exposes {
            expose.validate()?;
        }
        self.validate_expose_collisions()?;
        Ok(())
    }
    pub fn stateless_nat_exposes(&self) -> impl Iterator<Item = &VpcExpose> {
        self.exposes
            .iter()
            .filter(|expose| expose.has_stateless_nat())
    }
}

#[derive(Clone, Debug)]
pub struct VpcPeering {
    pub name: String,       /* name of peering (key in table) */
    pub left: VpcManifest,  /* manifest for one side of the peering */
    pub right: VpcManifest, /* manifest for the other side */
}
impl VpcPeering {
    #[must_use]
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
    #[must_use]
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
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Number of peerings in [`VpcPeeringTable`]
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Tells if [`VpcPeeringTable`] contains peerings or not
    #[must_use]
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

        // First look for an existing entry, to avoid inserting a duplicate peering
        if self.0.contains_key(&peering.name) {
            return Err(ConfigError::DuplicateVpcPeeringId(peering.name.clone()));
        }

        if self.0.insert(peering.name.clone(), peering).is_some() {
            // We should have prevented this case by checking for duplicates just above.
            // This should never happen, unless we have another thread modifying the table.
            unreachable!("Unexpected race condition in peering table")
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
    for prefix_left in prefixes_left {
        for prefix_right in prefixes_right {
            if prefix_left.covers(prefix_right) || prefix_right.covers(prefix_left) {
                colliding.push((*prefix_left, *prefix_right));
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
    //   the union of the exclusion prefixes applying to them, then it means that some addresses are
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
                    union_excludes.insert(*exclude_left);
                    continue 'outer;
                } else if exclude_right.covers(exclude_left) {
                    // exclude_left is contained within exclude_right, don't keep it as part of the
                    // union. Process next exclusion prefix from list excludes_left.
                    continue 'outer;
                }
            }
            // No collision for this exclude_left, add it to the union
            union_excludes.insert(*exclude_left);
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
                    union_excludes.insert(*exclude_right);
                    continue 'outer;
                } else if exclude_left.covers(exclude_right) {
                    // exclude_right is contained within exclude_left, don't keep it as part of the
                    // union. Process next exclusion prefix from list excludes_right.
                    continue 'outer;
                }
            }
            // No collision for this exclude_right, add it to the union
            union_excludes.insert(*exclude_right);
        }

        let union_size = union_excludes
            .iter()
            .map(|exclude| exclude.size())
            .sum::<PrefixSize>();

        if union_size < intersection_prefix.size() {
            // Some addresses at the intersection of both prefixes are not covered by the union of
            // all exclusion prefixes, in other words, they are available from both prefixes. This
            // is an error.
            return Err(ConfigError::OverlappingPrefixes(prefix_left, prefix_right));
        }
    }
    Ok(())
}
