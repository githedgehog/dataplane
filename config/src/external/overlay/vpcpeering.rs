// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: vpc peering

use crate::utils::{
    check_no_overlap_or_left_contains_right, check_private_prefixes_dont_overlap,
    check_public_prefixes_dont_overlap,
};
use lpm::prefix::{IpRangeWithPorts, Prefix, PrefixWithOptionalPorts, PrefixWithPortsSize};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound::{Excluded, Unbounded};
use std::time::Duration;

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

#[derive(Clone, Debug, Default, PartialEq)]
pub struct VpcExposePortForwarding;

#[derive(Clone, Debug, PartialEq)]
pub enum VpcExposeNatConfig {
    Stateful(VpcExposeStatefulNat),
    Stateless(VpcExposeStatelessNat),
    PortForwarding(VpcExposePortForwarding),
}

impl Default for VpcExposeNatConfig {
    fn default() -> Self {
        #[allow(clippy::default_constructed_unit_structs)]
        VpcExposeNatConfig::Stateless(VpcExposeStatelessNat::default())
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct VpcExposeNat {
    pub as_range: BTreeSet<PrefixWithOptionalPorts>,
    pub not_as: BTreeSet<PrefixWithOptionalPorts>,
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

    #[must_use]
    pub fn is_port_forwarding(&self) -> bool {
        matches!(self.config, VpcExposeNatConfig::PortForwarding(_))
    }
}

fn empty_btreeset() -> &'static BTreeSet<PrefixWithOptionalPorts> {
    static EMPTY_SET: std::sync::LazyLock<BTreeSet<PrefixWithOptionalPorts>> =
        std::sync::LazyLock::new(BTreeSet::new);
    &EMPTY_SET
}

use crate::{ConfigError, ConfigResult};
#[derive(Clone, Debug, Default, PartialEq)]
pub struct VpcExpose {
    pub default: bool,
    pub ips: BTreeSet<PrefixWithOptionalPorts>,
    pub nots: BTreeSet<PrefixWithOptionalPorts>,
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
    // Returns an error if the [`VpcExpose`] already has a different NAT mode.
    pub fn make_stateless_nat(mut self) -> Result<Self, ConfigError> {
        match self.nat.as_mut() {
            Some(nat) if nat.is_stateless() => Ok(self),
            Some(_) => Err(ConfigError::Invalid(format!(
                "refusing to overwrite previous NAT mode with stateless NAT mode for VpcExpose {self}"
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
    // Returns an error if the [`VpcExpose`] already has a different NAT mode.
    pub fn make_stateful_nat(
        mut self,
        idle_timeout: Option<Duration>,
    ) -> Result<Self, ConfigError> {
        let options = idle_timeout
            .map(|to| VpcExposeStatefulNat { idle_timeout: to })
            .unwrap_or_default();
        match self.nat.as_mut() {
            Some(nat) if nat.is_stateful() => {
                nat.config = VpcExposeNatConfig::Stateful(options);
                Ok(self)
            }
            Some(_) => Err(ConfigError::Invalid(format!(
                "refusing to overwrite previous NAT mode with stateful NAT mode for VpcExpose {self}"
            ))),

            None => {
                self.nat = Some(VpcExposeNat {
                    config: VpcExposeNatConfig::Stateful(options),
                    ..VpcExposeNat::default()
                });
                Ok(self)
            }
        }
    }

    // Make the [`VpcExpose`] use port forwarding.
    //
    // # Errors
    //
    // Returns an error if the [`VpcExpose`] already has a different NAT mode.
    pub fn make_port_forwarding(mut self) -> Result<Self, ConfigError> {
        match self.nat.as_mut() {
            Some(nat) if nat.is_port_forwarding() => Ok(self),
            Some(_) => Err(ConfigError::Invalid(format!(
                "refusing to overwrite previous NAT mode with port forwarding for VpcExpose {self}"
            ))),
            None => {
                self.nat = Some(VpcExposeNat {
                    config: VpcExposeNatConfig::PortForwarding(VpcExposePortForwarding {}),
                    ..VpcExposeNat::default()
                });
                Ok(self)
            }
        }
    }

    #[must_use]
    pub fn idle_timeout(&self) -> Option<Duration> {
        self.nat.as_ref().and_then(|nat| {
            if let VpcExposeNatConfig::Stateful(config) = &nat.config {
                Some(config.idle_timeout)
            } else {
                None
            }
        })
    }

    #[must_use]
    pub fn as_range_or_empty(&self) -> &BTreeSet<PrefixWithOptionalPorts> {
        self.nat
            .as_ref()
            .map_or(empty_btreeset(), |nat| &nat.as_range)
    }

    #[must_use]
    pub fn not_as_or_empty(&self) -> &BTreeSet<PrefixWithOptionalPorts> {
        self.nat
            .as_ref()
            .map_or(empty_btreeset(), |nat| &nat.not_as)
    }

    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }
    #[must_use]
    pub fn set_default(mut self) -> Self {
        self.default = true;
        self
    }
    #[must_use]
    pub fn ip(mut self, prefix: PrefixWithOptionalPorts) -> Self {
        self.ips.insert(prefix);
        self
    }
    // If the as_range list is empty, then there's no NAT required for the expose, meaning that the
    // public IPs are those from the "ips" list. This method extends the list of public prefixes,
    // whether it's "ips" or "as_range".
    #[must_use]
    pub fn insert_public_ip(mut self, prefix: PrefixWithOptionalPorts) -> Self {
        if let Some(nat) = self.nat.as_mut()
            && !nat.as_range.is_empty()
        {
            nat.as_range.insert(prefix);
        } else {
            self.ips.insert(prefix);
        }
        self
    }
    #[must_use]
    pub fn not(mut self, prefix: PrefixWithOptionalPorts) -> Self {
        self.nots.insert(prefix);
        self
    }
    #[must_use]
    pub fn as_range(self, prefix: PrefixWithOptionalPorts) -> Self {
        let mut ret = self.make_nat();
        let Some(nat) = ret.nat.as_mut() else {
            unreachable!()
        };
        nat.as_range.insert(prefix);
        ret
    }
    #[must_use]
    pub fn not_as(self, prefix: PrefixWithOptionalPorts) -> Self {
        let mut ret = self.make_nat();
        let Some(nat) = ret.nat.as_mut() else {
            unreachable!()
        };
        nat.not_as.insert(prefix);
        ret
    }
    #[must_use]
    pub fn has_host_prefixes(&self) -> bool {
        self.ips.iter().any(|p| p.prefix().is_host())
    }

    /// The prefixes of an expose to be advertised to a remote peer
    #[must_use]
    pub fn adv_prefixes(&self) -> Vec<Prefix> {
        if self.default {
            // only V4 atm
            vec![Prefix::root_v4()]
        } else if let Some(nat) = self.nat.as_ref() {
            nat.as_range.iter().map(|p| p.prefix()).collect::<Vec<_>>()
        } else {
            self.ips.iter().map(|p| p.prefix()).collect::<Vec<_>>()
        }
    }

    // If the as_range list is empty, then there's no NAT required for the expose, meaning that the
    // public IPs are those from the "ips" list. This method returns the current list of public IPs
    // for the VpcExpose.
    #[must_use]
    pub fn public_ips(&self) -> &BTreeSet<PrefixWithOptionalPorts> {
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
    pub fn public_excludes(&self) -> &BTreeSet<PrefixWithOptionalPorts> {
        let Some(nat) = self.nat.as_ref() else {
            return &self.nots;
        };
        if nat.as_range.is_empty() {
            &self.nots
        } else {
            &nat.not_as
        }
    }
    // This method returns true if the list of allowed prefixes is IPv4.
    // This method assumes that all prefixes the list are of the same IP version. It does not
    // validate the list for consistency.
    #[must_use]
    pub fn is_v4(&self) -> bool {
        self.ips.first().is_some_and(|p| p.prefix().is_ipv4())
    }
    // This method returns true if the list of allowed prefixes is IPv6.
    // This method assumes that all prefixes the list are of the same IP version. It does not
    // validate the list for consistency.
    #[must_use]
    pub fn is_v6(&self) -> bool {
        self.ips.first().is_some_and(|p| p.prefix().is_ipv6())
    }
    // This method returns true if both allowed and translated prefixes are IPv4.
    // This method assumes that all prefixes in each list are of the same IP version. It does not
    // validate the list for consistency.
    #[must_use]
    pub fn is_44(&self) -> bool {
        matches!(
            (
                self.ips.first().map(PrefixWithOptionalPorts::prefix),
                self.as_range_or_empty()
                    .first()
                    .map(PrefixWithOptionalPorts::prefix)
            ),
            (Some(Prefix::IPV4(_)), Some(Prefix::IPV4(_)))
        )
    }
    // This method returns true if both allowed and translated prefixes are IPv6.
    // This method assumes that all prefixes in each list are of the same IP version. It does not
    // validate the list for consistency.
    #[must_use]
    pub fn is_66(&self) -> bool {
        matches!(
            (
                self.ips.first().map(PrefixWithOptionalPorts::prefix),
                self.as_range_or_empty()
                    .first()
                    .map(PrefixWithOptionalPorts::prefix)
            ),
            (Some(Prefix::IPV6(_)), Some(Prefix::IPV6(_)))
        )
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

    pub fn has_port_forwarding(&self) -> bool {
        self.nat
            .as_ref()
            .is_some_and(VpcExposeNat::is_port_forwarding)
    }

    #[must_use]
    pub fn nat_config(&self) -> Option<&VpcExposeNatConfig> {
        self.nat.as_ref().map(|nat| &nat.config)
    }

    fn validate_default_expose(&self) -> ConfigResult {
        if self.default {
            if !self.ips.is_empty() || !self.nots.is_empty() || self.nat.is_some() {
                return Err(ConfigError::Invalid(
                    "Default expose cannot have ips/nots or nat configuration".to_string(),
                ));
            }
        } else {
            if self.ips.iter().any(|p| p.prefix().is_root()) {
                return Err(ConfigError::Forbidden(
                    "Expose: root prefix as 'ip' forbidden",
                ));
            }
            if self.nots.iter().any(|p| p.prefix().is_root()) {
                return Err(ConfigError::Forbidden(
                    "Expose: root prefix as 'not' is forbidden",
                ));
            }
            if let Some(nat) = &self.nat {
                if nat.as_range.iter().any(|p| p.prefix().is_root()) {
                    return Err(ConfigError::Forbidden(
                        "Expose: root prefix as NAT 'as' is forbidden",
                    ));
                }
                if nat.not_as.iter().any(|p| p.prefix().is_root()) {
                    return Err(ConfigError::Forbidden(
                        "Expose: root prefix as NAT 'as-not' is forbidden",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Validate the [`VpcExpose`]:
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> ConfigResult {
        // Check default exposes and prefixes
        self.validate_default_expose()?;

        // Static NAT: Check that all prefixes in a list are of the same IP version, as we don't
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
                    p.prefix().is_ipv4() != is_ipv4
                } else {
                    is_ipv4_opt = Some(p.prefix().is_ipv4());
                    false
                }
            }) {
                return Err(ConfigError::InconsistentIpVersion(Box::new(self.clone())));
            }
        }

        // Check that items in prefix lists of each kind don't overlap
        for prefixes in prefix_sets {
            for prefix_with_ports in prefixes {
                // Loop over the remaining prefixes in the tree
                for other_prefix in prefixes.range((Excluded(prefix_with_ports), Unbounded)) {
                    if prefix_with_ports.overlaps(other_prefix)
                        || other_prefix.overlaps(prefix_with_ports)
                    {
                        return Err(ConfigError::OverlappingPrefixes(
                            *prefix_with_ports,
                            *other_prefix,
                        ));
                    }
                }
            }
        }

        // Ensure all exclusion prefixes are contained within existing allowed prefixes, unless the
        // list of allowed prefixes is empty.
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
        fn prefixes_size(prefixes: &BTreeSet<PrefixWithOptionalPorts>) -> PrefixWithPortsSize {
            prefixes
                .iter()
                .map(|p| p.size())
                .sum::<PrefixWithPortsSize>()
        }
        let zero_size = PrefixWithPortsSize::from(0u8);

        // Ensure we don't exclude all of the allowed prefixes
        let ips_sizes = prefixes_size(&self.ips);
        let nots_sizes = prefixes_size(&self.nots);
        if ips_sizes > zero_size && ips_sizes <= nots_sizes {
            return Err(ConfigError::ExcludedAllPrefixes(Box::new(self.clone())));
        }
        let as_range_sizes = prefixes_size(self.as_range_or_empty());
        let not_as_sizes = prefixes_size(self.not_as_or_empty());

        if as_range_sizes > zero_size && as_range_sizes <= not_as_sizes {
            return Err(ConfigError::ExcludedAllPrefixes(Box::new(self.clone())));
        }

        // For static NAT, ensure that, if the list of publicly-exposed addresses is not empty, then
        // we have the same number of addresses on each side.
        //
        // Note: We shouldn't have subtraction overflows because we check that exclusion prefixes
        // size was smaller than allowed prefixes size already.
        if self.has_stateless_nat()
            && as_range_sizes > zero_size
            && ips_sizes - nots_sizes != as_range_sizes - not_as_sizes
        {
            return Err(ConfigError::MismatchedPrefixSizes(
                ips_sizes - nots_sizes,
                as_range_sizes - not_as_sizes,
            ));
        }

        // For port forwarding, ensure that:
        // - we have a single prefix on each side (private and public addresses)
        // - we do not use any exclusion prefixes
        // - if the list of publicly-exposed addresses is not empty, then we have the same number of
        //   addresses on each side
        // - the list of associated port ranges also is on the same size on each side
        if self.has_port_forwarding() {
            if self.ips.len() != 1
                || self.as_range_or_empty().len() != 1
                || !self.nots.is_empty()
                || !self.not_as_or_empty().is_empty()
            {
                return Err(ConfigError::Forbidden(
                    "Port forwarding requires a single prefix on each side, no exclusion prefix allowed",
                ));
            }
            if ips_sizes != as_range_sizes {
                return Err(ConfigError::MismatchedPrefixSizes(
                    ips_sizes,
                    as_range_sizes,
                ));
            }
        }

        // For stateful NAT, we don't support port ranges
        if self.has_stateful_nat()
            && (self.ips.iter().any(|p| p.ports().is_some())
                || self.as_range_or_empty().iter().any(|p| p.ports().is_some()))
        {
            return Err(ConfigError::Forbidden(
                "Port ranges are not supported with stateful NAT",
            ));
        }

        // Forbid empty ips list if not is non-empty.
        // Forbid empty as_range list if not_as is non-empty.
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
        self.exposes.iter().any(|expose| expose.has_host_prefixes())
    }
    fn validate_expose_collisions(&self) -> ConfigResult {
        // Check that prefixes in each expose don't overlap with prefixes in other exposes
        for (index, expose_left) in self.exposes.iter().enumerate() {
            // Loop over the remaining exposes in the list
            for expose_right in self.exposes.iter().skip(index + 1) {
                #[allow(clippy::unnested_or_patterns)]
                match (&expose_left.nat_config(), &expose_right.nat_config()) {
                    // Overlap allowed (with conditions)

                    // Port forwarding plus stateful NAT can be used in combination. This is because
                    // both imply a unique direction for opening a connection, so we can use port
                    // forwarding when the request is in the associated direction, and stateful NAT
                    // otherwise.
                    (
                        Some(VpcExposeNatConfig::Stateful { .. }),
                        Some(VpcExposeNatConfig::PortForwarding { .. }),
                    ) => {
                        check_no_overlap_or_left_contains_right(expose_left, expose_right)?;
                    }
                    (
                        Some(VpcExposeNatConfig::PortForwarding { .. }),
                        Some(VpcExposeNatConfig::Stateful { .. }),
                    ) => {
                        check_no_overlap_or_left_contains_right(expose_right, expose_left)?;
                    }

                    // Overlap denied

                    // If using no NAT at all, private prefixes (which are also publicly exposed)
                    // cannot overlap. Compared to the cases with NAT below, checking private and
                    // public prefixes is the same operation, so we only need to do it once.
                    (None, None) => {
                        check_private_prefixes_dont_overlap(expose_left, expose_right)?;
                    }

                    // We do not support stateless NAT in combination with another mode.
                    (Some(VpcExposeNatConfig::Stateless { .. }), _)
                    | (_, Some(VpcExposeNatConfig::Stateless { .. }))
                    // Two exposes using port forwarding must use distinct internal prefixes, or we
                    // don't know which to use.
                    | (
                        Some(VpcExposeNatConfig::PortForwarding { .. }),
                        Some(VpcExposeNatConfig::PortForwarding { .. }),
                    )
                    // Two exposes using stateful NAT must use distinct internal prefixes, or we
                    // don't know which to use.
                    | (
                        Some(VpcExposeNatConfig::Stateful { .. }),
                        Some(VpcExposeNatConfig::Stateful { .. }),
                    )
                    // Stateful NAT cannot be used in combination with no NAT, or we don't know
                    // which prefix to use. Similar to port forwarding plus no NAT, here we could
                    // figure out something based on the direction for stateful NAT (which only
                    // works for source NAT), but this is not supported at the moment, and stateful
                    // NAT might work in both directions in the future anyway.
                    | (Some(VpcExposeNatConfig::Stateful { .. }), None)
                    | (None, Some(VpcExposeNatConfig::Stateful { .. }))
                    // Port forwarding cannot be used in combination with no NAT, because no NAT is
                    // stateless and the flow entry for port forwarding would "mask" the prefix for
                    // use with no NAT
                    | (Some(VpcExposeNatConfig::PortForwarding { .. }), None)
                    | (None, Some(VpcExposeNatConfig::PortForwarding { .. })) => {
                        check_private_prefixes_dont_overlap(expose_left, expose_right)?;
                        check_public_prefixes_dont_overlap(expose_left, expose_right)?;
                    }
                }
            }
        }
        Ok(())
    }
    pub fn add_expose(&mut self, expose: VpcExpose) {
        self.exposes.push(expose);
    }
    pub fn add_exposes(&mut self, exposes: impl IntoIterator<Item = VpcExpose>) {
        self.exposes.extend(exposes);
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
    pub fn stateful_nat_exposes_44(&self) -> impl Iterator<Item = &VpcExpose> {
        self.exposes
            .iter()
            .filter(|expose| expose.has_stateful_nat())
            .filter(|expose| expose.is_44())
    }
    pub fn stateful_nat_exposes_66(&self) -> impl Iterator<Item = &VpcExpose> {
        self.exposes
            .iter()
            .filter(|expose| expose.has_stateful_nat())
            .filter(|expose| expose.is_66())
    }
    pub fn no_stateful_nat_exposes_v4(&self) -> impl Iterator<Item = &VpcExpose> {
        self.exposes
            .iter()
            .filter(|expose| !expose.has_stateful_nat())
            .filter(|expose| expose.is_v4())
    }
    pub fn no_stateful_nat_exposes_v6(&self) -> impl Iterator<Item = &VpcExpose> {
        self.exposes
            .iter()
            .filter(|expose| !expose.has_stateful_nat())
            .filter(|expose| expose.is_v6())
    }
    pub fn port_forwarding_exposes_44(&self) -> impl Iterator<Item = &VpcExpose> {
        self.exposes
            .iter()
            .filter(|expose| expose.has_port_forwarding())
            .filter(|expose| expose.is_44())
    }
    pub fn port_forwarding_exposes_66(&self) -> impl Iterator<Item = &VpcExpose> {
        self.exposes
            .iter()
            .filter(|expose| expose.has_port_forwarding())
            .filter(|expose| expose.is_66())
    }
    pub fn port_forwarding_exposes(&self) -> impl Iterator<Item = &VpcExpose> {
        self.exposes
            .iter()
            .filter(|expose| expose.has_port_forwarding())
    }
    pub fn default_expose(&self) -> Result<Option<&VpcExpose>, ConfigError> {
        let default_exposes: Vec<&VpcExpose> = self
            .exposes
            .iter()
            .filter(|expose| expose.default)
            .collect();
        if default_exposes.len() > 1 {
            return Err(ConfigError::InternalFailure(
                "Multiple default exposes found".to_string(),
            ));
        }
        Ok(default_exposes.first().copied())
    }
}

#[derive(Clone, Debug)]
pub struct VpcPeering {
    pub name: String,            /* name of peering (key in table) */
    pub left: VpcManifest,       /* manifest for one side of the peering */
    pub right: VpcManifest,      /* manifest for the other side */
    pub gwgroup: Option<String>, /* name of gateway group */
}
impl VpcPeering {
    #[must_use]
    pub fn new(name: &str, left: VpcManifest, right: VpcManifest, gwgroup: Option<String>) -> Self {
        Self {
            name: name.to_owned(),
            left,
            right,
            gwgroup,
        }
    }

    /// Create a VpcPeering mapped to a group called "default".
    /// This should only be used for tests
    #[must_use]
    pub fn with_default_group(name: &str, left: VpcManifest, right: VpcManifest) -> Self {
        Self {
            name: name.to_owned(),
            left,
            right,
            gwgroup: Some("default".to_string()),
        }
    }

    #[cfg(test)]
    /// Validate A VpcPeering. Only used in tests. Dataplane validates `Peerings`
    pub fn validate(&self) -> ConfigResult {
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
