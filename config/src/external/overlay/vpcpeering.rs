// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: vpc peering

use crate::utils::{
    check_private_prefixes_dont_overlap, check_public_prefixes_dont_overlap, collapse_prefixes,
};
use lpm::prefix::{IpRangeWithPorts, L4Protocol, Prefix, PrefixPortsSet, PrefixWithOptionalPorts};
use std::collections::BTreeMap;
use std::ops::Bound::{Excluded, Unbounded};
use std::time::Duration;
use tracing::warn;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct VpcExposeStatelessNat;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct VpcExposeStatefulNat {
    pub idle_timeout: Option<Duration>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct VpcExposePortForwarding {
    pub idle_timeout: Option<Duration>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum VpcExposeNatConfig {
    Stateful(VpcExposeStatefulNat),
    Stateless(VpcExposeStatelessNat),
    PortForwarding(VpcExposePortForwarding),
}

#[derive(Clone, Debug, PartialEq)]
pub struct VpcExposeNat {
    pub as_range: PrefixPortsSet,
    pub not_as: PrefixPortsSet,
    pub config: VpcExposeNatConfig,
    pub proto: L4Protocol,
}

impl VpcExposeNat {
    #[must_use]
    pub fn from_config(config: VpcExposeNatConfig) -> Self {
        Self {
            as_range: PrefixPortsSet::new(),
            not_as: PrefixPortsSet::new(),
            config,
            proto: L4Protocol::default(),
        }
    }

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

fn empty_set() -> &'static PrefixPortsSet {
    static EMPTY_SET: std::sync::LazyLock<PrefixPortsSet> =
        std::sync::LazyLock::new(PrefixPortsSet::new);
    &EMPTY_SET
}

use crate::{ConfigError, ConfigResult};
#[derive(Clone, Debug, Default, PartialEq)]
pub struct VpcExpose {
    pub default: bool,
    pub ips: PrefixPortsSet,
    pub nots: PrefixPortsSet,
    pub nat: Option<VpcExposeNat>,
}
impl VpcExpose {
    /// Make the [`VpcExpose`] use stateless NAT.
    ///
    /// # Errors
    ///
    /// Returns an error if the [`VpcExpose`] already has a different NAT mode.
    pub fn make_stateless_nat(mut self) -> Result<Self, ConfigError> {
        match self.nat.as_mut() {
            Some(nat) if nat.is_stateless() => Ok(self),
            Some(_) => Err(ConfigError::Invalid(format!(
                "refusing to overwrite previous NAT mode with stateless NAT mode for VpcExpose {self}"
            ))),
            None => {
                self.nat = Some(VpcExposeNat::from_config(VpcExposeNatConfig::Stateless(
                    VpcExposeStatelessNat {},
                )));
                Ok(self)
            }
        }
    }

    /// Make the [`VpcExpose`] use stateful NAT, with the given idle timeout, if provided.
    /// If the [`VpcExpose`] is already in stateful mode, the idle timeout is overwritten.
    ///
    /// # Errors
    ///
    /// Returns an error if the [`VpcExpose`] already has a different NAT mode.
    pub fn make_stateful_nat(
        mut self,
        idle_timeout: Option<Duration>,
    ) -> Result<Self, ConfigError> {
        let options = VpcExposeStatefulNat { idle_timeout };
        match self.nat.as_mut() {
            Some(nat) if nat.is_stateful() => {
                nat.config = VpcExposeNatConfig::Stateful(options);
                Ok(self)
            }
            Some(_) => Err(ConfigError::Invalid(format!(
                "refusing to overwrite previous NAT mode with stateful NAT mode for VpcExpose {self}"
            ))),

            None => {
                self.nat = Some(VpcExposeNat::from_config(VpcExposeNatConfig::Stateful(
                    options,
                )));
                Ok(self)
            }
        }
    }

    /// Make the [`VpcExpose`] use port forwarding, with the given idle timeout, if provided, and the
    /// given L4 protocol, if provided.
    ///
    /// If the [`VpcExpose`] is already in port forwarding mode, the idle timeout and L4 protocol are
    /// overwritten.
    ///
    /// # Errors
    ///
    /// Returns an error if the [`VpcExpose`] already has a different NAT mode.
    pub fn make_port_forwarding(
        mut self,
        idle_timeout: Option<Duration>,
        proto: Option<L4Protocol>,
    ) -> Result<Self, ConfigError> {
        let options = VpcExposePortForwarding { idle_timeout };
        match self.nat.as_mut() {
            Some(nat) if nat.is_port_forwarding() => {
                nat.config = VpcExposeNatConfig::PortForwarding(options);
                if let Some(proto) = proto {
                    nat.proto = proto;
                }
            }
            Some(_) => {
                return Err(ConfigError::Invalid(format!(
                    "refusing to overwrite previous NAT mode with port forwarding for VpcExpose {self}"
                )));
            }
            None => {
                let mut nat =
                    VpcExposeNat::from_config(VpcExposeNatConfig::PortForwarding(options));
                if let Some(proto) = proto {
                    nat.proto = proto;
                }
                self.nat = Some(nat);
            }
        }
        Ok(self)
    }

    fn as_range_or_empty(&self) -> &PrefixPortsSet {
        self.nat.as_ref().map_or(empty_set(), |nat| &nat.as_range)
    }

    fn not_as_or_empty(&self) -> &PrefixPortsSet {
        self.nat.as_ref().map_or(empty_set(), |nat| &nat.not_as)
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
    #[must_use]
    pub fn not(mut self, prefix: PrefixWithOptionalPorts) -> Self {
        self.nots.insert(prefix);
        self
    }
    /// Add a prefix to the NAT `as` range.
    ///
    /// # Errors
    ///
    /// Returns an error if the expose has no NAT configuration.
    pub fn as_range(mut self, prefix: PrefixWithOptionalPorts) -> Result<Self, ConfigError> {
        let nat = self.nat.as_mut().ok_or(ConfigError::MissingParameter(
            "'as' block requires NAT configuration for the expose",
        ))?;
        nat.as_range.insert(prefix);
        Ok(self)
    }
    /// Add a prefix to the NAT `not as` exclusion set.
    ///
    /// # Errors
    ///
    /// Returns an error if the expose has no NAT configuration.
    pub fn not_as(mut self, prefix: PrefixWithOptionalPorts) -> Result<Self, ConfigError> {
        let nat = self.nat.as_mut().ok_or(ConfigError::MissingParameter(
            "'not' prefix for 'as' block requires NAT configuration for the expose",
        ))?;
        nat.not_as.insert(prefix);
        Ok(self)
    }
    #[must_use]
    pub fn has_host_prefixes(&self) -> bool {
        self.ips.iter().any(|p| p.prefix().is_host())
    }

    // If the as_range list is empty, then there's no NAT required for the expose, meaning that the
    // public IPs are those from the "ips" list. This method returns the current list of public IPs
    // for the VpcExpose.
    #[must_use]
    pub fn public_ips(&self) -> &PrefixPortsSet {
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
    pub fn public_excludes(&self) -> &PrefixPortsSet {
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
    pub(crate) fn has_nat(&self) -> bool {
        self.nat
            .as_ref()
            .is_some_and(|nat| !nat.as_range.is_empty())
    }

    pub(crate) fn has_stateless_nat(&self) -> bool {
        self.nat.as_ref().is_some_and(VpcExposeNat::is_stateless)
    }

    #[must_use]
    pub fn nat_config(&self) -> Option<&VpcExposeNatConfig> {
        self.nat.as_ref().map(|nat| &nat.config)
    }

    fn validate_default_expose(&self) -> ConfigResult {
        if self.default && (!self.ips.is_empty() || !self.nots.is_empty() || self.nat.is_some()) {
            return Err(ConfigError::Invalid(
                "Default expose cannot have ips/nots or nat configuration".to_string(),
            ));
        }
        Ok(())
    }

    /// Validate the [`VpcExpose`].
    ///
    /// # Errors
    ///
    /// Returns an error if the expose configuration is invalid.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<ValidatedExpose, ConfigError> {
        // Check default exposes and prefixes
        self.validate_default_expose()?;

        // Forbid empty ips list
        if self.ips.is_empty() && !self.default {
            return Err(ConfigError::Forbidden(
                "Non-default expose cannot have empty 'ips' list",
            ));
        }

        // If NAT is enabled, forbid empty as_range list
        if self.nat.is_some() && self.as_range_or_empty().is_empty() {
            return Err(ConfigError::Forbidden(
                "Expose cannot have empty 'as_range' list with NAT enabled",
            ));
        }

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

        // Port 0 is not allowed in the exposed ranges. We do not check the excluded ranges here,
        // as they are only used to remove prefixes/ports from the effective configuration.
        for prefixes in [&self.ips, self.as_range_or_empty()] {
            for prefix_with_ports in prefixes {
                if let Some(ports) = prefix_with_ports.ports()
                    && ports.start() == 0
                {
                    return Err(ConfigError::Forbidden(
                        "Port 0 is not allowed in expose prefix port ranges",
                    ));
                }
            }
        }

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

        // Warn if any exclusion prefix does not overlap with any allowed prefix.
        for (prefixes, excludes) in [
            (prefix_sets[0], prefix_sets[1]),
            (prefix_sets[2], prefix_sets[3]),
        ] {
            for exclude in excludes {
                if !prefixes.iter().any(|p| p.overlaps(exclude)) {
                    warn!(
                        "Exclusion prefix {exclude} in expose {self} does not overlap with any allowed prefix"
                    );
                }
            }
        }

        // Apply exclusion prefixes
        let mut clone = self.clone();
        collapse_prefixes(&mut clone);
        let collapsed_expose = ValidatedExpose {
            default: clone.default,
            ips: clone.ips,
            nat: clone.nat,
        };

        // Ensure we don't exclude all of the allowed prefixes
        if collapsed_expose.ips().is_empty() && !collapsed_expose.is_default() {
            return Err(ConfigError::ExcludedAllPrefixes(Box::new(self.clone())));
        }
        if collapsed_expose.nat().is_some() && collapsed_expose.as_range_or_empty().is_empty() {
            return Err(ConfigError::ExcludedAllPrefixes(Box::new(self.clone())));
        }

        let ips_sizes = collapsed_expose.ips().total_prefixes_size();
        let as_range_sizes = collapsed_expose.as_range_or_empty().total_prefixes_size();

        // For static NAT, ensure that, if the list of publicly-exposed addresses is not empty, then
        // we have the same number of addresses on each side.
        //
        // Note: We shouldn't have subtraction overflows because we check that exclusion prefixes
        // size was smaller than allowed prefixes size already.
        if collapsed_expose.has_stateless_nat() && ips_sizes != as_range_sizes {
            return Err(ConfigError::MismatchedPrefixSizes(
                ips_sizes,
                as_range_sizes,
            ));
        }

        // For port forwarding, ensure that:
        // - we have no exclusion prefixes (note: we could relax this constraint now that we
        //   collapse exclusion prefixes early)
        // - we have a single prefix on each side (private and public addresses)
        // - we have the same number of addresses on each side
        // - the list of associated port ranges also has the same size on each side
        if collapsed_expose.has_port_forwarding() {
            if !self.nots.is_empty() || !self.not_as_or_empty().is_empty() {
                return Err(ConfigError::Forbidden(
                    "Port forwarding does not support exclusion prefixes",
                ));
            }
            if collapsed_expose.ips().len() != 1 || collapsed_expose.as_range_or_empty().len() != 1
            {
                return Err(ConfigError::Forbidden(
                    "Port forwarding requires a single prefix on each side",
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
        if collapsed_expose.has_stateful_nat()
            && (collapsed_expose.ips().iter().any(|p| p.ports().is_some())
                || collapsed_expose
                    .as_range_or_empty()
                    .iter()
                    .any(|p| p.ports().is_some()))
        {
            return Err(ConfigError::Forbidden(
                "Port ranges are not supported with stateful NAT",
            ));
        }

        Ok(collapsed_expose)
    }

    /// FOR TESTS ONLY
    #[cfg(feature = "testing")]
    #[must_use]
    #[allow(unsafe_code)]
    unsafe fn fake_validated_expose(&self) -> ValidatedExpose {
        ValidatedExpose {
            default: self.default,
            ips: self.ips.clone(),
            nat: self.nat.clone(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ValidatedExpose {
    default: bool,
    ips: PrefixPortsSet,
    nat: Option<VpcExposeNat>,
}

impl ValidatedExpose {
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.default
    }

    #[must_use]
    pub fn ips(&self) -> &PrefixPortsSet {
        &self.ips
    }

    #[must_use]
    pub fn as_range_or_empty(&self) -> &PrefixPortsSet {
        self.nat.as_ref().map_or(empty_set(), |nat| &nat.as_range)
    }

    // If the as_range list is empty, then there's no NAT required for the expose, meaning that the
    // public IPs are those from the "ips" list. This method returns the current list of public IPs
    // for the VpcExpose.
    #[must_use]
    pub fn public_ips(&self) -> &PrefixPortsSet {
        let Some(nat) = self.nat.as_ref() else {
            return &self.ips;
        };
        if nat.as_range.is_empty() {
            &self.ips
        } else {
            &nat.as_range
        }
    }

    /// The prefixes of an expose to be advertised to a remote peer
    #[must_use]
    pub fn adv_prefixes(&self) -> Vec<Prefix> {
        if self.default {
            // only V4 atm
            vec![Prefix::root_v4()]
        } else if let Some(nat) = self.nat.as_ref() {
            nat.as_range
                .iter()
                .map(PrefixWithOptionalPorts::prefix)
                .collect::<Vec<_>>()
        } else {
            self.ips
                .iter()
                .map(PrefixWithOptionalPorts::prefix)
                .collect::<Vec<_>>()
        }
    }

    // This method returns true if the list of allowed prefixes is IPv4.
    #[must_use]
    pub fn is_v4(&self) -> bool {
        self.ips.first().is_some_and(|p| p.prefix().is_ipv4())
    }

    // This method returns true if the list of allowed prefixes is IPv6.
    #[must_use]
    pub fn is_v6(&self) -> bool {
        self.ips.first().is_some_and(|p| p.prefix().is_ipv6())
    }

    // This method returns true if both allowed and translated prefixes are IPv4.
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
    pub fn has_stateful_nat(&self) -> bool {
        self.nat.as_ref().is_some_and(VpcExposeNat::is_stateful)
    }

    #[must_use]
    pub fn has_stateless_nat(&self) -> bool {
        self.nat.as_ref().is_some_and(VpcExposeNat::is_stateless)
    }

    #[must_use]
    pub fn has_port_forwarding(&self) -> bool {
        self.nat
            .as_ref()
            .is_some_and(VpcExposeNat::is_port_forwarding)
    }

    #[must_use]
    pub fn nat(&self) -> Option<&VpcExposeNat> {
        self.nat.as_ref()
    }

    #[must_use]
    pub fn nat_config(&self) -> Option<&VpcExposeNatConfig> {
        self.nat.as_ref().map(|nat| &nat.config)
    }

    #[must_use]
    pub fn nat_proto(&self) -> Option<&L4Protocol> {
        self.nat.as_ref().map(|nat| &nat.proto)
    }

    #[must_use]
    pub fn idle_timeout(&self) -> Option<Duration> {
        match self.nat_config()? {
            VpcExposeNatConfig::Stateful(config) => config.idle_timeout,
            VpcExposeNatConfig::PortForwarding(config) => config.idle_timeout,
            VpcExposeNatConfig::Stateless(_) => None,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct VpcManifest {
    pub name: String, /* key: name of vpc */
    pub(crate) exposes: Vec<VpcExpose>,
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
    pub fn with_exposes(vpc_name: &str, exposes: Vec<VpcExpose>) -> Self {
        let mut manifest = Self::new(vpc_name);
        manifest.add_exposes(exposes);
        manifest
    }

    #[must_use]
    pub fn exposing(mut self, expose: VpcExpose) -> Self {
        self.exposes.push(expose);
        self
    }

    pub fn add_expose(&mut self, expose: VpcExpose) {
        self.exposes.push(expose);
    }

    pub fn add_exposes(&mut self, exposes: impl IntoIterator<Item = VpcExpose>) {
        self.exposes.extend(exposes);
    }

    /// Validate the [`VpcManifest`].
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest configuration is invalid.
    pub fn validate(&mut self) -> Result<ValidatedManifest, ConfigError> {
        if self.name.is_empty() {
            return Err(ConfigError::MissingIdentifier("Manifest name"));
        }
        if self.exposes.is_empty() {
            return Err(ConfigError::NoExposes(self.name.clone()));
        }
        if self.exposes.iter().filter(|expose| expose.default).count() > 1 {
            return Err(ConfigError::Forbidden(
                "Manifest cannot have multiple default exposes",
            ));
        }

        let mut valid_manifest_candidate = ValidatedManifest {
            name: self.name.clone(),
            valexp: Vec::new(),
        };
        for expose in &self.exposes {
            valid_manifest_candidate.valexp.push(expose.validate()?);
        }

        valid_manifest_candidate.validate_expose_collisions()?;
        Ok(valid_manifest_candidate)
    }

    #[must_use]
    pub fn default_expose(&self) -> Option<&VpcExpose> {
        self.exposes.iter().find(|expose| expose.default)
    }

    /// FOR TESTS ONLY. Fake validation for the manifest.
    ///
    /// # Safety
    ///
    /// All bets are off. Do not use outside of tests.
    #[cfg(feature = "testing")]
    #[allow(unsafe_code)]
    #[must_use]
    pub unsafe fn fake_valid_manifest_for_tests(&self) -> ValidatedManifest {
        let mut fake_valid_manifest = ValidatedManifest {
            name: self.name.clone(),
            valexp: Vec::new(),
        };
        for expose in &self.exposes {
            let fake_valid_expose = unsafe { expose.fake_validated_expose() };
            fake_valid_manifest.valexp.push(fake_valid_expose);
        }
        fake_valid_manifest
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedManifest {
    name: String, /* key: name of vpc */
    // Validated, exclusion-prefixes-free view of exposes.
    valexp: Vec<ValidatedExpose>,
}

impl ValidatedManifest {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn valexp(&self) -> &[ValidatedExpose] {
        &self.valexp
    }

    #[must_use]
    pub fn default_expose(&self) -> Option<&ValidatedExpose> {
        self.valexp().iter().find(|expose| expose.is_default())
    }

    fn filter_exposes<F>(&self, predicate: F) -> impl Iterator<Item = &ValidatedExpose>
    where
        F: FnMut(&&ValidatedExpose) -> bool,
    {
        self.valexp().iter().filter(predicate)
    }

    pub fn stateless_nat_exposes(&self) -> impl Iterator<Item = &ValidatedExpose> {
        self.filter_exposes(|expose| expose.has_stateless_nat())
    }

    pub fn stateful_nat_exposes_44(&self) -> impl Iterator<Item = &ValidatedExpose> {
        self.filter_exposes(|expose| expose.has_stateful_nat() && expose.is_44())
    }

    pub fn stateful_nat_exposes_66(&self) -> impl Iterator<Item = &ValidatedExpose> {
        self.filter_exposes(|expose| expose.has_stateful_nat() && expose.is_66())
    }

    pub fn no_stateful_nat_exposes_v4(&self) -> impl Iterator<Item = &ValidatedExpose> {
        self.filter_exposes(|expose| !expose.has_stateful_nat() && expose.is_v4())
    }

    pub fn no_stateful_nat_exposes_v6(&self) -> impl Iterator<Item = &ValidatedExpose> {
        self.filter_exposes(|expose| !expose.has_stateful_nat() && expose.is_v6())
    }

    pub fn port_forwarding_exposes(&self) -> impl Iterator<Item = &ValidatedExpose> {
        self.filter_exposes(|expose| expose.has_port_forwarding())
    }

    pub fn port_forwarding_exposes_44(&self) -> impl Iterator<Item = &ValidatedExpose> {
        self.filter_exposes(|expose| expose.has_port_forwarding() && expose.is_44())
    }

    pub fn port_forwarding_exposes_66(&self) -> impl Iterator<Item = &ValidatedExpose> {
        self.filter_exposes(|expose| expose.has_port_forwarding() && expose.is_66())
    }

    fn validate_expose_collisions(&self) -> ConfigResult {
        // Check that prefixes in each expose don't overlap with prefixes in other exposes
        for (index, expose_left) in self.valexp.iter().enumerate() {
            // Loop over the remaining exposes in the list
            for expose_right in self.valexp.iter().skip(index + 1) {
                #[allow(clippy::unnested_or_patterns)]
                match (&expose_left.nat_config(), &expose_right.nat_config()) {
                    // Overlap allowed

                    // Port forwarding plus stateful NAT can be used in combination. This is because
                    // both imply a unique direction for opening a connection, so we can use port
                    // forwarding when the request is in the associated direction, and stateful NAT
                    // otherwise.
                    (
                        Some(VpcExposeNatConfig::Stateful { .. }),
                        Some(VpcExposeNatConfig::PortForwarding { .. }),
                    )
                    | (
                        Some(VpcExposeNatConfig::PortForwarding { .. }),
                        Some(VpcExposeNatConfig::Stateful { .. }),
                    ) => {}

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

    /// Create a `VpcPeering` mapped to a group called "default".
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
    /// Validate A `VpcPeering`. Only used in tests. Dataplane validates `Peerings`
    ///
    /// # Errors
    ///
    /// Returns an error if the peering configuration is invalid.
    pub fn validate(&mut self) -> ConfigResult {
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

    /// Add a [`VpcPeering`] to a [`VpcPeeringTable`].
    ///
    /// # Errors
    ///
    /// Returns an error if the peering name is missing or a duplicate peering exists.
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

    /// Iterate over all [`VpcPeering`]s in a [`VpcPeeringTable`], with mutable access
    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut VpcPeering> {
        self.0.values_mut()
    }

    /// Produce iterator of [`VpcPeering`]s that involve the vpc with the provided name
    pub fn peerings_vpc(&self, vpc: &str) -> impl Iterator<Item = &VpcPeering> {
        self.0
            .values()
            .filter(move |p| p.left.name == vpc || p.right.name == vpc)
    }
}
