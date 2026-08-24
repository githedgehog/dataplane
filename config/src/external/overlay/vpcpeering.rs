// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: vpc peering

use crate::external::overlay::acl::Acl;
use crate::utils::{
    check_private_prefixes_dont_overlap, check_public_prefixes_dont_overlap, collapse_prefixes,
    normalize,
};
use concurrency::sync::LazyLock;
use lpm::prefix::{
    IpRangeWithPorts, L4Protocol, PortRange, Prefix, PrefixPortsSet, PrefixWithOptionalPorts,
};
use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;
use tracing::warn;

/// Reserved prefixes that are never valid tenant endpoints, with the reason they are rejected.
static SPECIAL_USE_PREFIXES: LazyLock<Vec<(Prefix, &'static str)>> = LazyLock::new(|| {
    [
        ("0.0.0.0/8", "unspecified (0.0.0.0/8)"),
        ("127.0.0.0/8", "loopback"),
        ("169.254.0.0/16", "link-local"),
        ("224.0.0.0/4", "multicast"),
        // Listed before 240.0.0.0/4 so the more specific match wins for 255.255.255.255.
        ("255.255.255.255/32", "limited broadcast"),
        ("240.0.0.0/4", "reserved (240.0.0.0/4)"),
        ("::/128", "unspecified (::/128)"),
        ("::1/128", "loopback"),
        ("fe80::/10", "link-local"),
        ("ff00::/8", "multicast"),
    ]
    .into_iter()
    .map(|(cidr, class)| {
        let Ok(prefix) = Prefix::from_str(cidr) else {
            unreachable!("SPECIAL_USE_PREFIXES entries must be valid prefixes")
        };
        (prefix, class)
    })
    .collect()
});

/// Returns the reason a prefix is reserved (it overlaps a special-use block), or `None` if it is
/// usable. Does not itself reject anything; see [`reject_special_use`].
///
/// Overlap, not containment: a prefix is rejected if it holds *any* reserved address, so broad
/// prefixes such as the root `0.0.0.0/0` (which contain reserved blocks) are rejected too. Use a
/// `default` expose or exclude the reserved sub-blocks to express "everything".
fn special_use_class(prefix: &Prefix) -> Option<&'static str> {
    SPECIAL_USE_PREFIXES
        .iter()
        .find(|(special, _)| special.collides_with(prefix))
        .map(|(_, class)| *class)
}

/// Reject any prefix in `prefixes` that overlaps a reserved range.
fn reject_special_use(prefixes: &PrefixPortsSet) -> ConfigResult {
    for prefix_with_ports in prefixes {
        let prefix = prefix_with_ports.prefix();
        if let Some(class) = special_use_class(&prefix) {
            return Err(ConfigError::SpecialUsePrefix(prefix, class));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct VpcExposeStaticNat;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct VpcExposeMasquerade {
    pub idle_timeout: Option<Duration>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct VpcExposePortForwarding {
    pub idle_timeout: Option<Duration>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum VpcExposeNatConfig {
    Masquerade(VpcExposeMasquerade),
    Static(VpcExposeStaticNat),
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
    pub fn is_masquerade(&self) -> bool {
        matches!(self.config, VpcExposeNatConfig::Masquerade(_))
    }

    #[must_use]
    pub fn is_static(&self) -> bool {
        matches!(self.config, VpcExposeNatConfig::Static(_))
    }

    #[must_use]
    pub fn is_port_forwarding(&self) -> bool {
        matches!(self.config, VpcExposeNatConfig::PortForwarding(_))
    }
}

fn empty_set() -> &'static PrefixPortsSet {
    static EMPTY_SET: LazyLock<PrefixPortsSet> = LazyLock::new(PrefixPortsSet::new);
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
    /// Make the [`VpcExpose`] use static NAT.
    ///
    /// # Errors
    ///
    /// Returns an error if the [`VpcExpose`] already has a different NAT mode.
    pub fn make_static_nat(mut self) -> Result<Self, ConfigError> {
        match self.nat.as_mut() {
            Some(nat) if nat.is_static() => Ok(self),
            Some(_) => Err(ConfigError::Invalid(format!(
                "refusing to overwrite previous NAT mode with static NAT mode for VpcExpose {self}"
            ))),
            None => {
                self.nat = Some(VpcExposeNat::from_config(VpcExposeNatConfig::Static(
                    VpcExposeStaticNat {},
                )));
                Ok(self)
            }
        }
    }

    /// Make the [`VpcExpose`] use masquerade, with the given idle timeout, if provided.
    /// If the [`VpcExpose`] is already in masquerade mode, the idle timeout is overwritten.
    ///
    /// # Errors
    ///
    /// Returns an error if the [`VpcExpose`] already has a different NAT mode.
    pub fn make_masquerade(mut self, idle_timeout: Option<Duration>) -> Result<Self, ConfigError> {
        let options = VpcExposeMasquerade { idle_timeout };
        match self.nat.as_mut() {
            Some(nat) if nat.is_masquerade() => {
                nat.config = VpcExposeNatConfig::Masquerade(options);
                Ok(self)
            }
            Some(_) => Err(ConfigError::Invalid(format!(
                "refusing to overwrite previous NAT mode with masquerade mode for VpcExpose {self}"
            ))),

            None => {
                self.nat = Some(VpcExposeNat::from_config(VpcExposeNatConfig::Masquerade(
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

        // Check that all prefixes in a list are of the same IP version, as we don't support NAT46
        // or NAT64 at the moment.
        //
        // TODO: We can loosen this restriction in the future. When we do, some additional
        //       considerations might be required to validate independently the IPv4 and the IPv6
        //       prefixes and exclusion prefixes in the rest of this function.
        if !PrefixPortsSet::have_consistent_ip_version(&[
            &self.ips,
            &self.nots,
            self.as_range_or_empty(),
            self.not_as_or_empty(),
        ]) {
            return Err(ConfigError::InconsistentIpVersion(Box::new(self.clone())));
        }

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

        // Warn if any exclusion prefix does not overlap with any allowed prefix.
        for (prefixes, excludes) in [
            (&self.ips, &self.nots),
            (self.as_range_or_empty(), self.not_as_or_empty()),
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
        normalize(&mut clone.ips);
        if let Some(nat) = &mut clone.nat {
            normalize(&mut nat.as_range);
        }

        // Reject reserved prefixes in the effective (post-exclusion) sets. Checking here rather than
        // on the raw input means a reserved prefix that is entirely removed by an exclusion is not
        // flagged, since it can never become an endpoint.
        reject_special_use(&clone.ips)?;
        if let Some(nat) = &clone.nat {
            reject_special_use(&nat.as_range)?;
        }

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
        if collapsed_expose.has_static_nat() && ips_sizes != as_range_sizes {
            return Err(ConfigError::MismatchedPrefixSizes(
                ips_sizes,
                as_range_sizes,
            ));
        }

        // For port forwarding, ensure that:
        // - we have no exclusion prefixes (note: we could relax this constraint now that we
        //   collapse exclusion prefixes early)
        // - we have a single prefix on each side (private and public addresses)
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
            // For port forwarding, ensure that a port range is always present. Lack of port range would imply
            // all ports, which is not allowed since port 0 is forbidden in the implementation
            for prefixes in [collapsed_expose.ips(), collapsed_expose.as_range_or_empty()] {
                if prefixes.iter().any(|p| p.ports().is_none()) {
                    return Err(ConfigError::Forbidden(
                        "Port forwarding requires a port range on each prefix",
                    ));
                }
            }

            let (Some(internal), Some(external)) = (
                collapsed_expose.ips().first(),
                collapsed_expose.as_range_or_empty().first(),
            ) else {
                return Err(ConfigError::Forbidden(
                    "Port forwarding requires a single prefix on each side",
                ));
            };
            if internal.prefix().length() != external.prefix().length() {
                return Err(ConfigError::MismatchedPrefixLengths {
                    private: internal.prefix().length(),
                    public: external.prefix().length(),
                });
            }
            let (Some(internal_ports), Some(external_ports)) = (internal.ports(), external.ports())
            else {
                return Err(ConfigError::Forbidden(
                    "Port forwarding requires a port range on each prefix",
                ));
            };
            if internal_ports.len() != external_ports.len() {
                return Err(ConfigError::MismatchedPortRangeSizes {
                    private: internal_ports.len(),
                    public: external_ports.len(),
                });
            }
        }

        // For masquerade, we don't support port ranges
        if collapsed_expose.has_masquerade()
            && (collapsed_expose.ips().iter().any(|p| p.ports().is_some())
                || collapsed_expose
                    .as_range_or_empty()
                    .iter()
                    .any(|p| p.ports().is_some()))
        {
            return Err(ConfigError::Forbidden(
                "Port ranges are not supported with masquerade",
            ));
        }

        Ok(collapsed_expose)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortForwardExpose {
    internal: PrefixWithPortRange,
    external: PrefixWithPortRange,
    proto: L4Protocol,
    idle_timeout: Option<Duration>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrefixWithPortRange {
    prefix: Prefix,
    ports: PortRange,
}

impl PrefixWithPortRange {
    #[must_use]
    pub fn prefix(&self) -> Prefix {
        self.prefix
    }

    #[must_use]
    pub fn ports(&self) -> PortRange {
        self.ports
    }
}

impl PortForwardExpose {
    #[must_use]
    pub fn internal(&self) -> PrefixWithPortRange {
        self.internal
    }

    #[must_use]
    pub fn external(&self) -> PrefixWithPortRange {
        self.external
    }

    #[must_use]
    pub fn proto(&self) -> L4Protocol {
        self.proto
    }

    #[must_use]
    pub fn idle_timeout(&self) -> Option<Duration> {
        self.idle_timeout
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
    pub fn has_masquerade(&self) -> bool {
        self.nat.as_ref().is_some_and(VpcExposeNat::is_masquerade)
    }

    #[must_use]
    pub fn has_static_nat(&self) -> bool {
        self.nat.as_ref().is_some_and(VpcExposeNat::is_static)
    }

    #[must_use]
    pub fn has_port_forwarding(&self) -> bool {
        self.nat
            .as_ref()
            .is_some_and(VpcExposeNat::is_port_forwarding)
    }

    /// Returns whether a packet with source IP/port in this expose block can initiate a connection
    #[must_use]
    pub fn can_init_connection(&self) -> bool {
        !self.has_port_forwarding()
    }

    /// Returns whether destinations in this expose block are valid targets for incoming connections
    #[must_use]
    pub fn can_receive_connection(&self) -> bool {
        !self.has_masquerade()
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
    pub fn nat_proto(&self) -> Option<L4Protocol> {
        self.nat.as_ref().map(|nat| nat.proto)
    }

    #[must_use]
    pub fn as_port_forward(&self) -> Option<PortForwardExpose> {
        let nat = self.nat.as_ref()?;
        let VpcExposeNatConfig::PortForwarding(options) = &nat.config else {
            return None;
        };
        let side = |p: &PrefixWithOptionalPorts| {
            Some(PrefixWithPortRange {
                prefix: p.prefix(),
                ports: p.ports()?,
            })
        };
        Some(PortForwardExpose {
            internal: side(self.ips.first()?)?,
            external: side(nat.as_range.first()?)?,
            proto: nat.proto,
            idle_timeout: options.idle_timeout,
        })
    }

    #[must_use]
    pub fn idle_timeout(&self) -> Option<Duration> {
        match self.nat_config()? {
            VpcExposeNatConfig::Masquerade(config) => config.idle_timeout,
            VpcExposeNatConfig::PortForwarding(config) => config.idle_timeout,
            VpcExposeNatConfig::Static(_) => None,
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
    pub fn validate(&self) -> Result<ValidatedManifest, ConfigError> {
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

        valid_manifest_candidate.validate_single_ip_version()?;
        valid_manifest_candidate.validate_expose_collisions()?;
        Ok(valid_manifest_candidate)
    }

    #[must_use]
    pub fn default_expose(&self) -> Option<&VpcExpose> {
        self.exposes.iter().find(|expose| expose.default)
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
    pub fn has_default_expose(&self) -> bool {
        self.valexp().iter().any(ValidatedExpose::is_default)
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

    pub fn static_nat_exposes(&self) -> impl Iterator<Item = &ValidatedExpose> {
        self.filter_exposes(|expose| expose.has_static_nat())
    }

    pub fn masquerade_exposes_44(&self) -> impl Iterator<Item = &ValidatedExpose> {
        self.filter_exposes(|expose| expose.has_masquerade() && expose.is_44())
    }

    pub fn masquerade_exposes_66(&self) -> impl Iterator<Item = &ValidatedExpose> {
        self.filter_exposes(|expose| expose.has_masquerade() && expose.is_66())
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

    #[must_use]
    pub fn is_v4(&self) -> bool {
        self.valexp.iter().any(ValidatedExpose::is_v4)
    }

    #[must_use]
    pub fn is_v6(&self) -> bool {
        self.valexp.iter().any(ValidatedExpose::is_v6)
    }

    #[must_use]
    pub fn is_default_only(&self) -> bool {
        self.valexp.len() == 1 && self.valexp.first().is_some_and(ValidatedExpose::is_default)
    }

    /// Reject manifests containing both IPv4 and IPv6 exposes.
    /// Default exposes are version-neutral.
    fn validate_single_ip_version(&self) -> ConfigResult {
        let mut version: Option<bool> = None;
        for expose in &self.valexp {
            // A default expose has no IP version.
            let is_v4 = if expose.is_v4() {
                true
            } else if expose.is_v6() {
                false
            } else {
                continue;
            };
            match version {
                Some(seen) if seen != is_v4 => {
                    return Err(ConfigError::Forbidden(
                        "A manifest cannot mix IPv4 and IPv6 expose blocks",
                    ));
                }
                _ => version = Some(is_v4),
            }
        }
        Ok(())
    }

    fn validate_expose_collisions(&self) -> ConfigResult {
        // Check that prefixes in each expose don't overlap with prefixes in other exposes
        for (index, expose_left) in self.valexp.iter().enumerate() {
            // Loop over the remaining exposes in the list
            for expose_right in self.valexp.iter().skip(index + 1) {
                #[allow(clippy::unnested_or_patterns)]
                match (&expose_left.nat_config(), &expose_right.nat_config()) {
                    // Overlap allowed

                    // Port forwarding plus masquerade can be used in combination. This is because
                    // both imply a unique direction for opening a connection, so we can use port
                    // forwarding when the request is in the associated direction, and masquerade
                    // otherwise.
                    (
                        Some(VpcExposeNatConfig::Masquerade { .. }),
                        Some(VpcExposeNatConfig::PortForwarding { .. }),
                    )
                    | (
                        Some(VpcExposeNatConfig::PortForwarding { .. }),
                        Some(VpcExposeNatConfig::Masquerade { .. }),
                    ) => {}

                    // Overlap denied

                    // If using no NAT at all, private prefixes (which are also publicly exposed)
                    // cannot overlap. Compared to the cases with NAT below, checking private and
                    // public prefixes is the same operation, so we only need to do it once.
                    (None, None) => {
                        check_private_prefixes_dont_overlap(expose_left, expose_right)?;
                    }

                    // We do not support static NAT in combination with another mode.
                    (Some(VpcExposeNatConfig::Static { .. }), _)
                    | (_, Some(VpcExposeNatConfig::Static { .. }))
                    // Two exposes using port forwarding must use distinct internal prefixes, or we
                    // don't know which to use.
                    | (
                        Some(VpcExposeNatConfig::PortForwarding { .. }),
                        Some(VpcExposeNatConfig::PortForwarding { .. }),
                    )
                    // Two exposes using masquerade must use distinct internal prefixes, or we don't
                    // know which to use.
                    | (
                        Some(VpcExposeNatConfig::Masquerade { .. }),
                        Some(VpcExposeNatConfig::Masquerade { .. }),
                    )
                    // Masquerade cannot be used in combination with no NAT, or we don't know which
                    // prefix to use. Similar to port forwarding plus no NAT, here we could figure
                    // out something based on the direction for masquerade (which only works for
                    // source NAT), but this is not supported at the moment, and masquerade might
                    // work in both directions in the future anyway.
                    | (Some(VpcExposeNatConfig::Masquerade { .. }), None)
                    | (None, Some(VpcExposeNatConfig::Masquerade { .. }))
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

    #[must_use]
    pub fn all_ips(&self) -> PrefixPortsSet {
        self.valexp
            .iter()
            .fold(PrefixPortsSet::new(), |acc, valexp| {
                acc.union_prefixes_and_ports(valexp.ips())
            })
    }

    #[must_use]
    pub fn all_public_ips(&self) -> PrefixPortsSet {
        self.valexp
            .iter()
            .fold(PrefixPortsSet::new(), |acc, valexp| {
                acc.union_prefixes_and_ports(valexp.public_ips())
            })
    }
}

#[derive(Clone, Debug)]
pub struct VpcPeering {
    pub name: String,       /* name of peering (key in table) */
    pub left: VpcManifest,  /* manifest for one side of the peering */
    pub right: VpcManifest, /* manifest for the other side */
    pub gwgroup: String,    /* name of gateway group */
    pub acl: Option<Acl>,   /* optional peering-scoped ACL */
}
impl VpcPeering {
    #[must_use]
    pub fn new(name: &str, left: VpcManifest, right: VpcManifest, gwgroup: String) -> Self {
        Self {
            name: name.to_owned(),
            left,
            right,
            gwgroup,
            acl: None,
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
            gwgroup: "default".to_string(),
            acl: None,
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
    pub(crate) fn get_peering_manifests(&self, vpc: &str) -> (&VpcManifest, &VpcManifest) {
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

#[cfg(any(test, feature = "bolero"))]
pub mod contract {

    use super::{VpcExpose, VpcExposeNatConfig, VpcManifest, VpcPeering, VpcPeeringTable};
    use crate::ConfigError;
    use crate::external::overlay::acl::{
        Acl, AclAction, AclPattern, AclProtoMatch, AclRule, AclScope,
    };
    use crate::external::overlay::vpc::{Vpc, VpcTable};
    use crate::external::overlay::{Overlay, ValidatedOverlay};
    use bolero::{Driver, ValueGenerator};
    use lpm::prefix::PrefixPortsSet;
    use lpm::prefix::{
        IpPrefix, Ipv4Prefix, Ipv6Prefix, L4Protocol, PortRange, Prefix, PrefixWithOptionalPorts,
    };
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::ops::Bound::Included;
    use std::time::Duration;

    const MAX_HOST_BITS: u8 = 8;

    const MAX_PORTS: u16 = 1024;

    /// Which address family an expose should use.
    ///
    /// A manifest may not mix families, so a caller building several exposes for one
    /// manifest has to fix this once rather than let each expose draw its own. Letting
    /// them draw independently produced a manifest the validator refuses outright, which
    /// showed up as a large and unexplained share of discarded cases.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub enum Family {
        /// Let the driver choose. The right default for a lone expose.
        #[default]
        Either,
        V4,
        V6,
    }

    impl Family {
        fn is_v4<D: Driver>(self, driver: &mut D) -> Option<bool> {
            match self {
                Family::Either => driver.produce::<bool>(),
                Family::V4 => Some(true),
                Family::V6 => Some(false),
            }
        }
    }

    #[derive(Debug, Clone, Copy, Default)]
    pub struct PortForwardingExpose {
        pub family: Family,
    }

    impl ValueGenerator for PortForwardingExpose {
        type Output = VpcExpose;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<VpcExpose> {
            let host_bits = driver.gen_u8(Included(&0), Included(&MAX_HOST_BITS))?;
            let (internal, external) = if self.family.is_v4(driver)? {
                v4_pair(driver, host_bits)?
            } else {
                v6_pair(driver, host_bits)?
            };

            let count = driver.gen_u16(Included(&1), Included(&MAX_PORTS))?;
            let internal_ports = port_range(driver, count)?;
            let external_ports = port_range(driver, count)?;

            let proto = match driver.gen_u8(Included(&0), Included(&2))? {
                0 => L4Protocol::Tcp,
                1 => L4Protocol::Udp,
                _ => L4Protocol::Any,
            };
            let idle_timeout = match driver.gen_u8(Included(&0), Included(&2))? {
                0 => None,
                1 => Some(Duration::from_secs(5)),
                _ => Some(Duration::from_mins(5)),
            };

            VpcExpose::empty()
                .make_port_forwarding(idle_timeout, Some(proto))
                .ok()?
                .ip(PrefixWithOptionalPorts::new(internal, Some(internal_ports)))
                .as_range(PrefixWithOptionalPorts::new(external, Some(external_ports)))
                .ok()
        }
    }

    #[derive(Debug, Clone, Copy)]
    pub struct PortForwardingExposes(pub u8);

    impl Default for PortForwardingExposes {
        fn default() -> Self {
            Self(2)
        }
    }

    pub const MAX_PORT_FORWARDING_EXPOSES: u8 = 2;

    impl ValueGenerator for PortForwardingExposes {
        type Output = Vec<VpcExpose>;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Vec<VpcExpose>> {
            let v4 = driver.produce::<bool>()?;
            let count = driver.gen_u8(
                Included(&1),
                Included(&self.0.clamp(1, MAX_PORT_FORWARDING_EXPOSES)),
            )?;
            (0..count)
                .map(|slot| {
                    let proto = if slot == 0 {
                        L4Protocol::Tcp
                    } else {
                        L4Protocol::Udp
                    };
                    port_forwarding_expose(driver, v4, slot, proto)
                })
                .collect()
        }
    }

    fn port_forwarding_expose<D: Driver>(
        driver: &mut D,
        v4: bool,
        block: u8,
        proto: L4Protocol,
    ) -> Option<VpcExpose> {
        let host_bits = driver.gen_u8(Included(&0), Included(&MAX_HOST_BITS))?;
        let (internal, external) = if v4 {
            v4_pair_in_block(driver, host_bits, block)?
        } else {
            v6_pair_in_block(driver, host_bits, block)?
        };

        let count = driver.gen_u16(Included(&1), Included(&MAX_PORTS))?;
        let internal_ports = port_range(driver, count)?;
        let external_ports = port_range(driver, count)?;
        let idle_timeout = match driver.gen_u8(Included(&0), Included(&2))? {
            0 => None,
            1 => Some(Duration::from_secs(5)),
            _ => Some(Duration::from_mins(5)),
        };

        VpcExpose::empty()
            .make_port_forwarding(idle_timeout, Some(proto))
            .ok()?
            .ip(PrefixWithOptionalPorts::new(internal, Some(internal_ports)))
            .as_range(PrefixWithOptionalPorts::new(external, Some(external_ports)))
            .ok()
    }

    fn v4_pair_in_block<D: Driver>(
        driver: &mut D,
        host_bits: u8,
        block: u8,
    ) -> Option<(Prefix, Prefix)> {
        let len = 32 - host_bits;
        let mask = u32::MAX.checked_shl(u32::from(host_bits)).unwrap_or(0);
        let slot = u32::from(block) << 16;
        let internal = (0x0A00_0000 | slot | (driver.produce::<u32>()? & 0x0000_FFFF)) & mask;
        let external = (0xAC10_0000 | slot | (driver.produce::<u32>()? & 0x0000_FFFF)) & mask;
        Some((prefix_v4(internal, len)?, prefix_v4(external, len)?))
    }

    fn v6_pair_in_block<D: Driver>(
        driver: &mut D,
        host_bits: u8,
        block: u8,
    ) -> Option<(Prefix, Prefix)> {
        let len = 128 - host_bits;
        let mask = u128::MAX.checked_shl(u32::from(host_bits)).unwrap_or(0);
        let slot = u128::from(block) << 64;
        let internal = (INTERNAL_BASE | slot | u128::from(driver.produce::<u32>()?)) & mask;
        let external = (EXTERNAL_BASE | slot | u128::from(driver.produce::<u32>()?)) & mask;
        Some((prefix_v6(internal, len)?, prefix_v6(external, len)?))
    }

    #[derive(Debug, Clone, Copy, Default)]
    pub struct MasqueradeExpose {
        pub family: Family,
    }

    #[derive(Debug, Clone, Copy)]
    pub struct MasqueradeExposes(pub u8);

    impl Default for MasqueradeExposes {
        fn default() -> Self {
            Self(3)
        }
    }

    const MASQUERADE_SLOT: u8 = 4;

    impl ValueGenerator for MasqueradeExposes {
        type Output = Vec<VpcExpose>;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Vec<VpcExpose>> {
            let v4 = driver.produce::<bool>()?;
            let count = driver.gen_u8(Included(&1), Included(&self.0.max(1)))?;
            (0..count)
                .map(|slot| masquerade_expose(driver, v4, slot.wrapping_mul(MASQUERADE_SLOT)))
                .collect()
        }
    }

    impl ValueGenerator for MasqueradeExpose {
        type Output = VpcExpose;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<VpcExpose> {
            let v4 = self.family.is_v4(driver)?;
            let base = driver.produce::<u8>()?;
            masquerade_expose(driver, v4, base)
        }
    }

    fn masquerade_expose<D: Driver>(driver: &mut D, v4: bool, base: u8) -> Option<VpcExpose> {
        let privates = driver.gen_u8(Included(&1), Included(&3))?;
        let publics = driver.gen_u8(Included(&1), Included(&2))?;
        let idle_timeout = match driver.gen_u8(Included(&0), Included(&2))? {
            0 => None,
            1 => Some(Duration::from_secs(30)),
            _ => Some(Duration::from_mins(2)),
        };

        let mut expose = VpcExpose::empty().make_masquerade(idle_timeout).ok()?;
        for index in 0..privates {
            expose = expose.ip(PrefixWithOptionalPorts::new(
                block(v4, Side::Private, base.wrapping_add(index))?,
                None,
            ));
        }
        for index in 0..publics {
            expose = expose
                .as_range(PrefixWithOptionalPorts::new(
                    block(v4, Side::Public, base.wrapping_add(index))?,
                    None,
                ))
                .ok()?;
        }
        Some(expose)
    }

    #[derive(Clone, Copy)]
    enum Side {
        Private,
        Public,
    }

    fn block(v4: bool, side: Side, index: u8) -> Option<Prefix> {
        if v4 {
            let bits = match side {
                Side::Private => 0x0A00_0000 | (u32::from(index) << 16),
                Side::Public => 0xAC10_0000 | (u32::from(index) << 8),
            };
            prefix_v4(bits, 24)
        } else {
            let selector = match side {
                Side::Private => 0u128,
                Side::Public => 1,
            };
            let bits = (0x2001_0db8u128 << 96) | (selector << 80) | (u128::from(index) << 64);
            prefix_v6(bits, 64)
        }
    }

    #[derive(Debug, Clone, Copy, Default)]
    pub struct StaticNatExpose {
        pub family: Family,
    }

    #[derive(Debug, Clone, Copy)]
    pub struct StaticNatExposes {
        pub max: u8,
        pub ports: bool,
    }

    impl Default for StaticNatExposes {
        fn default() -> Self {
            Self::addresses_only(3)
        }
    }

    impl StaticNatExposes {
        #[must_use]
        pub fn addresses_only(max: u8) -> Self {
            Self { max, ports: false }
        }

        #[must_use]
        pub fn with_ports(max: u8) -> Self {
            Self { max, ports: true }
        }
    }

    const MAX_TOTAL_LOG: u8 = 6;

    const BLOCK_STRIDE: u128 = 4 << MAX_TOTAL_LOG;

    impl ValueGenerator for StaticNatExpose {
        type Output = VpcExpose;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<VpcExpose> {
            let v4 = self.family.is_v4(driver)?;
            static_nat_expose(driver, v4, 0)
        }
    }

    impl ValueGenerator for StaticNatExposes {
        type Output = Vec<VpcExpose>;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Vec<VpcExpose>> {
            let v4 = driver.produce::<bool>()?;
            let count = driver.gen_u8(Included(&1), Included(&self.max.max(1)))?;
            (0..count)
                .map(|block| {
                    if self.ports {
                        static_nat_pat_expose(driver, v4, block)
                    } else {
                        static_nat_expose(driver, v4, block)
                    }
                })
                .collect()
        }
    }

    fn static_nat_expose<D: Driver>(driver: &mut D, v4: bool, block: u8) -> Option<VpcExpose> {
        let total_log = driver.gen_u8(Included(&0), Included(&MAX_TOTAL_LOG))?;

        let privates = place(v4, Side::Private, block, &split(driver, total_log)?)?;
        let publics = place(v4, Side::Public, block, &split(driver, total_log)?)?;

        let mut expose = VpcExpose::empty().make_static_nat().ok()?;
        for prefix in privates {
            expose = expose.ip(PrefixWithOptionalPorts::new(prefix, None));
        }
        for prefix in publics {
            expose = expose
                .as_range(PrefixWithOptionalPorts::new(prefix, None))
                .ok()?;
        }
        Some(expose)
    }

    fn static_nat_pat_expose<D: Driver>(driver: &mut D, v4: bool, block: u8) -> Option<VpcExpose> {
        let total_log = driver.gen_u8(Included(&0), Included(&MAX_TOTAL_LOG))?;

        let mut side = |which| -> Option<PrefixWithOptionalPorts> {
            let port_log = driver.gen_u8(Included(&0), Included(&total_log))?;
            let addr_log = total_log - port_log;
            let prefix = *place(v4, which, block, &[addr_log])?.first()?;
            let ports = port_range(driver, 1u16 << port_log)?;
            Some(PrefixWithOptionalPorts::new(prefix, Some(ports)))
        };

        let private = side(Side::Private)?;
        let public = side(Side::Public)?;

        VpcExpose::empty()
            .make_static_nat()
            .ok()?
            .ip(private)
            .as_range(public)
            .ok()
    }

    fn split<D: Driver>(driver: &mut D, total_log: u8) -> Option<Vec<u8>> {
        let mut parts = vec![total_log];
        for _ in 0..driver.gen_u8(Included(&0), Included(&3))? {
            let splittable: Vec<usize> = parts
                .iter()
                .enumerate()
                .filter(|(_, log)| **log > 0)
                .map(|(index, _)| index)
                .collect();
            if splittable.is_empty() {
                break;
            }
            let choice = usize::from(driver.gen_u8(
                Included(&0),
                Included(&u8::try_from(splittable.len() - 1).ok()?),
            )?);
            let log = parts.swap_remove(splittable[choice]);
            parts.push(log - 1);
            parts.push(log - 1);
        }
        parts.sort_unstable_by(|a, b| b.cmp(a));
        Some(parts)
    }

    fn place(v4: bool, side: Side, block: u8, parts: &[u8]) -> Option<Vec<Prefix>> {
        let offset = u128::from(block) * BLOCK_STRIDE;
        let mut cursor = offset
            + if v4 {
                u128::from(match side {
                    Side::Private => 0x0A00_0000u32,
                    Side::Public => 0xAC10_0000,
                })
            } else {
                let selector = match side {
                    Side::Private => 0u128,
                    Side::Public => 1,
                };
                (0x2001_0db8u128 << 96) | (selector << 80)
            };

        let mut out = Vec::with_capacity(parts.len());
        for &log in parts {
            let prefix = if v4 {
                prefix_v4(u32::try_from(cursor).ok()?, 32 - log)?
            } else {
                prefix_v6(cursor, 128 - log)?
            };
            out.push(prefix);
            cursor += 2u128 << log;
        }
        Some(out)
    }

    pub const LOCAL_VNI: u32 = 100;
    pub const REMOTE_VNI: u32 = 200;

    /// Build the fixed two-vpc overlay around `expose` and validate it.
    ///
    /// # Errors
    ///
    /// Returns an error if the overlay cannot be assembled, as for
    /// [`overlay_with_exposes`], or if the assembled overlay does not validate,
    /// which is what a caller offering a deliberately illegal expose is testing for.
    pub fn overlay_offering(expose: VpcExpose) -> Result<ValidatedOverlay, ConfigError> {
        overlay_with(expose)?.validate()
    }

    /// Build the fixed two-vpc overlay around a single `expose`.
    ///
    /// # Errors
    ///
    /// Returns an error if the overlay cannot be assembled, as for
    /// [`overlay_with_exposes`].
    pub fn overlay_with(expose: VpcExpose) -> Result<Overlay, ConfigError> {
        overlay_with_exposes(vec![expose])
    }

    /// Build the fixed two-vpc overlay whose local manifest offers `exposes`.
    ///
    /// # Errors
    ///
    /// Returns an error if either vpc is rejected by the [`VpcTable`], or if the
    /// peering between them is rejected by the [`VpcPeeringTable`].
    pub fn overlay_with_exposes(exposes: Vec<VpcExpose>) -> Result<Overlay, ConfigError> {
        overlay_with_exposes_in_group(exposes, "default")
    }

    /// Build the fixed two-vpc overlay, with the peering handed to a named gateway group.
    ///
    /// Which group owns a peering decides whether a given gateway renders it at all, so
    /// a caller testing that distinction needs to say.
    ///
    /// # Errors
    ///
    /// Returns an error if either vpc is rejected by the [`VpcTable`], or if the
    /// peering between them is rejected by the [`VpcPeeringTable`].
    pub fn overlay_with_exposes_in_group(
        exposes: Vec<VpcExpose>,
        gwgroup: &str,
    ) -> Result<Overlay, ConfigError> {
        let remote_prefix = match exposes
            .first()
            .and_then(|expose| expose.ips.first().map(PrefixWithOptionalPorts::prefix))
        {
            Some(Prefix::IPV6(_)) => "2001:db8:ffff::/64",
            _ => "3.3.3.0/24",
        };

        let remote = vec![
            VpcExpose::empty().ip(remote_prefix
                .parse::<Prefix>()
                .unwrap_or_else(|_| unreachable!())
                .into()),
        ];

        overlay_between(exposes, remote, gwgroup)
    }

    /// Build the fixed two-vpc overlay from both sides' exposes.
    ///
    /// `gwgroup` names the gateway group that owns the peering, which is what decides
    /// whether a given gateway renders it.
    ///
    /// # Errors
    ///
    /// Returns an error if either vpc is rejected by the [`VpcTable`], or if the
    /// peering between them is rejected by the [`VpcPeeringTable`].
    pub fn overlay_between(
        local: Vec<VpcExpose>,
        remote: Vec<VpcExpose>,
        gwgroup: &str,
    ) -> Result<Overlay, ConfigError> {
        let mut vpc_table = VpcTable::new();
        vpc_table.add(Vpc::new("VPC-1", "AAAAA", LOCAL_VNI)?)?;
        vpc_table.add(Vpc::new("VPC-2", "BBBBB", REMOTE_VNI)?)?;

        let local = local
            .into_iter()
            .fold(VpcManifest::new("VPC-1"), VpcManifest::exposing);
        let remote = remote
            .into_iter()
            .fold(VpcManifest::new("VPC-2"), VpcManifest::exposing);
        let mut peerings = VpcPeeringTable::new();
        peerings.add(VpcPeering::new(
            "VPC-1--VPC-2",
            local,
            remote,
            gwgroup.to_string(),
        ))?;

        Ok(Overlay::new(vpc_table, peerings))
    }

    #[must_use]
    pub const fn peer_vni(n: u8) -> u32 {
        REMOTE_VNI + n as u32
    }

    #[must_use]
    pub fn peer_prefix(n: u8) -> Prefix {
        let octet = u16::from(n) + 1;
        format!("10.{octet}.0.0/16")
            .parse()
            .unwrap_or_else(|_| unreachable!("a well-formed prefix"))
    }

    pub fn overlay_with_peers(local: Prefix, peers: u8) -> Result<Overlay, ConfigError> {
        assert!(peers > 0, "a local vpc with no peers has nowhere to send");
        assert!(peers <= 254, "more peers than distinct second octets");

        let mut vpc_table = VpcTable::new();
        vpc_table.add(Vpc::new("VPC-1", "AAAAA", LOCAL_VNI)?)?;

        let mut peerings = VpcPeeringTable::new();
        for n in 0..peers {
            let name = format!("PEER-{n}");
            vpc_table.add(Vpc::new(&name, &format!("P{n:04}"), peer_vni(n))?)?;
            peerings.add(VpcPeering::with_default_group(
                &format!("VPC-1--{name}"),
                VpcManifest::new("VPC-1").exposing(VpcExpose::empty().ip(local.into())),
                VpcManifest::new(&name).exposing(VpcExpose::empty().ip(peer_prefix(n).into())),
            ))?;
        }

        Ok(Overlay::new(vpc_table, peerings))
    }

    #[must_use]
    pub fn peering_acl(default: AclAction, allow: AclProtoMatch) -> Acl {
        Acl::new(
            default,
            vec![AclRule {
                name: "allow-one-protocol".to_owned(),
                from: "VPC-1".to_owned(),
                to: "VPC-2".to_owned(),
                action: match default {
                    AclAction::Allow => AclAction::Deny,
                    AclAction::Deny => AclAction::Allow,
                },
                pattern: AclPattern {
                    src: PrefixPortsSet::new(),
                    dst: PrefixPortsSet::new(),
                    src_any_ports: Vec::new(),
                    dst_any_ports: Vec::new(),
                    proto: allow,
                },
                scope: AclScope::Packet,
                log: false,
            }],
        )
    }

    pub fn overlay_with_exposes_and_acl(
        exposes: Vec<VpcExpose>,
        acl: Option<&Acl>,
    ) -> Result<Overlay, ConfigError> {
        let mut overlay = overlay_with_exposes(exposes)?;
        for peering in overlay.peering_table.values_mut() {
            peering.acl = acl.cloned();
        }
        Ok(overlay)
    }

    #[must_use]
    pub fn nat_config(expose: &VpcExpose) -> Option<&VpcExposeNatConfig> {
        expose.nat_config()
    }

    fn v4_pair<D: Driver>(driver: &mut D, host_bits: u8) -> Option<(Prefix, Prefix)> {
        let len = 32 - host_bits;
        let mask = u32::MAX.checked_shl(u32::from(host_bits)).unwrap_or(0);
        let internal = (0x0A00_0000 | (driver.produce::<u32>()? & 0x00FF_FFFF)) & mask;
        let external = (0xAC10_0000 | (driver.produce::<u32>()? & 0x000F_FFFF)) & mask;
        Some((prefix_v4(internal, len)?, prefix_v4(external, len)?))
    }

    const INTERNAL_BASE: u128 = 0x2001_0db8_0000_0000_0000_0000_0000_0000;
    const EXTERNAL_BASE: u128 = 0x2001_0db8_0001_0000_0000_0000_0000_0000;

    fn v6_pair<D: Driver>(driver: &mut D, host_bits: u8) -> Option<(Prefix, Prefix)> {
        let len = 128 - host_bits;
        let mask = u128::MAX.checked_shl(u32::from(host_bits)).unwrap_or(0);
        let internal = (INTERNAL_BASE | u128::from(driver.produce::<u64>()?)) & mask;
        let external = (EXTERNAL_BASE | u128::from(driver.produce::<u64>()?)) & mask;
        Some((prefix_v6(internal, len)?, prefix_v6(external, len)?))
    }

    fn prefix_v4(bits: u32, len: u8) -> Option<Prefix> {
        Ipv4Prefix::new(Ipv4Addr::from_bits(bits), len)
            .ok()
            .map(Prefix::from)
    }

    fn prefix_v6(bits: u128, len: u8) -> Option<Prefix> {
        Ipv6Prefix::new(Ipv6Addr::from_bits(bits), len)
            .ok()
            .map(Prefix::from)
    }

    fn port_range<D: Driver>(driver: &mut D, count: u16) -> Option<PortRange> {
        let last_start = u16::MAX - (count - 1);
        let start = driver.gen_u16(Included(&1), Included(&last_start))?;
        PortRange::new(start, start + (count - 1)).ok()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn every_generated_expose_validates() {
            bolero::check!()
                .with_generator(PortForwardingExpose::default())
                .for_each(|expose: &VpcExpose| {
                    let validated = expose.validate();
                    assert!(
                        validated.is_ok(),
                        "generated expose was rejected: {expose} -- {:?}",
                        validated.err()
                    );
                });
        }

        fn forwarding(internal: (&str, u16, u16), external: (&str, u16, u16)) -> VpcExpose {
            let side = |(prefix, first, last): (&str, u16, u16)| {
                PrefixWithOptionalPorts::new(
                    prefix.into(),
                    Some(PortRange::new(first, last).unwrap_or_else(|_| unreachable!())),
                )
            };
            VpcExpose::empty()
                .make_port_forwarding(None, None)
                .unwrap_or_else(|_| unreachable!())
                .ip(side(internal))
                .as_range(side(external))
                .unwrap_or_else(|_| unreachable!())
        }

        #[test]
        fn compensating_sizes_do_not_make_a_valid_expose() {
            let expose = forwarding(("10.0.0.0/32", 1000, 1099), ("172.16.0.0/30", 2000, 2024));
            assert!(
                matches!(
                    expose.validate(),
                    Err(ConfigError::MismatchedPrefixLengths {
                        private: 32,
                        public: 30
                    })
                ),
                "a /32 with 100 ports opposite a /30 with 25 was accepted: {:?}",
                expose.validate()
            );
        }

        #[test]
        fn port_ranges_of_different_sizes_do_not_make_a_valid_expose() {
            let expose = forwarding(("10.0.0.0/32", 1000, 1099), ("172.16.0.0/32", 2000, 2049));
            assert!(
                matches!(
                    expose.validate(),
                    Err(ConfigError::MismatchedPortRangeSizes {
                        private: 100,
                        public: 50
                    })
                ),
                "100 ports opposite 50 was accepted: {:?}",
                expose.validate()
            );
        }

        #[test]
        fn matched_sides_still_make_a_valid_expose() {
            let expose = forwarding(("10.0.0.0/30", 1000, 1099), ("172.16.0.0/30", 2000, 2099));
            assert!(expose.validate().is_ok(), "{:?}", expose.validate());
        }

        #[test]
        fn every_generated_masquerade_expose_validates() {
            bolero::check!()
                .with_generator(MasqueradeExpose::default())
                .for_each(|expose: &VpcExpose| {
                    let validated = expose.validate().unwrap_or_else(|e| {
                        panic!("generated expose was rejected: {expose} -- {e:?}")
                    });
                    assert!(validated.has_masquerade());
                    assert!(!validated.ips().is_empty());
                    assert!(!validated.as_range_or_empty().is_empty());
                });
        }

        #[test]
        fn a_generated_expose_can_be_offered_in_an_overlay() {
            bolero::check!()
                .with_generator(MasqueradeExpose::default())
                .cloned()
                .for_each(|expose: VpcExpose| {
                    let shown = expose.to_string();
                    assert!(
                        overlay_offering(expose).is_ok(),
                        "could not build an overlay around {shown}"
                    );
                });
        }

        /// Below this many cases a rate says nothing, so the health checks stay quiet.
        ///
        /// The point is a replay: `bolero` reruns a single recorded input to reproduce a
        /// failure, and an aggregate assertion evaluated over one sample fails whenever
        /// that sample happens not to be the interesting one. That turns every replay of
        /// a valid input into a spurious failure and buries the real one.
        const ENOUGH_CASES: usize = 200;

        #[test]
        fn every_generated_static_nat_expose_validates() {
            let mut seen = 0usize;
            let mut shapes_differed = 0usize;
            bolero::check!()
                .with_generator(StaticNatExpose::default())
                .for_each(|expose: &VpcExpose| {
                    let validated = expose.validate().unwrap_or_else(|e| {
                        panic!("generated expose was rejected: {expose} -- {e:?}")
                    });
                    assert!(validated.has_static_nat());
                    seen += 1;
                    if validated.ips().len() != validated.as_range_or_empty().len() {
                        shapes_differed += 1;
                    }
                });
            println!("{shapes_differed} of {seen} exposes had a different shape on each side");
            if seen > ENOUGH_CASES {
                assert!(
                    shapes_differed > 0,
                    "none of {seen} generated exposes had a different number of prefixes on each \
                     side, so the mapping was never asked to fragment"
                );
            }
        }

        #[test]
        fn a_generated_expose_survives_validation_as_port_forwarding() {
            bolero::check!()
                .with_generator(PortForwardingExpose::default())
                .for_each(|expose: &VpcExpose| {
                    let validated = expose.validate().unwrap_or_else(|e| panic!("{e:?}"));
                    assert!(validated.has_port_forwarding());
                    assert_eq!(validated.ips().len(), 1);
                    assert_eq!(validated.as_range_or_empty().len(), 1);
                });
        }
    }
}
