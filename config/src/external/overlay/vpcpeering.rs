// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: vpc peering

use crate::external::overlay::acl::Acl;
use crate::utils::{
    check_private_prefixes_dont_overlap, check_public_prefixes_dont_overlap, collapse_prefixes,
    normalize,
};
use concurrency::sync::LazyLock;
use lpm::prefix::{IpRangeWithPorts, L4Protocol, Prefix, PrefixPortsSet, PrefixWithOptionalPorts};
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
        // - a port range is present on each side
        // - the two prefixes are the same length, and the two port ranges the same size
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

            // Matched lengths and matched port counts, rather than the matched *totals* static NAT
            // asks for just above.
            //
            // A total is addresses times ports, so it is equally satisfied by a `/32` carrying 100
            // ports opposite a `/30` carrying 25. A port-forwarding rule cannot express that: it
            // maps one prefix onto another address for address, and one port range onto another
            // positionally. `PortFwEntry::is_valid` duly refuses such a rule -- but it does so
            // while the configuration is being *applied*, at the last of the NAT stages, by which
            // point the kernel interfaces, the flow filter, the ACLs, the static NAT tables and
            // the masquerade allocator have all been committed. The apply then fails and rolls
            // back, which restores the configuration but not the masquerade flows that rebuilding
            // the allocator has already torn down. Refusing the same shape here costs nothing.
            //
            // Single prefixes carrying port ranges, both established above.
            let internal = collapsed_expose
                .ips()
                .first()
                .unwrap_or_else(|| unreachable!());
            let external = collapsed_expose
                .as_range_or_empty()
                .first()
                .unwrap_or_else(|| unreachable!());
            if internal.prefix().length() != external.prefix().length() {
                return Err(ConfigError::MismatchedPrefixLengths {
                    private: internal.prefix().length(),
                    public: external.prefix().length(),
                });
            }
            let internal_ports = internal.ports().unwrap_or_else(|| unreachable!());
            let external_ports = external.ports().unwrap_or_else(|| unreachable!());
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
    //! Generators for the configuration types.
    //!
    //! These exist so that the stages downstream of configuration -- NAT's static, masquerade and
    //! port-forwarding tables -- can be driven by generated configurations rather than by a
    //! handful of hand-written ones.

    use super::{VpcExpose, VpcExposeNatConfig, VpcManifest, VpcPeering, VpcPeeringTable};
    use crate::ConfigError;
    use crate::external::overlay::vpc::{Vpc, VpcTable};
    use crate::external::overlay::{Overlay, ValidatedOverlay};
    use bolero::{Driver, ValueGenerator};
    use lpm::prefix::{
        IpPrefix, Ipv4Prefix, Ipv6Prefix, L4Protocol, PortRange, Prefix, PrefixWithOptionalPorts,
    };
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::ops::Bound::Included;
    use std::time::Duration;

    /// The widest span of addresses either side of a generated expose covers, as host bits.
    ///
    /// Kept small because the two sides are matched address for address: nothing here needs a
    /// large prefix to be interesting, and a large one only makes what consumes it slower.
    const MAX_HOST_BITS: u8 = 8;

    /// The widest port range either side covers. Same reasoning.
    const MAX_PORTS: u16 = 1024;

    /// Generates [`VpcExpose`]s that use port forwarding and that [`VpcExpose::validate`] accepts.
    ///
    /// Valid by construction rather than by generate-and-reject, so every case reaches the code
    /// under test. The rules being satisfied, each of which `validate` enforces:
    ///
    /// * exactly one prefix on each side, and no exclusion prefixes;
    /// * both sides of one address family;
    /// * neither prefix overlapping a special-use block -- hence drawing from `10.0.0.0/8` and
    ///   `172.16.0.0/12` for v4 and from `2001:db8::/32` for v6, which are not reserved here;
    /// * a port range present on each side, since a missing one means every port and port 0 is
    ///   forbidden. Note that [`PrefixWithOptionalPorts::new`] *drops* a range covering all ports,
    ///   turning it into the missing case, so the ranges here are always bounded;
    /// * equal total size on the two sides, where size counts addresses times ports.
    ///
    /// The last of those used to be a product -- addresses times ports -- which a `/32` carrying
    /// 100 ports opposite a `/30` carrying 25 satisfies while being a pairing no port-forwarding
    /// rule can express. Validation compares the two lengths and the two port counts directly now,
    /// so matched sides are the whole legal space rather than a corner of it that this generator
    /// was staying inside. See `tests::compensating_sizes_do_not_make_a_valid_expose`.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct PortForwardingExpose;

    impl ValueGenerator for PortForwardingExpose {
        type Output = VpcExpose;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<VpcExpose> {
            let host_bits = driver.gen_u8(Included(&0), Included(&MAX_HOST_BITS))?;
            let (internal, external) = if driver.produce::<bool>()? {
                v4_pair(driver, host_bits)?
            } else {
                v6_pair(driver, host_bits)?
            };

            // One port count for both sides: equal address counts and equal port counts is what
            // makes the two totals agree, and is what `PortFwEntry` accepts.
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

    /// Generates [`VpcExpose`]s that masquerade and that [`VpcExpose::validate`] accepts.
    ///
    /// Looser than [`PortForwardingExpose`], because masquerade is: several prefixes are allowed on
    /// each side and their sizes need not agree, which is the point of masquerade -- many private
    /// addresses behind few public ones. What it does forbid is port ranges, on either side.
    ///
    /// Prefixes within a side are carved so as not to overlap, since a manifest rejects
    /// overlapping ones, and the two sides are drawn from separate blocks.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct MasqueradeExpose;

    impl ValueGenerator for MasqueradeExpose {
        type Output = VpcExpose;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<VpcExpose> {
            let v4 = driver.produce::<bool>()?;
            let privates = driver.gen_u8(Included(&1), Included(&3))?;
            let publics = driver.gen_u8(Included(&1), Included(&2))?;
            let base = driver.produce::<u8>()?;
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
    }

    #[derive(Clone, Copy)]
    enum Side {
        Private,
        Public,
    }

    // One non-overlapping block per index, from a range that is not special-use.
    fn block(v4: bool, side: Side, index: u8) -> Option<Prefix> {
        if v4 {
            // 10.<index>.0.0/24 and 172.16.<index>.0/24.
            let bits = match side {
                Side::Private => 0x0A00_0000 | (u32::from(index) << 16),
                Side::Public => 0xAC10_0000 | (u32::from(index) << 8),
            };
            prefix_v4(bits, 24)
        } else {
            // 2001:db8:0:<index>::/64 and 2001:db8:1:<index>::/64.
            let selector = match side {
                Side::Private => 0u128,
                Side::Public => 1,
            };
            let bits = (0x2001_0db8u128 << 96) | (selector << 80) | (u128::from(index) << 64);
            prefix_v6(bits, 64)
        }
    }

    /// Generates [`VpcExpose`]s that use static NAT and that [`VpcExpose::validate`] accepts.
    ///
    /// The interesting rule for static NAT is that the two sides must be the same total size while
    /// being free to have completely different shapes: a `/26` on one side can be answered by four
    /// `/28`s on the other. That fragmenting is what `RangeBuilder` exists to work out, so the
    /// generator produces it deliberately -- one total, split independently into a different set
    /// of prefixes per side.
    ///
    /// Sizes stay small so that a property can enumerate every address on both sides rather than
    /// sampling. Parts are placed largest first from an aligned base, which keeps every prefix
    /// aligned to its own size and keeps them from overlapping.
    ///
    /// Addresses only. For the port-range form, which takes the mapping down a different path, see
    /// [`StaticNatExposes::with_ports`].
    #[derive(Debug, Clone, Copy, Default)]
    pub struct StaticNatExpose;

    /// Several static NAT exposes for one manifest, which a manifest will accept together.
    ///
    /// [`StaticNatExpose`] draws one expose, and one expose builds a table with one rule in it.
    /// Several are what give a longest-prefix match anything to choose between, so anything testing
    /// a lookup wants this rather than a repeated draw of the single-expose generator.
    ///
    /// Two independent draws are refused by a manifest almost every time, for two reasons that both
    /// have to be handled here rather than by the caller:
    ///
    /// * **Overlap.** Every expose is laid out from the same two bases, so two of them cover the
    ///   same addresses. Each is placed in a block of its own instead, [`BLOCK_STRIDE`] apart, which
    ///   is wider than the widest span one expose can occupy.
    /// * **Address family.** A peering's manifests must agree on one family, so a v4 expose beside a
    ///   v6 one is refused. The family is drawn once here and shared.
    ///
    /// # Ports
    ///
    /// Static NAT permits a port range on each prefix, and that takes the mapping down a second
    /// path: `NatTableValue::Pat` and `PortAddrTranslationValue` rather than
    /// `NatTableValue::Nat` and `AddrTranslationValue`. The rule validation applies is that the two
    /// sides cover the same **total**, counting addresses times ports -- so a `/32` carrying 64
    /// ports is a legal answer to a `/30` carrying 16, and the mapping has to run across both
    /// dimensions at once.
    ///
    /// That asymmetry is the whole reason the path exists, so [`StaticNatExposes::with_ports`]
    /// draws it deliberately: one total per expose, split into addresses and ports **independently
    /// per side**. Note that this is legal for static NAT and *illegal* for port forwarding, which
    /// requires the two lengths and the two port counts to match individually.
    #[derive(Debug, Clone, Copy)]
    pub struct StaticNatExposes {
        /// The most exposes to draw. The generator draws between one and this.
        pub max: u8,
        /// Whether each prefix carries a port range.
        pub ports: bool,
    }

    impl Default for StaticNatExposes {
        fn default() -> Self {
            Self::addresses_only(3)
        }
    }

    impl StaticNatExposes {
        /// Exposes whose prefixes carry no port range, mapping address to address.
        #[must_use]
        pub fn addresses_only(max: u8) -> Self {
            Self { max, ports: false }
        }

        /// Exposes whose prefixes carry port ranges, mapping address and port together.
        #[must_use]
        pub fn with_ports(max: u8) -> Self {
            Self { max, ports: true }
        }
    }

    /// The largest total either side covers, as a power of two. Small enough to enumerate.
    const MAX_TOTAL_LOG: u8 = 6;

    /// The distance between two blocks.
    ///
    /// A side lays out at most `2^MAX_TOTAL_LOG` addresses, each part followed by a gap of its own
    /// size, so it spans at most twice that. Double it again for room to grow.
    const BLOCK_STRIDE: u128 = 4 << MAX_TOTAL_LOG;

    impl ValueGenerator for StaticNatExpose {
        type Output = VpcExpose;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<VpcExpose> {
            let v4 = driver.produce::<bool>()?;
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

    /// One static NAT expose of the given family, laid out in the given block.
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

    /// One static NAT expose whose two sides carry port ranges.
    ///
    /// One prefix per side rather than a split, because the interesting asymmetry here is between
    /// the two *dimensions* -- how a total is divided between addresses and ports -- and adding a
    /// prefix split on top only makes the case harder to read for no new coverage.
    ///
    /// Each side draws its own division of the same total, so a `/32` carrying 64 ports opposite a
    /// `/30` carrying 16 is a shape this produces on purpose. Both sides' port ranges start at a
    /// drawn offset, so a mapping that quietly assumes the two ranges begin at the same port fails
    /// here rather than in the field.
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

    // Split 2^total_log into powers of two, largest first. Halving a part keeps the total the
    // same, which is what lets the two sides be split independently and still agree.
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

    // Lay the parts out from the side's base, largest first, so each lands on a multiple of its
    // own size and none of them overlap.
    //
    // Each part is followed by a gap of its own size. Placed end to end they would be aligned
    // siblings, and validation normalizes those back into one prefix -- so the shape the generator
    // worked out to differ between the sides would be collapsed away before anything saw it.
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

    /// The VNI of the VPC offering the expose in [`overlay_offering`].
    pub const LOCAL_VNI: u32 = 100;
    /// The VNI of the peer it is offered to.
    pub const REMOTE_VNI: u32 = 200;

    /// A two-VPC overlay whose local side offers `expose`.
    ///
    /// The remote side exposes an unrelated prefix, because a manifest with no exposes is
    /// rejected, and one of the same address family, because a peering's two manifests must agree
    /// on that.
    ///
    /// # Errors
    ///
    /// Returns whatever validating the resulting overlay returns. A generator from this module
    /// produces exposes that pass, so a caller driving one can treat an error as a failure.
    pub fn overlay_offering(expose: VpcExpose) -> Result<ValidatedOverlay, ConfigError> {
        overlay_with(expose)?.validate()
    }

    /// The same two-VPC overlay as [`overlay_offering`], before validation.
    ///
    /// Separate because a caller assembling a whole [`crate::ExternalConfig`] has to hand it an
    /// unvalidated overlay and validate the lot -- validating the overlay alone skips every check
    /// that spans the underlay and the overlay together.
    ///
    /// # Errors
    ///
    /// Returns an error only if the fixed vpcs and peering this builds cannot be assembled, which
    /// would be a bug here rather than anything about `expose`.
    pub fn overlay_with(expose: VpcExpose) -> Result<Overlay, ConfigError> {
        overlay_with_exposes(vec![expose])
    }

    /// The same, with several exposes on the local side.
    ///
    /// Worth having separately because one expose at a time only reaches the checks that look at an
    /// expose on its own. The interesting rejections -- and the interesting things for whatever
    /// consumes the result to get wrong -- are between exposes.
    ///
    /// # Errors
    ///
    /// As [`overlay_with`]. Note that *validating* the result may still fail for reasons that are
    /// about the combination, such as two exposes covering overlapping prefixes, which is a
    /// legitimate rejection rather than a defect.
    pub fn overlay_with_exposes(exposes: Vec<VpcExpose>) -> Result<Overlay, ConfigError> {
        let remote_prefix = match exposes
            .first()
            .and_then(|expose| expose.ips.first().map(PrefixWithOptionalPorts::prefix))
        {
            Some(Prefix::IPV6(_)) => "2001:db8:ffff::/64",
            _ => "3.3.3.0/24",
        };

        let mut vpc_table = VpcTable::new();
        vpc_table.add(Vpc::new("VPC-1", "AAAAA", LOCAL_VNI)?)?;
        vpc_table.add(Vpc::new("VPC-2", "BBBBB", REMOTE_VNI)?)?;

        let local = exposes
            .into_iter()
            .fold(VpcManifest::new("VPC-1"), VpcManifest::exposing);
        let remote = VpcManifest::new("VPC-2").exposing(
            VpcExpose::empty().ip(remote_prefix
                .parse::<Prefix>()
                .unwrap_or_else(|_| unreachable!())
                .into()),
        );
        let mut peerings = VpcPeeringTable::new();
        peerings.add(VpcPeering::with_default_group(
            "VPC-1--VPC-2",
            local,
            remote,
        ))?;

        Ok(Overlay::new(vpc_table, peerings))
    }

    /// Which NAT flavour a generated expose uses, for a caller that wants to branch on it.
    #[must_use]
    pub fn nat_config(expose: &VpcExpose) -> Option<&VpcExposeNatConfig> {
        expose.nat_config()
    }

    // A private and a public prefix of the same length, from blocks that are not special-use.
    fn v4_pair<D: Driver>(driver: &mut D, host_bits: u8) -> Option<(Prefix, Prefix)> {
        let len = 32 - host_bits;
        let mask = u32::MAX.checked_shl(u32::from(host_bits)).unwrap_or(0);
        // 10.0.0.0/8 and 172.16.0.0/12; masking only clears host bits, so the blocks survive.
        let internal = (0x0A00_0000 | (driver.produce::<u32>()? & 0x00FF_FFFF)) & mask;
        let external = (0xAC10_0000 | (driver.produce::<u32>()? & 0x000F_FFFF)) & mask;
        Some((prefix_v4(internal, len)?, prefix_v4(external, len)?))
    }

    // 2001:db8::/32, with the two sides separated so they cannot be the same prefix.
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

    // A range of exactly `count` ports, never starting at 0 and never covering every port.
    fn port_range<D: Driver>(driver: &mut D, count: u16) -> Option<PortRange> {
        // Parenthesised: `start + count - 1` would add before subtracting, and the sum reaches
        // 65536 at the top of the range.
        let last_start = u16::MAX - (count - 1);
        let start = driver.gen_u16(Included(&1), Included(&last_start))?;
        PortRange::new(start, start + (count - 1)).ok()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Everything this generator produces is something `validate` accepts.
        ///
        /// The generator exists to reach the code past validation, so a case that does not get
        /// there is a case wasted -- and silently, since a rejected configuration still counts as
        /// a run.
        #[test]
        fn every_generated_expose_validates() {
            bolero::check!()
                .with_generator(PortForwardingExpose)
                .for_each(|expose: &VpcExpose| {
                    let validated = expose.validate();
                    assert!(
                        validated.is_ok(),
                        "generated expose was rejected: {expose} -- {:?}",
                        validated.err()
                    );
                });
        }

        // A port-forwarding expose from a prefix and an inclusive port range on each side.
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

        /// Sides of different prefix lengths are refused, however their totals work out.
        ///
        /// A total counts addresses times ports, so a `/32` with 100 ports and a `/30` with 25 have
        /// the same one -- which is what a size check alone accepts. A port-forwarding rule maps
        /// address for address and port for port, so it cannot express that pairing, and
        /// `PortFwEntry` refuses it. It used to refuse it during the apply, after the earlier
        /// stages had committed and with a rollback to follow that restores the configuration but
        /// not the flows already torn down. Refused here, none of that happens.
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

        /// Matched prefixes with port ranges of different sizes are refused too.
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

        /// And the matched case still passes, so the two guards are about mismatch rather than
        /// about port forwarding having stopped validating at all.
        #[test]
        fn matched_sides_still_make_a_valid_expose() {
            let expose = forwarding(("10.0.0.0/30", 1000, 1099), ("172.16.0.0/30", 2000, 2099));
            assert!(expose.validate().is_ok(), "{:?}", expose.validate());
        }

        /// The masquerade generator's cases validate too, and stay masquerade.
        ///
        /// Masquerade's own rule is that neither side carries a port range, which is easy to break
        /// by reusing the port-forwarding shape.
        #[test]
        fn every_generated_masquerade_expose_validates() {
            bolero::check!()
                .with_generator(MasqueradeExpose)
                .for_each(|expose: &VpcExpose| {
                    let validated = expose.validate().unwrap_or_else(|e| {
                        panic!("generated expose was rejected: {expose} -- {e:?}")
                    });
                    assert!(validated.has_masquerade());
                    assert!(!validated.ips().is_empty());
                    assert!(!validated.as_range_or_empty().is_empty());
                });
        }

        /// A generated expose can be dropped into an overlay that validates.
        ///
        /// The helper is what every downstream property is built on, so a case it cannot place is
        /// a case none of them see.
        #[test]
        fn a_generated_expose_can_be_offered_in_an_overlay() {
            bolero::check!()
                .with_generator(MasqueradeExpose)
                .cloned()
                .for_each(|expose: VpcExpose| {
                    let shown = expose.to_string();
                    assert!(
                        overlay_offering(expose).is_ok(),
                        "could not build an overlay around {shown}"
                    );
                });
        }

        /// The static NAT generator's cases validate, and the two sides really do differ in shape.
        ///
        /// The second half is the part worth asserting: a generator that always produced one
        /// prefix per side would pass the first half while never exercising the fragmenting that
        /// `RangeBuilder` exists for.
        #[test]
        fn every_generated_static_nat_expose_validates() {
            let mut shapes_differed = false;
            bolero::check!()
                .with_generator(StaticNatExpose)
                .for_each(|expose: &VpcExpose| {
                    let validated = expose.validate().unwrap_or_else(|e| {
                        panic!("generated expose was rejected: {expose} -- {e:?}")
                    });
                    assert!(validated.has_static_nat());
                    if validated.ips().len() != validated.as_range_or_empty().len() {
                        shapes_differed = true;
                    }
                });
            assert!(
                shapes_differed,
                "no generated expose had a different number of prefixes on each side, so the \
                 mapping was never asked to fragment"
            );
        }

        /// And it is port forwarding that comes out the other side, with both sides intact.
        #[test]
        fn a_generated_expose_survives_validation_as_port_forwarding() {
            bolero::check!()
                .with_generator(PortForwardingExpose)
                .for_each(|expose: &VpcExpose| {
                    let validated = expose.validate().unwrap_or_else(|e| panic!("{e:?}"));
                    assert!(validated.has_port_forwarding());
                    assert_eq!(validated.ips().len(), 1);
                    assert_eq!(validated.as_range_or_empty().len(), 1);
                });
        }
    }
}
