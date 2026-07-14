// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Access Control Lists (ACLs)

use super::vpcpeering::ValidatedManifest;
use crate::ConfigError;
use crate::utils::normalize;
use lpm::prefix::{PortRange, Prefix, PrefixPortsSet, PrefixWithOptionalPorts};
use match_action::RangeSpec;
use net::ip::NextHeader;
use tracing::debug;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AclAction {
    Allow,
    #[default]
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AclProtoMatch {
    Tcp,
    Udp,
    Other(u8),
    #[default]
    Any,
}

const TCP: u8 = NextHeader::TCP.as_u8();
const UDP: u8 = NextHeader::UDP.as_u8();

impl From<AclProtoMatch> for RangeSpec<u8> {
    fn from(proto: AclProtoMatch) -> Self {
        match proto {
            AclProtoMatch::Tcp => RangeSpec::new(TCP, TCP),
            AclProtoMatch::Udp => RangeSpec::new(UDP, UDP),
            AclProtoMatch::Other(p) => RangeSpec::new(p, p),
            AclProtoMatch::Any => RangeSpec::new(0, u8::MAX),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AclPattern {
    pub src: PrefixPortsSet,
    pub dst: PrefixPortsSet,
    /// Port ranges for match entries that specified neither `cidr` nor `vpcSubnet`, meaning "any
    /// address within the peering, restricted to these ports". These can't be resolved into
    /// concrete prefixes until the peering's manifests are known, so they're materialized into
    /// `src`/`dst` during [`AclRule::validate_patterns_coverage`] rather than at conversion time.
    pub src_any_ports: Vec<PortRange>,
    pub dst_any_ports: Vec<PortRange>,
    pub proto: AclProtoMatch,
}

impl AclPattern {
    #[must_use]
    pub(crate) fn new(
        src: PrefixPortsSet,
        dst: PrefixPortsSet,
        src_any_ports: Vec<PortRange>,
        dst_any_ports: Vec<PortRange>,
        proto: AclProtoMatch,
    ) -> Self {
        Self {
            src,
            dst,
            src_any_ports,
            dst_any_ports,
            proto,
        }
    }

    fn validate_ports(&self) -> bool {
        match self.proto {
            AclProtoMatch::Tcp | AclProtoMatch::Udp => true,
            AclProtoMatch::Other(_) | AclProtoMatch::Any => {
                !self.src.uses_ports()
                    && !self.dst.uses_ports()
                    && self.src_any_ports.is_empty()
                    && self.dst_any_ports.is_empty()
            }
        }
    }

    fn validate(mut self) -> Result<ValidatedAclPattern, ConfigError> {
        if !self.validate_ports() {
            return Err(ConfigError::InvalidAcl(format!(
                "Protocol {:?} does not support port matching",
                self.proto
            )));
        }
        if !PrefixPortsSet::have_consistent_ip_version(&[&self.src, &self.dst]) {
            return Err(ConfigError::InvalidAcl(format!(
                "Source and/or destination prefixes have inconsistent IP versions: {:?}, {:?}",
                self.src, self.dst
            )));
        }
        normalize(&mut self.src);
        normalize(&mut self.dst);
        Ok(ValidatedAclPattern {
            src: self.src,
            dst: self.dst,
            proto: self.proto,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ValidatedAclPattern {
    src: PrefixPortsSet,
    dst: PrefixPortsSet,
    proto: AclProtoMatch,
}

impl ValidatedAclPattern {
    #[must_use]
    pub fn src(&self) -> &PrefixPortsSet {
        &self.src
    }

    #[must_use]
    pub fn dst(&self) -> &PrefixPortsSet {
        &self.dst
    }

    #[must_use]
    pub fn proto(&self) -> AclProtoMatch {
        self.proto
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AclScope {
    #[default]
    Flow,
    Packet,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AclRule {
    pub name: String,
    pub from: String,
    pub to: String,
    pub action: AclAction,
    pub pattern: AclPattern,
    pub scope: AclScope,
    pub log: bool,
}

impl AclRule {
    #[must_use]
    pub(crate) fn new(
        name: String,
        from: String,
        to: String,
        action: AclAction,
        pattern: AclPattern,
        scope: AclScope,
        log: bool,
    ) -> Self {
        Self {
            name,
            from,
            to,
            action,
            pattern,
            scope,
            log,
        }
    }

    // The k8s CRD converter completes a rule's `from`/`to` against the peering's two VPC names
    // before an `AclRule` is ever built (see `converters::k8s::config::acl::complete_from_to`).
    fn validate_from_to(
        &self,
        manifest_left: &ValidatedManifest,
        manifest_right: &ValidatedManifest,
    ) -> Result<(), ConfigError> {
        match (self.from.as_str(), self.to.as_str()) {
            (from, to) if from == manifest_left.name() && to == manifest_right.name() => Ok(()),
            (from, to) if from == manifest_right.name() && to == manifest_left.name() => Ok(()),
            _ => Err(ConfigError::InvalidAcl(format!(
                "Rule '{}' has invalid 'from'/'to' fields: '{}' -> '{}', expected the peering's two VPCs '{}' and '{}'",
                self.name,
                self.from,
                self.to,
                manifest_left.name(),
                manifest_right.name(),
            ))),
        }
    }

    fn validate(
        self,
        manifest_left: &ValidatedManifest,
        manifest_right: &ValidatedManifest,
    ) -> Result<ValidatedAclRule, ConfigError> {
        self.validate_from_to(manifest_left, manifest_right)?;
        let src_any_ports = self.pattern.src_any_ports.clone();
        let dst_any_ports = self.pattern.dst_any_ports.clone();
        let pattern = self.pattern.validate()?;
        let mut validated_rule = ValidatedAclRule {
            name: self.name,
            from: self.from,
            to: self.to,
            action: self.action,
            pattern,
            scope: self.scope,
            log: self.log,
        };
        validated_rule.validate_patterns_coverage(
            manifest_left,
            manifest_right,
            &src_any_ports,
            &dst_any_ports,
        )?;
        Ok(validated_rule)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ValidatedAclRule {
    name: String,
    from: String,
    to: String,
    action: AclAction,
    pattern: ValidatedAclPattern,
    scope: AclScope,
    log: bool,
}

impl ValidatedAclRule {
    #[must_use]
    pub fn action(&self) -> AclAction {
        self.action
    }

    #[must_use]
    pub fn pattern(&self) -> &ValidatedAclPattern {
        &self.pattern
    }

    #[must_use]
    pub fn log(&self) -> bool {
        self.log
    }

    #[must_use]
    pub fn scope(&self) -> AclScope {
        self.scope
    }

    // This function assumes that validate_from_to has already been called, so exactly one of
    // from/to matches manifest_left/manifest_right
    fn manifest_to<'a>(
        &self,
        manifest_left: &'a ValidatedManifest,
        manifest_right: &'a ValidatedManifest,
    ) -> &'a ValidatedManifest {
        if self.to == manifest_left.name() {
            manifest_left
        } else {
            manifest_right
        }
    }

    // This function assumes that validate_from_to has already been called, so exactly one of
    // from/to matches manifest_left/manifest_right
    fn manifest_from<'a>(
        &self,
        manifest_left: &'a ValidatedManifest,
        manifest_right: &'a ValidatedManifest,
    ) -> &'a ValidatedManifest {
        if self.from == manifest_left.name() {
            manifest_left
        } else {
            manifest_right
        }
    }

    /// Materialize "any address within the peering, restricted to these ports" entries into
    /// concrete prefixes, one per port range per prefix advertised by `manifest_prefixes`.
    fn expand_any_ports(manifest_prefixes: &PrefixPortsSet, ports: &[PortRange]) -> PrefixPortsSet {
        ports
            .iter()
            .flat_map(|port| {
                manifest_prefixes
                    .iter()
                    .map(move |p| PrefixWithOptionalPorts::new(p.prefix(), Some(*port)))
            })
            .collect()
    }

    fn manifest_coverage_set(
        manifest: &ValidatedManifest,
        is_v4: bool,
        is_public: bool,
    ) -> PrefixPortsSet {
        if manifest.has_default_expose() {
            [PrefixWithOptionalPorts::from(if is_v4 {
                Prefix::root_v4()
            } else {
                Prefix::root_v6()
            })]
            .into()
        } else if is_public {
            manifest.all_public_ips()
        } else {
            manifest.all_ips()
        }
    }

    fn validate_pattern_coverage(
        name: &str,
        prefixes_acl: &mut PrefixPortsSet,
        prefixes_manifest: &PrefixPortsSet,
    ) -> Result<(), ConfigError> {
        // If the list of prefixes is empty, it means we match all prefixes from the manifest.
        if prefixes_acl.is_empty() {
            *prefixes_acl = prefixes_manifest.clone();
            return Ok(());
        }

        // If the ACL prefixes don't match any of the manifest prefixes, reject it.
        let intersection = prefixes_acl.intersection_prefixes_and_ports(prefixes_manifest);
        if intersection.is_empty() {
            return Err(ConfigError::InvalidAcl(format!(
                "ACL rule '{name}' has a 'match' that does not match any traffic in the manifest: {prefixes_acl:?} vs {prefixes_manifest:?}",
            )));
        }

        // If some addresses/ports covered by the ACL fall outside of the scope of the manifest, log
        // a message, and restrict the ACL to the manifest scope.
        if intersection.total_prefixes_size() != prefixes_acl.total_prefixes_size() {
            debug!(
                "ACL rule '{name}' has a 'match' that doesn't fully covers the manifest traffic: {prefixes_acl:?} vs {prefixes_manifest:?}",
            );
            *prefixes_acl = intersection;
        }
        Ok(())
    }

    fn validate_patterns_coverage(
        &mut self,
        manifest_left: &ValidatedManifest,
        manifest_right: &ValidatedManifest,
        src_any_ports: &[PortRange],
        dst_any_ports: &[PortRange],
    ) -> Result<(), ConfigError> {
        // A default-only manifest's is_v4()/is_v6() are always false, so fall back to the other side
        let is_v4 = if manifest_left.is_default_only() {
            manifest_right.is_v4()
        } else {
            manifest_left.is_v4()
        };

        let manifest_from = self.manifest_from(manifest_left, manifest_right);
        let src_set = Self::manifest_coverage_set(manifest_from, is_v4, false);
        let any = Self::expand_any_ports(&src_set, src_any_ports);
        self.pattern.src = self.pattern.src.union_prefixes_and_ports(&any);
        Self::validate_pattern_coverage(&self.name, &mut self.pattern.src, &src_set)?;

        let manifest_to = self.manifest_to(manifest_left, manifest_right);
        let dst_set = Self::manifest_coverage_set(manifest_to, is_v4, true);
        let any = Self::expand_any_ports(&dst_set, dst_any_ports);
        self.pattern.dst = self.pattern.dst.union_prefixes_and_ports(&any);
        Self::validate_pattern_coverage(&self.name, &mut self.pattern.dst, &dst_set)?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Acl {
    default: AclAction,
    rules: Vec<AclRule>,
}

impl Acl {
    #[must_use]
    pub(crate) fn new(default: AclAction, rules: Vec<AclRule>) -> Self {
        Self { default, rules }
    }

    #[must_use]
    pub fn default_action(&self) -> AclAction {
        self.default
    }

    #[must_use]
    pub fn rules(&self) -> &[AclRule] {
        &self.rules
    }

    fn validate_rules_names(&self) -> Result<(), ConfigError> {
        let mut seen_names = std::collections::HashSet::new();
        for rule in &self.rules {
            if rule.name.is_empty() {
                continue;
            }
            if !seen_names.insert(&rule.name) {
                return Err(ConfigError::InvalidAcl(format!(
                    "Duplicate non-empty ACL rule name: '{}'",
                    rule.name
                )));
            }
        }
        Ok(())
    }

    /// Validate the ACL rules.
    ///
    /// # Errors
    ///
    /// Returns an error if any of the rules are invalid, or if there are duplicate rule names.
    pub fn validate(
        &self,
        manifest_left: &ValidatedManifest,
        manifest_right: &ValidatedManifest,
    ) -> Result<ValidatedAcl, ConfigError> {
        if self.rules.is_empty() {
            return Err(ConfigError::InvalidAcl(
                "ACL list must contain at least one rule".to_string(),
            ));
        }
        self.validate_rules_names()?;
        let rules = self
            .rules
            .iter()
            .map(|rule| rule.clone().validate(manifest_left, manifest_right))
            .collect::<Result<_, _>>()?;
        Ok(ValidatedAcl {
            rules,
            default_action: self.default,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAcl {
    rules: Vec<ValidatedAclRule>,
    default_action: AclAction,
}

impl ValidatedAcl {
    #[must_use]
    pub fn rules(&self) -> &[ValidatedAclRule] {
        &self.rules
    }

    #[must_use]
    pub fn default_action(&self) -> AclAction {
        self.default_action
    }
}

// =================================================================================================
// ACL validation tests
//
// These tests cover the expected semantics and restrictions for ACL rules attached to a VPC peering
// (the from/to directions, protocol/port consistency, IP version consistency, and coverage of the
// rule patterns against the peering manifests).
// =================================================================================================
#[cfg(test)]
mod validation_tests {
    use super::{Acl, AclAction, AclPattern, AclProtoMatch, AclRule, AclScope};
    use crate::ConfigError;
    use crate::external::overlay::acl::ValidatedAclRule;
    use crate::external::overlay::vpcpeering::{ValidatedManifest, VpcExpose, VpcManifest};

    use lpm::prefix::{PortRange, Prefix, PrefixPortsSet, PrefixWithOptionalPorts};

    // Helper: build a validated manifest, exposing the given (no-NAT) prefixes
    fn manifest(name: &str, ips: &[&str]) -> ValidatedManifest {
        let mut expose = VpcExpose::empty();
        for ip in ips {
            expose = expose.ip((*ip).into());
        }
        VpcManifest::with_exposes(name, vec![expose])
            .validate()
            .unwrap()
    }

    // Helper: build a validated manifest with only a default expose (no concrete prefixes)
    fn default_manifest(name: &str) -> ValidatedManifest {
        VpcManifest::with_exposes(name, vec![VpcExpose::empty().set_default()])
            .validate()
            .unwrap()
    }

    // Helper: the standard two-side peering used by most tests
    // VPC-1 owns 10.0.0.0/16, VPC-2 owns 10.1.0.0/16
    fn manifests() -> (ValidatedManifest, ValidatedManifest) {
        (
            manifest("VPC-1", &["10.0.0.0/16"]),
            manifest("VPC-2", &["10.1.0.0/16"]),
        )
    }

    // Helper: build a PrefixPortsSet from a list of CIDR strings (no port restriction)
    fn prefixes(entries: &[&str]) -> PrefixPortsSet {
        entries
            .iter()
            .map(|p| PrefixWithOptionalPorts::new(Prefix::from(*p), None))
            .collect()
    }

    // Helper: a single prefix with a port range
    fn prefix_with_ports(prefix_str: &str, start: u16, end: u16) -> PrefixWithOptionalPorts {
        PrefixWithOptionalPorts::new(
            Prefix::from(prefix_str),
            Some(PortRange::new(start, end).unwrap()),
        )
    }

    // Helper: assemble an AclPattern
    fn pattern(src: PrefixPortsSet, dst: PrefixPortsSet, proto: AclProtoMatch) -> AclPattern {
        AclPattern {
            src,
            dst,
            src_any_ports: Vec::new(),
            dst_any_ports: Vec::new(),
            proto,
        }
    }

    // Helper: assemble an AclRule
    fn rule(name: &str, from: &str, to: &str, action: AclAction, pattern: AclPattern) -> AclRule {
        AclRule {
            name: name.to_owned(),
            from: from.to_owned(),
            to: to.to_owned(),
            action,
            pattern,
            scope: AclScope::Flow,
            log: false,
        }
    }

    // Helper: validate a single rule against the standard peering, returning the (possibly
    // completed/restricted) rule on success
    fn validate_rule(rule: AclRule) -> Result<ValidatedAclRule, ConfigError> {
        let (left, right) = manifests();
        rule.validate(&left, &right)
    }

    // Helper: a pattern matching all traffic in the rule's direction (empty src/dst, any proto)
    fn match_all() -> AclPattern {
        pattern(
            PrefixPortsSet::new(),
            PrefixPortsSet::new(),
            AclProtoMatch::Any,
        )
    }

    // =============================================================================================
    // from/to direction validation
    // =============================================================================================

    // Explicit from/to naming the two peering sides passes
    #[test]
    fn test_acl_from_to_explicit_passes() {
        let rule = rule("r", "VPC-1", "VPC-2", AclAction::Allow, match_all());
        assert!(validate_rule(rule).is_ok());
    }

    // Explicit from/to with the sides swapped passes
    #[test]
    fn test_acl_from_to_swapped_passes() {
        let rule = rule("r", "VPC-2", "VPC-1", AclAction::Allow, match_all());
        assert!(validate_rule(rule).is_ok());
    }

    #[test]
    fn test_acl_to_blank_rejected() {
        let rule = rule("r", "VPC-1", "", AclAction::Allow, match_all());
        let result = validate_rule(rule);
        assert!(
            matches!(result, Err(ConfigError::InvalidAcl(_))),
            "{result:?}"
        );
    }

    #[test]
    fn test_acl_from_blank_rejected() {
        let rule = rule("r", "", "VPC-2", AclAction::Allow, match_all());
        let result = validate_rule(rule);
        assert!(
            matches!(result, Err(ConfigError::InvalidAcl(_))),
            "{result:?}"
        );
    }

    // Omitting both "from" and "to" is rejected
    #[test]
    fn test_acl_both_from_and_to_empty_rejected() {
        let rule = rule("r", "", "", AclAction::Allow, match_all());
        let result = validate_rule(rule);
        assert!(
            matches!(result, Err(ConfigError::InvalidAcl(_))),
            "{result:?}"
        );
    }

    // A "from" value that is not one of the peering's two VPCs is rejected
    #[test]
    fn test_acl_unknown_from_rejected() {
        let rule = rule("r", "VPC-X", "VPC-2", AclAction::Allow, match_all());
        let result = validate_rule(rule);
        assert!(
            matches!(result, Err(ConfigError::InvalidAcl(_))),
            "{result:?}"
        );
    }

    // A "to" value that is not one of the peering's two VPCs is rejected
    #[test]
    fn test_acl_unknown_to_rejected() {
        let rule = rule("r", "VPC-1", "VPC-X", AclAction::Allow, match_all());
        let result = validate_rule(rule);
        assert!(
            matches!(result, Err(ConfigError::InvalidAcl(_))),
            "{result:?}"
        );
    }

    // Using identical "to" and "from" values is rejected
    #[test]
    fn test_acl_to_from_equal_rejected() {
        let rule = rule("r", "VPC-1", "VPC-1", AclAction::Allow, match_all());
        let result = validate_rule(rule);
        assert!(
            matches!(result, Err(ConfigError::InvalidAcl(_))),
            "{result:?}"
        );
    }

    // =============================================================================================
    // Empty ACL is rejected
    // =============================================================================================

    // Empty ACL is rejected
    #[test]
    fn test_acl_empty_list_rejected() {
        let (left, right) = manifests();
        let acl = Acl {
            default: AclAction::Deny,
            rules: vec![],
        };
        let result = acl.validate(&left, &right);
        assert!(
            matches!(result, Err(ConfigError::InvalidAcl(_))),
            "{result:?}"
        );
    }

    // =============================================================================================
    // Rule name validation (at the ACL level)
    // =============================================================================================

    // Duplicate rule names within an ACL are rejected
    #[test]
    fn test_acl_duplicate_rule_names_rejected() {
        let (left, right) = manifests();
        let acl = Acl {
            default: AclAction::Deny,
            rules: vec![
                rule("dup", "VPC-1", "VPC-2", AclAction::Allow, match_all()),
                rule("dup", "VPC-2", "VPC-1", AclAction::Allow, match_all()),
            ],
        };
        let result = acl.validate(&left, &right);
        assert!(
            matches!(result, Err(ConfigError::InvalidAcl(_))),
            "{result:?}"
        );
    }

    // Distinct rule names within an ACL pass
    #[test]
    fn test_acl_distinct_rule_names_passes() {
        let (left, right) = manifests();
        let acl = Acl {
            default: AclAction::Deny,
            rules: vec![
                rule("forward1", "VPC-1", "VPC-2", AclAction::Allow, match_all()),
                rule("forward2", "VPC-1", "VPC-2", AclAction::Allow, match_all()),
                rule("reverse", "VPC-2", "VPC-1", AclAction::Allow, match_all()),
            ],
        };
        assert!(acl.validate(&left, &right).is_ok());
    }

    // =============================================================================================
    // Protocol / port consistency validation
    // =============================================================================================

    // TCP with port matching passes
    #[test]
    fn test_acl_tcp_with_ports_passes() {
        let p = pattern(
            [prefix_with_ports("10.0.0.0/24", 1024, 2048)].into(),
            [prefix_with_ports("10.1.0.0/24", 443, 443)].into(),
            AclProtoMatch::Tcp,
        );
        let rule = rule("r", "VPC-1", "VPC-2", AclAction::Allow, p);
        assert!(validate_rule(rule).is_ok());
    }

    // UDP with port matching passes
    #[test]
    fn test_acl_udp_with_ports_passes() {
        let p = pattern(
            prefixes(&["10.0.0.0/24"]),
            [prefix_with_ports("10.1.0.0/24", 53, 53)].into(),
            AclProtoMatch::Udp,
        );
        let rule = rule("r", "VPC-1", "VPC-2", AclAction::Allow, p);
        assert!(validate_rule(rule).is_ok());
    }

    // A numeric protocol with port matching is rejected
    #[test]
    fn test_acl_other_proto_with_ports_rejected() {
        let p = pattern(
            [prefix_with_ports("10.0.0.0/24", 80, 80)].into(),
            prefixes(&["10.1.0.0/24"]),
            AclProtoMatch::Other(47),
        );
        let rule = rule("r", "VPC-1", "VPC-2", AclAction::Allow, p);
        let result = validate_rule(rule);
        assert!(
            matches!(result, Err(ConfigError::InvalidAcl(_))),
            "{result:?}"
        );
    }

    // "Any" protocol with port matching is rejected (ports are only meaningful per-protocol)
    #[test]
    fn test_acl_any_proto_with_ports_rejected() {
        let p = pattern(
            prefixes(&["10.0.0.0/24"]),
            [prefix_with_ports("10.1.0.0/24", 443, 443)].into(),
            AclProtoMatch::Any,
        );
        let rule = rule("r", "VPC-1", "VPC-2", AclAction::Allow, p);
        let result = validate_rule(rule);
        assert!(
            matches!(result, Err(ConfigError::InvalidAcl(_))),
            "{result:?}"
        );
    }

    // Unknown protocol without ports passes
    #[test]
    fn test_acl_other_proto_without_ports_passes() {
        let p = pattern(
            prefixes(&["10.0.0.0/24"]),
            prefixes(&["10.1.0.0/24"]),
            AclProtoMatch::Other(47),
        );
        let rule = rule("r", "VPC-1", "VPC-2", AclAction::Allow, p);
        assert!(validate_rule(rule).is_ok());
    }

    // =============================================================================================
    // IP version consistency validation
    // =============================================================================================

    // Mixed IPv4/IPv6 within the "src" set is rejected
    #[test]
    fn test_acl_mixed_src_ip_versions_rejected() {
        let p = pattern(
            prefixes(&["10.0.0.0/24", "2001:db8::/64"]),
            prefixes(&["10.1.0.0/24"]),
            AclProtoMatch::Any,
        );
        let rule = rule("r", "VPC-1", "VPC-2", AclAction::Allow, p);
        let result = validate_rule(rule);
        assert!(
            matches!(result, Err(ConfigError::InvalidAcl(_))),
            "{result:?}"
        );
    }

    // Mixed IPv4/IPv6 within the "dst" set is rejected
    #[test]
    fn test_acl_mixed_dst_ip_versions_rejected() {
        let p = pattern(
            prefixes(&["10.0.0.0/24"]),
            prefixes(&["10.1.0.0/24", "2001:db8::/64"]),
            AclProtoMatch::Any,
        );
        let rule = rule("r", "VPC-1", "VPC-2", AclAction::Allow, p);
        let result = validate_rule(rule);
        assert!(
            matches!(result, Err(ConfigError::InvalidAcl(_))),
            "{result:?}"
        );
    }

    // Mixed IPv4/IPv6 between "src" and "dst" sets is rejected
    #[test]
    fn test_acl_mixed_src_dst_ip_versions_rejected() {
        let p = pattern(
            prefixes(&["10.0.0.0/24"]),
            prefixes(&["2001:db8::/64"]),
            AclProtoMatch::Any,
        );
        let rule = rule("r", "VPC-1", "VPC-2", AclAction::Allow, p);
        let result = validate_rule(rule);
        assert!(
            matches!(result, Err(ConfigError::InvalidAcl(_))),
            "{result:?}"
        );
    }

    // =============================================================================================
    // Pattern coverage validation (src vs from-side, dst vs to-side)
    // =============================================================================================

    // An empty src/dst (the blanket "match all in this direction" rule) is accepted, and the
    // empty sets are filled in with the manifests' prefixes
    #[test]
    fn test_acl_empty_match_covers_manifest() {
        let rule = rule("r", "VPC-1", "VPC-2", AclAction::Allow, match_all());
        let validated = validate_rule(rule).expect("should validate");
        assert_eq!(validated.pattern.src, prefixes(&["10.0.0.0/16"]));
        assert_eq!(validated.pattern.dst, prefixes(&["10.1.0.0/16"]));
    }

    // A src that does not intersect the from-side's addresses is rejected (can never match)
    #[test]
    fn test_acl_src_outside_from_manifest_rejected() {
        let p = pattern(
            prefixes(&["192.168.0.0/24"]),
            prefixes(&["10.1.0.0/24"]),
            AclProtoMatch::Any,
        );
        let rule = rule("r", "VPC-1", "VPC-2", AclAction::Allow, p);
        let result = validate_rule(rule);
        assert!(
            matches!(result, Err(ConfigError::InvalidAcl(_))),
            "{result:?}"
        );
    }

    // A dst that does not intersect the to-side's advertised addresses is rejected
    #[test]
    fn test_acl_dst_outside_to_manifest_rejected() {
        let p = pattern(
            prefixes(&["10.0.0.0/24"]),
            prefixes(&["192.168.0.0/24"]),
            AclProtoMatch::Any,
        );
        let rule = rule("r", "VPC-1", "VPC-2", AclAction::Allow, p);
        let result = validate_rule(rule);
        assert!(
            matches!(result, Err(ConfigError::InvalidAcl(_))),
            "{result:?}"
        );
    }

    // A src broader than the from-side's addresses is accepted, but restricted (clamped) to the
    // intersection with the manifest
    #[test]
    fn test_acl_src_broader_than_manifest_is_restricted() {
        let p = pattern(
            prefixes(&["10.0.0.0/8"]),
            prefixes(&["10.1.0.0/24"]),
            AclProtoMatch::Any,
        );
        let rule = rule("r", "VPC-1", "VPC-2", AclAction::Allow, p);
        let validated = validate_rule(rule).expect("should validate");
        // 10.0.0.0/8 is clamped to VPC-1's 10.0.0.0/16
        assert_eq!(validated.pattern.src, prefixes(&["10.0.0.0/16"]));
    }

    // A fully-specified, in-range rule passes unchanged
    #[test]
    fn test_acl_full_valid_match_passes() {
        let p = pattern(
            prefixes(&["10.0.0.0/24"]),
            prefixes(&["10.1.0.0/24"]),
            AclProtoMatch::Tcp,
        );
        let rule = rule("r", "VPC-1", "VPC-2", AclAction::Allow, p);
        let validated = validate_rule(rule).expect("should validate");
        assert_eq!(validated.pattern.src, prefixes(&["10.0.0.0/24"]));
        assert_eq!(validated.pattern.dst, prefixes(&["10.1.0.0/24"]));
    }

    // =============================================================================================
    // "Any address within the peering" (neither cidr nor vpcSubnet set) match entries
    // =============================================================================================

    // A match entry with neither cidr/vpcSubnet nor ports (an empty entry) matches any address on
    // any port, same as omitting the field entirely.
    #[test]
    fn test_acl_any_address_any_port_covers_manifest() {
        let mut p = match_all();
        p.src_any_ports = vec![]; // no explicit ports: empty src == "match everything"
        let rule = rule("r", "VPC-1", "VPC-2", AclAction::Allow, p);
        let validated = validate_rule(rule).expect("should validate");
        assert_eq!(validated.pattern.src, prefixes(&["10.0.0.0/16"]));
    }

    // A match entry with neither cidr nor vpcSubnet, but with ports set, matches any address
    // advertised by the manifest restricted to those ports -- not literally "any port".
    #[test]
    fn test_acl_any_address_with_ports_restricts_to_manifest_prefixes_and_ports() {
        let mut p = pattern(
            PrefixPortsSet::new(),
            PrefixPortsSet::new(),
            AclProtoMatch::Tcp,
        );
        p.src_any_ports = vec![PortRange::new(443, 443).unwrap()];
        let rule = rule("r", "VPC-1", "VPC-2", AclAction::Allow, p);
        let validated = validate_rule(rule).expect("should validate");
        assert_eq!(
            validated.pattern.src,
            [prefix_with_ports("10.0.0.0/16", 443, 443)].into()
        );
        // dst was left fully unrestricted (empty, no any_ports): still "match everything".
        assert_eq!(validated.pattern.dst, prefixes(&["10.1.0.0/16"]));
    }

    // A protocol that doesn't support ports (e.g. ICMP) rejects an "any address" port-restricted
    // entry just like it rejects a concrete-prefix one.
    #[test]
    fn test_acl_any_address_with_ports_rejected_for_portless_proto() {
        let mut p = pattern(
            PrefixPortsSet::new(),
            PrefixPortsSet::new(),
            AclProtoMatch::Other(1),
        );
        p.src_any_ports = vec![PortRange::new(443, 443).unwrap()];
        let icmp_rule = rule("r", "VPC-1", "VPC-2", AclAction::Allow, p.clone());
        let result = validate_rule(icmp_rule);
        assert!(
            matches!(result, Err(ConfigError::InvalidAcl(_))),
            "{result:?}"
        );

        // same thing for numeric protocols
        p.proto = AclProtoMatch::Other(46);
        let num_rule = rule("r", "VPC-1", "VPC-2", AclAction::Allow, p);
        let result = validate_rule(num_rule);
        assert!(
            matches!(result, Err(ConfigError::InvalidAcl(_))),
            "{result:?}"
        );
    }

    // A default-exposed manifest has no concrete prefixes to resolve "any address" against, so an
    // "any address, these ports" entry on that side must fall back to the address family's root
    // prefix instead of being silently dropped.
    #[test]
    fn test_acl_any_address_with_ports_against_default_expose_resolves_to_root_prefix() {
        // VPC-1 is concrete IPv4, which also tells us the peering's IP family; VPC-2 only has a
        // default expose, so it has no prefixes of its own to fall back on.
        let left = manifest("VPC-1", &["10.0.0.0/16"]);
        let right = default_manifest("VPC-2");

        let mut p = pattern(
            PrefixPortsSet::new(),
            PrefixPortsSet::new(),
            AclProtoMatch::Tcp,
        );
        p.dst_any_ports = vec![PortRange::new(443, 443).unwrap()];
        let rule = rule("r", "VPC-1", "VPC-2", AclAction::Allow, p);

        let validated_rule = rule.validate(&left, &right).expect("should validate");
        assert_eq!(
            validated_rule.pattern().dst(),
            &PrefixPortsSet::from([PrefixWithOptionalPorts::new(
                Prefix::root_v4(),
                Some(PortRange::new(443, 443).unwrap())
            )])
        );
    }

    // =============================================================================================
    // Default ACL values
    // =============================================================================================

    #[test]
    fn test_default_rule_values() {
        let rule = AclRule::default();
        assert_eq!(rule.action, AclAction::Deny);
        assert_eq!(rule.scope, AclScope::Flow);
        assert!(!rule.log);
    }

    // =============================================================================================
    // ACL-level smoke test
    // =============================================================================================

    // A complete ACL with a default action and several valid rules validates, and the accessors
    // report what was configured
    #[test]
    fn test_acl_multiple_rules_passes() {
        let (left, right) = manifests();
        let acl = Acl {
            default: AclAction::Deny,
            rules: vec![
                rule(
                    "web",
                    "VPC-1",
                    "VPC-2",
                    AclAction::Allow,
                    pattern(
                        prefixes(&["10.0.0.0/24"]),
                        [prefix_with_ports("10.1.0.0/24", 443, 443)].into(),
                        AclProtoMatch::Tcp,
                    ),
                ),
                rule("return", "VPC-2", "VPC-1", AclAction::Allow, match_all()),
            ],
        };
        let acl = acl.validate(&left, &right).expect("should validate");
        assert_eq!(acl.default_action(), AclAction::Deny);
        assert_eq!(acl.rules().len(), 2);
    }
}
