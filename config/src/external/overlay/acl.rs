// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Access Control Lists (ACLs)

use super::vpcpeering::ValidatedManifest;
use crate::ConfigError;
use crate::utils::normalize;
use lpm::prefix::PrefixPortsSet;
use tracing::debug;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AclAction {
    Allow,
    #[default]
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AclProtoMatch {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
    #[default]
    Any,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AclPattern {
    src: PrefixPortsSet,
    dst: PrefixPortsSet,
    proto: AclProtoMatch,
}

impl AclPattern {
    #[must_use]
    pub fn src(&self) -> &PrefixPortsSet {
        &self.src
    }

    #[must_use]
    pub fn dst(&self) -> &PrefixPortsSet {
        &self.dst
    }

    #[must_use]
    pub fn proto(&self) -> &AclProtoMatch {
        &self.proto
    }

    fn validate_ports(&self) -> bool {
        match self.proto {
            AclProtoMatch::Tcp | AclProtoMatch::Udp => true,
            AclProtoMatch::Other(_) | AclProtoMatch::Icmp | AclProtoMatch::Any => {
                !self.src.uses_ports() && !self.dst.uses_ports()
            }
        }
    }

    fn validate(&mut self) -> Result<(), ConfigError> {
        if !self.validate_ports() {
            return Err(ConfigError::InvalidAcl(format!(
                "Protocol {:?} does not support port matching",
                self.proto
            )));
        }
        if !self.src.has_consistent_ip_version() {
            return Err(ConfigError::InvalidAcl(format!(
                "Source prefixes have inconsistent IP versions: {:?}",
                self.src
            )));
        }
        if !self.dst.has_consistent_ip_version() {
            return Err(ConfigError::InvalidAcl(format!(
                "Destination prefixes have inconsistent IP versions: {:?}",
                self.dst
            )));
        }
        normalize(&mut self.src);
        normalize(&mut self.dst);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AclRule {
    name: String,
    from: String,
    to: String,
    action: AclAction,
    pattern: AclPattern,
    log: bool,
}

impl AclRule {
    #[must_use]
    pub fn action(&self) -> AclAction {
        self.action
    }

    #[must_use]
    pub fn pattern(&self) -> &AclPattern {
        &self.pattern
    }

    #[must_use]
    pub fn log(&self) -> bool {
        self.log
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

    fn validate_from_to(
        &mut self,
        manifest_left: &ValidatedManifest,
        manifest_right: &ValidatedManifest,
    ) -> Result<(), ConfigError> {
        match (&self.from, &self.to) {
            // Accept if values match the names of the two manifests
            (from, to) if from == manifest_left.name() && to == manifest_right.name() => Ok(()),
            (from, to) if from == manifest_right.name() && to == manifest_left.name() => Ok(()),

            // Accept, and complete, if one value matches a manifest, and the other is empty
            (from, to) if from == manifest_left.name() && to.is_empty() => {
                self.to = manifest_right.name().to_string();
                Ok(())
            }
            (from, to) if from == manifest_right.name() && to.is_empty() => {
                self.to = manifest_left.name().to_string();
                Ok(())
            }
            (from, to) if from.is_empty() && to == manifest_left.name() => {
                self.from = manifest_right.name().to_string();
                Ok(())
            }
            (from, to) if from.is_empty() && to == manifest_right.name() => {
                self.from = manifest_left.name().to_string();
                Ok(())
            }

            // Reject both values empty
            (from, to) if from.is_empty() && to.is_empty() => {
                Err(ConfigError::InvalidAcl(format!(
                    "Rule '{}' must specify at least one of 'from' or 'to' fields",
                    self.name,
                )))
            }
            // Reject if one value is non-empty but does not match either manifest
            _ => Err(ConfigError::InvalidAcl(format!(
                "Rule '{}' has invalid 'from' or 'to' fields: '{}' -> '{}'",
                self.name, self.from, self.to,
            ))),
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
    ) -> Result<(), ConfigError> {
        let manifest_from = self.manifest_from(manifest_left, manifest_right);
        if manifest_from.has_default_expose() {
            // ACL pattern necessarily covers all traffic. Do not restrict the ACL pattern to the
            // manifest's prefixes, we'll use a wildcard match anyway.
        } else {
            let src_set = manifest_from.all_ips();
            Self::validate_pattern_coverage(&self.name, &mut self.pattern.src, &src_set)?;
        }

        let manifest_to = self.manifest_to(manifest_left, manifest_right);
        if manifest_to.has_default_expose() {
            // ACL pattern necessarily covers all traffic. Do not restrict the ACL pattern to the
            // manifest's prefixes, we'll use a wildcard match anyway.
        } else {
            let dst_set = manifest_to.all_public_ips();
            Self::validate_pattern_coverage(&self.name, &mut self.pattern.dst, &dst_set)?;
        }
        Ok(())
    }

    fn validate(
        &mut self,
        manifest_left: &ValidatedManifest,
        manifest_right: &ValidatedManifest,
    ) -> Result<(), ConfigError> {
        self.validate_from_to(manifest_left, manifest_right)?;
        self.pattern.validate()?;
        self.validate_patterns_coverage(manifest_left, manifest_right)?;
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
        &mut self,
        manifest_left: &ValidatedManifest,
        manifest_right: &ValidatedManifest,
    ) -> Result<(), ConfigError> {
        self.validate_rules_names()?;
        for rule in &mut self.rules {
            rule.validate(manifest_left, manifest_right)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAcl {
    rules: Vec<AclRule>,
    default_action: AclAction,
}

impl ValidatedAcl {
    #[must_use]
    pub fn rules(&self) -> &[AclRule] {
        &self.rules
    }

    #[must_use]
    pub fn default_action(&self) -> AclAction {
        self.default_action
    }

    /// Create a validated ACL collection from an unvalidated ACL collection and the two manifests
    /// of a peering.
    ///
    /// # Errors
    ///
    /// - Returns an error if any of the rules are invalid.
    pub fn from_acl(
        acl: &mut Acl,
        manifest_left: &ValidatedManifest,
        manifest_right: &ValidatedManifest,
    ) -> Result<Self, ConfigError> {
        acl.validate(manifest_left, manifest_right)?;
        Ok(Self {
            rules: acl.rules.clone(),
            default_action: acl.default,
        })
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
    use super::{Acl, AclAction, AclPattern, AclProtoMatch, AclRule};
    use crate::ConfigError;
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
        AclPattern { src, dst, proto }
    }

    // Helper: assemble an AclRule
    fn rule(name: &str, from: &str, to: &str, action: AclAction, pattern: AclPattern) -> AclRule {
        AclRule {
            name: name.to_owned(),
            from: from.to_owned(),
            to: to.to_owned(),
            action,
            pattern,
            log: false,
        }
    }

    // Helper: validate a single rule against the standard peering, returning the (possibly
    // completed/restricted) rule on success
    fn validate_rule(mut rule: AclRule) -> Result<AclRule, ConfigError> {
        let (left, right) = manifests();
        rule.validate(&left, &right).map(|()| rule)
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

    // "from" set to the left VPC, "to" omitted: the right VPC is implied
    #[test]
    fn test_acl_from_left_only_completes_to() {
        let rule = rule("r", "VPC-1", "", AclAction::Allow, match_all());
        let validated = validate_rule(rule).expect("should validate");
        assert_eq!(validated.to, "VPC-2");
    }

    // "from" set to the right VPC, "to" omitted: the left VPC is implied
    #[test]
    fn test_acl_from_right_only_completes_to() {
        let rule = rule("r", "VPC-2", "", AclAction::Allow, match_all());
        let validated = validate_rule(rule).expect("should validate");
        assert_eq!(validated.to, "VPC-1");
    }

    // "to" set to the right VPC, "from" omitted: the left VPC is implied
    #[test]
    fn test_acl_to_right_only_completes_from() {
        let rule = rule("r", "", "VPC-2", AclAction::Allow, match_all());
        let validated = validate_rule(rule).expect("should validate");
        assert_eq!(validated.from, "VPC-1");
    }

    // "to" set to the left VPC, "from" omitted: the right VPC is implied
    #[test]
    fn test_acl_to_left_only_completes_from() {
        let rule = rule("r", "", "VPC-1", AclAction::Allow, match_all());
        let validated = validate_rule(rule).expect("should validate");
        assert_eq!(validated.from, "VPC-2");
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
    // Rule name validation (at the ACL level)
    // =============================================================================================

    // Duplicate rule names within an ACL are rejected
    #[test]
    fn test_acl_duplicate_rule_names_rejected() {
        let (left, right) = manifests();
        let mut acl = Acl {
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
        let mut acl = Acl {
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

    // ICMP with port matching is rejected (ICMP has no ports)
    #[test]
    fn test_acl_icmp_with_ports_rejected() {
        let p = pattern(
            prefixes(&["10.0.0.0/24"]),
            [prefix_with_ports("10.1.0.0/24", 443, 443)].into(),
            AclProtoMatch::Icmp,
        );
        let rule = rule("r", "VPC-1", "VPC-2", AclAction::Allow, p);
        let result = validate_rule(rule);
        assert!(
            matches!(result, Err(ConfigError::InvalidAcl(_))),
            "{result:?}"
        );
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

    // ICMP without ports passes
    #[test]
    fn test_acl_icmp_without_ports_passes() {
        let p = pattern(
            prefixes(&["10.0.0.0/24"]),
            prefixes(&["10.1.0.0/24"]),
            AclProtoMatch::Icmp,
        );
        let rule = rule("r", "VPC-1", "VPC-2", AclAction::Allow, p);
        assert!(validate_rule(rule).is_ok());
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

    // Mixed IPv4/IPv6 within the `src` set is rejected
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

    // Mixed IPv4/IPv6 within the `dst` set is rejected
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
    // ACL-level smoke test
    // =============================================================================================

    // A complete ACL with a default action and several valid rules validates, and the accessors
    // report what was configured
    #[test]
    fn test_acl_multiple_rules_passes() {
        let (left, right) = manifests();
        let mut acl = Acl {
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
        assert!(acl.validate(&left, &right).is_ok());
        assert_eq!(acl.default_action(), AclAction::Deny);
        assert_eq!(acl.rules().len(), 2);
    }
}
