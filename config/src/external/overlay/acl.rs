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
