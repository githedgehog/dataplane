// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Ordered peering rules selecting shared meters, before NAT.
//!
//! The first matching rule selects one meter. Its byte profile runs before its packet profile;
//! packet metering can only preserve or worsen the byte result. Drops stop processing.

use super::acl::{AclAction, AclPattern, AclRule, AclScope, ValidatedAclPattern};
use super::vpc::ValidatedVpcTable;
use crate::ConfigError;
use net::ip::dscp::Dscp;
use net::vxlan::Vni;
use policer::Profile;
use std::collections::BTreeMap;

/// What happens to a packet of one color.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorAction {
    /// Forward it unchanged.
    Pass,
    /// Forward it with its DSCP rewritten.
    Remark(Dscp),
    /// Drop it.
    Drop,
}

/// What happens to a packet of each color.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColorActions {
    pub green: ColorAction,
    pub yellow: ColorAction,
    pub red: ColorAction,
}

impl Default for ColorActions {
    /// Police: pass what is within the limits, drop the rest.
    fn default() -> Self {
        ColorActions {
            green: ColorAction::Pass,
            yellow: ColorAction::Pass,
            red: ColorAction::Drop,
        }
    }
}

/// One component of a meter, in bytes or packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeterProfile {
    pub profile: Profile,
    pub actions: ColorActions,
}

/// A named meter may enforce both bandwidth and packet-rate limits.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Meter {
    pub bytes: Option<MeterProfile>,
    pub packets: Option<MeterProfile>,
}

/// A directional rule within a peering. Rules retain their configured order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitRule {
    pub peering: String,
    pub from: String,
    pub to: String,
    pub pattern: AclPattern,
    pub meter: String,
}

/// Named meters and the ordered rules that select them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RateLimitTables {
    pub meters: BTreeMap<String, Meter>,
    pub rules: Vec<RateLimitRule>,
}

impl RateLimitTables {
    /// Validate meter references and apply the same peering bounds as ACL matches.
    ///
    /// # Errors
    ///
    /// Rejects empty meters, unknown references, and invalid matches.
    pub fn validate(
        &self,
        vpcs: &ValidatedVpcTable,
    ) -> Result<ValidatedRateLimitTables, ConfigError> {
        for (name, meter) in &self.meters {
            if name.is_empty() || (meter.bytes.is_none() && meter.packets.is_none()) {
                return Err(ConfigError::InvalidRateLimit(format!(
                    "meter {name:?} needs a name and a profile"
                )));
            }
        }
        let mut rules = Vec::new();
        for (index, rule) in self.rules.iter().enumerate() {
            if !self.meters.contains_key(&rule.meter) {
                return Err(ConfigError::InvalidRateLimit(format!(
                    "rule {index} refers to unknown meter {:?}",
                    rule.meter
                )));
            }
            let from = vpcs
                .get_vpc(&rule.from)
                .ok_or_else(|| ConfigError::RateLimitNoSuchVpc {
                    limit: rule.meter.clone(),
                    vpc: rule.from.clone(),
                })?;
            let mut found = false;
            for peering in from
                .peerings()
                .iter()
                .filter(|p| p.name() == rule.peering && p.remote().name() == rule.to)
            {
                found = true;
                let acl = AclRule {
                    name: format!("rate limit {}/{}", rule.peering, index),
                    from: rule.from.clone(),
                    to: rule.to.clone(),
                    pattern: rule.pattern.clone(),
                    action: AclAction::Allow,
                    scope: AclScope::Packet,
                    log: false,
                }
                .validate(peering.local(), peering.remote())?;
                rules.push(ValidatedRateLimitRule {
                    meter: rule.meter.clone(),
                    from: from.vni(),
                    to: peering.remote_vni(),
                    pattern: acl.pattern().clone(),
                    description: format!("{} -> {}: {:?}", rule.from, rule.to, acl.pattern()),
                });
            }
            if !found {
                return Err(ConfigError::InvalidRateLimit(format!(
                    "rule {index} has no peering {} from {} to {}",
                    rule.peering, rule.from, rule.to
                )));
            }
        }
        Ok(ValidatedRateLimitTables {
            meters: self.meters.clone(),
            rules,
        })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.meters.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.meters.is_empty()
    }
}

/// A rule whose VPCs and match have been validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedRateLimitRule {
    pub meter: String,
    pub from: Vni,
    pub to: Vni,
    pub pattern: ValidatedAclPattern,
    pub description: String,
}

/// Validated named meters and ordered matches.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidatedRateLimitTables {
    pub meters: BTreeMap<String, Meter>,
    pub rules: Vec<ValidatedRateLimitRule>,
}
