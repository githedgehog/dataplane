// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Ordered gateway-wide rules on traffic as it arrives from a VPC, ahead of everything else.
//!
//! A rule matches only what a packet carries when it arrives (its source VPC, addresses,
//! protocol, ports and TCP flags), never where it is going or what flow it is on: the decision is
//! the same whatever state the gateway holds, so a NIC can take it in front of software exactly.
//! That is what makes these rules the gateway's first defence against floods: masquerade,
//! port forwarding and stateful ACLs all depend on flow state, which no stateless NIC rule sees.
//!
//! The first matching rule drops the packet or charges a named meter, which drops what it colors
//! red. Meters count the outer IP packets VPC traffic arrives in, VXLAN included, as the NIC does.

use super::acl::{AclPattern, ValidatedAclPattern};
use super::ratelimit::Meter;
use super::vpc::ValidatedVpcTable;
use crate::ConfigError;
use net::vxlan::Vni;
use std::collections::BTreeMap;

/// What a matching rule does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngressAction {
    /// Drop the packet.
    Drop,
    /// Charge the named meter, and drop what it colors red.
    Police(String),
}

/// One rule, in its configured order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressRule {
    /// The source VPC, by name, or every VPC.
    pub from: Option<String>,
    pub pattern: AclPattern,
    pub action: IngressAction,
}

/// Named meters and the ordered rules that drop or charge them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IngressPolicy {
    pub meters: BTreeMap<String, Meter>,
    pub rules: Vec<IngressRule>,
}

impl IngressPolicy {
    /// Validate meter references, VPC names and matches, and expand each rule to the VPCs and IP
    /// families it matches.
    ///
    /// # Errors
    ///
    /// Rejects meters without a profile, unknown meters and VPCs, and invalid matches.
    pub fn validate(
        &self,
        vpcs: &ValidatedVpcTable,
    ) -> Result<ValidatedIngressPolicy, ConfigError> {
        let invalid = |detail: String| ConfigError::InvalidIngressPolicy(detail);
        for (name, meter) in &self.meters {
            if name.is_empty() || (meter.bytes.is_none() && meter.packets.is_none()) {
                return Err(invalid(format!(
                    "meter {name:?} needs a name and a profile"
                )));
            }
        }
        let mut rules = Vec::new();
        for (index, rule) in self.rules.iter().enumerate() {
            if let IngressAction::Police(meter) = &rule.action
                && !self.meters.contains_key(meter)
            {
                return Err(invalid(format!("rule {index}: unknown meter {meter:?}")));
            }
            let from: Vec<(Vni, &str)> = match &rule.from {
                Some(name) => {
                    let vpc = vpcs
                        .get_vpc(name)
                        .ok_or_else(|| invalid(format!("rule {index}: unknown VPC {name:?}")))?;
                    vec![(vpc.vni(), name.as_str())]
                }
                None => vpcs.values().map(|v| (v.vni(), v.name())).collect(),
            };
            let patterns = rule
                .pattern
                .validate_unbounded()
                .map_err(|e| invalid(format!("rule {index}: {e}")))?;
            for (vni, name) in from {
                for pattern in &patterns {
                    rules.push(ValidatedIngressRule {
                        index,
                        from: vni,
                        pattern: pattern.clone(),
                        action: rule.action.clone(),
                        description: format!("rule {index} from {name}: {pattern:?}"),
                    });
                }
            }
        }
        Ok(ValidatedIngressPolicy {
            meters: self.meters.clone(),
            rules,
        })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// A rule for one source VPC and one IP family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedIngressRule {
    /// The configured rule it came from.
    pub index: usize,
    pub from: Vni,
    pub pattern: ValidatedAclPattern,
    pub action: IngressAction,
    pub description: String,
}

/// Validated named meters and ordered rules, in first-match order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidatedIngressPolicy {
    pub meters: BTreeMap<String, Meter>,
    pub rules: Vec<ValidatedIngressRule>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::external::overlay::acl::AclProtoMatch;
    use crate::external::overlay::ratelimit::{ColorActions, MeterProfile};
    use crate::external::overlay::vpc::{Vpc, VpcTable};
    use lpm::prefix::{PortRange, Prefix, PrefixWithOptionalPorts};
    use policer::{Profile, Rate};

    fn v4(cidr: &str) -> PrefixWithOptionalPorts {
        PrefixWithOptionalPorts::from(Prefix::from(cidr))
    }

    fn vpcs() -> ValidatedVpcTable {
        let mut vpcs = VpcTable::new();
        vpcs.add(Vpc::new("VPC-1", "AAAAA", 3000).unwrap()).unwrap();
        vpcs.validate().unwrap()
    }

    fn police(meter: &str, from: Option<&str>) -> IngressRule {
        IngressRule {
            from: from.map(str::to_string),
            pattern: AclPattern::default(),
            action: IngressAction::Police(meter.to_string()),
        }
    }

    fn policy(meters: Vec<(&str, Meter)>, rules: Vec<IngressRule>) -> IngressPolicy {
        IngressPolicy {
            meters: meters
                .into_iter()
                .map(|(name, meter)| (name.to_string(), meter))
                .collect(),
            rules,
        }
    }

    /// References are checked here, whoever built the policy (the k8s converter or not): meters
    /// and VPCs must exist, and a meter needs a name and a profile.
    #[test]
    fn unknown_references_and_empty_meters_are_rejected() {
        let rate = Rate::new(std::num::NonZeroU64::new(1000).unwrap());
        let meter = Meter {
            bytes: None,
            packets: Some(MeterProfile {
                profile: Profile::new(rate, 100, None, 0).unwrap(),
                actions: ColorActions::default(),
            }),
        };
        let valid = policy(vec![("m", meter.clone())], vec![police("m", Some("VPC-1"))]);
        // One rule per IP family.
        assert_eq!(valid.validate(&vpcs()).unwrap().rules.len(), 2);
        for invalid in [
            policy(vec![("m", meter.clone())], vec![police("other", None)]),
            policy(vec![("m", meter.clone())], vec![police("m", Some("VPC-2"))]),
            policy(vec![("m", Meter::default())], vec![]),
            policy(vec![("", meter.clone())], vec![]),
        ] {
            assert!(
                matches!(
                    invalid.validate(&vpcs()),
                    Err(ConfigError::InvalidIngressPolicy(_))
                ),
                "{invalid:?}"
            );
        }
    }

    /// A pattern naming no address matches both families; one naming an address only its own,
    /// and an empty side stands for every address of that family.
    #[test]
    fn unbounded_patterns_split_by_family() {
        let any = AclPattern::default().validate_unbounded().unwrap();
        assert_eq!(any.len(), 2);
        let ports = AclPattern {
            dst_any_ports: vec![PortRange::new(53, 53).unwrap()],
            proto: AclProtoMatch::Udp,
            ..AclPattern::default()
        }
        .validate_unbounded()
        .unwrap();
        assert_eq!(ports.len(), 2);
        assert!(
            ports
                .iter()
                .all(|p| p.dst().iter().all(|d| d.ports().is_some()))
        );
        let source = AclPattern {
            src: [v4("192.0.2.0/24")].into(),
            ..AclPattern::default()
        }
        .validate_unbounded()
        .unwrap();
        assert_eq!(source.len(), 1);
        assert!(
            source[0]
                .dst()
                .iter()
                .all(|d| d.prefix() == Prefix::root_v4())
        );
    }
}
