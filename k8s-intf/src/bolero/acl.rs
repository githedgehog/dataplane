// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::ops::Bound;

use bolero::{Driver, ValueGenerator};

use crate::gateway_agent_crd::{
    GatewayAgentPeeringsAcl, GatewayAgentPeeringsAclDefault, GatewayAgentPeeringsAclRules,
    GatewayAgentPeeringsAclRulesAction, GatewayAgentPeeringsAclRulesMatch,
    GatewayAgentPeeringsAclRulesMatchDst, GatewayAgentPeeringsAclRulesMatchSrc,
    GatewayAgentPeeringsAclRulesScope, GatewayAgentPeeringsPeering,
};

const MAX_RULES: u8 = 3;

#[derive(Debug, Clone)]
pub struct SideFacts {
    pub vpc: String,
    pub native: Vec<String>,
    pub advertised: Vec<String>,
    pub restricts_ports: bool,
    pub all_stateful: bool,
}

impl SideFacts {
    #[must_use]
    pub fn of(vpc: &str, manifest: &GatewayAgentPeeringsPeering) -> Self {
        let exposes = manifest.expose.as_deref().unwrap_or(&[]);
        let mut native = Vec::new();
        let mut advertised = Vec::new();
        let mut restricts_ports = false;
        let mut all_stateful = !exposes.is_empty();

        for expose in exposes {
            let ips: Vec<String> = expose
                .ips
                .iter()
                .flatten()
                .filter_map(|ip| ip.cidr.clone())
                .collect();
            let translations: Vec<String> = expose
                .r#as
                .iter()
                .flatten()
                .filter_map(|entry| entry.cidr.clone())
                .collect();

            native.extend(ips.iter().cloned());
            if translations.is_empty() {
                advertised.extend(ips);
            } else {
                advertised.extend(translations);
            }

            let nat = expose.nat.as_ref();
            if nat.is_some_and(|nat| nat.port_forward.is_some()) {
                restricts_ports = true;
            }
            if !nat.is_some_and(|nat| nat.masquerade.is_some() || nat.port_forward.is_some()) {
                all_stateful = false;
            }
        }

        Self {
            vpc: vpc.to_string(),
            native,
            advertised,
            restricts_ports,
            all_stateful,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AclGenerator {
    left: SideFacts,
    right: SideFacts,
}

impl AclGenerator {
    #[must_use]
    pub fn new(left: SideFacts, right: SideFacts) -> Self {
        Self { left, right }
    }

    fn ports<D: Driver>(d: &mut D) -> Option<Vec<String>> {
        let count = d.gen_u8(Bound::Included(&1), Bound::Included(&2))?;
        let mut out = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let first = d.gen_u16(Bound::Included(&1), Bound::Included(&65535))?;
            if d.produce::<bool>()? {
                out.push(format!("{first}"));
            } else {
                let second = d.gen_u16(Bound::Included(&1), Bound::Included(&65535))?;
                out.push(format!("{}-{}", first.min(second), first.max(second)));
            }
        }
        Some(out)
    }

    fn prefix<D: Driver>(d: &mut D, choices: &[String]) -> Option<String> {
        crate::bolero::support::choose(d, choices)
    }

    fn rule<D: Driver>(&self, d: &mut D, index: u8) -> Option<GatewayAgentPeeringsAclRules> {
        let (from, to) = if d.produce::<bool>()? {
            (&self.left, &self.right)
        } else {
            (&self.right, &self.left)
        };

        let (from_field, to_field) = match d.gen_u8(Bound::Included(&0), Bound::Included(&2))? {
            0 => (Some(from.vpc.clone()), None),
            1 => (None, Some(to.vpc.clone())),
            _ => (Some(from.vpc.clone()), Some(to.vpc.clone())),
        };

        let (proto, may_use_ports) = match d.gen_u8(Bound::Included(&0), Bound::Included(&3))? {
            0 => (None, false),
            1 => (Some("tcp".to_string()), true),
            2 => (Some("udp".to_string()), true),
            _ => (
                Some(
                    d.gen_u8(Bound::Included(&1), Bound::Included(&254))?
                        .to_string(),
                ),
                false,
            ),
        };

        let src_ports = may_use_ports && !from.restricts_ports && d.produce::<bool>()?;
        let dst_ports = may_use_ports && !to.restricts_ports && d.produce::<bool>()?;

        let src_prefix = if d.produce::<bool>()? {
            Self::prefix(d, &from.native)
        } else {
            None
        };
        let dst_prefix = if d.produce::<bool>()? {
            Self::prefix(d, &to.advertised)
        } else {
            None
        };

        let src = if src_prefix.is_some() || src_ports {
            Some(vec![GatewayAgentPeeringsAclRulesMatchSrc {
                cidr: src_prefix,
                ports: if src_ports {
                    Self::ports(d)?.into()
                } else {
                    None
                },
                vpc_subnet: None,
            }])
        } else {
            None
        };
        let dst = if dst_prefix.is_some() || dst_ports {
            Some(vec![GatewayAgentPeeringsAclRulesMatchDst {
                cidr: dst_prefix,
                ports: if dst_ports {
                    Self::ports(d)?.into()
                } else {
                    None
                },
                vpc_subnet: None,
            }])
        } else {
            None
        };

        let r#match = if src.is_some() || dst.is_some() || proto.is_some() {
            Some(GatewayAgentPeeringsAclRulesMatch { dst, proto, src })
        } else {
            None
        };

        let flow_allowed = self.left.all_stateful || self.right.all_stateful;
        let scope = if flow_allowed && d.produce::<bool>()? {
            if d.produce::<bool>()? {
                Some(GatewayAgentPeeringsAclRulesScope::Flow)
            } else {
                None
            }
        } else {
            Some(GatewayAgentPeeringsAclRulesScope::Packet)
        };

        Some(GatewayAgentPeeringsAclRules {
            action: if d.produce::<bool>()? {
                GatewayAgentPeeringsAclRulesAction::Allow
            } else {
                GatewayAgentPeeringsAclRulesAction::Deny
            },
            from: from_field,
            log: Some(d.produce::<bool>()?),
            r#match,
            name: Some(format!("rule{index}")),
            scope,
            to: to_field,
        })
    }
}

impl ValueGenerator for AclGenerator {
    type Output = GatewayAgentPeeringsAcl;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        let count = d.gen_u8(Bound::Included(&1), Bound::Included(&MAX_RULES))?;
        let mut rules = Vec::with_capacity(usize::from(count));
        for index in 0..count {
            rules.push(self.rule(d, index)?);
        }

        Some(GatewayAgentPeeringsAcl {
            default: match d.gen_u8(Bound::Included(&0), Bound::Included(&2))? {
                0 => GatewayAgentPeeringsAclDefault::Deny,
                1 => GatewayAgentPeeringsAclDefault::DenyUnlessExposed,
                _ => GatewayAgentPeeringsAclDefault::KopiumEmpty,
            },
            rules: Some(rules).filter(|r| !r.is_empty()),
        })
    }
}
