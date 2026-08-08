// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::ops::Bound;

use bolero::{Driver, ValueGenerator};

use crate::bolero::crd::GatewayAgents;
use crate::gateway_agent_crd::{
    GatewayAgent, GatewayAgentPeeringsAclRulesScope, GatewayAgentPeeringsPeeringExpose,
    GatewayAgentPeeringsPeeringExposeAs, GatewayAgentPeeringsPeeringExposeIps,
    GatewayAgentPeeringsPeeringExposeNatMasquerade,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutation {
    None,
    MismatchPortForwardPrefixes,
    MismatchStaticNatPrefixes,
    ExcludeFromPortForwarding,
    MixAddressFamilies,
    UseReservedPrefix,
    EmptyPrivatePrefixes,
    DropTranslationRange,
    MakeBothSidesStateful,
    NameAMissingGroup,
    NameAStrangerInARule,
    DemandFlowScope,
    UsePortZero,
}

impl Mutation {
    pub const COUNT: usize = 13;

    #[must_use]
    pub fn index(self) -> usize {
        Self::all()
            .iter()
            .position(|other| *other == self)
            .unwrap_or_else(|| unreachable!())
    }

    #[must_use]
    pub fn all() -> Vec<Self> {
        vec![
            Self::None,
            Self::MismatchPortForwardPrefixes,
            Self::MismatchStaticNatPrefixes,
            Self::ExcludeFromPortForwarding,
            Self::MixAddressFamilies,
            Self::UseReservedPrefix,
            Self::EmptyPrivatePrefixes,
            Self::DropTranslationRange,
            Self::MakeBothSidesStateful,
            Self::NameAMissingGroup,
            Self::NameAStrangerInARule,
            Self::DemandFlowScope,
            Self::UsePortZero,
        ]
    }
}

fn lengthen(cidr: &str, by: u8) -> Option<String> {
    let (address, len) = cidr.split_once('/')?;
    let len: u8 = len.parse().ok()?;
    let max = if address.contains(':') { 128 } else { 32 };
    let longer = len.saturating_add(by).min(max);
    if longer == len {
        return None;
    }
    Some(format!("{address}/{longer}"))
}

fn exposes_mut(agent: &mut GatewayAgent) -> Vec<&mut GatewayAgentPeeringsPeeringExpose> {
    agent
        .spec
        .peerings
        .iter_mut()
        .flatten()
        .flat_map(|(_, peerings)| peerings.peering.iter_mut().flatten())
        .flat_map(|(_, manifest)| manifest.expose.iter_mut().flatten())
        .collect()
}

fn is_port_forwarding(expose: &GatewayAgentPeeringsPeeringExpose) -> bool {
    expose
        .nat
        .as_ref()
        .is_some_and(|nat| nat.port_forward.is_some())
}

fn is_static(expose: &GatewayAgentPeeringsPeeringExpose) -> bool {
    expose
        .nat
        .as_ref()
        .is_some_and(|nat| nat.r#static.is_some())
}

#[allow(clippy::too_many_lines)]
pub fn apply<D: Driver>(d: &mut D, agent: &mut GatewayAgent, mutation: Mutation) -> Option<bool> {
    let bit = match mutation {
        Mutation::None => false,

        Mutation::MismatchPortForwardPrefixes | Mutation::MismatchStaticNatPrefixes => {
            let wanted: fn(&GatewayAgentPeeringsPeeringExpose) -> bool =
                if mutation == Mutation::MismatchPortForwardPrefixes {
                    is_port_forwarding
                } else {
                    is_static
                };
            let mut done = false;
            for expose in exposes_mut(agent) {
                if !wanted(expose) {
                    continue;
                }
                if let Some(entry) = expose.r#as.iter_mut().flatten().next()
                    && let Some(cidr) = entry.cidr.as_ref()
                    && let Some(longer) = lengthen(cidr, 2)
                {
                    entry.cidr = Some(longer);
                    done = true;
                    break;
                }
            }
            done
        }

        Mutation::ExcludeFromPortForwarding => {
            let mut done = false;
            for expose in exposes_mut(agent) {
                if !is_port_forwarding(expose) {
                    continue;
                }
                let Some(inside) = expose
                    .ips
                    .iter()
                    .flatten()
                    .find_map(|ip| ip.cidr.as_ref())
                    .and_then(|cidr| lengthen(cidr, 1))
                else {
                    continue;
                };
                expose.ips.get_or_insert_with(Vec::new).push(
                    GatewayAgentPeeringsPeeringExposeIps {
                        cidr: None,
                        not: Some(inside),
                        vpc_subnet: None,
                    },
                );
                done = true;
                break;
            }
            done
        }

        Mutation::MixAddressFamilies => {
            let mut done = false;
            for expose in exposes_mut(agent) {
                let Some(entry) = expose.ips.iter_mut().flatten().next() else {
                    continue;
                };
                let Some(cidr) = entry.cidr.as_ref() else {
                    continue;
                };
                let other = if cidr.contains(':') {
                    "10.99.0.0/16"
                } else {
                    "2001:db8:9999::/48"
                };
                expose.ips.get_or_insert_with(Vec::new).push(
                    GatewayAgentPeeringsPeeringExposeIps {
                        cidr: Some(other.to_string()),
                        not: None,
                        vpc_subnet: None,
                    },
                );
                done = true;
                break;
            }
            done
        }

        Mutation::UseReservedPrefix => {
            let reserved = ["127.0.0.0/8", "224.0.0.0/4", "0.0.0.0/8", "ff00::/8"];
            let choice =
                reserved[d.gen_usize(Bound::Included(&0), Bound::Excluded(&reserved.len()))?];
            let mut done = false;
            for expose in exposes_mut(agent) {
                if let Some(entry) = expose.ips.iter_mut().flatten().next()
                    && entry.cidr.is_some()
                {
                    entry.cidr = Some(choice.to_string());
                    done = true;
                    break;
                }
            }
            done
        }

        Mutation::EmptyPrivatePrefixes => {
            let mut done = false;
            for expose in exposes_mut(agent) {
                if expose.ips.is_some() {
                    expose.ips = None;
                    done = true;
                    break;
                }
            }
            done
        }

        Mutation::DropTranslationRange => {
            let mut done = false;
            for expose in exposes_mut(agent) {
                if expose.nat.is_some() && expose.r#as.is_some() {
                    expose.r#as = None;
                    done = true;
                    break;
                }
            }
            done
        }

        Mutation::MakeBothSidesStateful => {
            let mut done = false;
            for (_, peerings) in agent.spec.peerings.iter_mut().flatten() {
                let manifests = peerings.peering.iter_mut().flatten();
                let mut touched = 0;
                for (_, manifest) in manifests {
                    for expose in manifest.expose.iter_mut().flatten() {
                        let nat = expose.nat.get_or_insert(
                            crate::gateway_agent_crd::GatewayAgentPeeringsPeeringExposeNat {
                                masquerade: None,
                                port_forward: None,
                                r#static: None,
                            },
                        );
                        nat.port_forward = None;
                        nat.r#static = None;
                        nat.masquerade = Some(GatewayAgentPeeringsPeeringExposeNatMasquerade {
                            idle_timeout: None,
                        });
                        if expose.r#as.is_none() {
                            expose.r#as = Some(vec![GatewayAgentPeeringsPeeringExposeAs {
                                cidr: Some("172.31.0.0/16".to_string()),
                                not: None,
                            }]);
                        }
                    }
                    touched += 1;
                }
                if touched == 2 {
                    done = true;
                    break;
                }
            }
            done
        }

        Mutation::NameAMissingGroup => {
            if let Some((_, peerings)) = agent.spec.peerings.iter_mut().flatten().next() {
                peerings.gateway_group = Some("no-such-group".to_string());
                true
            } else {
                false
            }
        }

        Mutation::NameAStrangerInARule => {
            let mut done = false;
            for (_, peerings) in agent.spec.peerings.iter_mut().flatten() {
                let Some(acl) = peerings.acl.as_mut() else {
                    continue;
                };
                if let Some(rule) = acl.rules.iter_mut().flatten().next() {
                    rule.from = Some("not-in-this-peering".to_string());
                    done = true;
                    break;
                }
            }
            done
        }

        Mutation::DemandFlowScope => {
            let mut done = false;
            for (_, peerings) in agent.spec.peerings.iter_mut().flatten() {
                let Some(acl) = peerings.acl.as_mut() else {
                    continue;
                };
                for rule in acl.rules.iter_mut().flatten() {
                    rule.scope = Some(GatewayAgentPeeringsAclRulesScope::Flow);
                    done = true;
                }
                if done {
                    break;
                }
            }
            done
        }

        Mutation::UsePortZero => {
            let mut done = false;
            for expose in exposes_mut(agent) {
                let Some(nat) = expose.nat.as_mut() else {
                    continue;
                };
                let Some(pf) = nat.port_forward.as_mut() else {
                    continue;
                };
                if let Some(ports) = pf.ports.iter_mut().flatten().next() {
                    ports.port = Some("0-100".to_string());
                    ports.r#as = Some("0-100".to_string());
                    done = true;
                    break;
                }
            }
            done
        }
    };
    Some(bit)
}

#[derive(Debug, Clone, Default)]
pub struct MutatedAgents(GatewayAgents);

impl MutatedAgents {
    #[must_use]
    pub fn new(agents: GatewayAgents) -> Self {
        Self(agents)
    }
}

impl ValueGenerator for MutatedAgents {
    type Output = (Mutation, bool, GatewayAgent);

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        let mut agent = self.0.generate(d)?;
        let all = Mutation::all();
        let mutation = all[d.gen_usize(Bound::Included(&0), Bound::Excluded(&all.len()))?];
        let bit = apply(d, &mut agent, mutation)?;
        Some((mutation, bit, agent))
    }
}
