// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::ops::Bound;

use bolero::{Driver, ValueGenerator};

use crate::bolero::crd::GatewayAgents;
use crate::gateway_agent_crd::{
    GatewayAgent, GatewayAgentPeeringsAclRulesScope, GatewayAgentPeeringsPeering,
    GatewayAgentPeeringsPeeringExpose, GatewayAgentPeeringsPeeringExposeAs,
    GatewayAgentPeeringsPeeringExposeIps, GatewayAgentPeeringsPeeringExposeNatMasquerade,
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
    DuplicateAStaticExpose,
    OverlapWithAnotherPeer,
}

impl Mutation {
    pub const COUNT: usize = 15;

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
            Self::DuplicateAStaticExpose,
            Self::OverlapWithAnotherPeer,
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

fn sibling(cidr: &str) -> Option<String> {
    let (address, len) = cidr.split_once('/')?;
    let len: u8 = len.parse().ok()?;
    if address.contains(':') {
        let bits = address.parse::<std::net::Ipv6Addr>().ok()?.to_bits();
        let flipped = bits ^ (1u128 << (128u8.checked_sub(len)?));
        Some(format!("{}/{len}", std::net::Ipv6Addr::from(flipped)))
    } else {
        let bits = address.parse::<std::net::Ipv4Addr>().ok()?.to_bits();
        let flipped = bits ^ (1u32 << (32u8.checked_sub(len)?));
        Some(format!("{}/{len}", std::net::Ipv4Addr::from(flipped)))
    }
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
fn stateful_throughout(manifest: &GatewayAgentPeeringsPeering) -> bool {
    let exposes = manifest.expose.as_deref().unwrap_or(&[]);
    !exposes.is_empty()
        && exposes.iter().all(|expose| {
            expose
                .nat
                .as_ref()
                .is_some_and(|nat| nat.masquerade.is_some() || nat.port_forward.is_some())
        })
}

fn advertises_its_ips(expose: &GatewayAgentPeeringsPeeringExpose) -> bool {
    expose.nat.is_none()
        && expose.default != Some(true)
        && expose.ips.iter().flatten().all(|ip| ip.not.is_none())
}

fn overlap_with_another_peer(agent: &mut GatewayAgent) -> bool {
    let mut donor: Option<(String, String, String)> = None;
    for (key, peering) in agent.spec.peerings.iter().flatten() {
        let Some(manifests) = peering.peering.as_ref() else {
            continue;
        };
        for shared in manifests.keys() {
            let elsewhere = agent
                .spec
                .peerings
                .iter()
                .flatten()
                .any(|(other, peering)| {
                    other != key
                        && peering
                            .peering
                            .as_ref()
                            .is_some_and(|m| m.contains_key(shared))
                });
            if !elsewhere {
                continue;
            }
            let prefix = manifests
                .iter()
                .filter(|(name, _)| *name != shared)
                .flat_map(|(_, manifest)| manifest.expose.iter().flatten())
                .filter(|expose| advertises_its_ips(expose))
                .flat_map(|expose| expose.ips.iter().flatten())
                .find_map(|ip| ip.cidr.clone());
            if let Some(prefix) = prefix {
                donor = Some((key.clone(), shared.clone(), prefix));
                break;
            }
        }
        if donor.is_some() {
            break;
        }
    }

    let mut done = false;
    if let Some((donor_key, shared, prefix)) = donor {
        for (key, peering) in agent.spec.peerings.iter_mut().flatten() {
            if *key == donor_key {
                continue;
            }
            let Some(manifests) = peering.peering.as_mut() else {
                continue;
            };
            if !manifests.contains_key(&shared) {
                continue;
            }
            let names: Vec<String> = manifests
                .keys()
                .filter(|name| **name != shared)
                .cloned()
                .collect();
            for name in names {
                let Some(manifest) = manifests.get_mut(&name) else {
                    continue;
                };
                if let Some(ip) = manifest
                    .expose
                    .iter_mut()
                    .flatten()
                    .filter(|expose| advertises_its_ips(expose))
                    .flat_map(|expose| expose.ips.iter_mut().flatten())
                    .find(|ip| ip.cidr.is_some())
                {
                    ip.cidr = Some(prefix.clone());
                    done = true;
                    break;
                }
            }
            if done {
                break;
            }
        }
    }
    done
}

fn mutate_peering_metadata(agent: &mut GatewayAgent, mutation: Mutation) -> bool {
    match mutation {
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
                let allowed = peerings
                    .peering
                    .iter()
                    .flatten()
                    .any(|(_, manifest)| stateful_throughout(manifest));
                if allowed {
                    continue;
                }
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
        _ => unreachable!("mutate_peering_metadata called for {mutation:?}"),
    }
}

fn mutate_expose_shape(agent: &mut GatewayAgent, mutation: Mutation) -> bool {
    match mutation {
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
        _ => unreachable!("mutate_expose_shape called for {mutation:?}"),
    }
}

fn duplicate_a_static_expose(agent: &mut GatewayAgent) -> bool {
    for (_, peering) in agent.spec.peerings.iter_mut().flatten() {
        for manifest in peering.peering.iter_mut().flatten().map(|(_, m)| m) {
            let Some(exposes) = manifest.expose.as_mut() else {
                continue;
            };
            let statics: Vec<usize> = exposes
                .iter()
                .enumerate()
                .filter(|(_, expose)| {
                    expose
                        .nat
                        .as_ref()
                        .is_some_and(|nat| nat.r#static.is_some())
                })
                .map(|(index, _)| index)
                .collect();

            let (Some(donor), Some(recipient)) = (statics.first(), statics.get(1)) else {
                continue;
            };
            let mut copy = exposes[*donor].clone();
            let moved = copy
                .r#as
                .as_mut()
                .and_then(|ranges| ranges.first_mut())
                .and_then(|range| {
                    let next_door = sibling(range.cidr.as_ref()?)?;
                    range.cidr = Some(next_door);
                    Some(())
                });
            if moved.is_some() {
                exposes[*recipient] = copy;
                return true;
            }
        }
    }
    false
}

pub fn apply<D: Driver>(d: &mut D, agent: &mut GatewayAgent, mutation: Mutation) -> Option<bool> {
    let bit = match mutation {
        Mutation::None => false,

        Mutation::MismatchPortForwardPrefixes
        | Mutation::MismatchStaticNatPrefixes
        | Mutation::ExcludeFromPortForwarding
        | Mutation::MixAddressFamilies => mutate_expose_shape(agent, mutation),
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

        Mutation::MakeBothSidesStateful
        | Mutation::NameAMissingGroup
        | Mutation::NameAStrangerInARule
        | Mutation::DemandFlowScope => mutate_peering_metadata(agent, mutation),
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

        Mutation::DuplicateAStaticExpose => duplicate_a_static_expose(agent),
        Mutation::OverlapWithAnotherPeer => overlap_with_another_peer(agent),
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
