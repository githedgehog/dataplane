// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Hostile generators: legal configs with one thing deliberately wrong.
//!
//! Every other generator in this module produces values the system should *accept*.  That leaves
//! the rejection paths -- the ~30 `FromK8sConversionError` and `ConfigError` variants a malformed
//! CRD can provoke -- covered only by hand-written cases.  Those paths matter: config arrives from
//! outside the dataplane, so a malformed `GatewayAgent` must be refused cleanly rather than
//! panicking or half-applying.
//!
//! The mutation is carried *in the generated value* rather than applied by a loop in the test body.
//! That is what makes failures useful: `bolero` can shrink to the smallest config that still
//! exhibits the problem, and the failure report names the mutation that caused it.
//!
//! For that naming to mean anything, a mutation has to trip the guard it is named after rather than
//! some unrelated one.  The ACL mutations are the case worth checking, since they graft a `match`
//! onto a rule whose other fields are whatever the generator drew: a `proto` of, say, `58` makes
//! ports illegal on any rule, and an address match has to intersect what its side exposes.  Both of
//! those are `ValidatedAcl` rules, and every guard these mutations aim at -- `resolve_prefix` for a
//! dangling or doubly-specified subnet, `parse_entry_ports` for an empty list, `parse_port_ranges`
//! for an inverted range -- lives in `AclPattern::try_from`, which runs during conversion and so
//! fails first.  Nothing here needs to pin `proto` or the addresses to keep the labels honest.

use std::collections::BTreeMap;
use std::ops::Bound;

use bolero::{Driver, TypeGenerator};

use crate::bolero::LegalValue;
use crate::gateway_agent_crd::{GatewayAgent, GatewayAgentPeeringsAclRulesMatchSrc};

/// A single, named way to corrupt an otherwise legal [`GatewayAgent`].
///
/// Each variant targets a specific guard in the intake path.  Variants whose target is absent from
/// a given config are no-ops for that config -- see [`Mutated::is_noop`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutation {
    /// Clear `metadata.generation`, which `validate_metadata` requires.
    DropGeneration,
    /// Set `metadata.generation` to zero, which `validate_metadata` rejects explicitly.
    ZeroGeneration,
    /// Clear `metadata.name`.
    DropName,
    /// Blank `metadata.name`; distinct from absent, and separately rejected.
    EmptyName,
    /// Move the object out of the `default` namespace, the only one accepted.
    WrongNamespace,
    /// Clear `spec.gateway`, without which there is no device or underlay to build.
    DropGateway,
    /// Point a peering at a gateway group that does not exist.
    DanglingGatewayGroup,
    /// Name a VPC subnet that does not exist from an ACL match.
    DanglingAclSubnet,
    /// Give two VPCs the same VNI.
    DuplicateVni,
    /// Give two VPCs the same internal id.
    DuplicateVpcInternalId,
    /// Set a VPC's VNI to zero, outside the legal 1..2^24 range.
    ZeroVni,
    /// Corrupt a VPC subnet CIDR's mask beyond its address family.
    OversizeSubnetMask,
    /// Replace a VPC subnet CIDR with text that is not a prefix at all.
    MalformedSubnetCidr,
    /// Set `flowTableCapacity` to zero, which must be a non-zero value.
    ZeroFlowTableCapacity,
    /// Declare a peering over three VPCs; a peering is strictly between two.
    ThreeSidedPeering,
    /// Give an ACL rule a `from` naming neither of the peering's VPCs.
    AclFromUnknownVpc,
    /// Give an ACL match an inverted port range.
    InvertedAclPortRange,
    /// Give an ACL match an unparseable protocol.
    MalformedAclProto,
    /// Present an empty `ports` list, which is rejected rather than read as "all ports".
    EmptyAclPortsList,
    /// Set both `cidr` and `vpcSubnet` on an ACL match entry; they are mutually exclusive.
    AclCidrAndSubnet,
    /// Map a community to a non-numeric priority.
    MalformedCommunityPriority,
    /// Give a gateway group two members with the same name.
    DuplicateGroupMember,
    /// Give a gateway group member an unparseable VTEP address.
    MalformedGroupMemberAddress,
}

/// Every mutation, for the generator to draw from.
const MUTATIONS: &[Mutation] = &[
    Mutation::DropGeneration,
    Mutation::ZeroGeneration,
    Mutation::DropName,
    Mutation::EmptyName,
    Mutation::WrongNamespace,
    Mutation::DropGateway,
    Mutation::DanglingGatewayGroup,
    Mutation::DanglingAclSubnet,
    Mutation::DuplicateVni,
    Mutation::DuplicateVpcInternalId,
    Mutation::ZeroVni,
    Mutation::OversizeSubnetMask,
    Mutation::MalformedSubnetCidr,
    Mutation::ZeroFlowTableCapacity,
    Mutation::ThreeSidedPeering,
    Mutation::AclFromUnknownVpc,
    Mutation::InvertedAclPortRange,
    Mutation::MalformedAclProto,
    Mutation::EmptyAclPortsList,
    Mutation::AclCidrAndSubnet,
    Mutation::MalformedCommunityPriority,
    Mutation::DuplicateGroupMember,
    Mutation::MalformedGroupMemberAddress,
];

/// A [`GatewayAgent`] that was legal until one [`Mutation`] was applied.
///
/// The system must reject this -- or, when the mutation found nothing to corrupt, accept it.  Which
/// of the two is expected is reported by [`Mutated::is_noop`], so a test can assert the strong
/// property (rejected, with a specific error) without treating "nothing to mutate" as a failure.
#[derive(Debug, Clone)]
pub struct Mutated {
    agent: GatewayAgent,
    mutation: Mutation,
    applied: bool,
}

impl Mutated {
    #[must_use]
    pub fn agent(&self) -> &GatewayAgent {
        &self.agent
    }

    #[must_use]
    pub fn mutation(&self) -> Mutation {
        self.mutation
    }

    /// Whether the mutation found nothing to corrupt, leaving the config legal.
    ///
    /// A config with no peerings has no gateway group reference to break, for instance.  Rather
    /// than resample -- which would bias the distribution and complicate shrinking -- the value is
    /// returned as-is and flagged.
    #[must_use]
    pub fn is_noop(&self) -> bool {
        !self.applied
    }
}

/// Mutate the first VPC subnet CIDR found, via `edit`.
///
/// Reports "not applied" when the spec has no peerings, because nothing then reads the subnet:
/// `Vpc::try_from` ignores `subnets` outright, and the CIDRs are parsed only by the overlay
/// converter's `extract_subnets`, which runs only when both VPCs and peerings are present.  A
/// malformed CIDR on an unpeered VPC is therefore accepted as-is, so a mutation there has corrupted
/// nothing the intake path looks at.
fn edit_first_subnet_cidr(agent: &mut GatewayAgent, edit: impl FnOnce(&mut String)) -> bool {
    if agent.spec.peerings.as_ref().is_none_or(BTreeMap::is_empty) {
        return false;
    }
    let Some(vpcs) = agent.spec.vpcs.as_mut() else {
        return false;
    };
    for vpc in vpcs.values_mut() {
        let Some(subnets) = vpc.subnets.as_mut() else {
            continue;
        };
        for subnet in subnets.values_mut() {
            if let Some(cidr) = subnet.cidr.as_mut() {
                edit(cidr);
                return true;
            }
        }
    }
    false
}

/// Mutate the first ACL rule found, via `edit`.
fn edit_first_acl_rule(
    agent: &mut GatewayAgent,
    edit: impl FnOnce(&mut crate::gateway_agent_crd::GatewayAgentPeeringsAclRules),
) -> bool {
    let Some(peerings) = agent.spec.peerings.as_mut() else {
        return false;
    };
    for peering in peerings.values_mut() {
        let Some(acl) = peering.acl.as_mut() else {
            continue;
        };
        let Some(rules) = acl.rules.as_mut() else {
            continue;
        };
        if let Some(rule) = rules.first_mut() {
            edit(rule);
            return true;
        }
    }
    false
}

/// Give the first ACL rule found a `match.src` consisting of the single supplied entry.
fn set_first_acl_src(agent: &mut GatewayAgent, src: GatewayAgentPeeringsAclRulesMatchSrc) -> bool {
    edit_first_acl_rule(agent, |rule| {
        let m = rule.r#match.get_or_insert(
            crate::gateway_agent_crd::GatewayAgentPeeringsAclRulesMatch {
                dst: None,
                proto: None,
                src: None,
            },
        );
        m.src = Some(vec![src]);
    })
}

/// Apply `mutation` to `agent`, reporting whether it found anything to change.
#[allow(clippy::too_many_lines)]
fn apply(agent: &mut GatewayAgent, mutation: Mutation) -> bool {
    match mutation {
        Mutation::DropGeneration => agent.metadata.generation.take().is_some(),
        Mutation::ZeroGeneration => {
            agent.metadata.generation = Some(0);
            true
        }
        Mutation::DropName => agent.metadata.name.take().is_some(),
        Mutation::EmptyName => {
            agent.metadata.name = Some(String::new());
            true
        }
        Mutation::WrongNamespace => {
            agent.metadata.namespace = Some("kube-system".to_string());
            true
        }
        Mutation::DropGateway => agent.spec.gateway.take().is_some(),
        Mutation::DanglingGatewayGroup => {
            let Some(peerings) = agent.spec.peerings.as_mut() else {
                return false;
            };
            let Some(peering) = peerings.values_mut().next() else {
                return false;
            };
            peering.gateway_group = Some("no-such-group".to_string());
            true
        }
        Mutation::DanglingAclSubnet => set_first_acl_src(
            agent,
            GatewayAgentPeeringsAclRulesMatchSrc {
                cidr: None,
                ports: None,
                vpc_subnet: Some("no-such-subnet".to_string()),
            },
        ),
        Mutation::AclCidrAndSubnet => set_first_acl_src(
            agent,
            GatewayAgentPeeringsAclRulesMatchSrc {
                cidr: Some("10.0.0.0/24".to_string()),
                ports: None,
                vpc_subnet: Some("also-a-subnet".to_string()),
            },
        ),
        Mutation::EmptyAclPortsList => set_first_acl_src(
            agent,
            GatewayAgentPeeringsAclRulesMatchSrc {
                cidr: Some("10.0.0.0/24".to_string()),
                ports: Some(Vec::new()),
                vpc_subnet: None,
            },
        ),
        Mutation::InvertedAclPortRange => set_first_acl_src(
            agent,
            GatewayAgentPeeringsAclRulesMatchSrc {
                cidr: Some("10.0.0.0/24".to_string()),
                ports: Some(vec!["9000-80".to_string()]),
                vpc_subnet: None,
            },
        ),
        Mutation::MalformedAclProto => edit_first_acl_rule(agent, |rule| {
            let m = rule.r#match.get_or_insert(
                crate::gateway_agent_crd::GatewayAgentPeeringsAclRulesMatch {
                    dst: None,
                    proto: None,
                    src: None,
                },
            );
            m.proto = Some("not-a-protocol".to_string());
        }),
        Mutation::AclFromUnknownVpc => edit_first_acl_rule(agent, |rule| {
            rule.from = Some("no-such-vpc".to_string());
            rule.to = None;
        }),
        Mutation::DuplicateVni => {
            let Some(vpcs) = agent.spec.vpcs.as_mut() else {
                return false;
            };
            let Some(first_vni) = vpcs.values().next().and_then(|vpc| vpc.vni) else {
                return false;
            };
            // Needs a second VPC to collide with.
            if vpcs.len() < 2 {
                return false;
            }
            #[allow(clippy::unwrap_used)] // len >= 2 checked above
            let second = vpcs.values_mut().nth(1).unwrap();
            if second.vni == Some(first_vni) {
                return false;
            }
            second.vni = Some(first_vni);
            true
        }
        Mutation::DuplicateVpcInternalId => {
            let Some(vpcs) = agent.spec.vpcs.as_mut() else {
                return false;
            };
            if vpcs.len() < 2 {
                return false;
            }
            let Some(first_id) = vpcs.values().next().and_then(|vpc| vpc.internal_id.clone())
            else {
                return false;
            };
            #[allow(clippy::unwrap_used)] // len >= 2 checked above
            let second = vpcs.values_mut().nth(1).unwrap();
            if second.internal_id.as_ref() == Some(&first_id) {
                return false;
            }
            second.internal_id = Some(first_id);
            true
        }
        Mutation::ZeroVni => {
            let Some(vpcs) = agent.spec.vpcs.as_mut() else {
                return false;
            };
            let Some(vpc) = vpcs.values_mut().next() else {
                return false;
            };
            vpc.vni = Some(0);
            true
        }
        Mutation::OversizeSubnetMask => edit_first_subnet_cidr(agent, |cidr| {
            // A v4 prefix cannot have a /33, nor a v6 one a /129.
            let oversize = if cidr.contains(':') { "/129" } else { "/33" };
            if let Some((addr, _)) = cidr.split_once('/') {
                *cidr = format!("{addr}{oversize}");
            }
        }),
        Mutation::MalformedSubnetCidr => edit_first_subnet_cidr(agent, |cidr| {
            *cidr = "definitely/not/a/prefix".to_string();
        }),
        Mutation::ZeroFlowTableCapacity => {
            let Some(gateway) = agent.spec.gateway.as_mut() else {
                return false;
            };
            gateway.flow_table_capacity = Some(0);
            true
        }
        Mutation::ThreeSidedPeering => {
            let Some(peerings) = agent.spec.peerings.as_mut() else {
                return false;
            };
            let Some(peering) = peerings.values_mut().next() else {
                return false;
            };
            let Some(sides) = peering.peering.as_mut() else {
                return false;
            };
            let Some(extra) = sides.values().next().cloned() else {
                return false;
            };
            sides.insert("a-third-vpc".to_string(), extra);
            true
        }
        Mutation::MalformedCommunityPriority => {
            let communities = agent
                .spec
                .communities
                .get_or_insert_with(std::collections::BTreeMap::new);
            communities.insert("not-a-number".to_string(), "65000:999".to_string());
            true
        }
        Mutation::DuplicateGroupMember => {
            let Some(groups) = agent.spec.groups.as_mut() else {
                return false;
            };
            for group in groups.values_mut() {
                let Some(members) = group.members.as_mut() else {
                    continue;
                };
                let Some(first) = members.first().cloned() else {
                    continue;
                };
                members.push(first);
                return true;
            }
            false
        }
        Mutation::MalformedGroupMemberAddress => {
            let Some(groups) = agent.spec.groups.as_mut() else {
                return false;
            };
            for group in groups.values_mut() {
                let Some(members) = group.members.as_mut() else {
                    continue;
                };
                if let Some(member) = members.first_mut() {
                    member.vtep_ip = "300.1.2.3".to_string();
                    return true;
                }
            }
            false
        }
    }
}

impl TypeGenerator for Mutated {
    fn generate<D: Driver>(d: &mut D) -> Option<Self> {
        let mut agent = d.produce::<LegalValue<GatewayAgent>>()?.take();
        let index = d.gen_usize(Bound::Included(&0), Bound::Excluded(&MUTATIONS.len()))?;
        let mutation = MUTATIONS[index];
        let applied = apply(&mut agent, mutation);
        Some(Self {
            agent,
            mutation,
            applied,
        })
    }
}
