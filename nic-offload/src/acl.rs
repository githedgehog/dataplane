// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A peering's ACL as the rule planner takes it (slice 1 step 5c-2,
//! `notes/match-action-dag/slice1-step5/RESULTS.md`, 5c-2 design).
//!
//! The NIC decides one thing of an ACL: **drop exactly when the first matching rule denies**, and
//! pass everything else on. Software runs the ACL again on everything the NIC passes, so passing is
//! always safe; a NIC drop must be a true first-match deny.
//! - A TCP-flags rule (the planner has no flags field) becomes a pass, its flags ignored: each
//!   such rule only grows, so an earlier rule never stops matching what it matched, and a drop is
//!   still a first-match deny. The rule loses offload precision, not correctness.
//! - The table is split by L4 protocol (UDP, TCP, other), because only TCP and UDP packets have
//!   ports, and a NIC pattern matching ports matches only those. Within each table every packet
//!   has the fields its levels key on. The NIC dispatches by protocol first.
//! - The destination VPC is not known in the NIC at the ACL (software's flow filter decides it):
//!   only source VPCs with a single peer, where it is implied, are planned. The rest keep the
//!   per-rule deny path.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use acl_filter::AclFilterContext;
use config::external::overlay::acl::AclAction;
use flow_filter::Destination;
use lpm::prefix::with_ports::PortRange;
use net::vxlan::Vni;
use planner::rules::{Field, Rule, Set, Table};

use crate::program::{Fields, Match, Peering, Prefix, lower};

/// What the NIC does with a packet of a planned ACL.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AclVerdict {
    /// Pass it on: to the rest of the NIC's stages, then software, which runs the ACL again.
    Pass,
    /// Drop it: the first rule it matches denies.
    Deny,
}

/// A peering's ACL as planner tables, one per L4 protocol the NIC dispatches on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedAcl {
    /// The peering: its source VPC's only one.
    pub peering: Peering,
    /// The source VPC: the direction of the peering this ACL is of.
    pub src: Vni,
    /// UDP packets: source, destination, source port, destination port.
    pub udp: Table<AclVerdict>,
    /// TCP packets: as UDP.
    pub tcp: Table<AclVerdict>,
    /// Every other packet: protocol, source, destination.
    pub other: Table<AclVerdict>,
}

/// The fields of the UDP and TCP tables.
pub const PORTED: [Field; 4] = [
    Field {
        name: "src",
        width: 32,
    },
    Field {
        name: "dst",
        width: 32,
    },
    Field {
        name: "sport",
        width: 16,
    },
    Field {
        name: "dport",
        width: 16,
    },
];

/// The fields of the table of other protocols.
pub const UNPORTED: [Field; 3] = [
    Field {
        name: "proto",
        width: 8,
    },
    Field {
        name: "src",
        width: 32,
    },
    Field {
        name: "dst",
        width: 32,
    },
];

/// IP protocol numbers.
const TCP: u8 = 6;
const UDP: u8 = 17;

fn prefix(p: Prefix) -> Option<Set> {
    match p {
        Prefix::V4(addr, len) => Some(Set::prefix(u128::from(u32::from(addr)), len, 32)),
        Prefix::V6(..) => None,
    }
}

fn ports(range: Option<PortRange>) -> Set {
    range.map_or_else(
        || Set::any(16),
        |r| Set::range(u128::from(r.start()), u128::from(r.end())),
    )
}

/// The ACLs to plan: every single-peer source VPC's, if each of its rules lowers and none logs
/// or is IPv6. Returns them, and their peerings (whose rules the per-rule deny path then skips).
#[must_use]
pub fn planned(
    acls: &AclFilterContext,
    destinations: &[Destination],
) -> (Vec<PlannedAcl>, BTreeSet<(Vni, Vni)>) {
    let mut peers: BTreeMap<Vni, BTreeSet<Vni>> = BTreeMap::new();
    for d in destinations {
        peers.entry(d.src_vni).or_default().insert(d.dst_vni);
    }
    // IPv6 rules, and logged ones, keep their peering on the per-rule path.
    let unplannable: BTreeSet<Peering> = acls
        .v6()
        .iter()
        .map(|row| Peering::new(row.rule.src_vni.value, row.rule.dst_vni.value))
        .chain(
            acls.v4()
                .iter()
                .filter(|row| row.action.logs())
                .map(|row| Peering::new(row.rule.src_vni.value, row.rule.dst_vni.value)),
        )
        .collect();
    let mut planned = Vec::new();
    for (&src, dsts) in &peers {
        let [dst] = dsts.iter().copied().collect::<Vec<_>>()[..] else {
            continue;
        };
        let peering = Peering::new(src, dst);
        if unplannable.contains(&peering) {
            continue;
        }
        let rows: Vec<_> = acls
            .v4()
            .iter()
            .filter(|row| row.rule.src_vni.value == src && row.rule.dst_vni.value == dst)
            .collect();
        if rows.is_empty() {
            continue;
        }
        let matches: Option<Vec<(Match, AclVerdict)>> = rows
            .iter()
            .map(|row| {
                let matches = lower(
                    &Fields::from(&row.rule),
                    |p| Prefix::V4(p.value, p.len),
                    true,
                )
                .ok()?;
                let verdict =
                    if row.action.action() == AclAction::Deny && matches.tcp_flags.is_none() {
                        AclVerdict::Deny
                    } else {
                        AclVerdict::Pass
                    };
                Some((matches, verdict))
            })
            .collect();
        let Some(matches) = matches else { continue };
        let Some(acl) = tables(peering, src, &matches) else {
            continue;
        };
        planned.push(acl);
    }
    // By direction: the other direction's source VPC may have other peers, and keep its denies.
    let directions = planned
        .iter()
        .map(|acl: &PlannedAcl| (acl.src, acl.peering.other(acl.src)))
        .collect();
    (planned, directions)
}

/// The three tables of `rules` (a peering's, in first-match order). `None` if a rule is IPv6.
fn tables(peering: Peering, src: Vni, rules: &[(Match, AclVerdict)]) -> Option<PlannedAcl> {
    let table = |fields: &[Field]| Table {
        fields: fields.to_vec(),
        rules: Vec::new(),
        default: AclVerdict::Pass,
    };
    let (mut udp, mut tcp, mut other) = (table(&PORTED), table(&PORTED), table(&UNPORTED));
    for (m, verdict) in rules {
        let (src, dst) = (prefix(m.source)?, prefix(m.destination)?);
        let ported = Rule {
            matches: vec![
                src.clone(),
                dst.clone(),
                ports(m.src_port),
                ports(m.dst_port),
            ],
            action: *verdict,
        };
        match m.proto {
            Some(UDP) => udp.rules.push(ported),
            Some(TCP) => tcp.rules.push(ported),
            // Ports name TCP or UDP only (`lower` refuses them otherwise).
            Some(proto) => other.rules.push(Rule {
                matches: vec![Set::exact(u128::from(proto)), src, dst],
                action: *verdict,
            }),
            None => {
                udp.rules.push(ported.clone());
                tcp.rules.push(ported);
                other.rules.push(Rule {
                    matches: vec![Set::any(8), src, dst],
                    action: *verdict,
                });
            }
        }
    }
    Some(PlannedAcl {
        peering,
        src,
        udp,
        tcp,
        other,
    })
}

impl PlannedAcl {
    /// What the NIC decides for an IPv4 packet: the first rule's verdict of its protocol's table.
    #[must_use]
    pub fn decide(&self, proto: u8, src: Ipv4Addr, dst: Ipv4Addr, ports: (u16, u16)) -> AclVerdict {
        let (src, dst) = (u128::from(u32::from(src)), u128::from(u32::from(dst)));
        match proto {
            UDP => *self
                .udp
                .first_match(&[src, dst, u128::from(ports.0), u128::from(ports.1)]),
            TCP => *self
                .tcp
                .first_match(&[src, dst, u128::from(ports.0), u128::from(ports.1)]),
            proto => *self.other.first_match(&[u128::from(proto), src, dst]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vni(v: u32) -> Vni {
        Vni::new_checked(v).unwrap_or_else(|_| unreachable!())
    }

    fn rule(proto: Option<u8>, dst: (Ipv4Addr, u8), dport: Option<u16>, flags: bool) -> Match {
        Match {
            src_vni: vni(300),
            source: Prefix::V4(Ipv4Addr::UNSPECIFIED, 0),
            destination: Prefix::V4(dst.0, dst.1),
            proto,
            src_port: None,
            dst_port: dport.map(PortRange::single),
            tcp_flags: flags.then_some((0x02, 0x02)),
        }
    }

    /// The per-rule deny path refuses a deny an earlier allow overlaps; the planner takes the
    /// order as it is. And per protocol: an allow of UDP doesn't shadow the deny for TCP.
    #[test]
    fn a_deny_after_an_overlapping_allow_is_decided_in_order() {
        let net = (Ipv4Addr::new(10, 0, 2, 0), 24);
        let half = (Ipv4Addr::new(10, 0, 2, 0), 25);
        let rules = [
            (rule(Some(UDP), half, Some(5000), false), AclVerdict::Pass),
            (rule(None, net, None, false), AclVerdict::Deny),
        ];
        let acl = tables(Peering::new(vni(300), vni(400)), vni(300), &rules)
            .unwrap_or_else(|| unreachable!());
        let src = Ipv4Addr::new(10, 0, 1, 1);
        let low = Ipv4Addr::new(10, 0, 2, 1);
        let high = Ipv4Addr::new(10, 0, 2, 200);
        assert_eq!(acl.decide(UDP, src, low, (1, 5000)), AclVerdict::Pass);
        assert_eq!(acl.decide(UDP, src, low, (1, 5001)), AclVerdict::Deny);
        assert_eq!(acl.decide(UDP, src, high, (1, 5000)), AclVerdict::Deny);
        assert_eq!(acl.decide(TCP, src, low, (1, 5000)), AclVerdict::Deny);
        assert_eq!(acl.decide(1, src, low, (0, 0)), AclVerdict::Deny);
        assert_eq!(
            acl.decide(UDP, src, Ipv4Addr::new(10, 0, 3, 1), (1, 1)),
            AclVerdict::Pass
        );
    }

    /// A TCP-flags deny is a pass: the planner can't see flags, and a NIC drop must be certain.
    #[test]
    fn a_tcp_flags_deny_passes() {
        let all = (Ipv4Addr::UNSPECIFIED, 0);
        let m = rule(Some(TCP), all, None, true);
        // `planned` gives it Pass: here, the table as `planned` would build it.
        let acl = tables(
            Peering::new(vni(300), vni(400)),
            vni(300),
            &[(m, AclVerdict::Pass)],
        )
        .unwrap_or_else(|| unreachable!());
        let any = Ipv4Addr::new(10, 0, 2, 1);
        assert_eq!(acl.decide(TCP, any, any, (1, 2)), AclVerdict::Pass);
    }

    /// Against a first-match oracle over the original rules: a NIC deny is a first-match deny,
    /// and every first-match deny without TCP flags is a NIC deny.
    #[test]
    fn the_tables_deny_exactly_the_first_match_denies() {
        bolero::check!()
            .with_type::<(Vec<(u8, u8, u8, u16, bool, bool)>, Vec<(u8, u8, u16, u16)>)>()
            .for_each(|(specs, packets)| {
                let protos = [None, Some(TCP), Some(UDP), Some(1)];
                let rules: Vec<(Match, bool, bool)> = specs
                    .iter()
                    .take(12)
                    .map(|&(p, a, len, port, deny, flags)| {
                        let proto = protos[usize::from(p) % protos.len()];
                        let dport = (proto == Some(TCP) || proto == Some(UDP))
                            .then_some(port % 4 + 1)
                            .filter(|_| port % 3 != 0);
                        let flags = flags && proto == Some(TCP);
                        let dst = (Ipv4Addr::new(10, 0, a % 4, 0), 22 + len % 11);
                        (rule(proto, dst, dport, flags), deny, flags)
                    })
                    .collect();
                let verdicts: Vec<(Match, AclVerdict)> = rules
                    .iter()
                    .map(|(m, deny, flags)| {
                        let v = if *deny && !*flags {
                            AclVerdict::Deny
                        } else {
                            AclVerdict::Pass
                        };
                        (m.clone(), v)
                    })
                    .collect();
                let acl = tables(Peering::new(vni(300), vni(400)), vni(300), &verdicts)
                    .unwrap_or_else(|| unreachable!());
                for &(p, last, sport, dport) in packets.iter().take(32) {
                    let proto = [TCP, UDP, 1, 47][usize::from(p) % 4];
                    let dst = Ipv4Addr::new(10, 0, last % 5, last);
                    let ports = if proto == TCP || proto == UDP {
                        (sport % 5, dport % 5)
                    } else {
                        (0, 0)
                    };
                    let nic = acl.decide(proto, Ipv4Addr::new(10, 0, 1, 1), dst, ports);
                    // The oracle: the first original rule the packet matches (flags: a SYN).
                    let first = rules.iter().find(|(m, _, flags)| {
                        let in_dst = match m.destination {
                            Prefix::V4(a, len) => {
                                let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
                                u32::from(dst) & mask == u32::from(a) & mask
                            }
                            Prefix::V6(..) => false,
                        };
                        let in_proto = m.proto.is_none_or(|q| q == proto);
                        let in_port = m
                            .dst_port
                            .is_none_or(|r| r.start() <= ports.1 && ports.1 <= r.end());
                        // Every packet here is a SYN, so a flags rule matches TCP packets.
                        in_dst && in_proto && in_port && (!*flags || proto == TCP)
                    });
                    let software_denies = first.is_some_and(|(_, deny, _)| *deny);
                    if nic == AclVerdict::Deny {
                        assert!(
                            software_denies,
                            "the NIC drops what software allows: {proto} {dst} {ports:?}"
                        );
                    }
                    if software_denies && first.is_some_and(|(_, _, flags)| !*flags) {
                        assert_eq!(
                            nic,
                            AclVerdict::Deny,
                            "a certain deny passed: {proto} {dst} {ports:?}"
                        );
                    }
                }
            });
    }
}
