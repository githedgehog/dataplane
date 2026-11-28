// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A planned ACL (`crate::acl`) lowered onto mlx5: the rule planner's plans, as groups of a VPC's
//! generation (slice 1 step 5c-2).
//!
//! - **Dispatch** (`Group::AclDispatch`): inner IPv4 UDP, TCP, and any other protocol each enter
//!   their own protocol's plan, its entry step the rule's action. Like the per-rule denies', its
//!   patterns take only unfragmented IPv4 in an untagged inner frame, what software classifies
//!   with ports; everything else passes.
//! - **A level is a group** (`Group::Acl`): its key's parts are pattern items, a field's top bits
//!   as an IPv4 prefix, a protocol mask or a port mask, and a planner register as a TAG register
//!   (`r + 1`: TAG 0 holds the bank). Each entry is a rule; the level's miss, a catch-all behind
//!   them.
//! - **A step** writes its registers (`TagPerRule`), then jumps to its next level, drops (deny:
//!   counted), or goes on as the ACL stage would (pass: the VPC's rate limits, or delivery).
//!   Registers written at the end are dead, and not written.

use dpdk::flow::template::{Complete, Pattern, TemplateAction};
use dpdk::flow::{EthMatch, Ipv4Match, Ipv4Prefix, TcpMatch, UdpMatch};
use net::vxlan::Vni;
use planner::backend::{Backend, Mlx5 as Budget};
use planner::plan::{Part, Plan as Levels, Step, Then};
use planner::rfc::{self, Options};
use planner::rules::Table;
use std::net::Ipv4Addr;

use dpdk::flow::VxlanMatch;

use super::{
    ANY, Arg, Group, Plan, PlannedRule, PlannedTable, Role, VXLAN_PORT, any_pattern, single,
};
use crate::acl::{AclVerdict, PlannedAcl};

/// The packet rate the ACL's plans are sized for: each must fit the NIC's lookups at it.
const PPS: f64 = 50e6;

/// TAG registers 1 to 7 are the planner's (0 holds the bank).
const TAGS: usize = 7;

/// The protocol a planned ACL's plan is of.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AclProto {
    /// IPv4 UDP.
    Udp,
    /// IPv4 TCP.
    Tcp,
    /// Every other packet.
    Other,
}

impl AclProto {
    const ALL: [AclProto; 3] = [AclProto::Udp, AclProto::Tcp, AclProto::Other];

    fn table(self, acl: &PlannedAcl) -> &Table<AclVerdict> {
        match self {
            AclProto::Udp => &acl.udp,
            AclProto::Tcp => &acl.tcp,
            AclProto::Other => &acl.other,
        }
    }
}

/// Why a planned ACL can't be lowered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclUnfit {
    /// The planner made no plan.
    Unplanned(String),
    /// A plan doesn't fit the NIC's budget.
    Budget(String),
    /// A plan needs more registers than TAG has.
    Registers(usize),
}

/// The pattern of a level of `proto`'s plan with key `key`: its template's (`values`: `None`), or
/// a rule's, a value per part. The frame is the VPC's VXLAN, as the switch passed it on.
fn pattern(proto: AclProto, key: &[Part], values: Option<&[u128]>) -> Pattern<Complete> {
    let value = |i: usize| values.map_or(0, |v| v[i]);
    let mut ipv4 = Ipv4Match::default().unfragmented();
    // A port's value and mask, if the key has it.
    let (mut sport, mut dport): (Option<Masked>, Option<Masked>) = (None, None);
    let mut tags: Vec<(u8, u32)> = Vec::new();
    #[allow(clippy::cast_possible_truncation)] // fields are at most 32 bits wide
    for (i, part) in key.iter().enumerate() {
        match (proto, *part) {
            (_, Part::Reg(r)) => tags.push((r + 1, value(i) as u32)),
            // UDP and TCP: src, dst, sport, dport.
            (AclProto::Udp | AclProto::Tcp, Part::Field { field, len }) => match field {
                0 => ipv4 = ipv4.src(Ipv4Prefix::prefix(Ipv4Addr::from(value(i) as u32), len)),
                1 => ipv4 = ipv4.dst(Ipv4Prefix::prefix(Ipv4Addr::from(value(i) as u32), len)),
                2 => sport = Some((value(i) as u16, top(len, 16) as u16)),
                _ => dport = Some((value(i) as u16, top(len, 16) as u16)),
            },
            // Other: proto, src, dst.
            (AclProto::Other, Part::Field { field, len }) => match field {
                0 => ipv4 = ipv4.proto_masked(value(i) as u8, top(len, 8) as u8),
                1 => ipv4 = ipv4.src(Ipv4Prefix::prefix(Ipv4Addr::from(value(i) as u32), len)),
                _ => ipv4 = ipv4.dst(Ipv4Prefix::prefix(Ipv4Addr::from(value(i) as u32), len)),
            },
        }
    }
    // No VNI: the switch rule of the VPC led here.
    let base = Pattern::new()
        .eth(EthMatch::default())
        .ipv4(Ipv4Match::default())
        .udp(UdpMatch::default().dst(VXLAN_PORT))
        .vxlan(VxlanMatch::default())
        .inner_eth(EthMatch::default().tagged(false));
    let pattern = match proto {
        AclProto::Udp => {
            let mut udp = UdpMatch::default();
            if let Some((v, m)) = sport {
                udp = udp.src_masked(v, m);
            }
            if let Some((v, m)) = dport {
                udp = udp.dst_masked(v, m);
            }
            base.ipv4(ipv4.proto(17)).udp(udp).complete()
        }
        AclProto::Tcp => {
            let mut tcp = TcpMatch::default();
            if let Some((v, m)) = sport {
                tcp = tcp.src_masked(v, m);
            }
            if let Some((v, m)) = dport {
                tcp = tcp.dst_masked(v, m);
            }
            base.ipv4(ipv4.proto(6)).tcp(tcp).complete()
        }
        AclProto::Other => base.ipv4(ipv4).complete(),
    };
    tags.into_iter()
        .fold(pattern, |pattern, (index, value)| pattern.tag(index, value))
}

/// A port value, and its mask.
type Masked = (u16, u16);

/// The mask of a field's top `len` bits, of `width`.
fn top(len: u8, width: u8) -> u128 {
    let width = u32::from(width);
    let len = u32::from(len).min(width);
    if len == 0 {
        0
    } else {
        ((1u128 << len) - 1) << (width - len)
    }
}

impl Plan {
    /// The index of `actions` among the plan's actions templates, added if new.
    fn actions_template(&mut self, actions: Vec<TemplateAction>) -> usize {
        if let Some(at) = self.actions.iter().position(|a| *a == actions) {
            return at;
        }
        self.actions.push(actions);
        self.actions.len() - 1
    }

    /// The actions template and arguments of `step`, of `proto`'s plan of `vni`'s ACL; a pass
    /// goes on with `after`.
    fn acl_step(
        &mut self,
        vni: Vni,
        proto: AclProto,
        step: &Step<AclVerdict>,
        after: &(usize, Vec<Arg>),
    ) -> (usize, Vec<Arg>) {
        match &step.then {
            Then::Goto(level) => {
                let mut actions: Vec<TemplateAction> = step
                    .writes
                    .iter()
                    .map(|(r, _)| TemplateAction::TagPerRule(r + 1))
                    .collect();
                actions.push(TemplateAction::JumpPerRule);
                let mut args: Vec<Arg> = step.writes.iter().map(|(_, v)| Arg::Tag(*v)).collect();
                #[allow(clippy::cast_possible_truncation)] // a plan has few levels
                args.push(Arg::Jump(Group::Acl(vni, proto, *level as u16)));
                (self.actions_template(actions), args)
            }
            Then::Done(AclVerdict::Deny) => (super::DISCARD, Vec::new()),
            Then::Done(AclVerdict::Pass) => after.clone(),
        }
    }

    /// `vni`'s planned ACL lowered to tables: a dispatch group (`Group::AclDispatch`), entered
    /// first, then each protocol's plan's levels. A pass continues with `after`.
    ///
    /// # Errors
    ///
    /// If a plan can't be made, or doesn't fit the NIC.
    pub(crate) fn acl(
        &mut self,
        vni: Vni,
        acl: &PlannedAcl,
        after: &(usize, Vec<Arg>),
    ) -> Result<Vec<PlannedTable>, AclUnfit> {
        let budget = Budget::at(PPS);
        let mut tables = Vec::new();
        let mut entries: Vec<(AclProto, Step<AclVerdict>)> = Vec::new();
        for proto in AclProto::ALL {
            let (levels, _) = rfc::plan(proto.table(acl), &Options::default())
                .map_err(|e| AclUnfit::Unplanned(format!("{e:?}")))?;
            budget
                .assess(&levels)
                .map_err(|e| AclUnfit::Budget(format!("{e:?}")))?;
            if levels.registers.len() > TAGS {
                return Err(AclUnfit::Registers(levels.registers.len()));
            }
            tables.extend(self.acl_levels(vni, proto, &levels, after));
            entries.push((proto, levels.entry.clone()));
        }
        // Dispatch: UDP and TCP to their plans, then any other IPv4, then the rest passes.
        let group = Group::AclDispatch(vni);
        for (proto, entry) in entries {
            let (actions, args) = self.acl_step(vni, proto, &entry, after);
            self.patterns.push(pattern(proto, &[], None));
            let priority = u32::from(proto == AclProto::Other);
            tables.push(single(
                group,
                priority,
                self.patterns.len() - 1,
                actions,
                pattern(proto, &[], None),
                args,
                Role::Acl(vni),
            ));
        }
        tables.push(single(
            group,
            2,
            ANY,
            after.0,
            any_pattern(),
            after.1.clone(),
            Role::CatchAll(group),
        ));
        Ok(tables)
    }

    /// The tables of `levels`, `proto`'s plan of `vni`'s ACL.
    fn acl_levels(
        &mut self,
        vni: Vni,
        proto: AclProto,
        levels: &Levels<AclVerdict>,
        after: &(usize, Vec<Arg>),
    ) -> Vec<PlannedTable> {
        let mut tables = Vec::new();
        for (id, level) in levels.levels.iter().enumerate() {
            #[allow(clippy::cast_possible_truncation)] // a plan has few levels
            let group = Group::Acl(vni, proto, id as u16);
            if !level.entries.is_empty() {
                self.patterns.push(pattern(proto, &level.key, None));
                let template = self.patterns.len() - 1;
                let mut actions: Vec<usize> = Vec::new();
                let mut rules = Vec::with_capacity(level.entries.len());
                for (key, step) in level.entries.iter() {
                    let values = level.entries.unpack(key);
                    let (template_actions, args) = self.acl_step(vni, proto, step, after);
                    let at = actions
                        .iter()
                        .position(|&a| a == template_actions)
                        .unwrap_or_else(|| {
                            actions.push(template_actions);
                            actions.len() - 1
                        });
                    rules.push(PlannedRule {
                        pattern: pattern(proto, &level.key, Some(&values)),
                        actions: at,
                        args,
                        role: Role::Acl(vni),
                    });
                }
                tables.push(PlannedTable {
                    group,
                    priority: dpdk::flow::Priority(0),
                    capacity: u32::try_from(rules.len()).unwrap_or(u32::MAX),
                    pattern: template,
                    actions,
                    rules,
                });
            }
            let (miss, args) = self.acl_step(vni, proto, &level.miss, after);
            tables.push(single(
                group,
                1,
                ANY,
                miss,
                any_pattern(),
                args,
                Role::Acl(vni),
            ));
        }
        tables
    }
}
