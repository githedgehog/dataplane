// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Context table build (ACLs)

use super::PacketSummary;
use acl::reference::table::{RefRule, ReferenceTable};
use config::external::overlay::ValidatedOverlay;
use config::external::overlay::acl::{AclAction, AclProtoMatch, AclScope, ValidatedAclRule};
use lookup::Lookup;
use lpm::prefix::{Prefix, PrefixPortsSet, PrefixWithOptionalPorts};
use match_action::{Erased, ExactSpec, FieldPredicate, FixedSize, MatchKey, RangeSpec};
use net::ip::NextHeader;
use net::vxlan::Vni;
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::error;

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeeringAclRule {
    src_vni: Vni,
    dst_vni: Vni,
    src_ip_range: Option<Prefix>,
    dst_ip_range: Option<Prefix>,
    src_port_range: Option<RangeSpec<u16>>,
    dst_port_range: Option<RangeSpec<u16>>,
    log: bool,
    scope: AclScope,
    action: AclAction,
    proto: AclProtoMatch,
    is_ipv4: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct PeeringAclRuleSet {
    tcp_v4: Vec<PeeringAclRule>,
    udp_v4: Vec<PeeringAclRule>,
    other_v4: Vec<PeeringAclRule>,

    tcp_v6: Vec<PeeringAclRule>,
    udp_v6: Vec<PeeringAclRule>,
    other_v6: Vec<PeeringAclRule>,

    default_actions: HashMap<(Vni, Vni), AclAction>,
}

impl PeeringAclRuleSet {
    fn insert(&mut self, src_vni: Vni, dst_vni: Vni, rule: &ValidatedAclRule, is_ipv4: bool) {
        let pattern = rule.pattern();
        let (src_prefixes, dst_prefixes) = (pattern.src(), pattern.dst());
        let template = PeeringAclRule {
            src_vni,
            dst_vni,
            src_ip_range: None,
            dst_ip_range: None,
            src_port_range: None,
            dst_port_range: None,
            log: rule.log(),
            scope: rule.scope(),
            action: rule.action(),
            proto: pattern.proto(),
            is_ipv4,
        };
        if src_prefixes.is_empty() {
            self.insert_for_src_prefix(template, None, dst_prefixes);
        } else {
            for src_prefix in src_prefixes.iter() {
                self.insert_for_src_prefix(template.clone(), Some(src_prefix), dst_prefixes);
            }
        }
    }

    fn insert_for_src_prefix(
        &mut self,
        template: PeeringAclRule,
        src: Option<&PrefixWithOptionalPorts>,
        dst_prefixes: &PrefixPortsSet,
    ) {
        if dst_prefixes.is_empty() {
            self.insert_for_src_and_dst_prefix(template, src, None);
        } else {
            for dst_prefix in dst_prefixes.iter() {
                self.insert_for_src_and_dst_prefix(template.clone(), src, Some(dst_prefix));
            }
        }
    }

    fn insert_for_src_and_dst_prefix(
        &mut self,
        mut template_rule: PeeringAclRule,
        src: Option<&PrefixWithOptionalPorts>,
        dst: Option<&PrefixWithOptionalPorts>,
    ) {
        template_rule.src_ip_range = src.map(|pwop| pwop.prefix());
        template_rule.dst_ip_range = dst.map(|pwop| pwop.prefix());
        template_rule.src_port_range = src.and_then(|pwop| pwop.ports().map(|p| p.into()));
        template_rule.dst_port_range = dst.and_then(|pwop| pwop.ports().map(|p| p.into()));
        match (template_rule.proto, template_rule.is_ipv4) {
            (AclProtoMatch::Tcp, true) => self.tcp_v4.push(template_rule),
            (AclProtoMatch::Udp, true) => self.udp_v4.push(template_rule),
            (AclProtoMatch::Other(_), true) => self.other_v4.push(template_rule),
            (AclProtoMatch::Any, true) => {
                self.udp_v4.push(template_rule.clone());
                self.tcp_v4.push(template_rule.clone());
                self.other_v4.push(template_rule);
            }

            (AclProtoMatch::Tcp, false) => self.tcp_v6.push(template_rule),
            (AclProtoMatch::Udp, false) => self.udp_v6.push(template_rule),
            (AclProtoMatch::Other(_), false) => self.other_v6.push(template_rule),
            (AclProtoMatch::Any, false) => {
                self.udp_v6.push(template_rule.clone());
                self.tcp_v6.push(template_rule.clone());
                self.other_v6.push(template_rule);
            }
        }
    }
}

impl From<&ValidatedOverlay> for PeeringAclRuleSet {
    fn from(overlay: &ValidatedOverlay) -> Self {
        let mut ruleset = Self::default();
        for vpc in overlay.vpc_table().values() {
            let local_vni = vpc.vni();
            for peering in vpc.peerings() {
                let Some(acl) = peering.acl() else {
                    continue;
                };
                let remote_vni = overlay.vpc_table().get_remote_vni(peering);

                // The default action is a property of the peering and applies to both directions.
                // Each peering is visited once per VPC (with local/remote swapped), so registering
                // the local->remote pair on every visit covers both directed pairs.
                ruleset
                    .default_actions
                    .insert((local_vni, remote_vni), acl.default_action());

                for acl_rule in acl.rules() {
                    // A rule is directional: its validated pattern's src/dst prefixes are bound to
                    // the rule's `from`/`to` VPCs. Each peering is visited once per end VPC (with
                    // local/remote swapped), so insert the rule only from its `from` VPC's visit.
                    if acl_rule.from() != peering.local().name() {
                        continue;
                    }
                    ruleset.insert(local_vni, remote_vni, acl_rule, peering.is_v4());
                }
            }
        }
        ruleset
    }
}

// -------------------------------------------------------------------------------------------------
// Backend lowering layer.
//
// This is where source rules are lowered into ACL field predicates
// (`into_backend_fields::<RuleBackend>()`). Switching the reference backend for a hardware backend
// means changing `RuleBackend` here (and the table types in `PeeringEndsTables`).

type RuleBackend = Erased;

#[derive(Debug, MatchKey, Clone, PartialEq, Eq)]
struct IpsPortsTuple<I> {
    #[exact]
    src_vni: u32,
    #[exact]
    dst_vni: u32,
    #[prefix]
    src_ip_range: I,
    #[prefix]
    dst_ip_range: I,
    #[range]
    src_port_range: u16,
    #[range]
    dst_port_range: u16,
}

impl<I> IpsPortsTuple<I> {
    fn new(
        src_vni: Vni,
        dst_vni: Vni,
        src_ip: I,
        dst_ip: I,
        src_port: Option<u16>,
        dst_port: Option<u16>,
    ) -> Self {
        Self {
            src_vni: src_vni.as_u32(),
            dst_vni: dst_vni.as_u32(),
            src_ip_range: src_ip,
            dst_ip_range: dst_ip,
            src_port_range: src_port.unwrap_or(0),
            dst_port_range: dst_port.unwrap_or(0),
        }
    }

    fn predicates(
        src_vni: Vni,
        dst_vni: Vni,
        src_ip_range: Prefix,
        dst_ip_range: Prefix,
        src_port_range: RangeSpec<u16>,
        dst_port_range: RangeSpec<u16>,
    ) -> Option<Vec<FieldPredicate>> {
        match (src_ip_range, dst_ip_range) {
            (Prefix::IPV4(src_ip_range), Prefix::IPV4(dst_ip_range)) => Some(
                IpsPortsTupleRule {
                    src_vni: ExactSpec::new(src_vni.as_u32()),
                    dst_vni: ExactSpec::new(dst_vni.as_u32()),
                    src_ip_range: src_ip_range.into(),
                    dst_ip_range: dst_ip_range.into(),
                    src_port_range,
                    dst_port_range,
                }
                .into_backend_fields::<RuleBackend>(),
            ),
            (Prefix::IPV6(src_ip_range), Prefix::IPV6(dst_ip_range)) => Some(
                IpsPortsTupleRule {
                    src_vni: ExactSpec::new(src_vni.as_u32()),
                    dst_vni: ExactSpec::new(dst_vni.as_u32()),
                    src_ip_range: src_ip_range.into(),
                    dst_ip_range: dst_ip_range.into(),
                    src_port_range,
                    dst_port_range,
                }
                .into_backend_fields::<RuleBackend>(),
            ),
            _ => None,
        }
    }
}

#[derive(Debug, MatchKey, Clone, PartialEq, Eq)]
struct IpsProtoTuple<I> {
    #[exact]
    src_vni: u32,
    #[exact]
    dst_vni: u32,
    // A range so a single rule can match one protocol (when user specifies a numerical protocol),
    // or any protocol. For the lookup, the packet obviously supplies its single protocol number.
    #[range]
    proto: u8,
    #[prefix]
    src_ip_range: I,
    #[prefix]
    dst_ip_range: I,
}

impl<I> IpsProtoTuple<I> {
    fn predicates(
        src_vni: Vni,
        dst_vni: Vni,
        proto: AclProtoMatch,
        src_ip_range: Prefix,
        dst_ip_range: Prefix,
    ) -> Option<Vec<FieldPredicate>> {
        match (src_ip_range, dst_ip_range) {
            (Prefix::IPV4(src_ip_range), Prefix::IPV4(dst_ip_range)) => Some(
                IpsProtoTupleRule {
                    src_vni: ExactSpec::new(src_vni.as_u32()),
                    dst_vni: ExactSpec::new(dst_vni.as_u32()),
                    proto: proto.into(),
                    src_ip_range: src_ip_range.into(),
                    dst_ip_range: dst_ip_range.into(),
                }
                .into_backend_fields::<RuleBackend>(),
            ),
            (Prefix::IPV6(src_ip_range), Prefix::IPV6(dst_ip_range)) => Some(
                IpsProtoTupleRule {
                    src_vni: ExactSpec::new(src_vni.as_u32()),
                    dst_vni: ExactSpec::new(dst_vni.as_u32()),
                    proto: proto.into(),
                    src_ip_range: src_ip_range.into(),
                    dst_ip_range: dst_ip_range.into(),
                }
                .into_backend_fields::<RuleBackend>(),
            ),
            _ => None,
        }
    }
}

trait Wildcardable {
    fn wildcard() -> Prefix;
}

impl Wildcardable for Ipv4Addr {
    fn wildcard() -> Prefix {
        Prefix::root_v4()
    }
}

impl Wildcardable for Ipv6Addr {
    fn wildcard() -> Prefix {
        Prefix::root_v6()
    }
}

// Lower rules into a tuple (prefixes + ports) table.
fn build_ips_ports_tuple<T: FixedSize + Wildcardable>(
    rules: &[PeeringAclRule],
) -> ReferenceTable<IpsPortsTuple<T>, LookupResult> {
    let rules = rules
        .iter()
        .filter_map(|rule| {
            Some(RefRule::new(
                IpsPortsTuple::<T>::predicates(
                    rule.src_vni,
                    rule.dst_vni,
                    rule.src_ip_range.unwrap_or_else(T::wildcard),
                    rule.dst_ip_range.unwrap_or_else(T::wildcard),
                    rule.src_port_range
                        .unwrap_or(lpm::prefix::with_ports::PORT_RANGE_WILDCARD),
                    rule.dst_port_range
                        .unwrap_or(lpm::prefix::with_ports::PORT_RANGE_WILDCARD),
                )?,
                LookupResult {
                    action: rule.action,
                    log: rule.log,
                    scope: rule.scope,
                },
            ))
        })
        .collect();
    ReferenceTable::new(rules)
}

// Lower rules into a tuple (prefixes + proto) table.
fn build_ips_proto_tuple<T: FixedSize + Wildcardable>(
    rules: &[PeeringAclRule],
) -> ReferenceTable<IpsProtoTuple<T>, LookupResult> {
    let rules = rules
        .iter()
        .filter_map(|rule| {
            Some(RefRule::new(
                IpsProtoTuple::<T>::predicates(
                    rule.src_vni,
                    rule.dst_vni,
                    rule.proto,
                    rule.src_ip_range.unwrap_or_else(T::wildcard),
                    rule.dst_ip_range.unwrap_or_else(T::wildcard),
                )?,
                LookupResult {
                    action: rule.action,
                    log: rule.log,
                    scope: rule.scope,
                },
            ))
        })
        .collect();
    ReferenceTable::new(rules)
}

pub(super) trait TupleProto<T> {
    fn from_tuple_and_proto(tuple: &T, proto: u8) -> Self;
}

impl<I> TupleProto<IpsPortsTuple<I>> for IpsProtoTuple<I>
where
    I: Clone,
{
    fn from_tuple_and_proto(tuple: &IpsPortsTuple<I>, proto: u8) -> Self {
        Self {
            src_vni: tuple.src_vni,
            dst_vni: tuple.dst_vni,
            proto,
            src_ip_range: tuple.src_ip_range.clone(),
            dst_ip_range: tuple.dst_ip_range.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct LookupResult {
    pub(super) action: AclAction,
    pub(super) log: bool,
    pub(super) scope: AclScope,
}

#[derive(Debug, Clone)]
struct PeeringAclTables<T, U> {
    tcp: ReferenceTable<T, LookupResult>,
    udp: ReferenceTable<T, LookupResult>,
    other: ReferenceTable<U, LookupResult>,
}

impl<T, U> Default for PeeringAclTables<T, U>
where
    T: MatchKey,
    U: MatchKey,
{
    fn default() -> Self {
        Self {
            tcp: ReferenceTable::empty(),
            udp: ReferenceTable::empty(),
            other: ReferenceTable::empty(),
        }
    }
}

impl<I> PeeringAclTables<IpsPortsTuple<I>, IpsProtoTuple<I>>
where
    I: FixedSize + Wildcardable,
{
    fn from_tables(
        tcp: &[PeeringAclRule],
        udp: &[PeeringAclRule],
        other: &[PeeringAclRule],
    ) -> Self {
        PeeringAclTables {
            tcp: build_ips_ports_tuple(tcp),
            udp: build_ips_ports_tuple(udp),
            other: build_ips_proto_tuple(other),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub(super) struct AclTables {
    v4: PeeringAclTables<IpsPortsTuple<Ipv4Addr>, IpsProtoTuple<Ipv4Addr>>,
    v6: PeeringAclTables<IpsPortsTuple<Ipv6Addr>, IpsProtoTuple<Ipv6Addr>>,
    default_actions: HashMap<(Vni, Vni), AclAction>,
}

impl From<PeeringAclRuleSet> for AclTables {
    fn from(context: PeeringAclRuleSet) -> Self {
        Self {
            v4: PeeringAclTables::from_tables(&context.tcp_v4, &context.udp_v4, &context.other_v4),
            v6: PeeringAclTables::from_tables(&context.tcp_v6, &context.udp_v6, &context.other_v6),
            default_actions: context.default_actions,
        }
    }
}

impl From<&ValidatedOverlay> for AclTables {
    fn from(overlay: &ValidatedOverlay) -> Self {
        PeeringAclRuleSet::from(overlay).into()
    }
}

// -------------------------------------------------------------------------------------------------
// Lookup logic

impl<T, U> PeeringAclTables<T, U>
where
    T: MatchKey + Clone,
    U: MatchKey + TupleProto<T>,
{
    fn lookup(&self, proto: NextHeader, tuple: &T) -> Option<&LookupResult> {
        match proto {
            NextHeader::TCP => self.tcp.lookup(tuple),
            NextHeader::UDP => self.udp.lookup(tuple),
            _ => {
                let proto = proto.as_u8();
                let proto_tuple = U::from_tuple_and_proto(tuple, proto);
                self.other.lookup(&proto_tuple)
            }
        }
    }
}

impl AclTables {
    pub(super) fn lookup(&self, p: &PacketSummary) -> Option<&LookupResult> {
        let (src_ports, dst_ports) = p.ports.unzip();
        match (p.src_ip, p.dst_ip) {
            (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => {
                let tuple =
                    IpsPortsTuple::new(p.src_vni, p.dst_vni, src_ip, dst_ip, src_ports, dst_ports);
                self.v4.lookup(p.proto, &tuple)
            }
            (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => {
                let tuple =
                    IpsPortsTuple::new(p.src_vni, p.dst_vni, src_ip, dst_ip, src_ports, dst_ports);
                self.v6.lookup(p.proto, &tuple)
            }
            _ => {
                error!("Found packet with different IP versions for source and destination!");
                None
            }
        }
    }

    pub(super) fn find_default_action(&self, src_vni: Vni, dst_vni: Vni) -> Option<AclAction> {
        self.default_actions.get(&(src_vni, dst_vni)).copied()
    }
}
