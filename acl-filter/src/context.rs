// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Context table build (ACLs)

use super::PacketSummary;
use acl::reference::table::{RefRule, ReferenceTable};
use config::external::overlay::ValidatedOverlay;
use config::external::overlay::acl::{AclAction, AclProtoMatch, AclScope, ValidatedAclRule};
use lookup::Lookup;
use lpm::prefix::{Prefix, PrefixPortsSet, PrefixWithOptionalPorts};
use match_action::{Erased, ExactSpec, FieldPredicate, FixedSize, MaskSpec, MatchKey, RangeSpec};
use net::vxlan::Vni;
use std::collections::HashMap;
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
    // All rules for a given IP version live in one ordered list. The protocol is carried in the key
    // (a `#[mask]` byte), so there is no per-protocol table split and no need to duplicate an
    // `Any`-protocol rule across protocols. Insertion order is preserved, which is what gives
    // first-match precedence at lookup time.
    v4: Vec<PeeringAclRule>,
    v6: Vec<PeeringAclRule>,

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
        // The protocol is a key field (not a table selector), so a rule only splits by IP version.
        if template_rule.is_ipv4 {
            self.v4.push(template_rule);
        } else {
            self.v6.push(template_rule);
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
// means changing `RuleBackend` here (and the table types in `AclTables`).

type RuleBackend = Erased;

/// A single ACL match key: protocol, VPC pair, address pair, and port pair.
///
/// `proto` is a `#[mask]` byte on purpose. rte_acl requires the first field to be a single byte,
/// and a bitmask byte both satisfies that and lets one field express either an exact protocol
/// (`mask 0xff`) or "any protocol" (`mask 0x00`). Carrying the protocol in the key -- rather than
/// in the table identity -- collapses what used to be six per-protocol tables into one table per
/// IP version, and removes the need to duplicate an `Any` rule across protocols.
///
/// Ports are only meaningful for TCP/UDP; config validation forbids port matching on other
/// protocols, so non-TCP/UDP rules always carry a wildcard port range and a portless packet looks
/// up with port `0`.
#[derive(Debug, MatchKey, Clone, PartialEq, Eq)]
pub(super) struct AclKey<I> {
    #[mask]
    proto: u8,
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

impl<I> AclKey<I> {
    fn new(
        proto: u8,
        src_vni: Vni,
        dst_vni: Vni,
        src_ip: I,
        dst_ip: I,
        src_port: Option<u16>,
        dst_port: Option<u16>,
    ) -> Self {
        Self {
            proto,
            src_vni: src_vni.as_u32(),
            dst_vni: dst_vni.as_u32(),
            src_ip_range: src_ip,
            dst_ip_range: dst_ip,
            src_port_range: src_port.unwrap_or(0),
            dst_port_range: dst_port.unwrap_or(0),
        }
    }
}

/// Lower a single rule to backend field predicates for the concrete IP version of its prefixes.
/// Returns `None` if the source and destination prefixes disagree on IP version, which the config
/// validation already rules out for a well-formed peering.
fn rule_predicates(
    proto: AclProtoMatch,
    src_vni: Vni,
    dst_vni: Vni,
    src_ip_range: Prefix,
    dst_ip_range: Prefix,
    src_port_range: RangeSpec<u16>,
    dst_port_range: RangeSpec<u16>,
) -> Option<Vec<FieldPredicate>> {
    let proto: MaskSpec<u8> = proto.into();
    match (src_ip_range, dst_ip_range) {
        (Prefix::IPV4(src_ip_range), Prefix::IPV4(dst_ip_range)) => Some(
            AclKeyRule {
                proto,
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
            AclKeyRule {
                proto,
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

pub(super) trait Wildcardable {
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

// Lower a set of rules (already grouped by IP version) into a single table. A missing prefix or
// port range becomes the wildcard for that field.
fn build_acl_table<T: FixedSize + Wildcardable>(
    rules: &[PeeringAclRule],
) -> ReferenceTable<AclKey<T>, LookupResult> {
    let rules = rules
        .iter()
        .filter_map(|rule| {
            Some(RefRule::new(
                rule_predicates(
                    rule.proto,
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

#[derive(Debug, Clone)]
pub(super) struct LookupResult {
    pub(super) action: AclAction,
    pub(super) log: bool,
    pub(super) scope: AclScope,
}

#[derive(Debug, Clone)]
pub(super) struct AclTables {
    pub(super) v4: ReferenceTable<AclKey<Ipv4Addr>, LookupResult>,
    pub(super) v6: ReferenceTable<AclKey<Ipv6Addr>, LookupResult>,
    pub(super) default_actions: HashMap<(Vni, Vni), AclAction>,
}

impl Default for AclTables {
    fn default() -> Self {
        Self {
            v4: ReferenceTable::empty(),
            v6: ReferenceTable::empty(),
            default_actions: HashMap::new(),
        }
    }
}

impl From<PeeringAclRuleSet> for AclTables {
    fn from(context: PeeringAclRuleSet) -> Self {
        Self {
            v4: build_acl_table(&context.v4),
            v6: build_acl_table(&context.v6),
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

impl AclTables {
    pub(super) fn lookup(&self, p: &PacketSummary) -> Option<&LookupResult> {
        let proto = p.proto.as_u8();
        let (src_ports, dst_ports) = p.ports.unzip();
        match (p.src_ip, p.dst_ip) {
            (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => {
                let key = AclKey::new(
                    proto, p.src_vni, p.dst_vni, src_ip, dst_ip, src_ports, dst_ports,
                );
                self.v4.lookup(&key)
            }
            (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => {
                let key = AclKey::new(
                    proto, p.src_vni, p.dst_vni, src_ip, dst_ip, src_ports, dst_ports,
                );
                self.v6.lookup(&key)
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
