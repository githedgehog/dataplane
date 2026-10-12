// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Context table build (ACLs)

use super::PacketSummary;
use acl::table::build_table;
pub(super) use acl::table::{Backend, Table};
use config::ConfigError;
use config::external::overlay::ValidatedOverlay;
use config::external::overlay::acl::{AclAction, AclProtoMatch, AclScope, ValidatedAclRule};
use lpm::prefix::with_ports::KeyPort;
use lpm::prefix::{Prefix, PrefixPortsSet, PrefixWithOptionalPorts};
use match_action::{Erased, ExactSpec, FieldPredicate, MatchKey, PrefixSpec, RangeSpec};
use net::ip::{IpAddress, NextHeader};
use net::vxlan::Vni;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZero;
use tracing::error;

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeeringAclRule {
    src_vni: Vni,
    dst_vni: Vni,
    src_ip_range: Option<Prefix>,
    dst_ip_range: Option<Prefix>,
    src_port_range: Option<RangeSpec<KeyPort>>,
    dst_port_range: Option<RangeSpec<KeyPort>>,
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
// Key and rule lowering.
//
// Every rule is lowered once to backend-neutral `FieldPredicate`s (via the `Erased` backend). The
// selected backend (see `Backend`) then consumes those: `Dpdk` converts them to rte_acl fields at
// build time; `Reference` (test only) matches them directly.

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
    proto: NextHeader,
    #[exact]
    #[cli(column_name = "src-vni")]
    src_vni: Vni,
    #[exact]
    #[cli(column_name = "dst-vni")]
    dst_vni: Vni,
    #[prefix]
    #[cli(column_name = "source")]
    src_ip_range: I,
    #[prefix]
    #[cli(column_name = "destination")]
    dst_ip_range: I,
    #[range]
    #[cli(column_name = "src-port")]
    src_port_range: KeyPort,
    #[range]
    #[cli(column_name = "dst-port")]
    dst_port_range: KeyPort,
}

impl<I> AclKey<I> {
    #[must_use]
    fn new(
        proto: NextHeader,
        src_vni: Vni,
        dst_vni: Vni,
        src_ip: I,
        dst_ip: I,
        src_port: Option<NonZero<u16>>,
        dst_port: Option<NonZero<u16>>,
    ) -> Self {
        Self {
            proto,
            src_vni,
            dst_vni,
            src_ip_range: src_ip,
            dst_ip_range: dst_ip,
            src_port_range: KeyPort::new(src_port),
            dst_port_range: KeyPort::new(dst_port),
        }
    }
}

/// Lower one rule to backend-neutral predicates.
/// Returns `None` if either prefix does not match `T`.
fn rule_predicates<T: IpVersion>(
    proto: AclProtoMatch,
    src_vni: Vni,
    dst_vni: Vni,
    src_ip_range: Prefix,
    dst_ip_range: Prefix,
    src_port_range: RangeSpec<KeyPort>,
    dst_port_range: RangeSpec<KeyPort>,
) -> Option<(AclKeyRule<T>, Vec<FieldPredicate>)> {
    let rule = AclKeyRule {
        proto: proto.into(),
        src_vni: ExactSpec::new(src_vni),
        dst_vni: ExactSpec::new(dst_vni),
        src_ip_range: T::prefix_spec(src_ip_range)?,
        dst_ip_range: T::prefix_spec(dst_ip_range)?,
        src_port_range,
        dst_port_range,
    };
    Some((rule, rule.into_backend_fields::<Erased>()))
}

/// Per-IP-version behaviour for the address key fields: the wildcard prefix, and narrowing a
/// version-agnostic [`Prefix`] to this version. `prefix_spec` returns `None` for the other
/// version, which is what keeps each table to a single address width.
pub(super) trait IpVersion: IpAddress {
    fn wildcard() -> Prefix;
    fn prefix_spec(prefix: Prefix) -> Option<PrefixSpec<Self>>;
}

impl IpVersion for Ipv4Addr {
    fn wildcard() -> Prefix {
        Prefix::root_v4()
    }

    fn prefix_spec(prefix: Prefix) -> Option<PrefixSpec<Self>> {
        match prefix {
            Prefix::IPV4(prefix) => Some(prefix.into()),
            Prefix::IPV6(_) => None,
        }
    }
}

impl IpVersion for Ipv6Addr {
    fn wildcard() -> Prefix {
        Prefix::root_v6()
    }

    fn prefix_spec(prefix: Prefix) -> Option<PrefixSpec<Self>> {
        match prefix {
            Prefix::IPV6(prefix) => Some(prefix.into()),
            Prefix::IPV4(_) => None,
        }
    }
}

/// A typed rule, its backend predicates, and its action.
type LoweredRule<T> = (AclKeyRule<T>, Vec<FieldPredicate>, LookupResult);

/// Lower rules for `T` in first-match order.
/// Missing prefixes and port ranges become wildcards.
///
/// # Errors
///
/// Returns an error if a prefix has the wrong IP version.
/// Validation should make this unreachable; returning an error avoids silently dropping the rule.
fn lower_rules<T: IpVersion>(rules: &[PeeringAclRule]) -> Result<Vec<LoweredRule<T>>, ConfigError> {
    rules
        .iter()
        .map(|rule| {
            let (key_rule, fields) = rule_predicates(
                rule.proto,
                rule.src_vni,
                rule.dst_vni,
                rule.src_ip_range.unwrap_or_else(T::wildcard),
                rule.dst_ip_range.unwrap_or_else(T::wildcard),
                rule.src_port_range
                    .unwrap_or(lpm::prefix::with_ports::PORT_RANGE_WILDCARD),
                rule.dst_port_range
                    .unwrap_or(lpm::prefix::with_ports::PORT_RANGE_WILDCARD),
            )
            .ok_or_else(|| {
                let (src, dst) = (rule.src_ip_range, rule.dst_ip_range);
                error!(
                    "ACL rule for {} -> {} does not match the IP version of the table it was \
                     filed under (src {src:?}, dst {dst:?}); refusing the configuration",
                    rule.src_vni, rule.dst_vni,
                );
                ConfigError::FailureApply(format!(
                    "ACL rule for VNI {} -> {} has prefixes (src {src:?}, dst {dst:?}) that do \
                     not match the table's IP version",
                    rule.src_vni, rule.dst_vni,
                ))
            })?;
            Ok((
                key_rule,
                fields,
                LookupResult {
                    action: rule.action,
                    log: rule.log,
                    scope: rule.scope,
                },
            ))
        })
        .collect()
}

// -------------------------------------------------------------------------------------------------
// Backend selection.

/// Backend used to build the production context: the rte_acl classifier. It requires the EAL to be
/// initialized (done once in `dataplane::main`). The reference backend is `cfg(test)`-gated and is
/// never compiled into production builds.
pub(super) const PRODUCTION_BACKEND: Backend = Backend::Dpdk;

#[derive(Debug, Clone)]
pub(super) struct LookupResult {
    pub(super) action: AclAction,
    pub(super) log: bool,
    pub(super) scope: AclScope,
}

#[derive(Debug)]
pub(super) struct AclTables {
    pub(super) v4: Table<AclKey<Ipv4Addr>, LookupResult>,
    pub(super) v6: Table<AclKey<Ipv6Addr>, LookupResult>,
    pub(super) default_actions: HashMap<(Vni, Vni), AclAction>,
}

impl Default for AclTables {
    fn default() -> Self {
        Self {
            v4: Table::empty(),
            v6: Table::empty(),
            default_actions: HashMap::new(),
        }
    }
}

impl AclTables {
    pub(super) fn build(overlay: &ValidatedOverlay, backend: Backend) -> Result<Self, ConfigError> {
        let ruleset = PeeringAclRuleSet::from(overlay);
        let v4 = build_table::<AclKey<Ipv4Addr>, _>(
            backend,
            "v4",
            lower_rules::<Ipv4Addr>(&ruleset.v4)?,
        )
        .map_err(ConfigError::FailureApply)?;
        let v6 = build_table::<AclKey<Ipv6Addr>, _>(
            backend,
            "v6",
            lower_rules::<Ipv6Addr>(&ruleset.v6)?,
        )
        .map_err(ConfigError::FailureApply)?;
        Ok(Self {
            v4,
            v6,
            default_actions: ruleset.default_actions,
        })
    }
}

// -------------------------------------------------------------------------------------------------
// Lookup logic

impl AclTables {
    #[must_use]
    pub(super) fn lookup(&self, p: &PacketSummary) -> Option<&LookupResult> {
        let proto = p.proto;
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

    #[must_use]
    pub(super) fn find_default_action(&self, src_vni: Vni, dst_vni: Vni) -> Option<AclAction> {
        self.default_actions.get(&(src_vni, dst_vni)).copied()
    }
}
