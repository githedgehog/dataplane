// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Context table build (Routes)

use super::NatRequirement;
use acl::reference::table::{RefRule, ReferenceTable};
use config::external::overlay::ValidatedOverlay;
use config::external::overlay::vpc::ValidatedPeering;
use lookup::Lookup;
use lpm::prefix::Prefix;
use lpm::prefix::with_ports::L4Protocol;
use match_action::{Erased, FieldPredicate, FixedSize, MatchKey, RangeSpec};
use net::ip::NextHeader;
use net::packet::VpcDiscriminant;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::debug;

type NatMode = Option<NatRequirement>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Verdict {
    nat_mode: NatMode,
    dst_vpcd: VpcDiscriminant,
}

/// Backend-neutral source rule: carries the raw match ingredients (prefix +
/// port range) plus the already-resolved action. Lowering into ACL field
/// predicates is deferred to the table-build step (see `TwoTupleKey` /
/// `SingletonKey`), so the choice of backend lives at a single site rather than
/// being baked in here at the front of the pipeline.
#[derive(Debug, Clone)]
struct PeeringPrefixInfo<V> {
    ip_range: Prefix,
    port_range: RangeSpec<u16>,
    action: V,
}

#[derive(Debug, Clone)]
struct PeeringEndsContext<V> {
    tcp: Vec<PeeringPrefixInfo<V>>,
    udp: Vec<PeeringPrefixInfo<V>>,
    other: Vec<PeeringPrefixInfo<V>>,
    has_default: bool,
}

impl<V> Default for PeeringEndsContext<V> {
    fn default() -> Self {
        Self {
            tcp: Vec::new(),
            udp: Vec::new(),
            other: Vec::new(),
            has_default: false,
        }
    }
}

impl<V: Clone> PeeringEndsContext<V> {
    fn insert(&mut self, rule: PeeringPrefixInfo<V>, proto: L4Protocol) {
        match proto {
            L4Protocol::Tcp => self.tcp.push(rule),
            L4Protocol::Udp => self.udp.push(rule),
            L4Protocol::Any => {
                self.tcp.push(rule.clone());
                self.udp.push(rule.clone());
                self.other.push(rule);
            }
        }
    }
}

impl PeeringEndsContext<NatMode> {
    fn local_end(peering: &ValidatedPeering) -> Self {
        let mut ends = Self::default();
        for local_expose in peering
            .local()
            .valexp()
            .iter()
            .filter(|expose| expose.can_init_connection())
        {
            for local_prefix in local_expose.ips() {
                let proto = local_expose.nat_proto().unwrap_or(L4Protocol::Any);
                let rule = PeeringPrefixInfo {
                    ip_range: local_prefix.prefix(),
                    port_range: local_prefix.into(),
                    action: NatRequirement::from_expose(local_expose),
                };
                ends.insert(rule, proto);
            }
        }
        ends.has_default = peering.local().has_default_expose();
        ends
    }
}

impl PeeringEndsContext<Verdict> {
    fn add_remote_end(&mut self, remote_vpcd: VpcDiscriminant, peering: &ValidatedPeering) {
        for remote_expose in peering
            .remote()
            .valexp()
            .iter()
            .filter(|expose| expose.can_receive_connection())
        {
            for remote_prefix in remote_expose.public_ips() {
                let proto = remote_expose.nat_proto().unwrap_or(L4Protocol::Any);
                let rule = PeeringPrefixInfo {
                    ip_range: remote_prefix.prefix(),
                    port_range: remote_prefix.into(),
                    action: Verdict {
                        nat_mode: NatRequirement::from_expose(remote_expose),
                        dst_vpcd: remote_vpcd,
                    },
                };
                self.insert(rule, proto);
            }
        }
        self.has_default |= peering.remote().has_default_expose();
    }
}

#[derive(Debug, Default, Clone)]
struct VpcContext {
    local_ends: HashMap<VpcDiscriminant, PeeringEndsContext<NatMode>>,
    remote_ends: PeeringEndsContext<Verdict>,
    default_remote_vpcd: Option<VpcDiscriminant>,
}

impl VpcContext {
    fn insert(&mut self, remote_vpcd: VpcDiscriminant, peering: &ValidatedPeering) {
        self.local_ends
            .insert(remote_vpcd, PeeringEndsContext::local_end(peering));
        self.remote_ends.add_remote_end(remote_vpcd, peering);
    }
}

// -------------------------------------------------------------------------------------------------
// Backend lowering layer.
//
// This is where source rules are lowered into ACL field predicates
// (`into_backend_fields::<RuleBackend>()`). Switching the reference backend for a hardware backend
// means changing `RuleBackend` here (and the table types in `PeeringEndsTables`).

type RuleBackend = Erased;

#[derive(MatchKey, Clone)]
struct TwoTuple<I> {
    #[prefix]
    ip_range: I,
    #[range]
    port_range: u16,
}

/// A two-field key (prefix + port range), buildable from a `PeeringPrefixInfo`.
trait TwoTupleKey: MatchKey {
    fn predicates(ip_range: Prefix, port_range: RangeSpec<u16>) -> Option<Vec<FieldPredicate>>;
}

impl<I> TwoTuple<I> {
    fn new(ip: I, port: Option<u16>) -> Self {
        Self {
            ip_range: ip,
            port_range: port.unwrap_or(0),
        }
    }
}

impl<I: FixedSize> TwoTupleKey for TwoTuple<I> {
    fn predicates(ip_range: Prefix, port_range: RangeSpec<u16>) -> Option<Vec<FieldPredicate>> {
        match ip_range {
            Prefix::IPV4(ip_range) => Some(
                TwoTupleRule {
                    ip_range: ip_range.into(),
                    port_range,
                }
                .into_backend_fields::<RuleBackend>(),
            ),
            Prefix::IPV6(ip_range) => Some(
                TwoTupleRule {
                    ip_range: ip_range.into(),
                    port_range,
                }
                .into_backend_fields::<RuleBackend>(),
            ),
        }
    }
}

#[derive(MatchKey, Clone)]
struct Singleton<I> {
    #[prefix]
    ip_range: I,
}

impl<I> From<TwoTuple<I>> for Singleton<I> {
    fn from(tuple: TwoTuple<I>) -> Self {
        Self {
            ip_range: tuple.ip_range,
        }
    }
}

/// A single-field key (prefix only), buildable from a `PeeringPrefixInfo`.
/// Used for non-TCP/UDP traffic, where L4 ports are missing or not relevant.
trait SingletonKey: MatchKey {
    fn predicates(ip_range: Prefix) -> Option<Vec<FieldPredicate>>;
}

impl<I: FixedSize> SingletonKey for Singleton<I> {
    fn predicates(ip_range: Prefix) -> Option<Vec<FieldPredicate>> {
        match ip_range {
            Prefix::IPV4(ip_range) => Some(
                SingletonRule {
                    ip_range: ip_range.into(),
                }
                .into_backend_fields::<RuleBackend>(),
            ),
            Prefix::IPV6(ip_range) => Some(
                SingletonRule {
                    ip_range: ip_range.into(),
                }
                .into_backend_fields::<RuleBackend>(),
            ),
        }
    }
}

/// Lower rules into a two-field (prefix + port) table.
fn build_two_tuple<T: TwoTupleKey, V>(rules: Vec<PeeringPrefixInfo<V>>) -> ReferenceTable<T, V> {
    let rules = rules
        .into_iter()
        .filter_map(|rule| {
            Some(RefRule::new(
                T::predicates(rule.ip_range, rule.port_range)?,
                rule.action,
            ))
        })
        .collect();
    ReferenceTable::new(rules)
}

/// Lower rules into a single-field (prefix only) table, dropping the port predicate.
fn build_singleton<U: SingletonKey, V>(rules: Vec<PeeringPrefixInfo<V>>) -> ReferenceTable<U, V> {
    let rules = rules
        .into_iter()
        .filter_map(|rule| Some(RefRule::new(U::predicates(rule.ip_range)?, rule.action)))
        .collect();
    ReferenceTable::new(rules)
}

struct PeeringEndsTables<T, U, V> {
    tcp: ReferenceTable<T, V>,
    udp: ReferenceTable<T, V>,
    other: ReferenceTable<U, V>,
    has_default: bool,
}

impl<T, U, V> PeeringEndsTables<T, U, V>
where
    T: MatchKey + Clone,
    U: MatchKey + From<T>,
{
    fn lookup(&self, proto: NextHeader, tuple: &T) -> Option<&V> {
        match proto {
            NextHeader::TCP => self.tcp.lookup(tuple),
            NextHeader::UDP => self.udp.lookup(tuple),
            _ => self.other.lookup(&U::from(tuple.clone())),
        }
    }
}

struct VpcTable<T, U> {
    local_ends: HashMap<VpcDiscriminant, PeeringEndsTables<T, U, NatMode>>,
    remote_ends: PeeringEndsTables<T, U, Verdict>,
    default_remote_vpcd: Option<VpcDiscriminant>,
}

impl<T, U> From<VpcContext> for VpcTable<T, U>
where
    T: TwoTupleKey,
    U: SingletonKey,
{
    fn from(context: VpcContext) -> Self {
        let mut local_ends = HashMap::new();
        for (remote_vpcd, ends) in context.local_ends {
            local_ends.insert(
                remote_vpcd,
                PeeringEndsTables {
                    tcp: build_two_tuple::<T, _>(ends.tcp),
                    udp: build_two_tuple::<T, _>(ends.udp),
                    other: build_singleton::<U, _>(ends.other),
                    has_default: ends.has_default,
                },
            );
        }
        let remote_ends = PeeringEndsTables {
            tcp: build_two_tuple::<T, _>(context.remote_ends.tcp),
            udp: build_two_tuple::<T, _>(context.remote_ends.udp),
            other: build_singleton::<U, _>(context.remote_ends.other),
            has_default: context.remote_ends.has_default,
        };
        Self {
            local_ends,
            remote_ends,
            default_remote_vpcd: context.default_remote_vpcd,
        }
    }
}

impl<T, U> VpcTable<T, U>
where
    T: MatchKey + Clone,
    U: MatchKey + From<T>,
{
    fn lookup(
        &self,
        proto: NextHeader,
        src_tuple: &T,
        dst_tuple: &T,
    ) -> Option<(Verdict, NatMode)> {
        let remote_end_verdict =
            self.remote_ends
                .lookup(proto, dst_tuple)
                .cloned()
                .or_else(|| {
                    self.default_remote_vpcd.map(|dst_vpcd| Verdict {
                        nat_mode: None,
                        dst_vpcd,
                    })
                })?;
        let local_table = self.local_ends.get(&remote_end_verdict.dst_vpcd)?;
        let local_end_nat_mode =
            local_table
                .lookup(proto, src_tuple)
                .copied()
                .or(if local_table.has_default {
                    Some(None)
                } else {
                    None
                })?;
        Some((remote_end_verdict, local_end_nat_mode))
    }
}

#[derive(Default)]
pub(crate) struct PeeringTables {
    v4: HashMap<VpcDiscriminant, VpcTable<TwoTuple<Ipv4Addr>, Singleton<Ipv4Addr>>>,
    v6: HashMap<VpcDiscriminant, VpcTable<TwoTuple<Ipv6Addr>, Singleton<Ipv6Addr>>>,
}

impl From<&ValidatedOverlay> for PeeringTables {
    fn from(overlay: &ValidatedOverlay) -> Self {
        let mut tables = Self::default();
        for vpc in overlay.vpc_table().values() {
            let mut vpc_context_v4 = VpcContext::default();
            let mut vpc_context_v6 = VpcContext::default();
            let local_vpcd = VpcDiscriminant::VNI(vpc.vni());
            for peering in vpc.peerings() {
                let remote_vpcd = VpcDiscriminant::VNI(overlay.vpc_table().get_remote_vni(peering));
                if peering.is_v4() {
                    vpc_context_v4.insert(remote_vpcd, peering);
                    if peering.remote().has_default_expose() {
                        vpc_context_v4.default_remote_vpcd = Some(remote_vpcd);
                    }
                } else {
                    vpc_context_v6.insert(remote_vpcd, peering);
                    if peering.remote().has_default_expose() {
                        vpc_context_v6.default_remote_vpcd = Some(remote_vpcd);
                    }
                }
            }
            if !vpc_context_v4.local_ends.is_empty() {
                tables.v4.insert(
                    local_vpcd,
                    VpcTable::<TwoTuple<Ipv4Addr>, Singleton<Ipv4Addr>>::from(vpc_context_v4),
                );
            }
            if !vpc_context_v6.local_ends.is_empty() {
                tables.v6.insert(
                    local_vpcd,
                    VpcTable::<TwoTuple<Ipv6Addr>, Singleton<Ipv6Addr>>::from(vpc_context_v6),
                );
            }
        }
        tables
    }
}

impl PeeringTables {
    pub(crate) fn lookup(
        &self,
        src_vpcd: VpcDiscriminant,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        proto: NextHeader,
        ports: Option<(u16, u16)>,
    ) -> Option<(
        VpcDiscriminant,
        Option<NatRequirement>,
        Option<NatRequirement>,
    )> {
        let (src_port, dst_port) = ports.unzip();
        let result = match (src_ip, dst_ip) {
            (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => self.v4.get(&src_vpcd).and_then(|table| {
                table.lookup(
                    proto,
                    &TwoTuple::new(src_ip, src_port),
                    &TwoTuple::new(dst_ip, dst_port),
                )
            }),
            (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => self.v6.get(&src_vpcd).and_then(|table| {
                table.lookup(
                    proto,
                    &TwoTuple::new(src_ip, src_port),
                    &TwoTuple::new(dst_ip, dst_port),
                )
            }),
            _ => {
                debug!(
                    "Source and destination IP versions do not match: src_ip={src_ip:?}, dst_ip={dst_ip:?}",
                );
                None
            }
        };
        result.map(|(verdict, nat_mode)| (verdict.dst_vpcd, verdict.nat_mode, nat_mode))
    }
}
