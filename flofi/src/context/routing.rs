// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Context table build (Routes)

use super::NatRequirement;
use acl::reference::table::{RefRule, ReferenceTable};
use config::external::overlay::ValidatedOverlay;
use config::external::overlay::vpc::ValidatedPeering;
use lookup::Lookup;
use lpm::prefix::Prefix;
use lpm::prefix::with_ports::{L4Protocol, PortRange};
use match_action::{Erased, FieldPredicate, MatchKey, RangeSpec};
use net::ip::NextHeader;
use net::packet::VpcDiscriminant;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::debug;

const PORT_RANGE_WILDCARD: RangeSpec<u16> = RangeSpec::new(0, u16::MAX);

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeeringPrefixInfo {
    ip_range: Prefix,
    proto: L4Protocol,
    port_range: Option<PortRange>,
    dst_vpcd: VpcDiscriminant,
    nat_mode: Option<NatRequirement>,
}

impl From<&PeeringPrefixInfo> for RangeSpec<u16> {
    fn from(prefix: &PeeringPrefixInfo) -> Self {
        prefix
            .port_range
            .map_or(PORT_RANGE_WILDCARD, RangeSpec::from)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PeeringManifestInfo {
    prefixes: Vec<PeeringPrefixInfo>,
    has_default: bool,
}

impl PeeringManifestInfo {
    fn remote_end(remote_vpcd: VpcDiscriminant, peering: &ValidatedPeering) -> Self {
        let mut table = Self::default();
        for remote_expose in peering
            .remote()
            .valexp()
            .iter()
            .filter(|expose| expose.can_receive_connection())
        {
            for remote_prefix in remote_expose.public_ips() {
                table.prefixes.push(PeeringPrefixInfo {
                    ip_range: remote_prefix.prefix(),
                    proto: remote_expose.nat().map_or(L4Protocol::Any, |nat| nat.proto),
                    port_range: remote_prefix.ports(),
                    dst_vpcd: remote_vpcd,
                    nat_mode: NatRequirement::from_expose(remote_expose),
                });
            }
        }
        table.has_default = peering.remote().has_default_expose();
        table
    }

    fn local_end(remote_vpcd: VpcDiscriminant, peering: &ValidatedPeering) -> Self {
        let mut table = Self::default();
        for local_expose in peering
            .local()
            .valexp()
            .iter()
            .filter(|expose| expose.can_init_connection())
        {
            for local_prefix in local_expose.ips() {
                table.prefixes.push(PeeringPrefixInfo {
                    ip_range: local_prefix.prefix(),
                    proto: local_expose.nat().map_or(L4Protocol::Any, |nat| nat.proto),
                    port_range: local_prefix.ports(),
                    dst_vpcd: remote_vpcd,
                    nat_mode: NatRequirement::from_expose(local_expose),
                });
            }
        }
        table.has_default = peering.local().has_default_expose();
        table
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeeringInfo {
    local: PeeringManifestInfo,
    remote: PeeringManifestInfo,
    remote_vpcd: VpcDiscriminant,
}

impl PeeringInfo {
    fn from_peering(remote_vpcd: VpcDiscriminant, peering: &ValidatedPeering) -> Self {
        Self {
            local: PeeringManifestInfo::local_end(remote_vpcd, peering),
            remote: PeeringManifestInfo::remote_end(remote_vpcd, peering),
            remote_vpcd,
        }
    }
}

// -----------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NatMode {
    NoNat,
    StaticNat,
    Masquerade,
    PortForwarding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Verdict {
    nat_mode: NatMode,
    dst_vpcd: VpcDiscriminant,
}

trait FromPeeringEndPrefix {
    fn from(prefix: &PeeringPrefixInfo) -> Self;
}

impl FromPeeringEndPrefix for NatMode {
    fn from(prefix: &PeeringPrefixInfo) -> Self {
        prefix.nat_mode.into()
    }
}

impl FromPeeringEndPrefix for Verdict {
    fn from(prefix: &PeeringPrefixInfo) -> Self {
        Verdict {
            nat_mode: prefix.nat_mode.into(),
            dst_vpcd: prefix.dst_vpcd,
        }
    }
}

impl From<Option<NatRequirement>> for NatMode {
    fn from(nat: Option<NatRequirement>) -> Self {
        match nat {
            None => NatMode::NoNat,
            Some(NatRequirement::Static) => NatMode::StaticNat,
            Some(NatRequirement::Masquerade) => NatMode::Masquerade,
            Some(NatRequirement::PortForwarding) => NatMode::PortForwarding,
        }
    }
}

impl From<NatMode> for Option<NatRequirement> {
    fn from(nat_mode: NatMode) -> Self {
        match nat_mode {
            NatMode::NoNat => None,
            NatMode::StaticNat => Some(NatRequirement::Static),
            NatMode::Masquerade => Some(NatRequirement::Masquerade),
            NatMode::PortForwarding => Some(NatRequirement::PortForwarding),
        }
    }
}

/// Backend-neutral source rule: carries the raw match ingredients (prefix +
/// port range) plus the already-resolved action. Lowering into ACL field
/// predicates is deferred to the table-build step (see `TwoTupleKey` /
/// `SingletonKey`), so the choice of backend lives at a single site rather than
/// being baked in here at the front of the pipeline.
#[derive(Debug, Clone)]
struct PeeringRule<V> {
    ip_range: Prefix,
    port_range: RangeSpec<u16>,
    action: V,
}

impl<V: FromPeeringEndPrefix> From<&PeeringPrefixInfo> for PeeringRule<V> {
    fn from(prefix: &PeeringPrefixInfo) -> Self {
        Self {
            ip_range: prefix.ip_range,
            port_range: prefix.into(),
            action: V::from(prefix),
        }
    }
}

// -----------------------------------------------------------------------

#[derive(Debug, Clone)]
struct PeeringEndsContext<V> {
    tcp: Vec<PeeringRule<V>>,
    udp: Vec<PeeringRule<V>>,
    other: Vec<PeeringRule<V>>,
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
    fn insert(&mut self, rule: PeeringRule<V>, proto: L4Protocol) {
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

#[derive(Debug, Default, Clone)]
struct VpcContext {
    local_ends: HashMap<VpcDiscriminant, PeeringEndsContext<NatMode>>,
    remote_ends: PeeringEndsContext<Verdict>,
    default_remote_vpcd: Option<VpcDiscriminant>,
}

impl VpcContext {
    fn insert(&mut self, peering_info: &PeeringInfo) {
        let mut local_context = PeeringEndsContext::<NatMode>::default();
        for prefix in &peering_info.local.prefixes {
            local_context.insert(PeeringRule::from(prefix), prefix.proto);
        }
        local_context.has_default |= peering_info.local.has_default;
        self.local_ends
            .insert(peering_info.remote_vpcd, local_context);

        for prefix in &peering_info.remote.prefixes {
            self.remote_ends
                .insert(PeeringRule::from(prefix), prefix.proto);
        }
        self.remote_ends.has_default |= peering_info.remote.has_default;
    }
}

// -----------------------------------------------------------------------

#[derive(MatchKey, Clone)]
struct TwoTupleIpv4 {
    #[prefix]
    ip_range: Ipv4Addr,
    #[range]
    port_range: u16,
}

impl TwoTupleIpv4 {
    fn new(ip_range: Ipv4Addr, port_range: Option<u16>) -> Self {
        Self {
            ip_range,
            port_range: port_range.unwrap_or(0),
        }
    }
}

#[derive(MatchKey, Clone)]
struct SingletonIpv4 {
    #[prefix]
    ip_range: Ipv4Addr,
}

impl From<TwoTupleIpv4> for SingletonIpv4 {
    fn from(tuple: TwoTupleIpv4) -> Self {
        Self {
            ip_range: tuple.ip_range,
        }
    }
}

#[derive(MatchKey, Clone)]
struct TwoTupleIpv6 {
    #[prefix]
    ip_range: Ipv6Addr,
    #[range]
    port_range: u16,
}

impl TwoTupleIpv6 {
    fn new(ip_range: Ipv6Addr, port_range: Option<u16>) -> Self {
        Self {
            ip_range,
            port_range: port_range.unwrap_or(0),
        }
    }
}

#[derive(MatchKey, Clone)]
struct SingletonIpv6 {
    #[prefix]
    ip_range: Ipv6Addr,
}

impl From<TwoTupleIpv6> for SingletonIpv6 {
    fn from(tuple: TwoTupleIpv6) -> Self {
        Self {
            ip_range: tuple.ip_range,
        }
    }
}

// -----------------------------------------------------------------------
// Backend lowering layer.
//
// This is the single site where source rules are lowered into ACL field
// predicates. Switching the reference backend for a hardware backend means
// changing `RuleBackend` (and the table types in `PeeringEndsTables`) here --
// the build pipeline above stays backend-agnostic.

type RuleBackend = Erased;

/// A two-field key (prefix + port range), buildable from a `PeeringRule`.
trait TwoTupleKey: MatchKey {
    fn predicates(ip_range: Prefix, port_range: RangeSpec<u16>) -> Option<Vec<FieldPredicate>>;
}

/// A single-field key (prefix only), buildable from a `PeeringRule`. Used for
/// non-TCP/UDP traffic, where L4 ports are not meaningful and so are dropped
/// from the match.
trait SingletonKey: MatchKey {
    fn predicates(ip_range: Prefix) -> Option<Vec<FieldPredicate>>;
}

impl TwoTupleKey for TwoTupleIpv4 {
    fn predicates(ip_range: Prefix, port_range: RangeSpec<u16>) -> Option<Vec<FieldPredicate>> {
        let Prefix::IPV4(ip_range) = ip_range else {
            return None;
        };
        Some(
            TwoTupleIpv4Rule {
                ip_range: ip_range.into(),
                port_range,
            }
            .into_backend_fields::<RuleBackend>(),
        )
    }
}

impl TwoTupleKey for TwoTupleIpv6 {
    fn predicates(ip_range: Prefix, port_range: RangeSpec<u16>) -> Option<Vec<FieldPredicate>> {
        let Prefix::IPV6(ip_range) = ip_range else {
            return None;
        };
        Some(
            TwoTupleIpv6Rule {
                ip_range: ip_range.into(),
                port_range,
            }
            .into_backend_fields::<RuleBackend>(),
        )
    }
}

impl SingletonKey for SingletonIpv4 {
    fn predicates(ip_range: Prefix) -> Option<Vec<FieldPredicate>> {
        let Prefix::IPV4(ip_range) = ip_range else {
            return None;
        };
        Some(
            SingletonIpv4Rule {
                ip_range: ip_range.into(),
            }
            .into_backend_fields::<RuleBackend>(),
        )
    }
}

impl SingletonKey for SingletonIpv6 {
    fn predicates(ip_range: Prefix) -> Option<Vec<FieldPredicate>> {
        let Prefix::IPV6(ip_range) = ip_range else {
            return None;
        };
        Some(
            SingletonIpv6Rule {
                ip_range: ip_range.into(),
            }
            .into_backend_fields::<RuleBackend>(),
        )
    }
}

/// Lower a bucket of source rules into a two-field (prefix + port) table.
fn build_two_tuple<T: TwoTupleKey, V>(rules: Vec<PeeringRule<V>>) -> ReferenceTable<T, V> {
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

/// Lower a bucket of source rules into a single-field (prefix only) table,
/// dropping the port predicate.
fn build_singleton<U: SingletonKey, V>(rules: Vec<PeeringRule<V>>) -> ReferenceTable<U, V> {
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
        let verdict = self
            .remote_ends
            .lookup(proto, dst_tuple)
            .cloned()
            .or_else(|| {
                self.default_remote_vpcd.map(|dst_vpcd| Verdict {
                    nat_mode: NatMode::NoNat,
                    dst_vpcd,
                })
            })?;
        let local_table = self.local_ends.get(&verdict.dst_vpcd)?;
        let nat_mode =
            local_table
                .lookup(proto, src_tuple)
                .copied()
                .or(if local_table.has_default {
                    Some(NatMode::NoNat)
                } else {
                    None
                })?;
        Some((verdict, nat_mode))
    }
}

#[derive(Default)]
pub(crate) struct PeeringTables {
    v4: HashMap<VpcDiscriminant, VpcTable<TwoTupleIpv4, SingletonIpv4>>,
    v6: HashMap<VpcDiscriminant, VpcTable<TwoTupleIpv6, SingletonIpv6>>,
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
                let peering_info = PeeringInfo::from_peering(remote_vpcd, peering);
                if peering.is_v4() {
                    vpc_context_v4.insert(&peering_info);
                    if peering.remote().has_default_expose() {
                        vpc_context_v4.default_remote_vpcd = Some(remote_vpcd);
                    }
                } else {
                    vpc_context_v6.insert(&peering_info);
                    if peering.remote().has_default_expose() {
                        vpc_context_v6.default_remote_vpcd = Some(remote_vpcd);
                    }
                }
            }
            if !vpc_context_v4.local_ends.is_empty() {
                tables.v4.insert(
                    local_vpcd,
                    VpcTable::<TwoTupleIpv4, SingletonIpv4>::from(vpc_context_v4),
                );
            }
            if !vpc_context_v6.local_ends.is_empty() {
                tables.v6.insert(
                    local_vpcd,
                    VpcTable::<TwoTupleIpv6, SingletonIpv6>::from(vpc_context_v6),
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
        match (src_ip, dst_ip) {
            (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => self.v4.get(&src_vpcd).and_then(|table| {
                table
                    .lookup(
                        proto,
                        &TwoTupleIpv4::new(src_ip, src_port),
                        &TwoTupleIpv4::new(dst_ip, dst_port),
                    )
                    .map(|(verdict, nat_mode)| {
                        (verdict.dst_vpcd, verdict.nat_mode.into(), nat_mode.into())
                    })
            }),
            (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => self.v6.get(&src_vpcd).and_then(|table| {
                table
                    .lookup(
                        proto,
                        &TwoTupleIpv6::new(src_ip, src_port),
                        &TwoTupleIpv6::new(dst_ip, dst_port),
                    )
                    .map(|(verdict, nat_mode)| {
                        (verdict.dst_vpcd, verdict.nat_mode.into(), nat_mode.into())
                    })
            }),
            _ => {
                debug!(
                    "Source and destination IP versions do not match: src_ip={src_ip:?}, dst_ip={dst_ip:?}",
                );
                None
            }
        }
    }
}
