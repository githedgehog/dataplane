// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What a NIC may do for a gateway's policy: a backend-neutral program compiled from the typed
//! match-action rules software keeps, today those of the ACL filter (its denies) and of the rate
//! limiter.
//!
//! The contract is a *cascade*: a NIC may only drop what software would drop too, and never changes
//! a packet, so the software pipeline stays authoritative and unchanged. Anything that cannot keep
//! that promise is refused and stays in software alone.
//!
//! The ACL filter and the rate limiter decide independently, each by its own first match; the
//! program keeps them apart, so the NIC does too (see [`mlx5`](crate::mlx5)).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};

use acl_filter::{AclFilterContext, AclKey, AclKeyRule, LookupResult};
use config::external::overlay::acl::AclAction;
use config::external::overlay::ratelimit::ColorAction;
use flow_filter::Destination;
use lpm::prefix::with_ports::{KeyPort, PortRange};
use match_action::{ExactSpec, FixedSize, MaskSpec, PrefixSpec, RangeSpec};
use net::ip::NextHeader;
use net::tcp::TcpFlags;
use net::vxlan::Vni;
use policer::{Color, Profile};
use rate_limit::{
    Action, Billing, IngressKey, IngressKeyRule, IngressRules, PeeringKey, PeeringKeyRule,
    PeeringRules, RateLimits, RuleIndex, RuleRow, Unit,
};

/// An address prefix of either family.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Prefix {
    /// IPv4 address and length.
    V4(Ipv4Addr, u8),
    /// IPv6 address and length.
    V6(Ipv6Addr, u8),
}

impl Prefix {
    /// The prefix with the address bits past its length cleared: prefixes that match the same
    /// addresses are equal.
    #[must_use]
    pub fn canonical(self) -> Prefix {
        match self {
            Prefix::V4(addr, len) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(len.min(32)))
                    .unwrap_or(0);
                Prefix::V4(Ipv4Addr::from(u32::from(addr) & mask), len)
            }
            Prefix::V6(addr, len) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(len.min(128)))
                    .unwrap_or(0);
                Prefix::V6(Ipv6Addr::from(u128::from(addr) & mask), len)
            }
        }
    }

    /// The prefix length, in bits.
    #[must_use]
    pub fn bits(self) -> u8 {
        match self {
            Prefix::V4(_, len) | Prefix::V6(_, len) => len,
        }
    }

    /// Whether every address of `other` is in this prefix.
    #[must_use]
    pub fn contains(self, other: Prefix) -> bool {
        match (self, other) {
            (Prefix::V4(_, len), Prefix::V4(addr, other_len)) => {
                other_len >= len && Prefix::V4(addr, len).canonical() == self.canonical()
            }
            (Prefix::V6(_, len), Prefix::V6(addr, other_len)) => {
                other_len >= len && Prefix::V6(addr, len).canonical() == self.canonical()
            }
            _ => false,
        }
    }

    /// The addresses `self` and `other` both match, as a prefix, if any: prefixes either nest
    /// or are disjoint.
    #[must_use]
    pub fn intersection(self, other: Prefix) -> Option<Prefix> {
        if self.contains(other) {
            Some(other)
        } else if other.contains(self) {
            Some(self)
        } else {
            None
        }
    }
}

impl From<&lpm::prefix::Prefix> for Prefix {
    fn from(prefix: &lpm::prefix::Prefix) -> Self {
        match prefix.as_address() {
            std::net::IpAddr::V4(addr) => Prefix::V4(addr, prefix.length()),
            std::net::IpAddr::V6(addr) => Prefix::V6(addr, prefix.length()),
        }
        .canonical()
    }
}

/// What a rule matches, as a NIC sees the frame.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Match {
    /// The source VPC.
    pub src_vni: Vni,
    /// Inner source prefix.
    pub source: Prefix,
    /// Inner destination prefix; with `src_vni`, it stands in for the destination VPC.
    pub destination: Prefix,
    /// IP protocol, or any.
    pub proto: Option<u8>,
    /// Source ports, or any: exact, but in ingress rules, which may name ranges.
    pub src_port: Option<PortRange>,
    /// Destination ports, or any; as `src_port`.
    pub dst_port: Option<PortRange>,
    /// TCP flag values and the mask of flags constrained, or any (TCP only).
    pub tcp_flags: Option<(u8, u8)>,
}

impl Match {
    /// Whether some packet matches both.
    #[must_use]
    pub fn overlaps(&self, other: &Match) -> bool {
        fn either<T: PartialEq>(a: Option<T>, b: Option<T>) -> bool {
            a.zip(b).is_none_or(|(a, b)| a == b)
        }
        let ports = |a: Option<PortRange>, b: Option<PortRange>| {
            a.zip(b).is_none_or(|(a, b)| a.overlaps(b))
        };
        self.src_vni == other.src_vni
            && self.source.intersection(other.source).is_some()
            && self.destination.intersection(other.destination).is_some()
            && either(self.proto, other.proto)
            && ports(self.src_port, other.src_port)
            && ports(self.dst_port, other.dst_port)
            && self
                .tcp_flags
                .zip(other.tcp_flags)
                .is_none_or(|((a, am), (b, bm))| (a ^ b) & am & bm == 0)
    }
}

/// Which policy a meter is of: names are unique within one only (a peering named `ingress` has
/// meters named `ingress/...`, as the ingress policy does), so a meter is known by both.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    /// A peering's rate limits.
    Peering,
    /// The gateway's ingress policy.
    Ingress,
}

impl Scope {
    /// Its `policy` label in metrics, as software's meters are labelled.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Scope::Peering => "peering",
            Scope::Ingress => "ingress",
        }
    }
}

/// The meter component a NIC enforces for a named meter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoliceMeter {
    /// The meter's name, for counters and logs.
    pub name: String,
    /// The policy it is of.
    pub scope: Scope,
    /// What its tokens count.
    pub unit: Unit,
    /// What a byte is, for [`Unit::Bytes`]: the software meter's, which the NIC's must allow for.
    pub billing: Billing,
    /// Rates and bursts, in `unit`.
    pub profile: Profile,
    /// How far software's per-worker leases may let a burst exceed each bucket, committed then
    /// excess, in `unit`.
    pub lease_slack: [u64; 2],
}

/// A peering, by the VNIs of its two VPCs, in either direction: what is offloaded whole or not at
/// all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Peering(Vni, Vni);

impl Peering {
    /// The peering between the VPCs of `a` and `b`.
    #[must_use]
    pub fn new(a: Vni, b: Vni) -> Peering {
        Peering(a.min(b), a.max(b))
    }
}

impl Peering {
    /// The peering's VPC other than `vni`'s.
    #[must_use]
    pub fn other(self, vni: Vni) -> Vni {
        if self.0 == vni { self.1 } else { self.0 }
    }

    /// The VNIs of its two VPCs.
    #[must_use]
    pub fn vnis(self) -> [Vni; 2] {
        [self.0, self.1]
    }
}

impl std::fmt::Display for Peering {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "peering of VNIs {} and {}",
            self.0.as_u32(),
            self.1.as_u32()
        )
    }
}

/// A rate limit a NIC may enforce: the traffic it matches, and the meter it charges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoliceRule {
    /// The configured rule this came from.
    pub rule: RuleIndex,
    /// Its peering.
    pub peering: Peering,
    /// What it matches.
    pub matches: Match,
    /// Index into [`Program::meters`].
    pub meter: usize,
    /// See [`DenyRule::level`].
    pub level: u8,
}

/// An ACL deny a NIC may enforce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenyRule {
    /// Where it came from.
    pub origin: Origin,
    /// Its peering.
    pub peering: Peering,
    /// What it matches.
    pub matches: Match,
    /// The prefix length of the most specific destination of its peer it was narrowed to: rules
    /// of more specific destinations are matched first, and between them the passes of other
    /// peers' destinations ([`Program::passes`]).
    pub level: u8,
}

/// What a NIC does with what an ingress rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IngressVerdict {
    /// Drop it.
    Drop,
    /// Charge this meter (by index into [`Program::meters`]), drop red, then charge the second, if
    /// any, with what is left, drop red, and go on with the source VPC's peering policy. The two
    /// are a software meter's bytes and packets components, metered color-blind in the NIC.
    Police(usize, Option<usize>),
    /// Go on with the source VPC's peering policy: the rule takes the packet in software, but drops
    /// nothing.
    Continue,
    /// Hand it to software untouched, skipping the peering policy too: the rule is one the NIC
    /// cannot enforce, and its match may be wider than the rule's.
    Pass,
}

impl IngressVerdict {
    /// Whether it charges `meter` (by index into [`Program::meters`]).
    #[must_use]
    pub fn charges(self, meter: usize) -> bool {
        matches!(self, IngressVerdict::Police(first, then) if first == meter || then == Some(meter))
    }
}

/// A rule of the gateway's ingress policy, as a NIC enforces it. Ingress rules come before the
/// peering policy of their source VPC, as the ingress stage comes first in software.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressRule {
    /// Where it came from.
    pub origin: Origin,
    /// What it matches: what the software rule matches, or, for a [`IngressVerdict::Pass`],
    /// possibly more.
    pub matches: Match,
    /// What it does.
    pub verdict: IngressVerdict,
    /// Rules of lower layers are matched first. A rule's layer is above that of every earlier rule
    /// it overlaps with another verdict, so whichever rule of the lowest layer a packet matches
    /// does what the first rule it matches in software does.
    pub layer: u32,
    /// Whether it matches fragments too, as software does: a rule naming no protocol (so no ports
    /// or flags) matches every fragment of what it matches. Unless an earlier rule with another
    /// verdict that matches no fragments in the NIC overlaps it: software may match a first
    /// fragment to that one (it parses the protocol and ports of first fragments), so the NIC must
    /// not take it to this one. Every other rule matches no fragment in the NIC.
    pub fragments: bool,
}

/// What a NIC must leave to software, as offloading it failed or cannot be exact.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Exclusions {
    /// Peerings left in software, whole.
    pub peerings: BTreeSet<Peering>,
    /// Source VPCs whose ingress rules a NIC may not enforce: those, and every peering of the VPC,
    /// stay in software (a NIC enforcing a peering's rules without the ingress policy before them
    /// could charge meters with what software drops first).
    pub vpcs: BTreeSet<Vni>,
    /// Ingress meters a NIC cannot enforce, by name: their rules pass to software.
    pub ingress_meters: BTreeSet<String>,
    /// Ingress rules a NIC refused, by table (whether IPv6) and row, as [`Origin::Ingress`] names
    /// them: they pass to software, and the rest of their VPC's and meter's rules stay.
    pub ingress_rules: BTreeSet<(bool, usize)>,
}

impl Exclusions {
    /// Leave `peerings` in software.
    #[must_use]
    pub fn peerings(peerings: BTreeSet<Peering>) -> Exclusions {
        Exclusions {
            peerings,
            ..Exclusions::default()
        }
    }

    /// Whether everything `self` leaves to software, `other` does too.
    #[must_use]
    pub fn is_subset(&self, other: &Exclusions) -> bool {
        self.peerings.is_subset(&other.peerings)
            && self.vpcs.is_subset(&other.vpcs)
            && self.ingress_meters.is_subset(&other.ingress_meters)
            && self.ingress_rules.is_subset(&other.ingress_rules)
    }

    /// Leave what `other` leaves to software there too.
    pub fn extend(&mut self, other: Exclusions) {
        self.peerings.extend(other.peerings);
        self.vpcs.extend(other.vpcs);
        self.ingress_meters.extend(other.ingress_meters);
        self.ingress_rules.extend(other.ingress_rules);
    }

    /// Whether `peering` stays in software.
    fn excludes(&self, peering: Peering) -> bool {
        self.peerings.contains(&peering) || peering.vnis().iter().any(|v| self.vpcs.contains(v))
    }
}

/// The software rule a program rule or refusal came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// A rate-limit rule, by its index in the configuration.
    RateLimit(RuleIndex),
    /// A peering's ACL default action.
    AclDefault(Peering),
    /// An ACL rule, by its position in the ACL filter's table of its family.
    Acl {
        /// Whether the IPv6 table.
        v6: bool,
        /// The position in that table.
        row: usize,
    },
    /// An ingress rule, by its position in the ingress classifier's table of its family.
    Ingress {
        /// Whether the IPv6 table.
        v6: bool,
        /// The position in that table.
        row: usize,
    },
}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Origin::RateLimit(rule) => write!(f, "rate-limit rule {rule}"),
            Origin::AclDefault(peering) => write!(f, "the ACL default of the {peering}"),
            Origin::Acl { v6, row } => {
                write!(
                    f,
                    "ACL rule {row} of the IPv{} table",
                    if *v6 { 6 } else { 4 }
                )
            }
            Origin::Ingress { v6, row } => {
                write!(
                    f,
                    "ingress rule {row} of the IPv{} table",
                    if *v6 { 6 } else { 4 }
                )
            }
        }
    }
}

/// Why a peering's policy stays in software only: something of it no NIC may enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// ACL logging needs packets to reach software, including packets a NIC meter could drop.
    Logging,
    /// The ACL denies by default: whether a packet no rule matches passes depends on flow state
    /// (the replies of flows an allow opened).
    DefaultDeny,
    /// TCP flags matched on a protocol other than TCP.
    TcpFlags,
    /// Only an exact protocol, or any, is lowered.
    PartialProtocolMask,
    /// The protocol is an extension header's (hop-by-hop, routing, fragment, authentication,
    /// destination options): software resolves extension headers to the protocol after them, so
    /// the rule never matches there, and mlx5 refuses such a match outright.
    ExtensionHeader,
    /// Only an exact port, or any, is lowered for peering rules (ingress rules take ranges too).
    PortRange,
    /// Ports without TCP or UDP.
    PortsWithoutTransport,
    /// The NIC refused one of the peering's rules when it was installed.
    NotInstalled,
    /// A rate limit of traffic from a VPC the NIC polices at ingress: the NIC's ingress meters
    /// pass on some of what software's drop, which the NIC would charge the rate limit's meter
    /// for.
    IngressPoliced,
    /// An earlier rule with another meter, or another verdict, matches some of the same traffic:
    /// in hardware the two could not keep their order.
    Overlap,
}

/// The policy a NIC may enforce, and what it may not.
///
/// A peering is enforced in the NIC whole, or not at all: all of its ACL denies and rate limits,
/// or none. Then the NIC never charges a meter for a packet software denies (the NIC denied it
/// first), and a peering's policy is in one place or the other, never split. Rules that drop
/// nothing (ACL allows, meters that drop nothing) need nothing in the NIC.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Program {
    /// ACL denies, IPv4 then IPv6, each in first-match order.
    pub denies: Vec<DenyRule>,
    /// One meter component per named meter some rule charges.
    pub meters: Vec<PoliceMeter>,
    /// The rate limits, IPv4 then IPv6, each in first-match order.
    pub rules: Vec<PoliceRule>,
    /// The ingress policy's rules, IPv4 then IPv6, each in first-match order.
    pub ingress: Vec<IngressRule>,
    /// The peerings left in software, with what of each no NIC may enforce.
    pub refused: Vec<(Peering, Origin, Refusal)>,
    /// By source VPC, the destinations of its other peers its rules must let pass untouched: a
    /// rule's destination prefix covers them, but software sends their traffic to another peer
    /// than the rule's. A pass applies to the rules of less specific destinations
    /// ([`DenyRule::level`] below its prefix length) only: those of its own peer, and of more
    /// specific destinations inside it, are matched before it.
    pub passes: BTreeMap<Vni, BTreeSet<Prefix>>,
}

/// A flow-filter destination, as narrowing reads it.
struct Route {
    dst_vni: Vni,
    prefix: Prefix,
    /// Gated or partial: it takes only some of its prefix's traffic.
    some: bool,
}

/// Where software sends a source VPC's traffic: flow-filter's destinations, from which a rule's
/// destination prefix is narrowed to what goes to the rule's peer.
struct Routing {
    /// The destinations, by source VPC, in flow-filter's order.
    routes: BTreeMap<Vni, Vec<Route>>,
    passes: BTreeMap<Vni, BTreeSet<Prefix>>,
}

impl Routing {
    fn new(destinations: &[Destination]) -> Routing {
        let mut routes: BTreeMap<Vni, Vec<Route>> = BTreeMap::new();
        for d in destinations {
            routes.entry(d.src_vni).or_default().push(Route {
                dst_vni: d.dst_vni,
                prefix: Prefix::from(&d.prefix),
                some: d.gated || d.partial,
            });
        }
        Routing {
            routes,
            passes: BTreeMap::new(),
        }
    }

    /// `matches` of a rule for the traffic `src_vni` sends to `dst_vni`, narrowed to each of
    /// `dst_vni`'s destinations it overlaps (none: it matches nothing software sends there), each
    /// with its level ([`DenyRule::level`]). The other peers' destinations that take some of a
    /// narrowed match's traffic (at least as specific as the destination it was narrowed with) are
    /// recorded to pass untouched.
    ///
    /// A gated destination (masquerade) takes only replies, and a partial one (port forwarding)
    /// only some protocols and ports: the rest of their prefix goes to other peers, even less
    /// specific ones. A rule is not narrowed to them, so what software sends there it enforces
    /// alone. Nor to a destination another peer has too: which of the two takes its traffic is
    /// flow-filter's order, which a pass of the same level cannot follow.
    fn narrow(&mut self, dst_vni: Vni, matches: &Match) -> Vec<(Match, u8)> {
        let src_vni = matches.src_vni;
        let Some(routes) = self.routes.get(&src_vni) else {
            return Vec::new();
        };
        let mut narrowed: Vec<(Match, u8)> = Vec::new();
        for own in routes.iter().filter(|r| r.dst_vni == dst_vni && !r.some) {
            let Some(destination) = own.prefix.intersection(matches.destination) else {
                continue;
            };
            let others = || routes.iter().filter(|r| r.dst_vni != dst_vni);
            if others().any(|other| other.prefix == own.prefix) {
                continue;
            }
            for other in others() {
                if other.prefix.bits() >= own.prefix.bits()
                    && other.prefix.intersection(destination).is_some()
                {
                    self.passes.entry(src_vni).or_default().insert(other.prefix);
                }
            }
            let m = Match {
                destination,
                ..matches.clone()
            };
            // Matched from the most specific destination that holds it: a pass between that and
            // a less specific one would take traffic software sends to this peer.
            let level = own.prefix.bits();
            match narrowed.iter_mut().find(|(n, _)| *n == m) {
                Some((_, known)) => *known = (*known).max(level),
                None => narrowed.push((m, level)),
            }
        }
        narrowed
    }
}

/// The component of `meter` a NIC enforces, if it drops red: the bytes one if there is one, else
/// the packets one. Enforcing one component of a chain is conservative: the chain only ever makes a
/// color worse.
fn component<C>(limits: &RateLimits<C>, meter: usize) -> Option<Component> {
    let meter = limits.meters().get(meter)?;
    // With both, software meters packets with the colors the bytes component left them, which a
    // NIC meter cannot: only the bytes component is enforced.
    let unit = if meter.component(Unit::Bytes).is_some() {
        Unit::Bytes
    } else {
        Unit::Packets
    };
    let component = meter.component(unit)?;
    (component.action(Color::Red) == ColorAction::Drop).then(|| Component {
        unit,
        profile: component.profile(),
        lease_slack: component.lease_slack(),
    })
}

/// The components of `meter` a NIC enforces, bytes then packets, each dropping red, chained
/// color-blind. Software chains them color-aware and stops at the first drop
/// (`rate_limit::stage`), so the NIC enforces a component only where it charges it for nothing
/// software does not charge it for:
/// - a packet the bytes component colors red stays red in the packets one, uncharged, and is
///   dropped if either component drops red: the NIC's bytes meter drops red if either does;
/// - the NIC charges its packets meter for everything its bytes meter passes (everything, without
///   one), software for what its bytes component colors green or yellow and does not drop: the NIC
///   enforces the packets component only if it drops red and the bytes component passes yellow.
///   Otherwise only the bytes one, which is more permissive still.
///
/// So enforced, the two are as permissive as software's chain: traffic software colors nothing
/// red, the NIC colors nothing red (`meters.rs`).
fn components<C>(limits: &RateLimits<C>, meter: usize) -> [Option<Component>; 2] {
    let Some(meter) = limits.meters().get(meter) else {
        return [None, None];
    };
    let drops = |c: &rate_limit::Component, color| c.action(color) == ColorAction::Drop;
    let enforced = |unit, c: &rate_limit::Component| Component {
        unit,
        profile: c.profile(),
        lease_slack: c.lease_slack(),
    };
    match (meter.component(Unit::Bytes), meter.component(Unit::Packets)) {
        (None, None) => [None, None],
        (Some(b), None) => [drops(b, Color::Red).then(|| enforced(Unit::Bytes, b)), None],
        (None, Some(p)) => [
            None,
            drops(p, Color::Red).then(|| enforced(Unit::Packets, p)),
        ],
        (Some(b), Some(p)) => [
            (drops(b, Color::Red) || drops(p, Color::Red)).then(|| enforced(Unit::Bytes, b)),
            (drops(p, Color::Red) && !drops(b, Color::Yellow)).then(|| enforced(Unit::Packets, p)),
        ],
    }
}

/// The component of a software meter a NIC enforces.
#[derive(Debug, Clone, Copy)]
struct Component {
    unit: Unit,
    profile: Profile,
    lease_slack: [u64; 2],
}

fn proto(spec: MaskSpec<NextHeader>) -> Result<Option<u8>, Refusal> {
    match spec.mask.as_u8() {
        0 => Ok(None),
        u8::MAX if spec.value.is_ipv6_extension() => Err(Refusal::ExtensionHeader),
        u8::MAX => Ok(Some(spec.value.as_u8())),
        _ => Err(Refusal::PartialProtocolMask),
    }
}

/// The ports a NIC matches for `spec`: any, one, or, if `ranges`, a range. Port 0 alone stands for
/// no port in software, which no NIC match says.
fn port(spec: RangeSpec<KeyPort>, ranges: bool) -> Result<Option<PortRange>, Refusal> {
    match (spec.min.get(), spec.max.get()) {
        (0, u16::MAX) => Ok(None),
        (min, max) if min == max && min != 0 => Ok(Some(PortRange::single(min))),
        (min, max) if ranges && min < max => Ok(PortRange::new(min, max).ok()),
        _ => Err(Refusal::PortRange),
    }
}

/// The fields of a typed rule, whichever table it is from: rate limits and ACLs match alike.
struct Fields<I: FixedSize> {
    proto: MaskSpec<NextHeader>,
    src_vni: ExactSpec<Vni>,
    source: PrefixSpec<I>,
    destination: PrefixSpec<I>,
    src_port: RangeSpec<KeyPort>,
    dst_port: RangeSpec<KeyPort>,
    tcp_flags: MaskSpec<TcpFlags>,
}

impl<I: FixedSize> From<&PeeringKeyRule<I>> for Fields<I> {
    fn from(rule: &PeeringKeyRule<I>) -> Self {
        Fields {
            proto: rule.proto,
            src_vni: rule.src_vni,
            source: rule.source,
            destination: rule.destination,
            src_port: rule.src_port,
            dst_port: rule.dst_port,
            tcp_flags: rule.tcp_flags,
        }
    }
}

impl<I: FixedSize> From<&AclKeyRule<I>> for Fields<I> {
    fn from(rule: &AclKeyRule<I>) -> Self {
        Fields {
            proto: rule.proto,
            src_vni: rule.src_vni,
            source: rule.src_ip_range,
            destination: rule.dst_ip_range,
            src_port: rule.src_port_range,
            dst_port: rule.dst_port_range,
            tcp_flags: rule.tcp_flags,
        }
    }
}

impl<I: FixedSize> From<&IngressKeyRule<I>> for Fields<I> {
    fn from(rule: &IngressKeyRule<I>) -> Self {
        Fields {
            proto: rule.proto,
            src_vni: rule.src_vni,
            source: rule.source,
            destination: rule.destination,
            src_port: rule.src_port,
            dst_port: rule.dst_port,
            tcp_flags: rule.tcp_flags,
        }
    }
}

/// What a NIC can match of one typed rule's fields, matching at least what they do: a constraint
/// it cannot lower is left out.
fn widen<I: FixedSize>(rule: &Fields<I>, prefix: impl Fn(PrefixSpec<I>) -> Prefix) -> Match {
    let proto = proto(rule.proto).ok().flatten();
    let transport = matches!(proto, Some(6 | 17));
    let port = |spec| {
        if transport {
            port(spec, true).ok().flatten()
        } else {
            None
        }
    };
    Match {
        src_vni: rule.src_vni.value,
        source: prefix(rule.source).canonical(),
        destination: prefix(rule.destination).canonical(),
        proto,
        src_port: port(rule.src_port),
        dst_port: port(rule.dst_port),
        tcp_flags: (proto == Some(6) && rule.tcp_flags.mask != TcpFlags::empty())
            .then(|| (rule.tcp_flags.value.bits(), rule.tcp_flags.mask.bits())),
    }
}

/// Lower one typed rule's fields; port ranges only if `ranges`.
fn lower<I: FixedSize>(
    rule: &Fields<I>,
    prefix: impl Fn(PrefixSpec<I>) -> Prefix,
    ranges: bool,
) -> Result<Match, Refusal> {
    let proto = proto(rule.proto)?;
    let tcp_flags = (rule.tcp_flags.mask != TcpFlags::empty())
        .then(|| (rule.tcp_flags.value.bits(), rule.tcp_flags.mask.bits()));
    if tcp_flags.is_some() && proto != Some(6) {
        return Err(Refusal::TcpFlags);
    }
    let (src_port, dst_port) = (port(rule.src_port, ranges)?, port(rule.dst_port, ranges)?);
    if (src_port.is_some() || dst_port.is_some()) && !matches!(proto, Some(6 | 17)) {
        return Err(Refusal::PortsWithoutTransport);
    }
    let destination = prefix(rule.destination).canonical();
    Ok(Match {
        src_vni: rule.src_vni.value,
        source: prefix(rule.source).canonical(),
        destination,
        proto,
        src_port,
        dst_port,
        tcp_flags,
    })
}

/// A rate limit that may be offloaded, before its peering is known to be.
struct Candidate {
    rule: PoliceRule,
    /// The software meter, and the component a NIC enforces of it.
    meter: usize,
    component: Component,
}

/// The rules of a policy that may be offloaded, and the peerings that may not.
#[derive(Default)]
struct Compilation {
    denies: Vec<DenyRule>,
    rules: Vec<Candidate>,
    refused: Vec<(Peering, Origin, Refusal)>,
}

impl Program {
    /// Compile what a NIC may enforce of `acls`, `limits` and the `ingress` policy: every peering
    /// whose whole policy it may enforce, and the ingress rules of every source VPC, but what
    /// `excluded` leaves to software (refused by the NIC before). Nothing, if offload is turned
    /// off ([`RateLimits::attempt_offloads`]).
    #[must_use]
    pub fn compile(
        acls: &AclFilterContext,
        limits: &RateLimits<PeeringRules>,
        ingress: &RateLimits<IngressRules>,
        destinations: &[Destination],
        excluded: &Exclusions,
    ) -> Program {
        if !limits.attempt_offloads() {
            return Program::default();
        }
        let mut c = Compilation::default();
        for (src, dst, action) in acls.default_actions() {
            if action == AclAction::Deny {
                let peering = Peering::new(src, dst);
                c.refused
                    .push((peering, Origin::AclDefault(peering), Refusal::DefaultDeny));
            }
        }
        c.denies(acls.v4(), false, |p| Prefix::V4(p.value, p.len));
        c.denies(acls.v6(), true, |p| Prefix::V6(p.value, p.len));
        let classifier = limits.classifier();
        c.limits(limits, classifier.v4(), |p| Prefix::V4(p.value, p.len));
        c.limits(limits, classifier.v6(), |p| Prefix::V6(p.value, p.len));
        c.policed(ingress, excluded);

        let left: BTreeSet<Peering> = c
            .refused
            .iter()
            .map(|(peering, ..)| *peering)
            .chain(excluded.peerings.iter().copied())
            .collect();
        let left = |peering: Peering| left.contains(&peering) || excluded.excludes(peering);
        // A rule's destination prefix stands for its peer only as narrowed to what software
        // sends that peer.
        let mut routing = Routing::new(destinations);
        // A rule identical to an earlier one (of its source VPC: the VNI is part of the match)
        // adds nothing: an earlier identical rate limit charges the same meter, or the later one
        // overlaps another meter's and is refused. And mlx5 takes identical rules into one table
        // but fails to remove the second.
        let mut denies: Vec<DenyRule> = Vec::new();
        let mut seen: HashSet<Match> = HashSet::new();
        for deny in c.denies {
            if left(deny.peering) {
                continue;
            }
            let dst_vni = deny.peering.other(deny.matches.src_vni);
            for (matches, level) in routing.narrow(dst_vni, &deny.matches) {
                if seen.insert(matches.clone()) {
                    denies.push(DenyRule {
                        matches,
                        level,
                        ..deny.clone()
                    });
                }
            }
        }
        let mut program = Program {
            denies,
            refused: c.refused,
            ..Program::default()
        };
        // Software meter index -> program meter index, for the meters kept rules charge.
        let mut meters: Vec<Option<usize>> = vec![None; limits.meters().len()];
        let mut seen: HashSet<Match> = HashSet::new();
        for Candidate {
            mut rule,
            meter,
            component:
                Component {
                    unit,
                    profile,
                    lease_slack,
                },
        } in c.rules
        {
            if left(rule.peering) {
                continue;
            }
            let dst_vni = rule.peering.other(rule.matches.src_vni);
            let narrowed: Vec<(Match, u8)> = routing
                .narrow(dst_vni, &rule.matches)
                .into_iter()
                .filter(|(m, _)| seen.insert(m.clone()))
                .collect();
            if narrowed.is_empty() {
                continue;
            }
            rule.meter = *meters[meter].get_or_insert_with(|| {
                program.meters.push(PoliceMeter {
                    name: limits.meters()[meter].name().to_string(),
                    scope: Scope::Peering,
                    unit,
                    billing: Billing::Ip,
                    profile,
                    lease_slack,
                });
                program.meters.len() - 1
            });
            for (matches, level) in narrowed {
                program.rules.push(PoliceRule {
                    matches,
                    level,
                    ..rule.clone()
                });
            }
        }
        program.passes = routing.passes;
        program.add_ingress(ingress, excluded);
        program
    }

    /// Add the ingress policy's rules, and the meters they charge.
    fn add_ingress(&mut self, ingress: &RateLimits<IngressRules>, excluded: &Exclusions) {
        let classifier = ingress.classifier();
        let rows = lowered(classifier.v4(), false, |p| Prefix::V4(p.value, p.len)).chain(lowered(
            classifier.v6(),
            true,
            |p| Prefix::V6(p.value, p.len),
        ));
        // Software meter index and component (whether packets) -> program meter index.
        let mut meters: BTreeMap<(usize, bool), usize> = BTreeMap::new();
        let mut seen: HashSet<Match> = HashSet::new();
        let mut rules: Vec<IngressRule> = Vec::new();
        // The rules so far, by source VPC: a rule overlaps only its own VPC's.
        let mut by_vni: HashMap<Vni, Vec<usize>> = HashMap::new();
        for (origin, index, lowered, widened) in rows {
            if excluded.vpcs.contains(&widened.src_vni) {
                continue;
            }
            let Some(rule) = ingress.rules().get(index) else {
                continue;
            };
            let exact = lowered.is_ok();
            let matches = lowered.unwrap_or(widened);
            // An identical rule after another is never taken; mlx5 fails to remove the second.
            // Left out before its meters are made, so that every meter has a rule.
            if !seen.insert(matches.clone()) {
                continue;
            }
            let refused = match origin {
                Origin::Ingress { v6, row } => excluded.ingress_rules.contains(&(v6, row)),
                _ => false,
            };
            let verdict = match rule.action() {
                _ if !exact || refused => IngressVerdict::Pass,
                Action::Drop => IngressVerdict::Drop,
                Action::Police(meter) => self.police(ingress, meter, excluded, &mut meters),
            };
            let own = by_vni.entry(matches.src_vni).or_default();
            let earlier = || {
                own.iter()
                    .map(|&i| &rules[i])
                    .filter(|e| e.verdict != verdict && e.matches.overlaps(&matches))
            };
            let layer = earlier().map(|e| e.layer + 1).max().unwrap_or(0);
            let fragments = matches.proto.is_none() && !earlier().any(|e| !e.fragments);
            own.push(rules.len());
            rules.push(IngressRule {
                origin,
                matches,
                verdict,
                layer,
                fragments,
            });
        }
        self.ingress = rules;
    }

    /// What an ingress rule charging software meter `meter` does in the NIC, making the meters
    /// it charges (once per software meter and component, in `meters`).
    fn police(
        &mut self,
        ingress: &RateLimits<IngressRules>,
        meter: usize,
        excluded: &Exclusions,
        meters: &mut BTreeMap<(usize, bool), usize>,
    ) -> IngressVerdict {
        let name = ingress.meters()[meter].name();
        if excluded.ingress_meters.contains(name) {
            return IngressVerdict::Pass;
        }
        let mut at = |component: Component| {
            *meters
                .entry((meter, component.unit == Unit::Packets))
                .or_insert_with(|| {
                    self.meters.push(PoliceMeter {
                        name: name.to_string(),
                        scope: Scope::Ingress,
                        unit: component.unit,
                        billing: Billing::OuterIp,
                        profile: component.profile,
                        lease_slack: component.lease_slack,
                    });
                    self.meters.len() - 1
                })
        };
        // Both components, chained: floods are as much a matter of packets as of bytes.
        match components(ingress, meter) {
            [None, None] => IngressVerdict::Continue,
            [Some(one), None] | [None, Some(one)] => IngressVerdict::Police(at(one), None),
            [Some(bytes), Some(packets)] => {
                let first = at(bytes);
                IngressVerdict::Police(first, Some(at(packets)))
            }
        }
    }
}

/// The source VPCs `ingress` has rules for: a NIC needs their VTEPs too, peered or not.
#[must_use]
pub fn ingress_vpcs(ingress: &RateLimits<IngressRules>) -> BTreeSet<Vni> {
    let classifier = ingress.classifier();
    let v4 = classifier.v4().iter().map(|r| r.rule.src_vni.value);
    let v6 = classifier.v6().iter().map(|r| r.rule.src_vni.value);
    v4.chain(v6).collect()
}

/// The ingress rules of one family's table, each with where it came from, its configured rule,
/// and what a NIC matches of it: exactly, if it can, and at least, in any case.
fn lowered<I: FixedSize>(
    rows: &[RuleRow<IngressKey<I>, RuleIndex>],
    v6: bool,
    prefix: fn(PrefixSpec<I>) -> Prefix,
) -> impl Iterator<Item = (Origin, RuleIndex, Result<Match, Refusal>, Match)> + '_ {
    rows.iter().enumerate().map(move |(row, r)| {
        let fields = Fields::from(&r.rule);
        (
            Origin::Ingress { v6, row },
            r.action,
            lower(&fields, prefix, true),
            widen(&fields, prefix),
        )
    })
}

impl Compilation {
    /// Refuse the rate limits of traffic from a VPC the NIC polices at ingress, with their
    /// peerings. The NIC's ingress meters are looser than software's: they pass on some of what
    /// software's ingress stage drops, which a peering meter after them in the NIC would be
    /// charged for, and run dry ahead of software's.
    fn policed(&mut self, ingress: &RateLimits<IngressRules>, excluded: &Exclusions) {
        let mut policing = Program::default();
        policing.add_ingress(ingress, excluded);
        let policed: BTreeSet<Vni> = policing
            .ingress
            .iter()
            .filter(|r| matches!(r.verdict, IngressVerdict::Police(..)))
            .map(|r| r.matches.src_vni)
            .collect();
        for candidate in &self.rules {
            if policed.contains(&candidate.rule.matches.src_vni) {
                self.refused.push((
                    candidate.rule.peering,
                    Origin::RateLimit(candidate.rule.rule),
                    Refusal::IngressPoliced,
                ));
            }
        }
    }

    /// The denies of one family's ACL table.
    fn denies<I: FixedSize>(
        &mut self,
        rows: &[RuleRow<AclKey<I>, LookupResult>],
        v6: bool,
        prefix: impl Fn(PrefixSpec<I>) -> Prefix + Copy,
    ) {
        for (at, row) in rows.iter().enumerate() {
            let peering = Peering::new(row.rule.src_vni.value, row.rule.dst_vni.value);
            let origin = Origin::Acl { v6, row: at };
            // Logged allows also need software: a NIC meter could otherwise drop them before
            // the ACL filter records its verdict. Keep both directions of the peering there.
            if row.action.logs() {
                self.refused.push((peering, origin, Refusal::Logging));
                continue;
            }
            if row.action.action() != AclAction::Deny {
                continue;
            }
            // A direct match is final in the ACL filter, whatever the flow state, so a deny is
            // safe if nothing before it could allow some of its traffic.
            if rows[..at].iter().any(|earlier| {
                earlier.action.action() != AclAction::Deny && earlier.rule.overlaps(&row.rule)
            }) {
                self.refused.push((peering, origin, Refusal::Overlap));
                continue;
            }
            match lower(&Fields::from(&row.rule), prefix, false) {
                Ok(matches) => self.denies.push(DenyRule {
                    origin,
                    peering,
                    matches,
                    level: 0,
                }),
                Err(refusal) => self.refused.push((peering, origin, refusal)),
            }
        }
    }

    /// The rate limits of one family's table.
    fn limits<I: FixedSize>(
        &mut self,
        limits: &RateLimits<PeeringRules>,
        rows: &[RuleRow<PeeringKey<I>, RuleIndex>],
        prefix: impl Fn(PrefixSpec<I>) -> Prefix + Copy,
    ) {
        let meter_of = |row: &RuleRow<PeeringKey<I>, RuleIndex>| {
            limits
                .rules()
                .get(row.action)
                .and_then(rate_limit::Rule::meter)
        };
        for (at, row) in rows.iter().enumerate() {
            let Some(meter) = meter_of(row) else {
                continue;
            };
            let peering = Peering::new(row.rule.src_vni.value, row.rule.dst_vni.value);
            let origin = Origin::RateLimit(row.action);
            // Hardware tables keep no order between rules: a rule is safe only if nothing before
            // it could claim some of its traffic for another meter.
            if rows[..at]
                .iter()
                .any(|earlier| meter_of(earlier) != Some(meter) && earlier.rule.overlaps(&row.rule))
            {
                self.refused.push((peering, origin, Refusal::Overlap));
                continue;
            }
            // A meter that drops nothing needs nothing in the NIC.
            let Some(component) = component(limits, meter) else {
                continue;
            };
            match lower(&Fields::from(&row.rule), prefix, false) {
                Ok(matches) => self.rules.push(Candidate {
                    rule: PoliceRule {
                        rule: row.action,
                        peering,
                        matches,
                        meter: 0,
                        level: 0,
                    },
                    meter,
                    component,
                }),
                Err(refusal) => self.refused.push((peering, origin, refusal)),
            }
        }
    }
}
