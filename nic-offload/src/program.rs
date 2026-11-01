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

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use acl_filter::{AclFilterContext, AclKey, AclKeyRule, LookupResult};
use config::external::overlay::acl::AclAction;
use config::external::overlay::ratelimit::ColorAction;
use lpm::prefix::with_ports::KeyPort;
use match_action::{ExactSpec, FixedSize, MaskSpec, PrefixSpec, RangeSpec};
use net::ip::NextHeader;
use net::tcp::TcpFlags;
use net::vxlan::Vni;
use policer::{Color, Profile};
use rate_limit::{PeeringKey, PeeringKeyRule, PeeringRules, RateLimits, RuleIndex, RuleRow, Unit};

/// An address prefix of either family.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Prefix {
    /// IPv4 address and length.
    V4(Ipv4Addr, u8),
    /// IPv6 address and length.
    V6(Ipv6Addr, u8),
}

impl Prefix {
    /// The prefix length, in bits.
    #[must_use]
    pub fn bits(self) -> u8 {
        match self {
            Prefix::V4(_, len) | Prefix::V6(_, len) => len,
        }
    }
}

/// What a rule matches, as a NIC sees the frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    /// The source VPC.
    pub src_vni: Vni,
    /// Inner source prefix.
    pub source: Prefix,
    /// Inner destination prefix; with `src_vni`, it stands in for the destination VPC.
    pub destination: Prefix,
    /// IP protocol, or any.
    pub proto: Option<u8>,
    /// Exact source port, or any.
    pub src_port: Option<u16>,
    /// Exact destination port, or any.
    pub dst_port: Option<u16>,
}

/// The meter component a NIC enforces for a named meter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoliceMeter {
    /// The meter's name, for counters and logs.
    pub name: String,
    /// What its tokens count.
    pub unit: Unit,
    /// Rates and bursts, in `unit`.
    pub profile: Profile,
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
        }
    }
}

/// Why a peering's policy stays in software only: something of it no NIC may enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The ACL denies by default: whether a packet no rule matches passes depends on flow state
    /// (the replies of flows an allow opened).
    DefaultDeny,
    /// TCP flag matches are not lowered yet.
    TcpFlags,
    /// Only an exact protocol, or any, is lowered.
    PartialProtocolMask,
    /// The protocol is an extension header's (hop-by-hop, routing, fragment, authentication,
    /// destination options): software resolves extension headers to the protocol after them, so
    /// the rule never matches there, and mlx5 refuses such a match outright.
    ExtensionHeader,
    /// Only an exact port, or any, is lowered.
    PortRange,
    /// Ports without TCP or UDP.
    PortsWithoutTransport,
    /// A destination of every address: the destination VPC would be unconstrained.
    AnyDestination,
    /// The NIC refused one of the peering's rules when it was installed.
    NotInstalled,
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
    /// The peerings left in software, with what of each no NIC may enforce.
    pub refused: Vec<(Peering, Origin, Refusal)>,
}

/// The component of `meter` a NIC enforces: the one that drops red, bytes first. Enforcing one
/// component of a chain is conservative: the chain only ever makes a color worse.
fn component(limits: &RateLimits<PeeringRules>, meter: usize) -> Option<(Unit, Profile)> {
    let meter = limits.meters().get(meter)?;
    [Unit::Bytes, Unit::Packets].into_iter().find_map(|unit| {
        let component = meter.component(unit)?;
        (component.action(Color::Red) == ColorAction::Drop).then(|| (unit, component.profile()))
    })
}

fn proto(spec: MaskSpec<NextHeader>) -> Result<Option<u8>, Refusal> {
    match spec.mask.as_u8() {
        0 => Ok(None),
        u8::MAX if spec.value.is_ipv6_extension() => Err(Refusal::ExtensionHeader),
        u8::MAX => Ok(Some(spec.value.as_u8())),
        _ => Err(Refusal::PartialProtocolMask),
    }
}

fn port(spec: RangeSpec<KeyPort>) -> Result<Option<u16>, Refusal> {
    match (spec.min.get(), spec.max.get()) {
        (0, u16::MAX) => Ok(None),
        (min, max) if min == max && min != 0 => Ok(Some(min)),
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

/// Lower one typed rule's fields.
fn lower<I: FixedSize>(
    rule: &Fields<I>,
    prefix: impl Fn(PrefixSpec<I>) -> Prefix,
) -> Result<Match, Refusal> {
    if rule.tcp_flags.mask != TcpFlags::empty() {
        return Err(Refusal::TcpFlags);
    }
    let proto = proto(rule.proto)?;
    let (src_port, dst_port) = (port(rule.src_port)?, port(rule.dst_port)?);
    if (src_port.is_some() || dst_port.is_some()) && !matches!(proto, Some(6 | 17)) {
        return Err(Refusal::PortsWithoutTransport);
    }
    let destination = prefix(rule.destination);
    if destination.bits() == 0 {
        return Err(Refusal::AnyDestination);
    }
    Ok(Match {
        src_vni: rule.src_vni.value,
        source: prefix(rule.source),
        destination,
        proto,
        src_port,
        dst_port,
    })
}

/// A rate limit that may be offloaded, before its peering is known to be.
struct Candidate {
    rule: PoliceRule,
    /// The software meter, and the component a NIC enforces of it.
    meter: usize,
    component: (Unit, Profile),
}

/// The rules of a policy that may be offloaded, and the peerings that may not.
#[derive(Default)]
struct Compilation {
    denies: Vec<DenyRule>,
    rules: Vec<Candidate>,
    refused: Vec<(Peering, Origin, Refusal)>,
}

impl Program {
    /// Compile what a NIC may enforce of `acls` and `limits`: every peering whose whole policy it
    /// may enforce, but those in `excluded` (refused by the NIC before). Nothing, if offload is
    /// turned off ([`RateLimits::attempt_offloads`]).
    #[must_use]
    pub fn compile(
        acls: &AclFilterContext,
        limits: &RateLimits<PeeringRules>,
        excluded: &BTreeSet<Peering>,
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

        let left: BTreeSet<Peering> = c
            .refused
            .iter()
            .map(|(peering, ..)| *peering)
            .chain(excluded.iter().copied())
            .collect();
        let mut program = Program {
            denies: c
                .denies
                .into_iter()
                .filter(|d| !left.contains(&d.peering))
                .collect(),
            refused: c.refused,
            ..Program::default()
        };
        // Software meter index -> program meter index, for the meters kept rules charge.
        let mut meters: Vec<Option<usize>> = vec![None; limits.meters().len()];
        for Candidate {
            mut rule,
            meter,
            component: (unit, profile),
        } in c.rules
        {
            if left.contains(&rule.peering) {
                continue;
            }
            rule.meter = *meters[meter].get_or_insert_with(|| {
                program.meters.push(PoliceMeter {
                    name: limits.meters()[meter].name().to_string(),
                    unit,
                    profile,
                });
                program.meters.len() - 1
            });
            program.rules.push(rule);
        }
        program
    }
}

impl Compilation {
    /// The denies of one family's ACL table.
    fn denies<I: FixedSize>(
        &mut self,
        rows: &[RuleRow<AclKey<I>, LookupResult>],
        v6: bool,
        prefix: impl Fn(PrefixSpec<I>) -> Prefix + Copy,
    ) {
        for (at, row) in rows.iter().enumerate() {
            if row.action.action() != AclAction::Deny {
                continue;
            }
            let peering = Peering::new(row.rule.src_vni.value, row.rule.dst_vni.value);
            let origin = Origin::Acl { v6, row: at };
            // A direct match is final in the ACL filter, whatever the flow state, so a deny is
            // safe if nothing before it could allow some of its traffic.
            if rows[..at].iter().any(|earlier| {
                earlier.action.action() != AclAction::Deny && earlier.rule.overlaps(&row.rule)
            }) {
                self.refused.push((peering, origin, Refusal::Overlap));
                continue;
            }
            match lower(&Fields::from(&row.rule), prefix) {
                Ok(matches) => self.denies.push(DenyRule {
                    origin,
                    peering,
                    matches,
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
            limits.rules().get(row.action).map(rate_limit::Rule::meter)
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
            match lower(&Fields::from(&row.rule), prefix) {
                Ok(matches) => self.rules.push(Candidate {
                    rule: PoliceRule {
                        rule: row.action,
                        peering,
                        matches,
                        meter: 0,
                    },
                    meter,
                    component,
                }),
                Err(refusal) => self.refused.push((peering, origin, refusal)),
            }
        }
    }
}
