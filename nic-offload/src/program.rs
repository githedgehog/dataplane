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

/// A rate limit a NIC may enforce: the traffic it matches, and the meter it charges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoliceRule {
    /// The configured rule this came from.
    pub rule: RuleIndex,
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
    /// What it matches.
    pub matches: Match,
}

/// The software rule a program rule or refusal came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// A rate-limit rule, by its index in the configuration.
    RateLimit(RuleIndex),
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

/// Why a rule stays in software only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The meter drops nothing, so there is nothing to shed early.
    NothingToDrop,
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
    /// An earlier rule with another meter, or another verdict, matches some of the same traffic:
    /// in hardware the two could not keep their order.
    Overlap,
}

/// The policy a NIC may enforce, and what it may not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Program {
    /// ACL denies, IPv4 then IPv6, each in first-match order.
    pub denies: Vec<DenyRule>,
    /// One meter component per named meter some rule charges.
    pub meters: Vec<PoliceMeter>,
    /// The rate limits, IPv4 then IPv6, each in first-match order.
    pub rules: Vec<PoliceRule>,
    /// Lowered rules refused, with the software rule they came from.
    pub refused: Vec<(Origin, Refusal)>,
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

impl Program {
    /// Compile what a NIC may enforce of `acls` and `limits`, for the peerings that asked for
    /// offload (see [`RateLimits::offload`]).
    #[must_use]
    pub fn compile(acls: &AclFilterContext, limits: &RateLimits<PeeringRules>) -> Program {
        let mut program = Program::default();
        program.denies(acls.v4(), false, |p| Prefix::V4(p.value, p.len));
        program.denies(acls.v6(), true, |p| Prefix::V6(p.value, p.len));
        // Software meter index -> program meter index.
        let mut meters: Vec<Option<usize>> = vec![None; limits.meters().len()];
        let classifier = limits.classifier();
        program.family(limits, classifier.v4(), &mut meters, |p| {
            Prefix::V4(p.value, p.len)
        });
        program.family(limits, classifier.v6(), &mut meters, |p| {
            Prefix::V6(p.value, p.len)
        });
        program
    }

    /// The denies of one family's ACL table a NIC may enforce.
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
            let origin = Origin::Acl { v6, row: at };
            // A direct match is final in the ACL filter, whatever the flow state, so a deny is
            // safe if nothing before it could allow some of its traffic.
            if rows[..at].iter().any(|earlier| {
                earlier.action.action() != AclAction::Deny && earlier.rule.overlaps(&row.rule)
            }) {
                self.refused.push((origin, Refusal::Overlap));
                continue;
            }
            match lower(&Fields::from(&row.rule), prefix) {
                Ok(matches) => self.denies.push(DenyRule { origin, matches }),
                Err(refusal) => self.refused.push((origin, refusal)),
            }
        }
    }

    fn family<I: FixedSize>(
        &mut self,
        limits: &RateLimits<PeeringRules>,
        rows: &[RuleRow<PeeringKey<I>, RuleIndex>],
        meters: &mut [Option<usize>],
        prefix: impl Fn(PrefixSpec<I>) -> Prefix + Copy,
    ) {
        let meter_of = |row: &RuleRow<PeeringKey<I>, RuleIndex>| {
            limits.rules().get(row.action).map(rate_limit::Rule::meter)
        };
        for (at, row) in rows.iter().enumerate() {
            let Some(meter) = meter_of(row) else {
                continue;
            };
            // Hardware tables keep no order between rules: a rule is safe only if nothing before
            // it, offloaded or not, could claim some of its traffic for another meter.
            let origin = Origin::RateLimit(row.action);
            if rows[..at]
                .iter()
                .any(|earlier| meter_of(earlier) != Some(meter) && earlier.rule.overlaps(&row.rule))
            {
                self.refused.push((origin, Refusal::Overlap));
                continue;
            }
            let Some((unit, profile)) = component(limits, meter) else {
                self.refused.push((origin, Refusal::NothingToDrop));
                continue;
            };
            let matches = match lower(&Fields::from(&row.rule), prefix) {
                Ok(matches) => matches,
                Err(refusal) => {
                    self.refused.push((origin, refusal));
                    continue;
                }
            };
            let meter = *meters[meter].get_or_insert_with(|| {
                self.meters.push(PoliceMeter {
                    name: limits.meters()[meter].name().to_string(),
                    unit,
                    profile,
                });
                self.meters.len() - 1
            });
            self.rules.push(PoliceRule {
                rule: row.action,
                matches,
                meter,
            });
        }
    }
}
