// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The mlx5 backend: lower [`Program`] to hardware steering (`dv_flow_en=2`).
//!
//! ```text
//! root       IPv4 VXLAN -> switch
//! switch     source VNI + destination VTEP -> VPC generation; miss -> software
//!  ingress   first match -> drop, meter, next stage or software
//!   colors   green/yellow -> next stage; red -> drop
//!  deny      matching ACL deny -> drop; miss -> police
//!  police    matching rate limit -> meter + color group; miss -> software
//!   colors   green/yellow -> software; red -> drop
//! ```
//!
//! Each stage preserves software's first-match behavior; empty stages are omitted.
//! Unsupported matches pass a superset of their traffic to software, skipping later NIC stages.
//! [`Port`] detaches changed VPCs during rebuilds and preserves unchanged generations.
//! The root stays fixed because mlx5 firmware steering is slow and cannot update it in place.
//!
//! Switch rules match the destination VTEP so transit VXLAN stays in the underlay.
//! [`Plan`] stores named [`Group`]s, numbered at installation. Only IPv4 underlay is supported.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::Ipv4Addr;

use dpdk::flow::model::{Ipv6Extensions, Parser};
use dpdk::flow::template::{
    Color, Complete, MeterAlgorithm, MeterError, MeterProfile, MeterUnit, Pattern, TemplateAction,
    TemplateConfig, TemplateError,
};
use dpdk::flow::{
    EthMatch, FlowError, FlowGroup, Ipv4Match, Ipv4Prefix, Ipv6Match, Ipv6Prefix,
    PortRange as FlowPortRange, Priority, TcpMatch, UdpMatch, VxlanMatch,
};
use lpm::prefix::PortRange;
use net::vxlan::Vni;
use rate_limit::{Billing, Unit};

use crate::program::{Exclusions, IngressVerdict, Match, Origin, Peering, Prefix, Program, Scope};

/// What a port reserves for this backend when it is configured; fixed until the port restarts.
pub const RESOURCES: TemplateConfig = TemplateConfig {
    queue_size: 64,
    counters: 1 << 14,
    // mlx5 takes up to 2^25 a port; each reserved one costs host memory (a `mlx5_aso_mtr`) and
    // NIC memory from the start.
    meters: 1 << 16,
};

const VXLAN_PORT: u16 = 4789;
/// BlueField-3 qualification confirms that mlx5 walks IPv6 extension headers and matches
/// `proto` against the final protocol, as software does (239/239 hop-by-hop frames).
pub const PARSER: Parser = Parser {
    ipv6_extensions: Ipv6Extensions::WalkedToLast,
};

/// The switch group's number; the root is group 0.
pub(crate) const SWITCH: FlowGroup = FlowGroup(1);

/// Failures programming the NIC; the port then falls back to software alone.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A template or meter was refused.
    #[error(transparent)]
    Flow(#[from] FlowError),
    /// A table or rule was refused.
    #[error(transparent)]
    Template(#[from] TemplateError),
    /// A meter profile was refused.
    #[error(transparent)]
    Meter(#[from] MeterError),
    /// A pattern template was refused.
    #[error("pattern template refused: {0}")]
    Pattern(String),
    /// More meters than [`RESOURCES`] reserved.
    #[error("{0} meters exceed the {max} reserved", max = RESOURCES.meters)]
    TooManyMeters(usize),
    /// A meter is beyond what mlx5 encodes as permissive as software ([`unfit`]).
    #[error("meter {0} is beyond what the NIC encodes")]
    Unfit(String),
    /// Every group number is in use.
    #[error("no flow group left")]
    NoGroup,
    /// A rule charges a meter that could not be made.
    #[error("its meter was not made")]
    MeterNotMade,
    /// A rule jumps to a group its plan does not lay out.
    #[error("it jumps to {0:?}, which its plan does not lay out")]
    NoSuchGroup(Group),
    /// A rule's table was refused (the reason is with its first rule).
    #[error("its table was refused")]
    TableRefused,
    /// A generation's switch rule was refused (the reason is with the switch rule).
    #[error("its switch rule was refused")]
    SwitchRefused,
    /// There is no switch to attach to.
    #[error("the switch is not installed")]
    NoSwitch,
    /// An operation on the NIC failed in a way that leaves what it holds unknown (a removal that
    /// failed, or an operation that timed out or failed on completion): the port's offload is off
    /// until it restarts.
    #[error("{what}: the NIC's rules are no longer known: {source}")]
    Lost {
        /// What was being done.
        what: &'static str,
        /// How it failed.
        #[source]
        source: TemplateError,
    },
    /// The port's offload was turned off for good by an earlier [`Error::Lost`].
    #[error("NIC offload is off on this port until it restarts")]
    Poisoned,
    /// A source VPC has rules, but no IPv4 VTEP to tell its VXLAN from transit.
    #[error("VPC {0} has no IPv4 VTEP")]
    NoVtep(Vni),
}

/// Whether a failed operation leaves the NIC's state unknown, rather than refused cleanly.
fn unknown_state(error: &TemplateError) -> bool {
    matches!(
        error,
        TemplateError::Timeout(_)
            | TemplateError::OperationFailed(_)
            | TemplateError::Completion { .. }
            | TemplateError::Pending
    )
}

/// How a port is matched: one, or a range, which takes a template of its own (a rule's range is
/// ignored, else).
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum PortShape {
    Exact,
    Range,
}

impl PortShape {
    fn of(ports: Option<PortRange>) -> Option<PortShape> {
        ports.map(|p| {
            if p.len() == 1 {
                PortShape::Exact
            } else {
                PortShape::Range
            }
        })
    }
}

/// The protocol layout of an inner match.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum L4 {
    Any,
    Proto,
    Udp {
        src: Option<PortShape>,
        dst: Option<PortShape>,
    },
    /// TCP, with ports constrained or not, and the mask of flags constrained.
    Tcp {
        src: Option<PortShape>,
        dst: Option<PortShape>,
        flags: u8,
    },
}

/// What one table's pattern template fixes: everything but the values.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Shape {
    v6: bool,
    source: u8,
    destination: u8,
    l4: L4,
    /// Whether fragments match too (no protocol only; see
    /// [`IngressRule::fragments`](crate::program::IngressRule::fragments)).
    fragments: bool,
}

impl Shape {
    fn of(rule: &Match) -> Shape {
        let l4 = match (rule.proto, rule.src_port, rule.dst_port) {
            (None, ..) => L4::Any,
            (Some(17), src, dst) if src.is_some() || dst.is_some() => L4::Udp {
                src: PortShape::of(src),
                dst: PortShape::of(dst),
            },
            (Some(6), src, dst) if src.is_some() || dst.is_some() || rule.tcp_flags.is_some() => {
                L4::Tcp {
                    src: PortShape::of(src),
                    dst: PortShape::of(dst),
                    flags: rule.tcp_flags.map_or(0, |(_, mask)| mask),
                }
            }
            (Some(_), ..) => L4::Proto,
        };
        Shape {
            v6: matches!(rule.destination, Prefix::V6(..)),
            source: rule.source.bits(),
            destination: rule.destination.bits(),
            l4,
            fragments: false,
        }
    }

    /// The pattern of this shape, with `rule`'s values or placeholders for the template.
    fn pattern(self, rule: Option<&Match>) -> Pattern<Complete> {
        // No VNI: a generation is reached only through its own VPC's switch rule.
        let tunnel = Pattern::new()
            .eth(EthMatch::default())
            .ipv4(Ipv4Match::default())
            .udp(UdpMatch::default().dst(VXLAN_PORT))
            .vxlan(VxlanMatch::default())
            // Software does not parse a tagged inner frame, so must not be charged for one.
            .inner_eth(EthMatch::default().tagged(false));
        // A template's values are placeholders, but mlx5 still validates them: an IPv6 next
        // header of 0 is the hop-by-hop extension header, which it refuses.
        let proto = rule.and_then(|r| r.proto).unwrap_or(match self.l4 {
            L4::Tcp { .. } => 6,
            _ => 17,
        });
        // A placeholder range is a range, as the template must have one where its rules do.
        let ports = |p: Option<PortRange>, shape| {
            let p = p.unwrap_or_else(|| match shape {
                PortShape::Exact => PortRange::single(1),
                PortShape::Range => PortRange::new(1, 2).unwrap_or_else(|_| unreachable!()),
            });
            FlowPortRange::between(p.start(), p.end())
        };
        let (src_port, dst_port) = (rule.and_then(|r| r.src_port), rule.and_then(|r| r.dst_port));
        macro_rules! finish {
            ($ip:expr) => {
                match self.l4 {
                    L4::Any | L4::Proto => $ip.complete(),
                    L4::Udp { src, dst } => {
                        let mut udp = UdpMatch::default();
                        if let Some(shape) = src {
                            let p = ports(src_port, shape);
                            udp = udp.src_range(p);
                        }
                        if let Some(shape) = dst {
                            let p = ports(dst_port, shape);
                            udp = udp.dst_range(p);
                        }
                        $ip.udp(udp).complete()
                    }
                    L4::Tcp { src, dst, flags } => {
                        let mut tcp = TcpMatch::default();
                        if let Some(shape) = src {
                            let p = ports(src_port, shape);
                            tcp = tcp.src_range(p);
                        }
                        if let Some(shape) = dst {
                            let p = ports(dst_port, shape);
                            tcp = tcp.dst_range(p);
                        }
                        if flags != 0 {
                            let value = rule.and_then(|r| r.tcp_flags).map_or(0, |(v, _)| v);
                            tcp = tcp.flags(value, flags);
                        }
                        $ip.tcp(tcp).complete()
                    }
                }
            };
        }
        // Software classifies first and later fragments differently, so peering rules skip both.
        // Only eligible ingress rules with no protocol constraint may match fragments.
        if self.v6 {
            let addr = |p: Option<Prefix>, len| match p {
                Some(Prefix::V6(a, l)) => Ipv6Prefix::prefix(a, l),
                _ => Ipv6Prefix::prefix(std::net::Ipv6Addr::UNSPECIFIED, len),
            };
            let mut ip = Ipv6Match::default()
                .src(addr(rule.map(|r| r.source), self.source))
                .dst(addr(rule.map(|r| r.destination), self.destination));
            if !self.fragments {
                ip = ip.unfragmented();
            }
            if self.l4 != L4::Any {
                ip = ip.proto(proto);
            }
            finish!(tunnel.ipv6(ip))
        } else {
            let addr = |p: Option<Prefix>, len| match p {
                Some(Prefix::V4(a, l)) => Ipv4Prefix::prefix(a, l),
                _ => Ipv4Prefix::prefix(Ipv4Addr::UNSPECIFIED, len),
            };
            let mut ip = Ipv4Match::default()
                .src(addr(rule.map(|r| r.source), self.source))
                .dst(addr(rule.map(|r| r.destination), self.destination));
            if !self.fragments {
                ip = ip.unfragmented();
            }
            if self.l4 != L4::Any {
                ip = ip.proto(proto);
            }
            finish!(tunnel.ipv4(ip))
        }
    }
}

/// A burst size mlx5 can encode: the smallest at least `bytes` (and at most 256/255 of it), for
/// `bytes` at most [`MAX_BURST`]. mlx5 encodes sizes strictly between 255·2^k and 256·2^k as zero
/// (`mlx5_flow_meter_xbs_man_exp_calc`). Rounding up keeps the NIC at least as permissive as the
/// software it stands in front of.
fn encodable(bytes: u64) -> u64 {
    (0..31)
        .map(|k| (255u64 << k, 256u64 << k))
        .find(|&(low, high)| low < bytes && bytes < high)
        .map_or(bytes, |(_, high)| high)
}

/// The greatest burst mlx5 takes, in its (scaled) units: an 8-bit mantissa and a 5-bit exponent
/// (`MLX5_SRTCM_XBS_MAX`; it refuses a profile with a larger one).
const MAX_BURST: u64 = 255 << 31;

/// What the NIC's byte meters count beyond what software bills a packet (its IP bytes): the
/// outer Ethernet, IPv4, UDP and VXLAN headers (50), an outer VLAN tag (4), the inner Ethernet
/// header (14) and the FCS (4), whether or not a given NIC counts each.
pub const BYTE_OVERHEAD: u64 = 72;

/// Reference packet size, in inner IP bytes, for [`Billing::Ip`] byte meters.
/// Rates and bursts are scaled by ([`SIZED_FOR`] + [`BYTE_OVERHEAD`]) / [`SIZED_FOR`], about 1.14,
/// to cover overhead for packets at least this large.
///
/// Smaller packets may hit NIC rate or burst limits before software limits, including bursts
/// whose average rate is below the configured limit. For single-rate meters counting all of
/// [`BYTE_OVERHEAD`], estimated steady-state limits are 1.09 times the configured rate for
/// 1500 B packets and 0.54 times for 64 B packets, before hardware rounding.
/// NIC drops appear in `rate_limit_nic_packets_total`, not the software rate-limit counters.
pub(crate) const SIZED_FOR: u64 = 512;

/// Possible L2 overhead beyond [`Billing::OuterIp`]: Ethernet (14), VLAN (4) and FCS (4).
/// mlx5 documents IP-length billing, but this is not qualified on every part and firmware.
/// Allowing these extra bytes prevents stricter metering on hardware that counts them.
pub const OUTER_IP_OVERHEAD: u64 = 22;

/// The fewest bytes software bills a packet a NIC rule matches by its outer IP packet: the outer
/// IPv4, UDP and VXLAN headers (36), and the inner Ethernet and IPv4 headers (34).
pub(crate) const MIN_OUTER_IP_BILLED: u64 = 70;

/// The largest frame a NIC meter may let into debt, in bytes: a jumbo frame and its overhead.
const MAX_FRAME: u64 = 9216 + BYTE_OVERHEAD;

/// mlx5 scales packet-mode rates and bursts up by `1 << PPS_SHIFT` before encoding them
/// (`MLX5_MTRS_PPS_MAP_BPS_SHIFT`).
const PPS_SHIFT: u32 = 7;

/// The rate mlx5 programs for `rate`: the nearest it can encode, `1e9 * m >> e` for an 8-bit
/// mantissa and a 5-bit exponent, the last of equally near ones in its search
/// (`mlx5_flow_meter_xir_man_exp_calc`).
#[cfg(test)]
pub(crate) fn encoded_rate(rate: u64) -> u64 {
    let (mut best, mut delta) = (0, u64::MAX);
    for m in 0..=255u64 {
        for e in 0..=31 {
            let candidate = (1_000_000_000 * m) >> e;
            if rate.abs_diff(candidate) <= delta {
                (best, delta) = (candidate, rate.abs_diff(candidate));
            }
        }
    }
    best
}

/// The greatest rate mlx5 encodes.
const MAX_RATE: u64 = 255 * 1_000_000_000;

/// Maximum combined 32-bit IPv6 address words when metering a port range.
/// BlueField-3 accepts /96 + /96 or /128 + /64, but rejects /96 + /97 (`install_probe`).
/// Exact ports and drop actions support both full addresses.
const METERED_RANGE_ADDRESS_WORDS: u32 = 6;

/// Whether mlx5 can create a table that meters what `matches` matches.
fn meterable(matches: &Match) -> bool {
    let ranged = [matches.src_port, matches.dst_port]
        .into_iter()
        .any(|ports| PortShape::of(ports) == Some(PortShape::Range));
    let words = |prefix: Prefix| match prefix {
        Prefix::V4(..) => 0,
        Prefix::V6(_, len) => u32::from(len).div_ceil(32),
    };
    !ranged || words(matches.source) + words(matches.destination) <= METERED_RANGE_ADDRESS_WORDS
}

/// Exclude meters mlx5 cannot encode permissively, and their peerings when applicable.
/// Also exclude ingress police rules whose matches cannot be metered (see `meterable`).
#[must_use]
pub fn unfit(program: &Program) -> Exclusions {
    let unfit = |meter: usize| profile(&program.meters[meter]).is_none();
    Exclusions {
        peerings: program
            .rules
            .iter()
            .filter(|rule| unfit(rule.meter))
            .map(|rule| rule.peering)
            .collect(),
        ingress_meters: program
            .ingress
            .iter()
            .filter_map(|rule| match rule.verdict {
                IngressVerdict::Police(first, then) if unfit(first) || then.is_some_and(unfit) => {
                    Some(program.meters[first].name.clone())
                }
                _ => None,
            })
            .collect(),
        ingress_rules: program
            .ingress
            .iter()
            .filter(|rule| matches!(rule.verdict, IngressVerdict::Police(..)))
            .filter(|rule| !meterable(&rule.matches))
            .filter_map(|rule| match rule.origin {
                Origin::Ingress { v6, row } => Some((v6, row)),
                _ => None,
            })
            .collect(),
        ..Exclusions::default()
    }
}

/// What of `program` stays in software until the rest fits the meters [`RESOURCES`] reserves, if it
/// needs more: the peerings, and ingress meter, of its last meter.
#[must_use]
pub fn over_meters(program: &Program) -> Option<Exclusions> {
    let last = program.meters.len().checked_sub(1)?;
    if program.meters.len() <= RESOURCES.meters as usize {
        return None;
    }
    Some(Exclusions {
        peerings: program
            .rules
            .iter()
            .filter(|r| r.meter == last)
            .map(|r| r.peering)
            .collect(),
        ingress_meters: program
            .ingress
            .iter()
            .filter(|r| r.verdict.charges(last))
            .map(|_| program.meters[last].name.clone())
            .collect(),
        ..Exclusions::default()
    })
}

/// The least rate mlx5 encodes exactly at or above `rate` (the greatest it encodes, if none is).
fn encodable_rate(rate: u64) -> u64 {
    (0..=255u64)
        .flat_map(|m| (0..=31).map(move |e| (1_000_000_000 * m) >> e))
        .filter(|&candidate| candidate >= rate)
        .min()
        .unwrap_or(MAX_RATE)
}

/// The burst mlx5 programs for `burst`: rounded up to an 8-bit mantissa times a power of two, but
/// a mantissa that rounds up to 256 wraps to 0 (`mlx5_flow_meter_xbs_man_exp_calc`).
#[cfg(test)]
pub(crate) fn encoded_burst(burst: u64) -> u64 {
    if burst == 0 {
        return 0;
    }
    let bits = burst.bit_width();
    if bits < 8 {
        return 1 << bits;
    }
    let shift = bits - 8;
    (burst.div_ceil(1 << shift) & 0xff) << shift
}

/// How far mlx5 scales up a rate or burst in `unit` before encoding it.
#[cfg(test)]
pub(crate) fn pmd_scale(unit: MeterUnit) -> u32 {
    match unit {
        MeterUnit::Packets => PPS_SHIFT,
        MeterUnit::Bytes => 0,
    }
}

/// Build a NIC profile that passes traffic within the software meter's rates and bursts,
/// subject to the small-packet exception for inner-IP byte meters in [`SIZED_FOR`].
///
/// - Scale byte rates and bursts for the NIC's overhead beyond the billed IP length: for packets
///   of at least [`SIZED_FOR`] bytes with [`Billing::Ip`], and of any size with
///   [`Billing::OuterIp`].
/// - Add one maximum frame for NIC token debt and [`PoliceMeter::lease_slack`](crate::program::PoliceMeter::lease_slack) for worker leases.
/// - Round rates and bursts up to mlx5-encodable values.
/// - Use the sum of committed and excess rates for the NIC's uncoupled excess bucket.
///
/// Software still enforces the configured limit; see `meters.rs` for the meter property tests.
/// Returns `None` if the adjusted rate or burst exceeds [`MAX_RATE`] or [`MAX_BURST`].
pub(crate) fn profile(meter: &crate::program::PoliceMeter) -> Option<MeterProfile> {
    let p = meter.profile;
    // Tokens are scaled by `scale / sized_for`.
    let (scale, sized_for, frame) = match (meter.unit, meter.billing) {
        (Unit::Bytes, Billing::Ip) => (SIZED_FOR + BYTE_OVERHEAD, SIZED_FOR, MAX_FRAME),
        (Unit::Bytes, Billing::OuterIp) => (
            MIN_OUTER_IP_BILLED + OUTER_IP_OVERHEAD,
            MIN_OUTER_IP_BILLED,
            MAX_FRAME,
        ),
        (Unit::Packets, _) => (1, 1, 1),
    };
    let pmd = match meter.unit {
        Unit::Bytes => 0,
        Unit::Packets => PPS_SHIFT,
    };
    // In mlx5's units, if it takes that many: scaled, plus `extra`, shifted as mlx5 shifts them.
    let scaled = |tokens: u64, extra: u64, max: u64| {
        let wanted = (u128::from(tokens) * u128::from(scale)).div_ceil(u128::from(sized_for))
            + u128::from(extra);
        u64::try_from(wanted << pmd).ok().filter(|&w| w <= max)
    };
    // What mlx5 encodes exactly, in its (scaled) units, given back in ours, rounded up: mlx5 then
    // encodes at least that.
    let rate = |tokens: u64| Some(encodable_rate(scaled(tokens, 0, MAX_RATE)?).div_ceil(1 << pmd));
    let burst = |tokens: u64, slack: u64| {
        if tokens == 0 {
            return Some(0);
        }
        let wanted = scaled(tokens.checked_add(slack)?, frame, MAX_BURST)?;
        Some(encodable(wanted).div_ceil(1 << pmd))
    };
    let cir = p.committed_rate().per_second().get();
    let [committed_slack, excess_slack] = meter.lease_slack;
    let (cbs, ebs) = (
        burst(p.committed_burst(), committed_slack)?,
        burst(p.excess_burst(), excess_slack)?,
    );
    Some(MeterProfile {
        algorithm: match p.excess_rate() {
            None => MeterAlgorithm::Srtcm {
                cir: rate(cir)?,
                cbs,
                ebs,
            },
            Some(eir) => MeterAlgorithm::Rfc4115 {
                cir: rate(cir)?,
                eir: rate(eir.per_second().get().checked_add(cir)?)?,
                cbs,
                ebs,
            },
        },
        unit: match meter.unit {
            Unit::Bytes => MeterUnit::Bytes,
            Unit::Packets => MeterUnit::Packets,
        },
    })
}

mod install;

#[cfg(test)]
pub(crate) use install::peerings;
pub use install::{Installed, MeterName, Port, Reconciled, run, with_installed};

/// A group of a [`Plan`], by what it is for; numbered when installed.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Group {
    /// The root: VXLAN, to the switch.
    Root,
    /// One rule per source VPC, to its generation.
    Switch,
    /// A source VPC's ingress rules: the generation's first group, if it has any.
    Ingress(Vni),
    /// The colors a meter (by index into [`Plan::meters`]) gave a source VPC's ingress traffic.
    IngressColor(Vni, usize),
    /// A source VPC's ACL denies.
    Deny(Vni),
    /// A source VPC's rate limits.
    Police(Vni),
    /// A meter's colors, by index into [`Plan::meters`].
    Color(usize),
}

/// What a rule is for, to report its counts and refusals.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Role {
    /// The root rule, which takes VXLAN to the switch.
    Root,
    /// The switch rule of a source VPC.
    Switch(Vni),
    /// An ingress rule of the program, by index into [`Program::ingress`].
    Ingress(usize),
    /// What a meter, by index into [`Plan::meters`], colored of a source VPC's ingress traffic.
    IngressColor(Vni, usize, Color),
    /// An ACL deny of the program, by index into [`Program::denies`].
    Deny(usize),
    /// A rate limit of the program, by index into [`Program::rules`].
    Police(usize),
    /// A destination of another peer a source VPC's rules of less specific destinations must let
    /// pass: on to its next group, or to software.
    Pass(Vni),
    /// The rule for what no rule of the program in this group matches.
    CatchAll(Group),
    /// What a meter, by index into [`Plan::meters`], colored.
    Color(usize, Color),
}

/// A per-rule argument, by reference into the plan.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Arg {
    /// The meter of [`Plan::meters`] at this index.
    Meter(usize),
    /// Jump to this group.
    Jump(Group),
}

/// A rule of a [`PlannedTable`].
#[derive(Debug)]
pub struct PlannedRule {
    /// What it matches, with its table's masks.
    pub pattern: Pattern<Complete>,
    /// Its actions template, by index into its table's [`actions`](PlannedTable::actions).
    pub actions: usize,
    /// Its per-rule arguments, in the order of the template's per-rule actions.
    pub args: Vec<Arg>,
    /// What it is for.
    pub role: Role,
}

/// A template table and its rules.
#[derive(Debug)]
pub struct PlannedTable {
    /// The group the table is in.
    pub group: Group,
    /// Its priority in the group: lower is matched first.
    pub priority: Priority,
    /// How many rules it holds at most.
    pub capacity: u32,
    /// Its pattern template, by index into [`Plan::patterns`].
    pub pattern: usize,
    /// Its actions templates, by index into [`Plan::actions`].
    pub actions: Vec<usize>,
    /// Its rules.
    pub rules: Vec<PlannedRule>,
}

/// What identifies a meter across plans: a meter with the same key is the same meter, and an
/// installed one is kept, with its token state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeterKey {
    /// The policy it is of: names are unique within one only.
    pub scope: Scope,
    /// The meter's name.
    pub name: String,
    /// What the NIC enforces of it.
    pub profile: MeterProfile,
}

/// A meter of a plan, and its color group.
#[derive(Debug)]
pub struct PlannedMeter {
    /// What identifies it.
    pub key: MeterKey,
    /// Its color table, in [`Group::Color`] of its index: a peering meter's. An ingress meter's
    /// colors are matched in its source VPCs' [`Group::IngressColor`] groups instead.
    pub colors: Option<PlannedTable>,
}

/// What an ingress rule of a generation does, to tell generations apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngressSpec {
    /// See [`IngressVerdict::Drop`].
    Drop,
    /// See [`IngressVerdict::Police`].
    Police(MeterKey, Option<MeterKey>),
    /// See [`IngressVerdict::Continue`].
    Continue,
    /// See [`IngressVerdict::Pass`].
    Pass,
}

/// What a source VPC's generation enforces, to tell whether an installed one is still what is
/// wanted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpcSpec {
    /// Its ingress rules, in order, with their layers and whether they match fragments.
    pub ingress: Vec<(Match, u32, bool, IngressSpec)>,
    /// Its denies, in order, with their levels.
    pub denies: Vec<(Match, u8)>,
    /// Its rate limits, in order, with their levels and meters.
    pub limits: Vec<(Match, u8, MeterKey)>,
    /// The destinations it lets pass ahead of its rules of less specific ones.
    pub passes: Vec<Prefix>,
    /// The VTEP address its VXLAN is addressed to.
    pub vtep: Ipv4Addr,
    /// The peerings its rules are of: those the NIC enforces while it is attached.
    pub peerings: BTreeSet<Peering>,
}

/// A source VPC's generation of rules.
#[derive(Debug)]
pub struct PlannedVpc {
    /// What it enforces.
    pub spec: VpcSpec,
    /// The group its switch rule jumps to.
    pub entry: Group,
    /// Its tables: ingress rules and their colors, denies, then rate limits.
    pub tables: Vec<PlannedTable>,
}

/// A [`Program`] lowered onto mlx5, as data: every template, meter, table and rule a port gets,
/// so that it can be checked without the NIC (see [`crate::model`]) and installed piece by piece
/// ([`Port`]).
#[derive(Debug)]
pub struct Plan {
    /// Pattern templates.
    pub patterns: Vec<Pattern<Complete>>,
    /// Actions templates.
    pub actions: Vec<Vec<TemplateAction>>,
    /// The meters, and their color groups.
    pub meters: Vec<PlannedMeter>,
    /// The root, switch and catch-all tables, if any VPC is offloaded; the switch table's rules
    /// are the VPCs' switch rules.
    pub fixed: Vec<PlannedTable>,
    /// The source VPCs' generations.
    pub vpcs: BTreeMap<Vni, PlannedVpc>,
}

/// Pattern templates every plan has, by index.
const ROOT: usize = 0;
const ANY: usize = 1;
const COLOR: usize = 2;
const SWITCHED: usize = 3;

/// Actions templates every plan has, by index.
const TO_SWITCH: usize = 0;
const JUMP: usize = 1;
const POLICE_RULE: usize = 2;
const DELIVER: usize = 3;
const PASS: usize = 4;
const DISCARD: usize = 5;
const COUNT_JUMP: usize = 6;
const COUNT_POLICE: usize = 7;

fn root_pattern() -> Pattern<Complete> {
    Pattern::new()
        .eth(EthMatch::default())
        .ipv4(Ipv4Match::default())
        .udp(UdpMatch::default().dst(VXLAN_PORT))
        .complete()
}

fn any_pattern() -> Pattern<Complete> {
    Pattern::new().eth(EthMatch::default()).complete()
}

/// The pattern of a switch rule: VXLAN with the VPC's VNI, to its VTEP (placeholders for the
/// template).
fn switch_pattern(vpc: Option<(Vni, Ipv4Addr)>) -> Pattern<Complete> {
    let (vni, vtep) = vpc.unwrap_or_else(|| {
        let vni = Vni::new_checked(Vni::MIN).unwrap_or_else(|_| unreachable!());
        (vni, Ipv4Addr::UNSPECIFIED)
    });
    Pattern::new()
        .eth(EthMatch::default())
        .ipv4(Ipv4Match::default().dst(Ipv4Prefix::host(vtep)))
        .udp(UdpMatch::default().dst(VXLAN_PORT))
        .vxlan(VxlanMatch::default().vni(vni))
        .complete()
}

/// The rules letting `passes` through for source VPC `vni`: any source, any protocol.
fn pass_matches(vni: Vni, passes: &[Prefix]) -> Vec<Match> {
    passes
        .iter()
        .map(|p| {
            let source = match p {
                Prefix::V4(..) => Prefix::V4(Ipv4Addr::UNSPECIFIED, 0),
                Prefix::V6(..) => Prefix::V6(std::net::Ipv6Addr::UNSPECIFIED, 0),
            };
            Match {
                src_vni: vni,
                source,
                destination: *p,
                proto: None,
                src_port: None,
                dst_port: None,
                tcp_flags: None,
            }
        })
        .collect()
}

/// A rule of the program to lay out in a classifying group.
struct Classified<'a> {
    matches: &'a Match,
    /// See [`DenyRule::level`](crate::program::DenyRule::level).
    level: u8,
    role: Role,
    args: Vec<Arg>,
}

/// Table order: longest destination prefix first, then rules before passes, then shape.
/// A pass bypasses only rules for less-specific destinations.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Slot {
    level: std::cmp::Reverse<u8>,
    pass: bool,
    shape: Shape,
}

/// A table holding one rule.
fn single(
    group: Group,
    priority: u32,
    pattern: usize,
    actions: usize,
    matches: Pattern<Complete>,
    args: Vec<Arg>,
    role: Role,
) -> PlannedTable {
    PlannedTable {
        group,
        priority: Priority(priority),
        capacity: 1,
        pattern,
        actions: vec![actions],
        rules: vec![PlannedRule {
            pattern: matches,
            actions: 0,
            args,
            role,
        }],
    }
}

/// The most source VPCs one port's switch holds.
const SWITCH_CAPACITY: u32 = 4096;

impl Plan {
    /// Lay out a group of program rules with actions template `actions`, and a last table
    /// sending what none matches to actions template `otherwise` with its arguments. `passes`
    /// send what they match there too, ahead of the rules of less specific destinations (see
    /// [`Slot`]). One table per slot.
    fn classify(
        &mut self,
        group: Group,
        passes: &[Match],
        rules: Vec<Classified<'_>>,
        actions: usize,
        otherwise: (usize, Vec<Arg>),
    ) -> Vec<PlannedTable> {
        let (otherwise, otherwise_args) = otherwise;
        let mut slots: BTreeMap<Slot, Vec<Classified<'_>>> = BTreeMap::new();
        for pass in passes {
            let slot = Slot {
                level: std::cmp::Reverse(pass.destination.bits()),
                pass: true,
                shape: Shape::of(pass),
            };
            slots.entry(slot).or_default().push(Classified {
                matches: pass,
                level: pass.destination.bits(),
                role: Role::Pass(pass.src_vni),
                args: otherwise_args.clone(),
            });
        }
        for rule in rules {
            let slot = Slot {
                level: std::cmp::Reverse(rule.level),
                pass: false,
                shape: Shape::of(rule.matches),
            };
            slots.entry(slot).or_default().push(rule);
        }
        let mut tables = Vec::with_capacity(slots.len() + 1);
        for (priority, (slot, rules)) in (0u32..).zip(slots) {
            self.patterns.push(slot.shape.pattern(None));
            tables.push(PlannedTable {
                group,
                priority: Priority(priority),
                capacity: u32::try_from(rules.len()).unwrap_or(u32::MAX),
                pattern: self.patterns.len() - 1,
                actions: vec![if slot.pass { otherwise } else { actions }],
                rules: rules
                    .into_iter()
                    .map(|rule| PlannedRule {
                        pattern: slot.shape.pattern(Some(rule.matches)),
                        actions: 0,
                        args: rule.args,
                        role: rule.role,
                    })
                    .collect(),
            });
        }
        let catch_all = u32::try_from(tables.len()).unwrap_or(u32::MAX);
        tables.push(single(
            group,
            catch_all,
            ANY,
            otherwise,
            any_pattern(),
            otherwise_args,
            Role::CatchAll(group),
        ));
        tables
    }

    /// Lower `program`, sending what the NIC lets through to `fate`. A source VPC's rules apply to
    /// VXLAN addressed to its VTEP in `vteps`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooManyMeters`] if the program needs more meters than [`RESOURCES`],
    /// [`Error::Unfit`] if mlx5 cannot encode one of them ([`unfit`]), and [`Error::NoVtep`] if a
    /// source VPC with rules has no VTEP in `vteps`.
    pub fn new(
        program: &Program,
        vteps: &BTreeMap<Vni, Ipv4Addr>,
        fate: &TemplateAction,
    ) -> Result<Plan, Error> {
        if program.meters.len() > RESOURCES.meters as usize {
            return Err(Error::TooManyMeters(program.meters.len()));
        }
        let mut plan = Plan {
            patterns: vec![
                root_pattern(),
                any_pattern(),
                Pattern::meter_color(Color::Green).complete(),
                switch_pattern(None),
            ],
            actions: vec![
                vec![TemplateAction::Jump(SWITCH)],
                vec![TemplateAction::JumpPerRule],
                vec![TemplateAction::Meter, TemplateAction::JumpPerRule],
                vec![fate.clone()],
                vec![TemplateAction::Count, fate.clone()],
                vec![TemplateAction::Count, TemplateAction::Drop],
                vec![TemplateAction::Count, TemplateAction::JumpPerRule],
                vec![
                    TemplateAction::Count,
                    TemplateAction::Meter,
                    TemplateAction::JumpPerRule,
                ],
            ],
            meters: Vec::new(),
            fixed: Vec::new(),
            vpcs: BTreeMap::new(),
        };
        for (index, meter) in program.meters.iter().enumerate() {
            plan.meters.push(PlannedMeter {
                key: MeterKey {
                    scope: meter.scope,
                    name: meter.name.clone(),
                    profile: profile(meter).ok_or_else(|| Error::Unfit(meter.name.clone()))?,
                },
                colors: (meter.scope == Scope::Peering).then(|| color_table(index)),
            });
        }
        // The program's rules, by source VPC.
        let mut ingress: BTreeMap<Vni, Vec<usize>> = BTreeMap::new();
        let mut denies: BTreeMap<Vni, Vec<usize>> = BTreeMap::new();
        let mut limits: BTreeMap<Vni, Vec<usize>> = BTreeMap::new();
        for (index, rule) in program.ingress.iter().enumerate() {
            ingress.entry(rule.matches.src_vni).or_default().push(index);
        }
        for (index, deny) in program.denies.iter().enumerate() {
            denies.entry(deny.matches.src_vni).or_default().push(index);
        }
        for (index, rule) in program.rules.iter().enumerate() {
            limits.entry(rule.matches.src_vni).or_default().push(index);
        }
        let vnis: BTreeSet<Vni> = ingress
            .keys()
            .chain(denies.keys())
            .chain(limits.keys())
            .copied()
            .collect();
        for vni in vnis {
            let vtep = *vteps.get(&vni).ok_or(Error::NoVtep(vni))?;
            let vpc = plan.vpc(
                program,
                vni,
                vtep,
                &ingress.remove(&vni).unwrap_or_default(),
                &denies.remove(&vni).unwrap_or_default(),
                &limits.remove(&vni).unwrap_or_default(),
            );
            plan.vpcs.insert(vni, vpc);
        }
        if !plan.vpcs.is_empty() {
            plan.fixed = plan.fixed_tables();
        }
        Ok(plan)
    }

    /// What source VPC `vni`'s generation enforces, from its rules (indices into `program`).
    fn spec(
        &self,
        program: &Program,
        vni: Vni,
        vtep: Ipv4Addr,
        vni_ingress: &[usize],
        vni_denies: &[usize],
        vni_limits: &[usize],
    ) -> VpcSpec {
        VpcSpec {
            ingress: vni_ingress
                .iter()
                .map(|&i| {
                    let rule = &program.ingress[i];
                    let verdict = match rule.verdict {
                        IngressVerdict::Drop => IngressSpec::Drop,
                        IngressVerdict::Police(m, then) => IngressSpec::Police(
                            self.meters[m].key.clone(),
                            then.map(|t| self.meters[t].key.clone()),
                        ),
                        IngressVerdict::Continue => IngressSpec::Continue,
                        IngressVerdict::Pass => IngressSpec::Pass,
                    };
                    (rule.matches.clone(), rule.layer, rule.fragments, verdict)
                })
                .collect(),
            denies: vni_denies
                .iter()
                .map(|&i| (program.denies[i].matches.clone(), program.denies[i].level))
                .collect(),
            limits: vni_limits
                .iter()
                .map(|&i| {
                    let rule = &program.rules[i];
                    (
                        rule.matches.clone(),
                        rule.level,
                        self.meters[rule.meter].key.clone(),
                    )
                })
                .collect(),
            passes: program
                .passes
                .get(&vni)
                .map(|p| p.iter().copied().collect())
                .unwrap_or_default(),
            vtep,
            peerings: vni_denies
                .iter()
                .map(|&i| program.denies[i].peering)
                .chain(vni_limits.iter().map(|&i| program.rules[i].peering))
                .collect(),
        }
    }

    /// The generation of source VPC `vni`, from its ingress rules, denies and rate limits
    /// (indices into `program`).
    fn vpc(
        &mut self,
        program: &Program,
        vni: Vni,
        vtep: Ipv4Addr,
        vni_ingress: &[usize],
        vni_denies: &[usize],
        vni_limits: &[usize],
    ) -> PlannedVpc {
        // Identical rules are left out, as `Program::compile` does: mlx5 fails to remove the
        // second.
        let mut seen: HashSet<&Match> = HashSet::new();
        let vni_denies: Vec<usize> = vni_denies
            .iter()
            .copied()
            .filter(|&i| seen.insert(&program.denies[i].matches))
            .collect();
        let mut seen: HashSet<&Match> = HashSet::new();
        let vni_limits: Vec<usize> = vni_limits
            .iter()
            .copied()
            .filter(|&i| seen.insert(&program.rules[i].matches))
            .collect();
        let spec = self.spec(program, vni, vtep, vni_ingress, &vni_denies, &vni_limits);
        // What another peer takes of a rule's destination passes, in both groups: a pass in the
        // deny group leaves the traffic to the police group, whose own passes deliver it.
        let passes = pass_matches(vni, &spec.passes);
        let mut tables = Vec::new();
        let police = !vni_limits.is_empty();
        if !vni_denies.is_empty() {
            let rules = vni_denies
                .iter()
                .map(|&i| Classified {
                    matches: &program.denies[i].matches,
                    level: program.denies[i].level,
                    role: Role::Deny(i),
                    args: Vec::new(),
                })
                .collect();
            let otherwise = if police {
                (JUMP, vec![Arg::Jump(Group::Police(vni))])
            } else {
                (DELIVER, Vec::new())
            };
            tables.extend(self.classify(Group::Deny(vni), &passes, rules, DISCARD, otherwise));
        }
        if police {
            let rules = vni_limits
                .iter()
                .map(|&i| {
                    let rule = &program.rules[i];
                    Classified {
                        matches: &rule.matches,
                        level: rule.level,
                        role: Role::Police(i),
                        args: vec![Arg::Meter(rule.meter), Arg::Jump(Group::Color(rule.meter))],
                    }
                })
                .collect();
            tables.extend(self.classify(
                Group::Police(vni),
                &passes,
                rules,
                POLICE_RULE,
                (DELIVER, Vec::new()),
            ));
        }
        let entry = if !vni_ingress.is_empty() {
            Group::Ingress(vni)
        } else if vni_denies.is_empty() {
            Group::Police(vni)
        } else {
            Group::Deny(vni)
        };
        if !vni_ingress.is_empty() {
            // What the ingress rules let through goes on to the peering policy, or to software.
            let next = if !vni_denies.is_empty() {
                (COUNT_JUMP, vec![Arg::Jump(Group::Deny(vni))])
            } else if police {
                (COUNT_JUMP, vec![Arg::Jump(Group::Police(vni))])
            } else {
                (PASS, Vec::new())
            };
            let mut ingress = self.ingress(program, vni, vni_ingress, &next);
            ingress.append(&mut tables);
            tables = ingress;
        }
        PlannedVpc {
            spec,
            entry,
            tables,
        }
    }

    /// Build `vni`'s ingress and color groups, continuing to `next` on pass.
    /// Tables are ordered by [`IngressRule::layer`](crate::program::IngressRule::layer), then shape.
    /// Overlapping rules in one table have the same verdict; `Program::compile` removes duplicates.
    fn ingress(
        &mut self,
        program: &Program,
        vni: Vni,
        rules: &[usize],
        next: &(usize, Vec<Arg>),
    ) -> Vec<PlannedTable> {
        let group = Group::Ingress(vni);
        let mut slots: BTreeMap<(u32, Shape), Vec<usize>> = BTreeMap::new();
        for &i in rules {
            let rule = &program.ingress[i];
            let shape = Shape {
                fragments: rule.fragments,
                ..Shape::of(&rule.matches)
            };
            slots.entry((rule.layer, shape)).or_default().push(i);
        }
        let mut tables = Vec::with_capacity(slots.len() + 1);
        // The meters charged first, and the one each chains to, if any.
        let mut colored: BTreeMap<usize, Option<usize>> = BTreeMap::new();
        for (priority, ((_, shape), indices)) in (0u32..).zip(slots) {
            self.patterns.push(shape.pattern(None));
            let mut actions: Vec<usize> = Vec::new();
            let mut planned = Vec::with_capacity(indices.len());
            for i in indices {
                let rule = &program.ingress[i];
                let (template, args) = match rule.verdict {
                    IngressVerdict::Drop => (DISCARD, Vec::new()),
                    IngressVerdict::Police(m, then) => {
                        colored.insert(m, then);
                        (
                            POLICE_RULE,
                            vec![Arg::Meter(m), Arg::Jump(Group::IngressColor(vni, m))],
                        )
                    }
                    // As the catch-all, but uncounted: an ingress rule's count is what it dropped.
                    IngressVerdict::Continue => match next.0 {
                        COUNT_JUMP => (JUMP, next.1.clone()),
                        _ => (DELIVER, Vec::new()),
                    },
                    IngressVerdict::Pass => (DELIVER, Vec::new()),
                };
                let at = actions
                    .iter()
                    .position(|&a| a == template)
                    .unwrap_or_else(|| {
                        actions.push(template);
                        actions.len() - 1
                    });
                planned.push(PlannedRule {
                    pattern: shape.pattern(Some(&rule.matches)),
                    actions: at,
                    args,
                    role: Role::Ingress(i),
                });
            }
            tables.push(PlannedTable {
                group,
                priority: Priority(priority),
                capacity: u32::try_from(planned.len()).unwrap_or(u32::MAX),
                pattern: self.patterns.len() - 1,
                actions,
                rules: planned,
            });
        }
        let catch_all = u32::try_from(tables.len()).unwrap_or(u32::MAX);
        tables.push(single(
            group,
            catch_all,
            ANY,
            next.0,
            any_pattern(),
            next.1.clone(),
            Role::CatchAll(group),
        ));
        tables.extend(ingress_colors(vni, &colored, next));
        tables
    }

    /// The root, the switch with a rule per VPC, and the switch's catch-all.
    fn fixed_tables(&self) -> Vec<PlannedTable> {
        let switch_rules = self
            .vpcs
            .iter()
            .map(|(&vni, vpc)| PlannedRule {
                pattern: switch_pattern(Some((vni, vpc.spec.vtep))),
                actions: 0,
                args: vec![Arg::Jump(vpc.entry)],
                role: Role::Switch(vni),
            })
            .collect();
        vec![
            single(
                Group::Root,
                0,
                ROOT,
                TO_SWITCH,
                root_pattern(),
                Vec::new(),
                Role::Root,
            ),
            PlannedTable {
                group: Group::Switch,
                priority: Priority(0),
                capacity: SWITCH_CAPACITY,
                pattern: SWITCHED,
                actions: vec![JUMP],
                rules: switch_rules,
            },
            single(
                Group::Switch,
                1,
                ANY,
                DELIVER,
                any_pattern(),
                Vec::new(),
                Role::CatchAll(Group::Switch),
            ),
        ]
    }

    /// Every table of the plan.
    pub fn tables(&self) -> impl Iterator<Item = &PlannedTable> {
        self.fixed
            .iter()
            .chain(self.vpcs.values().flat_map(|vpc| &vpc.tables))
            .chain(self.meters.iter().filter_map(|meter| meter.colors.as_ref()))
    }

    /// Every table of the plan, to change it.
    pub fn tables_mut(&mut self) -> impl Iterator<Item = &mut PlannedTable> {
        self.fixed
            .iter_mut()
            .chain(self.vpcs.values_mut().flat_map(|vpc| &mut vpc.tables))
            .chain(
                self.meters
                    .iter_mut()
                    .filter_map(|meter| meter.colors.as_mut()),
            )
    }
}

/// Source VPC `vni`'s ingress color groups, for the meters in `colored` (charged first, and the
/// one each chains to, if any): a first meter's green and yellow are charged to the second, whose
/// own go to `next`, as do a meter's that chains to none; red is dropped.
fn ingress_colors(
    vni: Vni,
    colored: &BTreeMap<usize, Option<usize>>,
    next: &(usize, Vec<Arg>),
) -> Vec<PlannedTable> {
    let mut tables = Vec::new();
    let mut chains: Vec<(usize, (usize, Vec<Arg>))> = Vec::new();
    for (&meter, &then) in colored {
        match then {
            Some(second) => {
                chains.push((
                    meter,
                    (
                        COUNT_POLICE,
                        vec![
                            Arg::Meter(second),
                            Arg::Jump(Group::IngressColor(vni, second)),
                        ],
                    ),
                ));
                chains.push((second, next.clone()));
            }
            None => chains.push((meter, next.clone())),
        }
    }
    chains.sort_by_key(|(meter, _)| *meter);
    chains.dedup_by_key(|(meter, _)| *meter);
    for (meter, (on, args)) in chains {
        tables.push(PlannedTable {
            group: Group::IngressColor(vni, meter),
            priority: Priority(0),
            capacity: 3,
            pattern: COLOR,
            actions: vec![on, DISCARD],
            rules: Color::ALL
                .into_iter()
                .map(|c| PlannedRule {
                    pattern: Pattern::meter_color(c).complete(),
                    actions: usize::from(c == Color::Red),
                    args: if c == Color::Red {
                        Vec::new()
                    } else {
                        args.clone()
                    },
                    role: Role::IngressColor(vni, meter, c),
                })
                .collect(),
        });
    }
    tables
}

/// Meter `meter`'s color group: green and yellow are counted and passed, red counted and
/// dropped.
fn color_table(meter: usize) -> PlannedTable {
    PlannedTable {
        group: Group::Color(meter),
        priority: Priority(0),
        capacity: 3,
        pattern: COLOR,
        actions: vec![PASS, DISCARD],
        rules: Color::ALL
            .into_iter()
            .map(|c| PlannedRule {
                pattern: Pattern::meter_color(c).complete(),
                actions: usize::from(c == Color::Red),
                args: Vec::new(),
                role: Role::Color(meter, c),
            })
            .collect(),
    }
}
