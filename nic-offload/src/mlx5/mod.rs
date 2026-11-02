// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The mlx5 backend: a [`Program`] lowered onto hardware steering (`dv_flow_en=2`, template API).
//!
//! ```text
//! root        eth / ipv4 / udp dst 4789                       -> jump switch
//! switch      one rule per source VPC: eth / ipv4 dst vtep / udp / vxlan vni
//!                                                             -> jump to its generation
//!             last: eth                                       -> the driver's fate (software)
//! deny(v)     the VPC's ACL denies, one table per rule shape:
//!             ... / vxlan / eth / ip src, dst [proto] [/ udp|tcp ports, flags] -> drop
//!             last: eth                                       -> jump police(v) (or the fate)
//! police(v)   the VPC's rate limits, one table per rule shape:
//!             ... / vxlan / eth / ip src, dst [proto] [/ udp|tcp ports, flags] -> meter m / jump color(m)
//!             last: eth                                       -> the driver's fate
//! color(m)    meter color green, yellow                       -> count / the driver's fate
//!             meter color red                                 -> count / drop
//! ```
//!
//! A frame goes through the denies, then the rate limits, as a packet goes through the ACL filter,
//! then the rate limiter: each decides by its own first match. Groups with no rules are left out.
//!
//! Each source VPC's rules are a generation of their own, reached only through its switch rule:
//! a change of a VPC's policy detaches it (software alone enforces it meanwhile), builds its next
//! generation aside and attaches it, and leaves other VPCs alone ([`Port`]). The root is fixed: mlx5 steers the root group with firmware,
//! slow to change and unable to update a rule in place.
//!
//! A switch rule matches the VNI's VTEP address as the outer destination, as software decapsulates
//! only VXLAN addressed to it: other VXLAN through the gateway is transit, routed in the underlay
//! untouched, and the NIC leaves it to software too.
//!
//! [`Plan`] is the layout as data, with groups named for what they are for ([`Group`]); they are
//! numbered when installed. Limits: IPv4 underlay only.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::Ipv4Addr;

use dpdk::flow::model::{Ipv6Extensions, Parser};
use dpdk::flow::template::{
    Color, Complete, MeterAlgorithm, MeterError, MeterProfile, MeterUnit, Pattern, TemplateAction,
    TemplateConfig, TemplateError,
};
use dpdk::flow::{
    EthMatch, FlowError, FlowGroup, Ipv4Match, Ipv4Prefix, Ipv6Match, Ipv6Prefix, Priority,
    TcpMatch, UdpMatch, VxlanMatch,
};
use net::vxlan::Vni;
use rate_limit::Unit;

use crate::program::{Match, Prefix, Program};

/// What a port reserves for this backend when it is configured; fixed until the port restarts.
pub const RESOURCES: TemplateConfig = TemplateConfig {
    queue_size: 64,
    counters: 1 << 14,
    meters: 1 << 10,
};

const VXLAN_PORT: u16 = 4789;
/// What mlx5's parser is known to do, as the hardware qualification settled it on a BlueField-3:
/// it walks IPv6 extension headers and matches a pattern's IPv6 `proto` on the protocol after
/// them (hop-by-hop: 239 of 239 frames). Software does the same, so a rule naming a protocol sees
/// such packets alike in both.
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

/// The protocol layout of an inner match.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum L4 {
    Any,
    Proto,
    Udp {
        src: bool,
        dst: bool,
    },
    /// TCP, with ports constrained or not, and the mask of flags constrained.
    Tcp {
        src: bool,
        dst: bool,
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
}

impl Shape {
    fn of(rule: &Match) -> Shape {
        let l4 = match (rule.proto, rule.src_port, rule.dst_port) {
            (None, ..) => L4::Any,
            (Some(17), src, dst) if src.is_some() || dst.is_some() => L4::Udp {
                src: src.is_some(),
                dst: dst.is_some(),
            },
            (Some(6), src, dst) if src.is_some() || dst.is_some() || rule.tcp_flags.is_some() => {
                L4::Tcp {
                    src: src.is_some(),
                    dst: dst.is_some(),
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
        let ports = |p: Option<u16>| p.unwrap_or(1);
        let (src_port, dst_port) = (rule.and_then(|r| r.src_port), rule.and_then(|r| r.dst_port));
        macro_rules! finish {
            ($ip:expr) => {
                match self.l4 {
                    L4::Any | L4::Proto => $ip.complete(),
                    L4::Udp { src, dst } => {
                        let mut udp = UdpMatch::default();
                        if src {
                            udp = udp.src(ports(src_port));
                        }
                        if dst {
                            udp = udp.dst(ports(dst_port));
                        }
                        $ip.udp(udp).complete()
                    }
                    L4::Tcp { src, dst, flags } => {
                        let mut tcp = TcpMatch::default();
                        if src {
                            tcp = tcp.src(ports(src_port));
                        }
                        if dst {
                            tcp = tcp.dst(ports(dst_port));
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
        // Fragments are left to software: it sees a later fragment's protocol as the fragment,
        // with no ports, and a first fragment as its protocol, which no NIC rule can tell apart
        // alike for every rule of a peering. So no NIC rule matches any fragment.
        if self.v6 {
            let addr = |p: Option<Prefix>, len| match p {
                Some(Prefix::V6(a, l)) => Ipv6Prefix::prefix(a, l),
                _ => Ipv6Prefix::prefix(std::net::Ipv6Addr::UNSPECIFIED, len),
            };
            let mut ip = Ipv6Match::default()
                .src(addr(rule.map(|r| r.source), self.source))
                .dst(addr(rule.map(|r| r.destination), self.destination))
                .unfragmented();
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
                .dst(addr(rule.map(|r| r.destination), self.destination))
                .unfragmented();
            if self.l4 != L4::Any {
                ip = ip.proto(proto);
            }
            finish!(tunnel.ipv4(ip))
        }
    }
}

/// A burst size mlx5 can encode: the smallest at least `bytes` (and at most 256/255 of it).
/// mlx5 encodes sizes strictly between 255·2^k and 256·2^k as zero
/// (`mlx5_flow_meter_xbs_man_exp_calc`). Rounding up keeps the NIC at least as permissive as the
/// software it stands in front of.
fn encodable(bytes: u64) -> u64 {
    (0..56)
        .map(|k| (255u64 << k, 256u64 << k))
        .find(|&(low, high)| low < bytes && bytes < high)
        .map_or(bytes, |(_, high)| high)
}

/// What the NIC's byte meters count beyond what software bills a packet (its IP bytes): the
/// outer Ethernet, IPv4, UDP and VXLAN headers (50), an outer VLAN tag (4), the inner Ethernet
/// header (14) and the FCS (4), whether or not a given NIC counts each.
pub const BYTE_OVERHEAD: u64 = 72;

/// The fewest bytes software bills a packet a NIC rule matches: an IPv4 header.
const MIN_BILLED: u64 = 20;

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

/// The peerings of `program`'s meters whose rates mlx5 cannot encode as high as software's: they
/// stay in software.
#[must_use]
pub fn unfit(program: &Program) -> BTreeSet<crate::program::Peering> {
    let fits = |meter: &crate::program::PoliceMeter| {
        let pmd = match meter.unit {
            Unit::Bytes => 0,
            Unit::Packets => PPS_SHIFT,
        };
        let scale = match meter.unit {
            Unit::Bytes => MIN_BILLED + BYTE_OVERHEAD,
            Unit::Packets => MIN_BILLED,
        };
        let p = meter.profile;
        let cir = p.committed_rate().per_second().get();
        let fastest = p
            .excess_rate()
            .map_or(cir, |eir| eir.per_second().get().saturating_add(cir));
        ((u128::from(fastest) * u128::from(scale)).div_ceil(u128::from(MIN_BILLED)) << pmd)
            <= u128::from(MAX_RATE)
    };
    program
        .rules
        .iter()
        .filter(|rule| !fits(&program.meters[rule.meter]))
        .map(|rule| rule.peering)
        .collect()
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

/// The NIC's meter profile for `meter`, at least as permissive as the software's component,
/// so that whatever the NIC colors red, software would too:
///
/// - a NIC meters the outer frame where software bills the inner IP bytes: byte rates and bursts
///   are scaled by the most a packet's NIC count can exceed its bill,
///   `(MIN_BILLED + BYTE_OVERHEAD) / MIN_BILLED`;
/// - a NIC meter passes a packet while any token is left, and goes into debt: bursts gain one
///   largest frame;
/// - software's per-worker leases let a burst exceed its bucket by one lease per worker: bursts
///   gain that too ([`PoliceMeter::lease_slack`](crate::program::PoliceMeter::lease_slack));
/// - the NIC encodes rates to the nearest it can, and bursts up: rates are rounded up to one it
///   encodes exactly, bursts to one that does not wrap;
/// - software couples the excess bucket to the committed one (MEF 10), the NIC does not
///   (RFC 4115): its excess rate is the sum of both, the most the coupled bucket fills at.
///
/// The scaling is for the smallest packets: those get through the NIC at about the rate software
/// allows them, and full-size ones at up to `(MIN_BILLED + BYTE_OVERHEAD) / MIN_BILLED` times it
/// less their overhead (about 4.4 times, for 1500 bytes). The NIC stops floods, software enforces
/// the rate.
pub(crate) fn profile(meter: &crate::program::PoliceMeter) -> MeterProfile {
    let p = meter.profile;
    let (scale, frame) = match meter.unit {
        Unit::Bytes => (MIN_BILLED + BYTE_OVERHEAD, MAX_FRAME),
        Unit::Packets => (MIN_BILLED, 1),
    };
    let pmd = match meter.unit {
        Unit::Bytes => 0,
        Unit::Packets => PPS_SHIFT,
    };
    let scaled = |tokens: u64| tokens.saturating_mul(scale).div_ceil(MIN_BILLED);
    // What mlx5 encodes exactly, in its (scaled) units, given back in ours, rounded up: mlx5 then
    // encodes at least that.
    let rate = |tokens: u64| encodable_rate(scaled(tokens) << pmd).div_ceil(1 << pmd);
    let burst = |tokens: u64, slack: u64| {
        if tokens == 0 {
            return 0;
        }
        let wanted = scaled(tokens.saturating_add(slack)).saturating_add(frame);
        encodable(wanted << pmd).div_ceil(1 << pmd)
    };
    let cir = p.committed_rate().per_second().get();
    let [committed_slack, excess_slack] = meter.lease_slack;
    let (cbs, ebs) = (
        burst(p.committed_burst(), committed_slack),
        burst(p.excess_burst(), excess_slack),
    );
    MeterProfile {
        algorithm: match p.excess_rate() {
            None => MeterAlgorithm::Srtcm {
                cir: rate(cir),
                cbs,
                ebs,
            },
            Some(eir) => MeterAlgorithm::Rfc4115 {
                cir: rate(cir),
                eir: rate(eir.per_second().get().saturating_add(cir)),
                cbs,
                ebs,
            },
        },
        unit: match meter.unit {
            Unit::Bytes => MeterUnit::Bytes,
            Unit::Packets => MeterUnit::Packets,
        },
    }
}

mod install;

pub use install::{Installed, Port, Reconciled, run, with_installed};

/// A group of a [`Plan`], by what it is for; numbered when installed.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Group {
    /// The root: VXLAN, to the switch.
    Root,
    /// One rule per source VPC, to its generation.
    Switch,
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
    /// An ACL deny of the program, by index into [`Program::denies`].
    Deny(usize),
    /// A rate limit of the program, by index into [`Program::rules`].
    Police(usize),
    /// A destination of another peer a source VPC's rules must let pass: to software.
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
    /// Its color table, in [`Group::Color`] of its index.
    pub colors: PlannedTable,
}

/// What a source VPC's generation enforces, to tell whether an installed one is still what is
/// wanted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpcSpec {
    /// Its denies, in order.
    pub denies: Vec<Match>,
    /// Its rate limits, in order, with their meters.
    pub limits: Vec<(Match, MeterKey)>,
    /// The destinations it lets pass to software ahead of its rules.
    pub passes: Vec<Prefix>,
    /// The VTEP address its VXLAN is addressed to.
    pub vtep: Ipv4Addr,
}

/// A source VPC's generation of rules.
#[derive(Debug)]
pub struct PlannedVpc {
    /// What it enforces.
    pub spec: VpcSpec,
    /// The group its switch rule jumps to.
    pub entry: Group,
    /// Its tables: denies, then rate limits.
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
fn pass_matches(vni: Vni, passes: &[Prefix]) -> Vec<(Match, Vni)> {
    passes
        .iter()
        .map(|p| {
            let source = match p {
                Prefix::V4(..) => Prefix::V4(Ipv4Addr::UNSPECIFIED, 0),
                Prefix::V6(..) => Prefix::V6(std::net::Ipv6Addr::UNSPECIFIED, 0),
            };
            let matches = Match {
                src_vni: vni,
                source,
                destination: *p,
                proto: None,
                src_port: None,
                dst_port: None,
                tcp_flags: None,
            };
            (matches, vni)
        })
        .collect()
}

/// A rule of the program to lay out in a classifying group.
struct Classified<'a> {
    matches: &'a Match,
    role: Role,
    args: Vec<Arg>,
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
    /// Lay out a group of program rules, one table per shape, all with actions template
    /// `actions`, and a last table sending what none matches to actions template `otherwise`
    /// with `otherwise_args`. Ahead of them all, `passes` send what they match to the fate.
    fn classify(
        &mut self,
        group: Group,
        passes: &[(Match, Vni)],
        rules: Vec<Classified<'_>>,
        actions: usize,
        otherwise: (usize, Vec<Arg>),
    ) -> Vec<PlannedTable> {
        let mut pass_shapes: BTreeMap<Shape, Vec<&(Match, Vni)>> = BTreeMap::new();
        for pass in passes {
            pass_shapes
                .entry(Shape::of(&pass.0))
                .or_default()
                .push(pass);
        }
        let mut shapes: BTreeMap<Shape, Vec<Classified<'_>>> = BTreeMap::new();
        for rule in rules {
            shapes
                .entry(Shape::of(rule.matches))
                .or_default()
                .push(rule);
        }
        let first = u32::try_from(pass_shapes.len()).unwrap_or(u32::MAX);
        let catch_all = first.saturating_add(u32::try_from(shapes.len()).unwrap_or(u32::MAX));
        let mut tables = Vec::with_capacity(pass_shapes.len() + shapes.len() + 1);
        for (priority, (shape, passes)) in (0u32..).zip(pass_shapes) {
            self.patterns.push(shape.pattern(None));
            tables.push(PlannedTable {
                group,
                priority: Priority(priority),
                capacity: u32::try_from(passes.len()).unwrap_or(u32::MAX),
                pattern: self.patterns.len() - 1,
                actions: vec![DELIVER],
                rules: passes
                    .into_iter()
                    .map(|(matches, vni)| PlannedRule {
                        pattern: shape.pattern(Some(matches)),
                        actions: 0,
                        args: Vec::new(),
                        role: Role::Pass(*vni),
                    })
                    .collect(),
            });
        }
        for (priority, (shape, rules)) in (first..).zip(shapes) {
            self.patterns.push(shape.pattern(None));
            tables.push(PlannedTable {
                group,
                priority: Priority(priority),
                capacity: u32::try_from(rules.len()).unwrap_or(u32::MAX),
                pattern: self.patterns.len() - 1,
                actions: vec![actions],
                rules: rules
                    .into_iter()
                    .map(|rule| PlannedRule {
                        pattern: shape.pattern(Some(rule.matches)),
                        actions: 0,
                        args: rule.args,
                        role: rule.role,
                    })
                    .collect(),
            });
        }
        let (otherwise, args) = otherwise;
        tables.push(single(
            group,
            catch_all,
            ANY,
            otherwise,
            any_pattern(),
            args,
            Role::CatchAll(group),
        ));
        tables
    }

    /// Lower `program`, sending what the NIC lets through to `fate`. A source VPC's rules apply to
    /// VXLAN addressed to its VTEP in `vteps`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooManyMeters`] if the program needs more meters than [`RESOURCES`], and
    /// [`Error::NoVtep`] if a source VPC with rules has no VTEP in `vteps`.
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
            ],
            meters: Vec::new(),
            fixed: Vec::new(),
            vpcs: BTreeMap::new(),
        };
        for (index, meter) in program.meters.iter().enumerate() {
            plan.meters.push(PlannedMeter {
                key: MeterKey {
                    name: meter.name.clone(),
                    profile: profile(meter),
                },
                colors: color_table(index),
            });
        }
        // The program's rules, by source VPC.
        let mut denies: BTreeMap<Vni, Vec<usize>> = BTreeMap::new();
        let mut limits: BTreeMap<Vni, Vec<usize>> = BTreeMap::new();
        for (index, deny) in program.denies.iter().enumerate() {
            denies.entry(deny.matches.src_vni).or_default().push(index);
        }
        for (index, rule) in program.rules.iter().enumerate() {
            limits.entry(rule.matches.src_vni).or_default().push(index);
        }
        let vnis: BTreeSet<Vni> = denies.keys().chain(limits.keys()).copied().collect();
        for vni in vnis {
            let vtep = *vteps.get(&vni).ok_or(Error::NoVtep(vni))?;
            let vpc = plan.vpc(
                program,
                vni,
                vtep,
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

    /// The generation of source VPC `vni`, from its denies and rate limits (indices into
    /// `program`).
    fn vpc(
        &mut self,
        program: &Program,
        vni: Vni,
        vtep: Ipv4Addr,
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
        let spec = VpcSpec {
            denies: vni_denies
                .iter()
                .map(|&i| program.denies[i].matches.clone())
                .collect(),
            limits: vni_limits
                .iter()
                .map(|&i| {
                    let rule = &program.rules[i];
                    (rule.matches.clone(), self.meters[rule.meter].key.clone())
                })
                .collect(),
            passes: program
                .passes
                .get(&vni)
                .map(|p| p.iter().copied().collect())
                .unwrap_or_default(),
            vtep,
        };
        // What another peer takes of a rule's destination passes, ahead of every rule.
        let passes = pass_matches(vni, &spec.passes);
        let mut tables = Vec::new();
        let police = !vni_limits.is_empty();
        if !vni_denies.is_empty() {
            let rules = vni_denies
                .iter()
                .map(|&i| Classified {
                    matches: &program.denies[i].matches,
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
                        role: Role::Police(i),
                        args: vec![Arg::Meter(rule.meter), Arg::Jump(Group::Color(rule.meter))],
                    }
                })
                .collect();
            // The entry group lets the passes through first.
            let entry_passes: &[(Match, Vni)] = if vni_denies.is_empty() { &passes } else { &[] };
            tables.extend(self.classify(
                Group::Police(vni),
                entry_passes,
                rules,
                POLICE_RULE,
                (DELIVER, Vec::new()),
            ));
        }
        let entry = if vni_denies.is_empty() {
            Group::Police(vni)
        } else {
            Group::Deny(vni)
        };
        PlannedVpc {
            spec,
            entry,
            tables,
        }
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
            .chain(self.meters.iter().map(|meter| &meter.colors))
    }

    /// Every table of the plan, to change it.
    pub fn tables_mut(&mut self) -> impl Iterator<Item = &mut PlannedTable> {
        self.fixed
            .iter_mut()
            .chain(self.vpcs.values_mut().flat_map(|vpc| &mut vpc.tables))
            .chain(self.meters.iter_mut().map(|meter| &mut meter.colors))
    }
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
