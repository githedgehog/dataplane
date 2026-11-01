// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The mlx5 backend: a [`Program`] lowered onto hardware steering (`dv_flow_en=2`, template API).
//!
//! ```text
//! group 0     eth / ipv4 / udp dst 4789                                  -> jump 1 (or 2)
//! group 1     ACL denies, one table per rule shape:
//!             ... / vxlan vni / eth / ip src, dst [proto] [/ udp|tcp ports] -> drop
//!             last: eth                                                  -> jump 2 (or the fate)
//! group 2     rate limits, one table per rule shape:
//!             ... / vxlan vni / eth / ip src, dst [proto] [/ udp|tcp ports] -> meter m / jump 3 + m
//!             last: eth                                                  -> the driver's fate
//! group 3+m   meter color green, yellow                                  -> count / the driver's fate
//!             meter color red                                            -> count / drop
//! ```
//!
//! A frame goes through the denies, then the rate limits, as a packet goes through the ACL filter,
//! then the rate limiter: each decides by its own first match. Groups with no rules are left out.
//!
//! Prototype limits: IPv4 underlay only; every rule set is rebuilt from scratch on a change, so
//! traffic is briefly unlimited in hardware (never blocked) while it is.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use crate::Policy;
use dpdk::dev::{Dev, Started};
use dpdk::flow::model::{Ipv6Extensions, Parser};
use dpdk::flow::template::{
    Color, Complete, Counts, Meter, MeterAlgorithm, MeterError, MeterProfile, MeterProfileHandle,
    MeterProfileId, MeterUnit, Pattern, PatternTemplate, RuleArg, TableConfig, TemplateAction,
    TemplateConfig, TemplateError, TemplateFlows, TemplateRule, TemplateTable,
};
use dpdk::flow::{
    EthMatch, FlowError, FlowGroup, Ingress, Ipv4Match, Ipv4Prefix, Ipv6Match, Ipv6Prefix,
    Priority, TcpMatch, UdpMatch, VxlanMatch,
};
use net::vxlan::Vni;
use rate_limit::Unit;
use tracing::{error, info, warn};

use crate::program::{Match, Origin, Peering, Prefix, Program};

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

/// ACL denies.
const DENY: FlowGroup = FlowGroup(1);
/// Rate limits.
const POLICE: FlowGroup = FlowGroup(2);
/// How often the rules are checked against the published limits.
const POLL: Duration = Duration::from_millis(200);
/// How often hardware counters are reported.
const REPORT: Duration = Duration::from_secs(10);

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
        let vni = rule.map_or_else(
            || Vni::new_checked(Vni::MIN).unwrap_or_else(|_| unreachable!()),
            |r| r.src_vni,
        );
        let tunnel = Pattern::new()
            .eth(EthMatch::default())
            .ipv4(Ipv4Match::default())
            .udp(UdpMatch::default().dst(VXLAN_PORT))
            .vxlan(VxlanMatch::default().vni(vni))
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
        if self.v6 {
            let addr = |p: Option<Prefix>, len| match p {
                Some(Prefix::V6(a, l)) => Ipv6Prefix::prefix(a, l),
                _ => Ipv6Prefix::prefix(std::net::Ipv6Addr::UNSPECIFIED, len),
            };
            // Fragments are left to software: it sees a later fragment's protocol as the fragment,
            // with no ports, and a first fragment as its protocol, which no NIC rule can tell
            // apart alike for every rule of a peering. So no NIC rule matches any fragment.
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
                _ => Ipv4Prefix::prefix(std::net::Ipv4Addr::UNSPECIFIED, len),
            };
            // Fragments are left to software: it sees a later fragment's protocol as the fragment,
            // with no ports, and a first fragment as its protocol, which no NIC rule can tell
            // apart alike for every rule of a peering. So no NIC rule matches any fragment.
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

fn profile(meter: &crate::program::PoliceMeter) -> MeterProfile {
    let p = meter.profile;
    let cir = p.committed_rate().per_second().get();
    let (cbs, ebs) = (encodable(p.committed_burst()), encodable(p.excess_burst()));
    MeterProfile {
        algorithm: match p.excess_rate() {
            None => MeterAlgorithm::Srtcm { cir, cbs, ebs },
            Some(eir) => MeterAlgorithm::Rfc4115 {
                cir,
                eir: eir.per_second().get(),
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

fn color_group(meter: usize) -> FlowGroup {
    FlowGroup(3 + u32::try_from(meter).unwrap_or(u32::MAX - 3))
}

/// Program `dev` with what the published ACLs and rate limits allow, and follow them until `stop`
/// says so.
///
/// `fate` is where traffic the NIC lets through goes: the driver's data queues.
pub fn run(
    dev: &Dev<'_, Started>,
    port: &str,
    policy: &Policy,
    fate: &TemplateAction,
    stop: &dyn Fn() -> bool,
) {
    let (acls, reader) = (&policy.acls, &policy.rate_limits);
    let flows = match TemplateFlows::new(dev) {
        Ok(flows) => flows,
        Err(e) => {
            warn!("port {port}: no NIC rate limiting: {e}");
            return;
        }
    };
    while !stop() {
        let (filter, limits) = (acls.load(), reader.load());
        let changed = || {
            stop()
                || !concurrency::sync::Arc::ptr_eq(&acls.load(), &filter)
                || !concurrency::sync::Arc::ptr_eq(&reader.load(), &limits)
        };
        if !limits.attempt_offloads() {
            info!("port {port}: NIC offload is turned off; software alone enforces the policy");
        }
        // Peerings whose rules the NIC refused: they stay in software, whole.
        let mut excluded = BTreeSet::new();
        loop {
            let program = Program::compile(&filter, &limits, &excluded);
            let mut reported = BTreeSet::new();
            for (peering, origin, refusal) in &program.refused {
                if reported.insert(*peering) {
                    info!("port {port}: the {peering} stays in software: {origin}: {refusal:?}");
                }
            }
            let outcome = Plan::new(&program, fate)
                .and_then(|plan| install(&flows, port, &program, &plan, &changed));
            match outcome {
                Ok(Held) => break,
                Ok(Refused(peerings)) => excluded.extend(peerings),
                Err(e) => {
                    error!(
                        "port {port}: NIC offload failed, software only until the next change: {e}"
                    );
                    while !changed() {
                        std::thread::sleep(POLL);
                    }
                    break;
                }
            }
        }
    }
}

/// What a rule is for, to report its counts.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Role {
    /// The root rule, which takes VXLAN into the program.
    Root,
    /// An ACL deny of the program, by index into [`Program::denies`].
    Deny(usize),
    /// A rate limit of the program, by index into [`Program::rules`].
    Police(usize),
    /// The rule for what no rule of the program in this group matches.
    CatchAll(FlowGroup),
    /// What a meter, by index into [`Program::meters`], colored.
    Color(usize, Color),
}

/// A per-rule argument, by reference into the plan.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Arg {
    /// The meter of [`Plan::profiles`] at this index.
    Meter(usize),
    /// Jump to this group.
    Jump(FlowGroup),
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
    /// Where the table sits and its capacity.
    pub config: TableConfig,
    /// Its pattern template, by index into [`Plan::patterns`].
    pub pattern: usize,
    /// Its actions templates, by index into [`Plan::actions`].
    pub actions: Vec<usize>,
    /// Its rules.
    pub rules: Vec<PlannedRule>,
}

/// A [`Program`] lowered onto one mlx5 port, as data: every template, meter, table and rule the
/// port gets, so that it can be checked without the NIC (see [`crate::model`]).
///
/// Tables are listed from the root down, and installed in reverse, so traffic only ever enters
/// complete groups.
#[derive(Debug)]
pub struct Plan {
    /// Pattern templates.
    pub patterns: Vec<Pattern<Complete>>,
    /// Actions templates.
    pub actions: Vec<Vec<TemplateAction>>,
    /// One meter per program meter, by the same index.
    pub profiles: Vec<MeterProfile>,
    /// The tables, root first.
    pub tables: Vec<PlannedTable>,
}

/// Pattern templates every plan has, by index.
const ROOT: usize = 0;
const ANY: usize = 1;
const COLOR: usize = 2;

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

/// A rule of the program to lay out in a classifying group.
struct Classified<'a> {
    matches: &'a Match,
    role: Role,
    args: Vec<Arg>,
}

impl Plan {
    /// Lay out a group of program rules, one table per shape, all with actions template
    /// `actions`, and a last table sending what none matches to actions template `otherwise`.
    fn classify(
        &mut self,
        group: FlowGroup,
        rules: Vec<Classified<'_>>,
        actions: usize,
        otherwise: usize,
    ) {
        let mut shapes: BTreeMap<Shape, Vec<Classified<'_>>> = BTreeMap::new();
        for rule in rules {
            shapes
                .entry(Shape::of(rule.matches))
                .or_default()
                .push(rule);
        }
        let catch_all = u32::try_from(shapes.len()).unwrap_or(u32::MAX);
        for (priority, (shape, rules)) in (0u32..).zip(shapes) {
            self.patterns.push(shape.pattern(None));
            self.tables.push(PlannedTable {
                config: TableConfig {
                    group,
                    priority: Priority(priority),
                    capacity: u32::try_from(rules.len()).unwrap_or(u32::MAX),
                },
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
        self.tables.push(PlannedTable {
            config: TableConfig {
                group,
                priority: Priority(catch_all),
                capacity: 1,
            },
            pattern: ANY,
            actions: vec![otherwise],
            rules: vec![PlannedRule {
                pattern: any_pattern(),
                actions: 0,
                args: Vec::new(),
                role: Role::CatchAll(group),
            }],
        });
    }

    /// Lower `program`, sending what the NIC lets through to `fate`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooManyMeters`] if the program needs more meters than [`RESOURCES`].
    pub fn new(program: &Program, fate: &TemplateAction) -> Result<Plan, Error> {
        // Actions templates, by index.
        const TO_DENY: usize = 0;
        const TO_POLICE: usize = 1;
        const POLICE_RULE: usize = 2;
        const DELIVER: usize = 3;
        const PASS: usize = 4;
        const DISCARD: usize = 5;
        const DROP: usize = 6;
        if program.meters.len() > RESOURCES.meters as usize {
            return Err(Error::TooManyMeters(program.meters.len()));
        }
        let mut plan = Plan {
            patterns: vec![
                root_pattern(),
                any_pattern(),
                Pattern::meter_color(Color::Green).complete(),
            ],
            actions: vec![
                vec![TemplateAction::Jump(DENY)],
                vec![TemplateAction::Jump(POLICE)],
                vec![TemplateAction::Meter, TemplateAction::JumpPerRule],
                vec![fate.clone()],
                vec![TemplateAction::Count, fate.clone()],
                vec![TemplateAction::Count, TemplateAction::Drop],
                vec![TemplateAction::Drop],
            ],
            profiles: program.meters.iter().map(profile).collect(),
            tables: Vec::new(),
        };
        let (denies, police) = (!program.denies.is_empty(), !program.rules.is_empty());
        if !denies && !police {
            return Ok(plan);
        }
        plan.tables.push(PlannedTable {
            config: TableConfig {
                group: FlowGroup(0),
                priority: Priority(0),
                capacity: 1,
            },
            pattern: ROOT,
            actions: vec![if denies { TO_DENY } else { TO_POLICE }],
            rules: vec![PlannedRule {
                pattern: root_pattern(),
                actions: 0,
                args: Vec::new(),
                role: Role::Root,
            }],
        });
        if denies {
            let rules = (0..)
                .zip(&program.denies)
                .map(|(index, deny)| Classified {
                    matches: &deny.matches,
                    role: Role::Deny(index),
                    args: Vec::new(),
                })
                .collect();
            plan.classify(DENY, rules, DROP, if police { TO_POLICE } else { DELIVER });
        }
        if police {
            let rules = (0..)
                .zip(&program.rules)
                .map(|(index, rule)| Classified {
                    matches: &rule.matches,
                    role: Role::Police(index),
                    args: vec![Arg::Meter(rule.meter), Arg::Jump(color_group(rule.meter))],
                })
                .collect();
            plan.classify(POLICE, rules, POLICE_RULE, DELIVER);
            plan.tables.extend(
                (0..program.meters.len()).map(|meter| color_table(meter, COLOR, [PASS, DISCARD])),
            );
        }
        Ok(plan)
    }
}

/// Meter `meter`'s color group: green and yellow are counted and passed with `actions[0]`, red
/// counted and dropped with `actions[1]`.
fn color_table(meter: usize, pattern: usize, actions: [usize; 2]) -> PlannedTable {
    PlannedTable {
        config: TableConfig {
            group: color_group(meter),
            priority: Priority(0),
            capacity: 3,
        },
        pattern,
        actions: actions.to_vec(),
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

/// The rules of a plan while it is installed.
#[derive(Debug)]
pub struct Installed<'a> {
    rules: &'a [Vec<(Role, TemplateRule<'a>)>],
    refused: &'a [(Role, String)],
}

impl Installed<'_> {
    /// The rules of the program the NIC refused, and why: they stay in software alone.
    #[must_use]
    pub fn refused(&self) -> &[(Role, String)] {
        self.refused
    }

    /// How many installed rules have a role `which` accepts.
    #[must_use]
    pub fn installed(&self, which: impl Fn(Role) -> bool) -> usize {
        self.rules
            .iter()
            .flatten()
            .filter(|(role, _)| which(*role))
            .count()
    }

    /// What each counting rule has counted so far, by role. Hardware counters lag (by about half
    /// a second on a BlueField-3).
    #[must_use]
    pub fn counts(&self) -> Vec<(Role, Counts)> {
        self.rules
            .iter()
            .flatten()
            .filter(|(role, _)| matches!(role, Role::Color(..)))
            .map(|(role, rule)| (*role, rule.counts().unwrap_or_default()))
            .collect()
    }
}

/// Whether every rule of `table` is a rule of the program: then the NIC may refuse the table, or
/// any of its rules, and they stay in software alone. That is safe: rate limits charging
/// different meters never overlap, so no remaining rule takes their traffic; and a deny left out
/// only lets through what software then drops (a rate limit may still charge it: the tolerated
/// deviation, see the differential test).
fn optional(table: &PlannedTable) -> bool {
    table
        .rules
        .iter()
        .all(|rule| matches!(rule.role, Role::Police(_) | Role::Deny(_)))
}

/// Install `plan` on `flows`' port, call `f` while it is installed, and remove it again.
///
/// Rules of the program the NIC refuses (their template, their table, or the rule itself) are
/// left out and listed in [`Installed::refused`]; the rest of the plan is installed.
///
/// # Errors
///
/// Returns the first template, table, meter or rule the NIC refused that the plan cannot do
/// without; whatever was installed is removed again.
pub fn with_installed<R>(
    flows: &TemplateFlows<'_>,
    plan: &Plan,
    f: impl FnOnce(&Installed<'_>) -> R,
) -> Result<R, Error> {
    if plan.tables.is_empty() {
        return Ok(f(&Installed {
            rules: &[],
            refused: &[],
        }));
    }
    let mut refused: Vec<(Role, String)> = Vec::new();
    let mut refuse = |table: &PlannedTable, why: &dyn std::fmt::Display| {
        for rule in &table.rules {
            refused.push((rule.role, why.to_string()));
        }
    };
    let patterns: Vec<Result<PatternTemplate<'_, Ingress>, FlowError>> = plan
        .patterns
        .iter()
        .map(|p| flows.pattern_template::<Ingress, _>(p))
        .collect();
    let actions = plan
        .actions
        .iter()
        .map(|a| flows.actions_template::<Ingress>(a))
        .collect::<Result<Vec<_>, _>>()?;
    let profiles = plan
        .profiles
        .iter()
        .enumerate()
        .map(|(id, p)| {
            flows.meter_profile(MeterProfileId(u32::try_from(id).unwrap_or(u32::MAX)), p)
        })
        .collect::<Result<Vec<MeterProfileHandle<'_>>, _>>()?;
    let mut tables: Vec<Option<TemplateTable<'_, Ingress>>> = Vec::with_capacity(plan.tables.len());
    for planned in &plan.tables {
        let templates: Vec<_> = planned.actions.iter().map(|&a| &actions[a]).collect();
        let table = match &patterns[planned.pattern] {
            Ok(pattern) => flows
                .table(planned.config, &[pattern], &templates)
                .map_err(Error::from),
            Err(e) => Err(Error::Pattern(e.to_string())),
        };
        tables.push(match table {
            Ok(table) => Some(table),
            Err(e) if optional(planned) => {
                refuse(planned, &e);
                None
            }
            Err(e) => return Err(e),
        });
    }
    let meters = profiles
        .iter()
        .map(|p| flows.meter::<Ingress>(p))
        .collect::<Result<Vec<Meter<'_, Ingress>>, _>>()?;

    // Rules, deepest table first, so traffic only ever enters complete groups.
    let mut rules: Vec<Vec<(Role, TemplateRule<'_>)>> =
        plan.tables.iter().map(|_| Vec::new()).collect();
    for (at, (planned, table)) in plan.tables.iter().zip(&tables).enumerate().rev() {
        let Some(table) = table else { continue };
        for rule in &planned.rules {
            let args: Vec<RuleArg<'_, Ingress>> = rule
                .args
                .iter()
                .map(|&arg| match arg {
                    Arg::Meter(m) => RuleArg::Meter(&meters[m]),
                    Arg::Jump(group) => RuleArg::Jump(group),
                })
                .collect();
            match table.insert(0, &rule.pattern, rule.actions, &args) {
                Ok(installed) => rules[at].push((rule.role, installed)),
                Err(e) if optional(planned) => refused.push((rule.role, e.to_string())),
                Err(e) => return Err(e.into()),
            }
        }
    }
    let result = f(&Installed {
        rules: &rules,
        refused: &refused,
    });
    // The root rule goes first, so no packet enters a group being removed.
    rules[0].clear();
    Ok(result)
}

/// How an installed plan ended.
#[derive(Debug)]
enum Installation {
    /// It was held until the policy changed.
    Held,
    /// The NIC refused some rules of these peerings, so the plan was removed again: a peering is
    /// offloaded whole or not at all.
    Refused(BTreeSet<Peering>),
}
use Installation::{Held, Refused};

/// Install `plan` on `flows`' port, then hold it until `changed`, reporting its counts; everything
/// is removed on return. If the NIC refuses any rule of the program, the plan is removed at once
/// and the peerings of the refused rules returned.
///
/// # Errors
///
/// Returns the first template, table, meter or rule the NIC refused that the plan cannot do
/// without; whatever was installed is removed again.
fn install(
    flows: &TemplateFlows<'_>,
    port: &str,
    program: &Program,
    plan: &Plan,
    changed: &dyn Fn() -> bool,
) -> Result<Installation, Error> {
    with_installed(flows, plan, |installed| {
        let mut refused = BTreeSet::new();
        for (role, why) in installed.refused() {
            let (origin, peering) = match *role {
                Role::Police(rule) => {
                    let rule = &program.rules[rule];
                    (Origin::RateLimit(rule.rule), rule.peering)
                }
                Role::Deny(deny) => (program.denies[deny].origin, program.denies[deny].peering),
                _ => continue,
            };
            warn!(
                "port {port}: the NIC refused {origin}, so the {peering} stays in software: {why}"
            );
            refused.insert(peering);
        }
        if !refused.is_empty() {
            return Refused(refused);
        }
        if !plan.tables.is_empty() {
            info!(
                "port {port}: NIC enforcing {} ACL deny(s) and {} rate limit(s) with {} meter(s) in {} table(s)",
                installed.installed(|role| matches!(role, Role::Deny(_))),
                installed.installed(|role| matches!(role, Role::Police(_))),
                plan.profiles.len(),
                plan.tables.len()
            );
        }
        let mut reported = Instant::now();
        while !changed() {
            std::thread::sleep(POLL);
            if reported.elapsed() >= REPORT {
                report(port, program, installed);
                reported = Instant::now();
            }
        }
        report(port, program, installed);
        Held
    })
}

/// Log and export what each meter passed and dropped in hardware.
fn report(port: &str, program: &Program, installed: &Installed<'_>) {
    let mut passed = vec![Counts::default(); program.meters.len()];
    let mut dropped = vec![Counts::default(); program.meters.len()];
    for (role, counts) in installed.counts() {
        let Role::Color(meter, color) = role else {
            continue;
        };
        let sum = if color == Color::Red {
            &mut dropped[meter]
        } else {
            &mut passed[meter]
        };
        sum.packets += counts.packets;
        sum.bytes += counts.bytes;
    }
    for ((meter, passed), dropped) in program.meters.iter().zip(passed).zip(dropped) {
        info!(
            "port {port}: meter {} in the NIC: passed {} packets, dropped {} packets",
            meter.name, passed.packets, dropped.packets
        );
        for (result, counts) in [("conforming", passed), ("over_limit", dropped)] {
            metrics::counter!(
                "rate_limit_nic_packets_total",
                "port" => port.to_string(),
                "meter" => meter.name.clone(),
                "result" => result
            )
            .absolute(counts.packets);
        }
    }
}
