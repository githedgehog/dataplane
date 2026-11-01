// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The mlx5 backend: a [`Program`] lowered onto hardware steering (`dv_flow_en=2`, template API).
//!
//! ```text
//! group 0     eth / ipv4 / udp dst 4789                                  -> jump 1
//! group 1     one table per rule shape:
//!             ... / vxlan vni / eth / ip src, dst [proto] [/ udp|tcp ports] -> meter m / jump 2 + m
//!             last: eth                                                  -> the driver's fate
//! group 2+m   meter color green, yellow                                  -> count / the driver's fate
//!             meter color red                                            -> count / drop
//! ```
//!
//! Prototype limits: IPv4 underlay only; every rule set is rebuilt from scratch on a change, so
//! traffic is briefly unlimited in hardware (never blocked) while it is.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use dpdk::dev::{Dev, Started};
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
use rate_limit::{PeeringRules, RateLimitReader, Unit};
use tracing::{error, info, warn};

use crate::program::{PoliceRule, Prefix, Program};

/// What a port reserves for this backend when it is configured; fixed until the port restarts.
pub const RESOURCES: TemplateConfig = TemplateConfig {
    queue_size: 64,
    counters: 1 << 14,
    meters: 1 << 10,
};

const VXLAN_PORT: u16 = 4789;
const CLASSIFY: FlowGroup = FlowGroup(1);
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
    /// More meters than [`RESOURCES`] reserved.
    #[error("{0} meters exceed the {max} reserved", max = RESOURCES.meters)]
    TooManyMeters(usize),
}

/// The protocol layout of an inner match.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum L4 {
    Any,
    Proto,
    Udp { src: bool, dst: bool },
    Tcp { src: bool, dst: bool },
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
    fn of(rule: &PoliceRule) -> Shape {
        let l4 = match (rule.proto, rule.src_port, rule.dst_port) {
            (None, ..) => L4::Any,
            (Some(17), src, dst) if src.is_some() || dst.is_some() => L4::Udp {
                src: src.is_some(),
                dst: dst.is_some(),
            },
            (Some(6), src, dst) if src.is_some() || dst.is_some() => L4::Tcp {
                src: src.is_some(),
                dst: dst.is_some(),
            },
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
    fn pattern(self, rule: Option<&PoliceRule>) -> Pattern<Complete> {
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
                    L4::Tcp { src, dst } => {
                        let mut tcp = TcpMatch::default();
                        if src {
                            tcp = tcp.src(ports(src_port));
                        }
                        if dst {
                            tcp = tcp.dst(ports(dst_port));
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
            let mut ip = Ipv6Match::default()
                .src(addr(rule.map(|r| r.source), self.source))
                .dst(addr(rule.map(|r| r.destination), self.destination));
            if self.l4 != L4::Any {
                // Software sees a fragment's protocol as the fragment, with no ports.
                ip = ip.proto(proto).unfragmented();
            }
            finish!(tunnel.ipv6(ip))
        } else {
            let addr = |p: Option<Prefix>, len| match p {
                Some(Prefix::V4(a, l)) => Ipv4Prefix::prefix(a, l),
                _ => Ipv4Prefix::prefix(std::net::Ipv4Addr::UNSPECIFIED, len),
            };
            let mut ip = Ipv4Match::default()
                .src(addr(rule.map(|r| r.source), self.source))
                .dst(addr(rule.map(|r| r.destination), self.destination));
            if self.l4 != L4::Any {
                // Software sees a fragment's protocol as the fragment, with no ports.
                ip = ip.proto(proto).unfragmented();
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
    FlowGroup(2 + u32::try_from(meter).unwrap_or(u32::MAX - 2))
}

/// Program `dev` with what the published rate limits allow, and follow them until `stop` says so.
///
/// `fate` is where traffic the NIC lets through goes: the driver's data queues.
pub fn run(
    dev: &Dev<'_, Started>,
    port: &str,
    reader: &RateLimitReader<PeeringRules>,
    fate: &TemplateAction,
    stop: &dyn Fn() -> bool,
) {
    let flows = match TemplateFlows::new(dev) {
        Ok(flows) => flows,
        Err(e) => {
            warn!("port {port}: no NIC rate limiting: {e}");
            return;
        }
    };
    while !stop() {
        let limits = reader.load();
        let program = Program::compile(&limits);
        for (rule, refusal) in &program.refused {
            info!("port {port}: rate-limit rule {rule} stays in software: {refusal:?}");
        }
        let changed = || stop() || !concurrency::sync::Arc::ptr_eq(&reader.load(), &limits);
        match Plan::new(&program, fate)
            .and_then(|plan| install(&flows, port, &program, &plan, &changed))
        {
            Ok(()) => {}
            Err(e) => {
                error!(
                    "port {port}: NIC rate limiting failed, software only until the next change: {e}"
                );
                while !changed() {
                    std::thread::sleep(POLL);
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
    /// A rule of the program, by index into [`Program::rules`].
    Police(usize),
    /// The rule for what no rule of the program matches.
    CatchAll,
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

impl Plan {
    /// Lower `program`, sending what the NIC lets through to `fate`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooManyMeters`] if the program needs more meters than [`RESOURCES`].
    pub fn new(program: &Program, fate: &TemplateAction) -> Result<Plan, Error> {
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
                vec![TemplateAction::Jump(CLASSIFY)],
                vec![TemplateAction::Meter, TemplateAction::JumpPerRule],
                vec![fate.clone()],
                vec![TemplateAction::Count, fate.clone()],
                vec![TemplateAction::Count, TemplateAction::Drop],
            ],
            profiles: program.meters.iter().map(profile).collect(),
            tables: Vec::new(),
        };
        let (root, any, color) = (0, 1, 2);
        let (jump, police, deliver, pass, discard) = (0, 1, 2, 3, 4);
        if program.rules.is_empty() {
            return Ok(plan);
        }
        plan.tables.push(PlannedTable {
            config: TableConfig {
                group: FlowGroup(0),
                priority: Priority(0),
                capacity: 1,
            },
            pattern: root,
            actions: vec![jump],
            rules: vec![PlannedRule {
                pattern: root_pattern(),
                actions: 0,
                args: Vec::new(),
                role: Role::Root,
            }],
        });
        let mut shapes: BTreeMap<Shape, Vec<usize>> = BTreeMap::new();
        for (index, rule) in program.rules.iter().enumerate() {
            shapes.entry(Shape::of(rule)).or_default().push(index);
        }
        let catch_all = u32::try_from(shapes.len()).unwrap_or(u32::MAX);
        for (priority, (shape, rules)) in (0u32..).zip(shapes) {
            plan.patterns.push(shape.pattern(None));
            plan.tables.push(PlannedTable {
                config: TableConfig {
                    group: CLASSIFY,
                    priority: Priority(priority),
                    capacity: u32::try_from(rules.len()).unwrap_or(u32::MAX),
                },
                pattern: plan.patterns.len() - 1,
                actions: vec![police],
                rules: rules
                    .into_iter()
                    .map(|index| {
                        let rule = &program.rules[index];
                        PlannedRule {
                            pattern: shape.pattern(Some(rule)),
                            actions: 0,
                            args: vec![Arg::Meter(rule.meter), Arg::Jump(color_group(rule.meter))],
                            role: Role::Police(index),
                        }
                    })
                    .collect(),
            });
        }
        plan.tables.push(PlannedTable {
            config: TableConfig {
                group: CLASSIFY,
                priority: Priority(catch_all),
                capacity: 1,
            },
            pattern: any,
            actions: vec![deliver],
            rules: vec![PlannedRule {
                pattern: any_pattern(),
                actions: 0,
                args: Vec::new(),
                role: Role::CatchAll,
            }],
        });
        plan.tables.extend(
            (0..program.meters.len()).map(|meter| color_table(meter, color, [pass, discard])),
        );
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

/// Install `plan` on `flows`' port, then hold it until `changed`; everything is removed on
/// return.
///
/// # Errors
///
/// Returns the first template, table, meter or rule the NIC refused; whatever was installed is
/// removed again.
pub fn install(
    flows: &TemplateFlows<'_>,
    port: &str,
    program: &Program,
    plan: &Plan,
    changed: &dyn Fn() -> bool,
) -> Result<(), Error> {
    if plan.tables.is_empty() {
        while !changed() {
            std::thread::sleep(POLL);
        }
        return Ok(());
    }
    let patterns = plan
        .patterns
        .iter()
        .map(|p| flows.pattern_template::<Ingress, _>(p))
        .collect::<Result<Vec<PatternTemplate<'_, Ingress>>, _>>()?;
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
    let tables = plan
        .tables
        .iter()
        .map(|t| {
            let templates: Vec<_> = t.actions.iter().map(|&a| &actions[a]).collect();
            flows.table(t.config, &[&patterns[t.pattern]], &templates)
        })
        .collect::<Result<Vec<TemplateTable<'_, Ingress>>, _>>()?;
    let meters = profiles
        .iter()
        .map(|p| flows.meter::<Ingress>(p))
        .collect::<Result<Vec<Meter<'_, Ingress>>, _>>()?;

    // Rules, deepest table first, so traffic only ever enters complete groups.
    let mut rules: Vec<Vec<(Role, TemplateRule<'_>)>> =
        plan.tables.iter().map(|_| Vec::new()).collect();
    for (at, (planned, table)) in plan.tables.iter().zip(&tables).enumerate().rev() {
        for rule in &planned.rules {
            let args: Vec<RuleArg<'_, Ingress>> = rule
                .args
                .iter()
                .map(|&arg| match arg {
                    Arg::Meter(m) => RuleArg::Meter(&meters[m]),
                    Arg::Jump(group) => RuleArg::Jump(group),
                })
                .collect();
            rules[at].push((
                rule.role,
                table.insert(0, &rule.pattern, rule.actions, &args)?,
            ));
        }
    }
    let installed =
        |role: fn(Role) -> bool| rules.iter().flatten().filter(|(r, _)| role(*r)).count();
    info!(
        "port {port}: NIC rate limiting {} rule(s) with {} meter(s) in {} table(s)",
        installed(|r| matches!(r, Role::Police(_))),
        meters.len(),
        plan.tables.len()
    );

    let mut reported = Instant::now();
    while !changed() {
        std::thread::sleep(POLL);
        if reported.elapsed() >= REPORT {
            report(port, program, &rules);
            reported = Instant::now();
        }
    }
    report(port, program, &rules);
    // The root rule goes first, so no packet enters a group being removed.
    rules[0].clear();
    Ok(())
}

/// Log and export what each meter passed and dropped in hardware.
fn report(port: &str, program: &Program, rules: &[Vec<(Role, TemplateRule<'_>)>]) {
    let mut passed = vec![Counts::default(); program.meters.len()];
    let mut dropped = vec![Counts::default(); program.meters.len()];
    for (role, rule) in rules.iter().flatten() {
        let Role::Color(meter, color) = *role else {
            continue;
        };
        let counts = rule.counts().unwrap_or_default();
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
