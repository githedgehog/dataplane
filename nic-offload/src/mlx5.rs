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
            .inner_eth(EthMatch::default());
        let proto = rule.and_then(|r| r.proto).unwrap_or(match self.l4 {
            L4::Udp { .. } => 17,
            L4::Tcp { .. } => 6,
            _ => 0,
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
                ip = ip.proto(proto);
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
                ip = ip.proto(proto);
            }
            finish!(tunnel.ipv4(ip))
        }
    }
}

/// A burst size mlx5 can encode: the largest at most `bytes` (and at least 255/256 of it).
/// mlx5 encodes sizes strictly between 255·2^k and 256·2^k as zero
/// (`mlx5_flow_meter_xbs_man_exp_calc`).
fn encodable(bytes: u64) -> u64 {
    (0..56)
        .map(|k| (255u64 << k, 256u64 << k))
        .find(|&(low, high)| low < bytes && bytes < high)
        .map_or(bytes, |(low, _)| low)
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
        match install(&flows, port, &program, fate, &changed) {
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

/// Install `program`, then hold it until `changed`; everything is removed on return.
// One layer per stage: templates, tables, rules, each borrowing the last; splitting it would only
// pass the borrows around.
#[allow(clippy::too_many_lines)]
fn install(
    flows: &TemplateFlows<'_>,
    port: &str,
    program: &Program,
    fate: &TemplateAction,
    changed: &dyn Fn() -> bool,
) -> Result<(), Error> {
    if program.meters.len() > RESOURCES.meters as usize {
        return Err(Error::TooManyMeters(program.meters.len()));
    }
    if program.rules.is_empty() {
        while !changed() {
            std::thread::sleep(POLL);
        }
        return Ok(());
    }
    // Templates.
    let root = flows.pattern_template::<Ingress, _>(
        &Pattern::new()
            .eth(EthMatch::default())
            .ipv4(Ipv4Match::default())
            .udp(UdpMatch::default().dst(VXLAN_PORT)),
    )?;
    let any = flows.pattern_template::<Ingress, _>(&Pattern::new().eth(EthMatch::default()))?;
    let color = flows.pattern_template::<Ingress, _>(&Pattern::meter_color(Color::Green))?;
    let mut shapes: BTreeMap<Shape, (PatternTemplate<'_, Ingress>, usize)> = BTreeMap::new();
    for rule in &program.rules {
        let shape = Shape::of(rule);
        if let Some((_, count)) = shapes.get_mut(&shape) {
            *count += 1;
        } else {
            shapes.insert(shape, (flows.pattern_template(&shape.pattern(None))?, 1));
        }
    }
    let jump = flows.actions_template::<Ingress>(&[TemplateAction::Jump(CLASSIFY)])?;
    let police =
        flows.actions_template::<Ingress>(&[TemplateAction::Meter, TemplateAction::JumpPerRule])?;
    let deliver = flows.actions_template::<Ingress>(std::slice::from_ref(fate))?;
    let pass = flows.actions_template::<Ingress>(&[TemplateAction::Count, fate.clone()])?;
    let discard =
        flows.actions_template::<Ingress>(&[TemplateAction::Count, TemplateAction::Drop])?;
    let profiles = program
        .meters
        .iter()
        .enumerate()
        .map(|(id, meter)| {
            flows.meter_profile(
                MeterProfileId(u32::try_from(id).unwrap_or(u32::MAX)),
                &profile(meter),
            )
        })
        .collect::<Result<Vec<MeterProfileHandle<'_>>, _>>()?;

    // Tables and meters.
    let root_table = flows.table(
        TableConfig {
            group: FlowGroup(0),
            priority: Priority(0),
            capacity: 1,
        },
        &[&root],
        &[&jump],
    )?;
    let mut shape_tables: BTreeMap<Shape, TemplateTable<'_, Ingress>> = BTreeMap::new();
    for (priority, (shape, (template, count))) in (0u32..).zip(&shapes) {
        shape_tables.insert(
            *shape,
            flows.table(
                TableConfig {
                    group: CLASSIFY,
                    priority: Priority(priority),
                    capacity: u32::try_from(*count).unwrap_or(u32::MAX),
                },
                &[template],
                &[&police],
            )?,
        );
    }
    let catch_all = flows.table(
        TableConfig {
            group: CLASSIFY,
            priority: Priority(u32::try_from(shapes.len()).unwrap_or(u32::MAX)),
            capacity: 1,
        },
        &[&any],
        &[&deliver],
    )?;
    let color_tables = (0..program.meters.len())
        .map(|m| {
            flows.table(
                TableConfig {
                    group: color_group(m),
                    priority: Priority(0),
                    capacity: 3,
                },
                &[&color],
                &[&pass, &discard],
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let meters = profiles
        .iter()
        .map(|p| flows.meter::<Ingress>(p))
        .collect::<Result<Vec<Meter<'_, Ingress>>, _>>()?;

    // Rules, deepest first, so traffic only ever enters complete groups.
    let mut colors: Vec<[TemplateRule<'_>; 3]> = Vec::with_capacity(color_tables.len());
    for table in &color_tables {
        let rule = |c, at| table.insert(0, &Pattern::meter_color(c), at, &[]);
        colors.push([
            rule(Color::Green, 0)?,
            rule(Color::Yellow, 0)?,
            rule(Color::Red, 1)?,
        ]);
    }
    let mut classes = Vec::with_capacity(program.rules.len());
    for rule in &program.rules {
        let shape = Shape::of(rule);
        let table = &shape_tables[&shape];
        classes.push(table.insert(
            0,
            &shape.pattern(Some(rule)),
            0,
            &[
                RuleArg::Meter(&meters[rule.meter]),
                RuleArg::Jump(color_group(rule.meter)),
            ],
        )?);
    }
    let _catch_all = catch_all.insert(0, &Pattern::new().eth(EthMatch::default()), 0, &[])?;
    let root_rule = root_table.insert(
        0,
        &Pattern::new()
            .eth(EthMatch::default())
            .ipv4(Ipv4Match::default())
            .udp(UdpMatch::default().dst(VXLAN_PORT)),
        0,
        &[],
    )?;
    info!(
        "port {port}: NIC rate limiting {} rule(s) with {} meter(s) in {} table(s)",
        classes.len(),
        meters.len(),
        shape_tables.len()
    );

    let mut reported = Instant::now();
    while !changed() {
        std::thread::sleep(POLL);
        if reported.elapsed() >= REPORT {
            report(port, program, &colors);
            reported = Instant::now();
        }
    }
    report(port, program, &colors);
    // The root rule goes first, so no packet enters a group being removed.
    drop(root_rule);
    Ok(())
}

/// Log and export what each meter passed and dropped in hardware.
fn report(port: &str, program: &Program, colors: &[[TemplateRule<'_>; 3]]) {
    for (meter, rules) in program.meters.iter().zip(colors) {
        let count = |r: &TemplateRule<'_>| r.counts().unwrap_or_default();
        let (green, yellow, red) = (count(&rules[0]), count(&rules[1]), count(&rules[2]));
        let passed = Counts {
            packets: green.packets + yellow.packets,
            bytes: green.bytes + yellow.bytes,
        };
        info!(
            "port {port}: meter {} in the NIC: passed {} packets, dropped {} packets",
            meter.name, passed.packets, red.packets
        );
        for (result, counts) in [("conforming", passed), ("over_limit", red)] {
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
