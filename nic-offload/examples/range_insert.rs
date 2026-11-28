// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! How fast mlx5 inserts range rules (`last`) against exact ones (slice 1 step 5c-2: masked and
//! ranged planner levels).
//!
//! `range_insert <pci> [<rules>]` installs one table of `rules` UDP rules in a VPC's generation,
//! each a destination address (an exact field) and a destination port: exact, a range with its
//! own address (one rule per bucket), or four disjoint ranges per address (four per bucket),
//! and reports the time each took. Requires DPDK device privileges; `dv_flow_en=2`.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use dataplane_nic_offload::mlx5::{
    AclProto, Arg, Group, Plan, PlannedRule, PlannedTable, RESOURCES, Role, with_installed,
};
use dataplane_nic_offload::program::{DenyRule, Match, Origin, Peering, Prefix, Program};
use dpdk::dev::{DevConfig, RxOffload, TxOffloadConfig};
use dpdk::flow::template::{Complete, Pattern, TemplateAction, TemplateFlows};
use dpdk::flow::{EthMatch, Ipv4Match, Ipv4Prefix, PortRange, Priority, UdpMatch};
use dpdk::mem::{PoolConfig, PoolParams};
use dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dpdk::socket;
use net::vxlan::Vni;
use std::time::Instant;

fn vni(n: u32) -> Vni {
    Vni::new_checked(n).unwrap_or_else(|_| unreachable!())
}

/// A program with one deny of VPC 100, for a generation to hang the probe's groups on.
fn program() -> Program {
    let matches = Match {
        src_vni: vni(100),
        source: Prefix::V4(Ipv4Addr::new(10, 0, 0, 0), 16),
        destination: Prefix::V4(Ipv4Addr::new(10, 1, 0, 0), 16),
        proto: Some(17),
        src_port: None,
        dst_port: None,
        tcp_flags: None,
    };
    Program {
        denies: vec![DenyRule {
            origin: Origin::Acl { v6: false, row: 0 },
            peering: Peering::new(vni(100), vni(200)),
            level: matches.destination.bits(),
            matches,
        }],
        ..Program::default()
    }
}

fn any() -> Pattern<Complete> {
    Pattern::new().eth(EthMatch::default()).complete()
}

fn table(
    group: Group,
    priority: u32,
    pattern: usize,
    actions: usize,
    rule: PlannedRule,
) -> PlannedTable {
    PlannedTable {
        group,
        priority: Priority(priority),
        capacity: 1,
        pattern,
        actions: vec![actions],
        rules: vec![PlannedRule { actions: 0, ..rule }],
    }
}

/// How a rule matches its port.
#[derive(Debug, Clone, Copy)]
enum Kind {
    Exact,
    /// A range, its address its own.
    Range,
    /// Four disjoint ranges per address.
    Range4,
}

/// Rule `i`'s pattern: its address, and its port as `kind` has it.
fn pattern(kind: Kind, i: u32) -> Pattern<Complete> {
    let (addr, port) = match kind {
        Kind::Exact => (i, UdpMatch::default().dst(53)),
        Kind::Range => (
            i,
            UdpMatch::default().dst_range(PortRange::between(1000, 1999)),
        ),
        Kind::Range4 => {
            let lo = 1000 * (1 + u16::try_from(i % 4).unwrap_or(0));
            (
                i / 4,
                UdpMatch::default().dst_range(PortRange::between(lo, lo + 999)),
            )
        }
    };
    let dst = Ipv4Addr::from(0x0a00_0000 | addr);
    Pattern::new()
        .eth(EthMatch::default())
        .ipv4(Ipv4Match::default().dst(Ipv4Prefix::host(dst)))
        .udp(port)
        .complete()
}

/// `plan`, its VPC entered through a dispatch rule jumping to one table of `rules` rules.
fn probe(mut plan: Plan, kind: Kind, rules: u32) -> Plan {
    let vni = vni(100);
    let (dispatch, level) = (Group::AclDispatch(vni), Group::Acl(vni, AclProto::Udp, 0));
    plan.actions.push(vec![TemplateAction::JumpPerRule]);
    let jump = plan.actions.len() - 1;
    plan.actions.push(vec![TemplateAction::Drop]);
    let drop = plan.actions.len() - 1;
    plan.patterns.push(any());
    let any_pattern = plan.patterns.len() - 1;
    plan.patterns.push(pattern(kind, 0));
    let ruled = plan.patterns.len() - 1;
    let role = Role::Acl(vni);
    let entry = table(
        dispatch,
        0,
        any_pattern,
        jump,
        PlannedRule {
            pattern: any(),
            actions: 0,
            args: vec![Arg::Jump(level)],
            role,
        },
    );
    let level = PlannedTable {
        group: level,
        priority: Priority(0),
        capacity: rules,
        pattern: ruled,
        actions: vec![drop],
        rules: (0..rules)
            .map(|i| PlannedRule {
                pattern: pattern(kind, i),
                actions: 0,
                args: Vec::new(),
                role,
            })
            .collect(),
    };
    let vpc = plan.vpcs.get_mut(&vni).unwrap_or_else(|| unreachable!());
    vpc.entry = dispatch;
    vpc.tables.extend([entry, level]);
    plan
}

fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let pci = std::env::args()
        .nth(1)
        .expect("usage: range_insert <pci> [<rules>]");
    let eal = dpdk::eal::init([
        "--in-memory".to_string(),
        "--lcores".to_string(),
        dpdk::eal::main_lcore_arg(),
        "--no-huge".to_string(),
        "-m".to_string(),
        "512".to_string(),
        "-a".to_string(),
        format!("{pci},dv_flow_en=2"),
        "--log-level=pmd.net.mlx5:error".to_string(),
    ]);
    let index = eal
        .dev
        .iter()
        .find(|d| d.name().is_ok_and(|name| name == pci))
        .unwrap()
        .index();
    let mut dev = DevConfig {
        num_rx_queues: 1,
        num_tx_queues: 1,
        num_hairpin_queues: 0,
        tx_offloads: TxOffloadConfig::none(),
        rx_offloads: RxOffload::NONE,
        mtu: None,
        rss: None,
        rx_interrupts: false,
    }
    .apply(eal.claim(index).unwrap())
    .map_err(|e| e.error)
    .unwrap();
    dev.isolate().unwrap();
    dev.configure_templates(&RESOURCES).unwrap();
    let pool = eal
        .mem
        .new_pkt_pool(
            PoolConfig::new(
                "probe".to_string(),
                PoolParams {
                    size: 1023,
                    cache_size: 0,
                    ..Default::default()
                },
            )
            .unwrap(),
        )
        .unwrap();
    dev.new_rx_queue(RxQueueConfig {
        queue_index: RxQueueIndex(0),
        num_descriptors: 256,
        socket_preference: socket::Preference::Dev(index),
        offloads: RxOffload::NONE,
        pool,
    })
    .unwrap();
    dev.new_tx_queue(TxQueueConfig {
        queue_index: TxQueueIndex(0),
        num_descriptors: 256,
        socket_preference: socket::Preference::Dev(index),
        config: (),
    })
    .unwrap();
    let dev = dev.start().map_err(|e| e.error).unwrap();
    let flows = TemplateFlows::new(&dev).unwrap();
    let fate = TemplateAction::Queue(RxQueueIndex(0));
    let program = program();
    // Any VTEP: nothing is sent.
    let vteps: BTreeMap<Vni, Ipv4Addr> = [(vni(100), Ipv4Addr::new(192, 0, 2, 2))].into();

    let rules: u32 = std::env::args()
        .nth(2)
        .and_then(|r| r.parse().ok())
        .unwrap_or(100_000);
    for kind in [Kind::Exact, Kind::Range, Kind::Range4, Kind::Exact] {
        let plan = probe(
            Plan::new(&program, &vteps, &fate, true).unwrap(),
            kind,
            rules,
        );
        let start = Instant::now();
        let result = with_installed(&flows, &plan, |installed| {
            (start.elapsed(), installed.refused().len())
        });
        match result {
            Ok((took, refused)) => println!(
                "{kind:?}: {rules} rules in {took:.2?} ({:.0} rules/s), {refused} refused",
                f64::from(rules) / took.as_secs_f64()
            ),
            Err(e) => println!("{kind:?}: FAILED {e}"),
        }
    }
}
