// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Probe which TAG registers mlx5 lets a plan write and match (slice 1 step 5c-2).
//!
//! A planned ACL keeps planner register `r` in TAG `r + 1` (TAG 0 holds the bank), up to TAG 7. How
//! many TAG registers the PMD offers depends on the device and its metadata mode, so this installs
//! the shapes the lowering emits, with decapsulation (the bank selector writing TAG 0) as the
//! gateway runs:
//!
//! - a dispatch rule writing a set of TAG registers (`TagPerRule` each) and jumping to a level;
//! - a level whose rule matches the same registers (a join), and a catch-all behind it.
//!
//! `tag_probe <pci>` reports, per set, whether the NIC took it, and which rule it refused.
//! Requires DPDK device privileges; uses `dv_flow_en=2`, as the gateway does.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use dataplane_nic_offload::mlx5::{
    AclProto, Arg, Group, Plan, PlannedRule, PlannedTable, RESOURCES, Role, with_installed,
};
use dataplane_nic_offload::program::{DenyRule, Match, Origin, Peering, Prefix, Program};
use dpdk::dev::{DevConfig, RxOffload, TxOffloadConfig};
use dpdk::flow::template::{Complete, Pattern, TemplateAction, TemplateFlows};
use dpdk::flow::{EthMatch, Priority};
use dpdk::mem::{PoolConfig, PoolParams};
use dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dpdk::socket;
use net::vxlan::Vni;

/// The value each register is written and matched with.
const VALUE: u32 = 5;

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

/// `plan`, its VPC entered through a dispatch rule writing `tags`, then a level matching them.
fn probe(mut plan: Plan, tags: &[u8]) -> Plan {
    let vni = vni(100);
    let (dispatch, level) = (Group::AclDispatch(vni), Group::Acl(vni, AclProto::Udp, 0));
    // Actions: write each register and jump; drop, counted; deliver as a pass would (the plan's
    // own delivery, its fourth template).
    let mut write: Vec<TemplateAction> = tags
        .iter()
        .map(|&t| TemplateAction::TagPerRule(t))
        .collect();
    write.push(TemplateAction::JumpPerRule);
    plan.actions.push(write);
    let write = plan.actions.len() - 1;
    plan.actions
        .push(vec![TemplateAction::Count, TemplateAction::Drop]);
    let drop = plan.actions.len() - 1;
    let deliver = 3;
    // Patterns: any; any with the registers.
    let joined = || tags.iter().fold(any(), |p, &t| p.tag(t, VALUE));
    plan.patterns.push(any());
    let any_pattern = plan.patterns.len() - 1;
    plan.patterns.push(joined());
    let joined_pattern = plan.patterns.len() - 1;
    let role = Role::Acl(vni);
    let mut args: Vec<Arg> = tags.iter().map(|_| Arg::Tag(VALUE)).collect();
    args.push(Arg::Jump(level));
    let tables = [
        table(
            dispatch,
            0,
            any_pattern,
            write,
            PlannedRule {
                pattern: any(),
                actions: 0,
                args,
                role,
            },
        ),
        table(
            level,
            0,
            joined_pattern,
            drop,
            PlannedRule {
                pattern: joined(),
                actions: 0,
                args: Vec::new(),
                role,
            },
        ),
        table(
            level,
            1,
            any_pattern,
            deliver,
            PlannedRule {
                pattern: any(),
                actions: 0,
                args: Vec::new(),
                role: Role::CatchAll(level),
            },
        ),
    ];
    let vpc = plan.vpcs.get_mut(&vni).unwrap_or_else(|| unreachable!());
    vpc.entry = dispatch;
    vpc.tables.extend(tables);
    plan
}

fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let pci = std::env::args().nth(1).expect("usage: tag_probe <pci>");
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

    let singles = (1..=11u8).map(|t| vec![t]);
    let sets = [
        vec![1, 2],
        vec![1, 2, 3],
        (1..=5).collect(),
        (1..=7).collect(),
    ];
    let mut taken = Vec::new();
    for tags in singles.chain(sets) {
        let plan = probe(Plan::new(&program, &vteps, &fate, true).unwrap(), &tags);
        let refusals = |installed: &dataplane_nic_offload::mlx5::Installed<'_, '_>| {
            installed
                .refused()
                .iter()
                .map(|(role, why)| (*role, why.to_string()))
                .collect::<Vec<_>>()
        };
        match with_installed(&flows, &plan, refusals) {
            Ok(left_out) if left_out.is_empty() => {
                println!("ok       TAG {tags:?}");
                taken.push(tags);
            }
            Ok(left_out) => {
                let (role, why) = &left_out[0];
                println!(
                    "REFUSED  TAG {tags:?}: {} rule(s) left in software, first {role:?}: {why}",
                    left_out.len()
                );
            }
            Err(e) => println!("REFUSED  TAG {tags:?}: {e}"),
        }
    }
    println!("taken: {taken:?}");
}
