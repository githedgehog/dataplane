// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Whether an mlx5 port takes each rule shape the lowering produces.
//!
//! `install_probe <pci>` lowers one program per shape onto the port (`dv_flow_en=2`), as rate
//! limits and then as ACL denies in front of them, installs it, removes it again, and reports
//! what the NIC refused (whole plans, or rules it left to software). Needs the privileges DPDK
//! needs for the device (root, or `CAP_NET_RAW` and friends).

use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU64;

use dataplane_nic_offload::mlx5::{Plan, RESOURCES, with_installed};
use dataplane_nic_offload::program::{
    DenyRule, Match, Origin, PoliceMeter, PoliceRule, Prefix, Program,
};
use dpdk::dev::{DevConfig, RxOffload, TxOffloadConfig};
use dpdk::flow::template::{TemplateAction, TemplateFlows};
use dpdk::mem::{PoolConfig, PoolParams};
use dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dpdk::socket;
use policer::{Profile, Rate};
use rate_limit::Unit;

fn program(rules: Vec<PoliceRule>) -> Program {
    let rate = Rate::new(NonZeroU64::new(1_000_000).unwrap_or(NonZeroU64::MIN));
    Program {
        meters: vec![PoliceMeter {
            name: "probe".to_string(),
            unit: Unit::Bytes,
            profile: Profile::new(rate, 100_000, None, 0).unwrap_or_else(|_| unreachable!()),
        }],
        rules,
        denies: Vec::new(),
        refused: Vec::new(),
    }
}

/// `program` with every rule an ACL deny as well.
fn with_denies(rules: Vec<PoliceRule>) -> Program {
    let denies = rules
        .iter()
        .enumerate()
        .map(|(row, rule)| DenyRule {
            origin: Origin::Acl { v6: false, row },
            matches: rule.matches.clone(),
        })
        .collect();
    Program {
        denies,
        ..program(rules)
    }
}

fn rule(v6: bool, proto: Option<u8>, dst_port: Option<u16>) -> PoliceRule {
    let (source, destination) = if v6 {
        (
            Prefix::V6(Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 0), 64),
            Prefix::V6(Ipv6Addr::new(0xfd00, 0, 0, 2, 0, 0, 0, 0), 64),
        )
    } else {
        (
            Prefix::V4(Ipv4Addr::new(10, 0, 0, 0), 16),
            Prefix::V4(Ipv4Addr::new(10, 1, 0, 0), 16),
        )
    };
    PoliceRule {
        rule: 0,
        matches: Match {
            src_vni: net::vxlan::Vni::new_checked(100).unwrap_or_else(|_| unreachable!()),
            source,
            destination,
            proto,
            src_port: None,
            dst_port,
        },
        meter: 0,
    }
}

/// `rule` with prefixes of these lengths (IPv6 only) and these ports.
fn v6(src: u8, dst: u8, proto: Option<u8>, ports: (Option<u16>, Option<u16>)) -> PoliceRule {
    let mut rule = rule(true, proto, ports.1);
    rule.matches.source = Prefix::V6(Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 0), src);
    rule.matches.destination = Prefix::V6(Ipv6Addr::new(0xfd00, 0, 0, 2, 0, 0, 0, 0), dst);
    rule.matches.src_port = ports.0;
    rule
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let pci = std::env::args().nth(1).expect("usage: install_probe <pci>");
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

    let mut refused = 0;
    for (name, rules) in [
        ("IPv4, any protocol", vec![rule(false, None, None)]),
        ("IPv4, UDP, unfragmented", vec![rule(false, Some(17), None)]),
        (
            "IPv4, UDP port, unfragmented",
            vec![rule(false, Some(17), Some(53))],
        ),
        ("IPv6, any protocol", vec![rule(true, None, None)]),
        (
            "IPv6, TCP, no fragment header",
            vec![rule(true, Some(6), None)],
        ),
        (
            "IPv6, TCP port, no fragment header",
            vec![rule(true, Some(6), Some(443))],
        ),
        ("IPv4, ICMP", vec![rule(false, Some(1), None)]),
        (
            "IPv6 /128 /128, any protocol",
            vec![v6(128, 128, None, (None, None))],
        ),
        (
            "IPv6 /128 /128, TCP",
            vec![v6(128, 128, Some(6), (None, None))],
        ),
        (
            "IPv6 /64 /64, TCP both ports",
            vec![v6(64, 64, Some(6), (Some(1), Some(2)))],
        ),
        (
            "IPv6 /65 /65, TCP both ports",
            vec![v6(65, 65, Some(6), (Some(1), Some(2)))],
        ),
        (
            "IPv6 /96 /96, TCP both ports",
            vec![v6(96, 96, Some(6), (Some(1), Some(2)))],
        ),
        (
            "IPv6 /105 /125, TCP both ports",
            vec![v6(105, 125, Some(6), (Some(1), Some(2)))],
        ),
        (
            "IPv6 /128 /128, TCP both ports",
            vec![v6(128, 128, Some(6), (Some(1), Some(2)))],
        ),
        (
            "IPv6 /128 /128, TCP one port",
            vec![v6(128, 128, Some(6), (None, Some(2)))],
        ),
        (
            "IPv6 /97 /96, TCP both ports",
            vec![v6(97, 96, Some(6), (Some(1), Some(2)))],
        ),
        (
            "IPv6 /96 /97, TCP both ports",
            vec![v6(96, 97, Some(6), (Some(1), Some(2)))],
        ),
        (
            "IPv6 /97 /97, TCP both ports",
            vec![v6(97, 97, Some(6), (Some(1), Some(2)))],
        ),
        (
            "IPv6 /128 /64, TCP both ports",
            vec![v6(128, 64, Some(6), (Some(1), Some(2)))],
        ),
        (
            "IPv6 /128 /96, TCP both ports",
            vec![v6(128, 96, Some(6), (Some(1), Some(2)))],
        ),
        (
            "IPv6 /128 /128, any protocol, VNI",
            vec![v6(128, 128, None, (None, None))],
        ),
        (
            "all of the above",
            [false, true]
                .into_iter()
                .flat_map(|v6| {
                    [
                        rule(v6, None, None),
                        rule(v6, Some(17), None),
                        rule(v6, Some(17), Some(53)),
                    ]
                })
                .collect(),
        ),
    ] {
        // Each shape as a rate limit, then as an ACL deny in front of the same rate limit.
        for (denies, program) in [(false, program(rules.clone())), (true, with_denies(rules))] {
            let name = if denies {
                format!("{name}, as denies too")
            } else {
                name.to_string()
            };
            let plan = Plan::new(&program, &fate).unwrap();
            match with_installed(&flows, &plan, |installed| installed.refused().to_vec()) {
                Ok(left_out) if left_out.is_empty() => println!("ok       {name}"),
                Ok(left_out) => {
                    refused += 1;
                    let (role, why) = &left_out[0];
                    println!(
                        "REFUSED  {name}: {} rule(s) left in software, {role:?}: {why}",
                        left_out.len()
                    );
                }
                Err(e) => {
                    refused += 1;
                    println!("REFUSED  {name}: {e}");
                }
            }
        }
    }
    std::process::exit(i32::from(refused > 0));
}
