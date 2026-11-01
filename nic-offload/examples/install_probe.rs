// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Whether an mlx5 port takes each rule shape the lowering produces.
//!
//! `install_probe <pci>` lowers one program per shape onto the port (`dv_flow_en=2`), installs
//! it, removes it again, and reports what the NIC refused. Needs the privileges DPDK needs for
//! the device (root, or `CAP_NET_RAW` and friends).

use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU64;

use dataplane_nic_offload::mlx5::{Plan, RESOURCES, install};
use dataplane_nic_offload::program::{PoliceMeter, PoliceRule, Prefix, Program};
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
        refused: Vec::new(),
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
        src_vni: net::vxlan::Vni::new_checked(100).unwrap_or_else(|_| unreachable!()),
        source,
        destination,
        proto,
        src_port: None,
        dst_port,
        meter: 0,
    }
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
        let program = program(rules);
        let plan = Plan::new(&program, &fate).unwrap();
        match install(&flows, "probe", &program, &plan, &|| true) {
            Ok(()) => println!("ok       {name}"),
            Err(e) => {
                refused += 1;
                println!("REFUSED  {name}: {e}");
            }
        }
    }
    std::process::exit(i32::from(refused > 0));
}
