// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! IPv6 match via the safe `flow` wrapper -- validates the IPv6 match item + action canonicalization.
//!
//! Installs (no `dpdk-sys` flow calls, no `unsafe` flow code): group 0 `eth -> jump group 1`; group 1
//! `eth / ipv6(proto=58 ICMPv6) -> queue 0 / mark(0x1234)`. The MARK is added AFTER the QUEUE on
//! purpose -- the builder must canonicalize to the mlx5 pipeline order (MARK before the terminal
//! forward) or the HW rejects it. We then read the mbuf MARK back to confirm the rule matched.
//!
//! Drive it with the load gen sending IPv6 (e.g. `ping6 ff02::1%<cx6-port>` -- 1/s is plenty):
//! Run as root:  sudo ./flow_ipv6_probe 0000:e1:00.1 [seconds=20]

use std::time::{Duration, Instant};

use dataplane_dpdk::dev::{DevConfig, RxOffload};
use dataplane_dpdk::eal;
use dataplane_dpdk::flow::{Flow, FlowGroup, Ipv6Match, Mark};
use dataplane_dpdk::mem::{Pool, PoolConfig, PoolParams};
use dataplane_dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dataplane_dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dataplane_dpdk::socket::Preference;
use dpdk_sys::{rte_eth_allmulticast_enable, rte_eth_promiscuous_enable};

type Err = Box<dyn std::error::Error>;

const ICMP6: u8 = 58;
const MARK_ID: u32 = 0x1234;

fn main() -> Result<(), Err> {
    let mut args = std::env::args().skip(1);
    let bdf = args.next().unwrap_or_else(|| "0000:e1:00.1".to_string());
    let secs: u64 = args.next().unwrap_or_else(|| "20".into()).parse()?;

    let eal = eal::init([
        "-a",
        bdf.as_str(),
        "-n",
        "4",
        "--in-memory",
        "--iova-mode=va",
        "-l",
        "0-1",
        "--no-telemetry",
    ]);
    let info = eal.dev.iter().next().ok_or("no DPDK port probed")?;
    let pool = Pool::new_pkt_pool(
        PoolConfig::new("v6_pool", PoolParams::default()).map_err(|e| format!("pool: {e:?}"))?,
    )
    .map_err(|e| format!("pool create: {e:?}"))?;
    let cfg = DevConfig {
        num_rx_queues: 1,
        num_tx_queues: 1,
        num_hairpin_queues: 0,
        tx_offloads: None,
        rx_offloads: None,
        mtu: None,
        rss: None,
    };
    let mut dev = cfg
        .apply(info)
        .map_err(|e| format!("dev configure: {e:?}"))?;
    let idx = dev.info.index();
    println!(
        "port {bdf} index {}; IPv6 match via the safe flow API",
        idx.as_u16()
    );
    dev.new_rx_queue(RxQueueConfig {
        dev: idx,
        queue_index: RxQueueIndex(0),
        num_descriptors: 1024,
        socket_preference: Preference::CurrentThread,
        offloads: RxOffload::from(0u64),
        pool,
    })?;
    dev.new_tx_queue(TxQueueConfig {
        queue_index: TxQueueIndex(0),
        num_descriptors: 1024,
        socket_preference: Preference::CurrentThread,
        config: (),
    })?;
    let dev = dev.start().map_err(|e| format!("dev start: {e}"))?;
    // Accept the IPv6 multicast MAC (33:33:..) at the MAC layer.
    // SAFETY: started port.
    unsafe {
        rte_eth_promiscuous_enable(idx.as_u16());
        rte_eth_allmulticast_enable(idx.as_u16());
    }

    let _jump = Flow::ingress(&dev)
        .group(FlowGroup(0))
        .match_eth()
        .jump(FlowGroup(1))
        .create()?;
    // MARK after QUEUE on purpose -> the builder canonicalizes to a HW-valid order.
    let _rule = Flow::ingress(&dev)
        .group(FlowGroup(1))
        .match_eth()
        .match_ipv6(Ipv6Match::default().proto(ICMP6))
        .queue(RxQueueIndex(0))
        .mark(Mark(MARK_ID))
        .create()?;
    println!("rule: eth / ipv6(proto={ICMP6}) -> queue 0 / mark({MARK_ID:#x}) installed");

    let mut queues = dev.take_queues().ok_or("device queues already taken")?;
    let mut rxq = queues
        .take_rx(RxQueueIndex(0))
        .ok_or("rx queue 0 missing")?;
    println!("polling {secs}s -- have the load gen send IPv6 (e.g. ping6 ff02::1) now...");
    let deadline = Instant::now() + Duration::from_secs(secs);
    let (mut ipv6, mut marked) = (0u64, 0u64);
    while Instant::now() < deadline {
        let burst = rxq.receive();
        if burst.is_empty() {
            std::hint::spin_loop();
            continue;
        }
        for m in &burst {
            let f: &[u8] = m.as_ref();
            if f.len() < 14 || f[12..14] != [0x86, 0xDD] {
                continue;
            }
            ipv6 += 1;
            if m.rx_mark() == Some(MARK_ID) {
                marked += 1;
            }
        }
    }

    println!("=== ipv6 frames delivered={ipv6} carrying mark {MARK_ID:#x}={marked} ===");
    println!(
        "VERDICT: {}",
        if ipv6 > 0 && marked == ipv6 {
            "PASS -- IPv6 match steered the pings to the host queue AND the (canonicalized) MARK survived"
        } else if ipv6 > 0 {
            "PARTIAL -- IPv6 frames arrived but MARK missing (canonicalization/mark issue)"
        } else {
            "FAIL / inconclusive -- no IPv6 delivered (match miss? no traffic?)"
        }
    );
    Ok(())
}
