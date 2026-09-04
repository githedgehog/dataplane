// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The `offload_probe` MARK rule, re-expressed through the safe `flow` wrapper.
//!
//! Where `offload_probe` builds the `group0 -> jump -> group1, eth/ipv4 -> MARK + QUEUE` rules with
//! raw `rte_flow` FFI, this installs the identical rules through the typed `Flow` builder -- with no
//! `dpdk-sys` and no `unsafe` in this file -- then receives and confirms the MARK reached software.
//! It is the end-to-end proof that the wrapper produces a working hardware rule.
//!
//! Inject matching IPv4 from the cabled peer while it polls:
//!   sudo python3 send_frames.py <peer-netdev> <this-port-mac> <count>
//!
//! Run as root:  sudo ./flow_api_probe 0000:e1:00.1 [mark_hex=4242] [seconds=8]

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use dataplane_dpdk::dev::{DevConfig, RxOffload};
use dataplane_dpdk::eal;
use dataplane_dpdk::flow::{Flow, FlowGroup, Ipv4Match, Mark};
use dataplane_dpdk::mem::{Pool, PoolConfig, PoolParams};
use dataplane_dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dataplane_dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dataplane_dpdk::socket::Preference;

type Err = Box<dyn std::error::Error>;

fn main() -> Result<(), Err> {
    let mut args = std::env::args().skip(1);
    let bdf = args.next().unwrap_or_else(|| "0000:e1:00.1".to_string());
    let mark_id = u32::from_str_radix(&args.next().unwrap_or_else(|| "4242".into()), 16)?;
    let secs: u64 = args.next().unwrap_or_else(|| "8".into()).parse()?;

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
        PoolConfig::new("flowapi_pool", PoolParams::default())
            .map_err(|e| format!("pool: {e:?}"))?,
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
    let port = idx.as_u16();
    println!("port {bdf} index {port}; installing MARK rule via the safe flow API");
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

    // The whole point: build and install the rules through the safe wrapper -- no raw FFI.
    let _jump = Flow::ingress(&dev)
        .group(FlowGroup(0))
        .match_eth()
        .jump(FlowGroup(1))
        .create()?;
    println!("group0 eth -> jump group1: installed");
    let _mark = Flow::ingress(&dev)
        .group(FlowGroup(1))
        .match_eth()
        .match_ipv4(Ipv4Match::default())
        .mark(Mark(mark_id))
        .queue(RxQueueIndex(0))
        .create()?;
    println!("group1 eth/ipv4 -> MARK 0x{mark_id:x} + QUEUE0: installed");

    let mut queues = dev.take_queues().ok_or("device queues already taken")?;
    let mut rxq = queues
        .take_rx(RxQueueIndex(0))
        .ok_or("rx queue 0 missing")?;
    println!("polling rx queue 0 for {secs}s -- inject IPv4 from the peer now...");
    let deadline = Instant::now() + Duration::from_secs(secs);
    let (mut total, mut marked) = (0u64, 0u64);
    let mut mark_ids = BTreeSet::new();
    while Instant::now() < deadline {
        let burst = rxq.receive();
        if burst.is_empty() {
            std::hint::spin_loop();
            continue;
        }
        for m in &burst {
            let f: &[u8] = m.as_ref();
            if f.len() < 34
                || f[6..12] != [0x58, 0xa2, 0xe1, 0x04, 0x31, 0xa8]
                || f[12..14] != [0x08, 0x00]
            {
                continue;
            }
            total += 1;
            if let Some(id) = m.rx_mark() {
                marked += 1;
                mark_ids.insert(id);
            }
        }
    }

    println!("=== received={total} marked={marked} mark_ids={mark_ids:#x?} ===");
    let pass = marked > 0 && mark_ids.len() == 1 && mark_ids.contains(&mark_id);
    println!(
        "VERDICT: {}",
        if pass {
            "PASS -- the safe flow API installed a working MARK rule"
        } else {
            "FAIL / inconclusive"
        }
    );
    // `_mark` and `_jump` drop here (rte_flow_destroy) before `dev` drops (stop) -- the borrow
    // makes that ordering mandatory.
    Ok(())
}
