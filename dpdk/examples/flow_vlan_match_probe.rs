// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! VLAN match via the safe `flow` wrapper -- validates the VLAN match item + the `Within` lattice.
//!
//! Installs: group 0 `eth -> jump group 1`; group 1 `eth / vlan(vid=<arg>) -> queue 0 / mark`. Only
//! 802.1Q frames carrying the given VID reach group 1's match, so a delivered+MARKed frame proves the
//! VLAN item (and its VID sub-field) matched. No Rx VLAN-strip offload is enabled, so the tag stays in
//! the delivered frame (ethertype 0x8100).
//!
//! On the load gen, send VLAN-tagged traffic with the matching VID (e.g. a VLAN subinterface +
//! `ping6 ff02::1`).
//! Run as root:  sudo ./flow_vlan_match_probe 0000:e1:00.1 [vid=100] [seconds=20]

use std::time::{Duration, Instant};

use dataplane_dpdk::dev::{DevConfig, RxOffload};
use dataplane_dpdk::eal;
use dataplane_dpdk::flow::{Flow, FlowGroup, Mark, VlanMatch};
use dataplane_dpdk::mem::{PoolConfig, PoolParams};
use dataplane_dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dataplane_dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dataplane_dpdk::socket::Preference;
use dpdk_sys::{rte_eth_allmulticast_enable, rte_eth_promiscuous_enable};
use net::vlan::Vid;

type Err = Box<dyn std::error::Error>;

const MARK_ID: u32 = 0x5678;

fn main() -> Result<(), Err> {
    let mut args = std::env::args().skip(1);
    let bdf = args.next().unwrap_or_else(|| "0000:e1:00.1".to_string());
    let vid_raw: u16 = args.next().unwrap_or_else(|| "100".into()).parse()?;
    let secs: u64 = args.next().unwrap_or_else(|| "20".into()).parse()?;
    let vid = Vid::new(vid_raw).map_err(|e| format!("bad vid {vid_raw}: {e:?}"))?;

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
    let pool = eal
        .mem
        .new_pkt_pool(
            PoolConfig::new("vln_pool", PoolParams::default())
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
    println!(
        "port {bdf} index {}; VLAN match (vid={vid_raw}) via the safe flow API",
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
    let _rule = Flow::ingress(&dev)
        .group(FlowGroup(1))
        .match_eth()
        .match_vlan(VlanMatch::default().vid(vid))
        .queue(RxQueueIndex(0))
        .mark(Mark(MARK_ID))
        .create()?;
    println!("rule: eth / vlan(vid={vid_raw}) -> queue 0 / mark({MARK_ID:#x}) installed");

    let mut queues = dev.take_queues().ok_or("device queues already taken")?;
    let mut rxq = queues
        .take_rx(RxQueueIndex(0))
        .ok_or("rx queue 0 missing")?;
    println!(
        "polling {secs}s -- send VLAN-tagged (vid {vid_raw}) traffic from the load gen now..."
    );
    let deadline = Instant::now() + Duration::from_secs(secs);
    let (mut total, mut tagged, mut marked) = (0u64, 0u64, 0u64);
    while Instant::now() < deadline {
        let burst = rxq.receive();
        if burst.is_empty() {
            std::hint::spin_loop();
            continue;
        }
        for m in &burst {
            let f: &[u8] = m.as_ref();
            if f.len() < 14 {
                continue;
            }
            total += 1;
            if f[12..14] == [0x81, 0x00] {
                tagged += 1;
            }
            if m.rx_mark() == Some(MARK_ID) {
                marked += 1;
            }
        }
    }

    println!(
        "=== delivered total={total} vlan-tagged={tagged} marked={marked} (vid {vid_raw}) ==="
    );
    println!(
        "VERDICT: {}",
        if marked > 0 && marked == total {
            "PASS -- VLAN(vid) match steered the tagged frames to the host queue with the MARK"
        } else if marked > 0 {
            "PARTIAL -- some frames matched; check for untagged/other traffic on the queue"
        } else {
            "FAIL / inconclusive -- nothing matched (wrong vid? untagged traffic? no traffic?)"
        }
    );
    Ok(())
}
