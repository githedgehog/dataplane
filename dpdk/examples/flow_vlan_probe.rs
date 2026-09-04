// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! VLAN push / cross-stage set via the safe `flow` wrapper -- the first shape-changing action.
//!
//! Re-expresses the `l2_probe` VLAN edits through the typed `Flow` builder (no `dpdk-sys`, no
//! `unsafe` in this file), on ingress, reading the result straight out of the rx mbuf:
//!   push : group 1 `eth -> OF_PUSH_VLAN(0x8100) -> queue`            (expect a VLAN tag appears)
//!   set  : group 1 `eth -> OF_PUSH_VLAN -> jump g2`,
//!          group 2 `eth -> OF_SET_VLAN_VID(0x123) -> OF_SET_VLAN_PCP(5) -> queue`
//!          (cross-stage: the pushed tag's fields only exist after the group-1 push, so the set
//!           happens in a later group -- the wrapper expresses this with jump + groups)
//!
//! Group 0 only accepts a jump on this NIC, so every variant starts `eth -> jump group 1`.
//!
//! Inject plain IPv4 from the cabled peer:
//!   sudo python3 send_frames.py <peer-netdev> <this-port-mac> <count>
//!
//! Run as root:  sudo ./flow_vlan_probe 0000:e1:00.1 <push|set> [seconds=10]

use std::time::{Duration, Instant};

use dataplane_dpdk::dev::{DevConfig, RxOffload};
use dataplane_dpdk::eal;
use dataplane_dpdk::flow::{Flow, FlowGroup};
use dataplane_dpdk::mem::{Pool, PoolConfig, PoolParams};
use dataplane_dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dataplane_dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dataplane_dpdk::socket::Preference;
use net::eth::ethtype::EthType;
use net::vlan::{Pcp, Vid};

type Err = Box<dyn std::error::Error>;

// The peer's source MAC -- frames injected by send_frames.py carry it (bytes 6..12). The push does
// not touch the source MAC, so this filter survives the edit.
const PEER_SRC_MAC: [u8; 6] = [0x58, 0xa2, 0xe1, 0x04, 0x31, 0xa8];
const SET_VID: u16 = 0x123;
const SET_PCP: u8 = 5;

fn main() -> Result<(), Err> {
    let mut args = std::env::args().skip(1);
    let bdf = args.next().unwrap_or_else(|| "0000:e1:00.1".to_string());
    let mode = args.next().unwrap_or_else(|| "push".to_string());
    let secs: u64 = args.next().unwrap_or_else(|| "10".into()).parse()?;

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
        PoolConfig::new("vlan_pool", PoolParams::default()).map_err(|e| format!("pool: {e:?}"))?,
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
    println!("port {bdf} index {}; mode={mode}", idx.as_u16());
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

    // group 0 only accepts a jump on this NIC; the real work lives in later groups.
    let _g0 = Flow::ingress(&dev)
        .group(FlowGroup(0))
        .match_eth()
        .jump(FlowGroup(1))
        .create()?;

    // Hold the rule handles for the lifetime of the run (RAII destroy on drop).
    let _rules: Vec<_> = match mode.as_str() {
        "push" => {
            let g1 = Flow::ingress(&dev)
                .group(FlowGroup(1))
                .match_eth()
                .of_push_vlan(EthType::VLAN)
                .queue(RxQueueIndex(0))
                .create()?;
            println!("group1 eth -> PUSH_VLAN(0x8100) + QUEUE0: installed");
            vec![g1]
        }
        "set" => {
            let vid = Vid::new(SET_VID).map_err(|e| format!("vid: {e:?}"))?;
            let pcp = Pcp::new(SET_PCP).map_err(|e| format!("pcp: {e:?}"))?;
            let g1 = Flow::ingress(&dev)
                .group(FlowGroup(1))
                .match_eth()
                .of_push_vlan(EthType::VLAN)
                .jump(FlowGroup(2))
                .create()?;
            let g2 = Flow::ingress(&dev)
                .group(FlowGroup(2))
                .match_eth()
                .of_set_vlan_vid(vid)
                .of_set_vlan_pcp(pcp)
                .queue(RxQueueIndex(0))
                .create()?;
            println!(
                "group1 PUSH_VLAN -> jump g2; group2 SET_VLAN_VID({SET_VID:#x})+PCP({SET_PCP}) + QUEUE0: installed"
            );
            vec![g1, g2]
        }
        "xfer" => {
            // Diagnostic: push is rejected on ingress ("not supported for ingress"); try the
            // transfer (FDB) domain. QUEUE may or may not be a legal transfer fate -- the create()
            // result tells us whether transfer push works and whether we need represented_port.
            let g = Flow::transfer(&dev)
                .match_eth()
                .of_push_vlan(EthType::VLAN)
                .queue(RxQueueIndex(0))
                .create()?;
            println!("transfer eth -> PUSH_VLAN(0x8100) + QUEUE0: installed");
            vec![g]
        }
        other => return Err(format!("unknown mode '{other}' (use push|set|xfer)").into()),
    };

    let mut queues = dev.take_queues().ok_or("device queues already taken")?;
    let mut rxq = queues
        .take_rx(RxQueueIndex(0))
        .ok_or("rx queue 0 missing")?;
    println!("polling {secs}s -- inject plain IPv4 from the peer now...");
    let deadline = Instant::now() + Duration::from_secs(secs);
    let (mut total, mut tagged, mut correct) = (0u64, 0u64, 0u64);
    while Instant::now() < deadline {
        let burst = rxq.receive();
        if burst.is_empty() {
            std::hint::spin_loop();
            continue;
        }
        for m in &burst {
            let f: &[u8] = m.as_ref();
            if f.len() < 18 || f[6..12] != PEER_SRC_MAC {
                continue;
            }
            total += 1;
            if u16::from_be_bytes([f[12], f[13]]) != 0x8100 {
                continue; // no VLAN tag on this frame
            }
            tagged += 1;
            let tci = u16::from_be_bytes([f[14], f[15]]);
            let (pcp, vid) = ((tci >> 13) & 7, tci & 0x0fff);
            let ok = match mode.as_str() {
                "push" => true,
                "set" => vid == SET_VID && pcp as u8 == SET_PCP,
                _ => false,
            };
            if ok {
                correct += 1;
            }
        }
    }

    println!("=== {total} frames: tagged={tagged} correct={correct} ===");
    let pass = total > 0 && tagged == total && correct == total;
    println!(
        "VERDICT: {}",
        if pass {
            "PASS -- OF_PUSH_VLAN (+ cross-stage SET) works through the safe API"
        } else {
            "FAIL / inconclusive"
        }
    );
    Ok(())
}
