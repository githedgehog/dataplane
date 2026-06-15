// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Hairpin baseline, classic path: legacy/NIC mode + smfs steering + classic rte_flow.
//!
//! The HWS/hmfs path didn't loop traffic to the wire (the PMD auto rx->tx hairpin flow isn't inserted
//! when DPDK manages steering). This is the stock NIC config: classic rte_flow `eth -> QUEUE(hairpin)`,
//! tx_explicit=0 so the PMD inserts the rx->tx flow. If the NIC can hairpin at all, frames injected
//! from the peer should loop back out the wire and return to the peer.
//!
//! Run as root:  sudo ./hairpin_classic_probe 0000:e1:00.1 [seconds=12]

use core::ffi::c_void;
use core::ptr::null;
use std::time::{Duration, Instant};

use dataplane_dpdk::dev::{DevConfig, RxOffload};
use dataplane_dpdk::eal;
use dataplane_dpdk::mem::{Pool, PoolConfig, PoolParams};
use dataplane_dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dataplane_dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dataplane_dpdk::socket::Preference;

use dpdk_sys::{
    rte_eth_hairpin_bind, rte_eth_hairpin_conf, rte_eth_promiscuous_enable,
    rte_eth_rx_hairpin_queue_setup, rte_eth_stats, rte_eth_stats_get,
    rte_eth_tx_hairpin_queue_setup, rte_flow_action, rte_flow_action_queue, rte_flow_action_type,
    rte_flow_attr, rte_flow_create, rte_flow_error, rte_flow_item, rte_flow_item_type,
};

type Err = Box<dyn std::error::Error>;

const HAIRPIN_Q: u16 = 1;
const PEER_SRC_MAC: [u8; 6] = [0x58, 0xa2, 0xe1, 0x04, 0x31, 0xa8];

fn main() -> Result<(), Err> {
    let mut args = std::env::args().skip(1);
    let bdf = args.next().unwrap_or_else(|| "0000:e1:00.1".to_string());
    let secs: u64 = args.next().unwrap_or_else(|| "12".into()).parse()?;

    // No dv_flow_en devarg: classic DV flow engine (the default), paired with smfs steering.
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
        PoolConfig::new("hpc_pool", PoolParams::default()).map_err(|e| format!("pool: {e:?}"))?,
    )
    .map_err(|e| format!("pool: {e:?}"))?;
    let cfg = DevConfig {
        num_rx_queues: 2,
        num_tx_queues: 2,
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
    println!("port {bdf} index {port}; classic hairpin baseline (legacy/smfs)");
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

    let mut rx_hp = rte_eth_hairpin_conf::default();
    rx_hp.set_peer_count(1);
    rx_hp.peers[0].port = port;
    rx_hp.peers[0].queue = HAIRPIN_Q;
    let mut tx_hp = rte_eth_hairpin_conf::default();
    tx_hp.set_peer_count(1);
    tx_hp.peers[0].port = port;
    tx_hp.peers[0].queue = HAIRPIN_Q;
    // SAFETY: confs outlive the calls; queue 1 reserved by dev configure.
    if unsafe { rte_eth_rx_hairpin_queue_setup(port, HAIRPIN_Q, 1024, &rx_hp) } < 0 {
        return Err("rx_hairpin_queue_setup failed".into());
    }
    if unsafe { rte_eth_tx_hairpin_queue_setup(port, HAIRPIN_Q, 1024, &tx_hp) } < 0 {
        return Err("tx_hairpin_queue_setup failed".into());
    }
    let dev = dev.start().map_err(|e| format!("dev start: {e}"))?;
    // Accept foreign-dst frames (broadcast/unknown unicast) at the MAC layer so the rig switch can
    // flood our hairpin egress back to the peer.
    // SAFETY: started port.
    unsafe { rte_eth_promiscuous_enable(port) };
    // hairpin.rs relies on auto-bind (manual_bind=0); try an EXPLICIT bind in case that is the gap.
    // SAFETY: started port; same-port bind.
    let brc = unsafe { rte_eth_hairpin_bind(port, port) };
    println!("hairpin q{HAIRPIN_Q} set up; rte_eth_hairpin_bind(self) returned {brc}");

    // Classic rte_flow: ingress eth -> QUEUE(hairpin).
    let mut attr: rte_flow_attr = unsafe { core::mem::zeroed() };
    attr.set_ingress(1);
    attr.group = 0;
    let items = [
        rte_flow_item {
            type_: rte_flow_item_type::RTE_FLOW_ITEM_TYPE_ETH,
            spec: null(),
            last: null(),
            mask: null(),
        },
        rte_flow_item {
            type_: rte_flow_item_type::RTE_FLOW_ITEM_TYPE_END,
            spec: null(),
            last: null(),
            mask: null(),
        },
    ];
    let queue = rte_flow_action_queue { index: HAIRPIN_Q };
    let actions = [
        rte_flow_action {
            type_: rte_flow_action_type::RTE_FLOW_ACTION_TYPE_QUEUE,
            conf: core::ptr::from_ref(&queue).cast::<c_void>(),
        },
        rte_flow_action {
            type_: rte_flow_action_type::RTE_FLOW_ACTION_TYPE_END,
            conf: null(),
        },
    ];
    let mut err: rte_flow_error = unsafe { core::mem::zeroed() };
    // SAFETY: END-terminated arrays; conf/items outlive the call; the PMD copies before returning.
    let flow = unsafe { rte_flow_create(port, &attr, items.as_ptr(), actions.as_ptr(), &mut err) };
    if flow.is_null() {
        let msg = if err.message.is_null() {
            "(no message)".to_string()
        } else {
            unsafe { core::ffi::CStr::from_ptr(err.message) }
                .to_string_lossy()
                .into_owned()
        };
        return Err(format!(
            "rte_flow_create (eth->QUEUE hairpin) failed: type {:?}: {msg}",
            err.type_
        )
        .into());
    }
    println!("classic rule installed: eth -> QUEUE(hairpin q{HAIRPIN_Q})");

    let mut sbefore: rte_eth_stats = unsafe { core::mem::zeroed() };
    // SAFETY: started port; out-param.
    unsafe { rte_eth_stats_get(port, &mut sbefore) };
    let rxq = dev
        .rx_queue(RxQueueIndex(0))
        .ok_or("host rx queue 0 missing")?;
    println!("polling {secs}s -- inject from the peer now (watch peer rx_packets)...");
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut host_rx = 0u64;
    while Instant::now() < deadline {
        let burst = rxq.receive();
        if burst.is_empty() {
            std::hint::spin_loop();
            continue;
        }
        for m in &burst {
            let f: &[u8] = m.as_ref();
            if f.len() >= 12 && f[6..12] == PEER_SRC_MAC {
                host_rx += 1;
            }
        }
    }
    let mut safter: rte_eth_stats = unsafe { core::mem::zeroed() };
    // SAFETY: started port; out-param.
    unsafe { rte_eth_stats_get(port, &mut safter) };
    let din = safter.ipackets.wrapping_sub(sbefore.ipackets);
    let dout = safter.opackets.wrapping_sub(sbefore.opackets);
    let dmiss = safter.imissed.wrapping_sub(sbefore.imissed);
    println!(
        "=== port delta: ipackets={din} opackets={dout} imissed={dmiss} | host rx queue 0 saw {host_rx} ==="
    );
    println!(
        "VERDICT: {}",
        if din > 0 && dout >= din / 2 && host_rx <= din / 20 {
            "PASS -- NIC hairpinned rx->tx in HARDWARE (host rx ~empty, opackets tracked ingress)"
        } else if din > 0 && host_rx > din / 2 {
            "NO HAIRPIN -- traffic landed on the host rx queue"
        } else if din > 0 && dout == 0 {
            "INGRESS but NO EGRESS -- received, not hairpinned out"
        } else {
            "INCONCLUSIVE (check injection / counts)"
        }
    );
    Ok(())
}
