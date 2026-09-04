// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! VXLAN decapsulation via the safe `flow` wrapper -- the `VXLAN_DECAP` action.
//!
//! Installs: group 0 `eth -> jump group 1`; group 1
//! `eth / ipv4 / udp(4789) / vxlan(vni=999) -> vxlan_decap / queue 0`. The frames delivered to the
//! host should be the INNER packet (outer eth/IPv4/UDP/VXLAN stripped) -- detected by the absence of
//! the outer signature (ethertype 0x0800 at [12..14] AND UDP dst 4789 at [36..38]).
//!
//! On the load gen, send VXLAN traffic on VNI 999 (outer IPv4).
//! Run as root:  sudo ./flow_vxlan_decap_probe 0000:e1:00.1 [seconds=20]

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use dataplane_dpdk::dev::{DevConfig, RxOffload};
use dataplane_dpdk::eal;
use dataplane_dpdk::flow::{Flow, FlowGroup, Ipv4Match, UdpMatch, VxlanMatch};
use dataplane_dpdk::mem::{PoolConfig, PoolParams};
use dataplane_dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dataplane_dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dataplane_dpdk::socket::Preference;
use dpdk_sys::{rte_eth_allmulticast_enable, rte_eth_promiscuous_enable};
use net::vxlan::Vni;

type Err = Box<dyn std::error::Error>;

const ORIG_VNI: u32 = 999;
const VXLAN_PORT: u16 = 4789;

/// True if the frame still carries the outer VXLAN signature (outer IPv4 + UDP dst 4789).
fn still_encapsulated(f: &[u8]) -> bool {
    f.len() >= 38 && f[12..14] == [0x08, 0x00] && f[36..38] == VXLAN_PORT.to_be_bytes()
}

fn main() -> Result<(), Err> {
    let mut args = std::env::args().skip(1);
    let bdf = args.next().unwrap_or_else(|| "0000:e1:00.1".to_string());
    let secs: u64 = args.next().unwrap_or_else(|| "20".into()).parse()?;
    let orig = Vni::new_checked(ORIG_VNI).map_err(|e| format!("vni: {e:?}"))?;

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
            PoolConfig::new("vxd_pool", PoolParams::default())
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
        "port {bdf} index {}; VXLAN decap (vni={ORIG_VNI})",
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
        .match_ipv4(Ipv4Match::default())
        .match_udp(UdpMatch::default().dst(VXLAN_PORT))
        .match_vxlan(VxlanMatch::default().vni(orig))
        .vxlan_decap()
        .queue(RxQueueIndex(0))
        .create()?;
    println!("rule: vxlan(vni={ORIG_VNI}) -> vxlan_decap / queue 0 installed");

    let mut queues = dev.take_queues().ok_or("device queues already taken")?;
    let mut rxq = queues
        .take_rx(RxQueueIndex(0))
        .ok_or("rx queue 0 missing")?;
    println!("polling {secs}s -- send VXLAN vni {ORIG_VNI} traffic from the load gen now...");
    let deadline = Instant::now() + Duration::from_secs(secs);
    let (mut total, mut encapped) = (0u64, 0u64);
    let mut ethertypes = BTreeSet::new();
    let (mut min_len, mut max_len) = (usize::MAX, 0usize);
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
            min_len = min_len.min(f.len());
            max_len = max_len.max(f.len());
            ethertypes.insert(u16::from_be_bytes([f[12], f[13]]));
            if still_encapsulated(f) {
                encapped += 1;
            }
        }
    }

    let decapped = total - encapped;
    println!(
        "=== delivered={total}: decapped={decapped} still-encapsulated={encapped}; ethertypes={ethertypes:#x?} len={min_len}..={max_len} ==="
    );
    println!(
        "VERDICT: {}",
        if total > 0 && encapped == 0 {
            "PASS -- VXLAN_DECAP stripped the outer headers; host saw the inner frame"
        } else if total > 0 {
            "PARTIAL/FAIL -- some/all frames still carry the outer VXLAN signature"
        } else {
            "inconclusive -- no frames delivered"
        }
    );
    Ok(())
}
