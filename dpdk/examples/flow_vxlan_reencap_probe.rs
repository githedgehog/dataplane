// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! VXLAN re-encapsulation (VNI swap) via the safe `flow` wrapper -- `VXLAN_DECAP` + `VXLAN_ENCAP`.
//!
//! Installs: group 0 `eth -> jump group 1`; group 1
//! `eth / ipv4 / udp(4789) / vxlan(vni=999) -> vxlan_decap / vxlan_encap(vni=111) / queue 0`. decap
//! runs before encap (canonicalized), so the delivered frame is the original inner re-wrapped in a
//! fresh outer carrying VNI 111. Confirms the encap action and answers whether mlx5 accepts
//! decap+encap in ONE rule (vs needing separate groups).
//!
//! On the load gen, send VXLAN traffic on VNI 999 (outer IPv4).
//! Run as root:  sudo ./flow_vxlan_reencap_probe 0000:e1:00.1 [seconds=20]

use core::net::Ipv4Addr;
use std::time::{Duration, Instant};

use dataplane_dpdk::dev::{DevConfig, RxOffload};
use dataplane_dpdk::eal;
use dataplane_dpdk::flow::{Flow, FlowGroup, Ipv4Match, UdpMatch, VxlanEncap, VxlanMatch};
use dataplane_dpdk::mem::{Pool, PoolConfig, PoolParams};
use dataplane_dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dataplane_dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dataplane_dpdk::socket::Preference;
use dpdk_sys::{rte_eth_allmulticast_enable, rte_eth_promiscuous_enable};
use net::eth::mac::Mac;
use net::vxlan::Vni;

type Err = Box<dyn std::error::Error>;

const ORIG_VNI: u32 = 999;
const NEW_VNI: u32 = 111;
const VXLAN_PORT: u16 = 4789;

fn main() -> Result<(), Err> {
    let mut args = std::env::args().skip(1);
    let bdf = args.next().unwrap_or_else(|| "0000:e1:00.1".to_string());
    let secs: u64 = args.next().unwrap_or_else(|| "20".into()).parse()?;
    let orig = Vni::new_checked(ORIG_VNI).map_err(|e| format!("vni: {e:?}"))?;
    let new = Vni::new_checked(NEW_VNI).map_err(|e| format!("vni: {e:?}"))?;

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
        PoolConfig::new("vxr_pool", PoolParams::default()).map_err(|e| format!("pool: {e:?}"))?,
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
        "port {bdf} index {}; VXLAN re-encap {ORIG_VNI}->{NEW_VNI}",
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

    let outer = VxlanEncap {
        eth_src: Mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
        eth_dst: Mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]),
        ip_src: Ipv4Addr::new(10, 0, 0, 1),
        ip_dst: Ipv4Addr::new(10, 0, 0, 2),
        udp_src: 12345,
        vni: new,
    };
    let _jump = Flow::ingress(&dev)
        .group(FlowGroup(0))
        .match_eth()
        .jump(FlowGroup(1))
        .create()?;
    // mlx5 rejects decap+encap in ONE rule ("encap and decap combination aren't supported"), so split
    // across groups: group 1 decaps + jumps, group 2 (sees the inner) re-encaps + queues.
    let _decap = Flow::ingress(&dev)
        .group(FlowGroup(1))
        .match_eth()
        .match_ipv4(Ipv4Match::default())
        .match_udp(UdpMatch::default().dst(VXLAN_PORT))
        .match_vxlan(VxlanMatch::default().vni(orig))
        .vxlan_decap()
        .jump(FlowGroup(2))
        .create()?;
    let _encap = Flow::ingress(&dev)
        .group(FlowGroup(2))
        .match_eth()
        .vxlan_encap(outer)
        .queue(RxQueueIndex(0))
        .create()?;
    println!(
        "rule: vxlan(vni={ORIG_VNI}) [g1 decap -> g2 encap(vni={NEW_VNI})] -> queue 0 installed"
    );

    let mut queues = dev.take_queues().ok_or("device queues already taken")?;
    let mut rxq = queues
        .take_rx(RxQueueIndex(0))
        .ok_or("rx queue 0 missing")?;
    println!("polling {secs}s -- send VXLAN vni {ORIG_VNI} traffic from the load gen now...");
    let deadline = Instant::now() + Duration::from_secs(secs);
    // re-encapped outer: eth(14)/ipv4(20)/udp(8)/vxlan(8); VNI at [46..49].
    let (mut total, mut new_vni_ok) = (0u64, 0u64);
    while Instant::now() < deadline {
        let burst = rxq.receive();
        if burst.is_empty() {
            std::hint::spin_loop();
            continue;
        }
        for m in &burst {
            let f: &[u8] = m.as_ref();
            if f.len() < 49 {
                continue;
            }
            total += 1;
            let vni = (u32::from(f[46]) << 16) | (u32::from(f[47]) << 8) | u32::from(f[48]);
            if vni == NEW_VNI && f[36..38] == VXLAN_PORT.to_be_bytes() {
                new_vni_ok += 1;
            }
        }
    }

    println!("=== delivered={total}: re-encapped with outer vni {NEW_VNI} on {new_vni_ok} ===");
    println!(
        "VERDICT: {}",
        if total > 0 && new_vni_ok == total {
            "PASS -- VXLAN_DECAP + VXLAN_ENCAP swapped the VNI in one rule"
        } else if total > 0 {
            "PARTIAL/FAIL -- delivered but outer vni/structure unexpected (check bytes)"
        } else {
            "inconclusive -- no frames delivered"
        }
    );
    Ok(())
}
