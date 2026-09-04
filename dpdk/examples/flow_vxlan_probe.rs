// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! VXLAN (VNI) match via the safe `flow` wrapper -- the Hedgehog-relevant tunnel match.
//!
//! Installs: group 0 `eth -> jump group 1`; group 1 `eth / ip / udp(dst=4789) / vxlan(vni=<arg>) ->
//! queue 0 / mark`. Only VXLAN frames carrying the given VNI reach the MARK, so a delivered+MARKed
//! frame proves the VXLAN item and its VNI sub-field matched (and the eth/ip/udp/vxlan lattice).
//!
//! Outer IP version is selectable (`4`/`6`) since it depends on the tunnel's endpoints.
//! On the load gen, send VXLAN traffic on the matching VNI (e.g. ping over the vxlan netdev).
//! Run as root:  sudo ./flow_vxlan_probe 0000:e1:00.1 [vni=999] [outer_ip=4] [seconds=20]

use std::time::{Duration, Instant};

use dataplane_dpdk::dev::{DevConfig, RxOffload};
use dataplane_dpdk::eal;
use dataplane_dpdk::flow::{Flow, FlowGroup, Ipv4Match, Ipv6Match, Mark, UdpMatch, VxlanMatch};
use dataplane_dpdk::mem::{Pool, PoolConfig, PoolParams};
use dataplane_dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dataplane_dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dataplane_dpdk::socket::Preference;
use dpdk_sys::{rte_eth_allmulticast_enable, rte_eth_promiscuous_enable};
use net::vxlan::Vni;

type Err = Box<dyn std::error::Error>;

const VXLAN_PORT: u16 = 4789;
const MARK_ID: u32 = 0x9990;

fn main() -> Result<(), Err> {
    let mut args = std::env::args().skip(1);
    let bdf = args.next().unwrap_or_else(|| "0000:e1:00.1".to_string());
    let vni_raw: u32 = args.next().unwrap_or_else(|| "999".into()).parse()?;
    let outer: u8 = args.next().unwrap_or_else(|| "4".into()).parse()?;
    let secs: u64 = args.next().unwrap_or_else(|| "20".into()).parse()?;
    let vni = Vni::new_checked(vni_raw).map_err(|e| format!("bad vni {vni_raw}: {e:?}"))?;

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
        PoolConfig::new("vxl_pool", PoolParams::default()).map_err(|e| format!("pool: {e:?}"))?,
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
        "port {bdf} index {}; VXLAN match (vni={vni_raw}, outer ipv{outer}) via the safe flow API",
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
    let udp = UdpMatch::default().dst(VXLAN_PORT);
    let vxlan = VxlanMatch::default().vni(vni);
    let _rule = if outer == 6 {
        Flow::ingress(&dev)
            .group(FlowGroup(1))
            .match_eth()
            .match_ipv6(Ipv6Match::default())
            .match_udp(udp)
            .match_vxlan(vxlan)
            .queue(RxQueueIndex(0))
            .mark(Mark(MARK_ID))
            .create()?
    } else {
        Flow::ingress(&dev)
            .group(FlowGroup(1))
            .match_eth()
            .match_ipv4(Ipv4Match::default())
            .match_udp(udp)
            .match_vxlan(vxlan)
            .queue(RxQueueIndex(0))
            .mark(Mark(MARK_ID))
            .create()?
    };
    println!(
        "rule: eth / ipv{outer} / udp(dst={VXLAN_PORT}) / vxlan(vni={vni_raw}) -> queue 0 / mark({MARK_ID:#x}) installed"
    );

    let mut queues = dev.take_queues().ok_or("device queues already taken")?;
    let mut rxq = queues
        .take_rx(RxQueueIndex(0))
        .ok_or("rx queue 0 missing")?;
    println!("polling {secs}s -- send VXLAN traffic on vni {vni_raw} from the load gen now...");
    let deadline = Instant::now() + Duration::from_secs(secs);
    let (mut total, mut marked) = (0u64, 0u64);
    while Instant::now() < deadline {
        let burst = rxq.receive();
        if burst.is_empty() {
            std::hint::spin_loop();
            continue;
        }
        for m in &burst {
            total += 1;
            if m.rx_mark() == Some(MARK_ID) {
                marked += 1;
            }
        }
    }

    println!("=== delivered total={total} marked={marked} (vni {vni_raw}) ===");
    println!(
        "VERDICT: {}",
        if marked > 0 && marked == total {
            "PASS -- VXLAN(vni) match steered the tunnel frames to the host queue with the MARK"
        } else if marked > 0 {
            "PARTIAL -- some matched; other traffic also on the queue"
        } else {
            "FAIL / inconclusive -- no VXLAN(vni) match (wrong outer ip/port/vni? no traffic?)"
        }
    );
    Ok(())
}
