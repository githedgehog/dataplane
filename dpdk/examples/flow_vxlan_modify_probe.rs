// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! VXLAN VNI -> `META` via the safe `flow` wrapper -- the `MODIFY_FIELD` `set_meta` typed setter.
//!
//! Installs: group 0 `eth -> jump group 1`; group 1
//! `eth / ipv4 / udp(4789) / vxlan(vni=999) -> set_meta(999) / queue 0`. mlx5 rejects a `MODIFY_FIELD`
//! that reads or writes `VXLAN_VNI`, so the matched VNI reaches software as a per-VNI immediate stamp:
//! the delivered frames carry `META = 999` (read via `Mbuf::rx_meta`). META delivery additionally
//! needs the device-level dynfield registration + `dv_xmeta_en=4`.
//!
//! On the load gen, send VXLAN traffic on VNI 999 (outer IPv4).
//! Run as root:  sudo ./flow_vxlan_modify_probe 0000:e1:00.1 [seconds=20]

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use dataplane_dpdk::dev::{DevConfig, RxOffload};
use dataplane_dpdk::eal;
use dataplane_dpdk::flow::{Flow, FlowGroup, Ipv4Match, UdpMatch, VxlanMatch};
use dataplane_dpdk::mem::{Pool, PoolConfig, PoolParams};
use dataplane_dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dataplane_dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dataplane_dpdk::socket::Preference;
use dpdk_sys::{
    rte_eth_allmulticast_enable, rte_eth_promiscuous_enable, rte_flow_dynf_metadata_register,
};
use net::vxlan::Vni;

type Err = Box<dyn std::error::Error>;

const ORIG_VNI: u32 = 999;
const VXLAN_PORT: u16 = 4789;

fn main() -> Result<(), Err> {
    let mut args = std::env::args().skip(1);
    let bdf = args.next().unwrap_or_else(|| "0000:e1:00.1".to_string());
    let secs: u64 = args.next().unwrap_or_else(|| "20".into()).parse()?;
    let orig = Vni::new_checked(ORIG_VNI).map_err(|e| format!("vni: {e:?}"))?;

    let devarg = format!("{bdf},dv_xmeta_en=4");
    let eal = eal::init([
        "-a",
        devarg.as_str(),
        "-n",
        "4",
        "--in-memory",
        "--iova-mode=va",
        "-l",
        "0-1",
        "--no-telemetry",
    ]);
    // META delivery to the mbuf needs the metadata dynfield registered (device-level, separate from
    // the flow rule). SAFETY: FFI; installs the global offs/mask Mbuf::rx_meta() reads.
    if unsafe { rte_flow_dynf_metadata_register() } < 0 {
        return Err("rte_flow_dynf_metadata_register failed".into());
    }
    let info = eal.dev.iter().next().ok_or("no DPDK port probed")?;
    let pool = Pool::new_pkt_pool(
        PoolConfig::new("vxm_pool", PoolParams::default()).map_err(|e| format!("pool: {e:?}"))?,
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
    println!("port {bdf} index {}; VXLAN copy vni->meta", idx.as_u16());
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
        .set_meta(ORIG_VNI)
        .queue(RxQueueIndex(0))
        .create()?;
    println!("rule: vxlan(vni={ORIG_VNI}) -> set_meta({ORIG_VNI}) / queue 0 installed");

    let rxq = dev.rx_queue(RxQueueIndex(0)).ok_or("rx queue 0 missing")?;
    println!("polling {secs}s -- send VXLAN vni {ORIG_VNI} traffic from the load gen now...");
    let deadline = Instant::now() + Duration::from_secs(secs);
    let (mut total, mut meta_ok) = (0u64, 0u64);
    let mut meta_values = BTreeSet::new();
    while Instant::now() < deadline {
        let burst = rxq.receive();
        if burst.is_empty() {
            std::hint::spin_loop();
            continue;
        }
        for m in &burst {
            total += 1;
            if let Some(v) = m.rx_meta() {
                meta_values.insert(v);
                if v == ORIG_VNI {
                    meta_ok += 1;
                }
            }
        }
    }

    println!(
        "=== delivered={total}: META=={ORIG_VNI} on {meta_ok}; META values seen={meta_values:#x?} ==="
    );
    println!(
        "VERDICT: copy vxlan vni -> meta {}",
        if total > 0 && meta_ok == total {
            "PASS"
        } else {
            "FAIL / check the META value/byte-order above"
        }
    );
    Ok(())
}
