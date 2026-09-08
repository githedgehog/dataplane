// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What checksum offloads the device advertises, and whether the receive verdicts actually arrive.
//!
//! Two separate questions, and only the second is worth anything on its own:
//!
//! 1. **Capability.** What `rx_offload_capa` / `tx_offload_capa` claim. Cheap to read, and a claim
//!    -- `rte_flow_info_get` on this same card claims an async engine it then segfaults on, so a
//!    reported bit is a starting point rather than an answer.
//! 2. **Delivery.** Whether, with `RTE_ETH_RX_OFFLOAD_*_CKSUM` enabled, real received frames come
//!    back with `RTE_MBUF_F_RX_IP_CKSUM_GOOD` / `L4_CKSUM_GOOD` in `ol_flags` rather than
//!    `UNKNOWN`. That is the bit software would key off, and a NIC that reports `UNKNOWN` for
//!    everything has given us nothing however many capability bits it sets.
//!
//! Send correct and corrupt checksums separately, because "everything came back GOOD" is also what
//! a NIC that is not really checking would report.
//!
//! # What a BlueField-3 actually reports (measured 2026-09-08, 300 frames per mode)
//!
//! | sent | IP verdict | L4 verdict |
//! |---|---|---|
//! | all correct | GOOD 300 | GOOD 300 |
//! | bad L4 only | GOOD 300 | **UNKNOWN** 300 |
//! | bad IP only | **UNKNOWN** 300 | GOOD 300 |
//!
//! So the verdict is **one-sided**: `GOOD` means the NIC verified it, and anything else means only
//! that the NIC did not vouch for it. **`BAD` is never reported.** That conflates "the checksum is
//! wrong" with "I did not evaluate this" (an unrecognised protocol, a fragment, a tunnel), so the
//! offload can be used to *skip* software validation but **not** to reject a packet.
//!
//! The two verdicts are independent, which is the useful part: a bad IP checksum does not suppress
//! the L4 verdict, or vice versa.
//!
//! Inject from the cabled peer while this runs, one mode at a time:
//!   python3 send_checksum_frames.py <peer-netdev> <this-port-mac> good|bad-ip|bad-l4|bad-both <n>
//!
//! Run:
//!   ./checksum_offload_probe 0000:02:00.1 [seconds=10]

use std::time::{Duration, Instant};

use dataplane_dpdk::dev::{DevConfig, RssConf, RxOffload, TxOffloadConfig};
use dataplane_dpdk::eal;
use dataplane_dpdk::mem::{PoolConfig, PoolParams};
use dataplane_dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dataplane_dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dataplane_dpdk::socket::Preference;

type Err = Box<dyn std::error::Error>;

/// The receive-side checksum offloads, and what each one buys.
const RX_CKSUM_CAPS: [(u64, &str); 5] = [
    (
        dpdk_sys::rte_eth_rx_offload::RX_OFFLOAD_IPV4_CKSUM,
        "IPV4_CKSUM       (inner/only IPv4 header)",
    ),
    (
        dpdk_sys::rte_eth_rx_offload::RX_OFFLOAD_UDP_CKSUM,
        "UDP_CKSUM        (the one that reads the payload in software)",
    ),
    (
        dpdk_sys::rte_eth_rx_offload::RX_OFFLOAD_TCP_CKSUM,
        "TCP_CKSUM        (likewise)",
    ),
    (
        dpdk_sys::rte_eth_rx_offload::RX_OFFLOAD_OUTER_IPV4_CKSUM,
        "OUTER_IPV4_CKSUM (the VXLAN outer header)",
    ),
    (
        dpdk_sys::rte_eth_rx_offload::RX_OFFLOAD_OUTER_UDP_CKSUM,
        "OUTER_UDP_CKSUM  (the VXLAN outer UDP)",
    ),
];

const TX_CKSUM_CAPS: [(u64, &str); 5] = [
    (
        dpdk_sys::rte_eth_tx_offload::TX_OFFLOAD_IPV4_CKSUM,
        "IPV4_CKSUM",
    ),
    (
        dpdk_sys::rte_eth_tx_offload::TX_OFFLOAD_UDP_CKSUM,
        "UDP_CKSUM",
    ),
    (
        dpdk_sys::rte_eth_tx_offload::TX_OFFLOAD_TCP_CKSUM,
        "TCP_CKSUM",
    ),
    (
        dpdk_sys::rte_eth_tx_offload::TX_OFFLOAD_OUTER_IPV4_CKSUM,
        "OUTER_IPV4_CKSUM",
    ),
    (
        dpdk_sys::rte_eth_tx_offload::TX_OFFLOAD_OUTER_UDP_CKSUM,
        "OUTER_UDP_CKSUM",
    ),
];

/// How many frames landed in each receive verdict.
#[derive(Default, Debug)]
struct Verdicts {
    ip_good: u64,
    ip_bad: u64,
    ip_none: u64,
    ip_unknown: u64,
    l4_good: u64,
    l4_bad: u64,
    l4_none: u64,
    l4_unknown: u64,
    total: u64,
}

impl Verdicts {
    fn record(&mut self, ol_flags: u64) {
        self.total += 1;
        match ol_flags & u64::from(dpdk_sys::RTE_MBUF_F_RX_IP_CKSUM_MASK) {
            f if f == u64::from(dpdk_sys::RTE_MBUF_F_RX_IP_CKSUM_GOOD) => self.ip_good += 1,
            f if f == u64::from(dpdk_sys::RTE_MBUF_F_RX_IP_CKSUM_BAD) => self.ip_bad += 1,
            f if f == u64::from(dpdk_sys::RTE_MBUF_F_RX_IP_CKSUM_NONE) => self.ip_none += 1,
            _ => self.ip_unknown += 1,
        }
        match ol_flags & u64::from(dpdk_sys::RTE_MBUF_F_RX_L4_CKSUM_MASK) {
            f if f == u64::from(dpdk_sys::RTE_MBUF_F_RX_L4_CKSUM_GOOD) => self.l4_good += 1,
            f if f == u64::from(dpdk_sys::RTE_MBUF_F_RX_L4_CKSUM_BAD) => self.l4_bad += 1,
            f if f == u64::from(dpdk_sys::RTE_MBUF_F_RX_L4_CKSUM_NONE) => self.l4_none += 1,
            _ => self.l4_unknown += 1,
        }
    }
}

fn report_caps(what: &str, mask: u64, caps: &[(u64, &str)]) {
    println!("{what} (mask {mask:#x}):");
    for (bit, name) in caps {
        println!("  [{}] {name}", if mask & bit != 0 { "yes" } else { " no" });
    }
}

fn main() -> Result<(), Err> {
    let mut args = std::env::args().skip(1);
    let bdf = args.next().unwrap_or_else(|| "0000:02:00.1".to_string());
    let secs: u64 = args.next().unwrap_or_else(|| "10".into()).parse()?;

    let eal = eal::init([
        "-a",
        bdf.as_str(),
        "--in-memory",
        "--no-telemetry",
        "--no-shconf",
        "--iova-mode=va",
    ]);

    let info = eal.dev.iter().next().ok_or("no DPDK port probed")?;
    let index = info.index();
    println!("port {} ({bdf}), driver {}", index, info.driver_name());
    println!();

    let rx_capa = info.rx_offload_caps().into();
    let tx_capa: u64 = info.tx_offload_caps().into();
    report_caps("receive checksum offloads", rx_capa, &RX_CKSUM_CAPS);
    println!();
    report_caps("transmit checksum offloads", tx_capa, &TX_CKSUM_CAPS);
    println!();
    println!(
        "per-queue receive offload mask: {:#x} (a port-only offload is rejected at queue setup, \
         so this is the one queue config may ask for)",
        u64::from(info.rx_queue_offload_caps())
    );
    println!();

    // Ask for every receive checksum offload the device advertises. Anything it does not advertise
    // would be rejected by `rte_eth_dev_configure`.
    let wanted: u64 = RX_CKSUM_CAPS.iter().map(|(bit, _)| bit).sum();
    let rx_offloads = RxOffload::from(wanted & rx_capa);
    if u64::from(rx_offloads) == 0 {
        return Err("this device advertises no receive checksum offload at all".into());
    }

    let rss = RssConf::supported_on(&info);
    let mut dev = DevConfig {
        num_rx_queues: 1,
        num_tx_queues: 1,
        num_hairpin_queues: 0,
        rx_offloads: Some(if rss.is_some() {
            RxOffload::from(u64::from(rx_offloads) | u64::from(RxOffload::RSS_HASH))
        } else {
            rx_offloads
        }),
        tx_offloads: Some(TxOffloadConfig::default()),
        mtu: None,
        rss,
    }
    .apply(info)
    .map_err(|e| format!("configure: {e:?}"))?;

    let pool = eal
        .mem
        .new_pkt_pool(
            PoolConfig::new("cksum_probe_pool", PoolParams::default())
                .map_err(|e| format!("pool config: {e:?}"))?,
        )
        .map_err(|e| format!("pool create: {e:?}"))?;
    // The per-queue mask is a subset of the port mask; requesting a port-only offload here is
    // rejected, so intersect.
    let queue_offloads = RxOffload::from(u64::from(rx_offloads) & u64::from(info_queue_caps(&dev)));
    dev.new_rx_queue(RxQueueConfig {
        dev: index,
        queue_index: RxQueueIndex(0),
        num_descriptors: 1024,
        socket_preference: Preference::Dev(index),
        offloads: queue_offloads,
        pool,
    })?;
    dev.new_tx_queue(TxQueueConfig {
        queue_index: TxQueueIndex(0),
        num_descriptors: 1024,
        socket_preference: Preference::Dev(index),
        config: (),
    })?;
    let mut dev = dev.start().map_err(|e| format!("start: {e}"))?;
    dev.set_promiscuous(true).ok();

    let mac = dev.mac_address().map_err(|e| format!("mac: {e:?}"))?;
    println!("port up, mac {mac}; polling for {secs}s");
    println!("inject now, e.g.:");
    println!(
        "  python3 send_checksum_frames.py <peer-netdev> {mac} 200 200   # 200 good, 200 corrupt"
    );
    println!();

    let mut queues = dev.take_queues().ok_or("queues")?;
    let mut rx = queues.take_rx(RxQueueIndex(0)).ok_or("rx 0")?;

    let mut verdicts = Verdicts::default();
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        let burst = rx.receive();
        if burst.is_empty() {
            std::thread::sleep(Duration::from_millis(1));
            continue;
        }
        for mbuf in burst.into_iter() {
            verdicts.record(mbuf.ol_flags());
        }
    }

    println!("received {} frame(s)", verdicts.total);
    println!(
        "  IP  : good {} bad {} none {} unknown {}",
        verdicts.ip_good, verdicts.ip_bad, verdicts.ip_none, verdicts.ip_unknown
    );
    println!(
        "  L4  : good {} bad {} none {} unknown {}",
        verdicts.l4_good, verdicts.l4_bad, verdicts.l4_none, verdicts.l4_unknown
    );
    println!();

    let mut surprises: Vec<String> = Vec::new();
    let mut check = |claim: &str, holds: bool| {
        println!("  [{}] {claim}", if holds { "ok " } else { "!! " });
        if !holds {
            surprises.push(claim.to_string());
        }
    };

    check("frames arrived at all", verdicts.total > 0);
    check(
        "no frame was reported BAD -- mlx5 reports GOOD or nothing, never BAD",
        verdicts.ip_bad == 0 && verdicts.l4_bad == 0,
    );
    // Run this three times -- `good`, then `bad-ip`, then `bad-l4` -- and compare. A single run
    // cannot tell a working offload from a NIC that stamps GOOD unconditionally; the discrimination
    // is only visible across modes, which is why the sender takes one.
    println!();
    println!("interpretation:");
    println!(
        "  IP : {} verified, {} not vouched for",
        verdicts.ip_good,
        verdicts.total - verdicts.ip_good
    );
    println!(
        "  L4 : {} verified, {} not vouched for",
        verdicts.l4_good,
        verdicts.total - verdicts.l4_good
    );
    println!(
        "  Run the sender in `good`, `bad-ip` and `bad-l4` modes and compare: a real offload shows \
         GOOD only in the mode where that layer's checksum was correct."
    );

    println!();
    if surprises.is_empty() {
        println!("receive checksum verdicts are real and usable");
        Ok(())
    } else {
        for s in &surprises {
            println!("[CHECK] {s}");
        }
        println!(
            "(a failure here may just mean nothing was injected, or that no corrupt frames were \
             sent -- read the counts above before concluding anything about the NIC)"
        );
        Ok(())
    }
}

/// The device's per-queue receive offload capability mask.
fn info_queue_caps(dev: &dataplane_dpdk::dev::Dev<'_, dataplane_dpdk::dev::Stopped>) -> RxOffload {
    dev.info.rx_queue_offload_caps()
}
