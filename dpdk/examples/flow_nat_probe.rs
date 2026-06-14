// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Stateless-NAT rewrite via the safe `flow` wrapper -- exercises field matching + set actions.
//!
//! Installs (with no `dpdk-sys`, no `unsafe` in this file): group 0 `eth -> jump group 1`; group 1
//! `eth / ipv4(dst=10.0.0.2) / udp(dst=1000) -> set_ipv4_dst(10.9.9.9) / set_tp_dst(4321) / queue 0`.
//! It then injects IPv4/UDP to 10.0.0.2:1000, and confirms the delivered packets were rewritten to
//! 10.9.9.9:4321 with the IPv4 and UDP checksums fixed by the NIC -- proving per-field matching and
//! the SET_IPV4_DST/SET_TP_DST actions work through the wrapper.
//!
//! Inject from the cabled peer (send_frames.py defaults to dst 10.0.0.2:1000):
//!   sudo python3 send_frames.py <peer-netdev> <this-port-mac> <count>
//!
//! Run as root:  sudo ./flow_nat_probe 0000:e1:00.1 [seconds=10]

use core::net::Ipv4Addr;
use std::time::{Duration, Instant};

use dataplane_dpdk::dev::{DevConfig, RxOffload};
use dataplane_dpdk::eal;
use dataplane_dpdk::flow::{Flow, FlowGroup, Ipv4Match, Ipv4Prefix, UdpMatch};
use dataplane_dpdk::mem::{Pool, PoolConfig, PoolParams};
use dataplane_dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dataplane_dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dataplane_dpdk::socket::Preference;

type Err = Box<dyn std::error::Error>;

const ORIG_DST: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const ORIG_DPORT: u16 = 1000;
const NEW_DST: Ipv4Addr = Ipv4Addr::new(10, 9, 9, 9);
const NEW_DPORT: u16 = 4321;

fn fold(mut s: u32) -> u16 {
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    s as u16
}

fn ip_cksum_ok(hdr: &[u8]) -> bool {
    let mut s = 0u32;
    let mut i = 0;
    while i + 1 < 20 {
        s += u32::from(u16::from_be_bytes([hdr[i], hdr[i + 1]]));
        i += 2;
    }
    fold(s) == 0xffff
}

fn udp_cksum_ok(frame: &[u8]) -> bool {
    let udp_len = u16::from_be_bytes([frame[38], frame[39]]) as usize;
    let end = 34 + udp_len;
    if end > frame.len() {
        return false;
    }
    let mut s = 0u32;
    for c in [&frame[26..30], &frame[30..34]] {
        s += u32::from(u16::from_be_bytes([c[0], c[1]]));
        s += u32::from(u16::from_be_bytes([c[2], c[3]]));
    }
    s += 17 + udp_len as u32;
    let seg = &frame[34..end];
    let mut i = 0;
    while i + 1 < seg.len() {
        s += u32::from(u16::from_be_bytes([seg[i], seg[i + 1]]));
        i += 2;
    }
    if seg.len() % 2 == 1 {
        s += u32::from(seg[seg.len() - 1]) << 8;
    }
    fold(s) == 0xffff
}

fn main() -> Result<(), Err> {
    let mut args = std::env::args().skip(1);
    let bdf = args.next().unwrap_or_else(|| "0000:e1:00.1".to_string());
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
        PoolConfig::new("nat_pool", PoolParams::default()).map_err(|e| format!("pool: {e:?}"))?,
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
        "port {bdf} index {}; installing NAT rewrite via the safe flow API",
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

    let _jump = Flow::ingress(&dev)
        .group(FlowGroup(0))
        .match_eth()
        .jump(FlowGroup(1))
        .create()?;
    let _nat = Flow::ingress(&dev)
        .group(FlowGroup(1))
        .match_eth()
        .match_ipv4(Ipv4Match::default().dst(Ipv4Prefix::host(ORIG_DST)))
        .match_udp(UdpMatch::default().dst(ORIG_DPORT))
        .set_ipv4_dst(NEW_DST)
        .set_tp_dst(NEW_DPORT)
        .queue(RxQueueIndex(0))
        .create()?;
    println!(
        "rule: ipv4(dst={ORIG_DST})/udp(dst={ORIG_DPORT}) -> set dst={NEW_DST}:{NEW_DPORT} installed"
    );

    let rxq = dev.rx_queue(RxQueueIndex(0)).ok_or("rx queue 0 missing")?;
    println!("polling {secs}s -- inject IPv4/UDP to {ORIG_DST}:{ORIG_DPORT} now...");
    let deadline = Instant::now() + Duration::from_secs(secs);
    let (mut total, mut rewritten, mut ip_ok, mut udp_ok) = (0u64, 0u64, 0u64, 0u64);
    while Instant::now() < deadline {
        let burst = rxq.receive();
        if burst.is_empty() {
            std::hint::spin_loop();
            continue;
        }
        for m in &burst {
            let f: &[u8] = m.as_ref();
            if f.len() < 42
                || f[6..12] != [0x58, 0xa2, 0xe1, 0x04, 0x31, 0xa8]
                || f[12..14] != [0x08, 0x00]
            {
                continue;
            }
            total += 1;
            let dst_ok = f[30..34] == NEW_DST.octets();
            let port_ok = u16::from_be_bytes([f[36], f[37]]) == NEW_DPORT;
            if dst_ok && port_ok {
                rewritten += 1;
            }
            if ip_cksum_ok(&f[14..34]) {
                ip_ok += 1;
            }
            if udp_cksum_ok(f) {
                udp_ok += 1;
            }
        }
    }

    println!(
        "=== {total} frames: rewritten={rewritten} ip_cksum_ok={ip_ok} udp_cksum_ok={udp_ok} ==="
    );
    let pass = total > 0 && rewritten == total && ip_ok == total && udp_ok == total;
    println!(
        "VERDICT: {}",
        if pass {
            "PASS -- field match + SET_IPV4_DST/SET_TP_DST work through the safe API (checksums fixed)"
        } else {
            "FAIL / inconclusive"
        }
    );
    Ok(())
}
