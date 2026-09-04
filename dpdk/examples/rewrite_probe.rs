// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Header-rewrite + checksum probe (NAT-offload viability).
//!
//! Rewrites the IPv4 dst address and/or the L4 dst port of ingress packets with rte_flow
//! `SET_IPV4_DST` / `SET_TP_DST`, then checks whether the NIC fixed the checksums -- or whether a
//! separate checksum action would be needed.  Modifying the dst IP invalidates *both* the IPv4
//! header checksum and the L4 checksum (the UDP/TCP pseudo-header covers the IPs); modifying the
//! port invalidates the L4 checksum.  We verify two independent ways: recompute the checksums in
//! software over the delivered bytes (ground truth), and read the NIC's own RX-checksum `ol_flags`.
//!
//! Inject IPv4/UDP with valid checksums (dst 10.0.0.2:1000):
//!   sudo python3 send_frames.py <peer-netdev> <this-port-mac> <count>
//!
//! Run as root:  sudo ./rewrite_probe 0000:e1:00.1 [ip|port|both=both] [seconds=10]

use std::time::{Duration, Instant};

use dataplane_dpdk::dev::{DevConfig, RxOffload};
use dataplane_dpdk::eal;
use dataplane_dpdk::mem::{PoolConfig, PoolParams};
use dataplane_dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dataplane_dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dataplane_dpdk::socket::Preference;

use dpdk_sys::{
    RTE_MBUF_F_RX_IP_CKSUM_GOOD, RTE_MBUF_F_RX_IP_CKSUM_MASK, RTE_MBUF_F_RX_L4_CKSUM_GOOD,
    RTE_MBUF_F_RX_L4_CKSUM_MASK, rte_flow, rte_flow_action, rte_flow_action_jump,
    rte_flow_action_queue, rte_flow_action_set_ipv4, rte_flow_action_set_tp, rte_flow_action_type,
    rte_flow_attr, rte_flow_create, rte_flow_error, rte_flow_item, rte_flow_item_type,
};

type Err = Box<dyn std::error::Error>;

const NEW_DST: [u8; 4] = [10, 9, 9, 9];
const NEW_DPORT: u16 = 4321;

fn item(type_: rte_flow_item_type::Type) -> rte_flow_item {
    rte_flow_item {
        type_,
        spec: core::ptr::null(),
        last: core::ptr::null(),
        mask: core::ptr::null(),
    }
}
fn action(type_: rte_flow_action_type::Type, conf: *const core::ffi::c_void) -> rte_flow_action {
    rte_flow_action { type_, conf }
}
fn vp<T>(r: &T) -> *const core::ffi::c_void {
    core::ptr::from_ref(r).cast()
}
fn ingress_attr(group: u32) -> rte_flow_attr {
    let mut a = rte_flow_attr::default();
    a.set_ingress(1);
    a.group = group;
    a
}

/// # Safety
/// `items`/`actions` must be `END`-terminated and their pointers must outlive the call.
unsafe fn install(
    port: u16,
    attr: &rte_flow_attr,
    items: &[rte_flow_item],
    actions: &[rte_flow_action],
    label: &str,
) -> Result<*mut rte_flow, Err> {
    let mut err: rte_flow_error = unsafe { core::mem::zeroed() };
    let flow = unsafe { rte_flow_create(port, attr, items.as_ptr(), actions.as_ptr(), &mut err) };
    if flow.is_null() {
        let msg = if err.message.is_null() {
            "(no message)".to_string()
        } else {
            unsafe { core::ffi::CStr::from_ptr(err.message) }
                .to_string_lossy()
                .into_owned()
        };
        return Err(format!(
            "{label}: rte_flow_create failed (error type {:?}): {msg}",
            err.type_
        )
        .into());
    }
    println!("{label}: rule installed");
    Ok(flow)
}

fn fold(mut s: u32) -> u16 {
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    s as u16
}

/// Verify the IPv4 header checksum over the 20-byte header (sum incl. stored cksum == 0xffff).
fn ip_cksum_ok(hdr: &[u8]) -> bool {
    let mut s = 0u32;
    let mut i = 0;
    while i + 1 < 20 {
        s += u32::from(u16::from_be_bytes([hdr[i], hdr[i + 1]]));
        i += 2;
    }
    fold(s) == 0xffff
}

/// Verify the UDP checksum over pseudo-header + UDP segment (sum incl. stored cksum == 0xffff).
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
    s += 17 + udp_len as u32; // proto + udp length (pseudo-header)
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
    let mode = args.next().unwrap_or_else(|| "both".into());
    let secs: u64 = args.next().unwrap_or_else(|| "10".into()).parse()?;
    let (do_ip, do_port) = match mode.as_str() {
        "ip" => (true, false),
        "port" => (false, true),
        "both" => (true, true),
        other => return Err(format!("unknown mode '{other}' (ip|port|both)").into()),
    };

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
            PoolConfig::new("rw_pool", PoolParams::default())
                .map_err(|e| format!("pool: {e:?}"))?,
        )
        .map_err(|e| format!("pool create: {e:?}"))?;
    let cfg = DevConfig {
        num_rx_queues: 1,
        num_tx_queues: 1,
        num_hairpin_queues: 0,
        tx_offloads: None,
        rx_offloads: None, // all supported -> RX IP/L4 cksum validation is reported in ol_flags
        mtu: None,
        rss: None,
    };
    let mut dev = cfg
        .apply(info)
        .map_err(|e| format!("dev configure: {e:?}"))?;
    let idx = dev.info.index();
    let port = idx.as_u16();
    println!(
        "port {bdf} probed as index {port}; rewrite mode={mode} (dst->10.9.9.9, dport->{NEW_DPORT})"
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

    use rte_flow_action_type::{
        RTE_FLOW_ACTION_TYPE_END, RTE_FLOW_ACTION_TYPE_JUMP, RTE_FLOW_ACTION_TYPE_QUEUE,
        RTE_FLOW_ACTION_TYPE_SET_IPV4_DST, RTE_FLOW_ACTION_TYPE_SET_TP_DST,
    };
    use rte_flow_item_type::{
        RTE_FLOW_ITEM_TYPE_END, RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
        RTE_FLOW_ITEM_TYPE_UDP,
    };

    let attr0 = ingress_attr(0);
    let attr1 = ingress_attr(1);
    let jump1 = rte_flow_action_jump { group: 1 };
    let queue = rte_flow_action_queue { index: 0 };
    // rte_be{32,16}_t fields hold big-endian; `.to_be()` produces that on any host.
    let set_ip = rte_flow_action_set_ipv4 {
        ipv4_addr: u32::from_be_bytes(NEW_DST).to_be(),
    };
    let set_tp = rte_flow_action_set_tp {
        port: NEW_DPORT.to_be(),
    };

    let g0_items = [item(RTE_FLOW_ITEM_TYPE_ETH), item(RTE_FLOW_ITEM_TYPE_END)];
    let g0_acts = [
        action(RTE_FLOW_ACTION_TYPE_JUMP, vp(&jump1)),
        action(RTE_FLOW_ACTION_TYPE_END, core::ptr::null()),
    ];
    let g1_items = [
        item(RTE_FLOW_ITEM_TYPE_ETH),
        item(RTE_FLOW_ITEM_TYPE_IPV4),
        item(RTE_FLOW_ITEM_TYPE_UDP),
        item(RTE_FLOW_ITEM_TYPE_END),
    ];
    let mut g1_acts = Vec::new();
    if do_ip {
        g1_acts.push(action(RTE_FLOW_ACTION_TYPE_SET_IPV4_DST, vp(&set_ip)));
    }
    if do_port {
        g1_acts.push(action(RTE_FLOW_ACTION_TYPE_SET_TP_DST, vp(&set_tp)));
    }
    g1_acts.push(action(RTE_FLOW_ACTION_TYPE_QUEUE, vp(&queue)));
    g1_acts.push(action(RTE_FLOW_ACTION_TYPE_END, core::ptr::null()));

    // SAFETY: lists are END-terminated and all spec/conf locals outlive the install calls.
    unsafe {
        install(port, &attr0, &g0_items, &g0_acts, "g0 eth->jump1")?;
        install(
            port,
            &attr1,
            &g1_items,
            &g1_acts,
            "g1 ipv4/udp->rewrite+QUEUE",
        )?;
    }

    let mut queues = dev.take_queues().ok_or("device queues already taken")?;
    let mut rxq = queues
        .take_rx(RxQueueIndex(0))
        .ok_or("rx queue 0 missing")?;
    println!("polling {secs}s -- inject IPv4/UDP now...");
    let deadline = Instant::now() + Duration::from_secs(secs);
    let (mut total, mut dst_ok, mut port_ok, mut ipck_ok, mut udpck_ok) =
        (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut sampled = 0u32;
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
            let dst_hit = f[30..34] == NEW_DST;
            let port_hit = u16::from_be_bytes([f[36], f[37]]) == NEW_DPORT;
            let ipv = ip_cksum_ok(&f[14..34]);
            let udpv = udp_cksum_ok(f);
            if dst_hit {
                dst_ok += 1;
            }
            if port_hit {
                port_ok += 1;
            }
            if ipv {
                ipck_ok += 1;
            }
            if udpv {
                udpck_ok += 1;
            }
            if sampled < 5 {
                let olf = m.ol_flags();
                let ipf = (olf & u64::from(RTE_MBUF_F_RX_IP_CKSUM_MASK))
                    == u64::from(RTE_MBUF_F_RX_IP_CKSUM_GOOD);
                let l4f = (olf & u64::from(RTE_MBUF_F_RX_L4_CKSUM_MASK))
                    == u64::from(RTE_MBUF_F_RX_L4_CKSUM_GOOD);
                println!(
                    "  dst={:?} dport={} | sw: ip_cksum={} udp_cksum={} | nic ol_flags: ip_good={} l4_good={}",
                    &f[30..34],
                    u16::from_be_bytes([f[36], f[37]]),
                    ipv,
                    udpv,
                    ipf,
                    l4f
                );
                sampled += 1;
            }
        }
    }

    println!("=== summary (mode={mode}, {total} frames) ===");
    if do_ip {
        println!("dst rewritten to 10.9.9.9 : {dst_ok}/{total}");
    }
    if do_port {
        println!("dport rewritten to {NEW_DPORT}   : {port_ok}/{total}");
    }
    println!("IPv4 header cksum valid   : {ipck_ok}/{total}");
    println!("UDP   cksum valid         : {udpck_ok}/{total}");
    let rewrote = (!do_ip || dst_ok == total) && (!do_port || port_ok == total);
    let cksum_ok = ipck_ok == total && udpck_ok == total;
    println!(
        "VERDICT: {}",
        if total == 0 {
            "INCONCLUSIVE -- no frames"
        } else if rewrote && cksum_ok {
            "PASS -- NIC fixed checksums after rewrite (no separate cksum action needed)"
        } else if rewrote {
            "REWRITE OK but CHECKSUM STALE -- a checksum-correcting action is required"
        } else {
            "FAIL -- rewrite did not take for all frames"
        }
    );
    Ok(())
}
