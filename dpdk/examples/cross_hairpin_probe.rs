// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Cross-port (port-to-port) hairpin SETUP-ACCEPTANCE probe: rx on port A -> tx on port B.
//!
//! Same-port hairpin (rx==tx, wire-to-wire loopback) is confirmed; the real routing data path is
//! port-to-port: receive on uplink A, egress a *different* port B. This proves the PMD/FW ACCEPTS the
//! cross-port config -- cross-port hairpin queue peers, the explicit cross-port `rte_eth_hairpin_bind`,
//! and a steering rule into the hairpin -- without needing traffic (a full traffic test needs an
//! external peer on each port; the f0<->f1 loopback rig can't observe rx-A/tx-B independently).
//!
//! Data path: A(wire in) -> A.rxHairpin -> B.txHairpin -> B(wire out), bound via bind(tx=B, rx=A).
//!
//! Run as root:  sudo ./cross_hairpin_probe 0000:e1:00.0 0000:e1:00.1

use core::ffi::c_void;
use core::ptr::null;

use dataplane_dpdk::dev::{DevConfig, RxOffload};
use dataplane_dpdk::eal;
use dataplane_dpdk::mem::{PoolConfig, PoolParams};
use dataplane_dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dataplane_dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dataplane_dpdk::socket::Preference;

use std::time::{Duration, Instant};

use dpdk_sys::{
    rte_eth_allmulticast_enable, rte_eth_dev_get_name_by_port, rte_eth_dev_hairpin_capability_get,
    rte_eth_hairpin_bind, rte_eth_hairpin_cap, rte_eth_hairpin_conf, rte_eth_promiscuous_enable,
    rte_eth_rx_hairpin_queue_setup, rte_eth_tx_hairpin_queue_setup, rte_eth_xstat,
    rte_eth_xstat_name, rte_eth_xstats_get, rte_eth_xstats_get_names, rte_flow_action,
    rte_flow_action_queue, rte_flow_action_type, rte_flow_attr, rte_flow_create, rte_flow_error,
    rte_flow_item, rte_flow_item_type,
};

type Err = Box<dyn std::error::Error>;

fn port_name(port: u16) -> String {
    let mut buf = [0i8; 64];
    // SAFETY: buf is RTE_ETH_NAME_MAX_LEN-sized; port valid.
    unsafe { rte_eth_dev_get_name_by_port(port, buf.as_mut_ptr()) };
    // SAFETY: PMD writes a NUL-terminated name.
    unsafe { core::ffi::CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

/// Dump non-zero xstats whose name mentions a hairpin/queue counter -- workstation-side evidence that
/// the hairpin queues actually moved packets (esp. tx on the egress port).
fn dump_xstats(port: u16, label: &str) {
    // SAFETY: passing null/0 returns the count.
    let n = unsafe { rte_eth_xstats_get_names(port, core::ptr::null_mut(), 0) };
    if n <= 0 {
        println!("  {label} (port {port}): no xstats");
        return;
    }
    let n = n as usize;
    let mut names: Vec<rte_eth_xstat_name> = vec![unsafe { core::mem::zeroed() }; n];
    let mut vals: Vec<rte_eth_xstat> = vec![unsafe { core::mem::zeroed() }; n];
    // SAFETY: buffers sized to n.
    unsafe {
        rte_eth_xstats_get_names(port, names.as_mut_ptr(), n as u32);
        rte_eth_xstats_get(port, vals.as_mut_ptr(), n as u32);
    }
    println!("  {label} (port {port}) non-zero queue/hairpin xstats:");
    for (nm, v) in names.iter().zip(vals.iter()) {
        // SAFETY: name is a NUL-terminated C string in the fixed buffer.
        let name = unsafe { core::ffi::CStr::from_ptr(nm.name.as_ptr()) }.to_string_lossy();
        if v.value != 0
            && (name.contains('q') || name.contains("hairpin") || name.contains("packets"))
        {
            println!("      {name} = {}", v.value);
        }
    }
}

const HP_Q: u16 = 1; // hairpin queue index on each port (normal traffic uses queue 0)

fn caps(port: u16, label: &str) {
    let mut c: rte_eth_hairpin_cap = unsafe { core::mem::zeroed() };
    // SAFETY: valid probed port; out-param.
    unsafe { rte_eth_dev_hairpin_capability_get(port, &mut c) };
    println!(
        "  {label} (port {port}) caps: max_queues={} max_nb_desc={} max_rx_2_tx={} max_tx_2_rx={}",
        c.max_nb_queues, c.max_nb_desc, c.max_rx_2_tx, c.max_tx_2_rx,
    );
}

fn main() -> Result<(), Err> {
    // A = rx port (where the load gen sends), B = tx/egress port. On this rig the LG sends into f1
    // (e1:00.1) and we egress f0 (e1:00.0) -> CX6 P1.
    let mut args = std::env::args().skip(1);
    let bdf_a = args.next().unwrap_or_else(|| "0000:e1:00.1".to_string());
    let bdf_b = args.next().unwrap_or_else(|| "0000:e1:00.0".to_string());
    let secs: u64 = args.next().unwrap_or_else(|| "30".into()).parse()?;

    // Classic engine (no dv_flow_en); both physical ports of the same ASIC under one EAL.
    let eal = eal::init([
        "-a",
        bdf_a.as_str(),
        "-a",
        bdf_b.as_str(),
        "-n",
        "4",
        "--in-memory",
        "--iova-mode=va",
        "-l",
        "0-1",
        "--no-telemetry",
    ]);
    let infos: Vec<_> = eal.dev.iter().collect();
    if infos.len() < 2 {
        return Err(format!("need 2 DPDK ports, probed {}", infos.len()).into());
    }

    // Configure both ports: 2 rx + 2 tx queues each (queue 0 = normal, queue 1 = hairpin).
    let cfg = DevConfig {
        num_rx_queues: 2,
        num_tx_queues: 2,
        num_hairpin_queues: 0,
        tx_offloads: None,
        rx_offloads: None,
        mtu: None,
        rss: None,
    };
    let mut devs = Vec::new();
    for (n, info) in infos.into_iter().take(2).enumerate() {
        let pool = eal
            .mem
            .new_pkt_pool(
                PoolConfig::new(format!("xhp_pool_{n}"), PoolParams::default())
                    .map_err(|e| format!("pool cfg: {e:?}"))?,
            )
            .map_err(|e| format!("pool: {e:?}"))?;
        let mut dev = cfg
            .apply(info)
            .map_err(|e| format!("configure port {n}: {e:?}"))?;
        let idx = dev.info.index();
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
        devs.push(dev);
    }
    // EAL enumerates by PCI BDF order, NOT -a arg order -- order devs[0]=A(rx, bdf_a) by name match.
    let want_a = bdf_a.split(',').next().unwrap_or(&bdf_a);
    if !port_name(devs[0].info.index().as_u16()).contains(want_a) {
        devs.swap(0, 1);
        println!("(reordered: EAL port order != arg order)");
    }
    let port_a = devs[0].info.index().as_u16();
    let port_b = devs[1].info.index().as_u16();
    println!(
        "probed: port A(rx)={port_a} ({}), port B(tx)={port_b} ({})",
        port_name(port_a),
        port_name(port_b)
    );
    caps(port_a, "A");
    caps(port_b, "B");
    println!("--- cross-port hairpin setup: rx(A) -> tx(B) ---");

    // A: RX hairpin queue, peer = B's tx hairpin queue. manual_bind=1 (cross-port needs explicit bind).
    let mut rx_hp = rte_eth_hairpin_conf::default();
    rx_hp.set_peer_count(1);
    rx_hp.set_manual_bind(1);
    rx_hp.set_tx_explicit(1); // two-port hairpin: explicit tx flow + manual bind (mlx5 requirement)
    rx_hp.peers[0].port = port_b;
    rx_hp.peers[0].queue = HP_Q;
    // SAFETY: conf outlives the call; queue 1 reserved by configure.
    let rc = unsafe { rte_eth_rx_hairpin_queue_setup(port_a, HP_Q, 1024, &rx_hp) };
    println!(
        "  rx_hairpin_queue_setup(A q{HP_Q}, peer=B q{HP_Q}) -> rc={rc} {}",
        ok(rc)
    );
    if rc < 0 {
        return Err("cross-port RX hairpin queue setup REJECTED".into());
    }

    // B: TX hairpin queue, peer = A's rx hairpin queue.
    let mut tx_hp = rte_eth_hairpin_conf::default();
    tx_hp.set_peer_count(1);
    tx_hp.set_manual_bind(1);
    tx_hp.set_tx_explicit(1);
    tx_hp.peers[0].port = port_a;
    tx_hp.peers[0].queue = HP_Q;
    // SAFETY: conf outlives the call; queue 1 reserved by configure.
    let tc = unsafe { rte_eth_tx_hairpin_queue_setup(port_b, HP_Q, 1024, &tx_hp) };
    println!(
        "  tx_hairpin_queue_setup(B q{HP_Q}, peer=A q{HP_Q}) -> rc={tc} {}",
        ok(tc)
    );
    if tc < 0 {
        return Err("cross-port TX hairpin queue setup REJECTED".into());
    }

    // Start both (bind requires started state).
    let started_a = devs
        .remove(0)
        .start()
        .map_err(|e| format!("start A: {e}"))?;
    let started_b = devs
        .remove(0)
        .start()
        .map_err(|e| format!("start B: {e}"))?;
    println!("  both ports started");

    // Explicit cross-port bind: tx_port=B's Tx hairpin -> rx_port=A's Rx hairpin.
    // SAFETY: both ports started; hairpin queues configured.
    let brc = unsafe { rte_eth_hairpin_bind(port_b, port_a) };
    println!(
        "  rte_eth_hairpin_bind(tx=B {port_b}, rx=A {port_a}) -> rc={brc} {}",
        ok(brc)
    );
    if brc != 0 {
        return Err(format!("cross-port hairpin bind REJECTED (rc={brc})").into());
    }

    // Steering rule on A: classic rte_flow eth -> QUEUE(A's rx hairpin). Sends A's wire ingress into
    // the cross-port hairpin (-> B's tx -> B's wire).
    let mut attr: rte_flow_attr = unsafe { core::mem::zeroed() };
    attr.set_ingress(1);
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
    let queue = rte_flow_action_queue { index: HP_Q };
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
    // SAFETY: END-terminated arrays; items/conf outlive the call; PMD copies before returning.
    let flow =
        unsafe { rte_flow_create(port_a, &attr, items.as_ptr(), actions.as_ptr(), &mut err) };
    if flow.is_null() {
        let msg = if err.message.is_null() {
            "(no message)".to_string()
        } else {
            unsafe { core::ffi::CStr::from_ptr(err.message) }
                .to_string_lossy()
                .into_owned()
        };
        return Err(format!("steering rule on A REJECTED: type {:?}: {msg}", err.type_).into());
    }
    println!("  steering rule on A: eth -> QUEUE(hairpin q{HP_Q})  ACCEPTED");

    // Accept multicast/foreign-dst at the MAC layer on both ports (LG sends IPv6 mcast 33:33:..).
    // SAFETY: both ports started.
    unsafe {
        rte_eth_promiscuous_enable(port_a);
        rte_eth_allmulticast_enable(port_a);
        rte_eth_promiscuous_enable(port_b);
        rte_eth_allmulticast_enable(port_b);
    }
    println!(
        "\nCONFIG ACCEPTED end to end. Now watching for {secs}s.\n\
         Traffic path under test: LG -> CX6 P0 -> f1(A,{port_a}) --[HW hairpin]--> f0(B,{port_b}) -> CX6 P1.\n\
         ** On the LOAD GEN, run:  tcpdump -i <CX6 P1> -n icmp6   (expect the ~1/s ff02::1 pings if HW hairpin egresses) **\n\
         Workstation host rx queue 0 on A should stay ~0 (traffic went into the hairpin, not the host)."
    );

    let mut queues_a = started_a
        .take_queues()
        .ok_or("A device queues already taken")?;
    let mut rxq = queues_a
        .take_rx(RxQueueIndex(0))
        .ok_or("A host rx queue 0 missing")?;
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut host_rx = 0u64;
    let mut host_icmp6 = 0u64;
    while Instant::now() < deadline {
        let burst = rxq.receive();
        if burst.is_empty() {
            std::hint::spin_loop();
            continue;
        }
        for m in &burst {
            host_rx += 1;
            let f: &[u8] = m.as_ref();
            if f.len() >= 14 && f[12..14] == [0x86, 0xDD] {
                host_icmp6 += 1;
            }
        }
    }
    println!(
        "=== A host rx queue 0: total={host_rx} ipv6={host_icmp6} (expect ~0 -> traffic took the hairpin, not the host) ==="
    );
    dump_xstats(port_a, "A/rx");
    dump_xstats(port_b, "B/tx");
    let _ = (&started_a, &started_b);
    Ok(())
}

fn ok(rc: i32) -> &'static str {
    if rc == 0 {
        "OK"
    } else if rc < 0 {
        "REJECTED"
    } else {
        "?"
    }
}
