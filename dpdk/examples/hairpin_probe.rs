// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Hairpin baseline: can the NIC forward rx->tx internally (no host bounce) on this card/mode?
//!
//! End-to-end offload needs hairpin -- without it every offloaded packet round-trips a host bounce
//! buffer (I/O bound). DPDK docs hint hairpin may be unavailable in eswitch mode; this establishes a
//! baseline in the *current* mode before we explore eswitch-specific options.
//!
//! Setup (raw FFI for the hairpin queues; HWS for steering): host rx/tx on queue 0; a hairpin pair
//! on queue 1 (rx-q1 peered to tx-q1, same port, auto-bind at start); an HWS rule `eth -> QUEUE(1)`
//! steers ingress into the hairpin. Injected frames should be forwarded back out the wire by the NIC
//! -- visible as port opackets climbing while the host rx queue stays ~empty.
//!
//! Inject from the cabled peer:  sudo python3 send_frames.py <peer-netdev> <this-port-mac> <count>
//! Run as root:  sudo ./hairpin_probe 0000:e1:00.1 [seconds=10]

use core::ffi::c_void;
use core::ptr::{null, null_mut};
use std::time::{Duration, Instant};

use dataplane_dpdk::dev::{DevConfig, RxOffload};
use dataplane_dpdk::eal;
use dataplane_dpdk::mem::{Pool, PoolConfig, PoolParams};
use dataplane_dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dataplane_dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dataplane_dpdk::socket::Preference;

use dpdk_sys::{
    rte_eth_dev_hairpin_capability_get, rte_eth_hairpin_cap, rte_eth_hairpin_conf,
    rte_eth_rx_hairpin_queue_setup, rte_eth_stats, rte_eth_stats_get,
    rte_eth_tx_hairpin_queue_setup, rte_flow_action, rte_flow_action_jump, rte_flow_action_queue,
    rte_flow_action_type as at, rte_flow_actions_template_attr, rte_flow_actions_template_create,
    rte_flow_async_create, rte_flow_configure, rte_flow_error, rte_flow_isolate, rte_flow_item,
    rte_flow_item_type as it, rte_flow_op_attr, rte_flow_op_result, rte_flow_op_status,
    rte_flow_pattern_template_attr, rte_flow_pattern_template_create, rte_flow_port_attr,
    rte_flow_pull, rte_flow_push, rte_flow_queue_attr, rte_flow_table_hash_func,
    rte_flow_table_insertion_type, rte_flow_template_table_attr, rte_flow_template_table_create,
};

type Err = Box<dyn std::error::Error>;

const HAIRPIN_Q: u16 = 1; // rx/tx queue index dedicated to the hairpin (host uses 0)
const PEER_SRC_MAC: [u8; 6] = [0x58, 0xa2, 0xe1, 0x04, 0x31, 0xa8];

fn err_msg(e: &rte_flow_error) -> String {
    let msg = if e.message.is_null() {
        "(no message)".to_string()
    } else {
        // SAFETY: non-null message is a static C string owned by the PMD.
        unsafe { core::ffi::CStr::from_ptr(e.message) }
            .to_string_lossy()
            .into_owned()
    };
    format!("type {:?}: {msg}", e.type_)
}

fn item(type_: it::Type, spec: *const c_void, mask: *const c_void) -> rte_flow_item {
    rte_flow_item {
        type_,
        spec,
        last: null(),
        mask,
    }
}

fn action(type_: at::Type, conf: *const c_void) -> rte_flow_action {
    rte_flow_action { type_, conf }
}

fn vp<T>(r: &T) -> *const c_void {
    core::ptr::from_ref(r).cast()
}

fn flush(port: u16, count: u32) -> Result<(), Err> {
    let mut err: rte_flow_error = unsafe { core::mem::zeroed() };
    // SAFETY: started port, configured queue 0.
    if unsafe { rte_flow_push(port, 0, &mut err) } != 0 {
        return Err(format!("push: {}", err_msg(&err)).into());
    }
    let mut results: [rte_flow_op_result; 16] = unsafe { core::mem::zeroed() };
    let mut got = 0u32;
    let deadline = Instant::now() + Duration::from_secs(10);
    while got < count {
        // SAFETY: results holds 16; queue 0 valid.
        let n = unsafe { rte_flow_pull(port, 0, results.as_mut_ptr(), 16, &mut err) };
        if n < 0 {
            return Err(format!("pull: {}", err_msg(&err)).into());
        }
        for r in results.iter().take(n as usize) {
            if r.status != rte_flow_op_status::RTE_FLOW_OP_SUCCESS {
                return Err(format!("op failed: status {:?}", r.status).into());
            }
        }
        got += n as u32;
        if n == 0 && Instant::now() > deadline {
            return Err(format!("flush timeout: {got}/{count}").into());
        }
    }
    Ok(())
}

fn stats(port: u16) -> rte_eth_stats {
    let mut s: rte_eth_stats = unsafe { core::mem::zeroed() };
    // SAFETY: valid started port; s is a live out-param.
    unsafe { rte_eth_stats_get(port, &mut s) };
    s
}

fn main() -> Result<(), Err> {
    let mut args = std::env::args().skip(1);
    let bdf = args.next().unwrap_or_else(|| "0000:e1:00.1".to_string());
    let secs: u64 = args.next().unwrap_or_else(|| "10".into()).parse()?;

    let devarg = format!("{bdf},dv_flow_en=2");
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
    let info = eal.dev.iter().next().ok_or("no DPDK port probed")?;
    // Flow isolated mode -- BEFORE configure, per the rte_flow_isolate doc. Removes the PMD's default
    // rules (deliver-to-host / FDB miss handling) so our flow rules + hairpin fully own the datapath.
    let iso_port = info.index().as_u16();
    if std::env::var("HP_NO_ISOLATE").is_err() {
        let mut iso_err: rte_flow_error = unsafe { core::mem::zeroed() };
        let irc = unsafe { rte_flow_isolate(iso_port, 1, &mut iso_err) };
        if irc != 0 {
            return Err(format!("rte_flow_isolate(1) failed: {}", err_msg(&iso_err)).into());
        }
        println!("isolated mode enabled on port {iso_port}");
    } else {
        println!("isolated mode SKIPPED (HP_NO_ISOLATE)");
    }
    let pool = Pool::new_pkt_pool(
        PoolConfig::new("hp_pool", PoolParams::default()).map_err(|e| format!("pool: {e:?}"))?,
    )
    .map_err(|e| format!("pool: {e:?}"))?;
    // 2 rx + 2 tx queues: index 0 = host, index 1 = hairpin (set up via raw FFI below).
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
    println!("port {bdf} index {port}; hairpin baseline (HWS, current mode)");
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

    // Hairpin pair on queue 1: rx-q1 <-> tx-q1, same port. Defaults (manual_bind=0) => auto-bind at
    // dev start; tx_explicit=0 => PMD inserts the default rx->tx flow.
    // Query hairpin caps: does the device advertise locked on-chip (SRAM) memory? (gated by FW
    // HAIRPIN_DATA_BUFFER_LOCK). Set use_locked_device_memory only where it's actually supported.
    let mut hcap: rte_eth_hairpin_cap = unsafe { core::mem::zeroed() };
    // SAFETY: valid probed port; hcap is a live out-param.
    unsafe { rte_eth_dev_hairpin_capability_get(port, &mut hcap) };
    let rx_locked = hcap.rx_cap.locked_device_memory();
    let tx_locked = hcap.tx_cap.locked_device_memory();
    println!(
        "hairpin caps: max_queues={} max_nb_desc={} rx{{locked={} rte={}}} tx{{locked={} rte={}}}",
        hcap.max_nb_queues,
        hcap.max_nb_desc,
        rx_locked,
        hcap.rx_cap.rte_memory(),
        tx_locked,
        hcap.tx_cap.rte_memory(),
    );

    let mut rx_hp = rte_eth_hairpin_conf::default();
    rx_hp.set_peer_count(1);
    rx_hp.peers[0].port = port;
    rx_hp.peers[0].queue = HAIRPIN_Q; // peer = tx queue 1
    rx_hp.set_use_locked_device_memory(rx_locked); // on-chip SRAM where supported
    let mut tx_hp = rte_eth_hairpin_conf::default();
    tx_hp.set_peer_count(1);
    tx_hp.peers[0].port = port;
    tx_hp.peers[0].queue = HAIRPIN_Q; // peer = rx queue 1
    tx_hp.set_use_locked_device_memory(tx_locked); // keep hairpin data on-card where supported
    // SAFETY: confs outlive the calls; queue index 1 was reserved by dev configure.
    let rrc = unsafe { rte_eth_rx_hairpin_queue_setup(port, HAIRPIN_Q, 1024, &rx_hp) };
    if rrc < 0 {
        return Err(format!("rx_hairpin_queue_setup(q{HAIRPIN_Q}) failed: rc={rrc}").into());
    }
    let trc = unsafe { rte_eth_tx_hairpin_queue_setup(port, HAIRPIN_Q, 1024, &tx_hp) };
    if trc < 0 {
        return Err(format!("tx_hairpin_queue_setup(q{HAIRPIN_Q}) failed: rc={trc}").into());
    }
    println!("hairpin queues set up (rx/tx q{HAIRPIN_Q}, same-port)");

    let port_attr: rte_flow_port_attr = unsafe { core::mem::zeroed() };
    let queue_attr = rte_flow_queue_attr { size: 256 };
    let mut qa_ptrs = [&queue_attr as *const rte_flow_queue_attr];
    let mut err: rte_flow_error = unsafe { core::mem::zeroed() };
    // SAFETY: one flow queue; attrs outlive the call.
    if unsafe { rte_flow_configure(port, &port_attr, 1, qa_ptrs.as_mut_ptr(), &mut err) } != 0 {
        return Err(format!("rte_flow_configure: {}", err_msg(&err)).into());
    }
    let dev = dev.start().map_err(|e| format!("dev start: {e}"))?;
    println!("device started (hairpin auto-bound)");

    let mut op_attr: rte_flow_op_attr = unsafe { core::mem::zeroed() };
    op_attr.set_postpone(1);

    // ---- group 0: eth -> jump group 1; group 1: eth -> QUEUE(hairpin) ----
    let mut pt_attr: rte_flow_pattern_template_attr = unsafe { core::mem::zeroed() };
    pt_attr.set_ingress(1);
    let eth_pat = [
        item(it::RTE_FLOW_ITEM_TYPE_ETH, null(), null()),
        item(it::RTE_FLOW_ITEM_TYPE_END, null(), null()),
    ];
    let make_table = |group: u32,
                      acts: &[rte_flow_action],
                      masks: &[rte_flow_action],
                      err: &mut rte_flow_error|
     -> Result<*mut dpdk_sys::rte_flow_template_table, Err> {
        // SAFETY: END-terminated arrays; attrs/items/confs outlive the calls.
        let pt = unsafe { rte_flow_pattern_template_create(port, &pt_attr, eth_pat.as_ptr(), err) };
        if pt.is_null() {
            return Err(format!("pattern template g{group}: {}", err_msg(err)).into());
        }
        let mut at_attr: rte_flow_actions_template_attr = unsafe { core::mem::zeroed() };
        at_attr.set_ingress(1);
        let at = unsafe {
            rte_flow_actions_template_create(port, &at_attr, acts.as_ptr(), masks.as_ptr(), err)
        };
        if at.is_null() {
            return Err(format!("actions template g{group}: {}", err_msg(err)).into());
        }
        let mut t_attr: rte_flow_template_table_attr = unsafe { core::mem::zeroed() };
        t_attr.flow_attr.set_ingress(1);
        t_attr.flow_attr.group = group;
        t_attr.nb_flows = 1;
        t_attr.insertion_type =
            rte_flow_table_insertion_type::RTE_FLOW_TABLE_INSERTION_TYPE_PATTERN;
        t_attr.hash_func = rte_flow_table_hash_func::RTE_FLOW_TABLE_HASH_FUNC_DEFAULT;
        let mut pts = [pt];
        let mut ats = [at];
        let table = unsafe {
            rte_flow_template_table_create(
                port,
                &t_attr,
                pts.as_mut_ptr(),
                1,
                ats.as_mut_ptr(),
                1,
                err,
            )
        };
        if table.is_null() {
            return Err(format!("table g{group}: {}", err_msg(err)).into());
        }
        Ok(table)
    };

    let jump = rte_flow_action_jump { group: 1 };
    let jump_mask = rte_flow_action_jump { group: u32::MAX };
    let g0_acts = [
        action(at::RTE_FLOW_ACTION_TYPE_JUMP, vp(&jump)),
        action(at::RTE_FLOW_ACTION_TYPE_END, null()),
    ];
    let g0_mask = [
        action(at::RTE_FLOW_ACTION_TYPE_JUMP, vp(&jump_mask)),
        action(at::RTE_FLOW_ACTION_TYPE_END, null()),
    ];
    let table0 = make_table(0, &g0_acts, &g0_mask, &mut err)?;
    // SAFETY: END-terminated; table valid; copied during the call.
    let r0 = unsafe {
        rte_flow_async_create(
            port,
            0,
            &op_attr,
            table0,
            eth_pat.as_ptr(),
            0,
            g0_acts.as_ptr(),
            0,
            null_mut(),
            &mut err,
        )
    };
    if r0.is_null() {
        return Err(format!("g0 jump rule: {}", err_msg(&err)).into());
    }
    flush(port, 1)?;

    let queue = rte_flow_action_queue { index: HAIRPIN_Q };
    let queue_mask = rte_flow_action_queue { index: u16::MAX };
    let g1_acts = [
        action(at::RTE_FLOW_ACTION_TYPE_QUEUE, vp(&queue)),
        action(at::RTE_FLOW_ACTION_TYPE_END, null()),
    ];
    let g1_mask = [
        action(at::RTE_FLOW_ACTION_TYPE_QUEUE, vp(&queue_mask)),
        action(at::RTE_FLOW_ACTION_TYPE_END, null()),
    ];
    let table1 = make_table(1, &g1_acts, &g1_mask, &mut err)?;
    // SAFETY: END-terminated; table valid; copied during the call.
    let r1 = unsafe {
        rte_flow_async_create(
            port,
            0,
            &op_attr,
            table1,
            eth_pat.as_ptr(),
            0,
            g1_acts.as_ptr(),
            0,
            null_mut(),
            &mut err,
        )
    };
    if r1.is_null() {
        return Err(format!("g1 hairpin rule: {}", err_msg(&err)).into());
    }
    flush(port, 1)?;
    println!("rule installed: eth -> QUEUE(hairpin q{HAIRPIN_Q})");

    // ---- inject; watch port stats + the host rx queue ----
    let rxq = dev
        .rx_queue(RxQueueIndex(0))
        .ok_or("host rx queue 0 missing")?;
    let before = stats(port);
    println!("polling {secs}s -- inject from the peer now...");
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
    let after = stats(port);
    let din = after.ipackets.wrapping_sub(before.ipackets);
    let dout = after.opackets.wrapping_sub(before.opackets);
    let dmiss = after.imissed.wrapping_sub(before.imissed);

    println!(
        "=== port delta: ipackets={din} opackets={dout} imissed={dmiss} | host rx queue 0 saw {host_rx} ===",
    );
    // Hairpin works iff the NIC transmitted (opackets) what it received, with the host rx ~empty.
    let pass = din > 0 && dout >= din / 2 && host_rx <= din / 20;
    println!(
        "VERDICT: {}",
        if pass {
            "PASS -- NIC forwarded rx->tx internally (hairpin), host rx stayed ~empty"
        } else if dout == 0 && host_rx > 0 {
            "NO HAIRPIN -- traffic landed on the host rx queue instead of egressing"
        } else if din > 0 && dout == 0 {
            "NO HAIRPIN -- ingress seen but nothing egressed (dropped?)"
        } else {
            "INCONCLUSIVE (check injection / counts)"
        }
    );
    Ok(())
}
