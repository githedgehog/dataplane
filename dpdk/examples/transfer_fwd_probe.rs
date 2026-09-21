// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Transfer/FDB "hairpin": can the eswitch forward a wire packet back out the wire (no host)?
//!
//! In eswitch mode the NIC-domain hairpin egress goes into the FDB, not the uplink (see
//! hairpin_probe). The FDB-native equivalent is a TRANSFER rule whose action is REPRESENTED_PORT --
//! transfer can't QUEUE to a hairpin queue, but it can forward port->port inside the embedded switch.
//! For the PF in switchdev, REPRESENTED_PORT(self) targets the entity it represents (the uplink/wire),
//! so `transfer: eth -> REPRESENTED_PORT(0)` should loop ingress back out the wire with no host bounce.
//!
//! Inject from the cabled peer:  sudo python3 send_frames.py <peer-netdev> <this-port-mac> <count>
//! Run as root:  sudo ./transfer_fwd_probe 0000:e1:00.1 [dst_port=0] [seconds=12]

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
    rte_flow_action, rte_flow_action_ethdev, rte_flow_action_type as at,
    rte_flow_actions_template_attr, rte_flow_actions_template_create, rte_flow_async_create,
    rte_flow_configure, rte_flow_error, rte_flow_item, rte_flow_item_type as it, rte_flow_op_attr,
    rte_flow_op_result, rte_flow_op_status, rte_flow_pattern_template_attr,
    rte_flow_pattern_template_create, rte_flow_port_attr, rte_flow_pull, rte_flow_push,
    rte_flow_queue_attr, rte_flow_table_hash_func, rte_flow_table_insertion_type,
    rte_flow_template_table_attr, rte_flow_template_table_create,
};

type Err = Box<dyn std::error::Error>;

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

fn main() -> Result<(), Err> {
    let mut args = std::env::args().skip(1);
    let bdf = args.next().unwrap_or_else(|| "0000:e1:00.1".to_string());
    let dst_port: u16 = args.next().unwrap_or_else(|| "0".into()).parse()?;
    let secs: u64 = args.next().unwrap_or_else(|| "12".into()).parse()?;

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
    let pool = Pool::new_pkt_pool(
        PoolConfig::new("xfwd_pool", PoolParams::default()).map_err(|e| format!("pool: {e:?}"))?,
    )
    .map_err(|e| format!("pool: {e:?}"))?;
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
    let port = idx.as_u16();
    println!("port {bdf} index {port}; transfer-forward probe -> REPRESENTED_PORT({dst_port})");
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

    let port_attr: rte_flow_port_attr = unsafe { core::mem::zeroed() };
    let queue_attr = rte_flow_queue_attr { size: 256 };
    let mut qa_ptrs = [&queue_attr as *const rte_flow_queue_attr];
    let mut err: rte_flow_error = unsafe { core::mem::zeroed() };
    // SAFETY: one flow queue; attrs outlive the call.
    if unsafe { rte_flow_configure(port, &port_attr, 1, qa_ptrs.as_mut_ptr(), &mut err) } != 0 {
        return Err(format!("rte_flow_configure: {}", err_msg(&err)).into());
    }
    let dev = dev.start().map_err(|e| format!("dev start: {e}"))?;

    let mut op_attr: rte_flow_op_attr = unsafe { core::mem::zeroed() };
    op_attr.set_postpone(1);

    // ---- TRANSFER table, group 0: eth -> REPRESENTED_PORT(dst_port) ----
    let mut pt_attr: rte_flow_pattern_template_attr = unsafe { core::mem::zeroed() };
    pt_attr.set_transfer(1);
    let eth_pat = [
        item(it::RTE_FLOW_ITEM_TYPE_ETH, null(), null()),
        item(it::RTE_FLOW_ITEM_TYPE_END, null(), null()),
    ];
    // SAFETY: END-terminated; attr/items outlive the call.
    let pt =
        unsafe { rte_flow_pattern_template_create(port, &pt_attr, eth_pat.as_ptr(), &mut err) };
    if pt.is_null() {
        return Err(format!("transfer pattern template: {}", err_msg(&err)).into());
    }
    let mut at_attr: rte_flow_actions_template_attr = unsafe { core::mem::zeroed() };
    at_attr.set_transfer(1);
    let rep = rte_flow_action_ethdev { port_id: dst_port };
    let rep_mask = rte_flow_action_ethdev { port_id: u16::MAX };
    let acts = [
        action(at::RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT, vp(&rep)),
        action(at::RTE_FLOW_ACTION_TYPE_END, null()),
    ];
    let acts_mask = [
        action(at::RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT, vp(&rep_mask)),
        action(at::RTE_FLOW_ACTION_TYPE_END, null()),
    ];
    // SAFETY: END-terminated; attr/confs outlive the call.
    let atmpl = unsafe {
        rte_flow_actions_template_create(
            port,
            &at_attr,
            acts.as_ptr(),
            acts_mask.as_ptr(),
            &mut err,
        )
    };
    if atmpl.is_null() {
        return Err(format!(
            "transfer actions template (REPRESENTED_PORT): {}",
            err_msg(&err)
        )
        .into());
    }
    let mut t_attr: rte_flow_template_table_attr = unsafe { core::mem::zeroed() };
    t_attr.flow_attr.set_transfer(1);
    t_attr.flow_attr.group = 0;
    t_attr.nb_flows = 1;
    t_attr.insertion_type = rte_flow_table_insertion_type::RTE_FLOW_TABLE_INSERTION_TYPE_PATTERN;
    t_attr.hash_func = rte_flow_table_hash_func::RTE_FLOW_TABLE_HASH_FUNC_DEFAULT;
    let mut pts = [pt];
    let mut ats = [atmpl];
    // SAFETY: arrays/attr outlive the call; counts match.
    let table = unsafe {
        rte_flow_template_table_create(
            port,
            &t_attr,
            pts.as_mut_ptr(),
            1,
            ats.as_mut_ptr(),
            1,
            &mut err,
        )
    };
    if table.is_null() {
        return Err(format!("transfer table: {}", err_msg(&err)).into());
    }
    // SAFETY: END-terminated; table valid; copied during the call.
    let r = unsafe {
        rte_flow_async_create(
            port,
            0,
            &op_attr,
            table,
            eth_pat.as_ptr(),
            0,
            acts.as_ptr(),
            0,
            null_mut(),
            &mut err,
        )
    };
    if r.is_null() {
        return Err(format!("transfer rule: {}", err_msg(&err)).into());
    }
    flush(port, 1)?;
    println!("transfer rule installed: eth -> REPRESENTED_PORT({dst_port})");

    // host rx should stay empty (the eswitch forwarded, no host bounce). Peer-side rx (measured by
    // the harness) tells us if the frames actually came back out the wire.
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
    println!(
        "=== host rx queue 0 saw {host_rx} matched frames (expect ~0 if eswitch forwarded) ==="
    );
    println!("(decisive signal is the peer's rx_packets delta, measured by the harness)");
    Ok(())
}
