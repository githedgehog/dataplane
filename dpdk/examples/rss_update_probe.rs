// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Indirect-action UPDATE probe: one `handle_update` re-steers MANY rules atomically.
//!
//! The other half of the indirect-action design question (after `indirect_probe` showed sharing):
//! update ONE shared handle and watch every referencing rule change behavior, observing the
//! per-packet-consistency window.
//!
//! Setup (raw `rte_flow` HWS FFI): one indirect RSS handle steering to rx queue 0; N group-1 rules
//! (each matching a distinct ipv4 src) all reference it; a group-0 jump feeds them. Inject a steady
//! stream; at the half-way mark, `rte_flow_async_action_handle_update` flips the handle's RSS target
//! to rx queue 1. Expect: before the update all matched frames land on q0, after it on q1 -- a single
//! update changing all N rules.
//!
//! Inject a sustained stream (large count) spanning the run:
//!   sudo python3 send_frames.py <peer-netdev> <this-port-mac> 400000 0800 vary
//! Run as root:  sudo ./rss_update_probe 0000:e1:00.1 [n_rules=256] [seconds=10]

use core::ffi::c_void;
use core::net::Ipv4Addr;
use core::ptr::{null, null_mut};
use std::time::{Duration, Instant};

use dataplane_dpdk::dev::{DevConfig, RxOffload};
use dataplane_dpdk::eal;
use dataplane_dpdk::mem::{Pool, PoolConfig, PoolParams};
use dataplane_dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dataplane_dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dataplane_dpdk::socket::Preference;

use dpdk_sys::{
    rte_eth_hash_function, rte_flow_action, rte_flow_action_jump, rte_flow_action_rss,
    rte_flow_action_type as at, rte_flow_actions_template_attr, rte_flow_actions_template_create,
    rte_flow_async_action_handle_create, rte_flow_async_action_handle_update,
    rte_flow_async_create, rte_flow_configure, rte_flow_error, rte_flow_indir_action_conf,
    rte_flow_item, rte_flow_item_ipv4, rte_flow_item_type as it, rte_flow_op_attr,
    rte_flow_op_result, rte_flow_op_status, rte_flow_pattern_template_attr,
    rte_flow_pattern_template_create, rte_flow_port_attr, rte_flow_pull, rte_flow_push,
    rte_flow_queue_attr, rte_flow_table_hash_func, rte_flow_table_insertion_type,
    rte_flow_template_table_attr, rte_flow_template_table_create,
};

type Err = Box<dyn std::error::Error>;

const QUEUE_SIZE: u32 = 1024;
const BATCH: u32 = 512;

fn err_msg(e: &rte_flow_error) -> String {
    let msg = if e.message.is_null() {
        "(no message)".to_string()
    } else {
        // SAFETY: non-null message points to a static C string owned by the PMD.
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
    let mut results: [rte_flow_op_result; 64] = unsafe { core::mem::zeroed() };
    let mut got = 0u32;
    let deadline = Instant::now() + Duration::from_secs(10);
    while got < count {
        // SAFETY: results holds 64; queue 0 valid.
        let n = unsafe { rte_flow_pull(port, 0, results.as_mut_ptr(), 64, &mut err) };
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

/// Build an RSS action config steering to a single rx queue. `queue` must outlive its use.
fn rss_to(queue: &[u16; 1]) -> rte_flow_action_rss {
    rte_flow_action_rss {
        func: rte_eth_hash_function::RTE_ETH_HASH_FUNCTION_DEFAULT,
        level: 0,
        types: 0, // single queue: hashing is moot, "default" steers to queue[0]
        key_len: 0,
        queue_num: 1,
        key: null(),
        queue: queue.as_ptr(),
    }
}

fn is_ours(f: &[u8]) -> bool {
    f.len() >= 34 && f[12..14] == [0x08, 0x00] && f[26..29] == [10, 0, 0]
}

fn main() -> Result<(), Err> {
    let mut args = std::env::args().skip(1);
    let bdf = args.next().unwrap_or_else(|| "0000:e1:00.1".to_string());
    let n_rules: u32 = args.next().unwrap_or_else(|| "256".into()).parse()?;
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
    let pool0 = Pool::new_pkt_pool(
        PoolConfig::new("rss_pool0", PoolParams::default()).map_err(|e| format!("pool: {e:?}"))?,
    )
    .map_err(|e| format!("pool0: {e:?}"))?;
    let pool1 = Pool::new_pkt_pool(
        PoolConfig::new("rss_pool1", PoolParams::default()).map_err(|e| format!("pool: {e:?}"))?,
    )
    .map_err(|e| format!("pool1: {e:?}"))?;
    let cfg = DevConfig {
        num_rx_queues: 2,
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
    println!("port {bdf} index {port}; RSS-update probe, n_rules={n_rules}");
    for (qi, pool) in [(0u16, pool0), (1u16, pool1)] {
        dev.new_rx_queue(RxQueueConfig {
            dev: idx,
            queue_index: RxQueueIndex(qi),
            num_descriptors: 1024,
            socket_preference: Preference::CurrentThread,
            offloads: RxOffload::from(0u64),
            pool,
        })?;
    }
    dev.new_tx_queue(TxQueueConfig {
        queue_index: TxQueueIndex(0),
        num_descriptors: 1024,
        socket_preference: Preference::CurrentThread,
        config: (),
    })?;

    let port_attr: rte_flow_port_attr = unsafe { core::mem::zeroed() };
    let queue_attr = rte_flow_queue_attr { size: QUEUE_SIZE };
    let mut qa_ptrs = [&queue_attr as *const rte_flow_queue_attr];
    let mut err: rte_flow_error = unsafe { core::mem::zeroed() };
    // SAFETY: one flow queue; attrs outlive the call.
    if unsafe { rte_flow_configure(port, &port_attr, 1, qa_ptrs.as_mut_ptr(), &mut err) } != 0 {
        return Err(format!("rte_flow_configure: {}", err_msg(&err)).into());
    }
    let dev = dev.start().map_err(|e| format!("dev start: {e}"))?;

    let mut op_attr: rte_flow_op_attr = unsafe { core::mem::zeroed() };
    op_attr.set_postpone(1);

    // ---- ONE shared indirect RSS handle, initially -> queue 0 ----
    let q0_arr = [0u16];
    let q1_arr = [1u16];
    let rss0 = rss_to(&q0_arr);
    let rss_action = action(at::RTE_FLOW_ACTION_TYPE_RSS, vp(&rss0));
    let mut indir_conf: rte_flow_indir_action_conf = unsafe { core::mem::zeroed() };
    indir_conf.set_ingress(1);
    // SAFETY: conf/action/queue array outlive the call.
    let handle = unsafe {
        rte_flow_async_action_handle_create(
            port,
            0,
            &op_attr,
            &indir_conf,
            &rss_action,
            null_mut(),
            &mut err,
        )
    };
    if handle.is_null() {
        return Err(format!("indirect RSS handle create: {}", err_msg(&err)).into());
    }
    flush(port, 1)?;
    println!("indirect RSS handle created (-> queue 0)");

    // ---- group 0: eth -> jump group 1 ----
    let mut pt0_attr: rte_flow_pattern_template_attr = unsafe { core::mem::zeroed() };
    pt0_attr.set_ingress(1);
    let g0_pat = [
        item(it::RTE_FLOW_ITEM_TYPE_ETH, null(), null()),
        item(it::RTE_FLOW_ITEM_TYPE_END, null(), null()),
    ];
    // SAFETY: END-terminated; attr/items outlive the call.
    let pt0 =
        unsafe { rte_flow_pattern_template_create(port, &pt0_attr, g0_pat.as_ptr(), &mut err) };
    if pt0.is_null() {
        return Err(format!("g0 pattern template: {}", err_msg(&err)).into());
    }
    let mut at0_attr: rte_flow_actions_template_attr = unsafe { core::mem::zeroed() };
    at0_attr.set_ingress(1);
    let jump = rte_flow_action_jump { group: 1 };
    let jump_mask = rte_flow_action_jump { group: u32::MAX };
    let g0_acts = [
        action(at::RTE_FLOW_ACTION_TYPE_JUMP, vp(&jump)),
        action(at::RTE_FLOW_ACTION_TYPE_END, null()),
    ];
    let g0_acts_mask = [
        action(at::RTE_FLOW_ACTION_TYPE_JUMP, vp(&jump_mask)),
        action(at::RTE_FLOW_ACTION_TYPE_END, null()),
    ];
    // SAFETY: END-terminated; attr/confs outlive the call.
    let at0 = unsafe {
        rte_flow_actions_template_create(
            port,
            &at0_attr,
            g0_acts.as_ptr(),
            g0_acts_mask.as_ptr(),
            &mut err,
        )
    };
    if at0.is_null() {
        return Err(format!("g0 actions template: {}", err_msg(&err)).into());
    }
    let mut t0_attr: rte_flow_template_table_attr = unsafe { core::mem::zeroed() };
    t0_attr.flow_attr.set_ingress(1);
    t0_attr.flow_attr.group = 0;
    t0_attr.nb_flows = 1;
    t0_attr.insertion_type = rte_flow_table_insertion_type::RTE_FLOW_TABLE_INSERTION_TYPE_PATTERN;
    t0_attr.hash_func = rte_flow_table_hash_func::RTE_FLOW_TABLE_HASH_FUNC_DEFAULT;
    let mut pts0 = [pt0];
    let mut ats0 = [at0];
    // SAFETY: arrays/attr outlive the call; counts match.
    let table0 = unsafe {
        rte_flow_template_table_create(
            port,
            &t0_attr,
            pts0.as_mut_ptr(),
            1,
            ats0.as_mut_ptr(),
            1,
            &mut err,
        )
    };
    if table0.is_null() {
        return Err(format!("g0 table: {}", err_msg(&err)).into());
    }
    // SAFETY: END-terminated; table valid; copied during the call.
    let r0 = unsafe {
        rte_flow_async_create(
            port,
            0,
            &op_attr,
            table0,
            g0_pat.as_ptr(),
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

    // ---- group 1: eth / ipv4(src) -> INDIRECT(rss) ----
    let mut pt1_attr: rte_flow_pattern_template_attr = unsafe { core::mem::zeroed() };
    pt1_attr.set_ingress(1);
    let mut ipv4_mask: rte_flow_item_ipv4 = unsafe { core::mem::zeroed() };
    ipv4_mask.hdr.src_addr = u32::MAX;
    let g1_pat_tmpl = [
        item(it::RTE_FLOW_ITEM_TYPE_ETH, null(), null()),
        item(it::RTE_FLOW_ITEM_TYPE_IPV4, null(), vp(&ipv4_mask)),
        item(it::RTE_FLOW_ITEM_TYPE_END, null(), null()),
    ];
    // SAFETY: END-terminated; attr/mask outlive the call.
    let pt1 = unsafe {
        rte_flow_pattern_template_create(port, &pt1_attr, g1_pat_tmpl.as_ptr(), &mut err)
    };
    if pt1.is_null() {
        return Err(format!("g1 pattern template: {}", err_msg(&err)).into());
    }
    let mut at1_attr: rte_flow_actions_template_attr = unsafe { core::mem::zeroed() };
    at1_attr.set_ingress(1);
    let handle_conf: *const c_void = handle.cast();
    let g1_acts = [
        action(at::RTE_FLOW_ACTION_TYPE_INDIRECT, handle_conf),
        action(at::RTE_FLOW_ACTION_TYPE_END, null()),
    ];
    // Per rte_flow.h: the indirect action's mask slot carries the WRAPPED type (RSS), not INDIRECT.
    let g1_acts_mask = [
        action(at::RTE_FLOW_ACTION_TYPE_RSS, null()),
        action(at::RTE_FLOW_ACTION_TYPE_END, null()),
    ];
    // SAFETY: END-terminated; attr/handle outlive the call.
    let at1 = unsafe {
        rte_flow_actions_template_create(
            port,
            &at1_attr,
            g1_acts.as_ptr(),
            g1_acts_mask.as_ptr(),
            &mut err,
        )
    };
    if at1.is_null() {
        return Err(format!("g1 actions template: {}", err_msg(&err)).into());
    }
    let mut t1_attr: rte_flow_template_table_attr = unsafe { core::mem::zeroed() };
    t1_attr.flow_attr.set_ingress(1);
    t1_attr.flow_attr.group = 1;
    t1_attr.nb_flows = n_rules.saturating_mul(2).max(1);
    t1_attr.insertion_type = rte_flow_table_insertion_type::RTE_FLOW_TABLE_INSERTION_TYPE_PATTERN;
    t1_attr.hash_func = rte_flow_table_hash_func::RTE_FLOW_TABLE_HASH_FUNC_DEFAULT;
    let mut pts1 = [pt1];
    let mut ats1 = [at1];
    // SAFETY: arrays/attr outlive the call; counts match.
    let table1 = unsafe {
        rte_flow_template_table_create(
            port,
            &t1_attr,
            pts1.as_mut_ptr(),
            1,
            ats1.as_mut_ptr(),
            1,
            &mut err,
        )
    };
    if table1.is_null() {
        return Err(format!("g1 table: {}", err_msg(&err)).into());
    }

    let base = u32::from(Ipv4Addr::new(10, 0, 0, 0));
    let mut ipv4_spec: rte_flow_item_ipv4 = unsafe { core::mem::zeroed() };
    let mut created = 0u32;
    while created < n_rules {
        let target = (created + BATCH).min(n_rules);
        let batch_start = created;
        while created < target {
            ipv4_spec.hdr.src_addr = (base + created).to_be();
            let pattern = [
                item(it::RTE_FLOW_ITEM_TYPE_ETH, null(), null()),
                item(it::RTE_FLOW_ITEM_TYPE_IPV4, vp(&ipv4_spec), null()),
                item(it::RTE_FLOW_ITEM_TYPE_END, null(), null()),
            ];
            // SAFETY: END-terminated; copied during the call; table/handle valid.
            let flow = unsafe {
                rte_flow_async_create(
                    port,
                    0,
                    &op_attr,
                    table1,
                    pattern.as_ptr(),
                    0,
                    g1_acts.as_ptr(),
                    0,
                    null_mut(),
                    &mut err,
                )
            };
            if flow.is_null() {
                return Err(format!("g1 rule #{created}: {}", err_msg(&err)).into());
            }
            created += 1;
        }
        flush(port, target - batch_start)?;
    }
    println!("installed {created} group-1 rules -> the ONE indirect RSS handle");

    // ---- stream, flip the handle to queue 1 at half-time, watch all rules re-steer ----
    let mut queues = dev.take_queues().ok_or("device queues already taken")?;
    let mut rxq0 = queues.take_rx(RxQueueIndex(0)).ok_or("rx q0 missing")?;
    let mut rxq1 = queues.take_rx(RxQueueIndex(1)).ok_or("rx q1 missing")?;
    println!(
        "streaming {secs}s; will flip RSS -> queue 1 at {}s. Inject now...",
        secs / 2
    );
    let start = Instant::now();
    let deadline = start + Duration::from_secs(secs);
    let update_at = start + Duration::from_secs(secs / 2);
    let mut updated = false;
    let (mut before_q0, mut before_q1, mut after_q0, mut after_q1) = (0u64, 0u64, 0u64, 0u64);
    let (mut tick_q0, mut tick_q1) = (0u64, 0u64);
    let mut next_tick = start + Duration::from_secs(1);
    let rss1 = rss_to(&q1_arr);
    while Instant::now() < deadline {
        if !updated && Instant::now() >= update_at {
            // SAFETY: handle valid; rss1/queue array outlive the flush below.
            let rc = unsafe {
                rte_flow_async_action_handle_update(
                    port,
                    0,
                    &op_attr,
                    handle,
                    vp(&rss1),
                    null_mut(),
                    &mut err,
                )
            };
            if rc != 0 {
                return Err(format!("handle_update: {}", err_msg(&err)).into());
            }
            flush(port, 1)?;
            updated = true;
            println!("    *** handle_update: RSS -> queue 1 (one update, all rules) ***");
        }
        for (rxq, is_q0) in [(&mut rxq0, true), (&mut rxq1, false)] {
            for m in &rxq.receive() {
                if !is_ours(m.as_ref()) {
                    continue;
                }
                match (updated, is_q0) {
                    (false, true) => before_q0 += 1,
                    (false, false) => before_q1 += 1,
                    (true, true) => after_q0 += 1,
                    (true, false) => after_q1 += 1,
                }
                if is_q0 {
                    tick_q0 += 1;
                } else {
                    tick_q1 += 1;
                }
            }
        }
        if Instant::now() >= next_tick {
            let t = (Instant::now() - start).as_secs();
            println!(
                "    t={t}s  q0={tick_q0:<7} q1={tick_q1:<7}{}",
                if updated { "  (post-update)" } else { "" }
            );
            tick_q0 = 0;
            tick_q1 = 0;
            next_tick += Duration::from_secs(1);
        } else {
            std::hint::spin_loop();
        }
    }

    println!(
        "=== before update: q0={before_q0} q1={before_q1} | after update: q0={after_q0} q1={after_q1} ==="
    );
    // Before the flip traffic should be on q0; after, on q1. Allow a little in-flight slop post-flip.
    let pass = before_q0 > 0 && before_q1 == 0 && after_q1 > 0 && after_q0 <= after_q1 / 20;
    println!(
        "VERDICT: {}",
        if pass {
            "PASS -- one handle_update re-steered every referencing rule from q0 to q1"
        } else {
            "FAIL / inconclusive (need sustained injection across the flip)"
        }
    );
    Ok(())
}
