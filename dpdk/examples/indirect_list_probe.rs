// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Indirect-action LIST probe: one shared action-LIST handle referenced by many rules.
//!
//! Third of the indirect trio (after sharing via `indirect_probe`, update via `meter_update_probe`):
//! validate that `RTE_FLOW_ACTION_TYPE_INDIRECT_LIST` -- a handle wrapping a LIST of actions --
//! composes with HWS and is shareable across many rules. (Raw HWS FFI.)
//!   - create ONE action-list handle wrapping `[COUNT]` (rte_flow_async_action_list_handle_create),
//!   - install N group-1 rules, each matching a distinct ipv4 `src`, referencing the SAME list
//!     handle (`INDIRECT_LIST` action) plus `QUEUE 0`,
//!   - a group-0 jump feeds them,
//!   - inject across many srcs so MANY rules fire; confirm they all steer to queue 0 via the one
//!     list handle -- the list mechanism shared across rules, composing with the template engine.
//!
//! Inject (vary cycles src 10.0.0.1..250, dst 10.0.0.2):
//!   sudo python3 send_frames.py <peer-netdev> <this-port-mac> <count> 0800 vary
//! Run as root:  sudo ./indirect_list_probe 0000:e1:00.1 [n_rules=256] [seconds=10]

use core::ffi::c_void;
use core::net::Ipv4Addr;
use core::ptr::{null, null_mut};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use dataplane_dpdk::dev::{DevConfig, RxOffload};
use dataplane_dpdk::eal;
use dataplane_dpdk::mem::{Pool, PoolConfig, PoolParams};
use dataplane_dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dataplane_dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dataplane_dpdk::socket::Preference;

use dpdk_sys::{
    rte_flow_action, rte_flow_action_count, rte_flow_action_indirect_list, rte_flow_action_jump,
    rte_flow_action_queue, rte_flow_action_type as at, rte_flow_actions_template_attr,
    rte_flow_actions_template_create, rte_flow_async_action_handle_create,
    rte_flow_async_action_list_handle_create, rte_flow_async_create, rte_flow_configure,
    rte_flow_error, rte_flow_indir_action_conf, rte_flow_item, rte_flow_item_ipv4,
    rte_flow_item_type as it, rte_flow_op_attr, rte_flow_op_result, rte_flow_op_status,
    rte_flow_pattern_template_attr, rte_flow_pattern_template_create, rte_flow_port_attr,
    rte_flow_pull, rte_flow_push, rte_flow_queue_attr, rte_flow_table_hash_func,
    rte_flow_table_insertion_type, rte_flow_template_table_attr, rte_flow_template_table_create,
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

/// Push queue 0 and pull exactly `count` successful completions (or error/timeout).
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
    let pool = Pool::new_pkt_pool(
        PoolConfig::new("indir_pool", PoolParams::default()).map_err(|e| format!("pool: {e:?}"))?,
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
    let port = idx.as_u16();
    println!("port {bdf} index {port}; indirect-LIST probe, n_rules={n_rules}");
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

    // Reserve counters for the flow engine, then configure 1 flow queue (before start).
    let mut port_attr: rte_flow_port_attr = unsafe { core::mem::zeroed() };
    port_attr.nb_counters = 64;
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

    let mut indir_conf: rte_flow_indir_action_conf = unsafe { core::mem::zeroed() };
    indir_conf.set_ingress(1);

    // A bare [COUNT] list is rejected ("Invalid list"); mlx5's indirect-LIST composes already-created
    // INDIRECT handles. So first make a real indirect COUNT handle, then wrap [INDIRECT(count)] in a
    // list handle.
    let count_conf = rte_flow_action_count { id: 0 };
    let count_action = action(at::RTE_FLOW_ACTION_TYPE_COUNT, vp(&count_conf));
    // SAFETY: conf/action outlive the call; queue 0 valid.
    let count_handle = unsafe {
        rte_flow_async_action_handle_create(
            port,
            0,
            &op_attr,
            &indir_conf,
            &count_action,
            null_mut(),
            &mut err,
        )
    };
    if count_handle.is_null() {
        return Err(format!("indirect COUNT handle create: {}", err_msg(&err)).into());
    }
    flush(port, 1)?;

    let count_indirect = action(at::RTE_FLOW_ACTION_TYPE_INDIRECT, count_handle.cast());
    let list_actions = [count_indirect, action(at::RTE_FLOW_ACTION_TYPE_END, null())];
    // SAFETY: list_actions + the referenced count handle outlive the call.
    let handle = unsafe {
        rte_flow_async_action_list_handle_create(
            port,
            0,
            &op_attr,
            &indir_conf,
            list_actions.as_ptr(),
            null_mut(),
            &mut err,
        )
    };
    if handle.is_null() {
        return Err(format!("indirect-list handle create: {}", err_msg(&err)).into());
    }
    flush(port, 1)?;
    println!("indirect-LIST handle created (wraps [INDIRECT(COUNT)])");

    // ---- group 0: eth -> jump group 1 (root table, hash insertion) ----
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
    // SAFETY: END-terminated; table valid; confs copied during the call.
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
    println!("group 0 eth -> jump group 1 installed");

    // ---- group 1: eth / ipv4(src) -> INDIRECT(count) + QUEUE 0 ----
    let mut pt1_attr: rte_flow_pattern_template_attr = unsafe { core::mem::zeroed() };
    pt1_attr.set_ingress(1);
    let mut ipv4_mask: rte_flow_item_ipv4 = unsafe { core::mem::zeroed() };
    ipv4_mask.hdr.src_addr = u32::MAX; // src is the per-rule templated field
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
    let queue = rte_flow_action_queue { index: 0 };
    let queue_mask = rte_flow_action_queue { index: u16::MAX };
    // INDIRECT_LIST conf is rte_flow_action_indirect_list { handle, conf }. conf=NULL => no per-rule
    // mutable config (all rules share the list as-is). `il` must outlive the rule-creation loop.
    let il = rte_flow_action_indirect_list {
        handle,
        conf: null_mut(),
    };
    let g1_acts = [
        action(at::RTE_FLOW_ACTION_TYPE_INDIRECT_LIST, vp(&il)),
        action(at::RTE_FLOW_ACTION_TYPE_QUEUE, vp(&queue)),
        action(at::RTE_FLOW_ACTION_TYPE_END, null()),
    ];
    let g1_acts_mask = [
        action(at::RTE_FLOW_ACTION_TYPE_INDIRECT_LIST, null()),
        action(at::RTE_FLOW_ACTION_TYPE_QUEUE, vp(&queue_mask)),
        action(at::RTE_FLOW_ACTION_TYPE_END, null()),
    ];
    // SAFETY: END-terminated; attr/confs/handle outlive the call.
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
    println!("installed {created} group-1 rules, all referencing the ONE indirect-LIST handle");

    // ---- inject across many srcs; many distinct rules fire, all via the one list handle ----
    let mut queues = dev.take_queues().ok_or("device queues already taken")?;
    let mut rxq = queues
        .take_rx(RxQueueIndex(0))
        .ok_or("rx queue 0 missing")?;
    println!("polling {secs}s -- inject `... <count> 0800 vary` (src 10.0.0.1..250) now...");
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut rx = 0u64;
    let mut srcs = BTreeSet::new();
    while Instant::now() < deadline {
        let burst = rxq.receive();
        if burst.is_empty() {
            std::hint::spin_loop();
            continue;
        }
        for m in &burst {
            let f: &[u8] = m.as_ref();
            if f.len() >= 34 && f[12..14] == [0x08, 0x00] && f[26..29] == [10, 0, 0] {
                rx += 1;
                srcs.insert(f[29]); // last octet of src ip == which rule fired
            }
        }
    }

    println!(
        "=== rx on queue 0: {rx} frames across {} distinct srcs (rules), all via the ONE indirect-LIST handle ===",
        srcs.len()
    );
    let pass = rx > 0 && srcs.len() > 1;
    println!(
        "VERDICT: {}",
        if pass {
            "PASS -- one INDIRECT_LIST handle shared across many distinct-src rules; composes with HWS + steers"
        } else {
            "FAIL / inconclusive (inject with the `vary` arg?)"
        }
    );
    Ok(())
}
