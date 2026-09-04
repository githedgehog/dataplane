// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! HWS template-engine probe: stand up the async/template flow API, measure insertion rate, and
//! confirm one templated rule actually steers traffic.
//!
//! Sequence (raw `rte_flow` FFI -- this is exploratory, the safe wrapper follows the findings):
//!   1. EAL with `dv_flow_en=2` (mlx5: enable HWS template/async engine).
//!   2. dev configure + rx/tx queues, then `rte_flow_configure` (1 flow queue) BEFORE start.
//!   3. pattern template `eth / ipv4(dst mask)`, actions template `QUEUE(0)` (fixed), one table.
//!   4. `rte_flow_async_create` N rules (per-rule ipv4 dst = 10.0.0.i), `push`, `pull` completions;
//!      time the batch -> rules/sec.
//!   5. inject IPv4 to 10.0.0.2 (rule i=2) and confirm it lands on rx queue 0.
//!
//! Inject:  sudo python3 send_frames.py <peer-netdev> <this-port-mac> <count>
//! Run as root:  sudo ./template_probe 0000:e1:00.1 [n_rules=2048] [seconds=10]

use core::ffi::c_void;
use core::net::Ipv4Addr;
use core::ptr::{null, null_mut};
use std::time::{Duration, Instant};

use dataplane_dpdk::dev::{DevConfig, RxOffload};
use dataplane_dpdk::eal;
use dataplane_dpdk::mem::{PoolConfig, PoolParams};
use dataplane_dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dataplane_dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dataplane_dpdk::socket::Preference;

use dpdk_sys::{
    rte_flow_action, rte_flow_action_queue, rte_flow_action_type, rte_flow_actions_template_attr,
    rte_flow_actions_template_create, rte_flow_async_create,
    rte_flow_async_create_by_index_with_pattern, rte_flow_configure, rte_flow_error, rte_flow_item,
    rte_flow_item_ipv4, rte_flow_item_type, rte_flow_op_attr, rte_flow_op_result,
    rte_flow_op_status, rte_flow_pattern_template_attr, rte_flow_pattern_template_create,
    rte_flow_port_attr, rte_flow_pull, rte_flow_push, rte_flow_queue_attr,
    rte_flow_table_hash_func, rte_flow_table_insertion_type, rte_flow_template_table_attr,
    rte_flow_template_table_create,
};

type Err = Box<dyn std::error::Error>;

const QUEUE_SIZE: u32 = 1024;
// In-flight ops per push/drain cycle. Kept below QUEUE_SIZE: filling a flow queue to its exact
// capacity wedges completions (pull returns 0), so leave headroom.
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

fn item(
    type_: rte_flow_item_type::Type,
    spec: *const c_void,
    mask: *const c_void,
) -> rte_flow_item {
    rte_flow_item {
        type_,
        spec,
        last: null(),
        mask,
    }
}

fn action(type_: rte_flow_action_type::Type, conf: *const c_void) -> rte_flow_action {
    rte_flow_action { type_, conf }
}

fn vp<T>(r: &T) -> *const c_void {
    core::ptr::from_ref(r).cast()
}

fn main() -> Result<(), Err> {
    let mut args = std::env::args().skip(1);
    let bdf = args.next().unwrap_or_else(|| "0000:e1:00.1".to_string());
    let n_rules: u32 = args.next().unwrap_or_else(|| "2048".into()).parse()?;
    let secs: u64 = args.next().unwrap_or_else(|| "10".into()).parse()?;
    // "pattern" (default): matcher computes placement. "index": caller picks the slot via
    // create_by_index_with_pattern (INDEX_WITH_PATTERN table) -- same match, no placement search.
    let mode = args.next().unwrap_or_else(|| "pattern".into());
    let by_index = mode == "index";

    // dv_flow_en=2 selects the mlx5 HWS (hardware steering) template/async engine.
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
    let pool = eal
        .mem
        .new_pkt_pool(
            PoolConfig::new("tmpl_pool", PoolParams::default())
                .map_err(|e| format!("pool: {e:?}"))?,
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
    println!("port {bdf} index {port}; HWS template probe, n_rules={n_rules}, insertion={mode}");
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

    // rte_flow_configure must run after dev configure and BEFORE dev start -- so while Stopped.
    let port_attr: rte_flow_port_attr = unsafe { core::mem::zeroed() };
    let queue_attr = rte_flow_queue_attr { size: QUEUE_SIZE };
    let mut qa_ptrs = [&queue_attr as *const rte_flow_queue_attr];
    let mut err: rte_flow_error = unsafe { core::mem::zeroed() };
    // SAFETY: one flow queue; port_attr/queue_attr outlive the call.
    let rc = unsafe { rte_flow_configure(port, &port_attr, 1, qa_ptrs.as_mut_ptr(), &mut err) };
    if rc != 0 {
        return Err(format!("rte_flow_configure failed: {}", err_msg(&err)).into());
    }
    println!("rte_flow_configure: 1 flow queue, size {QUEUE_SIZE}");

    let dev = dev.start().map_err(|e| format!("dev start: {e}"))?;

    // ---- pattern template: eth / ipv4(dst is matchable) ----
    let mut pt_attr: rte_flow_pattern_template_attr = unsafe { core::mem::zeroed() };
    pt_attr.set_ingress(1);
    let mut ipv4_mask: rte_flow_item_ipv4 = unsafe { core::mem::zeroed() };
    ipv4_mask.hdr.dst_addr = u32::MAX; // dst is the per-rule templated field
    let pattern_tmpl = [
        item(rte_flow_item_type::RTE_FLOW_ITEM_TYPE_ETH, null(), null()),
        item(
            rte_flow_item_type::RTE_FLOW_ITEM_TYPE_IPV4,
            null(),
            vp(&ipv4_mask),
        ),
        item(rte_flow_item_type::RTE_FLOW_ITEM_TYPE_END, null(), null()),
    ];
    // SAFETY: END-terminated; attr/mask outlive the call.
    let pt = unsafe {
        rte_flow_pattern_template_create(port, &pt_attr, pattern_tmpl.as_ptr(), &mut err)
    };
    if pt.is_null() {
        return Err(format!("pattern_template_create failed: {}", err_msg(&err)).into());
    }

    // ---- actions template: QUEUE(0) fixed (mask field set => constant) ----
    let mut at_attr: rte_flow_actions_template_attr = unsafe { core::mem::zeroed() };
    at_attr.set_ingress(1);
    let queue = rte_flow_action_queue { index: 0 };
    let queue_mask = rte_flow_action_queue { index: u16::MAX };
    let acts_tmpl = [
        action(rte_flow_action_type::RTE_FLOW_ACTION_TYPE_QUEUE, vp(&queue)),
        action(rte_flow_action_type::RTE_FLOW_ACTION_TYPE_END, null()),
    ];
    let acts_mask = [
        action(
            rte_flow_action_type::RTE_FLOW_ACTION_TYPE_QUEUE,
            vp(&queue_mask),
        ),
        action(rte_flow_action_type::RTE_FLOW_ACTION_TYPE_END, null()),
    ];
    // SAFETY: END-terminated; attr/confs outlive the call.
    let at = unsafe {
        rte_flow_actions_template_create(
            port,
            &at_attr,
            acts_tmpl.as_ptr(),
            acts_mask.as_ptr(),
            &mut err,
        )
    };
    if at.is_null() {
        return Err(format!("actions_template_create failed: {}", err_msg(&err)).into());
    }

    // ---- template table at group 0, ingress, holding up to n_rules ----
    let mut table_attr: rte_flow_template_table_attr = unsafe { core::mem::zeroed() };
    table_attr.flow_attr.set_ingress(1);
    // Group 1 (non-root): the root matcher only supports hash insertion, so INDEX needs a non-root
    // group. Both modes use group 1 here so insertion_type is the only variable.
    table_attr.flow_attr.group = 1;
    // 2x headroom so the near-capacity load-factor cliff does not pollute the rate comparison.
    table_attr.nb_flows = n_rules.saturating_mul(2).max(1);
    table_attr.insertion_type = if by_index {
        rte_flow_table_insertion_type::RTE_FLOW_TABLE_INSERTION_TYPE_INDEX_WITH_PATTERN
    } else {
        rte_flow_table_insertion_type::RTE_FLOW_TABLE_INSERTION_TYPE_PATTERN
    };
    table_attr.hash_func = rte_flow_table_hash_func::RTE_FLOW_TABLE_HASH_FUNC_DEFAULT;
    let mut pts = [pt];
    let mut ats = [at];
    // SAFETY: template arrays/attr outlive the call; counts match.
    let table = unsafe {
        rte_flow_template_table_create(
            port,
            &table_attr,
            pts.as_mut_ptr(),
            1,
            ats.as_mut_ptr(),
            1,
            &mut err,
        )
    };
    if table.is_null() {
        return Err(format!("template_table_create failed: {}", err_msg(&err)).into());
    }
    println!("templates + table created; inserting {n_rules} rules via async API...");

    // ---- async insert: per-rule ipv4 dst = 10.0.0.i, all -> QUEUE 0 ----
    let mut op_attr: rte_flow_op_attr = unsafe { core::mem::zeroed() };
    op_attr.set_postpone(1); // batch until push
    let base = u32::from(Ipv4Addr::new(10, 0, 0, 0));
    let mut ipv4_spec: rte_flow_item_ipv4 = unsafe { core::mem::zeroed() };

    // A flow queue holds QUEUE_SIZE in-flight ops, so insert in batches of that depth: create up
    // to the cap, push, drain completions, repeat. (Fully draining each batch is conservative --
    // it serializes create/pull phases rather than pipelining -- but gives a sound first number.)
    let mut results: [rte_flow_op_result; 64] = unsafe { core::mem::zeroed() };
    let (mut created, mut pulled, mut ok, mut failed) = (0u32, 0u32, 0u32, 0u32);
    let (mut t_submit, mut t_drain) = (Duration::ZERO, Duration::ZERO);

    let t0 = Instant::now();
    while created < n_rules {
        let target = (created + BATCH).min(n_rules);
        let submit_start = Instant::now();
        while created < target {
            ipv4_spec.hdr.dst_addr = (base + created).to_be();
            let pattern = [
                item(rte_flow_item_type::RTE_FLOW_ITEM_TYPE_ETH, null(), null()),
                item(
                    rte_flow_item_type::RTE_FLOW_ITEM_TYPE_IPV4,
                    vp(&ipv4_spec),
                    null(),
                ),
                item(rte_flow_item_type::RTE_FLOW_ITEM_TYPE_END, null(), null()),
            ];
            // SAFETY: pattern/actions END-terminated and copied during the call; table valid.
            let flow = if by_index {
                unsafe {
                    rte_flow_async_create_by_index_with_pattern(
                        port,
                        0,
                        &op_attr,
                        table,
                        created, // caller-chosen slot
                        pattern.as_ptr(),
                        0,
                        acts_tmpl.as_ptr(),
                        0,
                        null_mut(),
                        &mut err,
                    )
                }
            } else {
                unsafe {
                    rte_flow_async_create(
                        port,
                        0,
                        &op_attr,
                        table,
                        pattern.as_ptr(),
                        0,
                        acts_tmpl.as_ptr(),
                        0,
                        null_mut(),
                        &mut err,
                    )
                }
            };
            if flow.is_null() {
                return Err(format!("async_create #{created} failed: {}", err_msg(&err)).into());
            }
            created += 1;
        }
        // SAFETY: valid started port + configured queue 0.
        let rc = unsafe { rte_flow_push(port, 0, &mut err) };
        if rc != 0 {
            return Err(format!("rte_flow_push failed: {}", err_msg(&err)).into());
        }
        let this_submit = submit_start.elapsed();
        t_submit += this_submit;
        // Occupancy curve: per-rule submit cost as the table fills.
        if (created / BATCH).is_multiple_of(8) {
            println!(
                "    @ {created:>6} rules in table: {:.1} us/rule",
                this_submit.as_secs_f64() * 1e6 / BATCH as f64
            );
        }
        let drain_start = Instant::now();
        let drain_deadline = Instant::now() + Duration::from_secs(10);
        while pulled < created {
            // SAFETY: results buffer holds 64; queue 0 valid.
            let n = unsafe { rte_flow_pull(port, 0, results.as_mut_ptr(), 64, &mut err) };
            if n < 0 {
                return Err(format!("rte_flow_pull failed: {}", err_msg(&err)).into());
            }
            for r in results.iter().take(n as usize) {
                if r.status == rte_flow_op_status::RTE_FLOW_OP_SUCCESS {
                    ok += 1;
                } else {
                    failed += 1;
                }
            }
            pulled += n as u32;
            if n == 0 && Instant::now() > drain_deadline {
                return Err(format!("pull timeout: only {pulled}/{created} completions").into());
            }
        }
        t_drain += drain_start.elapsed();
    }
    let dt = t0.elapsed();
    println!(
        "    submit (async_create+push): {:.1} ms; drain (pull): {:.1} ms",
        t_submit.as_secs_f64() * 1e3,
        t_drain.as_secs_f64() * 1e3
    );
    let rate = created as f64 / dt.as_secs_f64();
    println!(
        "=== inserted {created} rules in {:.3} ms: {ok} ok, {failed} failed -> {rate:.0} rules/sec ===",
        dt.as_secs_f64() * 1e3
    );

    // ---- confirm one templated rule steers: inject IPv4 to 10.0.0.2 (rule i=2) ----
    let mut queues = dev.take_queues().ok_or("device queues already taken")?;
    let mut rxq = queues
        .take_rx(RxQueueIndex(0))
        .ok_or("rx queue 0 missing")?;
    println!("polling {secs}s -- inject IPv4 to 10.0.0.2 from the peer now...");
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut steered = 0u64;
    while Instant::now() < deadline {
        let burst = rxq.receive();
        if burst.is_empty() {
            std::hint::spin_loop();
            continue;
        }
        for m in &burst {
            let f: &[u8] = m.as_ref();
            if f.len() >= 34 && f[12..14] == [0x08, 0x00] && f[30..34] == [10, 0, 0, 2] {
                steered += 1;
            }
        }
    }
    println!("=== steered to queue 0: {steered} frames (dst 10.0.0.2) ===");
    let pass = ok == created && failed == 0 && steered > 0;
    println!(
        "VERDICT: {}",
        if pass {
            "PASS -- HWS template engine installs rules and a templated rule steers"
        } else if ok == created {
            "PARTIAL -- all rules installed but no steered traffic observed (check injection)"
        } else {
            "FAIL"
        }
    );
    Ok(())
}
