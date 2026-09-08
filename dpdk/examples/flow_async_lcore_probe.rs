// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Does the async / template `rte_flow` engine care which kind of thread drives it?
//!
//! Offloading forwarding to hardware is a mission-critical eventual goal, and it runs on the async
//! (HWS) flow API: `rte_flow_async_create` / `rte_flow_push` / `rte_flow_pull`, each addressed to a
//! **flow queue**. If those were tied to EAL lcore identity the way `rte_power_pmd_mgmt` is, then
//! driving them from the registered non-EAL threads this dataplane uses as workers would be closed
//! off, and the whole worker-thread design would need revisiting.
//!
//! Source says they are not: `lib/ethdev/rte_flow.c` contains **no** reference to lcores at all, and
//! neither does mlx5's hardware-steering implementation (`drivers/net/mlx5/mlx5_flow_hw.c`). The
//! only `rte_lcore_index` uses in the mlx5 tree are the generic `mlx5_list` per-lcore cache (which
//! serves registered threads correctly on 26.07 -- see `examples/lcore_role_probe.rs`) and a dump
//! routine belonging to the *legacy* software-steering engine.
//!
//! This probe checks that against the hardware, because "grep found nothing" is a weaker claim than
//! "it ran". Setup happens on the main lcore, as it would in production -- flow queues are created
//! before the port starts. Then three thread flavours each drive their **own** flow queue through a
//! full create/push/pull cycle:
//!
//! - **main** -- a real EAL lcore, the control.
//! - **registered** -- an ordinary thread holding an `LCore`; what a worker is.
//! - **plain** -- an ordinary thread that never registered. Included because if even *this* works,
//!   the API has no lcore coupling whatsoever and nothing about the thread model can threaten the
//!   offload goal.
//!
//! # Prerequisite, and it is not optional
//!
//! The port must be in a mode where HWS actually works -- on a BlueField-3 that means switchdev
//! with HW steering (`scripts/bf3-eswitch-reset.sh` puts a card there). On a card that is not,
//! mlx5 reports the async engine as available through every public API and then **segfaults on the
//! first call that uses it**. That is a PMD defect, it is orthogonal to everything this probe is
//! asking about, and it takes the unrelated `examples/template_probe.rs` down identically.
//!
//! Run as root (or with the mlx5 capability set):
//!   ./flow_async_lcore_probe 0000:02:00.1

use core::ffi::c_void;
use core::ptr::{null, null_mut};

use dataplane_dpdk::dev::{DevConfig, RxOffload};
use dataplane_dpdk::eal;
use dataplane_dpdk::lcore::LCore;
use dataplane_dpdk::mem::{PoolConfig, PoolParams};
use dataplane_dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dataplane_dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dataplane_dpdk::socket::Preference;

use dpdk_sys::{
    rte_flow_action, rte_flow_action_queue, rte_flow_action_type, rte_flow_actions_template_attr,
    rte_flow_actions_template_create, rte_flow_async_create, rte_flow_configure, rte_flow_error,
    rte_flow_item, rte_flow_item_ipv4, rte_flow_item_type, rte_flow_op_attr, rte_flow_op_result,
    rte_flow_op_status, rte_flow_pattern_template_attr, rte_flow_pattern_template_create,
    rte_flow_port_attr, rte_flow_pull, rte_flow_push, rte_flow_queue_attr,
    rte_flow_table_hash_func, rte_flow_table_insertion_type, rte_flow_template_table_attr,
    rte_flow_template_table_create,
};

type Err = Box<dyn std::error::Error>;

const QUEUE_SIZE: u32 = 64;
/// One flow queue per driving thread, which is the production shape: a worker owns its queue the
/// way it owns its rx and tx queues.
const FLOW_QUEUES: u16 = 3;
/// Rules per thread. Small: this is testing reachability, not insertion rate (`template_probe`
/// measures that).
const RULES: u32 = 16;

fn err_msg(e: &rte_flow_error) -> String {
    let msg = if e.message.is_null() {
        "(no message)".to_string()
    } else {
        // SAFETY: a non-null message points to a static C string owned by the PMD.
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

fn vp<T>(t: &T) -> *const c_void {
    (t as *const T).cast()
}

/// A template table pointer that may be shared across the driving threads.
///
/// `rte_flow_template_table` is not `Sync` to Rust, but the async API's contract is per **flow
/// queue**: distinct queues may be driven concurrently, and each thread here owns one. The table
/// itself is only read.
#[derive(Copy, Clone)]
struct Table(*mut dpdk_sys::rte_flow_template_table);
// SAFETY: see the type docs -- each thread drives a distinct flow queue, which is the granularity
// the API serialises on.
unsafe impl Send for Table {}
unsafe impl Sync for Table {}

/// Result of driving one flow queue to completion.
struct Driven {
    lcore_id: u32,
    created: u32,
    pushed: i32,
    completed: u32,
    failed: u32,
    error: Option<String>,
}

/// Run a full async create/push/pull cycle on `queue`, entirely from the calling thread.
fn drive(port: u16, table: Table, queue: u32) -> Driven {
    let lcore_id = unsafe { dpdk_sys::rte_lcore_id_w() };
    let mut err: rte_flow_error = unsafe { core::mem::zeroed() };
    let mut op_attr: rte_flow_op_attr = unsafe { core::mem::zeroed() };
    // Postpone every op, so the whole batch is submitted to hardware by the single `push` below --
    // which is the shape a worker would use.
    op_attr.set_postpone(1);

    let mut created = 0;
    let mut error = None;

    for i in 0..RULES {
        // Per-rule match: a distinct ipv4 destination, so every rule is a different entry. The
        // high octet is the queue, so the three threads cannot collide on a rule.
        let mut spec: rte_flow_item_ipv4 = unsafe { core::mem::zeroed() };
        spec.hdr.dst_addr = (queue << 24) | (i + 1);
        let pattern = [
            item(rte_flow_item_type::RTE_FLOW_ITEM_TYPE_ETH, null(), null()),
            item(
                rte_flow_item_type::RTE_FLOW_ITEM_TYPE_IPV4,
                vp(&spec),
                null(),
            ),
            item(rte_flow_item_type::RTE_FLOW_ITEM_TYPE_END, null(), null()),
        ];
        let q = rte_flow_action_queue { index: 0 };
        let actions = [
            action(rte_flow_action_type::RTE_FLOW_ACTION_TYPE_QUEUE, vp(&q)),
            action(rte_flow_action_type::RTE_FLOW_ACTION_TYPE_END, null()),
        ];
        // SAFETY: pattern and actions are END-terminated and outlive the call; `queue` was
        // configured by `rte_flow_configure` and is driven only by this thread.
        let flow = unsafe {
            rte_flow_async_create(
                port,
                queue,
                &op_attr,
                table.0,
                pattern.as_ptr(),
                0,
                actions.as_ptr(),
                0,
                null_mut(),
                &mut err,
            )
        };
        if flow.is_null() {
            error = Some(format!("async_create #{i}: {}", err_msg(&err)));
            break;
        }
        created += 1;
    }

    // SAFETY: `queue` is this thread's alone.
    let pushed = unsafe { rte_flow_push(port, queue, &mut err) };
    if pushed != 0 && error.is_none() {
        error = Some(format!("push: {}", err_msg(&err)));
    }

    let mut completed = 0;
    let mut failed = 0;
    let mut results: [rte_flow_op_result; RULES as usize] = unsafe { core::mem::zeroed() };
    // Pull until every submitted op has been accounted for, bounded so a wedged queue ends the
    // probe rather than hanging it.
    for _ in 0..1000 {
        if completed + failed >= created {
            break;
        }
        // SAFETY: `results` has room for `RULES` entries; `queue` is this thread's alone.
        let n = unsafe { rte_flow_pull(port, queue, results.as_mut_ptr(), RULES as u16, &mut err) };
        if n < 0 {
            error = Some(format!("pull: {}", err_msg(&err)));
            break;
        }
        for result in results.iter().take(n as usize) {
            if result.status == rte_flow_op_status::RTE_FLOW_OP_SUCCESS {
                completed += 1;
            } else {
                failed += 1;
            }
        }
    }

    Driven {
        lcore_id,
        created,
        pushed,
        completed,
        failed,
        error,
    }
}

fn report(what: &str, d: &Driven) {
    let id = if d.lcore_id == u32::MAX {
        "ANY".to_string()
    } else {
        d.lcore_id.to_string()
    };
    println!(
        "  {what:<12} lcore={id:<4} created={:<3} push={:<3} completed={:<3} failed={:<3} {}",
        d.created,
        d.pushed,
        d.completed,
        d.failed,
        d.error.as_deref().unwrap_or(""),
    );
}

fn main() -> Result<(), Err> {
    let bdf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0000:02:00.1".to_string());

    // `dv_flow_en=2` selects the mlx5 HWS (hardware steering) template/async engine.
    let devarg = format!("{bdf},dv_flow_en=2");
    let eal = eal::init([
        "-a",
        devarg.as_str(),
        "--in-memory",
        "--no-telemetry",
        "--no-shconf",
        "--iova-mode=va",
    ]);

    let info = eal.dev.iter().next().ok_or("no DPDK port probed")?;
    let pool = eal
        .mem
        .new_pkt_pool(
            PoolConfig::new("flow_async_pool", PoolParams::default())
                .map_err(|e| format!("pool: {e:?}"))?,
        )
        .map_err(|e| format!("pool create: {e:?}"))?;
    let mut dev = DevConfig {
        num_rx_queues: 1,
        num_tx_queues: 1,
        num_hairpin_queues: 0,
        tx_offloads: None,
        rx_offloads: None,
        mtu: None,
        rss: None,
    }
    .apply(info)
    .map_err(|e| format!("dev configure: {e:?}"))?;
    let idx = dev.info.index();
    let port = idx.as_u16();
    println!("port {port} ({bdf}), HWS async flow engine");

    dev.new_rx_queue(RxQueueConfig {
        dev: idx,
        queue_index: RxQueueIndex(0),
        num_descriptors: 1024,
        socket_preference: Preference::Dev(idx),
        offloads: RxOffload::from(0u64),
        pool,
    })?;
    dev.new_tx_queue(TxQueueConfig {
        queue_index: TxQueueIndex(0),
        num_descriptors: 1024,
        socket_preference: Preference::Dev(idx),
        config: (),
    })?;

    // Report what the PMD claims, and then warn -- because the claim cannot be trusted.
    //
    // On a BlueField-3 whose eswitch is not in switchdev/HWS mode, mlx5 logs
    //   [mlx5dr_cmd_query_caps]: Failed to query wire port regc value
    //   [mlx5dr_context_check_hws_supp]: Required HWS WQE based insertion cap not supported
    // and then **lies to every public API about it**: `rte_flow_info_get` reports
    // `max_nb_queues = u32::MAX` and `rte_flow_configure` returns 0. The first HWS call after that
    // -- `rte_eth_dev_start`, or `rte_flow_pattern_template_create` if you reorder them --
    // dereferences the context that was never built and takes the process down with SIGSEGV.
    // There is no pre-flight check available through the public API; this was tried.
    //
    // So this probe cannot defend itself. It prints its intent first, so that a core dump here is
    // attributable to the device's mode rather than mistaken for a finding about threads.
    let mut port_info: dpdk_sys::rte_flow_port_info = unsafe { core::mem::zeroed() };
    let mut queue_info: dpdk_sys::rte_flow_queue_info = unsafe { core::mem::zeroed() };
    let mut err: rte_flow_error = unsafe { core::mem::zeroed() };
    // SAFETY: both out-params are live for the call.
    let rc = unsafe {
        dpdk_sys::rte_flow_info_get(port, &raw mut port_info, &raw mut queue_info, &mut err)
    };
    println!(
        "rte_flow_info_get rc={rc}, max_nb_queues={} (NOT a reliable capability signal -- see the \
         module docs)",
        port_info.max_nb_queues
    );
    println!(
        "about to configure the async engine; if this crashes, the port is not in switchdev/HWS \
         mode (see scripts/bf3-eswitch-reset.sh) and the crash says nothing about lcores"
    );

    // One flow queue per driving thread. `rte_flow_configure` must run after dev configure and
    // before dev start.
    let port_attr: rte_flow_port_attr = unsafe { core::mem::zeroed() };
    let queue_attr = rte_flow_queue_attr { size: QUEUE_SIZE };
    let mut qa_ptrs = [&queue_attr as *const rte_flow_queue_attr; FLOW_QUEUES as usize];
    // SAFETY: `FLOW_QUEUES` entries in `qa_ptrs`; attrs outlive the call.
    let rc = unsafe {
        rte_flow_configure(
            port,
            &port_attr,
            FLOW_QUEUES,
            qa_ptrs.as_mut_ptr(),
            &mut err,
        )
    };
    if rc != 0 {
        return Err(format!("rte_flow_configure: {}", err_msg(&err)).into());
    }
    println!("rte_flow_configure: {FLOW_QUEUES} flow queues of {QUEUE_SIZE}");

    let dev = dev.start().map_err(|e| format!("dev start: {e}"))?;

    // Pattern template: eth / ipv4 with a templated destination.
    let mut pt_attr: rte_flow_pattern_template_attr = unsafe { core::mem::zeroed() };
    pt_attr.set_ingress(1);
    let mut ipv4_mask: rte_flow_item_ipv4 = unsafe { core::mem::zeroed() };
    ipv4_mask.hdr.dst_addr = u32::MAX;
    let pattern_tmpl = [
        item(rte_flow_item_type::RTE_FLOW_ITEM_TYPE_ETH, null(), null()),
        item(
            rte_flow_item_type::RTE_FLOW_ITEM_TYPE_IPV4,
            null(),
            vp(&ipv4_mask),
        ),
        item(rte_flow_item_type::RTE_FLOW_ITEM_TYPE_END, null(), null()),
    ];
    // SAFETY: END-terminated; attr and mask outlive the call.
    let pt = unsafe {
        rte_flow_pattern_template_create(port, &pt_attr, pattern_tmpl.as_ptr(), &mut err)
    };
    if pt.is_null() {
        return Err(format!("pattern_template_create: {}", err_msg(&err)).into());
    }

    // Actions template: a fixed QUEUE(0).
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
    // SAFETY: END-terminated; attr and confs outlive the call.
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
        return Err(format!("actions_template_create: {}", err_msg(&err)).into());
    }

    let mut table_attr: rte_flow_template_table_attr = unsafe { core::mem::zeroed() };
    table_attr.flow_attr.set_ingress(1);
    table_attr.flow_attr.group = 1;
    table_attr.nb_flows = 4096;
    table_attr.insertion_type =
        rte_flow_table_insertion_type::RTE_FLOW_TABLE_INSERTION_TYPE_PATTERN;
    table_attr.hash_func = rte_flow_table_hash_func::RTE_FLOW_TABLE_HASH_FUNC_DEFAULT;
    let mut pts = [pt];
    let mut ats = [at];
    // SAFETY: one pattern and one actions template, both live; attr outlives the call.
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
        return Err(format!("template_table_create: {}", err_msg(&err)).into());
    }
    let table = Table(table);
    println!();

    // Queue 0 from the main lcore: the control.
    let main_driven = drive(port, table, 0);
    report("main", &main_driven);

    // Queues 1 and 2 from a registered and an unregistered thread, concurrently -- which is also a
    // check that distinct flow queues really are independently drivable.
    let (registered, plain) = std::thread::scope(|s| {
        let r = s.spawn(|| {
            let _registration = LCore::register().expect("could not register");
            drive(port, table, 1)
        });
        let p = s.spawn(|| drive(port, table, 2));
        (
            r.join().expect("registered thread panicked"),
            p.join().expect("plain thread panicked"),
        )
    });
    report("registered", &registered);
    report("plain", &plain);

    println!();
    let mut surprises: Vec<String> = Vec::new();
    let mut check = |claim: &str, holds: bool| {
        println!("  [{}] {claim}", if holds { "ok " } else { "!! " });
        if !holds {
            surprises.push(claim.to_string());
        }
    };

    let ok = |d: &Driven| {
        d.error.is_none() && d.created == RULES && d.completed == RULES && d.failed == 0
    };

    check("the main lcore can drive a flow queue", ok(&main_driven));
    check(
        "a REGISTERED thread can drive a flow queue (this is what a worker is)",
        ok(&registered),
    );
    check(
        "an UNREGISTERED thread can too -- the async flow API has no lcore coupling at all",
        ok(&plain),
    );
    check(
        "three threads drove three distinct flow queues concurrently",
        main_driven.completed + registered.completed + plain.completed == RULES * 3,
    );

    dev.stop()
        .map_err(|e| format!("stop: {e}"))?
        .close()
        .map_err(|e| format!("close: {e}"))?;

    println!();
    if surprises.is_empty() {
        println!("the async flow engine does not care which kind of thread drives it");
        Ok(())
    } else {
        for s in &surprises {
            println!("[SURPRISE] {s}");
        }
        Err(format!("{} claim(s) did not hold", surprises.len()).into())
    }
}
