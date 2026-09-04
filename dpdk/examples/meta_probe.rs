// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! META rx-delivery probe: can a `SET_META` value reach software under HWS?
//!
//! META would be a second HW->SW channel alongside MARK (see the trap-metadata design): MARK is one
//! ~24-bit field, but a mid-pipeline trap may need to convey trap-node + overwritten-context + gen.
//! The docs are unclear on which `dv_xmeta_en` mode delivers META under HWS, so this sweeps it.
//!
//! Mechanism (raw HWS FFI): `rte_flow_dynf_metadata_register()` installs the metadata dynfield; a
//! group-1 rule does `SET_META(0xDEADBEEF) + QUEUE 0`; on rx we read `Mbuf::rx_meta()`. The value
//! that comes back (and how many bits survive) tells us whether META works and at what width.
//!
//! Inject any IPv4 from the peer:
//!   sudo python3 send_frames.py <peer-netdev> <this-port-mac> <count>
//! Run as root:  sudo ./meta_probe 0000:e1:00.1 [dv_xmeta_en=4] [seconds=10]

use core::ffi::c_void;
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
    rte_flow_action, rte_flow_action_jump, rte_flow_action_modify_field, rte_flow_action_queue,
    rte_flow_action_type as at, rte_flow_actions_template_attr, rte_flow_actions_template_create,
    rte_flow_async_create, rte_flow_configure, rte_flow_dynf_metadata_register, rte_flow_error,
    rte_flow_field_id, rte_flow_item, rte_flow_item_type as it, rte_flow_modify_op,
    rte_flow_op_attr, rte_flow_op_result, rte_flow_op_status, rte_flow_pattern_template_attr,
    rte_flow_pattern_template_create, rte_flow_port_attr, rte_flow_pull, rte_flow_push,
    rte_flow_queue_attr, rte_flow_table_hash_func, rte_flow_table_insertion_type,
    rte_flow_template_table_attr, rte_flow_template_table_create,
};

type Err = Box<dyn std::error::Error>;

const META_VALUE: u32 = 0xDEAD_BEEF; // full 32 bits, so truncation reveals the delivered width
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
    let xmeta = args.next().unwrap_or_else(|| "4".to_string());
    let secs: u64 = args.next().unwrap_or_else(|| "10".into()).parse()?;

    let devarg = format!("{bdf},dv_flow_en=2,dv_xmeta_en={xmeta}");
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

    // Register the metadata dynfield BEFORE allocating the pool, so mbufs carry the field.
    // SAFETY: FFI; sets the global dynfield offset/mask Mbuf::rx_meta() reads.
    let rc = unsafe { rte_flow_dynf_metadata_register() };
    if rc != 0 {
        return Err(format!("rte_flow_dynf_metadata_register failed: rc={rc}").into());
    }
    println!("dv_xmeta_en={xmeta}; metadata dynfield registered");

    let info = eal.dev.iter().next().ok_or("no DPDK port probed")?;
    let pool = Pool::new_pkt_pool(
        PoolConfig::new("meta_pool", PoolParams::default()).map_err(|e| format!("pool: {e:?}"))?,
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

    // ---- group 0: eth -> jump group 1 ----
    let mut pt_attr: rte_flow_pattern_template_attr = unsafe { core::mem::zeroed() };
    pt_attr.set_ingress(1);
    let eth_pat = [
        item(it::RTE_FLOW_ITEM_TYPE_ETH, null(), null()),
        item(it::RTE_FLOW_ITEM_TYPE_END, null(), null()),
    ];
    // SAFETY: END-terminated; attr/items outlive the call.
    let pt0 =
        unsafe { rte_flow_pattern_template_create(port, &pt_attr, eth_pat.as_ptr(), &mut err) };
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

    // ---- group 1: eth -> SET_META(META_VALUE) + QUEUE 0 ----
    // SAFETY: END-terminated; attr/items outlive the call.
    let pt1 =
        unsafe { rte_flow_pattern_template_create(port, &pt_attr, eth_pat.as_ptr(), &mut err) };
    if pt1.is_null() {
        return Err(format!("g1 pattern template: {}", err_msg(&err)).into());
    }
    let mut at1_attr: rte_flow_actions_template_attr = unsafe { core::mem::zeroed() };
    at1_attr.set_ingress(1);
    // HWS rejects the legacy SET_META action; write META via the generic MODIFY_FIELD instead:
    // SET dst=META <- src=immediate VALUE (32 bits).
    let mut mf: rte_flow_action_modify_field = unsafe { core::mem::zeroed() };
    mf.operation = rte_flow_modify_op::RTE_FLOW_MODIFY_SET;
    mf.dst.field = rte_flow_field_id::RTE_FLOW_FIELD_META;
    mf.src.field = rte_flow_field_id::RTE_FLOW_FIELD_VALUE;
    mf.src.annon1.value = {
        let mut v = [0u8; 16];
        v[0..4].copy_from_slice(&META_VALUE.to_le_bytes());
        v
    };
    mf.width = 32;
    // MODIFY_FIELD's template mask is a HYBRID: selector fields (operation/field/width) must be
    // VALUE-EQUAL to the action, but location sub-fields (level/offset/tag) must be FULLY MASKED
    // (all-ones). mlx5 errors otherwise ("operation mask not equal" / "dst level must be masked").
    let mut mf_mask: rte_flow_action_modify_field = unsafe { core::mem::zeroed() };
    mf_mask.operation = rte_flow_modify_op::RTE_FLOW_MODIFY_SET; // value-equal
    mf_mask.dst.field = rte_flow_field_id::RTE_FLOW_FIELD_META; // value-equal
    mf_mask.dst.annon1.value = [0xff; 16]; // dst location (level/offset/tag) fully masked
    mf_mask.src.field = rte_flow_field_id::RTE_FLOW_FIELD_VALUE; // value-equal
    mf_mask.src.annon1.value = {
        let mut v = [0u8; 16]; // immediate value: value-equal to the action
        v[0..4].copy_from_slice(&META_VALUE.to_le_bytes());
        v
    };
    mf_mask.width = u32::MAX; // width must be fully masked, not value-equal
    let queue = rte_flow_action_queue { index: 0 };
    let queue_mask = rte_flow_action_queue { index: u16::MAX };
    let g1_acts = [
        action(at::RTE_FLOW_ACTION_TYPE_MODIFY_FIELD, vp(&mf)),
        action(at::RTE_FLOW_ACTION_TYPE_QUEUE, vp(&queue)),
        action(at::RTE_FLOW_ACTION_TYPE_END, null()),
    ];
    let g1_acts_mask = [
        action(at::RTE_FLOW_ACTION_TYPE_MODIFY_FIELD, vp(&mf_mask)),
        action(at::RTE_FLOW_ACTION_TYPE_QUEUE, vp(&queue_mask)),
        action(at::RTE_FLOW_ACTION_TYPE_END, null()),
    ];
    // SAFETY: END-terminated; attr/confs outlive the call.
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
        return Err(format!("g1 actions template (SET_META): {}", err_msg(&err)).into());
    }
    let mut t1_attr: rte_flow_template_table_attr = unsafe { core::mem::zeroed() };
    t1_attr.flow_attr.set_ingress(1);
    t1_attr.flow_attr.group = 1;
    t1_attr.nb_flows = 1;
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
        return Err(format!("g1 SET_META rule: {}", err_msg(&err)).into());
    }
    flush(port, 1)?;
    println!("rule installed: eth -> SET_META({META_VALUE:#010x}) + QUEUE0");

    // ---- inject; read META off each frame ----
    let mut queues = dev.take_queues().ok_or("device queues already taken")?;
    let mut rxq = queues
        .take_rx(RxQueueIndex(0))
        .ok_or("rx queue 0 missing")?;
    println!("polling {secs}s -- inject IPv4 from the peer now...");
    let deadline = Instant::now() + Duration::from_secs(secs);
    let (mut total, mut with_meta) = (0u64, 0u64);
    let mut values = BTreeSet::new();
    while Instant::now() < deadline {
        let burst = rxq.receive();
        if burst.is_empty() {
            std::hint::spin_loop();
            continue;
        }
        for m in &burst {
            let f: &[u8] = m.as_ref();
            if f.len() < 14 || f[6..12] != PEER_SRC_MAC {
                continue;
            }
            total += 1;
            if let Some(v) = m.rx_meta() {
                with_meta += 1;
                values.insert(v);
            }
        }
    }

    println!("=== received={total} with_meta={with_meta} meta_values={values:#x?} ===");
    let pass = with_meta == total && total > 0 && values.len() == 1;
    let exact = values.contains(&META_VALUE);
    println!(
        "VERDICT: {}",
        if pass && exact {
            "PASS -- META delivered to software, full 32 bits intact"
        } else if pass {
            "PARTIAL -- META delivered but value differs (truncated width? check the bits)"
        } else if with_meta > 0 {
            "PARTIAL -- META reached some frames only"
        } else {
            "FAIL -- no META delivered to software in this mode"
        }
    );
    Ok(())
}
