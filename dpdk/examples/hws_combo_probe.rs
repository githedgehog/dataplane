// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! HWS action-combination probe: which `{MODIFY_FIELD, MARK, QUEUE}` orderings/combos does mlx5 HWS
//! accept (legacy+hmfs)? The trap-metadata design wants MARK + META on one trapped packet, but
//! `MODIFY_FIELD(META) + MARK + QUEUE` was rejected ("Invalid action_type sequence: MODIFY_HDR, TAG,
//! TIR"). This sweeps combos to separate two hypotheses:
//!   - ORDERING: mlx5 HWS wants a fixed action order -> reordering MARK vs MODIFY_FIELD fixes it.
//!   - REGISTER CONFLICT: MARK and META share REG_C_* and can't coexist under dv_xmeta_en=4 ->
//!     a hard limit. Testing MODIFY_FIELD on a real header field (IPv4-dst) vs META isolates this:
//!     if MODIFY_FIELD(IPv4dst)+MARK works but MODIFY_FIELD(META)+MARK doesn't, it's a META/MARK clash.
//!
//! Only reaches template-table creation (where mlx5 validates the action combo); no injection.
//! Run as root:  sudo ./hws_combo_probe 0000:e1:00.1 [dv_xmeta_en=4]

use core::ffi::c_void;
use core::ptr::null;

use dataplane_dpdk::dev::{DevConfig, RxOffload};
use dataplane_dpdk::eal;
use dataplane_dpdk::mem::{Pool, PoolConfig, PoolParams};
use dataplane_dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dataplane_dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dataplane_dpdk::socket::Preference;

use dpdk_sys::{
    rte_flow_action, rte_flow_action_mark, rte_flow_action_modify_field, rte_flow_action_queue,
    rte_flow_action_type as at, rte_flow_actions_template_attr, rte_flow_actions_template_create,
    rte_flow_configure, rte_flow_error, rte_flow_field_id, rte_flow_item, rte_flow_item_type as it,
    rte_flow_modify_op, rte_flow_pattern_template_attr, rte_flow_pattern_template_create,
    rte_flow_port_attr, rte_flow_queue_attr, rte_flow_table_hash_func,
    rte_flow_table_insertion_type, rte_flow_template_table_attr, rte_flow_template_table_create,
};

type Err = Box<dyn std::error::Error>;

fn err_msg(e: &rte_flow_error) -> String {
    if e.message.is_null() {
        format!("type {:?}: (no message)", e.type_)
    } else {
        // SAFETY: non-null message is a static C string owned by the PMD.
        let m = unsafe { core::ffi::CStr::from_ptr(e.message) }
            .to_string_lossy()
            .into_owned();
        format!("type {:?}: {m}", e.type_)
    }
}

fn item(type_: it::Type) -> rte_flow_item {
    rte_flow_item {
        type_,
        spec: null(),
        last: null(),
        mask: null(),
    }
}

fn action(type_: at::Type, conf: *const c_void) -> rte_flow_action {
    rte_flow_action { type_, conf }
}

fn vp<T>(r: &T) -> *const c_void {
    core::ptr::from_ref(r).cast()
}

fn mf_set(dst: rte_flow_field_id::Type, val: u32) -> rte_flow_action_modify_field {
    let mut mf: rte_flow_action_modify_field = unsafe { core::mem::zeroed() };
    mf.operation = rte_flow_modify_op::RTE_FLOW_MODIFY_SET;
    mf.dst.field = dst;
    mf.src.field = rte_flow_field_id::RTE_FLOW_FIELD_VALUE;
    mf.src.annon1.value = {
        let mut v = [0u8; 16];
        v[0..4].copy_from_slice(&val.to_le_bytes());
        v
    };
    mf.width = 32;
    mf
}

fn mf_mask(dst: rte_flow_field_id::Type, val: u32) -> rte_flow_action_modify_field {
    // Hybrid mask: operation/field value-equal, dst location fully masked, width fully masked.
    let mut m: rte_flow_action_modify_field = unsafe { core::mem::zeroed() };
    m.operation = rte_flow_modify_op::RTE_FLOW_MODIFY_SET;
    m.dst.field = dst;
    m.dst.annon1.value = [0xff; 16];
    m.src.field = rte_flow_field_id::RTE_FLOW_FIELD_VALUE;
    m.src.annon1.value = {
        let mut v = [0u8; 16];
        v[0..4].copy_from_slice(&val.to_le_bytes());
        v
    };
    m.width = u32::MAX;
    m
}

fn main() -> Result<(), Err> {
    let mut args = std::env::args().skip(1);
    let bdf = args.next().unwrap_or_else(|| "0000:e1:00.1".to_string());
    let xmeta = args.next().unwrap_or_else(|| "4".to_string());

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
    let info = eal.dev.iter().next().ok_or("no DPDK port probed")?;
    let pool = Pool::new_pkt_pool(
        PoolConfig::new("hc_pool", PoolParams::default()).map_err(|e| format!("pool: {e:?}"))?,
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
    let _dev = dev.start().map_err(|e| format!("dev start: {e}"))?;
    println!("port {port} started; dv_xmeta_en={xmeta}; sweeping HWS action combos\n");

    // Pattern template (eth/end, ingress) -- shared across combos.
    let mut pt_attr: rte_flow_pattern_template_attr = unsafe { core::mem::zeroed() };
    pt_attr.set_ingress(1);
    let eth_pat = [
        item(it::RTE_FLOW_ITEM_TYPE_ETH),
        item(it::RTE_FLOW_ITEM_TYPE_END),
    ];

    // Pre-build action confs (must outlive the table-create calls).
    let mf_meta = mf_set(rte_flow_field_id::RTE_FLOW_FIELD_META, 0xDEAD_BEEF);
    let mf_meta_m = mf_mask(rte_flow_field_id::RTE_FLOW_FIELD_META, 0xDEAD_BEEF);
    let mf_ip = mf_set(rte_flow_field_id::RTE_FLOW_FIELD_IPV4_DST, 0x0A09_0909);
    let mf_ip_m = mf_mask(rte_flow_field_id::RTE_FLOW_FIELD_IPV4_DST, 0x0A09_0909);
    let mark = rte_flow_action_mark { id: 0x4242 };
    let mark_m = rte_flow_action_mark { id: u32::MAX };
    let q = rte_flow_action_queue { index: 0 };
    let q_m = rte_flow_action_queue { index: u16::MAX };

    let mf_meta_a = action(at::RTE_FLOW_ACTION_TYPE_MODIFY_FIELD, vp(&mf_meta));
    let mf_meta_a_m = action(at::RTE_FLOW_ACTION_TYPE_MODIFY_FIELD, vp(&mf_meta_m));
    let mf_ip_a = action(at::RTE_FLOW_ACTION_TYPE_MODIFY_FIELD, vp(&mf_ip));
    let mf_ip_a_m = action(at::RTE_FLOW_ACTION_TYPE_MODIFY_FIELD, vp(&mf_ip_m));
    let mark_a = action(at::RTE_FLOW_ACTION_TYPE_MARK, vp(&mark));
    let mark_a_m = action(at::RTE_FLOW_ACTION_TYPE_MARK, vp(&mark_m));
    let q_a = action(at::RTE_FLOW_ACTION_TYPE_QUEUE, vp(&q));
    let q_a_m = action(at::RTE_FLOW_ACTION_TYPE_QUEUE, vp(&q_m));
    let end_a = action(at::RTE_FLOW_ACTION_TYPE_END, null());

    // Each combo: (label, [(action, mask)...]) -- END appended in the builder.
    let combos: [(&str, Vec<(rte_flow_action, rte_flow_action)>); 9] = [
        ("MARK, QUEUE", vec![(mark_a, mark_a_m), (q_a, q_a_m)]),
        (
            "MF(META), QUEUE",
            vec![(mf_meta_a, mf_meta_a_m), (q_a, q_a_m)],
        ),
        (
            "MF(IPv4dst), QUEUE",
            vec![(mf_ip_a, mf_ip_a_m), (q_a, q_a_m)],
        ),
        (
            "MF(META), MARK, QUEUE",
            vec![(mf_meta_a, mf_meta_a_m), (mark_a, mark_a_m), (q_a, q_a_m)],
        ),
        (
            "MARK, MF(META), QUEUE",
            vec![(mark_a, mark_a_m), (mf_meta_a, mf_meta_a_m), (q_a, q_a_m)],
        ),
        (
            "MF(IPv4dst), MARK, QUEUE",
            vec![(mf_ip_a, mf_ip_a_m), (mark_a, mark_a_m), (q_a, q_a_m)],
        ),
        (
            "MARK, MF(IPv4dst), QUEUE",
            vec![(mark_a, mark_a_m), (mf_ip_a, mf_ip_a_m), (q_a, q_a_m)],
        ),
        (
            "MF(IPv4dst), MF(META), MARK, QUEUE",
            vec![
                (mf_ip_a, mf_ip_a_m),
                (mf_meta_a, mf_meta_a_m),
                (mark_a, mark_a_m),
                (q_a, q_a_m),
            ],
        ),
        (
            "MARK, MF(IPv4dst), MF(META), QUEUE (full, ordered)",
            vec![
                (mark_a, mark_a_m),
                (mf_ip_a, mf_ip_a_m),
                (mf_meta_a, mf_meta_a_m),
                (q_a, q_a_m),
            ],
        ),
    ];

    for (label, pairs) in &combos {
        let mut acts: Vec<rte_flow_action> = pairs.iter().map(|p| p.0).collect();
        let mut masks: Vec<rte_flow_action> = pairs.iter().map(|p| p.1).collect();
        acts.push(end_a);
        masks.push(end_a);
        let mut e: rte_flow_error = unsafe { core::mem::zeroed() };
        // SAFETY: END-terminated arrays; eth_pat/attrs/confs outlive the calls.
        let pt =
            unsafe { rte_flow_pattern_template_create(port, &pt_attr, eth_pat.as_ptr(), &mut e) };
        if pt.is_null() {
            println!("  [{label:38}] pattern-template FAIL: {}", err_msg(&e));
            continue;
        }
        let mut at_attr: rte_flow_actions_template_attr = unsafe { core::mem::zeroed() };
        at_attr.set_ingress(1);
        let att = unsafe {
            rte_flow_actions_template_create(port, &at_attr, acts.as_ptr(), masks.as_ptr(), &mut e)
        };
        if att.is_null() {
            println!("  [{label:38}] actions-template FAIL: {}", err_msg(&e));
            continue;
        }
        let mut t_attr: rte_flow_template_table_attr = unsafe { core::mem::zeroed() };
        t_attr.flow_attr.set_ingress(1);
        t_attr.flow_attr.group = 1;
        t_attr.nb_flows = 1;
        t_attr.insertion_type =
            rte_flow_table_insertion_type::RTE_FLOW_TABLE_INSERTION_TYPE_PATTERN;
        t_attr.hash_func = rte_flow_table_hash_func::RTE_FLOW_TABLE_HASH_FUNC_DEFAULT;
        let mut pts = [pt];
        let mut ats = [att];
        let table = unsafe {
            rte_flow_template_table_create(
                port,
                &t_attr,
                pts.as_mut_ptr(),
                1,
                ats.as_mut_ptr(),
                1,
                &mut e,
            )
        };
        if table.is_null() {
            println!("  [{label:38}] table-create FAIL: {}", err_msg(&e));
        } else {
            println!("  [{label:38}] OK");
        }
    }
    Ok(())
}
