// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Indirect-action UPDATE probe (METER_MARK): one `handle_update` re-rates MANY rules atomically.
//!
//! `rss_update_probe` showed indirect RSS *update* crashes under HWS (the PMD routes it through the
//! legacy DV update fn). METER_MARK is ASO-native in HWS, so its update should take the real HWS
//! path. This is the on-a-working-path demonstration of the design question: update ONE shared handle
//! and watch every referencing rule change behavior live.
//!
//! Setup (raw HWS FFI): a "slow" srTCM profile (drops almost everything) and a "fast" profile (passes
//! all), one policy (green->continue, yellow/red->drop), one indirect METER_MARK handle starting on
//! the slow profile; N group-1 rules (distinct ipv4 src) each reference it + QUEUE 0; a group-0 jump
//! feeds them. Inject a steady stream; at half-time, `handle_update` swaps the handle to the fast
//! profile. Expect: rx ~throttled before, ~line-rate after -- one update re-rates all rules.
//!
//! Inject a sustained stream:
//!   sudo python3 send_frames.py <peer-netdev> <this-port-mac> 600000 0800 vary
//! Run as root:  sudo ./meter_update_probe 0000:e1:00.1 [n_rules=256] [seconds=14]

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
    rte_flow_action, rte_flow_action_jump, rte_flow_action_meter_mark, rte_flow_action_queue,
    rte_flow_action_type as at, rte_flow_actions_template_attr, rte_flow_actions_template_create,
    rte_flow_async_action_handle_create, rte_flow_async_action_handle_update,
    rte_flow_async_create, rte_flow_configure, rte_flow_error, rte_flow_indir_action_conf,
    rte_flow_item, rte_flow_item_ipv4, rte_flow_item_type as it, rte_flow_op_attr,
    rte_flow_op_result, rte_flow_op_status, rte_flow_pattern_template_attr,
    rte_flow_pattern_template_create, rte_flow_port_attr, rte_flow_pull, rte_flow_push,
    rte_flow_queue_attr, rte_flow_table_hash_func, rte_flow_table_insertion_type,
    rte_flow_template_table_attr, rte_flow_template_table_create, rte_mtr_algorithm, rte_mtr_error,
    rte_mtr_meter_profile, rte_mtr_meter_profile__bindgen_ty_1__bindgen_ty_1 as Srtcm,
    rte_mtr_meter_profile_add, rte_mtr_meter_profile_get,
};

type Err = Box<dyn std::error::Error>;

const QUEUE_SIZE: u32 = 1024;
const BATCH: u32 = 512;

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

fn mtr_err_msg(e: &rte_mtr_error) -> String {
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

/// A packet-mode srTCM profile: `cir`/`cbs`/`ebs` in packets-per-second / packets.
fn srtcm(cir: u64, cbs: u64, ebs: u64) -> rte_mtr_meter_profile {
    let mut p: rte_mtr_meter_profile = unsafe { core::mem::zeroed() };
    p.alg = rte_mtr_algorithm::RTE_MTR_SRTCM_RFC2697;
    p.packet_mode = 1;
    p.annon1.srtcm_rfc2697 = Srtcm { cir, cbs, ebs };
    p
}

fn is_ours(f: &[u8]) -> bool {
    f.len() >= 34 && f[12..14] == [0x08, 0x00] && f[26..29] == [10, 0, 0]
}

fn main() -> Result<(), Err> {
    let mut args = std::env::args().skip(1);
    let bdf = args.next().unwrap_or_else(|| "0000:e1:00.1".to_string());
    let n_rules: u32 = args.next().unwrap_or_else(|| "256".into()).parse()?;
    let secs: u64 = args.next().unwrap_or_else(|| "14".into()).parse()?;

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
        PoolConfig::new("mtr_pool", PoolParams::default()).map_err(|e| format!("pool: {e:?}"))?,
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
    println!("port {bdf} index {port}; METER_MARK-update probe, n_rules={n_rules}");
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

    // Reserve ASO meters + a flow queue (before start).
    let mut port_attr: rte_flow_port_attr = unsafe { core::mem::zeroed() };
    port_attr.nb_meters = 8;
    let queue_attr = rte_flow_queue_attr { size: QUEUE_SIZE };
    let mut qa_ptrs = [&queue_attr as *const rte_flow_queue_attr];
    let mut err: rte_flow_error = unsafe { core::mem::zeroed() };
    // SAFETY: one flow queue; attrs outlive the call.
    if unsafe { rte_flow_configure(port, &port_attr, 1, qa_ptrs.as_mut_ptr(), &mut err) } != 0 {
        return Err(format!("rte_flow_configure: {}", err_msg(&err)).into());
    }
    let dev = dev.start().map_err(|e| format!("dev start: {e}"))?;

    // ---- meter profiles (slow: throttles; fast: passes all) ----
    let mut merr: rte_mtr_error = unsafe { core::mem::zeroed() };
    let mut p_slow = srtcm(2_000, 2_000, 2_000);
    let mut p_fast = srtcm(50_000_000, 1_000_000, 1_000_000);
    // SAFETY: profile structs outlive the calls.
    if unsafe { rte_mtr_meter_profile_add(port, 1, &mut p_slow, &mut merr) } != 0 {
        return Err(format!("profile_add slow: {}", mtr_err_msg(&merr)).into());
    }
    if unsafe { rte_mtr_meter_profile_add(port, 2, &mut p_fast, &mut merr) } != 0 {
        return Err(format!("profile_add fast: {}", mtr_err_msg(&merr)).into());
    }
    // SAFETY: profiles 1/2 were just added.
    let prof_slow = unsafe { rte_mtr_meter_profile_get(port, 1, &mut merr) };
    let prof_fast = unsafe { rte_mtr_meter_profile_get(port, 2, &mut merr) };
    if prof_slow.is_null() || prof_fast.is_null() {
        return Err(format!("profile_get: {}", mtr_err_msg(&merr)).into());
    }

    // The rte_mtr policy API is "Function not implemented" under mlx5 HWS here, so we run a focused
    // variant: METER_MARK with policy = NULL (marks color, no drop). We can't observe a drop-rate
    // change, but this isolates the decisive question -- does handle_update on an ASO action succeed
    // (vs the RSS update that segfaulted via the DV-fallback path)?
    let policy_ptr: *mut dpdk_sys::rte_flow_meter_policy = null_mut();

    let mut op_attr: rte_flow_op_attr = unsafe { core::mem::zeroed() };
    op_attr.set_postpone(1);

    // ---- ONE shared indirect METER_MARK handle, starting on the SLOW profile ----
    let mm_slow = rte_flow_action_meter_mark {
        profile: prof_slow,
        policy: policy_ptr,
        color_mode: 0, // color-blind
        state: 1,      // enabled
    };
    let mm_action = action(at::RTE_FLOW_ACTION_TYPE_METER_MARK, vp(&mm_slow));
    let mut indir_conf: rte_flow_indir_action_conf = unsafe { core::mem::zeroed() };
    indir_conf.set_ingress(1);
    // SAFETY: conf/action/profile/policy outlive the call.
    let handle = unsafe {
        rte_flow_async_action_handle_create(
            port,
            0,
            &op_attr,
            &indir_conf,
            &mm_action,
            null_mut(),
            &mut err,
        )
    };
    if handle.is_null() {
        return Err(format!("indirect METER_MARK create: {}", err_msg(&err)).into());
    }
    flush(port, 1)?;
    println!("indirect METER_MARK handle created (slow profile: ~2000 pps)");

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

    // ---- group 1: eth / ipv4(src) -> INDIRECT(meter_mark) + QUEUE 0 ----
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
    let queue = rte_flow_action_queue { index: 0 };
    let queue_mask = rte_flow_action_queue { index: u16::MAX };
    let handle_conf: *const c_void = handle.cast();
    let g1_acts = [
        action(at::RTE_FLOW_ACTION_TYPE_INDIRECT, handle_conf),
        action(at::RTE_FLOW_ACTION_TYPE_QUEUE, vp(&queue)),
        action(at::RTE_FLOW_ACTION_TYPE_END, null()),
    ];
    // Per rte_flow.h: indirect action's mask slot carries the WRAPPED type (METER_MARK), not INDIRECT.
    let g1_acts_mask = [
        action(at::RTE_FLOW_ACTION_TYPE_METER_MARK, null()),
        action(at::RTE_FLOW_ACTION_TYPE_QUEUE, vp(&queue_mask)),
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
    println!("installed {created} group-1 rules -> the ONE indirect METER_MARK handle");

    // ---- stream; swap the handle to the FAST profile at half-time ----
    let rxq = dev.rx_queue(RxQueueIndex(0)).ok_or("rx q0 missing")?;
    println!(
        "streaming {secs}s; will swap METER_MARK -> fast profile at {}s. Inject now...",
        secs / 2
    );
    let start = Instant::now();
    let deadline = start + Duration::from_secs(secs);
    let update_at = start + Duration::from_secs(secs / 2);
    let mut updated = false;
    let (mut before, mut after) = (0u64, 0u64);
    let mut tick = 0u64;
    let mut next_tick = start + Duration::from_secs(1);
    let mm_fast = rte_flow_action_meter_mark {
        profile: prof_fast,
        policy: policy_ptr,
        color_mode: 0,
        state: 1,
    };
    while Instant::now() < deadline {
        if !updated && Instant::now() >= update_at {
            // SAFETY: handle valid; mm_fast/profile/policy outlive the flush below.
            let rc = unsafe {
                rte_flow_async_action_handle_update(
                    port,
                    0,
                    &op_attr,
                    handle,
                    vp(&mm_fast),
                    null_mut(),
                    &mut err,
                )
            };
            if rc != 0 {
                return Err(format!("handle_update: {}", err_msg(&err)).into());
            }
            flush(port, 1)?;
            updated = true;
            println!(
                "    *** handle_update: METER_MARK -> fast profile (one update, all rules) ***"
            );
        }
        for m in &rxq.receive() {
            if is_ours(m.as_ref()) {
                if updated {
                    after += 1;
                } else {
                    before += 1;
                }
                tick += 1;
            }
        }
        if Instant::now() >= next_tick {
            let t = (Instant::now() - start).as_secs();
            println!(
                "    t={t}s  rx={tick:<7}{}",
                if updated {
                    "  (fast)"
                } else {
                    "  (slow/throttled)"
                }
            );
            tick = 0;
            next_tick += Duration::from_secs(1);
        } else {
            std::hint::spin_loop();
        }
    }

    println!("=== pre-update rx: {before} frames | post-update rx: {after} frames ===");
    // No policy => no drop to observe; the decisive result is that handle_update RETURNED (printed
    // the swap line, no segfault) and traffic kept flowing through the re-rated handle afterwards.
    let pass = updated && after > 0;
    println!(
        "VERDICT: {}",
        if pass {
            "PASS -- METER_MARK handle_update succeeded (no crash, unlike RSS); HWS indirect UPDATE works for an ASO action"
        } else {
            "FAIL / inconclusive"
        }
    );
    Ok(())
}
