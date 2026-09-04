// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! L2 push/pop/set probe (VLAN + MPLS), and cross-stage shape mutation.
//!
//! Exercises rte_flow header-edit actions on ingress and reports the L2 shape of each delivered
//! packet (so a push/pop/set is observed in the bytes, not inferred):
//!   vlan_push : eth/ipv4            -> OF_PUSH_VLAN                  (expect a VLAN tag appears)
//!   vlan_pop  : eth/vlan/ipv4       -> OF_POP_VLAN                   (expect the tag is gone)
//!   vlan_set  : eth/ipv4 -> OF_PUSH_VLAN -> jump -> OF_SET_VLAN_VID+PCP
//!               (cross-stage: the VLAN field only exists after the group-1 push; set it in group 2)
//!   mpls_push : eth/ipv4            -> OF_PUSH_MPLS                  (expect an MPLS label appears)
//!   mpls_pop  : eth/mpls/ipv4       -> OF_POP_MPLS                  (expect the label is gone)
//!
//! Inject the matching kind from the peer:
//!   push/set: send_frames.py <nd> <mac> <n>                 (plain ipv4)
//!   vlan_pop: send_frames.py <nd> <mac> <n> 0800 x vlan
//!   mpls_pop: send_frames.py <nd> <mac> <n> 0800 x mpls
//!
//! Run as root:  sudo ./l2_probe 0000:e1:00.1 <mode> [seconds=10]

use std::time::{Duration, Instant};

use dataplane_dpdk::dev::{DevConfig, RxOffload};
use dataplane_dpdk::eal;
use dataplane_dpdk::mem::{Pool, PoolConfig, PoolParams};
use dataplane_dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dataplane_dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dataplane_dpdk::socket::Preference;

use dpdk_sys::{
    rte_flow, rte_flow_action, rte_flow_action_jump, rte_flow_action_of_pop_mpls,
    rte_flow_action_of_push_mpls, rte_flow_action_of_push_vlan, rte_flow_action_of_set_vlan_pcp,
    rte_flow_action_of_set_vlan_vid, rte_flow_action_queue, rte_flow_action_type, rte_flow_attr,
    rte_flow_create, rte_flow_error, rte_flow_item, rte_flow_item_type,
};

type Err = Box<dyn std::error::Error>;

const SET_VID: u16 = 0x123;
const SET_PCP: u8 = 5;

fn item(type_: rte_flow_item_type::Type) -> rte_flow_item {
    rte_flow_item {
        type_,
        spec: core::ptr::null(),
        last: core::ptr::null(),
        mask: core::ptr::null(),
    }
}
fn action(type_: rte_flow_action_type::Type, conf: *const core::ffi::c_void) -> rte_flow_action {
    rte_flow_action { type_, conf }
}
fn vp<T>(r: &T) -> *const core::ffi::c_void {
    core::ptr::from_ref(r).cast()
}
fn ingress_attr(group: u32) -> rte_flow_attr {
    let mut a = rte_flow_attr::default();
    a.set_ingress(1);
    a.group = group;
    a
}

/// # Safety
/// `items`/`actions` must be `END`-terminated and their pointers must outlive the call.
unsafe fn install(
    port: u16,
    attr: &rte_flow_attr,
    items: &[rte_flow_item],
    actions: &[rte_flow_action],
    label: &str,
) -> Result<*mut rte_flow, Err> {
    let mut err: rte_flow_error = unsafe { core::mem::zeroed() };
    let flow = unsafe { rte_flow_create(port, attr, items.as_ptr(), actions.as_ptr(), &mut err) };
    if flow.is_null() {
        let msg = if err.message.is_null() {
            "(no message)".to_string()
        } else {
            unsafe { core::ffi::CStr::from_ptr(err.message) }
                .to_string_lossy()
                .into_owned()
        };
        return Err(format!(
            "{label}: rte_flow_create failed (error type {:?}): {msg}",
            err.type_
        )
        .into());
    }
    println!("{label}: rule installed");
    Ok(flow)
}

/// Summarize the L2 shape of a frame and whether the mode's expected edit happened.
fn describe(f: &[u8], mode: &str) -> (String, bool) {
    let et = u16::from_be_bytes([f[12], f[13]]);
    match et {
        0x8100 => {
            let tci = u16::from_be_bytes([f[14], f[15]]);
            let (pcp, dei, vid) = (tci >> 13 & 7, tci >> 12 & 1, tci & 0xfff);
            let inner = u16::from_be_bytes([f[16], f[17]]);
            let ok = match mode {
                "vlan_push" => true,
                "vlan_set" | "vlan_setx" => vid == SET_VID && pcp as u8 == SET_PCP,
                _ => false,
            };
            (
                format!("eth/vlan(vid={vid} pcp={pcp} dei={dei})/0x{inner:04x}"),
                ok,
            )
        }
        0x8847 => {
            let m = u32::from_be_bytes([f[14], f[15], f[16], f[17]]);
            let (label, tc, s, ttl) = (m >> 12 & 0xfffff, m >> 9 & 7, m >> 8 & 1, m & 0xff);
            (
                format!("eth/mpls(label={label} tc={tc} s={s} ttl={ttl})"),
                mode == "mpls_push",
            )
        }
        0x0800 => (
            "eth/ipv4".to_string(),
            mode == "vlan_pop" || mode == "mpls_pop",
        ),
        other => (format!("eth/0x{other:04x}"), false),
    }
}

fn main() -> Result<(), Err> {
    let mut args = std::env::args().skip(1);
    let bdf = args.next().unwrap_or_else(|| "0000:e1:00.1".to_string());
    let mode = args.next().unwrap_or_else(|| "vlan_push".into());
    let secs: u64 = args.next().unwrap_or_else(|| "10".into()).parse()?;

    let eal = eal::init([
        "-a",
        bdf.as_str(),
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
        PoolConfig::new("l2_pool", PoolParams::default()).map_err(|e| format!("pool: {e:?}"))?,
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
    println!("port {bdf} index {port}; mode={mode}");
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
    let dev = dev.start().map_err(|e| format!("dev start: {e}"))?;

    use rte_flow_action_type::{
        RTE_FLOW_ACTION_TYPE_END, RTE_FLOW_ACTION_TYPE_JUMP, RTE_FLOW_ACTION_TYPE_OF_POP_MPLS,
        RTE_FLOW_ACTION_TYPE_OF_POP_VLAN, RTE_FLOW_ACTION_TYPE_OF_PUSH_MPLS,
        RTE_FLOW_ACTION_TYPE_OF_PUSH_VLAN, RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_PCP,
        RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID, RTE_FLOW_ACTION_TYPE_QUEUE,
    };
    use rte_flow_item_type::{
        RTE_FLOW_ITEM_TYPE_END, RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_VLAN,
    };

    let attr0 = ingress_attr(0);
    let attr1 = ingress_attr(1);
    let attr2 = ingress_attr(2);
    let jump1 = rte_flow_action_jump { group: 1 };
    let jump2 = rte_flow_action_jump { group: 2 };
    let queue = rte_flow_action_queue { index: 0 };
    let push_vlan = rte_flow_action_of_push_vlan {
        ethertype: 0x8100u16.to_be(),
    };
    let push_mpls = rte_flow_action_of_push_mpls {
        ethertype: 0x8847u16.to_be(),
    };
    let pop_mpls = rte_flow_action_of_pop_mpls {
        ethertype: 0x0800u16.to_be(),
    };
    let set_vid = rte_flow_action_of_set_vlan_vid {
        vlan_vid: SET_VID.to_be(),
    };
    let set_pcp = rte_flow_action_of_set_vlan_pcp { vlan_pcp: SET_PCP };

    let eth = [item(RTE_FLOW_ITEM_TYPE_ETH), item(RTE_FLOW_ITEM_TYPE_END)];
    // POP_VLAN requires the rule to match the (outer) VLAN it strips.
    let eth_vlan = [
        item(RTE_FLOW_ITEM_TYPE_ETH),
        item(RTE_FLOW_ITEM_TYPE_VLAN),
        item(RTE_FLOW_ITEM_TYPE_END),
    ];
    let g0_acts = [
        action(RTE_FLOW_ACTION_TYPE_JUMP, vp(&jump1)),
        action(RTE_FLOW_ACTION_TYPE_END, core::ptr::null()),
    ];
    let q_end = |first: rte_flow_action| {
        [
            first,
            action(RTE_FLOW_ACTION_TYPE_QUEUE, vp(&queue)),
            action(RTE_FLOW_ACTION_TYPE_END, core::ptr::null()),
        ]
    };

    // SAFETY: every list is END-terminated and all conf locals outlive the install calls.
    unsafe {
        install(port, &attr0, &eth, &g0_acts, "g0 eth->jump1")?;
        match mode.as_str() {
            "vlan_push" => {
                install(
                    port,
                    &attr1,
                    &eth,
                    &q_end(action(RTE_FLOW_ACTION_TYPE_OF_PUSH_VLAN, vp(&push_vlan))),
                    "g1 PUSH_VLAN",
                )?;
            }
            "vlan_pop" => {
                install(
                    port,
                    &attr1,
                    &eth_vlan,
                    &q_end(action(RTE_FLOW_ACTION_TYPE_OF_POP_VLAN, core::ptr::null())),
                    "g1 POP_VLAN",
                )?;
            }
            "vlan_setx" => {
                // cross-stage set on an EXISTING tag (ingress can't push): match VLAN in g1, jump,
                // then set its VID/PCP in g2.
                let g1 = [
                    action(RTE_FLOW_ACTION_TYPE_JUMP, vp(&jump2)),
                    action(RTE_FLOW_ACTION_TYPE_END, core::ptr::null()),
                ];
                install(port, &attr1, &eth_vlan, &g1, "g1 match-VLAN+jump2")?;
                let g2 = [
                    action(RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID, vp(&set_vid)),
                    action(RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_PCP, vp(&set_pcp)),
                    action(RTE_FLOW_ACTION_TYPE_QUEUE, vp(&queue)),
                    action(RTE_FLOW_ACTION_TYPE_END, core::ptr::null()),
                ];
                install(port, &attr2, &eth_vlan, &g2, "g2 SET_VLAN_VID+PCP")?;
            }
            "mpls_push" => {
                install(
                    port,
                    &attr1,
                    &eth,
                    &q_end(action(RTE_FLOW_ACTION_TYPE_OF_PUSH_MPLS, vp(&push_mpls))),
                    "g1 PUSH_MPLS",
                )?;
            }
            "mpls_pop" => {
                install(
                    port,
                    &attr1,
                    &eth,
                    &q_end(action(RTE_FLOW_ACTION_TYPE_OF_POP_MPLS, vp(&pop_mpls))),
                    "g1 POP_MPLS",
                )?;
            }
            "vlan_set" => {
                let g1 = [
                    action(RTE_FLOW_ACTION_TYPE_OF_PUSH_VLAN, vp(&push_vlan)),
                    action(RTE_FLOW_ACTION_TYPE_JUMP, vp(&jump2)),
                    action(RTE_FLOW_ACTION_TYPE_END, core::ptr::null()),
                ];
                install(port, &attr1, &eth, &g1, "g1 PUSH_VLAN+jump2")?;
                let g2 = [
                    action(RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID, vp(&set_vid)),
                    action(RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_PCP, vp(&set_pcp)),
                    action(RTE_FLOW_ACTION_TYPE_QUEUE, vp(&queue)),
                    action(RTE_FLOW_ACTION_TYPE_END, core::ptr::null()),
                ];
                install(port, &attr2, &eth, &g2, "g2 SET_VLAN_VID+PCP")?;
            }
            other => return Err(format!("unknown mode '{other}'").into()),
        }
    }

    let mut queues = dev.take_queues().ok_or("device queues already taken")?;
    let mut rxq = queues
        .take_rx(RxQueueIndex(0))
        .ok_or("rx queue 0 missing")?;
    println!("polling {secs}s -- inject now...");
    let deadline = Instant::now() + Duration::from_secs(secs);
    let (mut total, mut ok) = (0u64, 0u64);
    let mut sampled = 0u32;
    while Instant::now() < deadline {
        let burst = rxq.receive();
        if burst.is_empty() {
            std::hint::spin_loop();
            continue;
        }
        for m in &burst {
            let f: &[u8] = m.as_ref();
            if f.len() < 18 || f[6..12] != [0x58, 0xa2, 0xe1, 0x04, 0x31, 0xa8] {
                continue;
            }
            total += 1;
            let (desc, good) = describe(f, &mode);
            if good {
                ok += 1;
            }
            if sampled < 5 {
                println!(
                    "  {desc}  -> {}",
                    if good { "expected" } else { "UNEXPECTED" }
                );
                sampled += 1;
            }
        }
    }
    println!("=== summary (mode={mode}) ===  matched: {ok}/{total}");
    println!(
        "VERDICT: {}",
        if total == 0 {
            "INCONCLUSIVE -- no frames"
        } else if ok == total {
            "PASS"
        } else {
            "FAIL / partial"
        }
    );
    Ok(())
}
