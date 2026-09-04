// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Cross-stage carry probe (`SET_TAG` / `SET_META`), trust-ladder primitive.
//!
//! Where the MARK probe shows a value reaching *software*, this shows a value carried *between
//! hardware pipeline stages*: group 1 sets a TAG (a transient register, explicitly not delivered to
//! the application) or META on every IPv4 packet and jumps to group 2; group 2 *matches* that
//! TAG/META and, only on a match, applies a `MARK` we already trust.  If the downstream MARK reaches
//! the mbuf, the set-in-stage-1 / match-in-stage-2 round-trip worked in hardware.  This is the
//! mechanism a multi-stage offload pipeline (offload-trust model, Rule 2) uses to carry context
//! forward before any trap.
//!
//! Inject IPv4 from the cabled peer:
//!   sudo python3 send_frames.py <peer-netdev> <this-port-mac> <count>
//!
//! Run as root:
//!   sudo ./stage_probe 0000:e1:00.1 [tag|meta] [seconds=10] [val_hex=1234] [mark_hex=5151]
//! For META on mlx5 you may need the extended-metadata devarg, e.g.
//!   sudo ./stage_probe 0000:e1:00.1,dv_xmeta_en=1 meta

use std::time::{Duration, Instant};

use dataplane_dpdk::dev::{DevConfig, RxOffload};
use dataplane_dpdk::eal;
use dataplane_dpdk::mem::{Pool, PoolConfig, PoolParams};
use dataplane_dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dataplane_dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dataplane_dpdk::socket::Preference;

use dpdk_sys::{
    rte_flow, rte_flow_action, rte_flow_action_jump, rte_flow_action_mark, rte_flow_action_queue,
    rte_flow_action_set_meta, rte_flow_action_set_tag, rte_flow_action_type, rte_flow_attr,
    rte_flow_create, rte_flow_error, rte_flow_item, rte_flow_item_meta, rte_flow_item_tag,
    rte_flow_item_type,
};

type Err = Box<dyn std::error::Error>;

fn item(type_: rte_flow_item_type::Type) -> rte_flow_item {
    rte_flow_item {
        type_,
        spec: core::ptr::null(),
        last: core::ptr::null(),
        mask: core::ptr::null(),
    }
}

fn item_spec(
    type_: rte_flow_item_type::Type,
    spec: *const core::ffi::c_void,
    mask: *const core::ffi::c_void,
) -> rte_flow_item {
    rte_flow_item {
        type_,
        spec,
        last: core::ptr::null(),
        mask,
    }
}

fn action(type_: rte_flow_action_type::Type, conf: *const core::ffi::c_void) -> rte_flow_action {
    rte_flow_action { type_, conf }
}

/// Erase a typed reference to a `*const c_void` for an rte_flow `spec`/`conf` slot.
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
/// `items`/`actions` must be `END`-terminated and their `spec`/`conf` pointers must outlive the call.
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

fn main() -> Result<(), Err> {
    let mut args = std::env::args().skip(1);
    let bdf = args.next().unwrap_or_else(|| "0000:e1:00.1".to_string());
    let mode = args.next().unwrap_or_else(|| "tag".into());
    let secs: u64 = args.next().unwrap_or_else(|| "10".into()).parse()?;
    let val = u32::from_str_radix(&args.next().unwrap_or_else(|| "1234".into()), 16)?;
    let mark_id = u32::from_str_radix(&args.next().unwrap_or_else(|| "5151".into()), 16)?;

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
    let info = eal
        .dev
        .iter()
        .next()
        .ok_or("no DPDK port probed -- check the BDF / run as root")?;

    let pool = Pool::new_pkt_pool(
        PoolConfig::new("stage_pool", PoolParams::default()).map_err(|e| format!("pool: {e:?}"))?,
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
    println!(
        "port {bdf} probed as dpdk index {port}; mode={mode} val=0x{val:x} mark=0x{mark_id:x}"
    );
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
        RTE_FLOW_ACTION_TYPE_END, RTE_FLOW_ACTION_TYPE_JUMP, RTE_FLOW_ACTION_TYPE_MARK,
        RTE_FLOW_ACTION_TYPE_QUEUE, RTE_FLOW_ACTION_TYPE_SET_META, RTE_FLOW_ACTION_TYPE_SET_TAG,
    };
    use rte_flow_item_type::{
        RTE_FLOW_ITEM_TYPE_END, RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
        RTE_FLOW_ITEM_TYPE_META, RTE_FLOW_ITEM_TYPE_TAG,
    };

    let attr0 = ingress_attr(0);
    let attr1 = ingress_attr(1);
    let attr2 = ingress_attr(2);
    let jump1 = rte_flow_action_jump { group: 1 };
    let jump2 = rte_flow_action_jump { group: 2 };
    let mark = rte_flow_action_mark { id: mark_id };
    let queue = rte_flow_action_queue { index: 0 };

    let eth_ipv4 = [
        item(RTE_FLOW_ITEM_TYPE_ETH),
        item(RTE_FLOW_ITEM_TYPE_IPV4),
        item(RTE_FLOW_ITEM_TYPE_END),
    ];
    let g0_items = [item(RTE_FLOW_ITEM_TYPE_ETH), item(RTE_FLOW_ITEM_TYPE_END)];
    let g0_acts = [
        action(RTE_FLOW_ACTION_TYPE_JUMP, vp(&jump1)),
        action(RTE_FLOW_ACTION_TYPE_END, core::ptr::null()),
    ];
    let mark_acts = [
        action(RTE_FLOW_ACTION_TYPE_MARK, vp(&mark)),
        action(RTE_FLOW_ACTION_TYPE_QUEUE, vp(&queue)),
        action(RTE_FLOW_ACTION_TYPE_END, core::ptr::null()),
    ];

    // SAFETY: every list is END-terminated and all spec/conf pointers live until install returns.
    unsafe {
        install(port, &attr0, &g0_items, &g0_acts, "g0 eth->jump1")?;
        match mode.as_str() {
            "tag" => {
                let set_tag = rte_flow_action_set_tag {
                    data: val,
                    mask: u32::MAX,
                    index: 0,
                };
                let g1_acts = [
                    action(RTE_FLOW_ACTION_TYPE_SET_TAG, vp(&set_tag)),
                    action(RTE_FLOW_ACTION_TYPE_JUMP, vp(&jump2)),
                    action(RTE_FLOW_ACTION_TYPE_END, core::ptr::null()),
                ];
                install(port, &attr1, &eth_ipv4, &g1_acts, "g1 ipv4->SET_TAG+jump2")?;
                let tag_spec = rte_flow_item_tag {
                    data: val,
                    index: 0,
                };
                let tag_mask = rte_flow_item_tag {
                    data: u32::MAX,
                    index: 0xff,
                };
                let g2_items = [
                    item_spec(RTE_FLOW_ITEM_TYPE_TAG, vp(&tag_spec), vp(&tag_mask)),
                    item(RTE_FLOW_ITEM_TYPE_END),
                ];
                install(port, &attr2, &g2_items, &mark_acts, "g2 match TAG->MARK")?;
            }
            "meta" => {
                let set_meta = rte_flow_action_set_meta {
                    data: val,
                    mask: u32::MAX,
                };
                let g1_acts = [
                    action(RTE_FLOW_ACTION_TYPE_SET_META, vp(&set_meta)),
                    action(RTE_FLOW_ACTION_TYPE_JUMP, vp(&jump2)),
                    action(RTE_FLOW_ACTION_TYPE_END, core::ptr::null()),
                ];
                install(port, &attr1, &eth_ipv4, &g1_acts, "g1 ipv4->SET_META+jump2")?;
                let meta_spec = rte_flow_item_meta { data: val };
                let meta_mask = rte_flow_item_meta { data: u32::MAX };
                let g2_items = [
                    item_spec(RTE_FLOW_ITEM_TYPE_META, vp(&meta_spec), vp(&meta_mask)),
                    item(RTE_FLOW_ITEM_TYPE_END),
                ];
                install(port, &attr2, &g2_items, &mark_acts, "g2 match META->MARK")?;
            }
            other => return Err(format!("unknown mode '{other}' (use tag|meta)").into()),
        }
    }

    let mut queues = dev.take_queues().ok_or("device queues already taken")?;
    let mut rxq = queues
        .take_rx(RxQueueIndex(0))
        .ok_or("rx queue 0 missing")?;
    println!("polling for {secs}s -- inject IPv4 from the peer now...");
    let deadline = Instant::now() + Duration::from_secs(secs);
    let (mut total, mut carried) = (0u64, 0u64);
    let mut sampled = false;
    while Instant::now() < deadline {
        let burst = rxq.receive();
        if burst.is_empty() {
            std::hint::spin_loop();
            continue;
        }
        for m in &burst {
            let frame: &[u8] = m.as_ref();
            if frame.len() < 34
                || frame[6..12] != [0x58, 0xa2, 0xe1, 0x04, 0x31, 0xa8]
                || frame[12..14] != [0x08, 0x00]
            {
                continue;
            }
            total += 1;
            let downstream = m.rx_mark();
            if downstream == Some(mark_id) {
                carried += 1;
            }
            if !sampled {
                println!(
                    "  first frame: ol_flags=0x{:016x} rx_mark={:?}",
                    m.ol_flags(),
                    downstream
                );
                sampled = true;
            }
        }
    }

    println!("=== summary (mode={mode}) ===");
    println!("our IPv4 frames     : {total}");
    println!(
        "carried-through     : {carried}   (matched group-2 {} and got MARK 0x{mark_id:x})",
        mode.to_uppercase()
    );
    let pass = total > 0 && carried == total;
    println!(
        "VERDICT             : {}",
        if pass {
            "PASS -- value set in stage 1 was matched in stage 2 (cross-stage carry works)"
        } else if total == 0 {
            "INCONCLUSIVE -- no frames received"
        } else {
            "FAIL -- stage-2 match did not fire for all frames"
        }
    );
    Ok(())
}
