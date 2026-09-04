// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Hardware offload probe (trust-ladder base).
//!
//! Brings up one mlx5 port, installs a `group 0 -> JUMP -> group 1, eth/ipv4 -> MARK + QUEUE`
//! rte_flow rule, then receives and reports the per-packet metadata the NIC stamped (the `MARK`
//! id and the RSS hash).  It confirms by *observed mbuf metadata* -- not by a create/validate
//! return -- that a `MARK` survives to software.  That is the channel a packet trapped to software
//! uses to carry hardware-stamped context (e.g. a pipeline epoch), so it is the primitive the
//! offload-trust model's Rule 2 (trap-anywhere) depends on.
//!
//! testpmd cannot show this in our build (its verbose dump is wired through Rx/Tx callbacks, which
//! the nix build disables), so this small harness reads the mbuf directly instead.
//!
//! Injection is external and already validated: against the cabled peer port, run
//!   sudo python3 send_frames.py <peer-netdev> <this-port-mac> <count>
//! while this probe polls.
//!
//! Run as root (for hugepages / mlx5 caps):
//!   sudo ./offload_probe 0000:e1:00.1 [mark_hex=4242] [seconds=8]

use core::ffi::{CStr, c_void};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use dataplane_dpdk::dev::{DevConfig, RxOffload};
use dataplane_dpdk::eal;
use dataplane_dpdk::mem::{PoolConfig, PoolParams};
use dataplane_dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dataplane_dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dataplane_dpdk::socket::Preference;

use dpdk_sys::{
    rte_flow, rte_flow_action, rte_flow_action_jump, rte_flow_action_mark, rte_flow_action_queue,
    rte_flow_action_type, rte_flow_attr, rte_flow_create, rte_flow_error, rte_flow_item,
    rte_flow_item_type,
};

type Err = Box<dyn std::error::Error>;

/// A pattern item that matches the mere presence of a header (null spec/last/mask).
fn item(type_: rte_flow_item_type::Type) -> rte_flow_item {
    rte_flow_item {
        type_,
        spec: core::ptr::null(),
        last: core::ptr::null(),
        mask: core::ptr::null(),
    }
}

fn action(type_: rte_flow_action_type::Type, conf: *const c_void) -> rte_flow_action {
    rte_flow_action { type_, conf }
}

/// Install one rte_flow rule, surfacing the PMD's error string on failure.
///
/// # Safety
///
/// `items` and `actions` must be `END`-terminated and their `spec`/`conf` pointers must outlive
/// this call (the PMD copies them before returning).
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
            unsafe { CStr::from_ptr(err.message) }
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
    let mark_id = u32::from_str_radix(&args.next().unwrap_or_else(|| "4242".into()), 16)?;
    let secs: u64 = args.next().unwrap_or_else(|| "8".into()).parse()?;

    // EAL prepends argv[0] itself, so pass only flags.  Hugepages + PCI are required (unlike the
    // crate's no-pci/no-huge unit-test EAL).
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

    let info = eal.dev.iter().next().ok_or(
        "no DPDK port probed -- check the BDF and that we have CAP_NET_RAW (or run as root)",
    )?;

    let pool = eal
        .mem
        .new_pkt_pool(
            PoolConfig::new("probe_pool", PoolParams::default())
                .map_err(|e| format!("pool config: {e:?}"))?,
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
    println!("port {bdf} probed as dpdk index {port}; bringing up 1 rx + 1 tx queue");

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

    // group 0 (root) only accepts JUMP; the MARK + QUEUE rule lives in group 1.
    let mut attr0 = rte_flow_attr::default();
    attr0.set_ingress(1);
    attr0.group = 0;
    let mut attr1 = rte_flow_attr::default();
    attr1.set_ingress(1);
    attr1.group = 1;

    let jump = rte_flow_action_jump { group: 1 };
    let mark = rte_flow_action_mark { id: mark_id };
    let queue = rte_flow_action_queue { index: 0 };

    use rte_flow_action_type::{
        RTE_FLOW_ACTION_TYPE_END, RTE_FLOW_ACTION_TYPE_JUMP, RTE_FLOW_ACTION_TYPE_MARK,
        RTE_FLOW_ACTION_TYPE_QUEUE,
    };
    use rte_flow_item_type::{
        RTE_FLOW_ITEM_TYPE_END, RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
    };

    let items_jump = [item(RTE_FLOW_ITEM_TYPE_ETH), item(RTE_FLOW_ITEM_TYPE_END)];
    let acts_jump = [
        action(
            RTE_FLOW_ACTION_TYPE_JUMP,
            (&jump as *const rte_flow_action_jump).cast(),
        ),
        action(RTE_FLOW_ACTION_TYPE_END, core::ptr::null()),
    ];
    let items_mark = [
        item(RTE_FLOW_ITEM_TYPE_ETH),
        item(RTE_FLOW_ITEM_TYPE_IPV4),
        item(RTE_FLOW_ITEM_TYPE_END),
    ];
    let acts_mark = [
        action(
            RTE_FLOW_ACTION_TYPE_MARK,
            (&mark as *const rte_flow_action_mark).cast(),
        ),
        action(
            RTE_FLOW_ACTION_TYPE_QUEUE,
            (&queue as *const rte_flow_action_queue).cast(),
        ),
        action(RTE_FLOW_ACTION_TYPE_END, core::ptr::null()),
    ];

    // SAFETY: both lists are END-terminated and every conf pointer (`jump`/`mark`/`queue`) lives
    // until after the `install` calls return.
    unsafe {
        install(port, &attr0, &items_jump, &acts_jump, "group0 jump->1")?;
        install(
            port,
            &attr1,
            &items_mark,
            &acts_mark,
            &format!("group1 ipv4->MARK 0x{mark_id:x}+QUEUE0"),
        )?;
    }

    let mut queues = dev.take_queues().ok_or("device queues already taken")?;
    let mut rxq = queues
        .take_rx(RxQueueIndex(0))
        .ok_or("rx queue 0 not found after start")?;

    println!("polling rx queue 0 for {secs}s -- inject IPv4 from the peer port now...");
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut total = 0u64;
    let mut marked = 0u64;
    let mut mark_ids = BTreeSet::new();
    let mut sampled = false;

    while Instant::now() < deadline {
        let burst = rxq.receive();
        if burst.is_empty() {
            std::hint::spin_loop();
            continue;
        }
        for m in &burst {
            total += 1;
            if let Some(id) = m.rx_mark() {
                marked += 1;
                mark_ids.insert(id);
            }
            if !sampled {
                println!(
                    "first packet: ol_flags=0x{:016x}  rss_hash={:?}  rx_mark={:?}",
                    m.ol_flags(),
                    m.rss_hash(),
                    m.rx_mark(),
                );
                sampled = true;
            }
        }
        // `burst` drops here: the whole MbufArray is bulk-freed.
    }

    println!("=== summary ===");
    println!("received  : {total}");
    println!("marked    : {marked}");
    println!("mark ids  : {mark_ids:#x?}");
    let pass = marked > 0 && mark_ids.len() == 1 && mark_ids.contains(&mark_id);
    println!(
        "VERDICT   : {} (expected every matched packet to carry mark 0x{mark_id:x})",
        if pass {
            "PASS -- MARK survives to software"
        } else {
            "FAIL / inconclusive"
        }
    );
    Ok(())
}
