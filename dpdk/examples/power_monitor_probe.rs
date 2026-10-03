// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Can a *registered* thread build a sleep-until-a-packet-arrives receive loop?
//!
//! The DPDK driver's workers are registered non-EAL threads rather than DPDK-launched lcores. The
//! open question that leaves is whether that forecloses a halfway-between-interrupt-and-polling
//! driver, which is a wanted goal for mlx5.
//!
//! There are two layers, and only one of them is closed to a registered thread:
//!
//! - **`rte_power_ethdev_pmgmt_queue_enable`**, the convenience layer, gates on
//!   `rte_lcore_is_enabled()` (`lcore_role == ROLE_RTE`) and so rejects a registered thread
//!   outright. It is *also* unusable in this build for an unrelated reason: it works by installing
//!   an ethdev receive callback, and this build compiles those out
//!   (`#undef RTE_ETHDEV_RXTX_CALLBACKS`), so `rte_eth_add_rx_callback` returns `ENOTSUP`. Same for
//!   the cpufreq half (`rte_power_init`), whose `RTE_POWER_VALID_LCOREID_OR_ERR_RET` demands
//!   `ROLE_RTE` or `ROLE_SERVICE`.
//!
//! - **The primitives it is built out of** -- `rte_eth_get_monitor_addr` plus `rte_power_monitor` /
//!   `rte_power_pause` -- reject only `LCORE_ID_ANY`, not `ROLE_NON_EAL`. Those live in `libeal`
//!   and `libethdev`, both already linked. This probe demonstrates that they are reachable from a
//!   registered thread.
//!
//! The demonstration is a contrast, because a bare success proves nothing about *why*: the
//! **same call on the same CPU** returns `-EINVAL` from an unregistered thread (the lcore check
//! rejecting `LCORE_ID_ANY`) and whatever the main lcore gets from a registered one. Matching the
//! main lcore is the evidence that a registered thread is not second-class here.
//!
//! `rte_power_monitor` is not Intel-only: DPDK dispatches on `RTE_CPUFLAG_MONITORX` to AMD's
//! `MONITORX`/`MWAITX` and otherwise to Intel's `UMONITOR`/`UMWAIT`, and the Arm implementation
//! uses `WFE` with no CPU feature gate at all. `rte_power_pause` *is* narrower -- it needs
//! `TPAUSE`, which is `WAITPKG` and so Intel-only -- but that is a CPU property, identical on the
//! main lcore, and not something registration costs.
//!
//! Run:
//!   ./power_monitor_probe 0000:02:00.1

use dataplane_dpdk::dev::{DevConfig, RssConf, RxOffload, TxOffloadConfig};
use dataplane_dpdk::eal;
use dataplane_dpdk::lcore::LCore;
use dataplane_dpdk::mem::{PoolConfig, PoolParams};
use dataplane_dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dataplane_dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dataplane_dpdk::socket::Preference;

type Err = Box<dyn std::error::Error>;

/// `errno` values, negated as DPDK returns them.
const NEG_EINVAL: i32 = -22;
const NEG_ENOTSUP: i32 = -95;

fn describe(rc: i32) -> String {
    match rc {
        0 => "ok".to_string(),
        NEG_EINVAL => "-EINVAL".to_string(),
        NEG_ENOTSUP => "-ENOTSUP".to_string(),
        other => format!("{other}"),
    }
}

/// What the monitor primitives say when called from this thread.
struct Attempt {
    lcore_id: u32,
    get_monitor_addr: i32,
    power_monitor: i32,
    power_pause: i32,
}

/// Ask the PMD for a monitor condition on `(port, queue)` and then try to sleep on it.
///
/// The sleep is given an already-elapsed deadline so that, on a host where it *is* supported, this
/// returns immediately rather than parking the probe until a packet happens to arrive.
fn attempt(port: u16, queue: u16) -> Attempt {
    let mut pmc: dpdk_sys::rte_power_monitor_cond = unsafe { core::mem::zeroed() };
    let get_monitor_addr = unsafe { dpdk_sys::rte_eth_get_monitor_addr(port, queue, &raw mut pmc) };

    // A deadline already in the past: `rte_power_monitor` treats the timestamp as an absolute TSC
    // wake time, so this asks it to wake immediately.
    let already_expired = 1u64;
    let power_monitor = if get_monitor_addr == 0 {
        unsafe { dpdk_sys::rte_power_monitor(&raw const pmc, already_expired) }
    } else {
        // No condition to sleep on, so the call would be testing argument validation rather than
        // the lcore gate.
        i32::MIN
    };

    Attempt {
        lcore_id: unsafe { dpdk_sys::rte_lcore_id_w() },
        get_monitor_addr,
        power_monitor,
        power_pause: unsafe { dpdk_sys::rte_power_pause(already_expired) },
    }
}

fn report(what: &str, a: &Attempt) {
    let id = if a.lcore_id == u32::MAX {
        "ANY".to_string()
    } else {
        a.lcore_id.to_string()
    };
    println!(
        "  {what:<12} lcore={id:<4} get_monitor_addr={:<8} power_monitor={:<8} power_pause={}",
        describe(a.get_monitor_addr),
        if a.power_monitor == i32::MIN {
            "(skipped)".to_string()
        } else {
            describe(a.power_monitor)
        },
        describe(a.power_pause),
    );
}

fn main() -> Result<(), Err> {
    let bdf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0000:02:00.1".to_string());

    let eal = eal::init([
        "-a",
        bdf.as_str(),
        "--in-memory",
        "--no-telemetry",
        "--no-shconf",
        "--iova-mode=va",
    ]);

    let info = eal.dev.iter().next().ok_or("no DPDK port probed")?;
    let index = info.index();
    let port = index.as_u16();
    println!("port {port} ({bdf}), driver {}", info.driver_name());

    let rss = RssConf::supported_on(&info);
    let mut dev = DevConfig {
        num_rx_queues: 1,
        num_tx_queues: 1,
        num_hairpin_queues: 0,
        rx_offloads: Some(if rss.is_some() {
            RxOffload::RSS_HASH
        } else {
            RxOffload::NONE
        }),
        tx_offloads: Some(TxOffloadConfig::default()),
        mtu: None,
        rss,
    }
    .apply(info)
    .map_err(|e| format!("configure: {e:?}"))?;

    let pool = eal
        .mem
        .new_pkt_pool(
            PoolConfig::new("pm_probe_pool", PoolParams::default())
                .map_err(|e| format!("pool config: {e:?}"))?,
        )
        .map_err(|e| format!("pool create: {e:?}"))?;
    dev.new_rx_queue(RxQueueConfig {
        dev: index,
        queue_index: RxQueueIndex(0),
        num_descriptors: 1024,
        socket_preference: Preference::Dev(index),
        offloads: RxOffload::NONE,
        pool,
    })?;
    dev.new_tx_queue(TxQueueConfig {
        queue_index: TxQueueIndex(0),
        num_descriptors: 1024,
        socket_preference: Preference::Dev(index),
        config: (),
    })?;
    let dev = dev.start().map_err(|e| format!("start: {e}"))?;

    println!();
    let main_attempt = attempt(port, 0);
    report("main", &main_attempt);

    let (plain, registered) = std::thread::scope(|s| {
        s.spawn(|| {
            let plain = attempt(port, 0);
            let _registration = LCore::register().expect("could not register");
            let registered = attempt(port, 0);
            (plain, registered)
        })
        .join()
        .expect("probe thread panicked")
    });
    report("plain", &plain);
    report("registered", &registered);

    println!();
    let mut surprises: Vec<String> = Vec::new();
    let mut check = |claim: &str, holds: bool| {
        println!("  [{}] {claim}", if holds { "ok " } else { "!! " });
        if !holds {
            surprises.push(claim.to_string());
        }
    };

    check(
        "mlx5 supplies a receive monitor condition (it implements get_monitor_addr)",
        registered.get_monitor_addr == 0,
    );
    check(
        "an UNregistered thread is refused by rte_power_monitor's lcore check (-EINVAL)",
        plain.power_monitor == NEG_EINVAL,
    );
    check(
        "a REGISTERED thread gets past that lcore check (anything but -EINVAL)",
        registered.power_monitor != NEG_EINVAL,
    );
    check(
        "whatever a registered thread hits next is the same thing the main lcore hits",
        registered.power_monitor == main_attempt.power_monitor,
    );

    println!();
    match registered.power_monitor {
        0 => println!(
            "rte_power_monitor SUCCEEDS from a registered thread on this host: the halfway \
             receive loop is available as-is."
        ),
        NEG_ENOTSUP => println!(
            "rte_power_monitor returns -ENOTSUP from a registered thread AND from the main lcore. \
             That is a CPU property, not an lcore one -- this host has neither WAITPKG nor \
             MONITORX. The lcore check still passed. On Arm (a BF3's own cores) the same API is \
             implemented with WFE and has no CPU feature gate at all."
        ),
        other => println!("rte_power_monitor returned {other} from a registered thread"),
    }

    dev.stop()
        .map_err(|e| format!("stop: {e}"))?
        .close()
        .map_err(|e| format!("close: {e}"))?;

    if surprises.is_empty() {
        println!("\nevery claim held on this host");
        Ok(())
    } else {
        for s in &surprises {
            println!("[SURPRISE] {s}");
        }
        Err(format!("{} claim(s) did not hold", surprises.len()).into())
    }
}
