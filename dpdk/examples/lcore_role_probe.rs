// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What a registered non-EAL thread gets, and what only a real EAL lcore gets.
//!
//! The DPDK driver's workers are ordinary Rust threads registered with
//! [`LCore`](dataplane_dpdk::lcore::LCore) rather than lcores DPDK launched
//! itself, because DPDK's own launch path takes an `int (*)(void *)` and cannot express the scoped
//! borrows the driver rests on. That is only the right trade if a registered thread is not
//! second-class in some way that matters later. This probe measures the difference instead of
//! arguing about it.
//!
//! Three thread flavours are compared on every property a caller might reasonably depend on:
//!
//! - **main** -- the thread that called `rte_eal_init`, a real EAL lcore (`ROLE_RTE`).
//! - **registered** -- an ordinary thread holding an `LCore` (`ROLE_NON_EAL`).
//! - **plain** -- an ordinary thread that never registered (`LCORE_ID_ANY`).
//!
//! Run (needs `IPC_LOCK`; no traffic, no device):
//!   ./lcore_role_probe [0000:02:00.1]

use dataplane_dpdk::eal;
use dataplane_dpdk::lcore::LCore;
use dataplane_dpdk::mem::{PoolConfig, PoolParams};

type Err = Box<dyn std::error::Error>;

/// Everything worth knowing about how the EAL sees the calling thread.
#[derive(Debug)]
struct Seen {
    lcore_id: u32,
    /// `rte_socket_id()` -- a thread-local, so it answers for any thread.
    socket_of_thread: i32,
    /// `rte_lcore_to_socket_id(id)` -- reads `lcore_config[id].numa_id`.
    socket_of_lcore: Option<u32>,
    /// `rte_lcore_is_enabled(id)`, which is `lcore_role == ROLE_RTE` and nothing else.
    is_enabled: bool,
    /// Whether `RTE_LCORE_FOREACH` (i.e. `rte_get_next_lcore`) yields this id.
    listed_by_foreach: bool,
    /// `rte_lcore_index(id)`; `-1` when the EAL never indexed this lcore.
    lcore_index: i32,
    /// `rte_lcore_to_cpu_id(id)`; only meaningful for an lcore the EAL configured.
    cpu_id: i32,
    /// Whether this thread gets a per-core mempool cache -- the thing the registration is *for*.
    has_mempool_cache: bool,
}

/// A mempool pointer that may cross into the probe thread.
///
/// `*mut rte_mempool` is not `Sync`, and rightly so in general. Here both threads only ever hand it
/// to `rte_mempool_default_cache`, which reads `mp->cache_size` and returns an interior pointer --
/// no mutation, no allocation. The pool outlives the scope.
#[derive(Copy, Clone)]
struct PoolPtr(*mut dpdk_sys::rte_mempool);

// SAFETY: see the type docs -- the pointee is only read, and only through a function that does not
// mutate it.
unsafe impl Send for PoolPtr {}
unsafe impl Sync for PoolPtr {}

fn look(pool: PoolPtr) -> Seen {
    let pool = pool.0;
    let lcore_id = unsafe { dpdk_sys::rte_lcore_id_w() };
    let in_range = lcore_id < dpdk_sys::RTE_MAX_LCORE;

    let listed_by_foreach = in_range && {
        let mut found = false;
        let mut i = unsafe { dpdk_sys::rte_get_next_lcore(u32::MAX, 0, 0) };
        while i < dpdk_sys::RTE_MAX_LCORE {
            if i == lcore_id {
                found = true;
                break;
            }
            i = unsafe { dpdk_sys::rte_get_next_lcore(i, 0, 0) };
        }
        found
    };

    Seen {
        lcore_id,
        socket_of_thread: unsafe { dpdk_sys::rte_socket_id() } as i32,
        socket_of_lcore: in_range.then(|| unsafe { dpdk_sys::rte_lcore_to_socket_id(lcore_id) }),
        is_enabled: in_range && unsafe { dpdk_sys::rte_lcore_is_enabled(lcore_id) } != 0,
        listed_by_foreach,
        lcore_index: unsafe { dpdk_sys::rte_lcore_index(-1) },
        cpu_id: unsafe { dpdk_sys::rte_lcore_to_cpu_id(-1) },
        // The payoff. `rte_mempool_default_cache` returns NULL for `LCORE_ID_ANY`, and a NULL cache
        // means every get/put goes to the shared ring under atomics.
        has_mempool_cache: !unsafe { dpdk_sys::rte_mempool_default_cache_w(pool, lcore_id) }
            .is_null(),
    }
}

fn report(what: &str, seen: &Seen) {
    let id = if seen.lcore_id == u32::MAX {
        "ANY".to_string()
    } else {
        seen.lcore_id.to_string()
    };
    println!(
        "  {what:<12} lcore_id={id:<4} socket(thread)={:<3} socket(lcore)={:<6} enabled={:<5} in_FOREACH={:<5} index={:<3} cpu={:<3} mempool_cache={}",
        seen.socket_of_thread,
        seen.socket_of_lcore
            .map_or("-".to_string(), |s| s.to_string()),
        seen.is_enabled,
        seen.listed_by_foreach,
        seen.lcore_index,
        seen.cpu_id,
        seen.has_mempool_cache,
    );
}

fn main() -> Result<(), Err> {
    let bdf = std::env::args().nth(1);
    let mut args: Vec<String> = vec![
        "--in-memory".into(),
        "--no-telemetry".into(),
        "--no-shconf".into(),
    ];
    match &bdf {
        Some(bdf) => {
            args.push("-a".into());
            args.push(bdf.clone());
        }
        None => args.push("--no-pci".into()),
    }
    let eal = eal::init(args);

    let _pool = eal
        .mem
        .new_pkt_pool(
            PoolConfig::new("role_probe_pool", PoolParams::default())
                .map_err(|e| format!("pool config: {e:?}"))?,
        )
        .map_err(|e| format!("pool create: {e:?}"))?;
    // Looked up by name rather than reached through the safe handle: `Pool::as_mut_ptr` is
    // crate-private, and widening it so an example can read a cache pointer would be a poor trade.
    let raw = unsafe { dpdk_sys::rte_mempool_lookup(c"role_probe_pool".as_ptr()) };
    if raw.is_null() {
        return Err("could not look the probe pool back up by name".into());
    }
    let raw = PoolPtr(raw);

    println!("RTE_MAX_LCORE = {}", dpdk_sys::RTE_MAX_LCORE);
    {
        // Dump the raw config around the boundary between detected CPUs and the first free slot,
        // because `rte_lcore_index` reads `lcore_config[id].core_index` directly and the value it
        // returns for a registered thread is not what the source alone predicts.
        let mut enabled: u32 = 0;
        for id in 0..dpdk_sys::RTE_MAX_LCORE {
            if unsafe { dpdk_sys::rte_lcore_is_enabled(id) } != 0 {
                enabled += 1;
            }
        }
        println!("enabled (ROLE_RTE) lcores = {enabled}");
        for id in [enabled.saturating_sub(1), enabled, enabled + 1] {
            if id < dpdk_sys::RTE_MAX_LCORE {
                println!(
                    "  lcore_config[{id}]: core_index={} cpu_id={} numa={} enabled={}",
                    unsafe { dpdk_sys::rte_lcore_index(id as core::ffi::c_int) },
                    unsafe { dpdk_sys::rte_lcore_to_cpu_id(id as core::ffi::c_int) },
                    unsafe { dpdk_sys::rte_lcore_to_socket_id(id) },
                    unsafe { dpdk_sys::rte_lcore_is_enabled(id) } != 0,
                );
            }
        }
    }
    println!(
        "lcore_count (EAL-enabled + registered) before any registration: {}",
        unsafe { dpdk_sys::rte_lcore_count() }
    );
    println!();

    let main_seen = look(raw);
    report("main", &main_seen);

    // A plain thread, then the same thread registered, so the only variable is the registration.
    let (plain_seen, registered_seen, count_while_registered) = std::thread::scope(|s| {
        s.spawn(|| {
            let plain = look(raw);
            let registration = LCore::register().expect("could not register");
            let registered = look(raw);
            let count = unsafe { dpdk_sys::rte_lcore_count() };
            drop(registration);
            (plain, registered, count)
        })
        .join()
        .expect("probe thread panicked")
    });

    report("plain", &plain_seen);
    report("registered", &registered_seen);

    // `core_index` for the registered id, read from main before / during / after, because the
    // boundary dump above (taken before any registration) disagreed with what the registered
    // thread itself saw.
    println!();
    let reg_id = registered_seen.lcore_id as core::ffi::c_int;
    println!(
        "  lcore_config[{reg_id}].core_index seen from main, after release: {}",
        unsafe { dpdk_sys::rte_lcore_index(reg_id) }
    );
    let held = std::thread::scope(|s| {
        s.spawn(|| {
            let r = LCore::register().expect("register again");
            let from_self = unsafe { dpdk_sys::rte_lcore_index(-1) };
            let by_id = unsafe { dpdk_sys::rte_lcore_index(reg_id) };
            drop(r);
            (from_self, by_id)
        })
        .join()
        .expect("probe thread panicked")
    });
    println!(
        "  while registered, from that thread: rte_lcore_index(-1)={} rte_lcore_index({reg_id})={}",
        held.0, held.1
    );

    println!();
    println!("lcore_count while a thread was registered: {count_while_registered}");
    println!("lcore_count after it released:             {}", unsafe {
        dpdk_sys::rte_lcore_count()
    });
    println!();

    // The findings, stated as assertions so this fails loudly if a DPDK bump changes any of them.
    let mut surprises: Vec<String> = Vec::new();
    let mut check = |claim: &str, holds: bool| {
        println!("  [{}] {claim}", if holds { "ok " } else { "!! " });
        if !holds {
            surprises.push(claim.to_string());
        }
    };

    println!("What registration buys:");
    check(
        "a registered thread gets a per-core mempool cache; a plain one does not",
        registered_seen.has_mempool_cache && !plain_seen.has_mempool_cache,
    );
    check(
        "a registered thread learns its NUMA node; a plain one reports SOCKET_ID_ANY",
        registered_seen.socket_of_thread >= 0 && plain_seen.socket_of_thread < 0,
    );
    check(
        "lcore_config[id].numa_id is populated for a registered thread",
        registered_seen.socket_of_lcore == Some(registered_seen.socket_of_thread as u32),
    );

    println!();
    println!("What it does NOT buy (real EAL lcores only):");
    check(
        "rte_lcore_is_enabled() is false for a registered thread (it tests ROLE_RTE)",
        main_seen.is_enabled && !registered_seen.is_enabled,
    );
    check(
        "RTE_LCORE_FOREACH does not list a registered thread",
        main_seen.listed_by_foreach && !registered_seen.listed_by_foreach,
    );
    // NOT a gap, as of the version this links against. DPDK 26.07 changed
    // `eal_lcore_non_eal_allocate` to allocate a real `core_index` for a registered thread out of a
    // bitset of free indices, and `eal_lcore_non_eal_release` to hand it back. On 26.03 it stayed
    // `-1`. This is checked rather than assumed because the *consumer* that matters is mlx5:
    // `mlx5_list_register` treats `rte_lcore_index() == -1` as "take `lcore_lock` and use the
    // shared bucket", so on the older behaviour every flow-list operation from a worker would
    // serialise on one spinlock. Here they get the lock-free per-lcore path.
    check(
        "rte_lcore_index() gives a registered thread a real index (26.07+), not -1",
        main_seen.lcore_index >= 0 && registered_seen.lcore_index >= 0,
    );
    check(
        "that index is within mlx5's per-lcore cache array (RTE_MAX_LCORE + 2)",
        (registered_seen.lcore_index as u32) < dpdk_sys::RTE_MAX_LCORE,
    );
    check(
        "rte_lcore_count() counts a registered thread even though FOREACH skips it",
        count_while_registered == unsafe { dpdk_sys::rte_lcore_count() } + 1,
    );

    println!();
    if surprises.is_empty() {
        println!("every claim held on this build of DPDK");
        Ok(())
    } else {
        for s in &surprises {
            println!("[SURPRISE] {s}");
        }
        Err(format!("{} claim(s) did not hold", surprises.len()).into())
    }
}
