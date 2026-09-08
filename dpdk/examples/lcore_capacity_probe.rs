// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! How many threads can be registered with the EAL, and what happens at the limit.
//!
//! The DPDK driver registers every worker with
//! [`LCore`](dataplane_dpdk::lcore::LCore). That is only safe at scale if
//! the limit is knowable, the failure at the limit is clean, and released ids are actually reused.
//!
//! The bookkeeping is two fixed-size resources, both `RTE_MAX_LCORE` wide:
//!
//! - **`lcore_role[]`** -- `eal_lcore_non_eal_allocate` scans for the first `ROLE_OFF` slot, so
//!   **every lcore the EAL enabled costs a registration slot**. That makes the answer depend on the
//!   EAL's `--lcores`/coremask arguments, not just on `RTE_MAX_LCORE`.
//! - **`core_indices`** -- a bitset added in 26.07, from which each registration takes a free
//!   `core_index` (see `examples/lcore_role_probe.rs`).
//!
//! Run it both ways, because the difference is the whole point:
//!   ./lcore_capacity_probe              # EAL enables every detected CPU
//!   ./lcore_capacity_probe --one-lcore  # `--lcores 0@(all cpus)`, as the dataplane does

use dataplane_dpdk::eal;
use dataplane_dpdk::lcore::LCore;

use std::sync::mpsc;

type Err = Box<dyn std::error::Error>;

fn enabled_lcores() -> u32 {
    (0..dpdk_sys::RTE_MAX_LCORE)
        .filter(|id| unsafe { dpdk_sys::rte_lcore_is_enabled(*id) } != 0)
        .count() as u32
}

fn role_count(role: dpdk_sys::rte_lcore_role_t::Type) -> u32 {
    (0..dpdk_sys::RTE_MAX_LCORE)
        .filter(|id| unsafe { dpdk_sys::rte_lcore_has_role(*id, role) } != 0)
        .count() as u32
}

/// Spawn threads that each register and then park until told to release.
///
/// Returns how many registered successfully and the error the first failure reported. Threads are
/// held live simultaneously -- which is the point, since the resource is per-live-registration.
fn saturate(limit: u32) -> (u32, Option<String>) {
    let (report_tx, report_rx) = mpsc::channel::<Result<(), String>>();

    let mut handles = Vec::new();
    let mut releases = Vec::new();
    let mut registered = 0;
    let mut first_error = None;

    for _ in 0..limit {
        // One release channel per thread rather than a shared receiver behind a mutex: the
        // workspace disallows `std::sync::Mutex` (there is a facade), and a channel each is
        // simpler than borrowing one anyway.
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let report_tx = report_tx.clone();
        handles.push(std::thread::spawn(move || {
            match LCore::register() {
                Ok(registration) => {
                    let _ = report_tx.send(Ok(()));
                    // Park until released, holding the registration. Every live registration is
                    // what consumes a slot, so they must overlap for this to measure anything.
                    let _ = release_rx.recv();
                    drop(registration);
                }
                Err(e) => {
                    let _ = report_tx.send(Err(format!("{e:?}")));
                }
            }
        }));
        releases.push(release_tx);
        match report_rx.recv().expect("a probe thread vanished") {
            Ok(()) => registered += 1,
            Err(e) => {
                first_error = Some(e);
                break;
            }
        }
    }

    // Dropping every sender releases every parked thread.
    drop(releases);
    for handle in handles {
        let _ = handle.join();
    }
    (registered, first_error)
}

fn main() -> Result<(), Err> {
    let one_lcore = std::env::args().any(|a| a == "--one-lcore");

    let mut args: Vec<String> = vec![
        "--in-memory".into(),
        "--no-telemetry".into(),
        "--no-shconf".into(),
        "--no-pci".into(),
        "--no-huge".into(),
    ];
    if one_lcore {
        // Exactly what `dataplane` passes: one lcore, mapped to every CPU the process may use.
        args.push("--lcores".into());
        args.push(dataplane_dpdk::eal::main_lcore_arg());
    }
    let _eal = eal::init(args);

    let max = dpdk_sys::RTE_MAX_LCORE;
    let enabled = enabled_lcores();
    println!(
        "RTE_MAX_LCORE = {max}, EAL-enabled (ROLE_RTE) lcores = {enabled}{}",
        if one_lcore {
            "  [--lcores 0@(...)]"
        } else {
            "  [default: every detected CPU]"
        }
    );

    // What RTE_MAX_LCORE actually costs, since the obvious question is why it is not simply huge.
    {
        let cache = core::mem::size_of::<dpdk_sys::rte_mempool_cache>();
        let stride = dpdk_sys::RTE_MAX_LCORE_VAR as usize;
        let per_pool = cache * max as usize;
        let per_lcore_var_buffer = stride * max as usize;
        println!();
        println!("what RTE_MAX_LCORE costs (all of these scale linearly with it):");
        println!(
            "  sizeof(rte_mempool_cache)            = {cache} B  \
             (RTE_MEMPOOL_CACHE_MAX_SIZE * 2 pointers, cache-line aligned)"
        );
        println!(
            "  per mempool with caching enabled     = {cache} x {max} = {:.2} MiB, \
             allocated up front whatever the lcore count",
            per_pool as f64 / (1024.0 * 1024.0)
        );
        println!(
            "  RTE_MAX_LCORE_VAR (per-lcore stride) = {stride} B ({} KiB)",
            stride / 1024
        );
        println!(
            "  one lcore_var_buffer                 = {stride} x {max} = {:.2} MiB",
            per_lcore_var_buffer as f64 / (1024.0 * 1024.0)
        );
        println!("  extrapolated, if RTE_MAX_LCORE were raised:");
        for candidate in [128u64, 1024, 65536] {
            println!(
                "    {candidate:>6}: {:>9.2} MiB per cached mempool, {:>9.2} MiB per lcore_var_buffer",
                (cache as u64 * candidate) as f64 / (1024.0 * 1024.0),
                (stride as u64 * candidate) as f64 / (1024.0 * 1024.0),
            );
        }
        println!(
            "  note the per-lcore *stride* is fixed, so a bigger RTE_MAX_LCORE adds regions \
             rather than spreading one lcore's data out: both lookups stay O(1) index arithmetic."
        );
    }
    println!();

    let expected = max - enabled;
    println!("so the expected registration capacity is {max} - {enabled} = {expected}");
    println!();

    // Ask for more than should be possible, so the limit is observed rather than assumed.
    let (registered, first_error) = saturate(expected + 8);
    println!("registered {registered} threads simultaneously");
    match &first_error {
        Some(e) => println!("the next registration failed with: {e}"),
        None => println!("no failure was observed (the limit was not reached)"),
    }

    println!();
    println!("after releasing all of them:");
    println!(
        "  ROLE_RTE      = {}",
        role_count(dpdk_sys::rte_lcore_role_t::ROLE_RTE)
    );
    println!(
        "  ROLE_NON_EAL  = {}",
        role_count(dpdk_sys::rte_lcore_role_t::ROLE_NON_EAL)
    );
    println!("  rte_lcore_count() = {}", unsafe {
        dpdk_sys::rte_lcore_count()
    });

    // Everything must be reusable afterwards, or a restart would degrade until nothing could
    // register at all.
    let (again, _) = saturate(expected);
    println!("  re-registered after release: {again}");

    println!();
    let mut surprises: Vec<String> = Vec::new();
    let mut check = |claim: &str, holds: bool| {
        println!("  [{}] {claim}", if holds { "ok " } else { "!! " });
        if !holds {
            surprises.push(claim.to_string());
        }
    };

    check(
        "capacity is RTE_MAX_LCORE minus the lcores the EAL enabled",
        registered == expected,
    );
    check(
        "exhaustion is a clean error, not a crash or a silent success",
        first_error.is_some(),
    );
    check(
        "every id is handed back on release (ROLE_NON_EAL returns to zero)",
        role_count(dpdk_sys::rte_lcore_role_t::ROLE_NON_EAL) == 0,
    );
    check(
        "rte_lcore_count() returns to the enabled count",
        unsafe { dpdk_sys::rte_lcore_count() } == enabled,
    );
    check(
        "the same capacity is available again afterwards",
        again == expected,
    );

    println!();
    if surprises.is_empty() {
        println!("every claim held");
        Ok(())
    } else {
        for s in &surprises {
            println!("[SURPRISE] {s}");
        }
        Err(format!("{} claim(s) did not hold", surprises.len()).into())
    }
}
