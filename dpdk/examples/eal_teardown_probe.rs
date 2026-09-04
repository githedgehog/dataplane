// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Times each phase of EAL teardown, to find out which one hangs.
//!
//! `hardware/tests/dpdk_in_vm.rs` cannot drop its [`Eal`] -- it calls `std::mem::forget` in five
//! places -- and the comment there blames `rte_eal_mp_wait_lcore`. That attribution has never been
//! measured, and it looks doubtful: the test launches no worker lcores, so that call should return
//! at once. This probe measures instead of guessing.
//!
//! Every EAL argument is taken from the command line, so one binary can compare configurations
//! (`rte_eal_init` may only run once per process, which is why this is an example and not a test).
//! The phases are driven through `dpdk_sys` directly rather than by dropping the `Eal`, so each is
//! timed separately:
//!
//! ```sh
//! # the unit-test configuration, which is known to work
//! eal_teardown_probe -- --no-huge --no-pci --in-memory --no-telemetry --no-shconf --no-hpet
//! # the same without --no-telemetry, which is what the in-VM road test omits
//! eal_teardown_probe -- --no-huge --no-pci --in-memory --no-shconf --no-hpet
//! ```
//!
//! Exits non-zero if any phase exceeds `PHASE_BUDGET`, so it can be used as a regression gate.

use dataplane_dpdk::eal;
use std::time::{Duration, Instant};

/// A teardown phase this slow is the bug, not a slow machine.
const PHASE_BUDGET: Duration = Duration::from_secs(5);

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: eal_teardown_probe <eal args...>");
        std::process::exit(2);
    }
    eprintln!("[probe] eal args: {args:?}");

    let init_start = Instant::now();
    let eal = eal::init(args.iter().map(String::as_str));
    eprintln!("[probe] rte_eal_init            {:?}", init_start.elapsed());
    eprintln!("[probe] lcore_count             {}", unsafe {
        dpdk_sys::rte_lcore_count()
    });
    eprintln!("[probe] main_lcore              {}", unsafe {
        dpdk_sys::rte_get_main_lcore()
    });

    // Suppress our own `Drop` so each underlying phase can be timed on its own.
    std::mem::forget(eal);

    let mut worst = Duration::ZERO;
    let mut slowest = "none";

    let t = Instant::now();
    unsafe { dpdk_sys::rte_eal_mp_wait_lcore() };
    let mp_wait = t.elapsed();
    eprintln!("[probe] rte_eal_mp_wait_lcore   {mp_wait:?}");
    if mp_wait > worst {
        worst = mp_wait;
        slowest = "rte_eal_mp_wait_lcore";
    }

    let t = Instant::now();
    let ret = unsafe { dpdk_sys::rte_eal_cleanup() };
    let cleanup = t.elapsed();
    eprintln!("[probe] rte_eal_cleanup         {cleanup:?} (returned {ret})");
    if cleanup > worst {
        worst = cleanup;
        slowest = "rte_eal_cleanup";
    }

    eprintln!("[probe] slowest phase: {slowest} at {worst:?}");
    if worst > PHASE_BUDGET {
        eprintln!("[probe] FAIL: {slowest} exceeded {PHASE_BUDGET:?}");
        std::process::exit(1);
    }
    eprintln!("[probe] OK: every phase within {PHASE_BUDGET:?}");
}
