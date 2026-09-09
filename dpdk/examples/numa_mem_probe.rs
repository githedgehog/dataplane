// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What `--numa-mem` does to EAL startup, at the exact figure the reservation would produce.
//!
//! Run with a page pool sized as the lab's: 4096 MiB of 2 MiB pages.
//!   ./numa_mem_probe            # baseline: no --numa-mem
//!   ./numa_mem_probe 4096       # ask for the whole pool, as the reservation does
//!   ./numa_mem_probe 2048       # ask for half
use std::process::ExitCode;

fn main() -> ExitCode {
    let arg: Option<String> = std::env::args().nth(1);

    let mut args: Vec<String> = vec![
        "dataplane".into(),
        "--in-memory".into(),
        "--no-telemetry".into(),
        "--no-shconf".into(),
        "--no-pci".into(),
        "--iova-mode=va".into(),
        "--lcores".into(),
        dataplane_dpdk::eal::main_lcore_arg(),
    ];
    match &arg {
        Some(mb) => {
            args.push(format!("--numa-mem={mb}"));
            println!("== asking the EAL to preallocate {mb} MiB ==");
        }
        None => println!("== baseline: no --numa-mem =="),
    }
    println!("args: {}", args.join(" "));

    // `eal::init` calls rte_exit on failure, so this process either prints the line below or dies
    // inside DPDK with its own message -- which is exactly the signal we want.
    let before = std::fs::read_to_string(
        "/sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages",
    )
    .unwrap_or_default();
    let _eal = dataplane_dpdk::eal::init(args);
    let after = std::fs::read_to_string(
        "/sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages",
    )
    .unwrap_or_default();
    // The question this probe exists to answer: did --numa-mem cause any hugepages to be taken?
    println!("EAL came up");
    println!(
        "  physmem visible to DPDK: {} MiB",
        unsafe { dpdk_sys::rte_eal_get_physmem_size() } / (1024 * 1024)
    );
    println!(
        "  2MiB free pages before={} after={}",
        before.trim(),
        after.trim()
    );
    ExitCode::SUCCESS
}
