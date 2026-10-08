// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Read-only check of what the hugepage reservation would see on this host.
//!
//! Reads the same sysfs the reservation reads, without writing anything, so the path arithmetic
//! and the `-1` handling can be checked on a real machine before the reservation is trusted on the
//! benchmark host.
use std::fs;

fn read(path: &str) -> String {
    fs::read_to_string(path).map_or_else(|e| format!("<{e}>"), |s| s.trim().to_string())
}

fn main() {
    let nodes: Vec<String> = fs::read_dir("/sys/devices/system/node")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            n.starts_with("node").then_some(n)
        })
        .collect();
    println!("NUMA nodes: {nodes:?}");

    for node in &nodes {
        for size in ["1048576", "2048"] {
            let dir = format!("/sys/devices/system/node/{node}/hugepages/hugepages-{size}kB");
            if fs::metadata(&dir).is_err() {
                continue;
            }
            println!(
                "  {node} {size}kB: nr={} free={} (writable={})",
                read(&format!("{dir}/nr_hugepages")),
                read(&format!("{dir}/free_hugepages")),
                // The check the reservation depends on: can we grow the pool at all?
                fs::OpenOptions::new()
                    .write(true)
                    .open(format!("{dir}/nr_hugepages"))
                    .is_ok()
            );
        }
        let compact = format!("/sys/devices/system/node/{node}/compact");
        println!(
            "  {node} compact present: {}",
            fs::metadata(&compact).is_ok()
        );
    }

    println!("\nPCI devices and their NUMA affinity (first 5 with a real node):");
    let mut shown = 0;
    for entry in fs::read_dir("/sys/bus/pci/devices")
        .into_iter()
        .flatten()
        .flatten()
    {
        let name = entry.file_name().to_string_lossy().to_string();
        let node = read(&format!("/sys/bus/pci/devices/{name}/numa_node"));
        if node != "-1" && shown < 5 {
            println!("  {name} -> node {node}");
            shown += 1;
        }
    }
    if shown == 0 {
        println!("  (every device reports -1: single-node machine, node-agnostic path taken)");
    }
}
