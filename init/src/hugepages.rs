// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Reserving hugepages on the NUMA node the NIC is attached to, before the dataplane starts.
//!
//! # Why this is not the EAL's job
//!
//! DPDK *is* NUMA-aware: `librte_eal` is linked against `libnuma` and calls `numa_set_preferred`
//! before faulting a hugepage in, so a mempool created for the port's socket really does try to
//! land on that socket. What it cannot do is **create** the pages. The kernel's hugepage pool is
//! host state, sized through sysfs, and an application only ever consumes what is already there.
//!
//! That matters more than it sounds, because `numa_set_preferred` is `MPOL_PREFERRED`: when the
//! preferred node has no free pages the kernel **silently satisfies the allocation from another
//! node**. Nothing fails, nothing warns, and the datapath runs with its packet buffers a QPI hop
//! away from the NIC. For a benchmark that is the worst possible failure -- a number that looks
//! like a result.
//!
//! So this module reserves the pages up front, on the right node, and reports what it actually got.
//! The dataplane then asks the EAL for exactly that much with `--numa-mem`, which turns a silent
//! fallback into a loud startup failure.
//!
//! # Best-effort, deliberately
//!
//! Every step here is allowed to fail. In a container without `CAP_SYS_ADMIN` the sysfs files are
//! read-only, and on a host that has been up for a while a 1 GiB reservation will usually fail no
//! matter how much memory is free -- a gigabyte page needs a gigabyte of *physically contiguous,
//! gigabyte-aligned* memory, which is why 1 GiB pages are normally reserved on the kernel command
//! line at boot (`hugepagesz=1G hugepages=N`). Refusing to start over that would be wrong: the
//! dataplane can still run on 2 MiB pages, and `--in-memory` means it does not even need a mount.
//! What this module owes the operator is an honest log line about which of those happened.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use args::HugepagePlan;
use hardware::pci::address::PciAddress;
use tracing::{debug, info, warn};

/// A 1 GiB page, in kilobytes, as sysfs names it.
const ONE_GIB_KB: u64 = 1024 * 1024;

/// A 2 MiB page, in kilobytes, as sysfs names it.
const TWO_MIB_KB: u64 = 2 * 1024;

/// How much hugepage memory the datapath wants per NUMA node it has a device on.
///
/// Four gigabytes: enough for the mbuf pools of a multi-queue port pair with headroom for the
/// rings and the heap, and small enough to be plausible on a machine that is also doing other
/// things. Expressed in kilobytes so it divides evenly by either page size.
const WANT_KB_PER_NODE: u64 = 4 * 1024 * 1024;

/// Which NUMA node a PCI device is attached to.
///
/// `None` when the kernel reports `-1`, which it does on a single-node machine and on any system
/// whose firmware did not describe the affinity. `None` is not an error: it means node-agnostic,
/// and the caller should size the pool without naming a node.
#[must_use]
pub fn numa_node_of(address: PciAddress) -> Option<u32> {
    let path = format!("/sys/bus/pci/devices/{address}/numa_node");
    let raw = fs::read_to_string(&path)
        .inspect_err(|e| debug!("could not read {path}: {e}; treating {address} as node-agnostic"))
        .ok()?;
    match raw.trim().parse::<i32>() {
        Ok(node) if node >= 0 => u32::try_from(node).ok(),
        Ok(_) => {
            debug!("{address} reports no NUMA affinity");
            None
        }
        Err(e) => {
            warn!("{path} did not contain a number ({e}); treating {address} as node-agnostic");
            None
        }
    }
}

/// The sysfs directory holding a page size's pool counters, per node or system-wide.
fn pool_dir(node: Option<u32>, page_size_kb: u64) -> PathBuf {
    match node {
        Some(n) => PathBuf::from(format!(
            "/sys/devices/system/node/node{n}/hugepages/hugepages-{page_size_kb}kB"
        )),
        None => PathBuf::from(format!(
            "/sys/kernel/mm/hugepages/hugepages-{page_size_kb}kB"
        )),
    }
}

/// Read a single unsigned number out of a sysfs file.
fn read_count(path: &Path) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse::<u64>().ok()
}

/// Ask the kernel to compact memory, so a large contiguous reservation has a chance.
///
/// Best-effort in the strongest sense: this is a hint, it is synchronous and can take a while, and
/// there is no way to find out whether it helped other than trying the reservation again. Prefers
/// the per-node trigger, because compacting one node is cheaper than compacting the machine and is
/// the only part we care about.
fn compact(node: Option<u32>) {
    let path = match node {
        Some(n) => PathBuf::from(format!("/sys/devices/system/node/node{n}/compact")),
        None => PathBuf::from("/proc/sys/vm/compact_memory"),
    };
    match fs::write(&path, "1") {
        Ok(()) => debug!("requested memory compaction via {}", path.display()),
        Err(e) => debug!(
            "could not request compaction via {}: {e}; continuing, as compaction is only a hint",
            path.display()
        ),
    }
}

/// Try to make `want_pages` of `page_size_kb` free on `node`, and report how many actually are.
///
/// Grows the pool by the shortfall rather than setting it to `want_pages`: `nr_hugepages` is the
/// *total* pool size and other things on the host may already be holding pages out of it, so
/// writing the bare figure could shrink a pool someone else is using.
fn try_reserve(node: Option<u32>, page_size_kb: u64, want_pages: u64) -> u64 {
    let dir = pool_dir(node, page_size_kb);
    let nr_path = dir.join("nr_hugepages");
    let free_path = dir.join("free_hugepages");

    let Some(free_now) = read_count(&free_path) else {
        debug!(
            "no {page_size_kb} kB pool at {} on this kernel",
            dir.display()
        );
        return 0;
    };
    if free_now >= want_pages {
        debug!(
            "{free_now} free {page_size_kb} kB page(s) already available{}",
            node.map_or(String::new(), |n| format!(" on node {n}"))
        );
        return free_now;
    }

    let Some(nr_now) = read_count(&nr_path) else {
        return free_now;
    };
    let target = nr_now.saturating_add(want_pages - free_now);
    if let Err(e) = fs::write(&nr_path, target.to_string()) {
        warn!(
            "could not grow the {page_size_kb} kB pool to {target} via {}: {e}. \
             This usually means the process lacks CAP_SYS_ADMIN or sysfs is mounted read-only.",
            nr_path.display()
        );
        return free_now;
    }

    // The kernel silently gives less than asked when it cannot find the contiguous memory, so the
    // write succeeding proves nothing. Only the read-back is evidence.
    read_count(&free_path).unwrap_or(free_now)
}

/// Reserve hugepages for every NUMA node the configured devices sit on.
///
/// Tries 1 GiB pages first and falls back to 2 MiB, compacting before each attempt. Returns the
/// plan that was actually achieved, or `None` when nothing could be secured -- in which case the
/// dataplane is left to whatever the host already has, exactly as before this existed.
#[must_use]
pub fn reserve_for(devices: &[PciAddress]) -> Option<HugepagePlan> {
    let mut nodes: Vec<Option<u32>> = devices.iter().copied().map(numa_node_of).collect();
    nodes.sort_unstable();
    nodes.dedup();
    if nodes.is_empty() {
        return None;
    }
    info!(
        "reserving hugepages for NUMA node(s) {}",
        nodes
            .iter()
            .map(|n| n.map_or("(node-agnostic)".to_string(), |n| n.to_string()))
            .collect::<Vec<_>>()
            .join(", ")
    );

    for page_size_kb in [ONE_GIB_KB, TWO_MIB_KB] {
        let want_pages = WANT_KB_PER_NODE / page_size_kb;
        let mut secured: BTreeMap<u32, u64> = BTreeMap::new();
        let mut short = false;

        for &node in &nodes {
            compact(node);
            let got = try_reserve(node, page_size_kb, want_pages);
            if got < want_pages {
                short = true;
            }
            // A node-agnostic device still contributes its pages, under node 0, because that is
            // the only index `--numa-mem` can name on a machine with no NUMA topology to speak of.
            let key = node.unwrap_or(0);
            let mb = (got * page_size_kb) / 1024;
            secured
                .entry(key)
                .and_modify(|e| *e = (*e).max(mb))
                .or_insert(mb);
        }

        let total: u64 = secured.values().sum();
        if total == 0 {
            continue;
        }
        let plan = HugepagePlan {
            page_size_kb,
            per_node_mb: secured.into_iter().collect(),
        };
        if short {
            info!(
                "could not get the full {} MiB of {page_size_kb} kB pages on every node; \
                 proceeding with {plan}",
                WANT_KB_PER_NODE / 1024
            );
        } else {
            info!("reserved {plan}");
        }
        return Some(plan);
    }

    warn!(
        "could not reserve any hugepages; the dataplane will use whatever the host already has. \
         On a host that has been up for a while, reserve 1 GiB pages at boot with \
         `hugepagesz=1G hugepages=N` on the kernel command line."
    );
    None
}
