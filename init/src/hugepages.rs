// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Prepare hugepage pools within the process's cgroup allowance.
//!
//! Try 1 GiB pages, then 2 MiB pages. Either size must satisfy the full memory
//! requirement. Missing quota, unreadable controls, or insufficient pools fail
//! startup. No pages are mapped or faulted here; EAL performs the actual allocation.

mod cgroup;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use args::HugepagePlan;
use hardware::pci::address::PciAddress;
use tracing::{debug, info};

use cgroup::HugetlbCgroup;

/// `off` disables pool growth, but still requires sufficient existing hugepages and quota.
const DISABLE_ENV: &str = "DATAPLANE_HUGEPAGE_RESERVE";
const ONE_GIB_KB: u64 = 1024 * 1024;
const TWO_MIB_KB: u64 = 2 * 1024;
/// Required memory per distinct NIC NUMA node, in KiB.
const WANT_KB_PER_NODE: u64 = 4 * 1024 * 1024;

fn numa_node_of(address: PciAddress) -> Result<i32, String> {
    let path = format!("/sys/bus/pci/devices/{address}/numa_node");
    let raw = fs::read_to_string(&path).map_err(|e| format!("could not read {path}: {e}"))?;
    raw.trim()
        .parse::<i32>()
        .map_err(|e| format!("invalid NUMA affinity in {path}: {e}"))
}

fn topology_nodes(scan: &hardware::Node) -> Result<Vec<u32>, String> {
    scan.iter()
        .filter(|node| node.type_() == "NUMANode")
        .map(|node| {
            node.os_index()
                .and_then(|index| u32::try_from(index).ok())
                .ok_or_else(|| "hardware scan found a NUMA node without a valid OS index".into())
        })
        .collect()
}

/// Resolve every NIC before changing any pool. Unknown affinity is safe only with one node.
fn resolve_nodes(
    devices: &[PciAddress],
    topology: &[u32],
    mut affinity: impl FnMut(PciAddress) -> Result<i32, String>,
) -> Result<Vec<u32>, String> {
    if topology.is_empty() {
        return Err("hardware scan found no NUMA nodes".into());
    }
    let mut nodes = Vec::new();
    for &address in devices {
        let reported = affinity(address)?;
        let node = match (reported, topology) {
            (-1, &[node]) => {
                debug!("{address} reports no NUMA affinity; using the only NUMA node {node}");
                node
            }
            (-1, _) => {
                return Err(format!(
                    "PCI device {address} reports unknown NUMA affinity on a multi-node system"
                ));
            }
            (reported, _) => u32::try_from(reported).map_err(|_| {
                format!("PCI device {address} reports invalid NUMA node {reported}")
            })?,
        };
        if !topology.contains(&node) {
            return Err(format!(
                "PCI device {address} reports NUMA node {node}, which is absent from the hardware scan"
            ));
        }
        nodes.push(node);
    }
    nodes.sort_unstable();
    nodes.dedup();
    Ok(nodes)
}

fn pool_dir(node: u32, page_size_kb: u64) -> PathBuf {
    PathBuf::from(format!(
        "/sys/devices/system/node/node{node}/hugepages/hugepages-{page_size_kb}kB"
    ))
}

fn read_count(path: &Path) -> Result<u64, String> {
    fs::read_to_string(path)
        .map_err(|e| format!("could not read {}: {e}", path.display()))?
        .trim()
        .parse::<u64>()
        .map_err(|e| format!("invalid counter in {}: {e}", path.display()))
}

/// A compaction hint is optional; the final pool counters determine success.
fn compact(node: u32) {
    let path = PathBuf::from(format!("/sys/devices/system/node/node{node}/compact"));
    if let Err(e) = fs::write(&path, "1") {
        debug!("could not request compaction via {}: {e}", path.display());
    }
}

/// Grow only by the shortfall, then verify the kernel supplied the full amount.
fn ensure_pages(dir: &Path, wanted: u64, grow: bool, compact: impl FnOnce()) -> Result<(), String> {
    let free_path = dir.join("free_hugepages");
    let free = read_count(&free_path)?;
    if free >= wanted {
        return Ok(());
    }
    if !grow {
        return Err(format!(
            "{} has {free} free pages, needs {wanted}; pool growth is disabled",
            dir.display()
        ));
    }
    let nr_path = dir.join("nr_hugepages");
    let total = read_count(&nr_path)?;
    let target = total
        .checked_add(wanted - free)
        .ok_or("hugepage pool size overflow")?;
    compact();
    fs::write(&nr_path, target.to_string()).map_err(|e| {
        format!(
            "could not grow {} to {target} pages: {e}",
            nr_path.display()
        )
    })?;
    let free = read_count(&free_path)?;
    if free < wanted {
        return Err(format!(
            "{} has only {free} free pages after reservation; needs {wanted}",
            dir.display()
        ));
    }
    Ok(())
}

/// Check quota before changing any pool. All nodes must satisfy the selected size.
fn plan_for(
    nodes: &[u32],
    mut allowance: impl FnMut(u64) -> Result<Option<u64>, String>,
    mut reserve: impl FnMut(u32, u64, u64) -> Result<(), String>,
) -> Result<HugepagePlan, String> {
    if nodes.is_empty() {
        return Err("no devices were supplied for hugepage reservation".into());
    }
    let mut failures = Vec::new();
    for size in [ONE_GIB_KB, TWO_MIB_KB] {
        let attempt = || -> Result<HugepagePlan, String> {
            let required = WANT_KB_PER_NODE * 1024;
            if let Some(available) = allowance(size)?
                && available < required
            {
                return Err(format!(
                    "cgroup permits {available} additional bytes; {required} required"
                ));
            }
            let mut per_node = BTreeMap::new();
            for &node in nodes {
                reserve(node, size, WANT_KB_PER_NODE / size)?;
                per_node.insert(node, WANT_KB_PER_NODE / 1024);
            }
            Ok(HugepagePlan {
                page_size_kb: size,
                per_node_mb: per_node.into_iter().collect(),
            })
        }();
        match attempt {
            Ok(plan) => return Ok(plan),
            Err(error) => {
                info!("cannot use {size} kB hugepages: {error}");
                failures.push(format!("{size} kB: {error}"));
            }
        }
    }
    Err(format!(
        "no supported hugepage size satisfies the dataplane requirement: {}",
        failures.join("; ")
    ))
}

/// Prepare the full hugepage requirement, respecting the administrator's cgroup limits.
/// Single-node hosts receive the same quota and pool checks as multi-node hosts.
///
/// # Errors
///
/// Returns an error if NIC NUMA placement is unresolved, cgroup controls cannot be read,
/// or neither hugepage size satisfies the requirement. The caller must stop startup on failure.
pub fn reserve_for(devices: &[PciAddress], scan: &hardware::Node) -> Result<HugepagePlan, String> {
    let nodes = resolve_nodes(devices, &topology_nodes(scan)?, numa_node_of)?;
    let cgroup = HugetlbCgroup::discover()?;
    let grow = !std::env::var(DISABLE_ENV).is_ok_and(|setting| setting.eq_ignore_ascii_case("off"));
    let plan = plan_for(
        &nodes,
        |size| cgroup.remaining_bytes(size),
        |node, size, wanted| ensure_pages(&pool_dir(node, size), wanted, grow, || compact(node)),
    )?;
    info!("hugepages available for EAL: {plan}");
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub(super) struct Fixture(pub(super) PathBuf);

    impl Fixture {
        pub(super) fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let root = std::env::temp_dir().join(format!(
                "init-hugepages-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            Self(root)
        }

        pub(super) fn write(&self, name: &str, value: &str) {
            let path = self.0.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, value).unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn device() -> PciAddress {
        PciAddress::try_from("0000:02:01.0").unwrap()
    }

    #[test]
    fn unknown_affinity_is_fatal_with_multiple_nodes() {
        let devices = [device(), PciAddress::try_from("0000:02:02.0").unwrap()];
        let error = resolve_nodes(&devices, &[0, 2], |address| {
            Ok(if address == devices[0] { 2 } else { -1 })
        })
        .unwrap_err();
        assert!(error.contains("0000:02:02.0"));
        assert!(error.contains("unknown NUMA affinity on a multi-node system"));
    }

    #[test]
    fn unknown_affinity_uses_the_only_nodes_os_index() {
        let nodes = resolve_nodes(&[device()], &[2], |_| Ok(-1)).unwrap();
        let mut reservations = Vec::new();
        let plan = plan_for(
            &nodes,
            |_| Ok(None),
            |node, size, _| {
                reservations.push(pool_dir(node, size));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(plan.per_node_mb, vec![(2, 4096)]);
        assert_eq!(plan.numa_mem_arg().as_deref(), Some("0,0,4096"));
        assert_eq!(
            reservations,
            vec![PathBuf::from(
                "/sys/devices/system/node/node2/hugepages/hugepages-1048576kB"
            )]
        );
    }

    #[test]
    fn affinity_must_name_a_node_in_the_scan() {
        for topology in [&[0][..], &[0, 2][..]] {
            for reported in [-2, 1] {
                let error = resolve_nodes(&[device()], topology, |_| Ok(reported)).unwrap_err();
                assert!(error.contains("0000:02:01.0"));
                assert!(error.contains("invalid NUMA node") || error.contains("absent"));
            }
        }
    }

    #[test]
    fn missing_topology_and_unreadable_affinity_are_errors() {
        let error =
            resolve_nodes(&[device()], &[], |_| panic!("topology is required")).unwrap_err();
        assert!(error.contains("no NUMA nodes"));
        for topology in [&[0][..], &[0, 2][..]] {
            let error = resolve_nodes(&[device()], topology, |_| Err("permission denied".into()))
                .unwrap_err();
            assert_eq!(error, "permission denied");
        }
    }

    #[test]
    fn devices_on_the_same_node_share_one_pool_requirement() {
        let nodes = resolve_nodes(&[device(); 3], &[0, 2], |_| Ok(2)).unwrap();
        assert_eq!(nodes, vec![2]);
        let mut reported = [2, 0, 2].into_iter();
        let nodes =
            resolve_nodes(&[device(); 3], &[0, 2], |_| Ok(reported.next().unwrap())).unwrap();
        assert_eq!(nodes, vec![0, 2]);
    }

    #[test]
    fn zero_large_page_quota_uses_small_hugepages_without_touching_large_pool() {
        let mut reservations = Vec::new();
        let plan = plan_for(
            &[0],
            |size| {
                Ok(Some(if size == ONE_GIB_KB {
                    0
                } else {
                    WANT_KB_PER_NODE * 1024
                }))
            },
            |node, size, wanted| {
                reservations.push((node, size, wanted));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(plan.page_size_kb, TWO_MIB_KB);
        assert_eq!(plan.per_node_mb, vec![(0, 4096)]);
        assert_eq!(reservations, vec![(0, TWO_MIB_KB, 2048)]);
    }

    #[test]
    fn insufficient_or_unreadable_quota_is_fatal_before_pool_writes() {
        for allowance in [
            Ok(Some(0)),
            Ok(Some(WANT_KB_PER_NODE * 1024 - 1)),
            Err("permission denied".to_string()),
        ] {
            let error = plan_for(
                &[0],
                |_| allowance.clone(),
                |_, _, _| panic!("must not change a pool without quota"),
            )
            .unwrap_err();
            assert!(error.contains("no supported hugepage size"));
        }
    }

    #[test]
    fn pool_failures_try_only_the_two_supported_hugepage_sizes() {
        let mut sizes = Vec::new();
        let error = plan_for(
            &[0],
            |_| Ok(None),
            |_, size, _| {
                sizes.push(size);
                Err("cannot allocate enough pages".into())
            },
        )
        .unwrap_err();
        assert_eq!(sizes, vec![ONE_GIB_KB, TWO_MIB_KB]);
        assert!(error.contains("cannot allocate enough pages"));
    }

    #[test]
    fn an_existing_pool_does_not_require_write_access_or_compaction() {
        let files = Fixture::new();
        files.write("free_hugepages", "4");
        // No writable nr_hugepages is needed when the pool is already sufficient.
        ensure_pages(&files.0, 4, true, || panic!("no compaction needed")).unwrap();
        ensure_pages(&files.0, 4, false, || panic!("growth is disabled")).unwrap();
        assert!(!files.0.join("nr_hugepages").exists());
    }

    #[test]
    fn an_empty_pool_is_grown_and_checked_again() {
        let files = Fixture::new();
        files.write("free_hugepages", "0");
        files.write("nr_hugepages", "3");
        ensure_pages(&files.0, 4, true, || files.write("free_hugepages", "4")).unwrap();
        assert_eq!(read_count(&files.0.join("nr_hugepages")).unwrap(), 7);
    }

    #[test]
    fn a_successful_write_with_too_few_pages_is_fatal() {
        let files = Fixture::new();
        files.write("free_hugepages", "1");
        files.write("nr_hugepages", "8");
        let error = ensure_pages(&files.0, 4, true, || {}).unwrap_err();
        assert!(error.contains("only 1 free pages after reservation"));
        assert_eq!(read_count(&files.0.join("nr_hugepages")).unwrap(), 11);
    }

    #[test]
    fn disabled_growth_still_requires_sufficient_existing_pages() {
        let files = Fixture::new();
        files.write("free_hugepages", "0");
        files.write("nr_hugepages", "3");
        let error = ensure_pages(&files.0, 4, false, || panic!("growth is disabled")).unwrap_err();
        assert!(error.contains("growth is disabled"));
        assert_eq!(read_count(&files.0.join("nr_hugepages")).unwrap(), 3);
    }

    #[test]
    fn unreadable_counters_or_unwritable_pool_are_errors() {
        let files = Fixture::new();
        assert!(ensure_pages(&files.0, 4, true, || {}).is_err());
        files.write("free_hugepages", "broken");
        assert!(ensure_pages(&files.0, 4, true, || {}).is_err());
        files.write("free_hugepages", "0");
        files.write("nr_hugepages", "0");
        let error = ensure_pages(&files.0, 4, true, || {
            fs::remove_file(files.0.join("nr_hugepages")).unwrap();
            fs::create_dir(files.0.join("nr_hugepages")).unwrap();
        })
        .unwrap_err();
        assert!(error.contains("could not grow"));
    }
}
