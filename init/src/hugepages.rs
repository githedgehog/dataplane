// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Prepare hugepage pools within the process's cgroup allowance.
//!
//! Try 1 GiB pages, then 2 MiB pages; either size must satisfy the whole requirement. The
//! requirement is computed from the ports and workers (`args::dpdk_memory`) unless
//! `--hugepages-gib` overrides it. Pools are grown on the NICs' NUMA nodes; when that placement is
//! unknown -- hwloc failed, or a NIC reports no node on a multi-node host -- the global pools are
//! grown instead and EAL places the memory, which costs locality rather than the gateway. An
//! abandoned page size gives back what it grew. No pages are mapped or faulted here; EAL performs
//! the actual allocation.
//!
//! Free pages are counted net of the pages other processes have reserved but not yet faulted in.
//! The kernel reports those only globally, so on a multi-node host the count is conservative;
//! the gateway is assumed to have its host's hugepages to itself otherwise.

mod cgroup;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use args::HugepagePlan;
use args::dpdk_memory::required_mib;
use hardware::pci::address::PciAddress;
use tracing::{debug, info, warn};

use cgroup::HugetlbCgroup;

/// `off` disables pool growth, but still requires sufficient existing hugepages and quota.
const DISABLE_ENV: &str = "DATAPLANE_HUGEPAGE_RESERVE";
const ONE_GIB_KB: u64 = 1024 * 1024;
const TWO_MIB_KB: u64 = 2 * 1024;

/// Where the hugepages are wanted, and how much, in MiB.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Placement {
    /// On each of these NUMA nodes: the NICs' own.
    Nodes(BTreeMap<u32, u64>),
    /// On whichever nodes the kernel has them, because the NICs' placement is unknown.
    Anywhere(u64),
}

impl Placement {
    fn total_mib(&self) -> Result<u64, String> {
        match self {
            Placement::Nodes(nodes) => nodes
                .values()
                .try_fold(0u64, |sum, mib| sum.checked_add(*mib))
                .ok_or_else(|| "hugepage requirement overflow".into()),
            Placement::Anywhere(mib) => Ok(*mib),
        }
    }

    fn pools(&self) -> Vec<(Pool, u64)> {
        match self {
            Placement::Nodes(nodes) => nodes
                .iter()
                .map(|(node, mib)| (Pool::Node(*node), *mib))
                .collect(),
            Placement::Anywhere(mib) => vec![(Pool::Global, *mib)],
        }
    }
}

/// One of the kernel's hugepage pools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Pool {
    /// A NUMA node's pool.
    Node(u32),
    /// The system-wide pool, which the kernel spreads across nodes.
    Global,
}

impl Pool {
    fn dir(self, page_size_kb: u64) -> PathBuf {
        match self {
            Pool::Node(node) => PathBuf::from(format!(
                "/sys/devices/system/node/node{node}/hugepages/hugepages-{page_size_kb}kB"
            )),
            Pool::Global => global_dir(page_size_kb),
        }
    }
}

fn global_dir(page_size_kb: u64) -> PathBuf {
    PathBuf::from(format!(
        "/sys/kernel/mm/hugepages/hugepages-{page_size_kb}kB"
    ))
}

fn numa_node_of(address: PciAddress) -> Result<i32, String> {
    let path = format!("/sys/bus/pci/devices/{address}/numa_node");
    let raw = fs::read_to_string(&path).map_err(|e| format!("could not read {path}: {e}"))?;
    raw.trim()
        .parse::<i32>()
        .map_err(|e| format!("invalid NUMA affinity in {path}: {e}"))
}

/// The NUMA nodes in the hardware scan, or `None` if there was no usable scan.
fn topology_nodes(scan: Option<&hardware::Node>) -> Option<Vec<u32>> {
    let nodes: Option<Vec<u32>> = scan?
        .iter()
        .filter(|node| node.type_() == "NUMANode")
        .map(|node| node.os_index().and_then(|index| u32::try_from(index).ok()))
        .collect();
    nodes.filter(|nodes| !nodes.is_empty())
}

/// Decide where the memory goes, and how much, before changing any pool.
///
/// `required(ports)` is the memory one node needs for that many ports. Placement that cannot be
/// established degrades to [`Placement::Anywhere`] with a warning: the NICs still work, only
/// without locality.
fn place(
    devices: &[PciAddress],
    topology: Option<&[u32]>,
    mut affinity: impl FnMut(PciAddress) -> Result<i32, String>,
    required: impl Fn(u32) -> u64,
) -> Result<Placement, String> {
    if devices.is_empty() {
        return Err("no devices were supplied for hugepage reservation".into());
    }
    let anywhere = || {
        let ports = u32::try_from(devices.len()).unwrap_or(u32::MAX);
        Placement::Anywhere(required(ports))
    };
    let Some(topology) = topology else {
        warn!(
            "the NUMA topology is unknown; reserving hugepages on no particular node, so the NICs \
             run without memory locality"
        );
        return Ok(anywhere());
    };
    let mut ports: BTreeMap<u32, u32> = BTreeMap::new();
    for &address in devices {
        let node = match (affinity(address)?, topology) {
            (-1, &[node]) => {
                debug!("{address} reports no NUMA affinity; using the only NUMA node {node}");
                node
            }
            (-1, _) => {
                warn!(
                    "PCI device {address} reports no NUMA affinity on a multi-node host; \
                     reserving hugepages on no particular node, so the NICs run without memory \
                     locality"
                );
                return Ok(anywhere());
            }
            (reported, _) => u32::try_from(reported).map_err(|_| {
                format!("PCI device {address} reports invalid NUMA node {reported}")
            })?,
        };
        if !topology.contains(&node) {
            warn!(
                "PCI device {address} reports NUMA node {node}, which the hardware scan does not \
                 have; reserving hugepages on no particular node"
            );
            return Ok(anywhere());
        }
        *ports.entry(node).or_default() += 1;
    }
    Ok(Placement::Nodes(
        ports
            .into_iter()
            .map(|(node, ports)| (node, required(ports)))
            .collect(),
    ))
}

fn read_count(path: &Path) -> Result<u64, String> {
    fs::read_to_string(path)
        .map_err(|e| format!("could not read {}: {e}", path.display()))?
        .trim()
        .parse::<u64>()
        .map_err(|e| format!("invalid counter in {}: {e}", path.display()))
}

/// The kernel's hugepage pools, as [`plan_for`] uses them.
trait Pools {
    /// Make `pages` pages of `size_kb` free in `pool`, growing it if allowed. Returns the pool's
    /// size before it was grown, if it was, so the growth can be given back.
    fn ensure(&mut self, pool: Pool, size_kb: u64, pages: u64) -> Result<Option<u64>, String>;
    /// Shrink `pool` back to `nr` pages.
    fn restore(&mut self, pool: Pool, size_kb: u64, nr: u64) -> Result<(), String>;
}

/// The real pools, under sysfs.
struct SysfsPools {
    grow: bool,
}

impl SysfsPools {
    /// Free pages in `pool`, less what other processes have reserved but not yet faulted in.
    ///
    /// Reservations are only reported globally, so this subtracts them from a node's pool too,
    /// which errs on the side of a smaller count.
    fn available(pool: Pool, size_kb: u64) -> Result<u64, String> {
        let free = read_count(&pool.dir(size_kb).join("free_hugepages"))?;
        let reserved = read_count(&global_dir(size_kb).join("resv_hugepages")).unwrap_or(0);
        Ok(free.saturating_sub(reserved))
    }

    /// A compaction hint is optional; the final pool counters determine success.
    fn compact(pool: Pool) {
        let path = match pool {
            Pool::Node(node) => {
                PathBuf::from(format!("/sys/devices/system/node/node{node}/compact"))
            }
            Pool::Global => PathBuf::from("/proc/sys/vm/compact_memory"),
        };
        if let Err(e) = fs::write(&path, "1") {
            debug!("could not request compaction via {}: {e}", path.display());
        }
    }
}

impl Pools for SysfsPools {
    fn ensure(&mut self, pool: Pool, size_kb: u64, pages: u64) -> Result<Option<u64>, String> {
        let dir = pool.dir(size_kb);
        let available = Self::available(pool, size_kb)?;
        if available >= pages {
            return Ok(None);
        }
        if !self.grow {
            return Err(format!(
                "{} has {available} available pages, needs {pages}; pool growth is disabled",
                dir.display()
            ));
        }
        let nr_path = dir.join("nr_hugepages");
        let total = read_count(&nr_path)?;
        let target = total
            .checked_add(pages - available)
            .ok_or("hugepage pool size overflow")?;
        Self::compact(pool);
        fs::write(&nr_path, target.to_string()).map_err(|e| {
            format!(
                "could not grow {} to {target} pages: {e}",
                nr_path.display()
            )
        })?;
        // From here on the pool has (or may have) grown, so even a failure reports the old size:
        // the caller gives it back.
        let available = Self::available(pool, size_kb)?;
        if available < pages {
            self.restore(pool, size_kb, total)?;
            return Err(format!(
                "{} has only {available} available pages after reservation; needs {pages}",
                dir.display()
            ));
        }
        Ok(Some(total))
    }

    fn restore(&mut self, pool: Pool, size_kb: u64, nr: u64) -> Result<(), String> {
        let nr_path = pool.dir(size_kb).join("nr_hugepages");
        fs::write(&nr_path, nr.to_string())
            .map_err(|e| format!("could not shrink {} back to {nr}: {e}", nr_path.display()))
    }
}

/// Check quota before changing any pool, then reserve the whole placement in one page size.
///
/// Every pool a page size grows is given back if that size is abandoned, so a failed attempt
/// leaves nothing pinned behind. 2 MiB pages are the fallback, with a warning: 1 GiB pages are
/// what the TLB wants.
fn plan_for(
    placement: &Placement,
    mut allowance: impl FnMut(u64) -> Result<Option<u64>, String>,
    pools: &mut impl Pools,
) -> Result<HugepagePlan, String> {
    let total_mib = placement.total_mib()?;
    let mut failures = Vec::new();
    for size_kb in [ONE_GIB_KB, TWO_MIB_KB] {
        let mut grown: Vec<(Pool, u64)> = Vec::new();
        let attempt = (|| -> Result<HugepagePlan, String> {
            // hugetlb limits are per cgroup, not per node, so the whole placement counts.
            let required = total_mib
                .checked_mul(1024 * 1024)
                .ok_or("hugepage requirement overflow")?;
            if let Some(available) = allowance(size_kb)?
                && available < required
            {
                return Err(format!(
                    "cgroup permits {available} additional bytes; {required} required"
                ));
            }
            let mut per_node = Vec::new();
            let mut unplaced_mb = 0;
            for (pool, mib) in placement.pools() {
                // Whole pages, rounded up.
                let pages = (mib * 1024).div_ceil(size_kb);
                if let Some(before) = pools.ensure(pool, size_kb, pages)? {
                    grown.push((pool, before));
                }
                let mib = pages * size_kb / 1024;
                match pool {
                    Pool::Node(node) => per_node.push((node, mib)),
                    Pool::Global => unplaced_mb = mib,
                }
            }
            Ok(HugepagePlan {
                page_size_kb: size_kb,
                per_node_mb: per_node,
                unplaced_mb,
            })
        })();
        match attempt {
            Ok(plan) => {
                if !failures.is_empty() {
                    warn!(
                        "running on {size_kb} kB hugepages because 1 GiB pages were unavailable \
                         ({}); smaller pages cost TLB reach",
                        failures.join("; ")
                    );
                }
                return Ok(plan);
            }
            Err(error) => {
                for (pool, before) in grown.into_iter().rev() {
                    if let Err(e) = pools.restore(pool, size_kb, before) {
                        warn!("{e}; that memory stays pinned until the pool is shrunk by hand");
                    }
                }
                info!("cannot use {size_kb} kB hugepages: {error}");
                failures.push(format!("{size_kb} kB: {error}"));
            }
        }
    }
    Err(format!(
        "no supported hugepage size satisfies the dataplane requirement: {}",
        failures.join("; ")
    ))
}

/// Prepare the full hugepage requirement, respecting the administrator's cgroup limits.
///
/// `scan` is `None` when hwloc could not describe the machine; the memory is then reserved on no
/// particular node. `workers` and `gib_per_node` size the requirement (see the module docs).
///
/// # Errors
///
/// Returns an error if a NIC's NUMA affinity cannot be read, cgroup controls cannot be read,
/// or neither hugepage size satisfies the requirement.
pub fn reserve_for(
    devices: &[PciAddress],
    scan: Option<&hardware::Node>,
    workers: u16,
    gib_per_node: Option<u32>,
) -> Result<HugepagePlan, String> {
    let required = |ports: u32| match gib_per_node {
        Some(gib) => u64::from(gib) * 1024,
        None => required_mib(ports, workers),
    };
    let placement = place(
        devices,
        topology_nodes(scan).as_deref(),
        numa_node_of,
        required,
    )?;
    let cgroup = HugetlbCgroup::discover()?;
    let grow = !std::env::var(DISABLE_ENV).is_ok_and(|setting| setting.eq_ignore_ascii_case("off"));
    let plan = plan_for(
        &placement,
        |size| cgroup.remaining_bytes(size),
        &mut SysfsPools { grow },
    )?;
    info!("hugepages available for EAL: {plan}");
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) struct Fixture(pub(super) PathBuf);

    impl Fixture {
        pub(super) fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("init-hugepages-{}", id::Id::<Fixture>::new()));
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

    /// 1 GiB per port, so the arithmetic in the assertions stays readable.
    fn per_port(ports: u32) -> u64 {
        u64::from(ports) * 1024
    }

    /// Pools that hold `free` pages of each size, keyed by (pool, size), and record what changed.
    #[derive(Default)]
    struct FakePools {
        nr: BTreeMap<(Pool, u64), u64>,
        /// Pages each pool can grow by before the kernel runs out.
        headroom: BTreeMap<(Pool, u64), u64>,
        grow: bool,
    }

    impl Pools for FakePools {
        fn ensure(&mut self, pool: Pool, size_kb: u64, pages: u64) -> Result<Option<u64>, String> {
            let before = *self.nr.get(&(pool, size_kb)).unwrap_or(&0);
            if before >= pages {
                return Ok(None);
            }
            if !self.grow {
                return Err("pool growth is disabled".into());
            }
            let room = *self.headroom.get(&(pool, size_kb)).unwrap_or(&u64::MAX);
            let after = before + (pages - before).min(room);
            self.nr.insert((pool, size_kb), after);
            if after < pages {
                self.nr.insert((pool, size_kb), before);
                return Err(format!("only {after} pages"));
            }
            Ok(Some(before))
        }

        fn restore(&mut self, pool: Pool, size_kb: u64, nr: u64) -> Result<(), String> {
            self.nr.insert((pool, size_kb), nr);
            Ok(())
        }
    }

    fn growing() -> FakePools {
        FakePools {
            grow: true,
            ..FakePools::default()
        }
    }

    #[test]
    fn unknown_affinity_on_a_multi_node_host_reserves_on_no_particular_node() {
        let devices = [device(), PciAddress::try_from("0000:02:02.0").unwrap()];
        let placement = place(
            &devices,
            Some(&[0, 2]),
            |address| Ok(if address == devices[0] { 2 } else { -1 }),
            per_port,
        )
        .unwrap();
        assert_eq!(placement, Placement::Anywhere(2048));
    }

    #[test]
    fn a_missing_topology_reserves_on_no_particular_node() {
        let placement = place(
            &[device(); 3],
            None,
            |_| panic!("affinity means nothing without a topology"),
            per_port,
        )
        .unwrap();
        assert_eq!(placement, Placement::Anywhere(3072));
    }

    #[test]
    fn an_affinity_the_scan_does_not_have_reserves_on_no_particular_node() {
        let placement = place(&[device()], Some(&[0, 2]), |_| Ok(1), per_port).unwrap();
        assert_eq!(placement, Placement::Anywhere(1024));
    }

    #[test]
    fn unknown_affinity_uses_the_only_nodes_os_index() {
        let placement = place(&[device()], Some(&[2]), |_| Ok(-1), per_port).unwrap();
        let mut pools = growing();
        let plan = plan_for(&placement, |_| Ok(None), &mut pools).unwrap();
        assert_eq!(plan.per_node_mb, vec![(2, 1024)]);
        assert_eq!(plan.numa_mem_arg().as_deref(), Some("0,0,1024"));
        assert_eq!(pools.nr.get(&(Pool::Node(2), ONE_GIB_KB)), Some(&1));
    }

    #[test]
    fn invalid_or_unreadable_affinity_is_an_error() {
        let error = place(&[device()], Some(&[0, 2]), |_| Ok(-2), per_port).unwrap_err();
        assert!(error.contains("invalid NUMA node -2"));
        let error = place(
            &[device()],
            Some(&[0]),
            |_| Err("permission denied".into()),
            per_port,
        )
        .unwrap_err();
        assert_eq!(error, "permission denied");
    }

    #[test]
    fn ports_on_a_node_add_up() {
        let mut reported = [2, 0, 2].into_iter();
        let placement = place(
            &[device(); 3],
            Some(&[0, 2]),
            |_| Ok(reported.next().unwrap()),
            per_port,
        )
        .unwrap();
        assert_eq!(
            placement,
            Placement::Nodes(BTreeMap::from([(0, 1024), (2, 2048)]))
        );
    }

    #[test]
    fn an_unplaced_requirement_grows_the_global_pool() {
        let mut pools = growing();
        let plan = plan_for(&Placement::Anywhere(3072), |_| Ok(None), &mut pools).unwrap();
        assert_eq!(plan.unplaced_mb, 3072);
        assert_eq!(plan.per_node_mb, Vec::new());
        assert_eq!(plan.numa_mem_arg(), None);
        assert_eq!(pools.nr.get(&(Pool::Global, ONE_GIB_KB)), Some(&3));
    }

    #[test]
    fn a_requirement_is_rounded_up_to_whole_pages() {
        let mut pools = growing();
        let plan = plan_for(&Placement::Anywhere(1500), |_| Ok(None), &mut pools).unwrap();
        assert_eq!(plan.unplaced_mb, 2048);
        assert_eq!(pools.nr.get(&(Pool::Global, ONE_GIB_KB)), Some(&2));
    }

    #[test]
    fn zero_large_page_quota_uses_small_hugepages_without_touching_large_pool() {
        let mut pools = growing();
        let plan = plan_for(
            &Placement::Nodes(BTreeMap::from([(0, 4096)])),
            |size| Ok(Some(if size == ONE_GIB_KB { 0 } else { u64::MAX })),
            &mut pools,
        )
        .unwrap();
        assert_eq!(plan.page_size_kb, TWO_MIB_KB);
        assert_eq!(plan.per_node_mb, vec![(0, 4096)]);
        assert_eq!(pools.nr.get(&(Pool::Node(0), ONE_GIB_KB)), None);
        assert_eq!(pools.nr.get(&(Pool::Node(0), TWO_MIB_KB)), Some(&2048));
    }

    /// hugetlb limits are per cgroup, so two nodes need the quota for both.
    #[test]
    fn the_quota_covers_every_node() {
        let placement = Placement::Nodes(BTreeMap::from([(0, 4096), (1, 4096)]));
        let one_node = 4096 * 1024 * 1024;
        let error = plan_for(
            &placement,
            |_| Ok(Some(one_node)),
            &mut FakePools::default(),
        )
        .unwrap_err();
        assert!(error.contains("cgroup permits"));
        plan_for(&placement, |_| Ok(Some(2 * one_node)), &mut growing()).unwrap();
    }

    #[test]
    fn insufficient_or_unreadable_quota_is_fatal_before_pool_writes() {
        for allowance in [
            Ok(Some(0)),
            Ok(Some(4096 * 1024 * 1024 - 1)),
            Err("permission denied".to_string()),
        ] {
            let mut pools = growing();
            let error = plan_for(
                &Placement::Nodes(BTreeMap::from([(0, 4096)])),
                |_| allowance.clone(),
                &mut pools,
            )
            .unwrap_err();
            assert!(error.contains("no supported hugepage size"));
            assert!(pools.nr.is_empty(), "a pool changed without quota");
        }
    }

    /// The second node cannot supply 1 GiB pages, so the first node's growth is given back before
    /// 2 MiB pages are tried.
    #[test]
    fn an_abandoned_page_size_gives_back_what_it_grew() {
        let mut pools = growing();
        pools.nr.insert((Pool::Node(0), ONE_GIB_KB), 1);
        pools.headroom.insert((Pool::Node(1), ONE_GIB_KB), 2);
        let plan = plan_for(
            &Placement::Nodes(BTreeMap::from([(0, 4096), (1, 4096)])),
            |_| Ok(None),
            &mut pools,
        )
        .unwrap();
        assert_eq!(plan.page_size_kb, TWO_MIB_KB);
        assert_eq!(pools.nr.get(&(Pool::Node(0), ONE_GIB_KB)), Some(&1));
        assert_eq!(pools.nr.get(&(Pool::Node(1), ONE_GIB_KB)), Some(&0));
    }

    #[test]
    fn pool_failures_try_only_the_two_supported_hugepage_sizes() {
        let error = plan_for(
            &Placement::Anywhere(1024),
            |_| Ok(None),
            &mut FakePools::default(),
        )
        .unwrap_err();
        assert!(error.contains(&format!("{ONE_GIB_KB} kB")));
        assert!(error.contains(&format!("{TWO_MIB_KB} kB")));
    }

    #[test]
    fn counters_must_parse() {
        let files = Fixture::new();
        assert!(read_count(&files.0.join("missing")).is_err());
        files.write("broken", "many");
        assert!(read_count(&files.0.join("broken")).is_err());
        files.write("fine", "7\n");
        assert_eq!(read_count(&files.0.join("fine")).unwrap(), 7);
    }
}

/// Against a real kernel's pools and cgroups, which a VM makes safe to change.
///
/// The Ubuntu kernel, because the default test kernels cannot allocate 1 GiB pages at runtime
/// (no `CONFIG_CONTIG_ALLOC`), and no hugepages reserved at boot, so every pool starts empty.
#[cfg(test)]
mod vm_tests {
    use super::*;
    use n_vm::config::{GuestHugePageConfig, VmConfig};
    use n_vm::kernel_profiles;

    const ROOMY: VmConfig = VmConfig::DEFAULT
        .to_builder()
        .kernel_profile(kernel_profiles::UBUNTU)
        .guest_hugepages(GuestHugePageConfig::None)
        // Plenty, so that aligned, contiguous gigabytes are still free after boot: at 6 GiB a
        // second runtime 1 GiB page was sometimes unavailable.
        .memory_mib(12288)
        .build();

    /// Room for some of 4 GiB of hugepages, but not all of it, at either size.
    const CRAMPED: VmConfig = ROOMY.to_builder().memory_mib(3072).build();

    fn nr(pool: Pool, size_kb: u64) -> u64 {
        read_count(&pool.dir(size_kb).join("nr_hugepages")).unwrap()
    }

    fn pools() -> SysfsPools {
        SysfsPools { grow: true }
    }

    #[cfg_attr(
        sanitized,
        ignore = "exercises the kernel's hugepage pools, nothing a sanitizer checks; a sanitized \
                  build is too slow for the guest to report within its timeout"
    )]
    #[n_vm::test(config = ROOMY)]
    fn the_kernel_grows_its_pools_to_the_plan() {
        // Modest: a small guest has only a few aligned, contiguous gigabytes to give.
        let plan = plan_for(&Placement::Anywhere(1024), |_| Ok(None), &mut pools()).unwrap();
        assert_eq!(plan.page_size_kb, ONE_GIB_KB);
        assert_eq!(plan.unplaced_mb, 1024);
        assert_eq!(nr(Pool::Global, ONE_GIB_KB), 1);

        // A node's pool is a share of the global one; asking it for 2 GiB grows it by one page.
        let plan = plan_for(
            &Placement::Nodes(BTreeMap::from([(0, 2048)])),
            |_| Ok(None),
            &mut pools(),
        )
        .unwrap();
        assert_eq!(plan.page_size_kb, ONE_GIB_KB);
        assert_eq!(plan.per_node_mb, vec![(0, 2048)]);
        assert_eq!(nr(Pool::Node(0), ONE_GIB_KB), 2);
    }

    /// Put this process in a fresh cgroup whose hugetlb limits are `limits`: (file, bytes).
    fn confine(limits: &[(&str, u64)]) {
        let root = Path::new("/sys/fs/cgroup");
        if !root.join("cgroup.controllers").exists() {
            nix::mount::mount(
                Some("cgroup2"),
                root,
                Some("cgroup2"),
                nix::mount::MsFlags::empty(),
                None::<&str>,
            )
            .expect("cgroup2 should mount");
        }
        fs::write(root.join("cgroup.subtree_control"), "+hugetlb").unwrap();
        let group = root.join("gateway");
        fs::create_dir_all(&group).unwrap();
        for (file, bytes) in limits {
            fs::write(group.join(file), bytes.to_string()).unwrap();
        }
        fs::write(group.join("cgroup.procs"), std::process::id().to_string()).unwrap();
    }

    #[cfg_attr(
        sanitized,
        ignore = "exercises the kernel's hugepage pools, nothing a sanitizer checks; a sanitized \
                  build is too slow for the guest to report within its timeout"
    )]
    #[n_vm::test(config = ROOMY)]
    fn a_cgroup_without_large_page_quota_falls_back_to_small_pages() {
        confine(&[("hugetlb.1GB.max", 0)]);
        let cgroup = HugetlbCgroup::discover().unwrap();
        let plan = plan_for(
            &Placement::Anywhere(2048),
            |size| cgroup.remaining_bytes(size),
            &mut pools(),
        )
        .unwrap();
        assert_eq!(plan.page_size_kb, TWO_MIB_KB);
        assert_eq!(
            nr(Pool::Global, ONE_GIB_KB),
            0,
            "the 1 GiB pool was touched"
        );
        assert_eq!(nr(Pool::Global, TWO_MIB_KB), 1024);
    }

    #[cfg_attr(
        sanitized,
        ignore = "exercises the kernel's hugepage pools, nothing a sanitizer checks; a sanitized \
                  build is too slow for the guest to report within its timeout"
    )]
    #[n_vm::test(config = ROOMY)]
    fn a_cgroup_without_any_quota_fails_without_touching_a_pool() {
        confine(&[("hugetlb.1GB.max", 0), ("hugetlb.2MB.max", 0)]);
        let cgroup = HugetlbCgroup::discover().unwrap();
        let error = plan_for(
            &Placement::Anywhere(2048),
            |size| cgroup.remaining_bytes(size),
            &mut pools(),
        )
        .unwrap_err();
        assert!(error.contains("cgroup permits"), "{error}");
        assert_eq!(nr(Pool::Global, ONE_GIB_KB), 0);
        assert_eq!(nr(Pool::Global, TWO_MIB_KB), 0);
    }

    /// Both sizes grow part of the way and fail; neither may leave pages pinned behind.
    #[cfg_attr(
        sanitized,
        ignore = "exercises the kernel's hugepage pools, nothing a sanitizer checks; a sanitized \
                  build is too slow for the guest to report within its timeout"
    )]
    #[n_vm::test(config = CRAMPED)]
    fn a_partial_growth_is_given_back() {
        let error = plan_for(&Placement::Anywhere(4096), |_| Ok(None), &mut pools()).unwrap_err();
        assert!(error.contains("no supported hugepage size"), "{error}");
        assert_eq!(nr(Pool::Global, ONE_GIB_KB), 0, "1 GiB pages left pinned");
        assert_eq!(nr(Pool::Global, TWO_MIB_KB), 0, "2 MiB pages left pinned");
    }
}
