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
use args::dpdk_memory::{RESERVE_MIB, RX_DESCRIPTOR_CHOICES, RX_DESCRIPTORS, required_mib};
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

/// Which NUMA node each device's memory belongs on, grouped by node, or `None` if that cannot be
/// established: the memory then goes on no particular node, with a warning (the NICs still work,
/// only without locality).
fn locate(
    devices: &[PciAddress],
    topology: Option<&[u32]>,
    mut affinity: impl FnMut(PciAddress) -> Result<i32, String>,
) -> Result<Option<BTreeMap<u32, Vec<PciAddress>>>, String> {
    if devices.is_empty() {
        return Err("no devices were supplied for hugepage reservation".into());
    }
    let Some(topology) = topology else {
        warn!(
            "the NUMA topology is unknown; reserving hugepages on no particular node, so the NICs \
             run without memory locality"
        );
        return Ok(None);
    };
    let mut on_node: BTreeMap<u32, Vec<PciAddress>> = BTreeMap::new();
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
                return Ok(None);
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
            return Ok(None);
        }
        on_node.entry(node).or_default().push(address);
    }
    Ok(Some(on_node))
}

/// Decide where the memory goes, and how much, before changing any pool.
///
/// `required(devices)` is the memory one node needs for those devices' ports; see [`locate`].
#[cfg(test)]
fn place(
    devices: &[PciAddress],
    topology: Option<&[u32]>,
    affinity: impl FnMut(PciAddress) -> Result<i32, String>,
    required: impl Fn(&[PciAddress]) -> u64,
) -> Result<Placement, String> {
    Ok(placement(
        devices,
        locate(devices, topology, affinity)?.as_ref(),
        required,
    ))
}

/// The memory `required` for each group of `located` devices, or for all `devices` on no
/// particular node.
fn placement(
    devices: &[PciAddress],
    located: Option<&BTreeMap<u32, Vec<PciAddress>>>,
    required: impl Fn(&[PciAddress]) -> u64,
) -> Placement {
    match located {
        None => Placement::Anywhere(required(devices)),
        Some(nodes) => Placement::Nodes(
            nodes
                .iter()
                .map(|(node, devices)| (*node, required(devices)))
                .collect(),
        ),
    }
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
    allowance: impl FnMut(u64) -> Result<Option<u64>, String>,
    pools: &mut impl Pools,
) -> Result<HugepagePlan, String> {
    plan_with(&[ONE_GIB_KB, TWO_MIB_KB], placement, allowance, pools)
}

/// [`plan_for`], trying only the page sizes in `sizes_kb`, in order.
fn plan_with(
    sizes_kb: &[u64],
    placement: &Placement,
    mut allowance: impl FnMut(u64) -> Result<Option<u64>, String>,
    pools: &mut impl Pools,
) -> Result<HugepagePlan, String> {
    let total_mib = placement.total_mib()?;
    let mut failures = Vec::new();
    for &size_kb in sizes_kb {
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
                debug!("cannot use {size_kb} kB hugepages: {error}");
                failures.push(format!("{size_kb} kB: {error}"));
            }
        }
    }
    Err(format!(
        "no supported hugepage size satisfies the dataplane requirement: {}",
        failures.join("; ")
    ))
}

/// The hugepages reserved for EAL, and the receive descriptors chosen for the ports that named
/// none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reservation {
    pub plan: HugepagePlan,
    /// By port, for those without `/rxd=N`.
    pub rx_descriptors: BTreeMap<PciAddress, u16>,
}

/// The deepest of [`RX_DESCRIPTOR_CHOICES`] whose memory, `need(rxd)` in MiB with [`RESERVE_MIB`]
/// to spare, fits `budget_mib`.
fn deepest_fitting(need: impl Fn(u16) -> u64, budget_mib: u64) -> Option<u16> {
    RX_DESCRIPTOR_CHOICES
        .into_iter()
        .find(|&rxd| need(rxd).saturating_add(RESERVE_MIB) <= budget_mib)
}

/// What one node's ports need with the given hugepage budget per node: the receive descriptors
/// for the ports that named none.
///
/// # Errors
///
/// If the ports do not fit the budget even at [`RX_DESCRIPTORS`].
fn within_budget(need: impl Fn(u16) -> u64, budget_mib: u64, node: &str) -> Result<u16, String> {
    if let Some(rxd) = deepest_fitting(&need, budget_mib) {
        info!(
            "{node}: {rxd} receive descriptors per queue, whose pools take {} MiB of the {budget_mib} \
             MiB of hugepages, with {RESERVE_MIB} MiB to spare",
            need(rxd)
        );
        return Ok(rxd);
    }
    let least = need(RX_DESCRIPTORS);
    if least <= budget_mib {
        warn!(
            "{node}: {RX_DESCRIPTORS} receive descriptors per queue, whose pools take {least} MiB of \
             the {budget_mib} MiB of hugepages, leaving less than the {RESERVE_MIB} MiB wanted for \
             ACL tables and NIC offload"
        );
        return Ok(RX_DESCRIPTORS);
    }
    Err(format!(
        "{node}: the hugepage allotment of {budget_mib} MiB is too small for the configured ports \
         and workers: they need {least} MiB at {RX_DESCRIPTORS} receive descriptors per queue"
    ))
}

/// Prepare the hugepages, respecting the administrator's cgroup limits, and choose the receive
/// descriptors of the ports that named none.
///
/// `ports` are the NICs with each one's `/rxd=N`, if any. `scan` is `None` when hwloc could not
/// describe the machine; the memory is then reserved on no particular node. `workers` sizes the
/// pools.
///
/// With `gib_per_node`, that many 1 GiB pages per NIC node are the budget: they must be available
/// (there is no falling back to 2 MiB pages), the ports and workers must fit in them, and the
/// ports without `/rxd=N` get the deepest ring of [`RX_DESCRIPTOR_CHOICES`] that leaves
/// [`RESERVE_MIB`] free. Without it, those ports get a deeper ring only if 1 GiB pages already free
/// hold it with the reserve to spare, and [`RX_DESCRIPTORS`] otherwise, with the requirement
/// computed (and the pools grown) as before.
///
/// # Errors
///
/// Returns an error if a NIC's NUMA affinity cannot be read, cgroup controls cannot be read,
/// the ports do not fit the allotment, or no hugepage size satisfies the requirement.
pub fn reserve_for(
    ports: &[(PciAddress, Option<u16>)],
    scan: Option<&hardware::Node>,
    workers: u16,
    gib_per_node: Option<u32>,
) -> Result<Reservation, String> {
    let devices: Vec<PciAddress> = ports.iter().map(|(address, _)| *address).collect();
    let total_ports = u32::try_from(ports.len()).unwrap_or(u32::MAX);
    // The memory `devices` need, the ports without `/rxd=N` at `rxd`.
    let need = |devices: &[PciAddress], rxd: u16| {
        required_mib(
            ports
                .iter()
                .filter(|(address, _)| devices.contains(address))
                .map(|(_, named)| named.unwrap_or(rxd)),
            total_ports,
            workers,
        )
    };
    let unnamed: Vec<PciAddress> = ports
        .iter()
        .filter(|(_, named)| named.is_none())
        .map(|(address, _)| *address)
        .collect();
    let located = locate(&devices, topology_nodes(scan).as_deref(), numa_node_of)?;
    let cgroup = HugetlbCgroup::discover()?;
    let grow = !std::env::var(DISABLE_ENV).is_ok_and(|setting| setting.eq_ignore_ascii_case("off"));
    let allowance = |size| cgroup.remaining_bytes(size);
    let deeper = || {
        if unnamed.is_empty() {
            None
        } else {
            deeper_in_free_pages(
                &devices,
                located.as_ref(),
                &need,
                allowance,
                &mut SysfsPools { grow: false },
            )
        }
    };
    let (plan, rxd_of) = if let Some(gib) = gib_per_node {
        within_allotment(
            &devices,
            located.as_ref(),
            &need,
            gib,
            allowance,
            &mut SysfsPools { grow },
        )?
    } else if let Some(found) = deeper() {
        found
    } else {
        let placement = placement(&devices, located.as_ref(), |devices| {
            need(devices, RX_DESCRIPTORS)
        });
        let plan = plan_for(&placement, allowance, &mut SysfsPools { grow })?;
        (plan, BTreeMap::new())
    };
    info!("hugepages available for EAL: {plan}");
    let rx_descriptors = unnamed
        .iter()
        .map(|&address| {
            (
                address,
                rxd_of.get(&address).copied().unwrap_or(RX_DESCRIPTORS),
            )
        })
        .collect();
    Ok(Reservation {
        plan,
        rx_descriptors,
    })
}

/// The allotment of `gib` 1 GiB pages per NIC node, and the deepest ring of each node's ports
/// within it.
fn within_allotment(
    devices: &[PciAddress],
    located: Option<&BTreeMap<u32, Vec<PciAddress>>>,
    need: &dyn Fn(&[PciAddress], u16) -> u64,
    gib: u32,
    allowance: impl FnMut(u64) -> Result<Option<u64>, String>,
    pools: &mut impl Pools,
) -> Result<(HugepagePlan, BTreeMap<PciAddress, u16>), String> {
    let budget = u64::from(gib) * 1024;
    let mut rxd_of = BTreeMap::new();
    if let Some(nodes) = located {
        for (node, on_node) in nodes {
            let rxd = within_budget(
                |rxd| need(on_node, rxd),
                budget,
                &format!("NUMA node {node}"),
            )?;
            rxd_of.extend(on_node.iter().map(|&address| (address, rxd)));
        }
    } else {
        let rxd = within_budget(|rxd| need(devices, rxd), budget, "the NICs")?;
        rxd_of.extend(devices.iter().map(|&address| (address, rxd)));
    }
    let placement = placement(devices, located, |_| budget);
    let plan = plan_with(&[ONE_GIB_KB], &placement, allowance, pools).map_err(|e| {
        format!("the hugepage allotment of {gib} GiB per NIC node is unavailable: {e}")
    })?;
    Ok((plan, rxd_of))
}

/// The deepest ring deeper than [`RX_DESCRIPTORS`] whose memory, with [`RESERVE_MIB`] to spare,
/// 1 GiB pages already free hold: deeper rings are not worth growing the pools for, so `pools`
/// must not grow.
fn deeper_in_free_pages(
    devices: &[PciAddress],
    located: Option<&BTreeMap<u32, Vec<PciAddress>>>,
    need: &dyn Fn(&[PciAddress], u16) -> u64,
    mut allowance: impl FnMut(u64) -> Result<Option<u64>, String>,
    pools: &mut impl Pools,
) -> Option<(HugepagePlan, BTreeMap<PciAddress, u16>)> {
    for rxd in RX_DESCRIPTOR_CHOICES
        .into_iter()
        .filter(|&rxd| rxd > RX_DESCRIPTORS)
    {
        let placement = placement(devices, located, |devices| {
            need(devices, rxd).saturating_add(RESERVE_MIB)
        });
        match plan_with(&[ONE_GIB_KB], &placement, &mut allowance, pools) {
            Ok(plan) => {
                info!(
                    "{rxd} receive descriptors per queue fit the free 1 GiB hugepages with \
                     {RESERVE_MIB} MiB to spare"
                );
                return Some((
                    plan,
                    devices.iter().map(|&address| (address, rxd)).collect(),
                ));
            }
            Err(e) => debug!("no room for {rxd} receive descriptors per queue: {e}"),
        }
    }
    None
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
    fn per_port(devices: &[PciAddress]) -> u64 {
        devices.len() as u64 * 1024
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

    /// Two ports on node 0, the ports naming no receive descriptors (32 workers, so that each
    /// step of ring depth costs more than a 1 GiB page).
    fn two_ports() -> (Vec<PciAddress>, BTreeMap<u32, Vec<PciAddress>>) {
        let devices = vec![device(), PciAddress::try_from("0000:02:02.0").unwrap()];
        let located = BTreeMap::from([(0, devices.clone())]);
        (devices, located)
    }

    fn two_port_need(devices: &[PciAddress], rxd: u16) -> u64 {
        required_mib(devices.iter().map(|_| rxd), 2, 32)
    }

    /// With room to spare, the deepest of the choices; with little, the shallowest.
    #[test]
    fn an_allotment_gets_the_deepest_ring_it_holds_with_the_reserve() {
        let (devices, located) = two_ports();
        let fits = |rxd| two_port_need(&devices, rxd) + RESERVE_MIB;
        for (gib, rxd) in [
            (64, 4096),
            (u32::try_from(fits(2048).div_ceil(1024)).unwrap(), 2048),
            (
                u32::try_from(two_port_need(&devices, 1024).div_ceil(1024)).unwrap(),
                1024,
            ),
        ] {
            let mut pools = growing();
            let (plan, chosen) = within_allotment(
                &devices,
                Some(&located),
                &two_port_need,
                gib,
                |_| Ok(None),
                &mut pools,
            )
            .unwrap();
            assert_eq!(plan.page_size_kb, ONE_GIB_KB);
            assert_eq!(plan.per_node_mb, vec![(0, u64::from(gib) * 1024)]);
            assert!(
                chosen.values().all(|&r| r == rxd) && chosen.len() == 2,
                "{gib} GiB: {chosen:?}"
            );
        }
    }

    /// An allotment the ports do not fit at the shallowest ring is refused, and so is one not
    /// available in 1 GiB pages, whatever 2 MiB pages there are.
    #[test]
    fn an_allotment_too_small_or_unavailable_is_fatal() {
        let (devices, located) = two_ports();
        let error = within_allotment(
            &devices,
            Some(&located),
            &|devices, rxd| two_port_need(devices, rxd) * 100,
            1,
            |_| Ok(None),
            &mut growing(),
        )
        .unwrap_err();
        assert!(error.contains("too small"), "{error}");
        let mut pools = FakePools::default();
        pools.nr.insert((Pool::Node(0), TWO_MIB_KB), 1 << 20);
        let error = within_allotment(
            &devices,
            Some(&located),
            &two_port_need,
            8,
            |_| Ok(None),
            &mut pools,
        )
        .unwrap_err();
        assert!(error.contains("unavailable"), "{error}");
        assert_eq!(pools.nr.get(&(Pool::Node(0), ONE_GIB_KB)), None);
    }

    /// Without an allotment, a deeper ring only in 1 GiB pages already free.
    #[test]
    fn free_pages_alone_decide_a_deeper_ring() {
        let (devices, located) = two_ports();
        let pages = |rxd: u16| (two_port_need(&devices, rxd) + RESERVE_MIB).div_ceil(1024);
        for (free, rxd) in [
            (pages(4096), Some(4096)),
            (pages(2048), Some(2048)),
            (1, None),
        ] {
            let mut pools = FakePools::default();
            pools.nr.insert((Pool::Node(0), ONE_GIB_KB), free);
            let found = deeper_in_free_pages(
                &devices,
                Some(&located),
                &two_port_need,
                |_| Ok(None),
                &mut pools,
            );
            assert_eq!(
                found.map(|(_, chosen)| chosen[&devices[0]]),
                rxd,
                "{free} free pages"
            );
            assert_eq!(pools.nr.get(&(Pool::Node(0), ONE_GIB_KB)), Some(&free));
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
