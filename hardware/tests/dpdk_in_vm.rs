// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK-in-VM integration tests.
//!
//! ## Phase 0 — EAL init spike
//!
//! Verify DPDK EAL initialisation and device binding inside a VM guest
//! with virtio-net NICs.
//!
//! ## Phase 1 — Receive traffic spike
//!
//! Transmit an ICMPv6 Neighbor Solicitation out a DPDK port, receive the
//! kernel's Neighbor Advertisement on the same port, and parse it with
//! [`Headers::parse`](net::headers::Headers).
//!
//! The TAP interfaces backing the guest NICs have IPv6 link-local
//! addresses configured by cloud-hypervisor (`fe80::ffff:1` for mgmt,
//! `fe80::1` for fabric1, etc.).  When we TX an NS targeting the
//! all-nodes multicast group (`ff02::1`), the host kernel responds on
//! the same TAP, and the response appears in the DPDK rx ring.
//!
//! # Host page size
//!
//! By default every test uses 1 GiB hugepages on the host to back the
//! VM's memory (`memory-backend-file` pointing at `/dev/hugepages`).
//! Tests suffixed with `_4k` override this to standard 4 KiB pages
//! (`memory-backend-memfd`) via `#[hypervisor(host_pages = "4k")]`.
//! This exercises the deployment path where no host hugepages are
//! available.  Guest-side hugepages (2 MiB, reserved via the kernel
//! command line) are unaffected — DPDK still gets its hugepage-backed
//! mempools inside the VM.
//!
//! Transparent Huge Pages (THP) on the host may silently coalesce the
//! memfd-backed 4 KiB pages into 2 MiB pages, but this is invisible to
//! the guest and should not affect correctness.
//!
//! # Supported NIC models
//!
//! | NIC model | Hypervisor | DPDK PMD | IOMMU variants |
//! |-----------|------------|----------|----------------|
//! | virtio-net | cloud-hypervisor, QEMU | `net_virtio` | no-IOMMU (PA), vIOMMU (VA) |
//! | e1000 (Intel 82540EM) | QEMU only | `net_e1000_em` | no-IOMMU (PA), vIOMMU (VA) |
//! | e1000e (Intel 82574L) | QEMU only | `net_e1000_igb` | no-IOMMU (PA), vIOMMU (VA) |
//!
//! The NIC model is selected via the `#[network(nic_model = "…")]`
//! companion attribute on each test function.  PCI discovery
//! ([`discover_pci_net_devices`]) auto-detects all supported NIC types
//! by vendor/device ID so the same `setup_dpdk_device` path works for
//! every model.
//!
//! # Prerequisites
//!
//! The VM image must include:
//!
//! - The `vfio-pci` driver built into the kernel (the VM kernel has no
//!   module support — `CONFIG_MODULES=n`).
//! - Kernel drivers for all tested NIC types (`CONFIG_VIRTIO_NET`,
//!   `CONFIG_E1000`, `CONFIG_E1000E`) so VFIO can unbind and rebind.
//! - Hugepage reservation matching the `#[guest]` attribute (64 × 2 MiB).

use dataplane_hardware::nic::{BindToVfioPci, PciNic};
use dataplane_hardware::pci::address::PciAddress;
use dpdk::dev::{Dev, DevConfig, RxOffload, Started, TxOffloadConfig};
use dpdk::eal::{self, Eal};
use dpdk::mem::{MbufArray, Pool, PoolConfig, PoolParams};
use dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dpdk::socket;
#[allow(unused_imports)]
// consumed by #[guest(…)], #[hypervisor(…)], #[network(…)] proc-macro attributes
use n_vm::config::{GuestHugePageConfig, GuestHugePageSize, HostPageSize, NicModel, VmConfig};
use n_vm::kernel_profiles;
use net::buffer::Append;
use net::headers::Headers;
use net::parse::Parse;
use std::fs;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Red Hat / virtio vendor ID.
const VIRTIO_VENDOR_ID: u16 = 0x1af4;

/// Legacy virtio-net device ID (transitional device).
const VIRTIO_NET_DEVICE_LEGACY: u16 = 0x1000;

/// Modern virtio-net device ID (non-transitional, virtio 1.0+).
const VIRTIO_NET_DEVICE_MODERN: u16 = 0x1041;

/// Intel vendor ID.
const INTEL_VENDOR_ID: u16 = 0x8086;

/// Intel 82540EM Gigabit Ethernet (QEMU `e1000` device).
const E1000_DEVICE_ID: u16 = 0x100e;

/// Intel 82574L Gigabit Ethernet (QEMU `e1000e` device).
const E1000E_DEVICE_ID: u16 = 0x10d3;

/// Root path for PCI device enumeration in sysfs.
const PCI_DEVICES_PATH: &str = "/sys/bus/pci/devices";

/// Hugetlbfs mount point created by `n-it` for 2 MiB hugepages.
///
/// The `n-it` init system mounts hugetlbfs at `/run/huge/2MiB` (with
/// `pagesize=2M`) and `/run/huge/1GiB` (with `pagesize=1G`).  These
/// are **not** at the conventional `/dev/hugepages` path, so DPDK must
/// be told explicitly via `--huge-dir`.
///
/// We use 2 MiB pages because the default VM has only 512 MiB of RAM —
/// a single 1 GiB hugepage cannot be reserved.
const HUGEPAGE_DIR: &str = "/run/huge/2MiB";

/// Sysfs directory containing per-page-size hugepage accounting.
const HUGEPAGES_SYSFS: &str = "/sys/kernel/mm/hugepages";

/// The sysfs path where the `vfio-pci` driver directory must exist.
///
/// The VM kernel is built with `CONFIG_MODULES=n` — every driver is
/// compiled in.  If `vfio-pci` is present, this directory appears
/// automatically at boot.
const VFIO_PCI_DRIVER_PATH: &str = "/sys/bus/pci/drivers/vfio-pci";

/// How long Phase 1 waits for at least one rx frame before giving up.
const RX_POLL_TIMEOUT: Duration = Duration::from_secs(10);

/// Sleep between rx poll attempts to avoid burning CPU.
const RX_POLL_INTERVAL: Duration = Duration::from_millis(50);

// ---------------------------------------------------------------------------
// Helpers — sysfs / diagnostics
// ---------------------------------------------------------------------------

/// Read a sysfs hex attribute file and return the parsed `u16` value.
///
/// Sysfs vendor/device files contain strings like `"0x1af4\n"`.
fn read_sysfs_hex_u16(path: &str) -> Option<u16> {
    let content = fs::read_to_string(path).ok()?;
    let trimmed = content.trim().trim_start_matches("0x");
    u16::from_str_radix(trimmed, 16).ok()
}

/// Returns `true` if the given vendor/device pair identifies a virtio-net
/// device.
fn is_virtio_net(vendor: u16, device: u16) -> bool {
    vendor == VIRTIO_VENDOR_ID
        && (device == VIRTIO_NET_DEVICE_LEGACY || device == VIRTIO_NET_DEVICE_MODERN)
}

/// Returns `true` if the given vendor/device pair identifies an Intel
/// e1000 (82540EM) NIC.
fn is_e1000(vendor: u16, device: u16) -> bool {
    vendor == INTEL_VENDOR_ID && device == E1000_DEVICE_ID
}

/// Returns `true` if the given vendor/device pair identifies an Intel
/// e1000e (82574L) NIC.
fn is_e1000e(vendor: u16, device: u16) -> bool {
    vendor == INTEL_VENDOR_ID && device == E1000E_DEVICE_ID
}

/// Returns `true` if the given vendor/device pair identifies any network
/// device that our test infrastructure knows how to drive with DPDK.
fn is_known_net_device(vendor: u16, device: u16) -> bool {
    is_virtio_net(vendor, device) || is_e1000(vendor, device) || is_e1000e(vendor, device)
}

/// Human-readable label for a recognised NIC based on its PCI IDs.
fn net_device_label(vendor: u16, device: u16) -> &'static str {
    if is_virtio_net(vendor, device) {
        "virtio-net"
    } else if is_e1000(vendor, device) {
        "e1000"
    } else if is_e1000e(vendor, device) {
        "e1000e"
    } else {
        "unknown-net"
    }
}

/// Enumerate PCI devices from sysfs and return the addresses of all
/// known network devices (virtio-net, e1000, e1000e).
///
/// Each entry under `/sys/bus/pci/devices/` is a directory named with the
/// BDF address (e.g. `0000:00:03.0`).  We read the `vendor` and `device`
/// files to identify supported NICs.
fn discover_pci_net_devices() -> Vec<PciAddress> {
    let entries = match fs::read_dir(PCI_DEVICES_PATH) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("[discover] failed to read {PCI_DEVICES_PATH}: {e}");
            return Vec::new();
        }
    };

    let mut found = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let base = format!("{PCI_DEVICES_PATH}/{name_str}");

        let vendor = match read_sysfs_hex_u16(&format!("{base}/vendor")) {
            Some(v) => v,
            None => continue,
        };
        let device = match read_sysfs_hex_u16(&format!("{base}/device")) {
            Some(d) => d,
            None => continue,
        };

        eprintln!("[discover] {name_str}: vendor=0x{vendor:04x} device=0x{device:04x}");

        if is_known_net_device(vendor, device) {
            let label = net_device_label(vendor, device);
            match PciAddress::try_from(name_str.as_ref()) {
                Ok(addr) => {
                    eprintln!("[discover]   -> {label} at {addr}");
                    found.push(addr);
                }
                Err(e) => {
                    eprintln!("[discover]   -> failed to parse PCI address '{name_str}': {e}");
                }
            }
        }
    }

    // Sort for deterministic ordering across runs.
    found.sort();
    found
}

/// Dump effective capabilities from `/proc/self/status`.
///
/// If `CapEff` is not `ffff…` we know the process is missing
/// privileges, which would explain "Permission denied" from DPDK
/// even though we *think* we are root inside the VM.
fn dump_capability_diagnostics() {
    eprintln!("[caps] --- capability diagnostics ---");

    match fs::read_to_string("/proc/self/status") {
        Ok(status) => {
            for line in status.lines() {
                if line.starts_with("Cap") || line.starts_with("Uid") || line.starts_with("Gid") {
                    eprintln!("[caps]   {line}");
                }
            }
        }
        Err(e) => eprintln!("[caps]   failed to read /proc/self/status: {e}"),
    }

    eprintln!("[caps] --- end capability diagnostics ---");
}

/// Dump hugepage-related diagnostic information from sysfs and
/// `/proc/mounts`.
///
/// This is called before `eal::init` so that if EAL fails with
/// "Cannot get hugepage information" we have the full picture in
/// the test output.
fn dump_hugepage_diagnostics() {
    eprintln!("[huge] --- hugepage diagnostics ---");

    // 1. What does /sys/kernel/mm/hugepages/ contain?
    match fs::read_dir(HUGEPAGES_SYSFS) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                let base = format!("{HUGEPAGES_SYSFS}/{name_str}");

                let nr = fs::read_to_string(format!("{base}/nr_hugepages"))
                    .unwrap_or_else(|e| format!("<err: {e}>"));
                let free = fs::read_to_string(format!("{base}/free_hugepages"))
                    .unwrap_or_else(|e| format!("<err: {e}>"));
                eprintln!(
                    "[huge]   {name_str}: nr={nr} free={free}",
                    nr = nr.trim(),
                    free = free.trim(),
                );
            }
        }
        Err(e) => eprintln!("[huge]   failed to read {HUGEPAGES_SYSFS}: {e}"),
    }

    // 2. Hugetlbfs mounts from /proc/mounts.
    match fs::read_to_string("/proc/mounts") {
        Ok(mounts) => {
            let hugetlb_lines: Vec<&str> =
                mounts.lines().filter(|l| l.contains("hugetlbfs")).collect();
            if hugetlb_lines.is_empty() {
                eprintln!("[huge]   NO hugetlbfs mounts found in /proc/mounts");
            } else {
                for line in &hugetlb_lines {
                    eprintln!("[huge]   mount: {line}");
                }
            }
        }
        Err(e) => eprintln!("[huge]   failed to read /proc/mounts: {e}"),
    }

    // 3. Does our expected huge-dir exist and is it writable?
    match fs::metadata(HUGEPAGE_DIR) {
        Ok(meta) => {
            eprintln!(
                "[huge]   {HUGEPAGE_DIR} exists (dir={}, readonly={})",
                meta.is_dir(),
                meta.permissions().readonly(),
            );
        }
        Err(e) => eprintln!("[huge]   {HUGEPAGE_DIR} not accessible: {e}"),
    }

    eprintln!("[huge] --- end diagnostics ---");
}

/// Assert that the `vfio-pci` driver is available in the VM kernel.
///
/// Because the VM kernel has no module support (`CONFIG_MODULES=n`),
/// there is nothing to load — the driver is either built-in or absent.
/// We simply check for its sysfs directory.
fn assert_vfio_pci_available() {
    match fs::metadata(VFIO_PCI_DRIVER_PATH) {
        Ok(_) => eprintln!("[vfio] {VFIO_PCI_DRIVER_PATH} exists (built-in driver present)"),
        Err(e) => {
            panic!(
                "vfio-pci driver not found at {VFIO_PCI_DRIVER_PATH}: {e} — \
                 the VM kernel must be built with CONFIG_VFIO_PCI=y"
            );
        }
    }
}

/// Dump IOMMU group information for diagnostic purposes.
///
/// When VFIO operates with a real (or virtual) IOMMU, each PCI device
/// must belong to a valid IOMMU group.  If no groups exist, VFIO will
/// reject bind attempts with `EINVAL`.
///
/// This function inspects:
/// 1. `/sys/kernel/iommu_groups/` — are any groups present?
/// 2. Each discovered device's `iommu_group` symlink.
/// 3. The VFIO no-IOMMU sysfs flag.
fn dump_iommu_diagnostics(virtio_addrs: &[PciAddress]) {
    eprintln!("[iommu] --- IOMMU diagnostics ---");

    // 1. Check if any IOMMU groups exist at all.
    match fs::read_dir("/sys/kernel/iommu_groups") {
        Ok(entries) => {
            let groups: Vec<String> = entries
                .flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .collect();
            if groups.is_empty() {
                eprintln!("[iommu]   /sys/kernel/iommu_groups/ exists but is EMPTY");
                eprintln!("[iommu]   -> the kernel IOMMU driver may not have initialised");
                eprintln!("[iommu]   -> check kernel log for: 'DMAR: IOMMU enabled'");
            } else {
                eprintln!(
                    "[iommu]   found {} IOMMU group(s): {:?}",
                    groups.len(),
                    groups
                );
            }
        }
        Err(e) => {
            eprintln!("[iommu]   /sys/kernel/iommu_groups/ not readable: {e}");
            eprintln!("[iommu]   -> IOMMU support may not be compiled into the kernel");
        }
    }

    // 2. Check each discovered device's IOMMU group.
    for addr in virtio_addrs {
        let group_link = format!("{PCI_DEVICES_PATH}/{addr}/iommu_group");
        match fs::read_link(&group_link) {
            Ok(target) => {
                let group_name = target
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "<unknown>".into());
                eprintln!("[iommu]   {addr}: iommu_group={group_name}");
            }
            Err(e) => {
                eprintln!("[iommu]   {addr}: NO iommu_group symlink ({e})");
                eprintln!("[iommu]       -> this device cannot be bound to vfio-pci with IOMMU");
            }
        }
    }

    // 3. Check VFIO no-IOMMU mode flag.
    match fs::read_to_string("/sys/module/vfio/parameters/enable_unsafe_noiommu_mode") {
        Ok(val) => eprintln!("[iommu]   vfio.enable_unsafe_noiommu_mode={}", val.trim()),
        Err(e) => eprintln!("[iommu]   vfio noiommu flag not readable: {e}"),
    }

    // 4. Check kernel command line for IOMMU-related params.
    match fs::read_to_string("/proc/cmdline") {
        Ok(cmdline) => {
            let relevant: Vec<&str> = cmdline
                .split_whitespace()
                .filter(|w| {
                    w.starts_with("iommu")
                        || w.starts_with("intel_iommu")
                        || w.starts_with("amd_iommu")
                        || w.starts_with("vfio")
                })
                .collect();
            eprintln!("[iommu]   kernel cmdline IOMMU params: {relevant:?}");
        }
        Err(e) => eprintln!("[iommu]   /proc/cmdline not readable: {e}"),
    }

    eprintln!("[iommu] --- end IOMMU diagnostics ---");
}

/// Dump VFIO state after binding devices to vfio-pci.
///
/// This runs **after** `bind_devices_to_vfio` to show the state that
/// DPDK will see when it initialises.  Useful for diagnosing "0 ports"
/// failures where the bind succeeded but DPDK can't open the VFIO
/// container/group.
fn dump_post_bind_vfio_diagnostics(addresses: &[PciAddress]) {
    eprintln!("[vfio-diag] --- post-bind VFIO diagnostics ---");

    // /dev/vfio/ contents — DPDK opens /dev/vfio/vfio (container) and
    // /dev/vfio/<group> (or /dev/vfio/noiommu-<group>) for each device.
    match fs::read_dir("/dev/vfio") {
        Ok(entries) => {
            let mut names: Vec<String> = entries
                .flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .collect();
            names.sort();
            eprintln!("[vfio-diag]   /dev/vfio/ entries: {names:?}");
        }
        Err(e) => {
            eprintln!("[vfio-diag]   /dev/vfio/ not readable: {e}");
        }
    }

    // Re-check IOMMU groups after bind — no-IOMMU mode creates groups
    // only after a device is bound to vfio-pci.
    match fs::read_dir("/sys/kernel/iommu_groups") {
        Ok(entries) => {
            let mut groups: Vec<String> = entries
                .flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .collect();
            groups.sort_by(|a, b| {
                a.parse::<u32>()
                    .unwrap_or(u32::MAX)
                    .cmp(&b.parse::<u32>().unwrap_or(u32::MAX))
            });
            eprintln!(
                "[vfio-diag]   iommu_groups after bind: {} group(s): {groups:?}",
                groups.len()
            );
        }
        Err(e) => {
            eprintln!("[vfio-diag]   /sys/kernel/iommu_groups/ not readable: {e}");
        }
    }

    // Per-device: show current driver and iommu_group
    for addr in addresses {
        let base = format!("{PCI_DEVICES_PATH}/{addr}");

        // Current driver
        match fs::read_link(format!("{base}/driver")) {
            Ok(target) => {
                let driver = target
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "?".into());
                eprintln!("[vfio-diag]   {addr}: driver={driver}");
            }
            Err(e) => {
                eprintln!("[vfio-diag]   {addr}: no driver symlink ({e})");
            }
        }

        // IOMMU group
        match fs::read_link(format!("{base}/iommu_group")) {
            Ok(target) => {
                let group = target
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "?".into());
                eprintln!("[vfio-diag]   {addr}: iommu_group={group}");
            }
            Err(e) => {
                eprintln!("[vfio-diag]   {addr}: no iommu_group ({e})");
            }
        }
    }

    eprintln!("[vfio-diag] --- end post-bind VFIO diagnostics ---");
}

/// Bind each address to `vfio-pci` and return those that succeeded.
///
/// Uses the [`PciNic`] / [`BindToVfioPci`] infrastructure from the
/// `hardware` crate which handles unbind → override → bind.
fn bind_devices_to_vfio(addresses: &[PciAddress]) -> Vec<PciAddress> {
    let mut bound = Vec::new();
    for &addr in addresses {
        let mut nic = match PciNic::new(addr) {
            Ok(nic) => nic,
            Err(e) => {
                eprintln!("[bind] PciNic::new({addr}) failed: {e}");
                continue;
            }
        };
        eprintln!("[bind] binding {addr} to vfio-pci …");
        match nic.bind_to_vfio_pci() {
            Ok(()) => {
                eprintln!("[bind]   {addr}: ok");
                bound.push(addr);
            }
            Err(e) => {
                eprintln!("[bind]   {addr}: failed: {e}");
            }
        }
    }
    bound
}

/// Construct EAL command-line arguments for the in-guest environment.
///
/// IOVA mode is left to DPDK's auto-detection: no-IOMMU requires PA
/// mode (the device does DMA with physical addresses), while a vIOMMU
/// would allow VA mode.
///
/// `--huge-dir` is set explicitly because the `n-it` init system
/// mounts hugetlbfs at a non-standard path (`/run/huge/2MiB`) rather
/// than the conventional `/dev/hugepages`.
///
/// PCI bus-level debug logging is enabled unconditionally to aid
/// diagnosis of "0 ports" failures where DPDK silently skips devices
/// during probe.
fn build_eal_args(pci_allow_list: &[PciAddress]) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "dpdk-test".into(),   // argv[0] — process name convention
        "--in-memory".into(), // no persistent hugepage files
        format!("--huge-dir={HUGEPAGE_DIR}"),
        // Verbose logging for PCI bus probe and VFIO setup — shows
        // exactly which devices DPDK attempts to claim and why it
        // skips any.
        "--log-level=pci:debug".into(),
        "--log-level=bus.pci:debug".into(),
        "--log-level=eal:debug".into(),
        "--log-level=vfio:debug".into(),
    ];

    for addr in pci_allow_list {
        args.push("-a".into());
        args.push(addr.to_string());
    }

    args
}

// ---------------------------------------------------------------------------
// Helpers — DPDK device setup
// ---------------------------------------------------------------------------

/// Shared setup: discover → bind → EAL init → configure → queue setup →
/// start.  Returns the `Eal` handle (which **must** be kept alive for the
/// duration of the test — dropping it calls `rte_eal_cleanup` and
/// invalidates every port), the started device, and optionally a separate
/// pool for tx allocation.
///
/// When `with_tx_pool` is `true` a second mempool is created that the
/// caller can use to allocate mbufs for transmission.
///
/// # Panics
///
/// Panics on any setup failure — this is test code, not library code.
fn setup_dpdk_device(with_tx_pool: bool) -> (Eal, Dev<Started>, Option<Pool>) {
    // -- vfio-pci ----------------------------------------------------------
    assert_vfio_pci_available();

    // -- PCI discovery -----------------------------------------------------
    let net_addrs = discover_pci_net_devices();
    eprintln!("[eal] discovered {} network device(s)", net_addrs.len());
    assert!(
        !net_addrs.is_empty(),
        "no supported PCI network devices found under {PCI_DEVICES_PATH} — \
         the VM may not have been booted with network interfaces"
    );

    // -- IOMMU diagnostics (before bind) -----------------------------------
    dump_iommu_diagnostics(&net_addrs);

    // -- bind to vfio-pci --------------------------------------------------
    let bound = bind_devices_to_vfio(&net_addrs);
    eprintln!("[eal] {} device(s) bound to vfio-pci", bound.len());
    assert!(
        !bound.is_empty(),
        "failed to bind any network device to vfio-pci — \
         check that the vfio-pci driver is available in the VM kernel"
    );

    // -- post-bind diagnostics ---------------------------------------------
    dump_post_bind_vfio_diagnostics(&bound);

    // -- EAL init ----------------------------------------------------------
    dump_capability_diagnostics();
    dump_hugepage_diagnostics();
    let eal_args = build_eal_args(&bound);
    eprintln!("[eal] args: {eal_args:?}");
    let eal = eal::init(eal_args);
    eprintln!("[eal] initialised (has_pci={})", eal.has_pci());

    // -- device enumeration ------------------------------------------------
    let num_ports = eal.dev.num_devices();
    eprintln!("[eal] DPDK reports {num_ports} ethernet port(s)");
    assert!(
        num_ports > 0,
        "DPDK enumerated 0 ports after EAL init — \
         the PMD may not have claimed the device(s); check the VFIO \
         and PCI bus debug log above for probe failures"
    );

    for dev_info in eal.dev.iter() {
        eprintln!(
            "[dev] port {}: driver=\"{}\", if_index={}, tx_offloads={:#x}, rx_offloads={:#x}",
            dev_info.index(),
            dev_info.driver_name(),
            dev_info.if_index(),
            u64::from(dev_info.tx_offload_caps()),
            u64::from(dev_info.rx_offload_caps()),
        );
    }

    // -- configure first device --------------------------------------------
    let first_dev_info = eal
        .dev
        .iter()
        .next()
        .expect("dev iterator empty despite num_devices > 0");

    eprintln!(
        "[dev] configuring port {} (driver: {}) …",
        first_dev_info.index(),
        first_dev_info.driver_name(),
    );

    let config = DevConfig {
        num_rx_queues: 1,
        num_tx_queues: 1,
        num_hairpin_queues: 0,
        // Explicitly none, which is what this test has always asked for: the
        // old `RxOffloadConfig::default()` was a struct of `bool`s, all false.
        // `None` here would mean the opposite -- every offload the device
        // supports -- and that turns LRO on, which brings DPDK's
        // `max_lro_pkt_size` validation into a test that has no use for it.
        rx_offloads: Some(RxOffload::NONE),
        tx_offloads: Some(TxOffloadConfig::default()),
        // The standard Ethernet MTU, clamped into whatever range the device advertises.  This
        // test's probe frames are far below it either way.
        mtu: None,
        // No RSS: a single rx queue has nothing to distribute across, and the emulated NICs in
        // this matrix advertise no RSS hash functions at all.
        rss: None,
    };

    let mut dev = config
        .apply(first_dev_info)
        .expect("failed to apply DevConfig");
    eprintln!("[dev] device configured");

    // -- mempools ----------------------------------------------------------
    let rx_pool = Pool::new_pkt_pool(
        PoolConfig::new(
            "rx_pool".to_string(),
            PoolParams {
                size: 1024,
                ..Default::default()
            },
        )
        .expect("invalid rx PoolConfig"),
    )
    .expect("failed to create rx mempool");
    eprintln!("[mem] rx mempool '{}' created", rx_pool.name());

    let tx_pool = if with_tx_pool {
        let pool = Pool::new_pkt_pool(
            PoolConfig::new(
                "tx_pool".to_string(),
                PoolParams {
                    size: 256,
                    cache_size: 128,
                    ..Default::default()
                },
            )
            .expect("invalid tx PoolConfig"),
        )
        .expect("failed to create tx mempool");
        eprintln!("[mem] tx mempool '{}' created", pool.name());
        Some(pool)
    } else {
        None
    };

    // -- queues ------------------------------------------------------------
    dev.new_rx_queue(RxQueueConfig {
        dev: dev.info.index(),
        queue_index: RxQueueIndex(0),
        num_descriptors: 256,
        socket_preference: socket::Preference::CurrentThread,
        // The *per-queue* capabilities, not the port's. DPDK keeps the two in
        // separate masks and refuses a queue that asks for anything outside
        // the per-queue one -- virtio-net reports 0x1d for the port and 0x0
        // per queue, so passing the port mask here fails with EINVAL.
        offloads: dev.info.rx_queue_offload_caps(),
        pool: rx_pool,
    })
    .expect("failed to set up rx queue 0");
    eprintln!("[queue] rx queue 0 ready");

    dev.new_tx_queue(TxQueueConfig {
        queue_index: TxQueueIndex(0),
        num_descriptors: 256,
        socket_preference: socket::Preference::CurrentThread,
        config: (),
    })
    .expect("failed to set up tx queue 0");
    eprintln!("[queue] tx queue 0 ready");

    // -- start -------------------------------------------------------------
    let dev = dev.start().expect("failed to start DPDK device");
    eprintln!("[dev] device started successfully");

    (eal, dev, tx_pool)
}

// ---------------------------------------------------------------------------
// Helpers — promiscuous mode
// ---------------------------------------------------------------------------

/// Enable promiscuous mode on a DPDK port.
fn enable_promiscuous_mode(dev: &mut Dev<Started>) {
    // A warning rather than a failure: not every driver implements it, and a
    // test whose frames are addressed to the port's own MAC does not need it.
    // Whether the frames arrived is asserted below either way.
    match dev.set_promiscuous(true) {
        Ok(()) => eprintln!(
            "[promisc] promiscuous mode enabled on port {port}",
            port = dev.info.index()
        ),
        Err(err) => eprintln!(
            "[promisc] WARNING: could not enable promiscuous mode on port {port}: {err:?}",
            port = dev.info.index()
        ),
    }
}

// ---------------------------------------------------------------------------
// Helpers — probe frame construction
// ---------------------------------------------------------------------------

/// Compute an ICMPv6 / UDP / TCP checksum (RFC 1071 one's complement sum)
/// over an IPv6 pseudo-header and the upper-layer payload.
///
/// This is intentionally simple and unoptimised — it is used exactly once
/// per test run to build a single probe frame.
fn ipv6_upper_layer_checksum(
    src: &[u8; 16],
    dst: &[u8; 16],
    next_header: u8,
    payload: &[u8],
) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header: source address
    for chunk in src.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    // Pseudo-header: destination address
    for chunk in dst.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    // Pseudo-header: upper-layer packet length (32-bit)
    let len = payload.len() as u32;
    sum += (len >> 16) & 0xffff;
    sum += len & 0xffff;
    // Pseudo-header: next header (zero-extended to 32-bit, only low 16 used)
    sum += next_header as u32;

    // Payload (with checksum field assumed to be zero by caller)
    let mut i = 0;
    while i + 1 < payload.len() {
        sum += u16::from_be_bytes([payload[i], payload[i + 1]]) as u32;
        i += 2;
    }
    if i < payload.len() {
        // Odd byte — pad with zero
        sum += (payload[i] as u32) << 8;
    }

    // Fold carries
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}

/// Build a raw ICMPv6 Neighbor Solicitation frame targeting the all-nodes
/// multicast group.
///
/// This solicits a Neighbor Advertisement from every IPv6 host on the
/// link, which includes the container's kernel on the TAP interface.
///
/// Source addresses:
///   - Ethernet: `02:00:00:00:00:42` (locally-administered unicast)
///   - IPv6: `fe80::42` (arbitrary link-local)
///
/// Destination addresses:
///   - Ethernet: `33:33:ff:00:00:01` (solicited-node multicast for `::1`)
///   - IPv6: `ff02::1:ff00:1` (solicited-node multicast)
///   - NS target: `fe80::1` (fabric1's link-local, but any host on the
///     link with an address ending in `::1` will respond)
///
/// Returns the complete Ethernet frame bytes ready to copy into an mbuf.
fn build_ndp_probe_frame() -> Vec<u8> {
    // — Source / destination addresses used in the probe —

    let src_mac: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x42];
    let dst_mac: [u8; 6] = [0x33, 0x33, 0xff, 0x00, 0x00, 0x01];

    // fe80::42
    let src_ipv6: [u8; 16] = [
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42,
    ];
    // ff02::1:ff00:1 (solicited-node multicast)
    let dst_ipv6: [u8; 16] = [
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, 0x01,
    ];
    // NS target: fe80::1
    let target_ipv6: [u8; 16] = [
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    // — ICMPv6 NS body (checksum zeroed, filled in below) —
    //
    // Layout (RFC 4861 §4.3):
    //   type(1) code(1) checksum(2) reserved(4) target(16)
    //   + option: Source Link-Layer Address type(1) len(1) addr(6)
    //
    // Total ICMPv6 payload: 24 + 8 = 32 bytes.

    let mut icmpv6_body = Vec::with_capacity(32);
    icmpv6_body.push(135); // type: Neighbor Solicitation
    icmpv6_body.push(0); //   code: 0
    icmpv6_body.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
    icmpv6_body.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // reserved
    icmpv6_body.extend_from_slice(&target_ipv6); // target address

    // Option: Source Link-Layer Address (type=1, length=1 unit of 8 bytes)
    icmpv6_body.push(1); //   option type
    icmpv6_body.push(1); //   option length (units of 8 octets)
    icmpv6_body.extend_from_slice(&src_mac);

    assert_eq!(icmpv6_body.len(), 32);

    // — Compute ICMPv6 checksum (RFC 2460 §8.1) —

    let cksum = ipv6_upper_layer_checksum(&src_ipv6, &dst_ipv6, 58, &icmpv6_body);
    icmpv6_body[2] = (cksum >> 8) as u8;
    icmpv6_body[3] = (cksum & 0xff) as u8;

    // — Assemble the full Ethernet frame —

    let ipv6_payload_len = icmpv6_body.len() as u16;
    let mut frame = Vec::with_capacity(14 + 40 + icmpv6_body.len());

    // Ethernet header (14 bytes)
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&[0x86, 0xdd]); // EtherType: IPv6

    // IPv6 header (40 bytes)
    frame.push(0x60); // version=6, traffic class high nibble=0
    frame.extend_from_slice(&[0x00, 0x00, 0x00]); // tc low + flow label
    frame.extend_from_slice(&ipv6_payload_len.to_be_bytes()); // payload length
    frame.push(58); // next header: ICMPv6
    frame.push(255); // hop limit (MUST be 255 for NDP per RFC 4861)
    frame.extend_from_slice(&src_ipv6);
    frame.extend_from_slice(&dst_ipv6);

    // ICMPv6 body
    frame.extend_from_slice(&icmpv6_body);

    assert_eq!(frame.len(), 14 + 40 + 32);
    frame
}

/// Build a second probe: an ICMPv6 Echo Request to the all-nodes multicast
/// address (`ff02::1`).
///
/// Unlike the NS probe, every IPv6 node on the link MUST respond with an
/// Echo Reply (RFC 4443 §4.2).  This is our fallback if the NS doesn't
/// elicit a NA (e.g. because no host address ends in `::1`).
fn build_echo_probe_frame() -> Vec<u8> {
    let src_mac: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x42];
    // 33:33:00:00:00:01 is the Ethernet multicast for ff02::1
    let dst_mac: [u8; 6] = [0x33, 0x33, 0x00, 0x00, 0x00, 0x01];

    // fe80::42
    let src_ipv6: [u8; 16] = [
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42,
    ];
    // ff02::1 (all-nodes multicast)
    let dst_ipv6: [u8; 16] = [
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    // ICMPv6 Echo Request: type=128, code=0, id=1, seq=1
    let mut icmpv6_body: Vec<u8> = vec![
        128, 0, // type, code
        0x00, 0x00, // checksum placeholder
        0x00, 0x01, // identifier
        0x00, 0x01, // sequence number
    ];

    let cksum = ipv6_upper_layer_checksum(&src_ipv6, &dst_ipv6, 58, &icmpv6_body);
    icmpv6_body[2] = (cksum >> 8) as u8;
    icmpv6_body[3] = (cksum & 0xff) as u8;

    let ipv6_payload_len = icmpv6_body.len() as u16;
    let mut frame = Vec::with_capacity(14 + 40 + icmpv6_body.len());

    // Ethernet
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&[0x86, 0xdd]);

    // IPv6
    frame.push(0x60);
    frame.extend_from_slice(&[0x00, 0x00, 0x00]);
    frame.extend_from_slice(&ipv6_payload_len.to_be_bytes());
    frame.push(58); // ICMPv6
    frame.push(64); // hop limit
    frame.extend_from_slice(&src_ipv6);
    frame.extend_from_slice(&dst_ipv6);

    // ICMPv6
    frame.extend_from_slice(&icmpv6_body);

    frame
}

/// Log parsed headers from a received frame in a human-readable format.
fn log_parsed_headers(frame_idx: usize, data: &[u8], headers: &Headers) {
    eprintln!(
        "[rx:{frame_idx}] --- parsed headers ({} bytes) ---",
        data.len()
    );

    if let Some(eth) = headers.eth() {
        let src: net::eth::mac::SourceMac = eth.source();
        let dst: net::eth::mac::DestinationMac = eth.destination();
        eprintln!(
            "[rx:{frame_idx}]   eth: src={} dst={} ethertype={:?}",
            src.inner(),
            dst.inner(),
            eth.ether_type(),
        );
    }

    if !headers.vlan().is_empty() {
        eprintln!("[rx:{frame_idx}]   vlan tags: {}", headers.vlan().len());
    }

    match headers.net() {
        Some(net_hdr) => {
            eprintln!(
                "[rx:{frame_idx}]   net: src={} dst={} next_hdr={}",
                net_hdr.src_addr(),
                net_hdr.dst_addr(),
                net_hdr.next_header(),
            );
        }
        None => {
            eprintln!("[rx:{frame_idx}]   net: <none>");
        }
    }

    match headers.transport() {
        Some(transport) => {
            let kind = match transport {
                net::headers::Transport::Tcp(_) => "TCP",
                net::headers::Transport::Udp(_) => "UDP",
                net::headers::Transport::Icmp4(_) => "ICMPv4",
                net::headers::Transport::Icmp6(_) => "ICMPv6",
            };
            eprintln!("[rx:{frame_idx}]   transport: {kind}");
        }
        None => {
            eprintln!("[rx:{frame_idx}]   transport: <none>");
        }
    }

    eprintln!("[rx:{frame_idx}] --- end parsed headers ---");
}

/// Log a hex dump of the first N bytes of a buffer.
fn log_hex_dump(tag: &str, data: &[u8], max_bytes: usize) {
    let limit = data.len().min(max_bytes);
    let hex: Vec<String> = data[..limit].iter().map(|b| format!("{b:02x}")).collect();
    let suffix = if data.len() > max_bytes {
        format!(" … ({} bytes total)", data.len())
    } else {
        String::new()
    };
    eprintln!("[{tag}] {}{suffix}", hex.join(" "));
}

// ---------------------------------------------------------------------------
// Helpers — rx test body
// ---------------------------------------------------------------------------

/// Shared tx/rx traffic test body.
///
/// Factored out so that each backend / IOMMU combination can reuse the
/// same logic — only the proc-macro attributes on the outer test
/// function differ.
///
/// # Rx traffic expectations
///
/// Cloud-hypervisor configures IPv6 link-local addresses on the TAP
/// interfaces (`NetConfig.ip`), so the host kernel generates NDP
/// chatter immediately and responds to our ICMPv6 probes.
///
/// QEMU uses `script=no` when creating TAPs, which means the TAPs
/// are **not** brought UP and have no IPv6 addresses.  Without a
/// traffic source on the host side, no frames arrive.  The `n-vm`
/// QEMU backend will need to bring the TAPs up (or the container
/// tier will need to inject traffic via `AF_PACKET`) before rx
/// validation can work reliably on QEMU.
///
/// When `expect_rx` is `false`, the test still exercises the full
/// tx path and polls for rx (logging any frames that do arrive),
/// but does not fail if the rx ring stays empty.
fn run_rx_test(label: &str, expect_rx: bool) {
    eprintln!("=== {label} ===");

    // ── setup (same as Phase 0 but with a tx pool) ──────────────────────

    let (eal, mut started, tx_pool) = setup_dpdk_device(true);

    // Leak the Eal handle to prevent `Eal::drop()` from running at
    // function exit.  `Eal::drop()` calls `rte_eal_mp_wait_lcore()`
    // which blocks indefinitely waiting for worker lcores to finish,
    // hanging the test process and preventing the VM init system from
    // performing a clean shutdown (`reboot(RB_POWER_OFF)`).
    //
    // The underlying DPDK global state survives the forget — all port,
    // queue, and mempool handles remain valid for the rest of the process.
    //
    // NOTE: forgetting the Eal also skips `mem::release_all()`, so the
    // mempools are never freed.  That is harmless in a process that is
    // about to exit, but it does mean this test does not exercise the
    // pool-release path — the ordering it validates is device stop/close
    // (below), not mempool teardown.
    //
    // The `rte_eal_mp_wait_lcore()` attribution above is unverified and
    // looks doubtful: this test launches no worker lcores, so that call
    // should return immediately.  A likelier culprit is `rte_eal_cleanup`
    // itself — note that these EAL args, unlike the unit-test ones in
    // `dpdk::test_support::start_eal`, do not pass `--no-telemetry`, and
    // the telemetry socket thread is torn down during cleanup.  Worth
    // testing that before assuming the wait is at fault.
    std::mem::forget(eal);
    let tx_pool = tx_pool.expect("setup_dpdk_device should return a tx pool");

    // ── enable promiscuous mode ─────────────────────────────────────────
    //
    // We send frames from a locally-administered MAC (02:00:00:00:00:42),
    // not the port's own MAC, so the NIC would normally drop the reply
    // (which is addressed to our fake MAC).  Promiscuous mode ensures we
    // see everything.
    //
    // NOTE: virtio-net returns ENOTSUP (-95) here because it passes all
    // multicast by default.  Other PMDs (e1000, e1000e) may require it.

    enable_promiscuous_mode(&mut started);

    // ── build probe frames ──────────────────────────────────────────────
    //
    // We send two probes to maximise our chances of getting a reply:
    //
    //   1. An ICMPv6 Neighbor Solicitation for fe80::1.  If any host on
    //      the link owns that address (cloud-hypervisor sets it on the
    //      fabric1 TAP), the kernel responds with a Neighbor Advertisement.
    //
    //   2. An ICMPv6 Echo Request to ff02::1 (all-nodes multicast).
    //      Every IPv6 node MUST respond with an Echo Reply.

    let ndp_frame = build_ndp_probe_frame();
    let echo_frame = build_echo_probe_frame();

    eprintln!(
        "[tx] probe frames built: NS={} bytes, Echo={} bytes",
        ndp_frame.len(),
        echo_frame.len(),
    );

    // ── transmit probes ─────────────────────────────────────────────────

    // Take the device's queues once. Each leaves the set by value, so these handles are the only
    // way to drive those queues -- which is what makes DPDK's one-queue-one-thread rule a borrow
    // error rather than a convention.
    let mut queues = started.take_queues().expect("device queues already taken");
    let mut tx_queue = queues
        .take_tx(TxQueueIndex(0))
        .expect("tx queue 0 missing after start");

    // Helper: allocate one mbuf per frame, copy the frame bytes in, and collect them into the
    // burst-sized array `transmit` takes.
    let make_batch = |pool: &Pool, frames: &[&[u8]]| -> MbufArray {
        let mbufs = pool
            .alloc_bulk(frames.len())
            .expect("failed to allocate mbufs from tx pool");
        assert_eq!(
            mbufs.len(),
            frames.len(),
            "tx pool returned {} mbufs for {} frames",
            mbufs.len(),
            frames.len(),
        );
        let mut batch = MbufArray::new_empty();
        for (mut mbuf, frame) in mbufs.into_iter().zip(frames) {
            let data = mbuf
                .append(frame.len() as u16)
                .expect("failed to extend mbuf tailroom for probe frame");
            data[..frame.len()].copy_from_slice(frame);
            assert!(
                batch.try_push(mbuf).is_ok(),
                "probe batch exceeded MbufArray capacity",
            );
        }
        batch
    };

    log_hex_dump("tx:ndp", &ndp_frame, 86);
    log_hex_dump("tx:echo", &echo_frame, 62);

    // `transmit` hands ownership of every accepted mbuf to the PMD and returns the ones the queue
    // refused; dropping that array frees exactly those.  A two-frame burst on a 256-descriptor
    // queue has no legitimate reason to be refused, so treat any refusal as a failure here.
    let batch = make_batch(&tx_pool, &[&ndp_frame, &echo_frame]);
    let sent = batch.len();
    let unsent = tx_queue.transmit(batch);
    assert!(
        unsent.is_empty(),
        "tx queue refused {refused} of {sent} probe frames",
        refused = unsent.len(),
    );
    eprintln!("[tx] {sent} probe frames transmitted");

    // ── poll rx queue for responses ─────────────────────────────────────

    let mut rx_queue = queues
        .take_rx(RxQueueIndex(0))
        .expect("rx queue 0 missing after start");

    let deadline = Instant::now() + RX_POLL_TIMEOUT;
    let mut total_received: usize = 0;
    let mut total_parsed: usize = 0;
    let mut poll_iterations: u64 = 0;

    eprintln!("[rx] polling rx queue (timeout={RX_POLL_TIMEOUT:?}) …",);

    // Re-send probes periodically in case the first batch was lost during
    // NIC / TAP setup race.  One extra burst per second is cheap.
    let mut last_retransmit = Instant::now();

    while Instant::now() < deadline {
        poll_iterations += 1;

        // Retransmit probes every second if we have not received anything.
        if total_received == 0 && last_retransmit.elapsed() > Duration::from_secs(1) {
            let batch = make_batch(&tx_pool, &[&ndp_frame, &echo_frame]);
            // Unlike the first burst, a refusal here is only worth reporting: this path exists to
            // paper over a lost frame, so dropping (and freeing) the refused mbufs is fine.
            let unsent = tx_queue.transmit(batch);
            if !unsent.is_empty() {
                eprintln!(
                    "[tx] WARNING: tx queue refused {refused} retransmitted frame(s)",
                    refused = unsent.len(),
                );
            }
            eprintln!("[tx] retransmitted probes (poll iteration {poll_iterations})");
            last_retransmit = Instant::now();
        }

        for mbuf in rx_queue.receive() {
            let data = mbuf.raw_data();
            total_received += 1;

            eprintln!("[rx] frame #{total_received}: {} bytes", data.len(),);
            log_hex_dump(&format!("rx:{total_received}"), data, 128);

            match Headers::parse(data) {
                Ok((headers, consumed)) => {
                    total_parsed += 1;
                    eprintln!("[rx:{total_received}] parsed {consumed} header bytes",);
                    log_parsed_headers(total_received, data, &headers);
                }
                Err(e) => {
                    eprintln!("[rx:{total_received}] parse failed (not fatal): {e:?}",);
                    // A parse failure is fine for the spike — we still
                    // proved the frame arrived.  The parser may not
                    // understand every protocol (e.g. ARP).
                }
            }
        }

        // If we have received at least a few frames, stop early —
        // we have proven the path works.
        if total_received >= 2 {
            eprintln!("[rx] received enough frames, stopping early");
            break;
        }

        std::thread::sleep(RX_POLL_INTERVAL);
    }

    // ── report ──────────────────────────────────────────────────────────

    eprintln!("[rx] --- summary ---");
    eprintln!("[rx]   poll iterations:  {poll_iterations}");
    eprintln!("[rx]   frames received:  {total_received}");
    eprintln!("[rx]   frames parsed:    {total_parsed}");
    eprintln!("[rx]   expect_rx:        {expect_rx}");
    eprintln!("[rx] --- end summary ---");

    if total_received > 0 {
        eprintln!("=== {label} complete — received and parsed {total_received} frame(s)! ===");
    } else if expect_rx {
        panic!(
            "no frames received after {RX_POLL_TIMEOUT:?} — \
             the host kernel may not have responded to our ICMPv6 probes, \
             or promiscuous mode may not be working on this virtio backend"
        );
    } else {
        eprintln!(
            "[rx] no frames received (expected — the QEMU TAP interfaces \
             are likely DOWN because `script=no` is used without a \
             post-launch TAP-setup step in the n-vm QEMU backend)"
        );
        eprintln!("=== {label} complete — tx path validated, rx skipped (no traffic source) ===");
    }

    // Teardown. This used to be an ordering hazard: the PMD owns every transmitted mbuf until
    // the device is stopped and its tx ring reclaimed, those mbufs live in `tx_pool`, and Rust
    // drops locals in reverse declaration order -- so the natural order freed the mempool first
    // and left the stop path walking freed memory (a SIGSEGV inside `rte_pktmbuf_free`, after
    // every assertion above had already passed).
    //
    // It is no longer expressible. `Pool` is a `Copy` handle whose mempool is released at EAL
    // teardown, after every device is closed, so there is no early free to get wrong -- the
    // compiler now rejects `drop(tx_pool)` as a no-op on a `Copy` type.
    //
    // Both steps are spelled out rather than left to `Drop` so that a teardown failure fails the
    // test instead of being logged and swallowed.
    let stopped = started.stop().expect("failed to stop device");
    stopped.close().expect("failed to close device");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// -- VM configurations -----------------------------------------------------
//
// These were attributes (`#[guest(...)]`, `#[hypervisor(...)]`,
// `#[network(...)]`) when this test was written; n-vm now takes one `const
// VmConfig`, checked at compile time rather than at launch.
//
// Two things changed meaning in that move, and both are deliberate here.
//
// The host page default inverted. It used to be 1 GiB, with
// `#[hypervisor(host_pages = "4k")]` as the override; `VmConfig::DEFAULT` is
// now `Standard`, and 1 GiB has to be asked for. Porting the old intent
// literally would put eight of these twelve tests back on a pool that is tiny
// and unarbitrated -- which is what made VM tests look flaky before anyone
// worked out that they were contending for it. So the 1 GiB variants are
// gated behind `host_hugepage_tests`, exactly as the n-vm suite's own are.
//
// QEMU is named as a *profile* rather than as a backend. `.backend(Qemu)`
// says "this test needs QEMU", and a run whose kernel profile is
// cloud-hypervisor answers that by skipping -- which nextest prints as a
// pass. Measured on the n-vm suite: six of its twenty-nine tests never
// execute under the default profile for exactly this reason. Naming the
// profile makes these run in every sweep.

/// What DPDK needs from the guest to run at all: 64 x 2 MiB pages.
///
/// DPDK without hugepages is a different program on a different allocator
/// path, so every test here reserves them.
const GUEST_2M: GuestHugePageConfig = GuestHugePageConfig::Allocate {
    size: GuestHugePageSize::Huge2M,
    count: 64,
};

/// virtio-net under cloud-hypervisor: default hypervisor, default NIC.
const VIRTIO_CH: VmConfig = VmConfig {
    guest_hugepages: GUEST_2M,
    ..VmConfig::DEFAULT
};

/// The same guest under QEMU.
const VIRTIO_QEMU: VmConfig = VIRTIO_CH
    .to_builder()
    .kernel_profile(kernel_profiles::QEMU)
    .build();

/// QEMU with a virtual IOMMU, which is what DPDK's vfio-pci path wants.
const VIRTIO_QEMU_IOMMU: VmConfig = VIRTIO_QEMU.to_builder().iommu(true).build();

const E1000_QEMU: VmConfig = VIRTIO_QEMU.to_builder().nic_model(NicModel::E1000).build();
const E1000_QEMU_IOMMU: VmConfig = E1000_QEMU.to_builder().iommu(true).build();
const E1000E_QEMU: VmConfig = VIRTIO_QEMU.to_builder().nic_model(NicModel::E1000E).build();
const E1000E_QEMU_IOMMU: VmConfig = E1000E_QEMU.to_builder().iommu(true).build();

/// The 1 GiB-host-page counterparts.
///
/// Host page size is the one thing only DPDK-through-an-IOMMU can tell apart:
/// it decides whether the guest's memory is physically contiguous. That is
/// what makes these worth having, and also what makes them expensive.
const E1000_QEMU_1G: VmConfig = E1000_QEMU
    .to_builder()
    .host_page_size(HostPageSize::Huge1G)
    .build();
const E1000_QEMU_IOMMU_1G: VmConfig = E1000_QEMU_IOMMU
    .to_builder()
    .host_page_size(HostPageSize::Huge1G)
    .build();
const E1000E_QEMU_1G: VmConfig = E1000E_QEMU
    .to_builder()
    .host_page_size(HostPageSize::Huge1G)
    .build();
const E1000E_QEMU_IOMMU_1G: VmConfig = E1000E_QEMU_IOMMU
    .to_builder()
    .host_page_size(HostPageSize::Huge1G)
    .build();

/// Phase 0 spike: DPDK EAL init + device start with virtio-net on
/// cloud-hypervisor.
///
/// Validates the entire chain:
///
/// 1. Verify `vfio-pci` is built into the kernel
/// 2. Discover virtio-net devices in `/sys/bus/pci/devices/`
/// 3. Unbind from kernel virtio driver, bind to `vfio-pci`
/// 4. `eal::init` with PCI allow-list
/// 5. Assert DPDK enumerates ≥ 1 port
/// 6. Configure 1 rx + 1 tx queue, create mempool
/// 7. `dev.start()` succeeds
#[n_vm::test(config = VIRTIO_CH)]
fn dpdk_eal_init_virtio_cloud_hypervisor() {
    eprintln!("=== Phase 0 spike: DPDK EAL init in cloud-hypervisor VM ===");

    let (eal, _started, _) = setup_dpdk_device(false);

    // Leak the Eal handle so `Eal::drop()` does not hang the test
    // process on `rte_eal_mp_wait_lcore()`.  See the comment in
    // `run_rx_test` for the full explanation.
    std::mem::forget(eal);

    eprintln!("=== Phase 0 spike complete — DPDK init works in the VM! ===");
}

/// Rx spike: cloud-hypervisor + virtio-net, VFIO no-IOMMU (PA mode).
///
/// DPDK selects `IOVA mode 'PA'` because there is no vIOMMU.
#[n_vm::test(config = VIRTIO_CH)]
fn dpdk_rx_frame_virtio_cloud_hypervisor() {
    run_rx_test("cloud-hypervisor / virtio-net / no-IOMMU (PA)", true);
}

/// Rx spike: QEMU + virtio-net, VFIO no-IOMMU (PA mode).
///
/// Same as the cloud-hypervisor variant but exercises the QEMU backend
/// and its TAP + vhost-net networking stack.
#[n_vm::test(config = VIRTIO_QEMU)]
fn dpdk_rx_frame_virtio_qemu() {
    // TAPs are now brought UP with IPv6 addresses by the QEMU backend
    // via rtnetlink (configure_host_taps), so rx should work.
    run_rx_test("QEMU / virtio-net / no-IOMMU (PA)", true);
}

/// Rx spike: QEMU + virtio-net + vIOMMU (VA mode).
///
/// Enables the Intel IOMMU device (`intel-iommu`) in QEMU and sets
/// `iommu_platform=on,ats=on` on the virtio-net devices.  DPDK should
/// auto-detect `IOVA mode 'VA'` (virtual addresses translated by the
/// IOMMU), exercising a fundamentally different DMA path.
#[n_vm::test(config = VIRTIO_QEMU_IOMMU)]
fn dpdk_rx_frame_virtio_qemu_iommu() {
    // TAPs are now brought UP with IPv6 addresses by the QEMU backend
    // via rtnetlink (configure_host_taps), so rx should work.
    run_rx_test("QEMU / virtio-net / vIOMMU (VA)", true);
}

// ---------------------------------------------------------------------------
// e1000 tests (QEMU only)
// ---------------------------------------------------------------------------

/// Rx spike: QEMU + e1000 (Intel 82540EM), VFIO no-IOMMU (PA mode).
///
/// Exercises the DPDK `net_e1000_em` PMD against a fully emulated Intel
/// GbE NIC.  No vIOMMU — DPDK uses PA-mode IOVA.
#[cfg_attr(
    not(host_hugepage_tests),
    ignore = "needs 1 GiB host pages; run with --cfg=host_hugepage_tests"
)]
#[n_vm::test(config = E1000_QEMU_1G)]
fn dpdk_rx_frame_e1000_qemu() {
    run_rx_test("QEMU / e1000 / no-IOMMU (PA)", true);
}

/// Rx spike: QEMU + e1000 (Intel 82540EM) + vIOMMU (VA mode).
///
/// Same as the no-IOMMU variant but enables the Intel IOMMU device in
/// QEMU.  e1000 does not support `iommu_platform` or ATS, but it sits
/// behind the IOMMU on the PCI bus so DMA is still remapped.  DPDK
/// should auto-detect VA mode.
#[cfg_attr(
    not(host_hugepage_tests),
    ignore = "needs 1 GiB host pages; run with --cfg=host_hugepage_tests"
)]
#[n_vm::test(config = E1000_QEMU_IOMMU_1G)]
fn dpdk_rx_frame_e1000_qemu_iommu() {
    run_rx_test("QEMU / e1000 / vIOMMU (VA)", true);
}

/// Rx spike: QEMU + e1000 (Intel 82540EM), VFIO no-IOMMU (PA mode),
/// host 4 KiB pages.
///
/// Same as [`dpdk_rx_frame_e1000_qemu`] but the VM's memory is backed
/// by standard 4 KiB pages on the host (`memory-backend-memfd`) instead
/// of hugetlbfs.  Guest-side 2 MiB hugepages are still reserved for
/// DPDK's mempool.  This exercises the "no host hugepages" deployment
/// path — only the guest kernel's own hugepage allocator is used.
///
/// Transparent Huge Pages (THP) on the host may silently promote the
/// backing pages to 2 MiB, but that is a host-side optimisation and
/// does not affect DPDK's view of guest memory.
#[n_vm::test(config = E1000_QEMU)]
fn dpdk_rx_frame_e1000_qemu_4k() {
    run_rx_test("QEMU / e1000 / no-IOMMU (PA) / host 4K pages", true);
}

/// Rx spike: QEMU + e1000 (Intel 82540EM) + vIOMMU (VA mode),
/// host 4 KiB pages.
///
/// Combines the vIOMMU variant with standard host pages.  DPDK should
/// auto-detect VA mode via the IOMMU while the VM's memory is backed
/// by `memory-backend-memfd` (no hugetlbfs on the host).
#[n_vm::test(config = E1000_QEMU_IOMMU)]
fn dpdk_rx_frame_e1000_qemu_iommu_4k() {
    run_rx_test("QEMU / e1000 / vIOMMU (VA) / host 4K pages", true);
}

// ---------------------------------------------------------------------------
// e1000e tests (QEMU only)
// ---------------------------------------------------------------------------

/// Rx spike: QEMU + e1000e (Intel 82574L), VFIO no-IOMMU (PA mode).
///
/// Exercises the DPDK `net_e1000_igb` PMD against QEMU's emulated
/// Intel 82574L NIC with MSI-X and hardware offloads.
#[cfg_attr(
    not(host_hugepage_tests),
    ignore = "needs 1 GiB host pages; run with --cfg=host_hugepage_tests"
)]
#[n_vm::test(config = E1000E_QEMU_1G)]
fn dpdk_rx_frame_e1000e_qemu() {
    run_rx_test("QEMU / e1000e / no-IOMMU (PA)", true);
}

/// Rx spike: QEMU + e1000e (Intel 82574L) + vIOMMU (VA mode).
///
/// Same as the no-IOMMU variant but with the Intel IOMMU enabled.
/// Like e1000, e1000e has no `iommu_platform`/ATS support but DMA is
/// remapped by the IOMMU on the PCI bus.
#[cfg_attr(
    not(host_hugepage_tests),
    ignore = "needs 1 GiB host pages; run with --cfg=host_hugepage_tests"
)]
#[n_vm::test(config = E1000E_QEMU_IOMMU_1G)]
fn dpdk_rx_frame_e1000e_qemu_iommu() {
    run_rx_test("QEMU / e1000e / vIOMMU (VA)", true);
}

/// Rx spike: QEMU + e1000e (Intel 82574L), VFIO no-IOMMU (PA mode),
/// host 4 KiB pages.
///
/// Same as [`dpdk_rx_frame_e1000e_qemu`] but with standard 4 KiB host
/// pages.  QEMU uses `memory-backend-memfd` instead of hugetlbfs-backed
/// files, while the guest still reserves 2 MiB hugepages for DPDK.
#[n_vm::test(config = E1000E_QEMU)]
fn dpdk_rx_frame_e1000e_qemu_4k() {
    run_rx_test("QEMU / e1000e / no-IOMMU (PA) / host 4K pages", true);
}

/// Rx spike: QEMU + e1000e (Intel 82574L) + vIOMMU (VA mode),
/// host 4 KiB pages.
///
/// Combines the vIOMMU variant with standard host pages.  DMA is
/// remapped by the IOMMU while the VM's physical memory is backed by
/// anonymous shared memory (no hugetlbfs).
#[n_vm::test(config = E1000E_QEMU_IOMMU)]
fn dpdk_rx_frame_e1000e_qemu_iommu_4k() {
    run_rx_test("QEMU / e1000e / vIOMMU (VA) / host 4K pages", true);
}
