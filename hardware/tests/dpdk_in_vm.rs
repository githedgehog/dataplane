// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Test DPDK device binding, ICMPv6 traffic, and teardown in VM guests.
//!
//! Traffic tests require a Neighbor Advertisement and an Echo Reply from the host TAP interface.
//! Teardown tests cover both explicit device cleanup and a leaked device with queued mbufs.
//!
//! # Supported NIC models
//!
//! | NIC model | Hypervisor | DPDK PMD | IOMMU variants |
//! |-----------|------------|----------|----------------|
//! | virtio-net | cloud-hypervisor | `net_virtio` | no-IOMMU (PA) |
//! | virtio-net | QEMU | `net_virtio` | no-IOMMU (PA), vIOMMU (VA) |
//! | e1000 (Intel 82540EM) | QEMU only | `net_e1000_em` | no-IOMMU (PA), vIOMMU (VA) |
//! | e1000e (Intel 82574L) | QEMU only | `net_e1000_igb` | no-IOMMU (PA), vIOMMU (VA) |
//!
//! # IOMMU variants
//!
//! DPDK selects physical addresses (PA) without a virtual IOMMU and virtual addresses (VA)
//! with QEMU's `intel-iommu` device.
//! Virtio-net also enables `iommu_platform` and ATS; e1000 and e1000e use PCI bus remapping.
//!
//! # Host page size
//!
//! Tests use 4 KiB host pages by default.
//! The e1000 and e1000e traffic tests without a `_4k` suffix use 1 GiB host hugepages and are
//! ignored unless built with `--cfg host_hugepage_tests`, since the host pool is shared and limited.
//! All configurations reserve 64 × 2 MiB guest hugepages for DPDK.
//!
//! # Prerequisites
//!
//! The VM image must include:
//!
//! - Built-in `vfio-pci` and NIC drivers (`CONFIG_VIRTIO_NET`, `CONFIG_E1000`, `CONFIG_E1000E`),
//!   since the VM kernel disables module loading.
//! - The guest hugepage reservation requested by each [`VmConfig`].

use clock::Duration;
use dataplane_hardware::nic::{BindToVfioPci, PciNic, PciNicError};
use dataplane_hardware::pci::address::PciAddress;
use dataplane_hardware::support::DpdkDriverType;
use dpdk::dev::{Dev, DevConfig, RxOffload, Started, TxOffloadConfig};
use dpdk::eal::{self, Eal};
use dpdk::mem::{MbufArray, Pool, PoolConfig, PoolParams};
use dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dpdk::socket;
use n_vm::config::{
    GuestHugePageConfig, GuestHugePageSize, HostPageSize, NetIface, NicModel, VmConfig,
};
use n_vm::kernel_profiles;
use net::buffer::Append;
use net::eth::mac::{DestinationMac, Mac, SourceMac};
use net::headers::builder::HeaderStack;
use net::headers::{Headers, Net, Transport};
use net::icmp6::{Icmp6EchoReply, Icmp6EchoRequest, Icmp6Type};
use net::ipv6::UnicastIpv6Addr;
use net::parse::DeParse;
use net::parse::Parse;
use std::fs;
use std::net::Ipv6Addr;

// Constants

/// Root path for PCI device enumeration in sysfs.
const PCI_DEVICES_PATH: &str = "/sys/bus/pci/devices";

/// `n-it`'s hugetlbfs mount, passed to DPDK with `--huge-dir`.
/// The default 512 MiB guest can reserve 2 MiB pages but cannot fit a 1 GiB page.
const HUGEPAGE_DIR: &str = "/run/huge/2MiB";

/// Sysfs directory containing per-page-size hugepage accounting.
const HUGEPAGES_SYSFS: &str = "/sys/kernel/mm/hugepages";

/// Sysfs directory for the built-in `vfio-pci` driver.
const VFIO_PCI_DRIVER_PATH: &str = "/sys/bus/pci/drivers/vfio-pci";

/// Deadline for receiving both probe replies.
const RX_POLL_TIMEOUT: Duration = Duration::from_secs(10);

/// Sleep between rx poll attempts to avoid burning CPU.
const RX_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Retry interval until both probes are answered.
const RETRANSMIT_INTERVAL: Duration = Duration::from_secs(1);

// Helpers — sysfs / diagnostics

/// Find NICs that [`PciNic`] supports binding to `vfio-pci`.
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
        let addr = match PciAddress::try_from(name_str.as_ref()) {
            Ok(addr) => addr,
            Err(e) => {
                eprintln!("[discover] failed to parse PCI address '{name_str}': {e}");
                continue;
            }
        };
        let nic = match PciNic::new(addr) {
            Ok(nic) => nic.device(),
            Err(PciNicError::Unsupported { vendor, device, .. }) => {
                eprintln!("[discover] {addr}: vendor=0x{vendor:04x} device=0x{device:04x}");
                continue;
            }
            Err(e) => {
                eprintln!("[discover] {addr}: {e}");
                continue;
            }
        };
        if DpdkDriverType::from(nic) != DpdkDriverType::VfioPci {
            eprintln!("[discover] {addr}: {nic}, not driven through vfio-pci; skipping");
            continue;
        }
        eprintln!("[discover] {addr}: {nic}");
        found.push(addr);
    }

    found.sort();
    found
}

/// Where the kernel lists its network interfaces.
const NET_CLASS_PATH: &str = "/sys/class/net";

/// Find a NIC by its kernel interface's MAC address before binding it to `vfio-pci`.
/// Virtio-net's `device` link points below the PCI function, so search its ancestors.
fn pci_address_of_mac(mac: &str) -> Option<PciAddress> {
    let iface = fs::read_dir(NET_CLASS_PATH).ok()?.flatten().find(|iface| {
        fs::read_to_string(iface.path().join("address"))
            .is_ok_and(|address| address.trim().eq_ignore_ascii_case(mac))
    })?;
    let device = fs::canonicalize(iface.path().join("device")).ok()?;
    device
        .ancestors()
        .find_map(|dir| PciAddress::try_from(dir.file_name()?.to_str()?).ok())
}

/// Log process credentials and capabilities to diagnose permission errors.
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

/// Log hugepage pools and mounts before EAL initialization.
fn dump_hugepage_diagnostics() {
    eprintln!("[huge] --- hugepage diagnostics ---");

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

/// Require the built-in `vfio-pci` driver.
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

/// Where the kernel lists IOMMU groups.
const IOMMU_GROUPS_PATH: &str = "/sys/kernel/iommu_groups";

/// The names in a directory, numbers in numeric order and anything else after them.
fn dir_entries(path: &str) -> std::io::Result<Vec<String>> {
    let mut names: Vec<String> = fs::read_dir(path)?
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    names.sort_by_key(|name| (name.parse::<u32>().unwrap_or(u32::MAX), name.clone()));
    Ok(names)
}

/// The last component of a symlink's target, such as a device's driver or IOMMU group.
fn link_target_name(path: &str) -> std::io::Result<String> {
    let target = fs::read_link(path)?;
    Ok(target
        .file_name()
        .map_or_else(|| "?".into(), |name| name.to_string_lossy().into_owned()))
}

/// Log IOMMU groups and kernel settings to diagnose VFIO binding failures.
fn dump_iommu_diagnostics(addresses: &[PciAddress]) {
    eprintln!("[iommu] --- IOMMU diagnostics ---");

    match dir_entries(IOMMU_GROUPS_PATH) {
        Ok(groups) if groups.is_empty() => {
            eprintln!("[iommu]   {IOMMU_GROUPS_PATH}/ exists but is EMPTY");
            eprintln!("[iommu]   -> the kernel IOMMU driver may not have initialised");
            eprintln!("[iommu]   -> check kernel log for: 'DMAR: IOMMU enabled'");
        }
        Ok(groups) => eprintln!(
            "[iommu]   found {} IOMMU group(s): {groups:?}",
            groups.len()
        ),
        Err(e) => {
            eprintln!("[iommu]   {IOMMU_GROUPS_PATH}/ not readable: {e}");
            eprintln!("[iommu]   -> IOMMU support may not be compiled into the kernel");
        }
    }

    for addr in addresses {
        match link_target_name(&format!("{PCI_DEVICES_PATH}/{addr}/iommu_group")) {
            Ok(group) => eprintln!("[iommu]   {addr}: iommu_group={group}"),
            Err(e) => {
                eprintln!("[iommu]   {addr}: NO iommu_group symlink ({e})");
                eprintln!("[iommu]       -> this device cannot be bound to vfio-pci with IOMMU");
            }
        }
    }

    match fs::read_to_string("/sys/module/vfio/parameters/enable_unsafe_noiommu_mode") {
        Ok(val) => eprintln!("[iommu]   vfio.enable_unsafe_noiommu_mode={}", val.trim()),
        Err(e) => eprintln!("[iommu]   vfio noiommu flag not readable: {e}"),
    }

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

/// Log VFIO devices, drivers, and groups after binding to diagnose DPDK probe failures.
fn dump_post_bind_vfio_diagnostics(addresses: &[PciAddress]) {
    eprintln!("[vfio-diag] --- post-bind VFIO diagnostics ---");

    // DPDK opens /dev/vfio/vfio (container) and /dev/vfio/<group> (or
    // /dev/vfio/noiommu-<group>) for each device.
    match dir_entries("/dev/vfio") {
        Ok(names) => eprintln!("[vfio-diag]   /dev/vfio/ entries: {names:?}"),
        Err(e) => eprintln!("[vfio-diag]   /dev/vfio/ not readable: {e}"),
    }

    // In no-IOMMU mode, groups are created when devices bind to vfio-pci.
    match dir_entries(IOMMU_GROUPS_PATH) {
        Ok(groups) => eprintln!(
            "[vfio-diag]   iommu_groups after bind: {} group(s): {groups:?}",
            groups.len()
        ),
        Err(e) => eprintln!("[vfio-diag]   {IOMMU_GROUPS_PATH}/ not readable: {e}"),
    }

    for addr in addresses {
        let base = format!("{PCI_DEVICES_PATH}/{addr}");
        match link_target_name(&format!("{base}/driver")) {
            Ok(driver) => eprintln!("[vfio-diag]   {addr}: driver={driver}"),
            Err(e) => eprintln!("[vfio-diag]   {addr}: no driver symlink ({e})"),
        }
        match link_target_name(&format!("{base}/iommu_group")) {
            Ok(group) => eprintln!("[vfio-diag]   {addr}: iommu_group={group}"),
            Err(e) => eprintln!("[vfio-diag]   {addr}: no iommu_group ({e})"),
        }
    }

    eprintln!("[vfio-diag] --- end post-bind VFIO diagnostics ---");
}

/// Bind each address to `vfio-pci` and return those that succeeded.
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

/// Configure guest memory, PCI probing, and diagnostics; let DPDK select the IOVA mode.
fn build_eal_args(pci_allow_list: &[PciAddress]) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "dpdk-test".into(),   // argv[0] — process name convention
        "--in-memory".into(), // no persistent hugepage files
        format!("--huge-dir={HUGEPAGE_DIR}"),
        // Explain skipped devices and VFIO setup failures in the test log.
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

// Helpers — DPDK device setup

/// The first fabric link, which the tests drive where the guest has one.
const FABRIC_LINK: &str = "fabric1";

/// The link n-vm sets aside for management. It keeps its kernel driver unless it is the only
/// link there is.
const MGMT_LINK: &str = "mgmt";

/// Use the first fabric NIC on QEMU and the management NIC on cloud-hypervisor.
/// Cloud-hypervisor guests do not enumerate the PCI segment containing the fabric NICs.
fn probed_link_id(config: &VmConfig) -> &'static str {
    let on_qemu = config.kernel_profile == Some(kernel_profiles::QEMU)
        || config.first_qemu_only_nic().is_some();
    if on_qemu { FABRIC_LINK } else { MGMT_LINK }
}

/// Find the named interface in the VM configuration.
fn link(config: &VmConfig, id: &str) -> NetIface {
    config
        .all_ifaces()
        .into_iter()
        .find(|iface| iface.id == id)
        .unwrap_or_else(|| panic!("the VM has no {id} interface"))
}

/// The PCI address of `link`'s NIC, found by its MAC address.
fn pci_address_of_link(link: &NetIface) -> PciAddress {
    pci_address_of_mac(&link.mac).unwrap_or_else(|| {
        panic!(
            "no kernel network interface has the {} MAC address {}",
            link.id, link.mac
        )
    })
}

/// Bind supported NICs and initialize the EAL for the link selected by [`probed_link_id`].
/// The management NIC keeps its kernel driver unless it is the selected link.
/// Allow only the selected NIC in the EAL so probes use the intended host TAP interface.
///
/// # Panics
///
/// Panics on setup failure.
fn init_dpdk_eal(config: &VmConfig) -> (Eal, NetIface) {
    assert_vfio_pci_available();

    // Before binding: a NIC bound to vfio-pci has no kernel interface left to read a MAC from.
    let probed = link(config, probed_link_id(config));
    let probed_addr = pci_address_of_link(&probed);
    let mut net_addrs = discover_pci_net_devices();
    if probed.id != MGMT_LINK {
        let mgmt_addr = pci_address_of_link(&link(config, MGMT_LINK));
        net_addrs.retain(|&addr| addr != mgmt_addr);
        eprintln!("[eal] {MGMT_LINK} ({mgmt_addr}) keeps its kernel driver");
    }
    eprintln!(
        "[eal] {} NIC(s) to bind; probing {} ({probed_addr})",
        net_addrs.len(),
        probed.id
    );
    assert!(
        net_addrs.contains(&probed_addr),
        "{} ({probed_addr}) is not among the supported vfio-pci NICs {net_addrs:?}",
        probed.id
    );

    dump_iommu_diagnostics(&net_addrs);

    let bound = bind_devices_to_vfio(&net_addrs);
    eprintln!("[eal] {} device(s) bound to vfio-pci", bound.len());
    assert_eq!(
        bound, net_addrs,
        "every NIC to bind must bind to vfio-pci; see the [bind] log above"
    );

    dump_post_bind_vfio_diagnostics(&bound);

    dump_capability_diagnostics();
    dump_hugepage_diagnostics();
    let eal_args = build_eal_args(&[probed_addr]);
    eprintln!("[eal] args: {eal_args:?}");
    let eal = eal::init(eal_args);
    eprintln!("[eal] initialised (has_pci={})", eal.has_pci());
    (eal, probed)
}

/// Start `link`'s NIC with one RX queue and one TX queue.
/// If `with_tx_pool` is true, also allocate a pool for outgoing packets.
/// The caller owns the EAL because the returned device and pools borrow it.
///
/// # Panics
///
/// Panics on setup failure.
fn setup_dpdk_device<'eal>(
    eal: &'eal Eal,
    link: &NetIface,
    with_tx_pool: bool,
) -> SetupDevice<'eal> {
    let num_ports = eal.dev.num_devices();
    eprintln!("[eal] DPDK reports {num_ports} ethernet port(s)");
    assert_eq!(
        num_ports, 1,
        "the EAL was allowed only the {} NIC — with 0 ports, the PMD may not have claimed it; \
         check the VFIO and PCI bus debug log above for probe failures",
        link.id
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

    let dev_info = eal
        .dev
        .iter()
        .next()
        .expect("dev iterator empty despite num_devices > 0");

    eprintln!(
        "[dev] configuring port {} (driver: {}) …",
        dev_info.index(),
        dev_info.driver_name(),
    );

    let config = DevConfig {
        num_rx_queues: 1,
        num_tx_queues: 1,
        num_hairpin_queues: 0,
        // These probes do not require receive offloads.
        rx_offloads: RxOffload::NONE,
        tx_offloads: TxOffloadConfig::none(),
        // The standard MTU, clamped to the device's range, accommodates these small probes.
        mtu: None,
        // A single RX queue does not need RSS.
        rss: None,
    };

    let mut dev = config
        .apply(
            eal.claim(dev_info.index())
                .expect("failed to claim the port"),
        )
        .expect("failed to apply DevConfig");
    eprintln!("[dev] device configured");

    let mac = dev
        .mac_address()
        .expect("read the port's MAC address")
        .inner();
    let expected: Mac = link.mac.parse().expect("n-vm MAC address");
    assert_eq!(mac, expected, "DPDK's port is not the {} NIC", link.id);

    let rx_pool = eal
        .mem
        .new_pkt_pool(
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
        let pool = eal
            .mem
            .new_pkt_pool(
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

    dev.new_rx_queue(RxQueueConfig {
        queue_index: RxQueueIndex(0),
        num_descriptors: 256,
        socket_preference: socket::Preference::CurrentThread,
        // Queue offload capabilities can differ from the port's capabilities.
        offloads: dev.info().rx_queue_offload_caps(),
        pool: rx_pool.clone(),
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

    let dev = dev.start().expect("failed to start DPDK device");
    eprintln!("[dev] device started successfully");

    SetupDevice {
        dev,
        mac,
        rx_pool,
        tx_pool,
    }
}

/// A started device and its packet pools.
struct SetupDevice<'eal> {
    /// The started device.
    dev: Dev<'eal, Started>,
    /// Its MAC address, which the probes are sent from so that the replies come back to it.
    mac: Mac,
    /// RX queue 0's pool; its in-use count tracks mbufs held by the driver.
    rx_pool: Pool<'eal>,
    /// Optional pool for outgoing packets.
    tx_pool: Option<Pool<'eal>>,
}

// Helpers — probe frame construction

/// Probe source address: an arbitrary link-local.
const PROBE_SRC_IP: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x42);

/// Identifier and sequence number of the probe Echo Request, which its reply echoes back.
const PROBE_ECHO: Icmp6EchoRequest = Icmp6EchoRequest { id: 1, seq: 1 };

/// Build an Ethernet / IPv6 / ICMPv6 frame from `src_mac` and [`PROBE_SRC_IP`], with `body` after
/// the 8-byte ICMPv6 header. `net` fills in the length fields and the ICMPv6 checksum.
fn icmp6_probe_frame(
    src_mac: Mac,
    dst_mac: Mac,
    dst_ip: Ipv6Addr,
    hop_limit: u8,
    icmp_type: Icmp6Type,
    body: &[u8],
) -> Vec<u8> {
    let headers = HeaderStack::new()
        .eth(|eth| {
            eth.set_source(SourceMac::new(src_mac).expect("unicast source MAC"))
                .set_destination(DestinationMac::new(dst_mac).expect("valid destination MAC"));
        })
        .ipv6(|ip| {
            ip.set_source(UnicastIpv6Addr::new(PROBE_SRC_IP).expect("unicast source address"))
                .set_destination(dst_ip)
                .set_hop_limit(hop_limit);
        })
        .icmp6(|icmp| icmp.set_type(icmp_type))
        .build_headers_with_payload(body)
        .expect("failed to build probe headers");
    let mut frame = vec![0; usize::from(headers.size().get())];
    headers
        .deparse(&mut frame)
        .expect("failed to write probe headers");
    frame.extend_from_slice(body);
    frame
}

/// An ICMPv6 Neighbor Solicitation for `target`, sent from `src_mac` to the target's
/// solicited-node multicast group (RFC 4291 section 2.7.1) with `src_mac` as our link-layer
/// address.
///
/// The source link-layer option lets the host cache our MAC before replying to the Echo Request
/// (RFC 4861 section 7.2.3); this test does not answer Neighbor Solicitations.
/// NDP requires a hop limit of 255 (RFC 4861 section 4.3).
fn ndp_probe_frame(src_mac: Mac, target: Ipv6Addr) -> Vec<u8> {
    let [.., a, b, c] = target.octets();
    let group = Ipv6Addr::new(
        0xff02,
        0,
        0,
        0,
        0,
        1,
        0xff00 | u16::from(a),
        u16::from_be_bytes([b, c]),
    );
    // RFC 2464 section 7: 33:33 followed by the group's last four octets.
    let [.., w, x, y, z] = group.octets();
    let mut body = target.octets().to_vec();
    // Source Link-Layer Address option: type 1, length 1 (in units of 8 octets).
    body.extend_from_slice(&[1, 1]);
    body.extend_from_slice(&src_mac.0);
    icmp6_probe_frame(
        src_mac,
        Mac([0x33, 0x33, w, x, y, z]),
        group,
        255,
        Icmp6Type::NeighborSolicitation,
        &body,
    )
}

/// An ICMPv6 Echo Request from `src_mac` to all nodes (`ff02::1`, MAC `33:33:00:00:00:01`).
///
/// RFC 4443 section 4.1 says a node SHOULD answer an Echo Request sent to a multicast address,
/// and Linux does unless `net.ipv6.icmp.echo_ignore_multicast` is set.
fn echo_probe_frame(src_mac: Mac) -> Vec<u8> {
    icmp6_probe_frame(
        src_mac,
        Mac([0x33, 0x33, 0x00, 0x00, 0x00, 0x01]),
        Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
        64,
        Icmp6Type::EchoRequest(PROBE_ECHO),
        &[],
    )
}

/// The reply to one of the probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeReply {
    /// The answer to [`ndp_probe_frame`].
    NeighborAdvertisement,
    /// The answer to [`echo_probe_frame`].
    EchoReply,
}

/// Which probe a received frame answers, if any.
///
/// Replies must be unicast to `port_mac` and [`PROBE_SRC_IP`], with either `host` as the advertised
/// neighbor or [`PROBE_ECHO`]'s identifier and sequence number.
/// An Echo Reply may use any host address on the link because the request is multicast.
/// `body` follows the parsed headers and contains a Neighbor Advertisement's target address.
fn probe_reply(
    headers: &Headers,
    body: &[u8],
    port_mac: Mac,
    host: Ipv6Addr,
) -> Option<ProbeReply> {
    if headers.eth()?.destination().inner() != port_mac {
        return None;
    }
    let Some(Net::Ipv6(ip)) = headers.net() else {
        return None;
    };
    if ip.destination() != PROBE_SRC_IP {
        return None;
    }
    let Some(Transport::Icmp6(icmp)) = headers.transport() else {
        return None;
    };
    match icmp.icmp_type() {
        Icmp6Type::EchoReply(Icmp6EchoReply { id, seq })
            if id == PROBE_ECHO.id && seq == PROBE_ECHO.seq =>
        {
            Some(ProbeReply::EchoReply)
        }
        Icmp6Type::NeighborAdvertisement(_)
            if Ipv6Addr::from(ip.source()) == host
                && body.get(..16) == Some(&host.octets()[..]) =>
        {
            Some(ProbeReply::NeighborAdvertisement)
        }
        _ => None,
    }
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

// Helpers — rx test body

/// Copy `frames` into freshly allocated mbufs from `pool`, one frame per mbuf.
fn make_batch<'eal>(pool: &Pool<'eal>, frames: &[&[u8]]) -> MbufArray<'eal> {
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
}

/// Require the host to answer both ICMPv6 probes, then check device and EAL teardown.
/// `config` must match the enclosing VM test's configuration.
fn run_rx_test(label: &str, config: &VmConfig) {
    eprintln!("=== {label} ===");

    let (eal, link) = init_dpdk_eal(config);
    let SetupDevice {
        dev: started,
        mac,
        tx_pool,
        ..
    } = setup_dpdk_device(&eal, &link, true);

    let tx_pool = tx_pool.expect("setup_dpdk_device should return a tx pool");
    let host = link.host_ipv6;

    // Use the port's MAC so replies arrive without promiscuous mode.
    let ndp_frame = ndp_probe_frame(mac, host);
    let echo_frame = echo_probe_frame(mac);

    eprintln!(
        "[tx] probe frames built: NS={} bytes, Echo={} bytes",
        ndp_frame.len(),
        echo_frame.len(),
    );

    let mut queues = started.take_queues().expect("device queues already taken");
    let mut tx_queue = queues
        .take_tx(TxQueueIndex(0))
        .expect("tx queue 0 missing after start");

    log_hex_dump("tx:ndp", &ndp_frame, 86);
    log_hex_dump("tx:echo", &echo_frame, 62);

    // The empty TX ring must accept both initial probes.
    let batch = make_batch(&tx_pool, &[&ndp_frame, &echo_frame]);
    let sent = batch.len();
    let unsent = tx_queue.transmit(batch);
    assert!(
        unsent.is_empty(),
        "tx queue refused {refused} of {sent} probe frames",
        refused = unsent.len(),
    );
    // Release the batch's EAL borrow before teardown, even when the batch is empty.
    drop(unsent);
    eprintln!("[tx] {sent} probe frames transmitted");

    let mut rx_queue = queues
        .take_rx(RxQueueIndex(0))
        .expect("rx queue 0 missing after start");

    let deadline = clock::deadline(RX_POLL_TIMEOUT);
    let mut total_received: usize = 0;
    let mut total_parsed: usize = 0;
    let mut poll_iterations: u64 = 0;
    let mut neighbor_advertised = false;
    let mut echo_replied = false;

    eprintln!("[rx] polling rx queue (timeout={RX_POLL_TIMEOUT:?}) …",);

    // Retry probes in case NIC or TAP setup dropped the first batch.
    let mut last_retransmit = clock::now();

    while clock::now() < deadline {
        poll_iterations += 1;

        if !(neighbor_advertised && echo_replied)
            && clock::elapsed(last_retransmit) > RETRANSMIT_INTERVAL
        {
            let batch = make_batch(&tx_pool, &[&ndp_frame, &echo_frame]);
            // Retries may encounter a full TX ring; dropped mbufs can be retried next time.
            let unsent = tx_queue.transmit(batch);
            if !unsent.is_empty() {
                eprintln!(
                    "[tx] WARNING: tx queue refused {refused} retransmitted frame(s)",
                    refused = unsent.len(),
                );
            }
            eprintln!("[tx] retransmitted probes (poll iteration {poll_iterations})");
            last_retransmit = clock::now();
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
                    let body = &data[usize::from(consumed.get())..];
                    match probe_reply(&headers, body, mac, host) {
                        Some(reply) => {
                            eprintln!("[rx:{total_received}] answers a probe: {reply:?}");
                            match reply {
                                ProbeReply::NeighborAdvertisement => neighbor_advertised = true,
                                ProbeReply::EchoReply => echo_replied = true,
                            }
                        }
                        None => eprintln!("[rx:{total_received}] not a reply to a probe"),
                    }
                }
                Err(e) => {
                    // Ignore unrelated traffic; an unparseable probe reply fails the final assertions.
                    eprintln!("[rx:{total_received}] parse failed: {e:?}",);
                }
            }
        }

        if neighbor_advertised && echo_replied {
            eprintln!("[rx] both probes answered, stopping early");
            break;
        }

        std::thread::sleep(RX_POLL_INTERVAL);
    }

    eprintln!("[rx] --- summary ---");
    eprintln!("[rx]   poll iterations:  {poll_iterations}");
    eprintln!("[rx]   frames received:  {total_received}");
    eprintln!("[rx]   frames parsed:    {total_parsed}");
    eprintln!("[rx]   neighbor advertisement: {neighbor_advertised}");
    eprintln!("[rx]   echo reply:       {echo_replied}");
    eprintln!("[rx] --- end summary ---");

    assert!(
        neighbor_advertised,
        "no Neighbor Advertisement for {host} after {RX_POLL_TIMEOUT:?} \
         ({total_received} other frame(s) received)"
    );
    assert!(
        echo_replied,
        "no Echo Reply to the all-nodes probe after {RX_POLL_TIMEOUT:?} \
         ({total_received} other frame(s) received)"
    );
    eprintln!("=== {label} complete — both probes answered! ===");

    // Drop the queue collection before consuming the device, then tear down the EAL.
    // Explicit stop/close calls make driver errors fail the test.
    drop(queues);
    assert_within_budget("closing the device", time_device_teardown(started));
    assert_within_budget("dropping the EAL", time_eal_teardown(eal));
}

/// Maximum teardown duration. The VM timeout catches hangs; this check catches slow returns.
const TEARDOWN_BUDGET: Duration = Duration::from_secs(5);

/// Marks teardown entry in logs when the VM times out.
const TEARDOWN_STARTING: &str = "[teardown] starting";

/// Stop and close the device, returning the elapsed time. Panics on driver errors.
fn time_device_teardown(started: Dev<'_, Started>) -> Duration {
    eprintln!("{TEARDOWN_STARTING}");
    let t = clock::now();
    let stopped = started.stop().expect("failed to stop device");
    let closed = stopped.close().expect("failed to close device");
    drop(closed);
    clock::elapsed(t)
}

/// Drop the EAL, returning the elapsed time.
fn time_eal_teardown(eal: Eal) -> Duration {
    let t = clock::now();
    drop(eal);
    clock::elapsed(t)
}

/// Fail if a teardown step took longer than [`TEARDOWN_BUDGET`].
fn assert_within_budget(step: &str, elapsed: Duration) {
    eprintln!("[teardown] {step} took {elapsed:?}");
    assert!(
        elapsed < TEARDOWN_BUDGET,
        "{step} took {elapsed:?}, over the {TEARDOWN_BUDGET:?} budget"
    );
}

/// Verify EAL teardown closes a leaked device before releasing its pools.
/// Require mbufs to remain in the RX and TX rings so the test exercises driver cleanup.
fn run_leaked_device_test(label: &str, config: &VmConfig) {
    eprintln!("=== {label} ===");

    let (eal, link) = init_dpdk_eal(config);
    let SetupDevice {
        dev: started,
        mac,
        rx_pool,
        tx_pool,
    } = setup_dpdk_device(&eal, &link, true);
    let tx_pool = tx_pool.expect("setup_dpdk_device should return a tx pool");

    // Fill the TX ring; drivers may retain mbufs until a later burst reclaims descriptors.
    let mut queues = started.take_queues().expect("device queues already taken");
    let mut tx_queue = queues
        .take_tx(TxQueueIndex(0))
        .expect("tx queue 0 missing after start");
    let frame = echo_probe_frame(mac);
    let unsent = tx_queue.transmit(make_batch(&tx_pool, &[&frame, &frame, &frame, &frame]));
    assert!(
        unsent.is_empty(),
        "tx queue refused {} frame(s)",
        unsent.len()
    );
    drop(unsent);
    drop(queues);

    let rx_held = rx_pool.in_use();
    let tx_held = tx_pool.in_use();
    eprintln!("[leak] PMD holds {rx_held} rx mbuf(s) and {tx_held} tx mbuf(s)");
    assert!(
        rx_held > 0,
        "the receive ring holds no mbufs, so leaking the device would test nothing"
    );
    assert!(
        tx_held > 0,
        "the transmit ring holds no mbufs, so leaking the device would not test the tx pool"
    );

    core::mem::forget(started);

    eprintln!("{TEARDOWN_STARTING}");
    assert_within_budget(
        "dropping the EAL with a leaked device",
        time_eal_teardown(eal),
    );
    eprintln!("=== {label} complete ===");
}

// Tests

/// Guest hugepages reserved for DPDK mempools in every configuration.
const GUEST_2M: GuestHugePageConfig = GuestHugePageConfig::Allocate {
    size: GuestHugePageSize::Huge2M,
    count: 64,
};

/// Virtio-net under the default cloud-hypervisor backend.
const VIRTIO_CH: VmConfig = VmConfig {
    guest_hugepages: GUEST_2M,
    ..VmConfig::DEFAULT
};

/// The same guest under QEMU.
const VIRTIO_QEMU: VmConfig = VIRTIO_CH
    .to_builder()
    .kernel_profile(kernel_profiles::QEMU)
    .build();

/// QEMU with a virtual IOMMU for DMA remapping.
const VIRTIO_QEMU_IOMMU: VmConfig = VIRTIO_QEMU.to_builder().iommu(true).build();

const E1000_QEMU: VmConfig = VIRTIO_QEMU.to_builder().nic_model(NicModel::E1000).build();
const E1000_QEMU_IOMMU: VmConfig = E1000_QEMU.to_builder().iommu(true).build();
const E1000E_QEMU: VmConfig = VIRTIO_QEMU.to_builder().nic_model(NicModel::E1000E).build();
const E1000E_QEMU_IOMMU: VmConfig = E1000E_QEMU.to_builder().iommu(true).build();

// Variants backed by 1 GiB host hugepages.
const E1000_QEMU_1G: VmConfig = on_1g_host_pages(E1000_QEMU);
const E1000_QEMU_IOMMU_1G: VmConfig = on_1g_host_pages(E1000_QEMU_IOMMU);
const E1000E_QEMU_1G: VmConfig = on_1g_host_pages(E1000E_QEMU);
const E1000E_QEMU_IOMMU_1G: VmConfig = on_1g_host_pages(E1000E_QEMU_IOMMU);

/// `config`, with its memory backed by 1 GiB host pages.
const fn on_1g_host_pages(config: VmConfig) -> VmConfig {
    config
        .to_builder()
        .host_page_size(HostPageSize::Huge1G)
        .build()
}

/// Start and close a virtio-net device, then drop the EAL within the teardown budget.
#[n_vm::test(config = VIRTIO_CH)]
fn dpdk_eal_init_virtio_cloud_hypervisor() {
    eprintln!("=== DPDK device lifecycle: cloud-hypervisor / virtio-net ===");

    let (eal, link) = init_dpdk_eal(&VIRTIO_CH);
    let started = setup_dpdk_device(&eal, &link, false).dev;

    eprintln!("=== DPDK device started ===");
    assert_within_budget("closing the device", time_device_teardown(started));
    assert_within_budget("dropping the EAL", time_eal_teardown(eal));
}

/// One ICMPv6 round-trip test per VM configuration.
///
/// `opt_in_1g:` rows require 1 GiB host pages and `--cfg host_hugepage_tests`.
macro_rules! rx_tests {
    (opt_in_1g: $($name:ident: $config:ident => $label:literal;)*) => {
        $(
            #[cfg_attr(
                not(host_hugepage_tests),
                ignore = "needs 1 GiB host pages; run with --cfg=host_hugepage_tests"
            )]
            #[n_vm::test(config = $config)]
            fn $name() {
                run_rx_test($label, &$config);
            }
        )*
    };
    ($($name:ident: $config:ident => $label:literal;)*) => {
        $(
            #[n_vm::test(config = $config)]
            fn $name() {
                run_rx_test($label, &$config);
            }
        )*
    };
}

rx_tests! {
    dpdk_rx_frame_virtio_cloud_hypervisor: VIRTIO_CH => "cloud-hypervisor / virtio-net / no-IOMMU (PA)";
    dpdk_rx_frame_virtio_qemu: VIRTIO_QEMU => "QEMU / virtio-net / no-IOMMU (PA)";
    dpdk_rx_frame_virtio_qemu_iommu: VIRTIO_QEMU_IOMMU => "QEMU / virtio-net / vIOMMU (VA)";
    dpdk_rx_frame_e1000_qemu_4k: E1000_QEMU => "QEMU / e1000 / no-IOMMU (PA) / host 4K pages";
    dpdk_rx_frame_e1000_qemu_iommu_4k: E1000_QEMU_IOMMU => "QEMU / e1000 / vIOMMU (VA) / host 4K pages";
    dpdk_rx_frame_e1000e_qemu_4k: E1000E_QEMU => "QEMU / e1000e / no-IOMMU (PA) / host 4K pages";
    dpdk_rx_frame_e1000e_qemu_iommu_4k: E1000E_QEMU_IOMMU => "QEMU / e1000e / vIOMMU (VA) / host 4K pages";
}

rx_tests! {
    opt_in_1g:
    dpdk_rx_frame_e1000_qemu: E1000_QEMU_1G => "QEMU / e1000 / no-IOMMU (PA)";
    dpdk_rx_frame_e1000_qemu_iommu: E1000_QEMU_IOMMU_1G => "QEMU / e1000 / vIOMMU (VA)";
    dpdk_rx_frame_e1000e_qemu: E1000E_QEMU_1G => "QEMU / e1000e / no-IOMMU (PA)";
    dpdk_rx_frame_e1000e_qemu_iommu: E1000E_QEMU_IOMMU_1G => "QEMU / e1000e / vIOMMU (VA)";
}

/// EAL teardown closes a leaked virtio-net device with queued mbufs.
#[n_vm::test(config = VIRTIO_CH)]
fn dpdk_leaked_device_teardown_virtio_cloud_hypervisor() {
    run_leaked_device_test("cloud-hypervisor / virtio-net / leaked device", &VIRTIO_CH);
}

/// EAL teardown closes a leaked e1000 device with queued mbufs.
#[n_vm::test(config = E1000_QEMU)]
fn dpdk_leaked_device_teardown_e1000_qemu() {
    run_leaked_device_test("QEMU / e1000 / leaked device", &E1000_QEMU);
}
