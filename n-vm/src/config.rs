// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Shared VM configuration used by all hypervisor backends.

use std::net::Ipv6Addr;
use std::time::Duration;

use n_vm_protocol::{INIT_BINARY_PATH, VsockAllocation};
use tokio::io::AsyncReadExt;
use tracing::{error, warn};

/// Network interface card model presented to the VM guest.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NicModel {
    /// Paravirtualised virtio-net (default).
    #[default]
    VirtioNet,

    /// Intel 82540EM Gigabit Ethernet (QEMU `e1000` device).
    E1000,

    /// Intel 82574L Gigabit Ethernet (QEMU `e1000e` device).
    E1000E,
}

impl NicModel {
    /// Returns `true` if this NIC model is virtio-based.
    #[must_use]
    pub const fn is_virtio(self) -> bool {
        matches!(self, Self::VirtioNet)
    }

    /// Returns `true` if this NIC model requires QEMU.
    #[must_use]
    pub const fn requires_qemu(self) -> bool {
        matches!(self, Self::E1000 | Self::E1000E)
    }
}

/// Page size used by the hypervisor to back VM memory on the host.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum HostPageSize {
    /// Standard 4 KiB pages.  No hugepage mount required on the host.
    Standard,
    /// 2 MiB huge pages.
    Huge2M,
    /// 1 GiB huge pages.
    #[default]
    Huge1G,
}

impl HostPageSize {
    /// Size in bytes of a single page at this page size.
    #[must_use]
    pub const fn bytes(self) -> i64 {
        match self {
            Self::Standard => 4 * 1024,
            Self::Huge2M => 2 * 1024 * 1024,
            Self::Huge1G => 1024 * 1024 * 1024,
        }
    }

    /// Whether this page size requires a hugetlbfs mount on the host.
    #[must_use]
    pub const fn requires_hugepages(self) -> bool {
        match self {
            Self::Standard => false,
            Self::Huge2M | Self::Huge1G => true,
        }
    }
}

/// Hugepage size for guest kernel command-line reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestHugePageSize {
    /// 2 MiB guest hugepages.
    Huge2M,
    /// 1 GiB guest hugepages.
    Huge1G,
}

impl GuestHugePageSize {
    /// The kernel command-line size suffix (e.g. `"2M"`, `"1G"`).
    #[must_use]
    pub const fn kernel_suffix(self) -> &'static str {
        match self {
            Self::Huge2M => "2M",
            Self::Huge1G => "1G",
        }
    }

    /// Size in bytes of a single hugepage at this granularity.
    #[must_use]
    pub const fn bytes(self) -> i64 {
        match self {
            Self::Huge2M => 2 * 1024 * 1024,
            Self::Huge1G => 1024 * 1024 * 1024,
        }
    }
}

/// Guest hugepage reservation passed on the kernel command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestHugePageConfig {
    /// No guest hugepages.  DPDK must use `--no-huge`.
    None,
    /// Reserve hugepages of the given size and count.
    Allocate {
        /// Hugepage granularity.
        size: GuestHugePageSize,
        /// Number of hugepages to reserve.
        count: u32,
    },
}

impl Default for GuestHugePageConfig {
    /// Returns one 1 GiB hugepage.
    fn default() -> Self {
        Self::Allocate {
            size: GuestHugePageSize::Huge1G,
            count: 1,
        }
    }
}

impl GuestHugePageConfig {
    /// Builds the kernel command-line fragment for hugepage reservation.
    pub(crate) fn kernel_cmdline_fragment(&self) -> String {
        match self {
            Self::None => String::new(),
            Self::Allocate { size, count } => {
                let sz = size.kernel_suffix();
                format!("default_hugepagesz={sz} hugepagesz={sz} hugepages={count} ")
            }
        }
    }
}

/// Complete VM configuration passed through the dispatch chain.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VmConfig {
    /// Whether to present a virtual IOMMU device to the guest.
    pub iommu: bool,
    /// Page size backing the VM's memory on the host.
    pub host_page_size: HostPageSize,
    /// Guest hugepage reservation for the kernel command line.
    pub guest_hugepages: GuestHugePageConfig,
    /// NIC model for all network interfaces in the VM.
    pub nic_model: NicModel,
}

impl VmConfig {
    /// Checks that the VM memory is properly aligned for the host page
    /// size and that guest hugepage reservations fit within VM memory.
    ///
    /// # Errors
    ///
    /// Returns a human-readable error string if validation fails.
    ///
    /// [`TestVm::launch`]: crate::vm::TestVm::launch
    pub fn validate_memory_alignment(&self) -> Result<(), String> {
        let page_bytes = self.host_page_size.bytes();
        if VM_MEMORY_BYTES % page_bytes != 0 {
            return Err(format!(
                "VM_MEMORY_BYTES ({VM_MEMORY_BYTES}) is not aligned to \
                 host page size ({page_bytes} bytes)",
            ));
        }
        if let GuestHugePageConfig::Allocate { size, count } = self.guest_hugepages {
            let required = size.bytes() * i64::from(count);
            if required > VM_MEMORY_BYTES {
                return Err(format!(
                    "guest hugepage reservation ({count} × {} = {required} bytes) \
                     exceeds VM memory ({VM_MEMORY_BYTES} bytes)",
                    size.bytes(),
                ));
            }
        }
        Ok(())
    }
}

/// Total guest memory in MiB (1 GiB).
pub(crate) const VM_MEMORY_MIB: u32 = 1024;

/// Total guest memory in bytes (1 GiB).
pub(crate) const VM_MEMORY_BYTES: i64 = (VM_MEMORY_MIB as i64) * 1024 * 1024;

// The topology must satisfy:
//   VM_SOCKETS × VM_DIES_PER_PACKAGE × VM_CORES_PER_DIE × VM_THREADS_PER_CORE == VM_VCPUS

/// Number of vCPUs.
pub(crate) const VM_VCPUS: u32 = 6;

/// Threads per core in the CPU topology.
pub(crate) const VM_THREADS_PER_CORE: u32 = 2;

/// Cores per die in the CPU topology.
pub(crate) const VM_CORES_PER_DIE: u32 = 1;

/// Dies per package (socket) in the CPU topology.
pub(crate) const VM_DIES_PER_PACKAGE: u32 = 3;

/// Number of sockets in the CPU topology.
pub(crate) const VM_SOCKETS: u32 = 1;

/// Describes a network interface shared across all hypervisor backends.
pub(crate) struct NetIface {
    /// Unique identifier used in device configuration (e.g. `"mgmt"`,
    /// `"fabric1"`).
    pub id: &'static str,
    /// TAP device name on the host.
    pub tap: &'static str,
    /// MAC address in `XX:XX:XX:XX:XX:XX` format.
    pub mac: &'static str,
    /// IPv6 link-local address assigned to the host-side TAP.
    pub host_ipv6: Ipv6Addr,
}

/// The management network interface (standard Ethernet).
pub(crate) const IFACE_MGMT: NetIface = NetIface {
    id: "mgmt",
    tap: "mgmt",
    mac: "02:DE:AD:BE:EF:01",
    host_ipv6: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0xffff, 1),
};

/// First fabric-facing network interface (jumbo frames).
pub(crate) const IFACE_FABRIC1: NetIface = NetIface {
    id: "fabric1",
    tap: "fabric1",
    mac: "02:CA:FE:BA:BE:01",
    host_ipv6: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
};

/// Second fabric-facing network interface (jumbo frames).
pub(crate) const IFACE_FABRIC2: NetIface = NetIface {
    id: "fabric2",
    tap: "fabric2",
    mac: "02:CA:FE:BA:BE:02",
    host_ipv6: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
};

/// All network interfaces in the order they are presented to the VM.
pub(crate) const ALL_IFACES: [&NetIface; 3] = [&IFACE_MGMT, &IFACE_FABRIC1, &IFACE_FABRIC2];

/// IPv6 prefix length for host-side TAP addresses (link-local /64).
pub(crate) const TAP_IPV6_PREFIX_LEN: u8 = 64;

/// MTU for the management network interface (standard Ethernet).
pub(crate) const MGMT_MTU: i32 = 1500;

/// MTU for fabric-facing network interfaces (jumbo frames).
pub(crate) const FABRIC_MTU: i32 = 9500;

/// Virtio queue depth for the management network interface.
pub(crate) const MGMT_QUEUE_SIZE: i32 = 512;

/// Virtio queue depth for fabric-facing network interfaces.
pub(crate) const FABRIC_QUEUE_SIZE: i32 = 8192;

/// Virtio queue depth for the virtiofs filesystem device.
pub(crate) const VIRTIOFS_QUEUE_SIZE: u32 = 1024;

/// Initial buffer capacity for vsock reader tasks.
pub(crate) const VSOCK_READER_CAPACITY: usize = 32_768;

/// Duration to continue draining hypervisor events after a guest panic
/// is detected.
pub(crate) const POST_PANIC_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);

/// Builds the guest kernel command line.
pub(crate) fn build_kernel_cmdline(
    vm_bin_path: &str,
    test_name: &str,
    vsock: &VsockAllocation,
    iommu: bool,
    guest_hugepages: &GuestHugePageConfig,
) -> String {
    let vsock_cmdline = vsock.kernel_cmdline_fragment();

    // Without a vIOMMU, allow DPDK to bind devices via vfio-pci.
    let noiommu_fragment = if iommu {
        ""
    } else {
        "vfio.enable_unsafe_noiommu_mode=1 "
    };

    let hugepage_fragment = guest_hugepages.kernel_cmdline_fragment();

    format!(
        "iommu=on \
         intel_iommu=on \
         amd_iommu=on \
         {noiommu_fragment}\
         earlyprintk=ttyS0 \
         console=ttyS0 \
         ro \
         rootfstype=virtiofs \
         root=root \
         {hugepage_fragment}\
         {vsock_cmdline} \
         init={INIT_BINARY_PATH} \
         -- {vm_bin_path} {test_name} --exact --no-capture --format=terse",
    )
}

/// Reads an async byte stream to EOF and returns its contents as a
/// UTF-8 string.
pub(crate) async fn read_vsock_stream(
    mut stream: impl tokio::io::AsyncRead + Unpin,
    label: &str,
) -> String {
    let mut buf = Vec::with_capacity(VSOCK_READER_CAPACITY);
    loop {
        match stream.read_buf(&mut buf).await {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                error!("error reading {label} vsock stream: {e}");
                break;
            }
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Best-effort capture of a child process's stderr, logged at
/// appropriate levels.
pub(crate) async fn drain_child_stderr(child: &mut tokio::process::Child, label: &str) {
    // Give the child a moment to flush its output.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let Some(mut stderr) = child.stderr.take() else {
        return;
    };

    let mut buf = String::with_capacity(4096);
    match tokio::time::timeout(Duration::from_secs(2), stderr.read_to_string(&mut buf)).await {
        Ok(Ok(_)) if !buf.is_empty() => {
            error!("{label} stderr (captured after launch failure):\n{buf}");
        }
        Ok(Ok(_)) => {
            warn!("{label} stderr was empty after launch failure");
        }
        Ok(Err(e)) => {
            warn!("failed to read {label} stderr: {e}");
        }
        Err(_) => {
            warn!("timed out reading {label} stderr");
            if !buf.is_empty() {
                error!("{label} stderr (partial, timed out):\n{buf}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT_HP: GuestHugePageConfig = GuestHugePageConfig::Allocate {
        size: GuestHugePageSize::Huge1G,
        count: 1,
    };

    #[test]
    fn kernel_cmdline_includes_hugepage_reservation_for_1g() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let hp = GuestHugePageConfig::Allocate {
            size: GuestHugePageSize::Huge1G,
            count: 1,
        };
        let cmdline = build_kernel_cmdline("/test/bin", "my::test", &vsock, false, &hp);
        assert!(
            cmdline.contains("hugepages=1"),
            "cmdline should configure hugepage count: {cmdline}",
        );
        assert!(
            cmdline.contains("hugepagesz=1G"),
            "cmdline should configure hugepage size: {cmdline}",
        );
        assert!(
            cmdline.contains("default_hugepagesz=1G"),
            "cmdline should set default hugepage size: {cmdline}",
        );
    }

    #[test]
    fn kernel_cmdline_includes_hugepage_reservation_for_2m() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let hp = GuestHugePageConfig::Allocate {
            size: GuestHugePageSize::Huge2M,
            count: 512,
        };
        let cmdline = build_kernel_cmdline("/test/bin", "my::test", &vsock, false, &hp);
        assert!(
            cmdline.contains("hugepages=512"),
            "cmdline should configure hugepage count: {cmdline}",
        );
        assert!(
            cmdline.contains("hugepagesz=2M"),
            "cmdline should configure 2M hugepage size: {cmdline}",
        );
        assert!(
            cmdline.contains("default_hugepagesz=2M"),
            "cmdline should set default hugepage size: {cmdline}",
        );
    }

    #[test]
    fn kernel_cmdline_omits_hugepages_when_none() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let cmdline = build_kernel_cmdline(
            "/test/bin",
            "my::test",
            &vsock,
            false,
            &GuestHugePageConfig::None,
        );
        assert!(
            !cmdline.contains("hugepagesz"),
            "cmdline should not contain hugepagesz: {cmdline}",
        );
        assert!(
            !cmdline.contains("default_hugepagesz"),
            "cmdline should not contain default_hugepagesz: {cmdline}",
        );
    }

    #[test]
    fn kernel_cmdline_includes_init_binary() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let cmdline = build_kernel_cmdline("/test/bin", "my::test", &vsock, false, &DEFAULT_HP);
        assert!(
            cmdline.contains(&format!("init={INIT_BINARY_PATH}")),
            "cmdline should set init binary: {cmdline}",
        );
    }

    #[test]
    fn kernel_cmdline_passes_test_binary_and_name() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let cmdline = build_kernel_cmdline("/test/bin", "my::test", &vsock, false, &DEFAULT_HP);
        assert!(
            cmdline.contains("-- /test/bin my::test --exact"),
            "cmdline should pass test binary and name after '--': {cmdline}",
        );
    }

    #[test]
    fn kernel_cmdline_includes_vsock_parameters() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let fragment = vsock.kernel_cmdline_fragment();
        let cmdline = build_kernel_cmdline("/test/bin", "my::test", &vsock, false, &DEFAULT_HP);
        assert!(
            cmdline.contains(&fragment),
            "cmdline should contain vsock port parameters ({fragment}): {cmdline}",
        );
    }

    #[test]
    fn kernel_cmdline_enables_noiommu_mode_when_iommu_disabled() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let cmdline = build_kernel_cmdline("/test/bin", "my::test", &vsock, false, &DEFAULT_HP);
        assert!(
            cmdline.contains("vfio.enable_unsafe_noiommu_mode=1"),
            "cmdline should enable no-IOMMU mode when iommu is disabled: {cmdline}",
        );
    }

    #[test]
    fn kernel_cmdline_omits_noiommu_mode_when_iommu_enabled() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let cmdline = build_kernel_cmdline("/test/bin", "my::test", &vsock, true, &DEFAULT_HP);
        assert!(
            !cmdline.contains("noiommu"),
            "cmdline should NOT enable no-IOMMU mode when iommu is enabled: {cmdline}",
        );
    }

    #[test]
    fn kernel_cmdline_enables_iommu_kernel_support_always() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();

        for iommu in [false, true] {
            let cmdline = build_kernel_cmdline("/test/bin", "my::test", &vsock, iommu, &DEFAULT_HP);
            assert!(
                cmdline.contains("iommu=on"),
                "cmdline should always enable iommu (iommu={iommu}): {cmdline}",
            );
            assert!(
                cmdline.contains("intel_iommu=on"),
                "cmdline should always enable intel_iommu (iommu={iommu}): {cmdline}",
            );
            assert!(
                cmdline.contains("amd_iommu=on"),
                "cmdline should always enable amd_iommu (iommu={iommu}): {cmdline}",
            );
        }
    }

    #[test]
    fn kernel_cmdline_configures_serial_console() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let cmdline = build_kernel_cmdline("/test/bin", "my::test", &vsock, false, &DEFAULT_HP);
        assert!(cmdline.contains("console=ttyS0"), "cmdline: {cmdline}",);
        assert!(cmdline.contains("earlyprintk=ttyS0"), "cmdline: {cmdline}",);
    }

    #[test]
    fn kernel_cmdline_uses_virtiofs_root() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let cmdline = build_kernel_cmdline("/test/bin", "my::test", &vsock, false, &DEFAULT_HP);
        assert!(
            cmdline.contains("rootfstype=virtiofs"),
            "cmdline: {cmdline}",
        );
        assert!(cmdline.contains("root=root"), "cmdline: {cmdline}");
    }

    #[test]
    fn kernel_cmdline_passes_no_capture_and_terse_format() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let cmdline = build_kernel_cmdline("/test/bin", "my::test", &vsock, false, &DEFAULT_HP);
        assert!(
            cmdline.contains("--no-capture"),
            "cmdline should pass --no-capture: {cmdline}",
        );
        assert!(
            cmdline.contains("--format=terse"),
            "cmdline should pass --format=terse: {cmdline}",
        );
    }

    #[test]
    fn all_interfaces_have_unique_mac_addresses() {
        let macs: Vec<&str> = ALL_IFACES.iter().map(|i| i.mac).collect();
        let mut deduped = macs.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(
            macs.len(),
            deduped.len(),
            "MAC addresses must be unique: {macs:?}",
        );
    }

    #[test]
    fn all_interfaces_have_unique_tap_names() {
        let taps: Vec<&str> = ALL_IFACES.iter().map(|i| i.tap).collect();
        let mut deduped = taps.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(
            taps.len(),
            deduped.len(),
            "TAP names must be unique: {taps:?}",
        );
    }

    #[test]
    fn all_interfaces_have_unique_ids() {
        let ids: Vec<&str> = ALL_IFACES.iter().map(|i| i.id).collect();
        let mut deduped = ids.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(
            ids.len(),
            deduped.len(),
            "interface IDs must be unique: {ids:?}",
        );
    }

    #[test]
    fn interface_count_is_three() {
        assert_eq!(
            ALL_IFACES.len(),
            3,
            "expected exactly 3 interfaces (mgmt + 2 fabric)",
        );
    }

    #[test]
    fn topology_multiplies_to_vcpu_count() {
        let total = VM_SOCKETS * VM_DIES_PER_PACKAGE * VM_CORES_PER_DIE * VM_THREADS_PER_CORE;
        assert_eq!(
            total, VM_VCPUS,
            "topology ({VM_SOCKETS}S × {VM_DIES_PER_PACKAGE}D × \
             {VM_CORES_PER_DIE}C × {VM_THREADS_PER_CORE}T = {total}) \
             must equal VM_VCPUS ({VM_VCPUS})",
        );
    }

    #[test]
    fn default_config_passes_memory_alignment_validation() {
        VmConfig::default()
            .validate_memory_alignment()
            .expect("default VmConfig should pass memory alignment validation");
    }

    #[test]
    fn all_host_page_sizes_are_memory_aligned() {
        for host_page_size in [
            HostPageSize::Standard,
            HostPageSize::Huge2M,
            HostPageSize::Huge1G,
        ] {
            let config = VmConfig {
                host_page_size,
                ..VmConfig::default()
            };
            config
                .validate_memory_alignment()
                .unwrap_or_else(|e| panic!("{host_page_size:?}: {e}"));
        }
    }

    #[test]
    fn guest_hugepages_exceeding_memory_fails_validation() {
        let config = VmConfig {
            guest_hugepages: GuestHugePageConfig::Allocate {
                size: GuestHugePageSize::Huge1G,
                count: 100,
            },
            ..VmConfig::default()
        };
        assert!(
            config.validate_memory_alignment().is_err(),
            "100 × 1G hugepages should exceed VM memory",
        );
    }

    #[test]
    fn guest_hugepages_none_passes_validation() {
        let config = VmConfig {
            guest_hugepages: GuestHugePageConfig::None,
            ..VmConfig::default()
        };
        config
            .validate_memory_alignment()
            .expect("GuestHugePageConfig::None should always pass validation");
    }

    #[test]
    fn memory_mib_and_bytes_are_consistent() {
        assert_eq!(
            VM_MEMORY_BYTES,
            (VM_MEMORY_MIB as i64) * 1024 * 1024,
            "VM_MEMORY_BYTES and VM_MEMORY_MIB must be consistent",
        );
    }
}
