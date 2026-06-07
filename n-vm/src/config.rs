// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Shared VM configuration used by all hypervisor backends.

use std::net::Ipv6Addr;
use std::time::Duration;

use n_vm_protocol::{INIT_BINARY_PATH, VsockAllocation};
use tokio::io::AsyncReadExt;
use tracing::{error, warn};

/// VM acceleration mode.
///
/// Chosen at run time by the host tier: [`Kvm`](Self::Kvm) when the host
/// and guest architectures match, [`Tcg`](Self::Tcg) (software emulation)
/// for a cross-architecture guest.  Only the QEMU backend honours
/// [`Tcg`](Self::Tcg); cloud-hypervisor is KVM-only and is never selected
/// for a cross-arch guest.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Accel {
    /// Hardware-accelerated via KVM (host arch == guest arch).
    #[default]
    Kvm,
    /// Software emulation via TCG (cross-arch guest).
    Tcg,
}

impl Accel {
    /// The wire value used in the [`ENV_ACCEL`](n_vm_protocol::ENV_ACCEL)
    /// environment variable.
    #[must_use]
    pub const fn as_env(self) -> &'static str {
        match self {
            Self::Kvm => "kvm",
            Self::Tcg => "tcg",
        }
    }

    /// Parses an [`ENV_ACCEL`](n_vm_protocol::ENV_ACCEL) value, defaulting
    /// to [`Kvm`](Self::Kvm) for an absent or unrecognised value.
    #[must_use]
    pub fn from_env(value: Option<&str>) -> Self {
        match value {
            Some("tcg") => Self::Tcg,
            _ => Self::Kvm,
        }
    }
}

/// The per-ISA realization of a virtual IOMMU.
///
/// One object capturing every piece of "how a vIOMMU is wired up on this
/// architecture", so the pieces can't drift apart or be half-applied.
/// Returned by [`Arch::virtual_iommu`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VIommuLowering {
    /// QEMU `-device` string for the vIOMMU.  Emitted only when a test
    /// requests `iommu = true`.
    pub device: &'static str,
    /// Extra `-machine` options the vIOMMU requires (e.g. the x86 Intel
    /// IOMMU needs `kernel-irqchip=split` for interrupt remapping).
    /// Applied alongside the device; empty if none.
    pub machine_opts: &'static str,
    /// Guest kernel command-line parameters enabling IOMMU support.  These
    /// are emitted whenever the ISA *has* a vIOMMU (harmless without a
    /// device present), so one kernel serves both iommu and non-iommu
    /// tests.
    pub kernel_params: &'static str,
}

/// Guest CPU architecture.
///
/// Equal to the test binary's compile-time `target_arch` (the binary *is*
/// the guest payload, so its architecture is the guest's).  Selected at
/// run time via [`Arch::current`] so the arg builders can be unit-tested
/// for both architectures on a single host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    /// x86_64 (`q35` machine, `ttyS0` console, ISA pvpanic).
    X86_64,
    /// aarch64 (`virt` machine, `ttyAMA0` console, PCI pvpanic).
    Aarch64,
}

impl Arch {
    /// The architecture of the running test binary, i.e. the guest arch.
    ///
    /// Unrecognised architectures fall back to [`X86_64`](Self::X86_64);
    /// only x86_64 and aarch64 guests are supported.
    #[must_use]
    pub fn current() -> Self {
        match std::env::consts::ARCH {
            "aarch64" => Self::Aarch64,
            _ => Self::X86_64,
        }
    }

    /// Path to the `qemu-system-<arch>` binary inside the container.
    ///
    /// For a cross-arch guest this is a build-native (host-arch) emulator
    /// that the nix `testroot`/`vmroot` derivations install (step 4).
    #[must_use]
    pub const fn qemu_system_binary(self) -> &'static str {
        match self {
            Self::X86_64 => "/bin/qemu-system-x86_64",
            Self::Aarch64 => "/bin/qemu-system-aarch64",
        }
    }

    /// Path to the guest kernel image inside the container.
    ///
    /// x86_64 boots a `bzImage`; aarch64 boots a raw `Image`.
    #[must_use]
    pub const fn kernel_image_path(self) -> &'static str {
        match self {
            Self::X86_64 => "/bzImage",
            Self::Aarch64 => "/Image",
        }
    }

    /// The QEMU `-machine` base type (before accel / IOMMU options).
    #[must_use]
    pub const fn qemu_machine_base(self) -> &'static str {
        match self {
            Self::X86_64 => "q35",
            // `gic-version=max` selects the best interrupt controller the
            // accelerator supports (GICv3 under TCG).
            Self::Aarch64 => "virt,gic-version=max",
        }
    }

    /// QEMU `-smp` topology string preserving [`VM_VCPUS`] total vCPUs.
    ///
    /// The `dies=` level is x86-only; on aarch64 it is folded into `cores`.
    #[must_use]
    pub fn smp_topology(self) -> String {
        match self {
            Self::X86_64 => format!(
                "{VM_VCPUS},sockets={VM_SOCKETS},dies={VM_DIES_PER_PACKAGE},\
                 cores={VM_CORES_PER_DIE},threads={VM_THREADS_PER_CORE}",
            ),
            Self::Aarch64 => format!(
                "{VM_VCPUS},sockets={VM_SOCKETS},cores={cores},threads={VM_THREADS_PER_CORE}",
                cores = VM_DIES_PER_PACKAGE * VM_CORES_PER_DIE,
            ),
        }
    }

    /// QEMU guest-panic device for this architecture.
    #[must_use]
    pub const fn pvpanic_device(self) -> &'static str {
        match self {
            Self::X86_64 => "pvpanic",
            Self::Aarch64 => "pvpanic-pci",
        }
    }

    /// Kernel command-line console parameters for this architecture's
    /// default serial port.
    #[must_use]
    pub const fn console_kernel_params(self) -> &'static str {
        match self {
            Self::X86_64 => "earlyprintk=ttyS0 console=ttyS0",
            Self::Aarch64 => "earlycon console=ttyAMA0",
        }
    }

    /// The complete virtual-IOMMU lowering for this ISA, or `None` if no
    /// vIOMMU is wired up.
    ///
    /// This is the single source of truth for "how a virtual IOMMU is
    /// realized on this architecture" -- the QEMU device, the extra
    /// `-machine` options it needs, and the guest kernel parameters, as one
    /// object.  Adding a new ISA's vIOMMU (e.g. aarch64 SMMUv3) means
    /// filling in one [`VIommuLowering`] rather than touching several
    /// scattered methods.  `None` (currently aarch64) means an
    /// `iommu = true` request is resolved to a skip in the host tier rather
    /// than producing a wrong or partial config.
    #[must_use]
    pub const fn virtual_iommu(self) -> Option<VIommuLowering> {
        match self {
            Self::X86_64 => Some(VIommuLowering {
                device: "intel-iommu,intremap=on,device-iotlb=on,caching-mode=on",
                // Intel IOMMU interrupt remapping requires split irqchip.
                machine_opts: "kernel-irqchip=split",
                kernel_params: "iommu=on intel_iommu=on amd_iommu=on",
            }),
            Self::Aarch64 => None,
        }
    }

    /// Whether the virtual-IOMMU (`iommu = true`) configuration is
    /// supported on this architecture -- i.e. whether there is a
    /// [`virtual_iommu`](Self::virtual_iommu) lowering.
    #[must_use]
    pub const fn supports_virtual_iommu(self) -> bool {
        self.virtual_iommu().is_some()
    }
}

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
    arch: Arch,
) -> String {
    let vsock_cmdline = vsock.kernel_cmdline_fragment();

    // Without a vIOMMU, allow DPDK to bind devices via vfio-pci.
    let noiommu_fragment = if iommu {
        ""
    } else {
        "vfio.enable_unsafe_noiommu_mode=1 "
    };

    let hugepage_fragment = guest_hugepages.kernel_cmdline_fragment();

    // The IOMMU and console parameters are lowered per guest ISA
    // (x86 ttyS0 vs aarch64 ttyAMA0); `arch` is passed in explicitly so
    // this is testable for every ISA on any build host.  The IOMMU kernel
    // params come from the vIOMMU lowering and are present whenever the
    // ISA has one (empty otherwise) -- independent of the per-test flag.
    let iommu_params = arch.virtual_iommu().map_or("", |l| l.kernel_params);
    let console_params = arch.console_kernel_params();

    format!(
        "{iommu_params} \
         {noiommu_fragment}\
         {console_params} \
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

    // ── Arch profiles (both arches exercised on a single host) ───────

    #[test]
    fn virtual_iommu_lowering_is_coherent_per_arch() {
        // The point of folding the vIOMMU into one object: an ISA either
        // has a complete lowering (device + kernel params) or none -- the
        // pieces can't drift apart or be half-applied.
        for arch in [Arch::X86_64, Arch::Aarch64] {
            match arch.virtual_iommu() {
                Some(l) => {
                    assert!(
                        !l.device.is_empty(),
                        "{arch:?}: lowering must name a device"
                    );
                    assert!(
                        !l.kernel_params.is_empty(),
                        "{arch:?}: lowering must enable IOMMU in the guest kernel",
                    );
                    assert!(arch.supports_virtual_iommu());
                }
                None => assert!(!arch.supports_virtual_iommu()),
            }
        }
    }

    #[test]
    fn arch_x86_64_profile() {
        let a = Arch::X86_64;
        assert_eq!(a.qemu_system_binary(), "/bin/qemu-system-x86_64");
        assert_eq!(a.kernel_image_path(), "/bzImage");
        assert_eq!(a.qemu_machine_base(), "q35");
        assert_eq!(a.pvpanic_device(), "pvpanic");
        assert!(a.console_kernel_params().contains("ttyS0"));
        let viommu = a.virtual_iommu().expect("x86 has a vIOMMU lowering");
        assert!(viommu.device.starts_with("intel-iommu"));
        assert_eq!(viommu.machine_opts, "kernel-irqchip=split");
        assert!(viommu.kernel_params.contains("intel_iommu=on"));
        assert!(a.supports_virtual_iommu());
        assert!(a.smp_topology().contains("dies="));
    }

    #[test]
    fn arch_aarch64_profile() {
        let a = Arch::Aarch64;
        assert_eq!(a.qemu_system_binary(), "/bin/qemu-system-aarch64");
        assert_eq!(a.kernel_image_path(), "/Image");
        assert!(a.qemu_machine_base().starts_with("virt"));
        assert_eq!(a.pvpanic_device(), "pvpanic-pci");
        assert!(a.console_kernel_params().contains("ttyAMA0"));
        assert_eq!(a.virtual_iommu(), None);
        assert!(!a.supports_virtual_iommu());
        assert!(
            !a.smp_topology().contains("dies="),
            "aarch64 -smp must not use the x86-only dies= level: {}",
            a.smp_topology(),
        );
    }

    #[test]
    fn smp_topology_preserves_vcpu_count_on_both_arches() {
        for arch in [Arch::X86_64, Arch::Aarch64] {
            let smp = arch.smp_topology();
            assert!(
                smp.starts_with(&format!("{VM_VCPUS},")),
                "{arch:?} -smp must declare {VM_VCPUS} vCPUs: {smp}",
            );
            // sockets * (dies) * cores * threads == VM_VCPUS
            let product: u32 = smp
                .split(',')
                .skip(1)
                .filter_map(|kv| kv.split('=').nth(1))
                .filter_map(|v| v.parse::<u32>().ok())
                .product();
            assert_eq!(
                product, VM_VCPUS,
                "{arch:?} topology must multiply to {VM_VCPUS}: {smp}"
            );
        }
    }

    #[test]
    fn kernel_cmdline_includes_hugepage_reservation_for_1g() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let hp = GuestHugePageConfig::Allocate {
            size: GuestHugePageSize::Huge1G,
            count: 1,
        };
        let cmdline =
            build_kernel_cmdline("/test/bin", "my::test", &vsock, false, &hp, Arch::X86_64);
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
        let cmdline =
            build_kernel_cmdline("/test/bin", "my::test", &vsock, false, &hp, Arch::X86_64);
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
            Arch::X86_64,
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
        let cmdline = build_kernel_cmdline(
            "/test/bin",
            "my::test",
            &vsock,
            false,
            &DEFAULT_HP,
            Arch::X86_64,
        );
        assert!(
            cmdline.contains(&format!("init={INIT_BINARY_PATH}")),
            "cmdline should set init binary: {cmdline}",
        );
    }

    #[test]
    fn kernel_cmdline_passes_test_binary_and_name() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let cmdline = build_kernel_cmdline(
            "/test/bin",
            "my::test",
            &vsock,
            false,
            &DEFAULT_HP,
            Arch::X86_64,
        );
        assert!(
            cmdline.contains("-- /test/bin my::test --exact"),
            "cmdline should pass test binary and name after '--': {cmdline}",
        );
    }

    #[test]
    fn kernel_cmdline_includes_vsock_parameters() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let fragment = vsock.kernel_cmdline_fragment();
        let cmdline = build_kernel_cmdline(
            "/test/bin",
            "my::test",
            &vsock,
            false,
            &DEFAULT_HP,
            Arch::X86_64,
        );
        assert!(
            cmdline.contains(&fragment),
            "cmdline should contain vsock port parameters ({fragment}): {cmdline}",
        );
    }

    #[test]
    fn kernel_cmdline_enables_noiommu_mode_when_iommu_disabled() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let cmdline = build_kernel_cmdline(
            "/test/bin",
            "my::test",
            &vsock,
            false,
            &DEFAULT_HP,
            Arch::X86_64,
        );
        assert!(
            cmdline.contains("vfio.enable_unsafe_noiommu_mode=1"),
            "cmdline should enable no-IOMMU mode when iommu is disabled: {cmdline}",
        );
    }

    #[test]
    fn kernel_cmdline_omits_noiommu_mode_when_iommu_enabled() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let cmdline = build_kernel_cmdline(
            "/test/bin",
            "my::test",
            &vsock,
            true,
            &DEFAULT_HP,
            Arch::X86_64,
        );
        assert!(
            !cmdline.contains("noiommu"),
            "cmdline should NOT enable no-IOMMU mode when iommu is enabled: {cmdline}",
        );
    }

    #[test]
    fn kernel_cmdline_iommu_kernel_params_match_arch() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();

        // x86_64 always carries the Intel/AMD IOMMU kernel hints (whether or
        // not a vIOMMU device is present); aarch64 carries none.  Asserting
        // both ISAs here -- on a single build -- is the point of threading
        // `Arch` instead of reading `Arch::current()`.
        for iommu in [false, true] {
            let x86 = build_kernel_cmdline(
                "/test/bin",
                "my::test",
                &vsock,
                iommu,
                &DEFAULT_HP,
                Arch::X86_64,
            );
            assert!(x86.contains("intel_iommu=on"), "x86 (iommu={iommu}): {x86}");

            let arm = build_kernel_cmdline(
                "/test/bin",
                "my::test",
                &vsock,
                iommu,
                &DEFAULT_HP,
                Arch::Aarch64,
            );
            assert!(
                !arm.contains("intel_iommu"),
                "aarch64 must not carry x86 IOMMU kernel params (iommu={iommu}): {arm}",
            );
        }
    }

    #[test]
    fn kernel_cmdline_console_matches_arch() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let x86 = build_kernel_cmdline(
            "/test/bin",
            "my::test",
            &vsock,
            false,
            &DEFAULT_HP,
            Arch::X86_64,
        );
        assert!(x86.contains("console=ttyS0"), "x86: {x86}");

        let arm = build_kernel_cmdline(
            "/test/bin",
            "my::test",
            &vsock,
            false,
            &DEFAULT_HP,
            Arch::Aarch64,
        );
        assert!(arm.contains("console=ttyAMA0"), "aarch64: {arm}");
        assert!(!arm.contains("ttyS0"), "aarch64 must not use ttyS0: {arm}");
    }

    #[test]
    fn kernel_cmdline_uses_virtiofs_root() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let cmdline = build_kernel_cmdline(
            "/test/bin",
            "my::test",
            &vsock,
            false,
            &DEFAULT_HP,
            Arch::X86_64,
        );
        assert!(
            cmdline.contains("rootfstype=virtiofs"),
            "cmdline: {cmdline}",
        );
        assert!(cmdline.contains("root=root"), "cmdline: {cmdline}");
    }

    #[test]
    fn kernel_cmdline_passes_no_capture_and_terse_format() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let cmdline = build_kernel_cmdline(
            "/test/bin",
            "my::test",
            &vsock,
            false,
            &DEFAULT_HP,
            Arch::X86_64,
        );
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
