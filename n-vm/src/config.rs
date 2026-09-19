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
    /// QEMU `-device` string for the vIOMMU, if it is realized as a device.
    /// `None` when the vIOMMU is a `-machine` option instead (aarch64's
    /// SMMUv3 is `-machine iommu=smmuv3`, not a device).  Emitted only when
    /// a test requests `iommu = true`.
    pub device: Option<&'static str>,
    /// Extra `-machine` options the vIOMMU requires: the x86 Intel IOMMU
    /// needs `kernel-irqchip=split` for interrupt remapping; the aarch64
    /// SMMUv3 *is* `iommu=smmuv3`.  Applied alongside the device; empty if
    /// none.
    pub machine_opts: &'static str,
    /// Guest kernel command-line parameters enabling IOMMU support.  These
    /// are emitted whenever the ISA *has* a vIOMMU (harmless without a
    /// device present), so one kernel serves both iommu and non-iommu
    /// tests.  Empty when the IOMMU is auto-probed (the arm64 SMMUv3 is
    /// described in the device tree and needs no command-line opt-in).
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

    /// This architecture's name as spelled in the kernel manifest.
    ///
    /// The guest kernel image is *not* derived from the architecture any
    /// more -- it is looked up in the manifest nix writes into `testroot`
    /// (see [`kernel_manifest`](crate::kernel_manifest)), because which
    /// kernels exist is a fact about the nix build.  This is what lets the
    /// manifest's claimed architecture be checked against the guest's.
    #[must_use]
    pub const fn manifest_name(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
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

    /// QEMU `-smp` topology string for `vcpus` total vCPUs.
    ///
    /// The `dies=` level is x86-only; on aarch64 it is folded into `cores`.
    #[must_use]
    pub fn smp_topology(self, vcpus: u32) -> String {
        let t = SmpTopology::for_vcpus(vcpus);
        match self {
            Self::X86_64 => format!(
                "{vcpus},sockets={sockets},dies={dies},cores={cores},threads={threads}",
                sockets = t.sockets,
                dies = t.dies,
                cores = t.cores,
                threads = t.threads,
            ),
            Self::Aarch64 => format!(
                "{vcpus},sockets={sockets},cores={cores},threads={threads}",
                sockets = t.sockets,
                cores = t.dies * t.cores,
                threads = t.threads,
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
                device: Some("intel-iommu,intremap=on,device-iotlb=on,caching-mode=on"),
                // Intel IOMMU interrupt remapping requires split irqchip.
                machine_opts: "kernel-irqchip=split",
                kernel_params: "iommu=on intel_iommu=on amd_iommu=on",
            }),
            // aarch64: QEMU's `virt` SMMUv3 is a machine option, not a
            // device, and is auto-probed from the device tree (no kernel
            // command-line opt-in).  Validated under TCG: PCI devices
            // (incl. e1000) land in IOMMU groups, so vfio-pci works.
            Self::Aarch64 => Some(VIommuLowering {
                device: None,
                machine_opts: "iommu=smmuv3",
                kernel_params: "",
            }),
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

    /// Whether this page size draws from a hugepage pool.
    ///
    /// Renamed in spirit from "requires a hugetlbfs mount": neither backend
    /// mounts anything any more.  Both allocate through `memfd` with the
    /// `MFD_HUGE_*` flags, which draws straight from the kernel's pool for
    /// that size.
    #[must_use]
    pub const fn requires_hugepages(self) -> bool {
        match self {
            Self::Standard => false,
            Self::Huge2M | Self::Huge1G => true,
        }
    }

    /// QEMU's `hugetlbsize=` spelling for this page size.
    ///
    /// Needed because QEMU's `memory-backend-memfd` takes the size as an
    /// option, unlike `memory-backend-file`, which infers it from whatever
    /// the mount happens to be -- see [`Self::pool_dir`].
    #[must_use]
    pub const fn qemu_hugetlbsize(self) -> &'static str {
        match self {
            // Not reachable for a non-huge page size, which uses a plain
            // memfd with no `hugetlb=on`.
            Self::Standard => "",
            Self::Huge2M => "2M",
            Self::Huge1G => "1G",
        }
    }

    /// The sysfs directory for this size's hugepage pool.
    ///
    /// `None` for [`Standard`](Self::Standard), which has no pool.
    ///
    /// This is what a pre-flight check should look at.  The previous check
    /// tested whether `/dev/hugepages` *existed*, which passed happily while
    /// the pool it stands for was empty -- and an empty pool is exactly the
    /// failure it was meant to catch.
    #[must_use]
    pub const fn pool_dir(self) -> Option<&'static str> {
        match self {
            Self::Standard => None,
            Self::Huge2M => Some("/sys/kernel/mm/hugepages/hugepages-2048kB"),
            Self::Huge1G => Some("/sys/kernel/mm/hugepages/hugepages-1048576kB"),
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
    /// Let the harness decide, from what the test is for.
    ///
    /// A reservation is memory the guest kernel hands to hugetlbfs and can
    /// never hand back, so it is only worth taking when something is going
    /// to claim it.  The two roles want opposite answers:
    ///
    /// * an ordinary guest test gets [`DEFAULT_RESERVATION`], because the
    ///   thing these VMs mostly exist to run is DPDK, and DPDK without
    ///   hugepages is a different program;
    /// * a fuzz target gets [`None`], because a coverage-guided engine
    ///   claims ordinary heap and nothing else.  Reserving for it is
    ///   strictly a subtraction: it halved the usable memory of a 1 GiB
    ///   guest, and the engine's own `-rss_limit_mb` was left describing
    ///   memory the kernel had already given away.
    ///
    /// This is a default, not a rule.  Naming either variant explicitly
    /// wins, including on a fuzz target -- fuzzing a hugepage-dependent path
    /// is a coherent thing to want.
    ///
    /// [`DEFAULT_RESERVATION`]: Self::DEFAULT_RESERVATION
    /// [`None`]: Self::None
    Auto,
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
    /// Returns [`Auto`](Self::Auto): defer, rather than guess in the dark.
    ///
    /// This used to return one 1 GiB page while [`VmConfig::DEFAULT`] used
    /// 256 2 MiB pages -- two "defaults" that had already drifted apart
    /// because nothing forced them to agree.  Deferring is the only answer
    /// that cannot drift.
    fn default() -> Self {
        Self::Auto
    }
}

impl Default for VmConfig {
    /// Delegates to [`VmConfig::DEFAULT`].
    ///
    /// Written out rather than derived so the const and the trait cannot
    /// drift: a derived `Default` would independently consult each field's
    /// own `Default`, and nothing would notice if the two answers diverged.
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl GuestHugePageConfig {
    /// What [`Auto`](Self::Auto) means for a test that is not a fuzz target.
    ///
    /// 512 MiB of a 1 GiB guest, in 2 MiB pages.  Small enough to leave the
    /// guest kernel room (see [`VmConfig::check`]), and 2 MiB rather than
    /// 1 GiB because a guest cannot count on being handed a contiguous
    /// gigabyte.
    pub const DEFAULT_RESERVATION: Self = Self::Allocate {
        size: GuestHugePageSize::Huge2M,
        count: 256,
    };

    /// Builds the kernel command-line fragment for hugepage reservation.
    ///
    /// Call this on a *resolved* reservation --
    /// [`VmConfig::hugepage_reservation`] -- never on the raw field.
    /// [`Auto`](Self::Auto) is a request to decide, and this type does not
    /// hold what the decision is made from.
    pub(crate) fn kernel_cmdline_fragment(&self) -> String {
        match self {
            Self::Auto => unreachable!(
                "Auto must be resolved by VmConfig::hugepage_reservation before rendering"
            ),
            Self::None => String::new(),
            Self::Allocate { size, count } => {
                let sz = size.kernel_suffix();
                format!("default_hugepagesz={sz} hugepagesz={sz} hugepages={count} ")
            }
        }
    }
}

/// A kernel module parameter, set on the guest command line as
/// `<module>.<key>=<value>`.
///
/// Structured rather than a free-form command-line string on purpose. The
/// kernel command line is a flat namespace in which `root=`, `init=` and
/// `n_it.result_port=` sit beside module parameters, and a test that
/// overwrote one of those would not report an error -- it would hang, or
/// boot a guest whose init protocol had been quietly redirected. A value of
/// this type can only ever render as a module parameter, so the only thing
/// left to guard is the module name.
///
/// Everything this checks is checked in [`new`](Self::new), which is `const`,
/// so a malformed parameter is a build error rather than a console line forty
/// lines into a boot dump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleParam {
    module: &'static str,
    key: &'static str,
    value: &'static str,
}

/// Whether `s` is a legal module or parameter name.
///
/// Kernel module and parameter names are C identifiers, with `-` also
/// appearing in module names (`vfio-pci`). Anything else -- a `.`, an `=`, a
/// space -- would change where the kernel splits the token, so it is rejected
/// rather than escaped.
const fn is_module_ident(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        let ok = c.is_ascii_alphanumeric() || c == b'_' || c == b'-';
        if !ok {
            return false;
        }
        i += 1;
    }
    true
}

/// Whether `s` can appear as a command-line value.
///
/// The command line is split on whitespace, so a value containing any would
/// silently become two parameters.
const fn is_cmdline_value(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            return false;
        }
        i += 1;
    }
    true
}

/// `const`-callable string equality; `PartialEq` is not `const`.
const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

impl ModuleParam {
    /// Declares `<module>.<key>=<value>` on the guest kernel command line.
    ///
    /// # Panics
    ///
    /// Panics if `module` or `key` is not a legal identifier, if `value` is
    /// empty or contains whitespace, or if `module` is the namespace `n-it`
    /// reads its own parameters from.  In a `const` context each panic *is*
    /// the compile error.
    #[must_use]
    pub const fn new(module: &'static str, key: &'static str, value: &'static str) -> Self {
        assert!(
            is_module_ident(module),
            "a module name must be a kernel module identifier: letters, digits, `_` or `-`"
        );
        assert!(
            is_module_ident(key),
            "a module parameter name must be an identifier: letters, digits, `_` or `-`"
        );
        assert!(
            is_cmdline_value(value),
            "a module parameter value must be non-empty and contain no whitespace; \
             the kernel command line is split on whitespace, so one that does \
             would silently become two parameters"
        );
        assert!(
            !str_eq(module, n_vm_protocol::CMDLINE_NAMESPACE),
            "that module name is the namespace `n-it` reads its own boot parameters from; \
             setting it would redirect the guest's init protocol rather than configure a module"
        );
        Self { module, key, value }
    }

    /// Renders as it appears on the kernel command line.
    #[must_use]
    pub fn render(&self) -> String {
        format!("{}.{}={}", self.module, self.key, self.value)
    }
}

/// Complete VM configuration passed through the dispatch chain.
///
/// Written at the call site as a `const`, so that a test's configuration is
/// ordinary Rust in an ordinary position -- completion, hover, and
/// go-to-definition all work on it, which is not true of anything spelled
/// inside an attribute:
///
/// ```ignore
/// const FAST_VM: VmConfig = VmConfig { iommu: true, ..VmConfig::DEFAULT };
///
/// #[n_vm::test(config = FAST_VM)]
/// fn my_test() { ... }
/// ```
///
/// Being `const` also means [`assert_valid`](Self::assert_valid) can run at
/// compile time, turning what were runtime launch failures into build
/// errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmConfig {
    /// Whether to present a virtual IOMMU device to the guest.
    pub iommu: bool,
    /// Page size backing the VM's memory on the host.
    pub host_page_size: HostPageSize,
    /// Guest hugepage reservation for the kernel command line.
    ///
    /// A *request*, which [`GuestHugePageConfig::Auto`] leaves open; read
    /// [`hugepage_reservation`](Self::hugepage_reservation) for the answer.
    pub guest_hugepages: GuestHugePageConfig,
    /// NIC model for the management interface, and for fabric links that
    /// do not name their own.
    ///
    /// A [`FabricNics::Mixed`] fabric names each of its links, and this is
    /// then the management link's model alone -- which is the one a test
    /// of device identification wants held fixed, since it is how the
    /// harness reaches the guest.
    pub nic_model: NicModel,
    /// Kernel features this test depends on.
    ///
    /// Checked against the kernel's own config before launch, so a missing
    /// feature is reported by name rather than surfacing as whatever it
    /// breaks deep inside the test body.  See
    /// [`kernel_feature`](crate::kernel_feature) for why these are verified
    /// rather than used to generate the kernel's config.
    ///
    /// ```ignore
    /// const TC_VM: VmConfig = VmConfig {
    ///     kernel_features: &[features::NET_CLS_FLOWER, features::NET_CLS_ACT],
    ///     ..VmConfig::DEFAULT
    /// };
    /// ```
    pub kernel_features: &'static [crate::kernel_feature::KernelFeature],
    /// The hypervisor the test asked for.
    ///
    /// Part of the machine rather than of the attribute that declares the
    /// test, so that "the same VM on both backends" is written as two
    /// configurations -- which is what it is.  Derive the second from the
    /// first with [`to_builder`](Self::to_builder).
    pub backend: crate::backend::RequestedBackend,
    /// The tokio runtime an `async` body is driven on in the guest.
    ///
    /// Ignored by a synchronous test, which has no runtime to shape.
    pub runtime: GuestRuntime,
    /// How long the test body may take, before the VM's own overhead.
    ///
    /// The VM is given this *plus* room to boot, load a corpus and shut down
    /// -- the container cannot hold exactly what it contains, or the guest is
    /// killed somewhere inside its last second and whatever it was about to
    /// report is lost.
    ///
    /// `None` means the body gets the same allowance an ordinary test does,
    /// which is what nearly every test wants.  Set it for work that is
    /// deliberately long-lived: a fuzz campaign's length arrives separately,
    /// from the engine, and the larger of the two wins.
    pub guest_time_limit: Option<Duration>,
    /// Kernel module parameters to set on the guest command line.
    ///
    /// Rendered as `<module>.<key>=<value>` into the kernel section of the
    /// command line.  A module does not have to be built in for this to
    /// apply: the kernel stores parameters for modules that are not loaded
    /// yet and applies them at load time, so this composes with a
    /// [`KernelFeature`](crate::kernel_feature::KernelFeature) declared
    /// `modular`.
    pub module_params: &'static [ModuleParam],
    /// The kernel profile to boot, by name.
    ///
    /// A profile is a *(kernel, hypervisor)* pair from the manifest nix
    /// materialises into `testroot` -- `flatcar` is a distribution kernel
    /// with its own module tree booted through an initramfs, `qemu` and
    /// `cloud_hypervisor` are the union kernel this repo builds and boots
    /// directly.  See [`crate::kernel_feature::kernel_profiles`] for the names.
    ///
    /// `None` leaves the choice to the run: `N_VM_PROFILE` if it is set,
    /// otherwise the manifest's default.  Naming one here outranks both,
    /// because a test that says which kernel it needs is saying what it is
    /// *for* -- a module-loading test that got swept onto a
    /// built-in-only kernel by an environment variable would not be
    /// testing anything.
    ///
    /// Because a profile names a hypervisor, this can contradict
    /// [`backend`](Self::backend).  That cannot be checked here -- which
    /// hypervisor a profile uses is in a file, not in this type -- so it is
    /// caught at launch, by name, rather than silently booting one of them.
    pub kernel_profile: Option<&'static str>,
    /// Number of fabric-facing network interfaces.
    ///
    /// The management interface is always present and is not counted here,
    /// so the default of 2 gives the three the VM has always had.
    ///
    /// Raise it to test what only more than one link can show -- failover,
    /// ECMP, a bond losing a member.  Lower it to nothing for a test that
    /// never touches the network: each interface is a TAP device, a virtio
    /// device and a queue pair, all of which are set up before the guest
    /// starts running.
    ///
    /// [`FabricNics::Mixed`] names a model per link instead of a count.
    /// That is what a test of the startup sequence wants: the failure it
    /// is looking for is a program that unbinds a device it did not mean
    /// to, and on a machine where every NIC is the same device there is no
    /// wrong one to pick.
    pub fabric: FabricNics,
    /// Total guest memory, in MiB.
    ///
    /// A whole number of [`host_page_size`](Self::host_page_size) pages, or
    /// the VM cannot be backed at all -- see [`ConfigProblem::MemoryNotAligned`].
    ///
    /// Raise it for work that needs room: a fuzz engine's `-rss_limit_mb`
    /// is derived from this by [`fuzz_rss_limit_mib`](Self::fuzz_rss_limit_mib),
    /// and the default gigabyte is a tight fit for a coverage-guided
    /// campaign.  Every MiB is taken from the host
    /// for the VM's whole life, so this is also what bounds how many VMs
    /// can run at once.
    pub memory_mib: u32,
    /// Number of vCPUs.
    ///
    /// Arranged into a socket/die/core/thread topology by
    /// `SmpTopology::for_vcpus`, which is what both hypervisors actually
    /// want.  Like [`memory_mib`](Self::memory_mib) this bounds
    /// concurrency: vCPUs, not memory, is what usually limits how many of
    /// these VMs a host can run.
    pub vcpus: u32,
    /// What writable storage this test gets, and whether it is a fuzz
    /// target.  See [`CorpusPolicy`].
    pub corpus: CorpusPolicy,
    /// The test's own `(file!(), CARGO_MANIFEST_DIR)`, injected by the
    /// attribute macro; `None` on a configuration built by hand.
    ///
    /// Carried as raw compile-time strings rather than a pre-computed
    /// directory so that both tiers derive the path identically from one
    /// constant.
    ///
    /// Both are needed because `file!()` alone is not reliably
    /// workspace-relative.  It is relative under a plain `cargo test`, but
    /// this workspace builds with `--remap-path-prefix==${src}`
    /// (default.nix), an empty-FROM mapping that deliberately rewrites
    /// source paths *to* the nix store so debuggers can find them.  Under
    /// that flag `file!()` is `/nix/store/<hash>-source/n-vm/tests/foo.rs`,
    /// and treating it as relative produced a corpus path of
    /// `/workspace//nix/store/...` in the guest and a host path that escaped
    /// the workspace entirely -- so `#[corpus]` silently got no writable
    /// directory.  The manifest dir supplies the anchor needed to recover
    /// the workspace-relative tail; see [`Self::corpus_rel_dir`].
    pub source_file: Option<(&'static str, &'static str)>,
}

/// What writable storage a test is given, and whether it is a fuzz target.
///
/// One value rather than a `bool` because the two things it decides are the
/// same decision: a coverage-guided target is exactly the thing that needs
/// somewhere to save an input, and `cargo bolero list` exists to name the
/// things that can be fuzzed.  Splitting them would let a test be announced
/// with nowhere to write, or given a writable share it never uses.
///
/// An enum rather than a `bool` for the usual reason -- it reads at the call
/// site, and a third answer can be added without breaking the second -- and
/// for a specific one: everything a run might want to vary about a corpus
/// (where it lives, whether it carries over, whether to start clean) is a
/// property of the *invocation*, not of the test.  Those levers belong to
/// `just fuzz`; see [`n_vm_protocol::FuzzDirs`].  What is left for the test
/// to declare is only whether it needs them at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CorpusPolicy {
    /// No writable storage.  The guest is read-only throughout, and the
    /// test is not announced to `cargo bolero list`.
    #[default]
    None,
    /// A coverage-guided fuzz target.
    ///
    /// Gets a writable corpus share, a writable crashes share when the
    /// engine names a separate one, and an entry in `cargo bolero list`.
    Fuzz,
}

/// The tokio runtime an `async` test body is driven on inside the guest.
///
/// A worker count that only means something on the multi-threaded scheduler
/// is *inside* the variant that has one, so `worker_threads` without
/// `multi_thread` cannot be written down.  It used to be two independent
/// attribute options and a hand-written check that rejected the combination;
/// there is now nothing to reject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestRuntime {
    /// The current-thread scheduler.  The default: a test that does not say
    /// otherwise gets no worker pool.
    CurrentThread,
    /// The multi-threaded scheduler.
    MultiThread {
        /// Worker threads, or `None` for tokio's default (one per core).
        worker_threads: Option<usize>,
    },
}

/// Builds a [`VmConfig`] by naming only what differs from
/// [`VmConfig::DEFAULT`].
///
/// Every method is `const`, which is the whole point rather than an
/// optimisation. A test's configuration is evaluated on the *host* tier, in
/// another process, before the guest exists, so it must not be able to
/// observe anything in the test body -- and `const` is what enforces that:
/// naming a local in one cannot resolve, and is reported at that name rather
/// than somewhere inside generated code. It is also what keeps
/// [`assert_valid`](VmConfig::assert_valid) running at compile time, so a
/// contradictory configuration stays a build error.
///
/// This is why the builder is written out rather than derived.
/// `derive_builder` produces `build(&self) -> Result<_, _>`, and neither the
/// method nor the `unwrap` that follows it can appear in a `const`.
///
/// ```ignore
/// #[n_vm::test]
/// fn drives_a_nic() {
///     #[n_vm::config]
///     const _: _ = VmConfigBuilder::default()
///         .iommu(true)
///         .kernel_features(&[features::VFIO_PCI])
///         .build();
///
///     // the test body follows
/// }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct VmConfigBuilder(VmConfig);

impl VmConfigBuilder {
    /// Starts from [`VmConfig::DEFAULT`].
    ///
    /// An inherent method rather than the `Default` trait because
    /// `Default::default` is not `const`, and a builder that cannot be used
    /// in a `const` would defeat the purpose -- see the type's own docs.
    #[must_use]
    #[allow(clippy::should_implement_trait)]
    pub const fn default() -> Self {
        Self(VmConfig::DEFAULT)
    }

    /// Presents a virtual IOMMU to the guest.
    #[must_use]
    pub const fn iommu(mut self, iommu: bool) -> Self {
        self.0.iommu = iommu;
        self
    }

    /// Sets the host page size backing guest memory.
    ///
    /// Anything other than [`HostPageSize::Standard`] draws on a host
    /// hugepage pool that nothing arbitrates; see [`VmConfig::DEFAULT`] for
    /// why the default declines to.
    #[must_use]
    pub const fn host_page_size(mut self, size: HostPageSize) -> Self {
        self.0.host_page_size = size;
        self
    }

    /// Names the kernel profile to boot.
    ///
    /// Use a constant from [`crate::kernel_feature::kernel_profiles`] rather than a bare string,
    /// so a rename shows up as a build error instead of an "unknown
    /// profile" at launch.
    #[must_use]
    pub const fn kernel_profile(mut self, name: &'static str) -> Self {
        self.0.kernel_profile = Some(name);
        self
    }

    /// Sets how many fabric-facing interfaces the VM gets, all of the same
    /// model.
    ///
    /// The management interface is always present and is not counted.
    #[must_use]
    pub const fn fabric_nics(mut self, count: u8) -> Self {
        self.0.fabric = FabricNics::Uniform(count);
        self
    }

    /// Gives the VM one fabric interface per model named, in order.
    ///
    /// Replaces any earlier [`fabric_nics`](Self::fabric_nics): the count
    /// and the models are one field, so they cannot disagree.
    ///
    /// ```ignore
    /// .fabric_nic_models(&[NicModel::VirtioNet, NicModel::E1000, NicModel::E1000E])
    /// ```
    ///
    /// An emulated model needs QEMU, so a mixed fabric that names one also
    /// pins the backend -- see [`ConfigProblem::NicRequiresQemu`].
    #[must_use]
    pub const fn fabric_nic_models(mut self, models: &'static [NicModel]) -> Self {
        self.0.fabric = FabricNics::Mixed(models);
        self
    }

    /// Sets the guest's total memory, in MiB.
    ///
    /// Must stay a whole number of host pages; with
    /// [`HostPageSize::Huge1G`] that means a whole number of gibibytes.
    #[must_use]
    pub const fn memory_mib(mut self, mib: u32) -> Self {
        self.0.memory_mib = mib;
        self
    }

    /// Sets the guest's vCPU count.
    #[must_use]
    pub const fn vcpus(mut self, vcpus: u32) -> Self {
        self.0.vcpus = vcpus;
        self
    }

    /// Declares what writable storage the test needs.
    ///
    /// [`CorpusPolicy::Fuzz`] is what replaced the old `#[n_vm::corpus]`
    /// attribute.  It is a configuration value rather than an attribute
    /// because it decides things the other configuration decides -- notably
    /// the hugepage reservation, which a fuzz target declines -- and those
    /// could not see each other while one lived in the macro.
    #[must_use]
    pub const fn corpus(mut self, policy: CorpusPolicy) -> Self {
        self.0.corpus = policy;
        self
    }

    /// Sets the guest's own hugepage reservation.
    ///
    /// Overrides [`GuestHugePageConfig::Auto`], including on a fuzz target,
    /// which otherwise reserves nothing.
    #[must_use]
    pub const fn guest_hugepages(mut self, hugepages: GuestHugePageConfig) -> Self {
        self.0.guest_hugepages = hugepages;
        self
    }

    /// Sets the NIC model for every interface in the VM.
    #[must_use]
    pub const fn nic_model(mut self, model: NicModel) -> Self {
        self.0.nic_model = model;
        self
    }

    /// Declares the kernel features the test depends on.
    ///
    /// Prefer the curated constants in
    /// [`features`](crate::kernel_feature::features) over spelling a symbol
    /// out: the table exists so that a typo is a compile error and shows up
    /// in completion, and a hand-written `KernelFeature` gets neither.
    #[must_use]
    pub const fn kernel_features(
        mut self,
        features: &'static [crate::kernel_feature::KernelFeature],
    ) -> Self {
        self.0.kernel_features = features;
        self
    }

    /// Pins the hypervisor.
    ///
    /// Leaving it at [`RequestedBackend::Default`](crate::backend::RequestedBackend::Default)
    /// is not the same as naming cloud-hypervisor: the default tolerates
    /// falling back to QEMU for a cross-architecture guest, where a pinned
    /// cloud-hypervisor test is skipped instead.
    #[must_use]
    pub const fn backend(mut self, backend: crate::backend::RequestedBackend) -> Self {
        self.0.backend = backend;
        self
    }

    /// Sets the tokio runtime an `async` body is driven on in the guest.
    #[must_use]
    pub const fn runtime(mut self, runtime: GuestRuntime) -> Self {
        self.0.runtime = runtime;
        self
    }

    /// Gives the test body longer than an ordinary test gets.
    ///
    /// Bounds the *body*, not the VM: boot, corpus load and shutdown are
    /// added on top, so a test that asks for ten minutes gets a VM that
    /// outlives ten minutes of work.
    #[must_use]
    pub const fn guest_time_limit(mut self, limit: Duration) -> Self {
        self.0.guest_time_limit = Some(limit);
        self
    }

    /// Sets kernel module parameters on the guest command line.
    #[must_use]
    pub const fn module_params(mut self, params: &'static [ModuleParam]) -> Self {
        self.0.module_params = params;
        self
    }

    /// Produces the configuration, checking it.
    ///
    /// # Panics
    ///
    /// Panics via [`assert_valid`](VmConfig::assert_valid) if the
    /// combination is contradictory.  In a `const` context that panic *is*
    /// the compile error, which is why this returns a [`VmConfig`] rather
    /// than a `Result`: `Result::unwrap` is not callable in a `const`.
    #[must_use]
    pub const fn build(self) -> VmConfig {
        self.0.assert_valid();
        self.0
    }
}

/// A way a [`VmConfig`] can be wrong.
///
/// Carried as a variant rather than a message so that one `const fn` check
/// serves both the compile-time assertion (which can only panic with a
/// literal) and the runtime path (which can afford to format the actual
/// numbers into the message).  Otherwise the two would each need their own
/// copy of the conditions, and would drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigProblem {
    /// VM memory is not a whole number of host pages.
    MemoryNotAligned,
    /// The guest hugepage reservation is larger than the VM's memory.
    HugepagesExceedMemory,
    /// The NIC model is emulated only by QEMU, but cloud-hypervisor is pinned.
    NicRequiresQemu,
    /// The VM was given no memory.
    NoMemory,
    /// The VM was given no vCPUs.
    NoVcpus,
    /// More fabric interfaces were asked for than have distinct addresses.
    TooManyNics,
    /// A fuzz target whose VM has no memory left for the engine to use.
    NoRoomToFuzz,
}

impl VmConfig {
    /// The default configuration: 4 KiB host pages, 512 MiB of 2 MiB guest hugepages, virtio-net,
    /// no IOMMU.
    ///
    /// # Why the host pages are small and the guest's are not
    ///
    /// These two settings look alike and are not. The guest hugepage is reserved *inside* the
    /// guest, on its kernel command line, and a guest that wants one gets one however the host
    /// backs the memory underneath. The host page size decides only whether that backing is
    /// physically contiguous, which matters to exactly one thing: DPDK driving a real device
    /// through an IOMMU. A test that boots a guest and does not do that cannot tell the
    /// difference.
    ///
    /// So the host pool is a resource this default should not spend. It is small -- two 1 GiB
    /// pages on the machine where this was found -- and nothing arbitrates it, so a default of
    /// [`HostPageSize::Huge1G`] made every test that never overrode it contend for a page it had
    /// no use for. Ten of eighteen integration tests failed that way in a parallel run, reporting
    /// "the 1073741824-byte hugepage pool has 0 free page(s)", which reads as flakiness and is a
    /// default asking for something it does not need.
    ///
    /// Tests that *do* drive DPDK through an IOMMU ask for [`HostPageSize::Huge1G`] explicitly,
    /// and pay for it honestly.
    ///
    /// # Why the guest's reservation is 512 MiB of 2 MiB pages
    ///
    /// It used to be a single 1 GiB page, out of a guest with exactly 1 GiB of RAM, which the
    /// guest kernel cannot satisfy -- it has already taken memory by the time it reserves. That
    /// was invisible while the host handed over a contiguous 1 GiB page and became intermittent
    /// as soon as it did not. [`VmConfig::check`] now requires the headroom, so this is a build
    /// error rather than a console line forty lines into a failure dump.
    ///
    /// Spell overrides against this with struct update syntax, which works
    /// in a `const`:
    ///
    /// ```ignore
    /// const NO_HUGE: VmConfig = VmConfig {
    ///     guest_hugepages: GuestHugePageConfig::None,
    ///     ..VmConfig::DEFAULT
    /// };
    /// ```
    pub const DEFAULT: Self = Self {
        iommu: false,
        host_page_size: HostPageSize::Standard,
        guest_hugepages: GuestHugePageConfig::Auto,
        nic_model: NicModel::VirtioNet,
        kernel_features: &[],
        backend: crate::backend::RequestedBackend::Default,
        runtime: GuestRuntime::CurrentThread,
        guest_time_limit: None,
        module_params: &[],
        kernel_profile: None,
        fabric: FabricNics::Uniform(2),
        memory_mib: 1024,
        vcpus: 6,
        corpus: CorpusPolicy::None,
        source_file: None,
    };

    /// Reopens this configuration as a builder, for deriving a variant.
    ///
    /// The `const`-callable equivalent of `..BASE` struct update syntax, and
    /// the answer to "the same VM on the other hypervisor":
    ///
    /// ```ignore
    /// const IOMMU_VM: VmConfig = VmConfigBuilder::default().iommu(true).build();
    /// const IOMMU_VM_QEMU: VmConfig = IOMMU_VM.to_builder()
    ///     .backend(RequestedBackend::Qemu)
    ///     .build();
    /// ```
    #[must_use]
    pub const fn to_builder(self) -> VmConfigBuilder {
        VmConfigBuilder(self)
    }

    /// Whether this test is a coverage-guided fuzz target.
    ///
    /// Read through this rather than off the field, so the meaning has one
    /// name.  It is also what the generated harness branches on to decide
    /// whether to announce itself to `cargo bolero list`; being `const`, that
    /// branch folds away entirely in an ordinary test.
    #[must_use]
    pub const fn is_fuzz_target(&self) -> bool {
        matches!(self.corpus, CorpusPolicy::Fuzz)
    }

    /// Total guest memory in bytes.
    ///
    /// `i64` because both hypervisors' memory sizes are signed, and the
    /// hugepage arithmetic in [`check`](Self::check) is done in the same
    /// type to keep it `const`.
    #[must_use]
    pub const fn memory_bytes(&self) -> i64 {
        (self.memory_mib as i64) * 1024 * 1024
    }

    /// The hugepage reservation this VM actually boots with.
    ///
    /// Resolves [`GuestHugePageConfig::Auto`] against the test's role; any
    /// other value is returned unchanged.  Every consumer -- the validity
    /// check, the kernel command line, the launcher -- must go through here,
    /// because the raw field is a *request* and `Auto` is a request to
    /// decide.
    #[must_use]
    pub const fn hugepage_reservation(&self) -> GuestHugePageConfig {
        match self.guest_hugepages {
            GuestHugePageConfig::Auto => {
                if self.is_fuzz_target() {
                    GuestHugePageConfig::None
                } else {
                    GuestHugePageConfig::DEFAULT_RESERVATION
                }
            }
            explicit => explicit,
        }
    }

    /// Every interface presented to this VM, in device order.
    ///
    /// The management interface is always first and always present: it is
    /// the standard-MTU link on the unprotected PCI segment, and the fabric
    /// links are defined by contrast with it.
    ///
    /// A method rather than a free function taking a count, because a link
    /// now carries a device model as well as an index, and both come from
    /// the configuration.  Reading them from one place is what keeps the
    /// two backends lowering the same list.
    #[must_use]
    pub fn all_ifaces(&self) -> Vec<NetIface> {
        let mgmt = NetIface {
            id: "mgmt".to_owned(),
            tap: "mgmt".to_owned(),
            mac: "02:DE:AD:BE:EF:01".to_owned(),
            host_ipv6: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0xffff, 1),
            mtu: MGMT_MTU,
            queue_size: MGMT_QUEUE_SIZE,
            pci_segment: 0,
            model: self.nic_model,
        };

        // Clamped rather than trusted. `check` rejects a longer fabric, but
        // a configuration can reach the launcher without having been
        // checked, and past 254 the index no longer fits the last octet of
        // the MAC -- two links would come up sharing an address, which is
        // the symptom a network test would then be trying to explain.
        let count = MAX_FABRIC_NICS.min(u8::try_from(self.fabric.len()).unwrap_or(u8::MAX));

        std::iter::once(mgmt)
            .chain((1..=count).map(|n| NetIface {
                id: format!("fabric{n}"),
                tap: format!("fabric{n}"),
                mac: format!("02:CA:FE:BA:BE:{n:02X}"),
                host_ipv6: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, u16::from(n)),
                mtu: FABRIC_MTU,
                queue_size: FABRIC_QUEUE_SIZE,
                pci_segment: 1,
                model: self.fabric.model(usize::from(n) - 1, self.nic_model),
            }))
            .collect()
    }

    /// The first interface in this VM that only QEMU can emulate, if any.
    ///
    /// Covers the management link as well as the fabric, so that
    /// `nic_model` alone is enough to pin the backend even on a VM with no
    /// fabric links at all.
    #[must_use]
    pub const fn first_qemu_only_nic(&self) -> Option<NicModel> {
        if self.nic_model.requires_qemu() {
            return Some(self.nic_model);
        }
        self.fabric.first_qemu_only(self.nic_model)
    }

    /// The `-rss_limit_mb` a fuzz engine running in this VM should be held
    /// to, or [`None`] if this VM has no room to fuzz at all.
    ///
    /// libfuzzer's own default is 2048 MB, which is twice the default guest
    /// and was never reached: the guest kernel ran out of memory first and
    /// killed the engine, and an engine killed from outside writes no
    /// artifact.  The input that grew the heap is then gone, so the one
    /// finding a memory bug is supposed to produce is exactly what the
    /// failure destroys.  Under the limit, libfuzzer notices the growth
    /// itself, saves the input, and says which one it was.
    ///
    /// The derivation is what is left after the two claims the engine
    /// cannot touch: a hugepage reservation, which the guest kernel hands
    /// to hugetlbfs and never hands back, and
    /// `GUEST_KERNEL_HEADROOM_BYTES` for the kernel and `n-it`
    /// themselves.  That is a bound, not a measurement -- an engine that
    /// stays under it can still be killed by a guest that was busy
    /// elsewhere -- but every part of it is memory that provably is not
    /// available to the engine.
    ///
    /// [`None`] rather than a floor because libfuzzer reads
    /// `-rss_limit_mb=0` as *no limit*.  Saturating at zero would turn a VM
    /// too small to fuzz into one whose engine is unbounded, which is the
    /// opposite of what this is for.  [`check`](Self::check) rejects a fuzz
    /// target that lands here, so the [`None`] arm is only reachable for a
    /// configuration that never declared itself one.
    #[must_use]
    pub const fn fuzz_rss_limit_mib(&self) -> Option<u32> {
        let reserved_bytes = match self.hugepage_reservation() {
            // `as i64` rather than `i64::from`: trait methods are not
            // callable in a const fn.
            GuestHugePageConfig::Allocate { size, count } => size.bytes() * (count as i64),
            // `Auto` is unreachable -- `hugepage_reservation` resolves it --
            // and `None` reserves nothing.
            _ => 0,
        };
        let available_mib =
            (self.memory_bytes() - reserved_bytes - GUEST_KERNEL_HEADROOM_BYTES) / (1024 * 1024);
        // Rounded down first, then tested: a remainder under a mebibyte is
        // not a limit anybody can express, and `0` would mean the opposite
        // of one.
        if available_mib <= 0 {
            return None;
        }
        Some(available_mib as u32)
    }

    /// Checks the configuration for internal contradictions.
    ///
    /// `const` so the same check can run at compile time; see
    /// [`assert_valid`](Self::assert_valid).
    ///
    /// # Errors
    ///
    /// Returns the first [`ConfigProblem`] found.
    pub const fn check(&self) -> Result<(), ConfigProblem> {
        // Zero first, because every check below passes vacuously on it:
        // `0 % anything` is 0, so an empty VM would read as well-aligned
        // and then fail at launch with whatever the hypervisor says about
        // a machine with nothing in it.
        if self.memory_mib == 0 {
            return Err(ConfigProblem::NoMemory);
        }
        if self.vcpus == 0 {
            return Err(ConfigProblem::NoVcpus);
        }
        if self.fabric.len() > MAX_FABRIC_NICS as usize {
            return Err(ConfigProblem::TooManyNics);
        }
        let memory_bytes = self.memory_bytes();
        let page_bytes = self.host_page_size.bytes();
        if memory_bytes % page_bytes != 0 {
            return Err(ConfigProblem::MemoryNotAligned);
        }
        // The *resolved* reservation, not the raw field: `Auto` is what
        // nearly every config carries, and checking the field would check
        // nothing at all for them.
        if let GuestHugePageConfig::Allocate { size, count } = self.hugepage_reservation() {
            // `as i64` rather than `i64::from`: trait methods are not
            // callable in a const fn, and this check must stay const.
            let required = size.bytes() * (count as i64);
            // Strictly less, not `<=`. The guest kernel has already claimed memory by the time it
            // reserves hugepages, so a reservation of *all* of RAM cannot be satisfied -- it
            // reports "HugeTLB: allocating 1 of page size 1.00 GiB failed. Only allocated 0
            // hugepages." on the console and boots without them, which surfaces much later as a
            // test failure with nothing pointing here.
            //
            // `<=` accepted exactly that, and the default was exactly that: one 1 GiB page out of
            // 1 GiB. It only ever worked because 1 GiB host pages handed the guest a contiguous
            // block; it became intermittent the moment the host default stopped doing so.
            if required + GUEST_KERNEL_HEADROOM_BYTES > memory_bytes {
                return Err(ConfigProblem::HugepagesExceedMemory);
            }
        }
        // A fuzz target with nowhere to fuzz. Checked here rather than
        // clamped at the point of use because the clamp would have to be
        // zero, and libfuzzer reads zero as "no limit" -- see
        // `fuzz_rss_limit_mib`.
        if self.is_fuzz_target() && self.fuzz_rss_limit_mib().is_none() {
            return Err(ConfigProblem::NoRoomToFuzz);
        }
        // Now that the backend is part of the configuration this is an
        // internal contradiction like the others, rather than something only
        // a caller holding both halves could check.
        //
        // `RequestedBackend::Default` stays permissive: an unpinned test that
        // asks for an emulated NIC is not a contradiction, it is a test that
        // wants QEMU, and `RequestedBackend::resolve` selects it.
        if self.first_qemu_only_nic().is_some()
            && matches!(
                self.backend,
                crate::backend::RequestedBackend::CloudHypervisor
            )
        {
            return Err(ConfigProblem::NicRequiresQemu);
        }
        Ok(())
    }

    /// Rejects an invalid configuration at compile time.
    ///
    /// The generated test harness emits `const _: () = CONFIG.assert_valid();`
    /// so that a contradiction is a build error rather than a VM that fails
    /// to launch several tiers later.
    ///
    /// # Panics
    ///
    /// Panics if [`check`](Self::check) fails.  In a `const` context that
    /// panic *is* the compile error.
    pub const fn assert_valid(&self) {
        match self.check() {
            Ok(()) => {}
            Err(ConfigProblem::MemoryNotAligned) => panic!(
                "VM memory is not a whole number of host pages; \
                 pick a host_page_size that divides the VM's memory"
            ),
            Err(ConfigProblem::HugepagesExceedMemory) => panic!(
                "the guest hugepage reservation does not leave the guest kernel room; \
                 reduce hugepage_count, use a smaller hugepage size, or set \
                 guest_hugepages to GuestHugePageConfig::None"
            ),
            Err(ConfigProblem::NoMemory) => {
                panic!("a VM needs memory; set memory_mib to a non-zero whole number of host pages")
            }
            Err(ConfigProblem::NoVcpus) => panic!("a VM needs at least one vCPU; set vcpus"),
            Err(ConfigProblem::TooManyNics) => panic!(
                "too many fabric interfaces; beyond 254 two of them would share a \
                 MAC address and a link-local address"
            ),
            Err(ConfigProblem::NoRoomToFuzz) => panic!(
                "this fuzz target's VM has no memory left for the engine once the guest \
                 kernel and the hugepage reservation have taken theirs; raise memory_mib, \
                 or set guest_hugepages to GuestHugePageConfig::None"
            ),
            Err(ConfigProblem::NicRequiresQemu) => panic!(
                "this NIC model is emulated only by QEMU, but the configuration pinned \
                 cloud-hypervisor; leave the backend at RequestedBackend::Default to let \
                 the harness pick QEMU, or ask for RequestedBackend::Qemu"
            ),
        }
    }

    /// The corpus directory for this test, relative to the workspace root.
    ///
    /// Guaranteed relative, which the callers rely on: the host tier joins
    /// it onto the workspace root (an absolute path would silently *replace*
    /// the root rather than extend it) and the guest path is built by
    /// concatenation.
    ///
    /// A relative `file!()` is used as-is.  An absolute one is the
    /// `--remap-path-prefix==${src}` case described on
    /// [`Self::source_file`]: the remap prepends the workspace's
    /// store path, so the workspace-relative tail is recovered by cutting at
    /// the crate directory's own name, which is where the manifest dir and
    /// the source path necessarily agree.  `rposition` because the anchor is
    /// the *last* such component -- a store hash like `abc-n-vm-source`
    /// would otherwise match ahead of the real crate directory.
    ///
    /// This is the *fallback* location, used when no engine named one.
    /// Under `cargo bolero test` the directories come from the engine's own
    /// command line instead (see [`n_vm_protocol::fuzz_dirs`]), because
    /// `cargo-bolero` computes them from `--corpus-dir` and from its own
    /// `fuzz_dir()` derivation -- recomputing them here would mean
    /// reimplementing that derivation and drifting from it.
    ///
    /// `None` when the test is not a fuzz target, when the path has no
    /// parent to hang `__fuzz__` off, or when the anchor is absent (a crate
    /// sitting at the workspace root, whose directory name the remapped
    /// prefix does not preserve).  Callers must treat `None` on a fuzz
    /// target as an error: a missing corpus mount otherwise surfaces as a
    /// confusing read-only failure inside the guest.
    #[must_use]
    pub fn corpus_rel_dir(&self) -> Option<std::path::PathBuf> {
        use std::path::{Component, Path, PathBuf};

        if !self.is_fuzz_target() {
            return None;
        }
        let (file, crate_dir) = self.source_file?;
        let file = Path::new(file);

        let relative: PathBuf = if file.is_relative() {
            file.to_path_buf()
        } else {
            let anchor = Path::new(crate_dir).file_name()?;
            let components: Vec<Component<'_>> = file.components().collect();
            let start = components.iter().rposition(|c| c.as_os_str() == anchor)?;
            components[start..].iter().collect()
        };

        Some(relative.parent()?.join(n_vm_protocol::CORPUS_DIR_NAME))
    }

    /// The absolute path at which the corpus directory appears *inside the
    /// guest*, given that the workspace is mounted at
    /// `/{VM_WORKSPACE_DIR}`.
    ///
    /// Both the host tier (which bind-mounts the directory) and the
    /// container tier (which puts this on the kernel command line) compute
    /// it from the same compile-time constant, so they cannot disagree.
    #[must_use]
    pub fn corpus_guest_path(&self) -> Option<String> {
        let rel = self.corpus_rel_dir()?;
        Some(format!(
            "/{workspace}/{rel}",
            workspace = n_vm_protocol::VM_WORKSPACE_DIR,
            rel = rel.display(),
        ))
    }
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
        // Same conditions as `check`, but with the numbers formatted in.
        // This path survives because a config can reach the launcher without
        // having gone through `assert_valid` -- it is built at run time in
        // tests, for one -- and because "1024 MiB is not a multiple of 1 GiB"
        // is a more useful thing to read than the static message a const
        // panic is limited to.
        match self.check() {
            Ok(()) => Ok(()),
            Err(ConfigProblem::NoMemory) => Err("memory_mib is 0; a VM needs memory".to_owned()),
            Err(ConfigProblem::NoVcpus) => Err("vcpus is 0; a VM needs at least one".to_owned()),
            Err(ConfigProblem::TooManyNics) => Err(format!(
                "fabric_nics ({n}) exceeds {MAX_FABRIC_NICS}; the MAC and link-local \
                 addresses are derived from the index and would collide",
                n = self.fabric.len(),
            )),
            Err(ConfigProblem::MemoryNotAligned) => Err(format!(
                "guest memory ({mib} MiB = {bytes} bytes) is not a whole number of \
                 host pages ({page_bytes} bytes)",
                mib = self.memory_mib,
                bytes = self.memory_bytes(),
                page_bytes = self.host_page_size.bytes(),
            )),
            Err(ConfigProblem::HugepagesExceedMemory) => {
                let GuestHugePageConfig::Allocate { size, count } = self.hugepage_reservation()
                else {
                    unreachable!(
                        "HugepagesExceedMemory is only reachable when hugepages are allocated"
                    )
                };
                let required = size.bytes() * i64::from(count);
                Err(format!(
                    "guest hugepage reservation ({count} x {} = {required} bytes) \
                     exceeds VM memory ({bytes} bytes)",
                    size.bytes(),
                    bytes = self.memory_bytes(),
                ))
            }
            Err(ConfigProblem::NoRoomToFuzz) => Err(format!(
                "this is a fuzz target, but its VM ({mib} MiB) has nothing left for the \
                 engine once the guest kernel and the hugepage reservation have taken \
                 theirs; raise memory_mib or drop the reservation",
                mib = self.memory_mib,
            )),
            Err(ConfigProblem::NicRequiresQemu) => {
                let Some(nic) = self.first_qemu_only_nic() else {
                    unreachable!("NicRequiresQemu is only reachable when some NIC needs QEMU")
                };
                Err(format!(
                    "{nic:?} is emulated only by QEMU, but this configuration pinned \
                     cloud-hypervisor",
                ))
            }
        }
    }
}

/// Guest memory a hugepage reservation must leave for the kernel that performs it.
///
/// Not a measurement -- a floor. The kernel reserves hugepages very early, but not before it
/// exists, so a reservation may not name the whole of RAM. 128 MiB is enough for the kernels this
/// boots and small enough not to constrain a reservation anybody would actually want.
pub(crate) const GUEST_KERNEL_HEADROOM_BYTES: i64 = 128 * 1024 * 1024;

/// A CPU topology whose levels multiply to a given vCPU count.
///
/// Both hypervisors want the four levels rather than a total, and both
/// reject a topology that does not multiply back -- so this is derived in
/// one place and used by both, rather than each backend guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SmpTopology {
    /// Sockets (packages).
    pub sockets: u32,
    /// Dies per socket.  x86-only; aarch64 folds this into `cores`.
    pub dies: u32,
    /// Cores per die.
    pub cores: u32,
    /// Hardware threads per core.
    pub threads: u32,
}

impl SmpTopology {
    /// Arranges `vcpus` into levels whose product is exactly `vcpus`.
    ///
    /// An even count keeps SMT, because that is the shape a real host has
    /// and the guest is code that inspects its own topology: DPDK reads
    /// `/sys` to lay lcores out, and a machine that claims no hyperthreads
    /// exercises a different path from every machine this code runs on in
    /// production.  An odd count cannot be split that way, so it falls back
    /// to flat cores rather than rounding the request.
    ///
    /// At the default of 6 this reproduces the topology that used to be
    /// four hand-written constants -- 1 socket, 3 dies, 1 core, 2 threads --
    /// so making the count a lever changes nothing for a test that does not
    /// set it.
    pub(crate) const fn for_vcpus(vcpus: u32) -> Self {
        if vcpus.is_multiple_of(2) {
            Self {
                sockets: 1,
                dies: vcpus / 2,
                cores: 1,
                threads: 2,
            }
        } else {
            Self {
                sockets: 1,
                dies: 1,
                cores: vcpus,
                threads: 1,
            }
        }
    }
}

/// Describes a network interface shared across all hypervisor backends.
///
/// Owned rather than `&'static`, because the fabric interfaces are
/// generated from a count.  Carrying the MTU, queue depth and PCI segment
/// here rather than branching on "is this the management one" in each
/// backend is what lets both of them lower an arbitrary list identically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetIface {
    /// Unique identifier used in device configuration (e.g. `"mgmt"`,
    /// `"fabric1"`).
    pub id: String,
    /// TAP device name on the host.
    pub tap: String,
    /// MAC address in `XX:XX:XX:XX:XX:XX` format.
    pub mac: String,
    /// IPv6 link-local address assigned to the host-side TAP.
    pub host_ipv6: Ipv6Addr,
    /// Link MTU.
    pub mtu: i32,
    /// Virtio queue depth.
    pub queue_size: i32,
    /// PCI segment the device is placed on.
    ///
    /// Segment 1 is the one placed behind the virtual IOMMU, so this is
    /// also what decides whether a device gets DMA remapping.
    pub pci_segment: u16,
    /// The device model the guest sees, and therefore which driver binds
    /// it.
    ///
    /// Per-interface rather than per-VM because a machine whose links are
    /// all the same device cannot exercise the thing that goes wrong: a
    /// program that picks a NIC by ordinal, or by whatever `/sys` lists
    /// first, looks correct on a uniform machine and unbinds the wrong
    /// device on a mixed one.
    pub model: NicModel,
}

/// The largest fabric NIC index the address derivation can represent.
///
/// The last octet of the MAC and the last group of the IPv6 address are
/// both the interface's index, so 254 is where two NICs would start
/// sharing an address.  That does not fail: the guest brings both up, and
/// forwarding silently goes to whichever answered -- which is precisely
/// the symptom a failover test would then be trying to explain.
pub(crate) const MAX_FABRIC_NICS: u8 = 254;

/// The fabric-facing interfaces a VM is given.
///
/// Two spellings of one list, because the two things a test wants to say
/// about its fabric are different questions.  Most tests care only how
/// many links there are; a test of device *identification* cares what each
/// one is, and needs them to differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FabricNics {
    /// `n` links, every one of [`VmConfig::nic_model`].
    Uniform(u8),
    /// One link per entry, each of the model named.
    ///
    /// A `&'static` slice rather than an array so this stays writable in
    /// the `const` the builder produces -- the same reason
    /// [`VmConfig::kernel_features`] is one.
    Mixed(&'static [NicModel]),
}

impl Default for FabricNics {
    fn default() -> Self {
        VmConfig::DEFAULT.fabric
    }
}

impl FabricNics {
    /// How many fabric links this describes.
    ///
    /// `usize` rather than `u8` so that an over-long [`Mixed`](Self::Mixed)
    /// is a number [`VmConfig::check`] can compare against
    /// `MAX_FABRIC_NICS`, instead of one that has already wrapped past
    /// it.
    #[must_use]
    pub const fn len(&self) -> usize {
        match self {
            Self::Uniform(count) => *count as usize,
            Self::Mixed(models) => models.len(),
        }
    }

    /// Whether this VM has no fabric links at all, which is what a test
    /// that never touches the network should ask for.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The model of the `index`-th link, counting from zero.
    ///
    /// `default` is what a [`Uniform`](Self::Uniform) fabric is made of;
    /// it is the VM's own [`nic_model`](VmConfig::nic_model), which is
    /// also what the management link uses.  It is returned for an index
    /// past the end of a [`Mixed`](Self::Mixed) fabric too, which
    /// [`VmConfig::all_ifaces`] never asks for -- it iterates
    /// [`len`](Self::len).
    #[must_use]
    pub const fn model(&self, index: usize, default: NicModel) -> NicModel {
        match self {
            Self::Uniform(_) => default,
            Self::Mixed(models) => {
                if index < models.len() {
                    models[index]
                } else {
                    default
                }
            }
        }
    }

    /// The first model here that only QEMU emulates, if any.
    ///
    /// Returned rather than a bare `bool` so the error can name the device
    /// that forced the choice -- on a mixed fabric, "some NIC in this VM
    /// needs QEMU" is not enough to act on.
    #[must_use]
    pub const fn first_qemu_only(&self, default: NicModel) -> Option<NicModel> {
        match self {
            Self::Uniform(count) => {
                if *count > 0 && default.requires_qemu() {
                    Some(default)
                } else {
                    None
                }
            }
            Self::Mixed(models) => {
                // A `while` rather than an iterator: this must stay `const`,
                // because it is what `check` asks.
                let mut i = 0;
                while i < models.len() {
                    if models[i].requires_qemu() {
                        return Some(models[i]);
                    }
                    i += 1;
                }
                None
            }
        }
    }
}

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

/// A writable share that this run actually has, and where it lands.
///
/// Separate from [`n_vm_protocol::WritableShare`], which is the static
/// description of a window that *could* exist.  Which windows are open, and
/// what guest path each covers, is decided per run: the engine names its own
/// directories, and their guest paths are host paths put through the
/// workspace remap.  Resolving that once and threading the result keeps the
/// backends' argument lowering a pure function of its inputs, the same way
/// `arch` and `kernel_image` are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveShare {
    /// Which window this is.
    pub share: n_vm_protocol::WritableShare,
    /// Absolute path the guest mounts it at.
    pub guest_path: String,
}

impl ActiveShare {
    /// The shares this container has, in [`n_vm_protocol::WRITABLE_SHARES`]
    /// order.
    ///
    /// A share is present when *both* halves are: the host tier bind-mounted
    /// a directory at the container path, and it named the guest path in the
    /// environment.  Requiring both is what keeps a virtio device from being
    /// added with no daemon behind it, which does not fail -- it hangs the
    /// hypervisor waiting on a vhost-user socket that will never be served.
    #[must_use]
    pub fn resolve() -> Vec<Self> {
        n_vm_protocol::WRITABLE_SHARES
            .iter()
            .filter(|share| std::path::Path::new(share.container_path).is_dir())
            .filter_map(|share| {
                let guest_path = std::env::var(share.env_key).ok()?;
                (!guest_path.is_empty()).then_some(Self {
                    share: *share,
                    guest_path,
                })
            })
            .collect()
    }
}

/// Builds the guest kernel command line.
pub(crate) fn build_kernel_cmdline(
    vm_bin_path: &str,
    test_name: &str,
    vsock: &VsockAllocation,
    // Grouped rather than passed field by field: `iommu`, the hugepage
    // reservation and the module parameters all come from here, and
    // threading them separately made the signature grow every time the
    // config did.
    vm_config: &VmConfig,
    // Not from the config, because which windows are open is a fact about
    // this run rather than about the test -- see [`ActiveShare`].
    shares: &[ActiveShare],
    arch: Arch,
    boot: crate::kernel_manifest::BootMode,
) -> String {
    let vsock_cmdline = vsock.kernel_cmdline_fragment();
    let iommu = vm_config.iommu;
    let guest_hugepages = vm_config.hugepage_reservation();

    // Without a vIOMMU, allow DPDK to bind devices via vfio-pci.
    let noiommu_fragment = if iommu {
        ""
    } else {
        "vfio.enable_unsafe_noiommu_mode=1 "
    };

    let hugepage_fragment = guest_hugepages.kernel_cmdline_fragment();

    // Module parameters, in the kernel section (before `--`).  Each was
    // checked for shape when it was declared, so this only has to join them.
    let module_param_fragment =
        vm_config
            .module_params
            .iter()
            .fold(String::new(), |mut acc, param| {
                acc.push_str(&param.render());
                acc.push(' ');
                acc
            });

    // The IOMMU and console parameters are lowered per guest ISA
    // (x86 ttyS0 vs aarch64 ttyAMA0); `arch` is passed in explicitly so
    // this is testable for every ISA on any build host.  The IOMMU kernel
    // params come from the vIOMMU lowering and are present whenever the
    // ISA has one (empty otherwise) -- independent of the per-test flag.
    let iommu_params = arch.virtual_iommu().map_or("", |l| l.kernel_params);
    let console_params = arch.console_kernel_params();

    // Where `n-it` should mount each writable share.  Empty for an ordinary
    // test, which never sees a writable filesystem at all.
    let corpus_fragment = shares.iter().fold(String::new(), |mut acc, active| {
        use std::fmt::Write as _;
        let _ = write!(
            acc,
            "{key}={path} ",
            key = active.share.cmdline_key,
            path = active.guest_path,
        );
        acc
    });

    // `sysctl.debug.exception-trace=1` makes the kernel report a userspace
    // fault -- faulting PC, SP and address -- instead of killing the process
    // silently.  It defaults to 0 (`show_unhandled_signals` in
    // arch/arm64/kernel/traps.c), which meant a test binary taking SIGSEGV
    // in the guest produced no diagnostic at all: `n-it` could say only
    // "main process exited with failure status signal: 11".  A VM that
    // exists to run tests should say why one died.
    //
    // How the kernel is told to find its root.
    //
    // A direct boot names the virtiofs share and the init to exec once it
    // is mounted.  An initramfs boot reaches none of that code:
    // `prepare_namespace` is skipped entirely when a cpio supplies the
    // root, so `root=`/`rootfstype=` would be read by nothing, and `init=`
    // applies only after a switch_root the pre-init does not perform.
    // Naming them anyway would be inert *and* misleading about how the
    // guest actually boots.
    //
    // `rdinit=` is spelled explicitly even though `/init` is the kernel's
    // default, because an external initramfs layered onto a foreign
    // kernel's embedded one (as Flatcar would need) resolves `/init` to
    // whichever cpio was unpacked last.  Naming the path does not depend on
    // that ordering.
    let root_params = match boot {
        crate::kernel_manifest::BootMode::Direct => {
            format!("rootfstype=virtiofs root=root init={INIT_BINARY_PATH}")
        }
        crate::kernel_manifest::BootMode::Initramfs => "rdinit=/init".to_owned(),
    };

    format!(
        "{iommu_params} \
         {noiommu_fragment}\
         {console_params} \
         sysctl.debug.exception-trace=1 \
         ro \
         {root_params} \
         {hugepage_fragment}\
         {module_param_fragment}\
         {corpus_fragment}\
         {vsock_cmdline} \
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

    /// The default VM with `n` fabric links, all of the default model.
    const fn uniform_fabric(n: u8) -> VmConfig {
        VmConfig {
            fabric: FabricNics::Uniform(n),
            ..VmConfig::DEFAULT
        }
    }

    const DEFAULT_HP: GuestHugePageConfig = GuestHugePageConfig::Allocate {
        size: GuestHugePageSize::Huge1G,
        count: 1,
    };

    // -- Writable shares ----------------------------------------------

    fn active(share: n_vm_protocol::WritableShare, guest_path: &str) -> ActiveShare {
        ActiveShare {
            share,
            guest_path: guest_path.to_owned(),
        }
    }

    fn cmdline_with(shares: &[ActiveShare]) -> String {
        build_kernel_cmdline(
            "/test/bin",
            "my::test",
            &n_vm_protocol::VsockAllocation::with_defaults(),
            &VmConfig::DEFAULT,
            shares,
            Arch::X86_64,
            crate::kernel_manifest::BootMode::Direct,
        )
    }

    /// Both windows reach `n-it`, each under its own key.
    ///
    /// One key could not carry two paths, and the guest has to mount them
    /// separately -- they are in unrelated trees.
    #[test]
    fn each_writable_share_gets_its_own_cmdline_key() {
        let cmdline = cmdline_with(&[
            active(n_vm_protocol::CORPUS_SHARE, "/workspace/.fuzz-corpus/t"),
            active(
                n_vm_protocol::CRASHES_SHARE,
                "/workspace/m/__fuzz__/t/crashes",
            ),
        ]);
        assert!(
            cmdline.contains("n_it.corpus_mount=/workspace/.fuzz-corpus/t"),
            "{cmdline}",
        );
        assert!(
            cmdline.contains("n_it.crashes_mount=/workspace/m/__fuzz__/t/crashes"),
            "{cmdline}",
        );
    }

    /// An ordinary test is told about no writable filesystem at all.
    #[test]
    fn a_test_with_no_shares_names_no_mounts() {
        let cmdline = cmdline_with(&[]);
        assert!(!cmdline.contains("_mount="), "{cmdline}");
    }

    /// The keys land in the kernel section, before the `--` that separates
    /// it from the test binary's own argv.  A parameter on the wrong side
    /// of that split does not fail: `n-it` never sees it, and the guest
    /// silently has no writable share.
    #[test]
    fn the_mount_keys_precede_the_argv_separator() {
        let cmdline = cmdline_with(&[active(n_vm_protocol::CORPUS_SHARE, "/workspace/c")]);
        let key = cmdline.find("n_it.corpus_mount=").expect("key is present");
        let split = cmdline.find(" -- ").expect("separator is present");
        assert!(key < split, "{cmdline}");
    }

    // -- Hugepage defaulting ------------------------------------------

    /// The reservation an ordinary guest test still gets: the same 512 MiB
    /// it got when `VmConfig::DEFAULT` spelled it out.
    #[test]
    fn an_ordinary_test_reserves_what_it_always_reserved() {
        assert_eq!(
            VmConfig::DEFAULT.hugepage_reservation(),
            GuestHugePageConfig::Allocate {
                size: GuestHugePageSize::Huge2M,
                count: 256,
            },
        );
    }

    /// A fuzz target reserves nothing: a coverage-guided engine claims
    /// ordinary heap, and the reservation was pure subtraction from the
    /// memory it could use.
    #[test]
    fn a_fuzz_target_reserves_nothing() {
        let config = with_corpus("n-vm/tests/integration.rs", "/home/dev/dataplane/n-vm");
        assert_eq!(config.guest_hugepages, GuestHugePageConfig::Auto);
        assert_eq!(config.hugepage_reservation(), GuestHugePageConfig::None);
    }

    /// `Auto` is a default, not a rule.  Fuzzing a hugepage-dependent path
    /// is a coherent thing to want, and saying so wins.
    #[test]
    fn a_fuzz_target_may_still_ask_for_hugepages() {
        let asked = GuestHugePageConfig::Allocate {
            size: GuestHugePageSize::Huge2M,
            count: 64,
        };
        let config = VmConfig {
            guest_hugepages: asked,
            ..with_corpus("n-vm/tests/integration.rs", "/home/dev/dataplane/n-vm")
        };
        assert_eq!(config.hugepage_reservation(), asked);
    }

    /// And an explicit `None` on an ordinary test still means none, rather
    /// than falling through to the reservation `Auto` would have picked.
    #[test]
    fn an_ordinary_test_may_still_decline_hugepages() {
        let config = VmConfig {
            guest_hugepages: GuestHugePageConfig::None,
            ..VmConfig::DEFAULT
        };
        assert_eq!(config.hugepage_reservation(), GuestHugePageConfig::None);
    }

    /// The end of the chain: what the guest kernel is actually told.
    ///
    /// Asserted here as well as on the resolved value because the command
    /// line is the only thing the guest sees, and `build_kernel_cmdline`
    /// reading the raw field instead of the resolved one is exactly the
    /// mistake this defaulting invites.
    #[test]
    fn a_fuzz_target_gets_no_hugepage_reservation_on_the_cmdline() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let cmdline = build_kernel_cmdline(
            "/test/bin",
            "my::test",
            &vsock,
            &with_corpus("n-vm/tests/integration.rs", "/home/dev/dataplane/n-vm"),
            &[],
            Arch::X86_64,
            crate::kernel_manifest::BootMode::Direct,
        );
        assert!(
            !cmdline.contains("hugepages"),
            "a fuzz target should be told nothing about hugepages: {cmdline}",
        );
    }

    // -- Corpus paths -------------------------------------------------

    fn with_corpus(file: &'static str, crate_dir: &'static str) -> VmConfig {
        VmConfig {
            corpus: CorpusPolicy::Fuzz,
            source_file: Some((file, crate_dir)),
            ..VmConfig::DEFAULT
        }
    }

    /// A plain `cargo test` gives a workspace-relative `file!()`.
    #[test]
    fn corpus_dir_from_a_relative_source_path() {
        let config = with_corpus("n-vm/tests/integration.rs", "/home/dev/dataplane/n-vm");
        assert_eq!(
            config.corpus_rel_dir().expect("resolvable"),
            std::path::Path::new("n-vm/tests/__fuzz__"),
        );
    }

    /// The `--remap-path-prefix==${src}` build gives an absolute store path.
    ///
    /// Treating it as relative is what broke `#[corpus]`: the host tier's
    /// `workspace.join(rel)` discarded the workspace, and the guest was told
    /// to look under `/workspace//nix/store/...`.
    #[test]
    fn corpus_dir_from_a_remapped_absolute_source_path() {
        let config = with_corpus(
            "/nix/store/7qpx1j7sqw6zklc13w0v338vwwykjzpl-source/n-vm/tests/integration.rs",
            "/build/source/n-vm",
        );
        let rel = config.corpus_rel_dir().expect("resolvable");
        assert!(rel.is_relative(), "must be relative, got {}", rel.display());
        assert_eq!(rel, std::path::Path::new("n-vm/tests/__fuzz__"));
    }

    /// The guest path must not contain a doubled root.
    #[test]
    fn corpus_guest_path_is_a_single_rooted_path() {
        let config = with_corpus(
            "/nix/store/7qpx1j7sqw6zklc13w0v338vwwykjzpl-source/n-vm/tests/integration.rs",
            "/build/source/n-vm",
        );
        assert_eq!(
            config.corpus_guest_path().expect("resolvable"),
            "/workspace/n-vm/tests/__fuzz__",
        );
    }

    /// The anchor is the *last* matching component, so a store hash that
    /// happens to contain the crate name does not win.
    #[test]
    fn corpus_dir_anchors_on_the_last_matching_component() {
        let config = with_corpus(
            "/nix/store/abcd-n-vm-source/n-vm/tests/integration.rs",
            "/build/source/n-vm",
        );
        assert_eq!(
            config.corpus_rel_dir().expect("resolvable"),
            std::path::Path::new("n-vm/tests/__fuzz__"),
        );
    }

    /// Unresolvable rather than silently wrong when there is no anchor; the
    /// caller turns this into an error instead of a read-only corpus.
    #[test]
    fn corpus_dir_is_unresolvable_without_an_anchor() {
        let config = with_corpus(
            "/nix/store/abcd-source/tests/integration.rs",
            "/build/source",
        );
        assert_eq!(config.corpus_rel_dir(), None);
    }

    /// A test that never opted in has no corpus and no error.
    #[test]
    fn no_corpus_opt_in_means_no_corpus_dir() {
        assert_eq!(VmConfig::DEFAULT.corpus_rel_dir(), None);
        assert_eq!(VmConfig::DEFAULT.corpus_guest_path(), None);
    }

    // -- Arch profiles (both arches exercised on a single host) -------

    #[test]
    fn virtual_iommu_lowering_is_coherent_per_arch() {
        // The point of folding the vIOMMU into one object: a lowering must
        // describe at least one way to instantiate the IOMMU -- a `-device`
        // (x86 intel-iommu) or a `-machine` option (aarch64 iommu=smmuv3)
        // -- so it can't be present-but-inert.  `supports_virtual_iommu`
        // tracks `is_some` exactly.
        for arch in [Arch::X86_64, Arch::Aarch64] {
            match arch.virtual_iommu() {
                Some(l) => {
                    assert!(
                        l.device.is_some() || !l.machine_opts.is_empty(),
                        "{arch:?}: lowering must have a device or a machine option",
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
        assert_eq!(a.manifest_name(), "x86_64");
        assert_eq!(a.qemu_machine_base(), "q35");
        assert_eq!(a.pvpanic_device(), "pvpanic");
        assert!(a.console_kernel_params().contains("ttyS0"));
        let viommu = a.virtual_iommu().expect("x86 has a vIOMMU lowering");
        assert!(viommu.device.is_some_and(|d| d.starts_with("intel-iommu")));
        assert_eq!(viommu.machine_opts, "kernel-irqchip=split");
        assert!(viommu.kernel_params.contains("intel_iommu=on"));
        assert!(a.supports_virtual_iommu());
        assert!(a.smp_topology(6).contains("dies="));
    }

    #[test]
    fn arch_aarch64_profile() {
        let a = Arch::Aarch64;
        assert_eq!(a.qemu_system_binary(), "/bin/qemu-system-aarch64");
        assert_eq!(a.manifest_name(), "aarch64");
        assert!(a.qemu_machine_base().starts_with("virt"));
        assert_eq!(a.pvpanic_device(), "pvpanic-pci");
        assert!(a.console_kernel_params().contains("ttyAMA0"));
        // aarch64's SMMUv3 is a machine option, not a device, and is
        // auto-probed (no kernel command-line params).
        let viommu = a.virtual_iommu().expect("aarch64 has an SMMUv3 lowering");
        assert_eq!(viommu.device, None);
        assert_eq!(viommu.machine_opts, "iommu=smmuv3");
        assert!(viommu.kernel_params.is_empty());
        assert!(a.supports_virtual_iommu());
        assert!(
            !a.smp_topology(6).contains("dies="),
            "aarch64 -smp must not use the x86-only dies= level: {}",
            a.smp_topology(6),
        );
    }

    /// Both hypervisors reject a topology whose levels do not multiply to
    /// the vCPU count, so this has to hold for every count a test can ask
    /// for -- not just the default it used to be checked at.
    #[test]
    fn smp_topology_preserves_vcpu_count_on_both_arches() {
        for vcpus in [1, 2, 3, 4, 6, 7, 8, 16, 31, 64] {
            for arch in [Arch::X86_64, Arch::Aarch64] {
                let smp = arch.smp_topology(vcpus);
                assert!(
                    smp.starts_with(&format!("{vcpus},")),
                    "{arch:?} -smp must declare {vcpus} vCPUs: {smp}",
                );
                // sockets * (dies) * cores * threads == vcpus
                let product: u32 = smp
                    .split(',')
                    .skip(1)
                    .filter_map(|kv| kv.split('=').nth(1))
                    .filter_map(|v| v.parse::<u32>().ok())
                    .product();
                assert_eq!(
                    product, vcpus,
                    "{arch:?} topology must multiply to {vcpus}: {smp}"
                );
            }
        }
    }

    /// The default still produces the machine the four hand-written
    /// constants used to: making the count a lever must not silently change
    /// what a test that never sets it boots on.
    #[test]
    fn the_default_vcpu_count_lowers_to_the_topology_it_always_did() {
        assert_eq!(
            Arch::X86_64.smp_topology(VmConfig::DEFAULT.vcpus),
            "6,sockets=1,dies=3,cores=1,threads=2",
        );
    }

    #[test]
    fn kernel_cmdline_includes_hugepage_reservation_for_1g() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let hp = GuestHugePageConfig::Allocate {
            size: GuestHugePageSize::Huge1G,
            count: 1,
        };
        let cmdline = build_kernel_cmdline(
            "/test/bin",
            "my::test",
            &vsock,
            &VmConfig {
                iommu: false,
                guest_hugepages: hp,
                source_file: None,
                ..VmConfig::DEFAULT
            },
            &[],
            Arch::X86_64,
            crate::kernel_manifest::BootMode::Direct,
        );
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
        let cmdline = build_kernel_cmdline(
            "/test/bin",
            "my::test",
            &vsock,
            &VmConfig {
                iommu: false,
                guest_hugepages: hp,
                source_file: None,
                ..VmConfig::DEFAULT
            },
            &[],
            Arch::X86_64,
            crate::kernel_manifest::BootMode::Direct,
        );
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
            &VmConfig {
                guest_hugepages: GuestHugePageConfig::None,
                ..VmConfig::DEFAULT
            },
            &[],
            Arch::X86_64,
            crate::kernel_manifest::BootMode::Direct,
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
            &VmConfig {
                iommu: false,
                guest_hugepages: DEFAULT_HP,
                source_file: None,
                ..VmConfig::DEFAULT
            },
            &[],
            Arch::X86_64,
            crate::kernel_manifest::BootMode::Direct,
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
            &VmConfig {
                iommu: false,
                guest_hugepages: DEFAULT_HP,
                source_file: None,
                ..VmConfig::DEFAULT
            },
            &[],
            Arch::X86_64,
            crate::kernel_manifest::BootMode::Direct,
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
            &VmConfig {
                iommu: false,
                guest_hugepages: DEFAULT_HP,
                source_file: None,
                ..VmConfig::DEFAULT
            },
            &[],
            Arch::X86_64,
            crate::kernel_manifest::BootMode::Direct,
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
            &VmConfig {
                iommu: false,
                guest_hugepages: DEFAULT_HP,
                source_file: None,
                ..VmConfig::DEFAULT
            },
            &[],
            Arch::X86_64,
            crate::kernel_manifest::BootMode::Direct,
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
            &VmConfig {
                iommu: true,
                guest_hugepages: DEFAULT_HP,
                source_file: None,
                ..VmConfig::DEFAULT
            },
            &[],
            Arch::X86_64,
            crate::kernel_manifest::BootMode::Direct,
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
                &VmConfig {
                    iommu,
                    guest_hugepages: DEFAULT_HP,
                    source_file: None,
                    ..VmConfig::DEFAULT
                },
                &[],
                Arch::X86_64,
                crate::kernel_manifest::BootMode::Direct,
            );
            assert!(x86.contains("intel_iommu=on"), "x86 (iommu={iommu}): {x86}");

            let arm = build_kernel_cmdline(
                "/test/bin",
                "my::test",
                &vsock,
                &VmConfig {
                    iommu,
                    guest_hugepages: DEFAULT_HP,
                    source_file: None,
                    ..VmConfig::DEFAULT
                },
                &[],
                Arch::Aarch64,
                crate::kernel_manifest::BootMode::Direct,
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
            &VmConfig {
                iommu: false,
                guest_hugepages: DEFAULT_HP,
                source_file: None,
                ..VmConfig::DEFAULT
            },
            &[],
            Arch::X86_64,
            crate::kernel_manifest::BootMode::Direct,
        );
        assert!(x86.contains("console=ttyS0"), "x86: {x86}");

        let arm = build_kernel_cmdline(
            "/test/bin",
            "my::test",
            &vsock,
            &VmConfig {
                iommu: false,
                guest_hugepages: DEFAULT_HP,
                source_file: None,
                ..VmConfig::DEFAULT
            },
            &[],
            Arch::Aarch64,
            crate::kernel_manifest::BootMode::Direct,
        );
        assert!(arm.contains("console=ttyAMA0"), "aarch64: {arm}");
        assert!(!arm.contains("ttyS0"), "aarch64 must not use ttyS0: {arm}");
    }

    // -- Module parameters and the const builder ----------------------

    #[test]
    fn a_module_param_renders_as_the_kernel_expects() {
        assert_eq!(
            ModuleParam::new("vfio-pci", "disable_idle_d3", "1").render(),
            "vfio-pci.disable_idle_d3=1",
        );
    }

    #[test]
    fn declared_module_params_reach_the_kernel_cmdline() {
        const PARAMS: &[ModuleParam] = &[
            ModuleParam::new("mlx5_core", "prof_sel", "2"),
            ModuleParam::new("vfio-pci", "disable_idle_d3", "1"),
        ];
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let cmdline = build_kernel_cmdline(
            "/test/bin",
            "my::test",
            &vsock,
            &VmConfig {
                module_params: PARAMS,
                ..VmConfig::DEFAULT
            },
            &[],
            Arch::X86_64,
            crate::kernel_manifest::BootMode::Direct,
        );
        assert!(
            cmdline.contains("mlx5_core.prof_sel=2"),
            "cmdline: {cmdline}"
        );
        assert!(
            cmdline.contains("vfio-pci.disable_idle_d3=1"),
            "cmdline: {cmdline}",
        );
        // In the kernel section: everything after `--` is argv for the test
        // binary, where a module parameter would be read by libtest instead.
        let (kernel, _init) = cmdline
            .split_once(" -- ")
            .expect("cmdline has an init separator");
        assert!(
            kernel.contains("mlx5_core.prof_sel=2"),
            "kernel section: {kernel}"
        );
    }

    /// The default carries none, so no test that never asks for one pays a
    /// stray command-line token for the feature existing.
    #[test]
    fn no_module_params_adds_nothing_to_the_cmdline() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let cmdline = build_kernel_cmdline(
            "/test/bin",
            "my::test",
            &vsock,
            &VmConfig::DEFAULT,
            &[],
            Arch::X86_64,
            crate::kernel_manifest::BootMode::Direct,
        );
        assert!(!cmdline.contains("  "), "double space in {cmdline:?}");
    }

    /// The builder is `..VmConfig::DEFAULT` in fluent spelling, so the two
    /// must agree -- otherwise a test converted from one form to the other
    /// would silently boot a different machine.
    #[test]
    fn the_builder_agrees_with_struct_update_syntax() {
        const BUILT: VmConfig = VmConfigBuilder::default()
            .iommu(true)
            .guest_hugepages(GuestHugePageConfig::None)
            .build();
        const WRITTEN: VmConfig = VmConfig {
            iommu: true,
            guest_hugepages: GuestHugePageConfig::None,
            ..VmConfig::DEFAULT
        };
        assert_eq!(BUILT, WRITTEN);
    }

    /// The pairs in the integration suite depend on this: a derived config
    /// must differ in exactly what was named and nowhere else, or "both
    /// backends present the same guest" stops being what those tests check.
    #[test]
    fn to_builder_changes_only_what_is_named() {
        const BASE: VmConfig = VmConfigBuilder::default().iommu(true).build();
        const DERIVED: VmConfig = BASE
            .to_builder()
            .backend(crate::backend::RequestedBackend::Qemu)
            .build();
        assert_eq!(DERIVED.backend, crate::backend::RequestedBackend::Qemu);
        assert_eq!(
            DERIVED.to_builder().backend(BASE.backend).build(),
            BASE,
            "putting the backend back should recover the base exactly",
        );
    }

    /// The check that used to need the backend passed in alongside the value.
    #[test]
    fn a_qemu_only_nic_contradicts_a_pinned_cloud_hypervisor() {
        let pinned = VmConfig {
            nic_model: NicModel::E1000,
            backend: crate::backend::RequestedBackend::CloudHypervisor,
            ..VmConfig::DEFAULT
        };
        assert_eq!(pinned.check(), Err(ConfigProblem::NicRequiresQemu));

        // Unpinned is not a contradiction: it is a test that wants QEMU, and
        // `RequestedBackend::resolve` is what gives it one.
        let unpinned = VmConfig {
            backend: crate::backend::RequestedBackend::Default,
            ..pinned
        };
        assert_eq!(unpinned.check(), Ok(()));
    }

    #[test]
    fn the_default_runtime_is_current_thread() {
        assert_eq!(VmConfig::DEFAULT.runtime, GuestRuntime::CurrentThread);
    }

    #[test]
    fn an_untouched_builder_is_the_default() {
        const BUILT: VmConfig = VmConfigBuilder::default().build();
        assert_eq!(BUILT, VmConfig::DEFAULT);
    }

    /// `build()` runs the same check the generated harness does, so a
    /// contradiction is caught at the builder rather than at launch.  This is
    /// the runtime half; the compile-time half is a `compile_fail` case in
    /// `n-vm-macros`, because a `const` panic cannot be caught here.
    #[test]
    fn the_builder_checks_what_it_builds() {
        let problem = VmConfig {
            guest_hugepages: GuestHugePageConfig::Allocate {
                size: GuestHugePageSize::Huge1G,
                count: 2,
            },
            ..VmConfig::DEFAULT
        }
        .check();
        assert_eq!(problem, Err(ConfigProblem::HugepagesExceedMemory));
    }

    #[test]
    fn kernel_cmdline_uses_virtiofs_root() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let cmdline = build_kernel_cmdline(
            "/test/bin",
            "my::test",
            &vsock,
            &VmConfig {
                iommu: false,
                guest_hugepages: DEFAULT_HP,
                source_file: None,
                ..VmConfig::DEFAULT
            },
            &[],
            Arch::X86_64,
            crate::kernel_manifest::BootMode::Direct,
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
            &VmConfig {
                iommu: false,
                guest_hugepages: DEFAULT_HP,
                source_file: None,
                ..VmConfig::DEFAULT
            },
            &[],
            Arch::X86_64,
            crate::kernel_manifest::BootMode::Direct,
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

    /// Uniqueness across *every* count, not just the default three.
    ///
    /// The MAC, tap name, link-local address and device id are all derived
    /// from the interface index now, so a collision is a bug in the
    /// derivation rather than a typo in a table -- and it would not fail
    /// loudly: the guest brings both links up and forwards out of whichever
    /// answered.
    #[test]
    fn every_interface_is_distinct_at_every_count() {
        for fabric_nics in [0, 1, 2, 3, 8, 64, MAX_FABRIC_NICS] {
            let ifaces = uniform_fabric(fabric_nics).all_ifaces();
            assert_eq!(
                ifaces.len(),
                usize::from(fabric_nics) + 1,
                "expected {fabric_nics} fabric interfaces plus mgmt",
            );

            for (label, mut values) in [
                (
                    "MAC",
                    ifaces.iter().map(|i| i.mac.clone()).collect::<Vec<_>>(),
                ),
                ("TAP", ifaces.iter().map(|i| i.tap.clone()).collect()),
                ("id", ifaces.iter().map(|i| i.id.clone()).collect()),
                (
                    "link-local address",
                    ifaces.iter().map(|i| i.host_ipv6.to_string()).collect(),
                ),
            ] {
                let count = values.len();
                values.sort();
                values.dedup();
                assert_eq!(
                    count,
                    values.len(),
                    "{label}s must be unique at {fabric_nics} fabric NICs",
                );
            }
        }
    }

    /// The bound the engine is given is the memory it can actually reach:
    /// the whole VM, less what the kernel reserves before the engine runs.
    #[test]
    fn a_fuzz_targets_heap_is_bounded_by_the_memory_it_can_reach() {
        const FUZZ: VmConfig = VmConfig {
            corpus: CorpusPolicy::Fuzz,
            ..VmConfig::DEFAULT
        };
        // A fuzz target reserves no hugepages, so only the kernel headroom
        // comes off the top.
        assert_eq!(FUZZ.fuzz_rss_limit_mib(), Some(1024 - 128));
    }

    /// A reservation is memory the guest kernel has given away, so it is
    /// not memory the engine may grow into -- even though nothing stops it
    /// trying.
    #[test]
    fn a_hugepage_reservation_comes_off_the_engines_bound() {
        const FUZZ: VmConfig = VmConfig {
            corpus: CorpusPolicy::Fuzz,
            guest_hugepages: GuestHugePageConfig::DEFAULT_RESERVATION,
            ..VmConfig::DEFAULT
        };
        assert_eq!(FUZZ.fuzz_rss_limit_mib(), Some(1024 - 512 - 128));
    }

    /// Zero would mean "unlimited" to libfuzzer, so a VM with nothing left
    /// reports having nothing left.
    #[test]
    fn a_vm_with_no_room_reports_none_rather_than_an_unlimited_engine() {
        const TINY: VmConfig = VmConfig {
            guest_hugepages: GuestHugePageConfig::None,
            memory_mib: 128,
            ..VmConfig::DEFAULT
        };
        assert_eq!(TINY.fuzz_rss_limit_mib(), None);
        // Not a contradiction on its own: this VM is fine, it just is not
        // one anybody can fuzz in.
        assert_eq!(TINY.check(), Ok(()));
    }

    /// ...and declaring such a VM a fuzz target is a contradiction, caught
    /// where every other one is.
    #[test]
    fn a_fuzz_target_with_no_room_is_rejected() {
        const TINY_FUZZ: VmConfig = VmConfig {
            corpus: CorpusPolicy::Fuzz,
            guest_hugepages: GuestHugePageConfig::None,
            memory_mib: 128,
            ..VmConfig::DEFAULT
        };
        assert_eq!(TINY_FUZZ.check(), Err(ConfigProblem::NoRoomToFuzz));
        assert!(
            TINY_FUZZ
                .validate_memory_alignment()
                .is_err_and(|why| why.contains("fuzz target")),
        );
    }

    /// The default still produces the three interfaces, with the exact
    /// addresses, that used to be written out by hand.
    #[test]
    fn the_default_interfaces_are_the_ones_that_were_hand_written() {
        let ifaces = VmConfig::DEFAULT.all_ifaces();
        let described: Vec<_> = ifaces
            .iter()
            .map(|i| {
                (
                    i.id.as_str(),
                    i.mac.as_str(),
                    i.host_ipv6.to_string(),
                    i.mtu,
                )
            })
            .collect();
        assert_eq!(
            described,
            vec![
                ("mgmt", "02:DE:AD:BE:EF:01", "fe80::ffff:1".to_owned(), 1500),
                ("fabric1", "02:CA:FE:BA:BE:01", "fe80::1".to_owned(), 9500),
                ("fabric2", "02:CA:FE:BA:BE:02", "fe80::2".to_owned(), 9500),
            ],
        );
    }

    /// A mixed fabric is what a startup-sequence test needs: the links
    /// differ, so "the second NIC" and "the virtio NIC" are different
    /// devices and picking the wrong rule is visible.
    #[test]
    fn each_link_in_a_mixed_fabric_is_the_model_it_named() {
        const MIXED: VmConfig = VmConfig {
            fabric: FabricNics::Mixed(&[NicModel::VirtioNet, NicModel::E1000, NicModel::E1000E]),
            ..VmConfig::DEFAULT
        };
        let models: Vec<_> = MIXED.all_ifaces().iter().map(|i| i.model).collect();
        assert_eq!(
            models,
            vec![
                // The management link keeps the VM's own model: it is how
                // the harness reaches the guest, so it is the one thing a
                // test of device identification should hold fixed.
                NicModel::VirtioNet,
                NicModel::VirtioNet,
                NicModel::E1000,
                NicModel::E1000E,
            ],
        );
    }

    /// The count spelling still means what it meant: every link the same.
    #[test]
    fn a_uniform_fabric_takes_the_vms_own_model() {
        const UNIFORM: VmConfig = VmConfig {
            nic_model: NicModel::E1000,
            fabric: FabricNics::Uniform(2),
            backend: crate::backend::RequestedBackend::Qemu,
            ..VmConfig::DEFAULT
        };
        assert!(
            UNIFORM
                .all_ifaces()
                .iter()
                .all(|i| i.model == NicModel::E1000),
        );
    }

    /// One emulated link anywhere in the machine decides the hypervisor for
    /// the whole machine -- there is no per-device backend.
    #[test]
    fn an_emulated_link_anywhere_pins_qemu() {
        const MIXED: VmConfig = VmConfig {
            fabric: FabricNics::Mixed(&[NicModel::VirtioNet, NicModel::E1000E]),
            ..VmConfig::DEFAULT
        };
        assert_eq!(MIXED.first_qemu_only_nic(), Some(NicModel::E1000E));

        const PINNED: VmConfig = VmConfig {
            backend: crate::backend::RequestedBackend::CloudHypervisor,
            ..MIXED
        };
        assert_eq!(PINNED.check(), Err(ConfigProblem::NicRequiresQemu));
    }

    /// An all-virtio mixed fabric is not a QEMU-only machine.  Worth
    /// pinning: reading "mixed" as "emulated" would quietly take every
    /// mixed test off the default backend.
    #[test]
    fn a_mixed_fabric_of_virtio_links_still_runs_anywhere() {
        const MIXED: VmConfig = VmConfig {
            fabric: FabricNics::Mixed(&[NicModel::VirtioNet, NicModel::VirtioNet]),
            backend: crate::backend::RequestedBackend::CloudHypervisor,
            ..VmConfig::DEFAULT
        };
        assert_eq!(MIXED.first_qemu_only_nic(), None);
        assert_eq!(MIXED.check(), Ok(()));
    }

    /// The management link counts too, so a VM with no fabric at all can
    /// still be one only QEMU can run.
    #[test]
    fn an_emulated_management_link_pins_qemu_with_no_fabric_at_all() {
        const MGMT_ONLY: VmConfig = VmConfig {
            nic_model: NicModel::E1000,
            fabric: FabricNics::Uniform(0),
            backend: crate::backend::RequestedBackend::CloudHypervisor,
            ..VmConfig::DEFAULT
        };
        assert_eq!(MGMT_ONLY.first_qemu_only_nic(), Some(NicModel::E1000));
        assert_eq!(MGMT_ONLY.check(), Err(ConfigProblem::NicRequiresQemu));
    }

    /// Only the fabric links sit on the segment the vIOMMU protects.
    #[test]
    fn management_stays_off_the_protected_segment() {
        let ifaces = uniform_fabric(4).all_ifaces();
        assert_eq!(ifaces[0].pci_segment, 0, "mgmt is unprotected");
        assert!(
            ifaces[1..].iter().all(|i| i.pci_segment == 1),
            "every fabric link belongs behind the vIOMMU",
        );
    }

    /// A test that never touches the network can ask for no fabric links,
    /// and still gets a machine.
    #[test]
    fn a_vm_can_have_no_fabric_interfaces() {
        let ifaces = uniform_fabric(0).all_ifaces();
        assert_eq!(ifaces.len(), 1);
        assert_eq!(ifaces[0].id, "mgmt");
    }

    /// Beyond the derivation's range the configuration is rejected rather
    /// than silently issuing a duplicate address.
    #[test]
    fn more_fabric_interfaces_than_addresses_is_rejected() {
        assert_eq!(uniform_fabric(MAX_FABRIC_NICS).check(), Ok(()));
        assert_eq!(
            uniform_fabric(MAX_FABRIC_NICS + 1).check(),
            Err(ConfigProblem::TooManyNics),
        );
        // A named-model fabric is counted the same way, and by its length
        // rather than by a number somebody wrote next to it.
        const TOO_MANY: &[NicModel] = &[NicModel::VirtioNet; MAX_FABRIC_NICS as usize + 1];
        const MIXED: VmConfig = VmConfig {
            fabric: FabricNics::Mixed(TOO_MANY),
            ..VmConfig::DEFAULT
        };
        assert_eq!(MIXED.check(), Err(ConfigProblem::TooManyNics));
    }

    #[test]
    fn topology_multiplies_to_vcpu_count() {
        for vcpus in 1..=64 {
            let t = SmpTopology::for_vcpus(vcpus);
            assert_eq!(
                t.sockets * t.dies * t.cores * t.threads,
                vcpus,
                "topology for {vcpus} vCPUs does not multiply back: {t:?}",
            );
        }
    }

    /// An even count keeps SMT, because that is the shape of every machine
    /// this code runs on in production and the guest inspects its own
    /// topology to lay lcores out.
    #[test]
    fn an_even_vcpu_count_keeps_hyperthreads() {
        assert_eq!(SmpTopology::for_vcpus(8).threads, 2);
        assert_eq!(SmpTopology::for_vcpus(1).threads, 1);
        assert_eq!(SmpTopology::for_vcpus(7).threads, 1);
    }

    #[test]
    fn default_config_passes_memory_alignment_validation() {
        VmConfig::default()
            .validate_memory_alignment()
            .expect("default VmConfig should pass memory alignment validation");
    }

    // -- Const configuration ------------------------------------------

    /// `Default` delegates to `DEFAULT`, so the two cannot drift.  A derived
    /// `Default` would consult each field's own `Default` independently and
    /// nothing would notice if the answers diverged.
    #[test]
    fn default_trait_matches_the_default_const() {
        assert_eq!(VmConfig::default(), VmConfig::DEFAULT);
    }

    /// The point of `assert_valid` is that it runs at compile time.  This
    /// item *is* the assertion: if `assert_valid` ever stopped being
    /// const-evaluable, this would fail to compile rather than fail a test.
    const _: () = VmConfig::DEFAULT.assert_valid();

    /// Struct update syntax has to work in a `const`, since that is how
    /// every call site is expected to spell an override.
    const OVERRIDDEN: VmConfig = VmConfig {
        iommu: true,
        guest_hugepages: GuestHugePageConfig::None,
        ..VmConfig::DEFAULT
    };
    const _: () = OVERRIDDEN.assert_valid();

    // The overridden fields are checked at compile time -- there is nothing
    // to run, and asserting on a const at run time only defers the answer.
    // `matches!` rather than `==` because `PartialEq` is a trait, and trait
    // methods are not callable in a const.
    const _: () = assert!(OVERRIDDEN.iommu);
    const _: () = assert!(matches!(
        OVERRIDDEN.guest_hugepages,
        GuestHugePageConfig::None
    ));

    /// Fields the update did not name must keep the default.  This one stays
    /// a runtime test precisely so it can compare *against*
    /// `VmConfig::DEFAULT` rather than restating its values -- which would
    /// pass even if the defaults changed underneath it.
    #[test]
    fn struct_update_leaves_unnamed_fields_at_the_default() {
        assert_eq!(OVERRIDDEN.host_page_size, VmConfig::DEFAULT.host_page_size);
        assert_eq!(OVERRIDDEN.nic_model, VmConfig::DEFAULT.nic_model);
        assert_eq!(OVERRIDDEN.source_file, VmConfig::DEFAULT.source_file);
    }

    #[test]
    fn check_rejects_hugepages_larger_than_vm_memory() {
        let config = VmConfig {
            guest_hugepages: GuestHugePageConfig::Allocate {
                size: GuestHugePageSize::Huge1G,
                // VM memory is 1 GiB, so two 1 GiB pages cannot fit.
                count: 2,
            },
            ..VmConfig::DEFAULT
        };
        assert_eq!(
            config.check(),
            Err(ConfigProblem::HugepagesExceedMemory),
            "reserving more hugepages than the VM has memory must be rejected",
        );
    }

    /// The runtime formatter and the const check must agree on *whether* a
    /// config is valid; they differ only in how much detail the message can
    /// carry.  Sharing one `check` is what keeps them from drifting.
    #[test]
    fn runtime_validation_agrees_with_the_const_check() {
        let configs = [
            VmConfig::DEFAULT,
            OVERRIDDEN,
            VmConfig {
                guest_hugepages: GuestHugePageConfig::Allocate {
                    size: GuestHugePageSize::Huge1G,
                    count: 2,
                },
                ..VmConfig::DEFAULT
            },
            VmConfig {
                host_page_size: HostPageSize::Standard,
                ..VmConfig::DEFAULT
            },
        ];
        for config in configs {
            assert_eq!(
                config.check().is_ok(),
                config.validate_memory_alignment().is_ok(),
                "const check and runtime validation disagree on {config:?}",
            );
        }
    }

    /// The runtime path exists to say more than a const panic can, so it
    /// should actually name the numbers involved.
    #[test]
    fn runtime_validation_message_names_the_numbers() {
        let config = VmConfig {
            guest_hugepages: GuestHugePageConfig::Allocate {
                size: GuestHugePageSize::Huge1G,
                count: 2,
            },
            ..VmConfig::DEFAULT
        };
        let err = config
            .validate_memory_alignment()
            .expect_err("two 1 GiB hugepages exceed 1 GiB of VM memory");
        assert!(
            err.contains('2') && err.contains(&VmConfig::DEFAULT.memory_bytes().to_string()),
            "message should carry the reservation and the VM memory: {err}",
        );
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
            "100 x 1G hugepages should exceed VM memory",
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
    fn memory_bytes_follows_memory_mib() {
        for mib in [1, 512, 1024, 4096, 65536] {
            let config = VmConfig {
                memory_mib: mib,
                ..VmConfig::DEFAULT
            };
            assert_eq!(config.memory_bytes(), i64::from(mib) * 1024 * 1024);
        }
    }

    /// Shrinking the VM below its own hugepage reservation is caught, and
    /// caught at build time.
    ///
    /// The two levers are independent to write and not independent in
    /// effect: `guest_hugepages` defaults to 512 MiB, so asking for a
    /// smaller VM without also lowering it describes a guest whose kernel
    /// has no room to boot.  Left unchecked the guest reports
    /// "HugeTLB: allocating ... failed" on a console nobody reads and boots
    /// without them, which surfaces much later as a test failure with
    /// nothing pointing here.
    #[test]
    fn a_vm_too_small_for_its_own_hugepages_is_rejected() {
        let config = VmConfig {
            memory_mib: 256,
            ..VmConfig::DEFAULT
        };
        assert_eq!(config.check(), Err(ConfigProblem::HugepagesExceedMemory));
    }

    /// ...and lowering the reservation with it is accepted.
    #[test]
    fn a_small_vm_that_declines_hugepages_is_fine() {
        let config = VmConfig {
            memory_mib: 256,
            guest_hugepages: GuestHugePageConfig::None,
            ..VmConfig::DEFAULT
        };
        assert_eq!(config.check(), Ok(()));
    }

    /// A VM with nothing in it is rejected before any check that would
    /// pass vacuously on it.
    #[test]
    fn an_empty_vm_is_rejected() {
        let no_memory = VmConfig {
            memory_mib: 0,
            ..VmConfig::DEFAULT
        };
        assert_eq!(no_memory.check(), Err(ConfigProblem::NoMemory));

        let no_cpus = VmConfig {
            vcpus: 0,
            ..VmConfig::DEFAULT
        };
        assert_eq!(no_cpus.check(), Err(ConfigProblem::NoVcpus));
    }

    /// Memory must still be a whole number of host pages, now measured
    /// against the configured size rather than a constant.
    #[test]
    fn memory_must_be_a_whole_number_of_host_pages() {
        let unaligned = VmConfig {
            memory_mib: 1536,
            host_page_size: HostPageSize::Huge1G,
            guest_hugepages: GuestHugePageConfig::None,
            ..VmConfig::DEFAULT
        };
        assert_eq!(unaligned.check(), Err(ConfigProblem::MemoryNotAligned));

        let aligned = VmConfig {
            memory_mib: 2048,
            ..unaligned
        };
        assert_eq!(aligned.check(), Ok(()));
    }
}
