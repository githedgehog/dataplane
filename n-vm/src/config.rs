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
    pub guest_hugepages: GuestHugePageConfig,
    /// NIC model for all network interfaces in the VM.
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
    /// Kernel module parameters to set on the guest command line.
    ///
    /// Rendered as `<module>.<key>=<value>` into the kernel section of the
    /// command line.  A module does not have to be built in for this to
    /// apply: the kernel stores parameters for modules that are not loaded
    /// yet and applies them at load time, so this composes with a
    /// [`KernelFeature`](crate::kernel_feature::KernelFeature) declared
    /// `modular`.
    pub module_params: &'static [ModuleParam],
    /// The test's own `(file!(), CARGO_MANIFEST_DIR)` when it opted in to a
    /// writable corpus directory via `#[corpus]`; `None` otherwise.
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
    pub corpus_source_file: Option<(&'static str, &'static str)>,
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

    /// Sets the guest's own hugepage reservation.
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
        guest_hugepages: GuestHugePageConfig::Allocate {
            size: GuestHugePageSize::Huge2M,
            count: 256,
        },
        nic_model: NicModel::VirtioNet,
        kernel_features: &[],
        module_params: &[],
        corpus_source_file: None,
    };

    /// Checks the configuration for internal contradictions.
    ///
    /// `const` so the same check can run at compile time; see
    /// [`assert_valid`](Self::assert_valid).
    ///
    /// # Errors
    ///
    /// Returns the first [`ConfigProblem`] found.
    pub const fn check(&self) -> Result<(), ConfigProblem> {
        let page_bytes = self.host_page_size.bytes();
        if VM_MEMORY_BYTES % page_bytes != 0 {
            return Err(ConfigProblem::MemoryNotAligned);
        }
        if let GuestHugePageConfig::Allocate { size, count } = self.guest_hugepages {
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
            if required + GUEST_KERNEL_HEADROOM_BYTES > VM_MEMORY_BYTES {
                return Err(ConfigProblem::HugepagesExceedMemory);
            }
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
        }
    }

    /// Rejects a configuration that cannot work with the requested backend.
    ///
    /// The config itself is a `const` the macro cannot read, but the
    /// *backend* is one of the macro's own arguments -- so combining them in
    /// a `const fn` keeps this a compile error rather than demoting it to a
    /// runtime skip.  That matters because a NIC model the chosen hypervisor
    /// cannot emulate is a contradiction in the test as written, true on
    /// every host, and it should not need a VM boot to discover.
    ///
    /// [`RequestedBackend::Default`] is deliberately permissive: an
    /// unpinned test that asks for an emulated NIC is not a contradiction,
    /// it is a test that wants QEMU, and
    /// [`resolve`](crate::backend::RequestedBackend::resolve) selects it.
    ///
    /// # Panics
    ///
    /// Panics if [`check`](Self::check) fails, or if the NIC model requires
    /// QEMU while the test explicitly pinned cloud-hypervisor.
    pub const fn assert_valid_for(&self, backend: crate::backend::RequestedBackend) {
        self.assert_valid();
        if self.nic_model.requires_qemu()
            && matches!(backend, crate::backend::RequestedBackend::CloudHypervisor)
        {
            panic!(
                "this NIC model is emulated only by QEMU, but the test pinned \
                 cloud-hypervisor; drop the backend argument to let the harness \
                 pick QEMU, or write #[n_vm::test(qemu)]"
            );
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
    /// [`Self::corpus_source_file`]: the remap prepends the workspace's
    /// store path, so the workspace-relative tail is recovered by cutting at
    /// the crate directory's own name, which is where the manifest dir and
    /// the source path necessarily agree.  `rposition` because the anchor is
    /// the *last* such component -- a store hash like `abc-n-vm-source`
    /// would otherwise match ahead of the real crate directory.
    ///
    /// `None` when the test did not opt in, when the path has no parent to
    /// hang `__fuzz__` off, or when the anchor is absent (a crate sitting at
    /// the workspace root, whose directory name the remapped prefix does not
    /// preserve).  Callers must treat `None` on an opted-in test as an
    /// error: a missing corpus mount otherwise surfaces as a confusing
    /// read-only failure inside the guest.
    #[must_use]
    pub fn corpus_rel_dir(&self) -> Option<std::path::PathBuf> {
        use std::path::{Component, Path, PathBuf};

        let (file, crate_dir) = self.corpus_source_file?;
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
            Err(ConfigProblem::MemoryNotAligned) => Err(format!(
                "VM_MEMORY_BYTES ({VM_MEMORY_BYTES}) is not aligned to \
                 host page size ({page_bytes} bytes)",
                page_bytes = self.host_page_size.bytes(),
            )),
            Err(ConfigProblem::HugepagesExceedMemory) => {
                let GuestHugePageConfig::Allocate { size, count } = self.guest_hugepages else {
                    unreachable!(
                        "HugepagesExceedMemory is only reachable when hugepages are allocated"
                    )
                };
                let required = size.bytes() * i64::from(count);
                Err(format!(
                    "guest hugepage reservation ({count} x {} = {required} bytes) \
                     exceeds VM memory ({VM_MEMORY_BYTES} bytes)",
                    size.bytes(),
                ))
            }
        }
    }
}

/// Total guest memory in MiB (1 GiB).
pub(crate) const VM_MEMORY_MIB: u32 = 1024;

/// Total guest memory in bytes (1 GiB).
pub(crate) const VM_MEMORY_BYTES: i64 = (VM_MEMORY_MIB as i64) * 1024 * 1024;

/// Guest memory a hugepage reservation must leave for the kernel that performs it.
///
/// Not a measurement -- a floor. The kernel reserves hugepages very early, but not before it
/// exists, so a reservation may not name the whole of RAM. 128 MiB is enough for the kernels this
/// boots and small enough not to constrain a reservation anybody would actually want.
pub(crate) const GUEST_KERNEL_HEADROOM_BYTES: i64 = 128 * 1024 * 1024;

// The topology must satisfy:
//   VM_SOCKETS x VM_DIES_PER_PACKAGE x VM_CORES_PER_DIE x VM_THREADS_PER_CORE == VM_VCPUS

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
    // Grouped rather than passed field by field: `iommu`, the hugepage
    // reservation and the corpus mount all come from here, and threading
    // them separately made the signature grow every time the config did.
    vm_config: &VmConfig,
    arch: Arch,
    boot: crate::kernel_manifest::BootMode,
) -> String {
    let vsock_cmdline = vsock.kernel_cmdline_fragment();
    let iommu = vm_config.iommu;
    let guest_hugepages = &vm_config.guest_hugepages;
    let corpus_mount = vm_config.corpus_guest_path();
    let corpus_mount = corpus_mount.as_deref();

    // Without a vIOMMU, allow DPDK to bind devices via vfio-pci.
    let noiommu_fragment = if iommu {
        ""
    } else {
        "vfio.enable_unsafe_noiommu_mode=1 "
    };

    let hugepage_fragment = guest_hugepages.kernel_cmdline_fragment();

    // Module parameters, in the kernel section (before `--`).  Each was
    // checked for shape when it was declared, so this only has to join them.
    let module_param_fragment = vm_config
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

    // Where `n-it` should mount the writable corpus share.  Absent unless
    // the test opted in via `#[corpus]`, in which case the guest never sees
    // a writable filesystem backed by the source tree at all.
    let corpus_fragment = corpus_mount.map_or_else(String::new, |path| {
        format!("{key}={path} ", key = n_vm_protocol::CMDLINE_CORPUS_MOUNT)
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

    const DEFAULT_HP: GuestHugePageConfig = GuestHugePageConfig::Allocate {
        size: GuestHugePageSize::Huge1G,
        count: 1,
    };

    // -- Corpus paths -------------------------------------------------

    fn with_corpus(file: &'static str, crate_dir: &'static str) -> VmConfig {
        VmConfig {
            corpus_source_file: Some((file, crate_dir)),
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
        assert!(a.smp_topology().contains("dies="));
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
        let cmdline = build_kernel_cmdline(
            "/test/bin",
            "my::test",
            &vsock,
            &VmConfig {
                iommu: false,
                guest_hugepages: hp,
                corpus_source_file: None,
                ..VmConfig::DEFAULT
            },
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
                corpus_source_file: None,
                ..VmConfig::DEFAULT
            },
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
                corpus_source_file: None,
                ..VmConfig::DEFAULT
            },
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
                corpus_source_file: None,
                ..VmConfig::DEFAULT
            },
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
                corpus_source_file: None,
                ..VmConfig::DEFAULT
            },
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
                corpus_source_file: None,
                ..VmConfig::DEFAULT
            },
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
                corpus_source_file: None,
                ..VmConfig::DEFAULT
            },
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
                    corpus_source_file: None,
                    ..VmConfig::DEFAULT
                },
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
                    corpus_source_file: None,
                    ..VmConfig::DEFAULT
                },
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
                corpus_source_file: None,
                ..VmConfig::DEFAULT
            },
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
                corpus_source_file: None,
                ..VmConfig::DEFAULT
            },
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
            Arch::X86_64,
            crate::kernel_manifest::BootMode::Direct,
        );
        assert!(cmdline.contains("mlx5_core.prof_sel=2"), "cmdline: {cmdline}");
        assert!(
            cmdline.contains("vfio-pci.disable_idle_d3=1"),
            "cmdline: {cmdline}",
        );
        // In the kernel section: everything after `--` is argv for the test
        // binary, where a module parameter would be read by libtest instead.
        let (kernel, _init) = cmdline.split_once(" -- ").expect("cmdline has an init separator");
        assert!(kernel.contains("mlx5_core.prof_sel=2"), "kernel section: {kernel}");
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
                corpus_source_file: None,
                ..VmConfig::DEFAULT
            },
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
                corpus_source_file: None,
                ..VmConfig::DEFAULT
            },
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
            "topology ({VM_SOCKETS}S x {VM_DIES_PER_PACKAGE}D x \
             {VM_CORES_PER_DIE}C x {VM_THREADS_PER_CORE}T = {total}) \
             must equal VM_VCPUS ({VM_VCPUS})",
        );
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
        assert_eq!(
            OVERRIDDEN.corpus_source_file,
            VmConfig::DEFAULT.corpus_source_file
        );
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
            err.contains('2') && err.contains(&VM_MEMORY_BYTES.to_string()),
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
    fn memory_mib_and_bytes_are_consistent() {
        assert_eq!(
            VM_MEMORY_BYTES,
            (VM_MEMORY_MIB as i64) * 1024 * 1024,
            "VM_MEMORY_BYTES and VM_MEMORY_MIB must be consistent",
        );
    }
}
