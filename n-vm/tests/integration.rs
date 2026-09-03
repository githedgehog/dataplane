// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use n_vm::{
    CorpusPolicy, GuestHugePageConfig, GuestHugePageSize, GuestRuntime, HostPageSize, ModuleParam,
    RequestedBackend, VmConfig, VmConfigBuilder, features,
};

/// Reads the first `len` bytes of `path`, or the whole file if it is shorter.
fn read_prefix(path: &str, len: usize) -> Vec<u8> {
    use std::io::Read;

    let mut file = std::fs::File::open(path).unwrap_or_else(|e| panic!("cannot open {path}: {e}"));
    let mut buf = Vec::with_capacity(len);
    file.by_ref()
        .take(len as u64)
        .read_to_end(&mut buf)
        .unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    assert!(!buf.is_empty(), "{path} is empty");
    buf
}

fn hugepages_total() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .unwrap()
        .lines()
        .find(|l| l.starts_with("HugePages_Total:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

// -- Configurations under test ----------------------------------------
//
// Named once and shared, which is most of the point: the same VM shape can
// be exercised on both backends without restating it, and the names say what
// each one is for at the call site.

/// A virtual IOMMU.  Both backends support one; only the aarch64 *guest*
/// lacks a lowering, which the container tier resolves to a skip.
const IOMMU_VM: VmConfig = VmConfig {
    iommu: true,
    ..VmConfig::DEFAULT
};

/// 1 GiB host pages, which is the one thing the default deliberately does not ask for.
///
/// The default backs guest memory with 4 KiB pages because the host pool is small, unarbitrated,
/// and irrelevant to a guest that is not driving DPDK through an IOMMU. That makes this the only
/// test of the hugetlbfs path, and it is here so that flipping the default did not silently
/// delete the coverage it used to get for free.
const HOST_1G_VM: VmConfig = VmConfig {
    host_page_size: HostPageSize::Huge1G,
    ..VmConfig::DEFAULT
};

/// The same VMs on QEMU.
///
/// Two configurations rather than one config and a backend argument, because
/// that is what they are: the pair exists to check that both hypervisors
/// present the same guest, which is only a claim worth making if each side
/// names the machine it booted.  `to_builder` keeps the derivation to one
/// line, so the shape is still stated once.
const IOMMU_VM_QEMU: VmConfig = IOMMU_VM
    .to_builder()
    .backend(RequestedBackend::Qemu)
    .build();
const HOST_1G_VM_QEMU: VmConfig = HOST_1G_VM
    .to_builder()
    .backend(RequestedBackend::Qemu)
    .build();

/// The same path at a page size a host will actually hand over.
///
/// A 1 GiB page has to come from a physically contiguous gigabyte, so a
/// machine that has been up a while generally cannot produce one on request
/// -- the kernel expects them reserved at boot. 2 MiB pages allocate at
/// runtime and reliably. What is lost is real but narrow: only DPDK driving a
/// device through an IOMMU can tell a contiguous gigabyte from 512 contiguous
/// megabytes. Everything between here and there -- asking for a hugepage
/// backing at all, `memfd` with `MFD_HUGE_*`, the pool accounting, and both
/// VMMs' plumbing for it -- is the same code, and this is what keeps it
/// covered on a host that cannot host the 1 GiB version.
const HOST_2M_VM: VmConfig = VmConfig {
    host_page_size: HostPageSize::Huge2M,
    ..VmConfig::DEFAULT
};
const HOST_2M_VM_QEMU: VmConfig = HOST_2M_VM
    .to_builder()
    .backend(RequestedBackend::Qemu)
    .build();

/// QEMU, otherwise default.  Pinned because these assert on the initramfs
/// boot path, which only QEMU takes under the `modular` profile.
const QEMU_VM: VmConfig = VmConfigBuilder::default()
    .backend(RequestedBackend::Qemu)
    .build();

/// No guest hugepage reservation at all.
const NO_GUEST_HUGEPAGES_VM: VmConfig = VmConfig {
    guest_hugepages: GuestHugePageConfig::None,
    ..VmConfig::DEFAULT
};

/// 64 x 2 MiB guest hugepages.
const GUEST_2M_HUGEPAGES_VM: VmConfig = VmConfig {
    guest_hugepages: GuestHugePageConfig::Allocate {
        size: GuestHugePageSize::Huge2M,
        count: 64,
    },
    ..VmConfig::DEFAULT
};

/// 4 KiB host pages *and* 64 x 2 MiB guest hugepages -- the guest can back
/// hugepages that the host is not itself backing with hugepages.
const HOST_4K_GUEST_2M_VM: VmConfig = VmConfig {
    host_page_size: HostPageSize::Standard,
    guest_hugepages: GuestHugePageConfig::Allocate {
        size: GuestHugePageSize::Huge2M,
        count: 64,
    },
    iommu: true,
    ..VmConfig::DEFAULT
};

/// The same, on QEMU.
const HOST_4K_GUEST_2M_VM_QEMU: VmConfig = HOST_4K_GUEST_2M_VM
    .to_builder()
    .backend(RequestedBackend::Qemu)
    .build();

/// The multi-threaded guest runtime, with a pinned worker count.
const MULTI_THREAD_VM: VmConfig = VmConfigBuilder::default()
    .runtime(GuestRuntime::MultiThread {
        worker_threads: Some(2),
    })
    .build();

/// Declares the kernel features it actually leans on.
///
/// `hugetlbfs` and the `tc` flower classifier are both checked against the
/// kernel's own config before the VM boots, so a fragment list that stopped
/// providing them would fail here by name rather than somewhere far from the
/// cause.
const TC_VM: VmConfig = VmConfig {
    kernel_features: &[features::HUGETLBFS, features::NET_CLS_FLOWER],
    // 4 KiB host pages so this runs on a host with no hugepage reservation.
    host_page_size: HostPageSize::Standard,
    ..VmConfig::DEFAULT
};

#[n_vm::test]
fn test_which_runs_in_vm() {
    assert_eq!(2 + 2, 4);
}

/// The declared-requirement path, end to end: these features are verified
/// against `kernels/<profile>/config` before launch, and the VM boots.
#[n_vm::test(config = TC_VM)]
fn vm_boots_with_declared_kernel_features() {
    // `tc` flower needs both the classifier and action support; if the
    // pre-boot check passed, the kernel really does have them.
    assert!(std::path::Path::new("/proc/net").exists());
}

// NOTE: there is deliberately no `#[n_vm::test] #[should_panic]` negative
// control here.  `#[should_panic]` does not compose with `#[n_vm::test]` (the
// body runs in a separate VM-guest process across three dispatch tiers, so
// the panic is absorbed inconsistently) and the macro now rejects it.  The
// "does the harness actually detect failures" property is covered at the
// unit level by the verdict-decoding tests (`cloud_hypervisor::events`,
// `n_vm_protocol::TestResult` parse tests: an absent/failed verdict ->
// failure), not by a panicking end-to-end test.

/// A file on the read-only share reads back the same after its pages are
/// dropped and refetched.
///
/// This is the property the harness silently depended on and never checked,
/// and getting it wrong cost a lot: every aarch64 test failed for a whole
/// debugging session, presenting as guest userspace corruption -- garbage ELF
/// relocations, pointers with their low word zeroed, jumps into `.rodata` --
/// which looked convincingly like a guest kernel misconfiguration and was
/// chased as one through many kernel configs before virtiofsd's cache policy
/// turned out to be the cause.
///
/// Refetching is the specific thing to exercise.  Sweeping virtiofsd's four
/// policies on aarch64 showed `auto`, `never` and `metadata` all faulting and
/// only `always` surviving, and what the three failures share is that a file
/// page can have to be fetched more than once.  So this drops the guest page
/// cache between two reads to force exactly that, rather than reading twice
/// and being served the same cached copy both times.
///
/// `drop_caches` frees only clean, unreferenced pages, so it cannot evict the
/// running binary's own mapped text -- the process stays alive to make the
/// assertion, which a broader eviction would not allow.
///
/// Deliberately not a hash against a value baked in at build time: the share
/// serves the developer's live workspace, so any uncommitted edit would fail
/// such a test for a reason that has nothing to do with virtiofs.
#[n_vm::test]
fn file_on_read_only_share_survives_a_page_cache_drop() {
    // The test binary itself: guaranteed present, served by the same
    // virtiofsd as everything else the guest executes, and far larger than
    // one page, so the comparison spans many.
    const SLICE: usize = 4 * 1024 * 1024;
    let exe = std::fs::read_link("/proc/self/exe")
        .expect("the guest should be able to resolve /proc/self/exe");
    let exe = exe.to_str().expect("test binary path should be UTF-8");

    let before = read_prefix(exe, SLICE);

    // 3 = page cache + reclaimable slab.  A write to this is what forces the
    // next read to come from the host again instead of the guest's cache.
    std::fs::write("/proc/sys/vm/drop_caches", b"3\n")
        .expect("the guest should be able to drop its page cache");

    let after = read_prefix(exe, SLICE);

    assert_eq!(
        before.len(),
        after.len(),
        "read {} bytes before dropping caches and {} after",
        before.len(),
        after.len(),
    );
    // Compared by position rather than with `assert_eq!` on the buffers,
    // because a mismatch dumping 4 MiB of bytes is unreadable and the offset
    // is the useful part: it says which page came back wrong.
    if let Some(at) = (0..before.len()).find(|&i| before[i] != after[i]) {
        panic!(
            "{exe} changed across a page cache drop at offset {at} \
             (0x{at:x}, page {page}): {b:#04x} -> {a:#04x}.  The guest \
             refetched this file and got different bytes, so mappings of it \
             -- including executable ones -- cannot be trusted.",
            page = at / 4096,
            b = before[at],
            a = after[at],
        );
    }
}

#[n_vm::test]
fn root_filesystem_in_vm_is_read_only() {
    let error = std::fs::File::create_new("/some.file").unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ReadOnlyFilesystem);
}

#[n_vm::test]
fn run_filesystem_in_vm_is_read_write() {
    std::fs::File::create_new("/run/some.file").unwrap();
}

#[n_vm::test]
fn tmp_filesystem_in_vm_is_read_write() {
    std::fs::File::create_new("/tmp/some.file").unwrap();
}

#[n_vm::test(config = IOMMU_VM)]
fn test_which_runs_in_vm_with_iommu() {
    assert_eq!(2 + 2, 4);
}

#[n_vm::test(config = IOMMU_VM_QEMU)]
fn test_which_runs_in_vm_with_qemu_iommu() {
    assert_eq!(2 + 2, 4);
}

/// The four tests below need a host hugepage pool, and CI does not have one.
///
/// Gated rather than deleted, and gated rather than skipped. They are valid
/// tests of a path that matters -- a host hugepage is what makes a guest's
/// memory physically contiguous, which is the only thing DPDK driving a
/// device through an IOMMU can tell apart -- and they pass on a workstation
/// that reserves pages. What they are not is something CI should be arranging
/// for itself.
///
/// Reserving pages *from* CI was tried and withdrawn. A privileged container
/// does reach the host's `nr_hugepages`, so it works mechanically, but 1 GiB
/// pages need a physically contiguous gigabyte the kernel could not find
/// (0 allocated, before and after compaction), and pinning 2 MiB pages on a
/// shared runner took memory away from everything else on it: the coverage
/// suite went from 76s to 155s and `a_vm_boots_the_kernel_profile_it_named`
/// from 3s to 96s, its guest going silent. Reserving at boot --
/// `default_hugepagesz=1G hugepagesz=1G hugepages=4` -- is the arrangement
/// that costs nothing at run time, and it is the runner's to make.
///
/// `#[cfg_attr(not(host_hugepage_tests), ignore)]` rather than n-vm's own
/// skip: a skip is the right answer to a mismatch that is permanent and true
/// everywhere, like cloud-hypervisor being unable to emulate aarch64. This is
/// not that. Run them with:
///
/// ```text
/// RUSTFLAGS='--cfg=host_hugepage_tests' cargo test -p dataplane-n-vm --test integration
/// ```
///
/// or on any host with pages, `cargo test ... -- --ignored`.
#[n_vm::test(config = HOST_1G_VM)]
#[cfg_attr(
    not(host_hugepage_tests),
    ignore = "needs a host hugepage pool; run with --cfg=host_hugepage_tests"
)]
fn vm_boots_with_host_hugepages() {
    assert!(std::path::Path::new("/proc/meminfo").exists());
}

/// See [`vm_boots_with_host_hugepages`].
#[n_vm::test(config = HOST_1G_VM_QEMU)]
#[cfg_attr(
    not(host_hugepage_tests),
    ignore = "needs a host hugepage pool; run with --cfg=host_hugepage_tests"
)]
fn vm_boots_with_host_hugepages_on_qemu() {
    assert!(std::path::Path::new("/proc/meminfo").exists());
}

/// See [`vm_boots_with_host_hugepages`].
#[n_vm::test(config = HOST_2M_VM)]
#[cfg_attr(
    not(host_hugepage_tests),
    ignore = "needs a host hugepage pool; run with --cfg=host_hugepage_tests"
)]
fn vm_boots_with_host_hugepages_2m() {
    assert!(std::path::Path::new("/proc/meminfo").exists());
}

/// See [`vm_boots_with_host_hugepages`].
#[n_vm::test(config = HOST_2M_VM_QEMU)]
#[cfg_attr(
    not(host_hugepage_tests),
    ignore = "needs a host hugepage pool; run with --cfg=host_hugepage_tests"
)]
fn vm_boots_with_host_hugepages_2m_on_qemu() {
    assert!(std::path::Path::new("/proc/meminfo").exists());
}

#[n_vm::test(config = NO_GUEST_HUGEPAGES_VM)]
fn vm_boots_without_guest_hugepages() {
    assert_eq!(
        hugepages_total(),
        0,
        "expected no guest hugepages when hugepage_size = none"
    );
}

#[n_vm::test(config = GUEST_2M_HUGEPAGES_VM)]
fn vm_boots_with_2m_guest_hugepages() {
    assert_eq!(
        hugepages_total(),
        64,
        "expected 64 guest hugepages from kernel reservation"
    );
}

#[n_vm::test(config = HOST_4K_GUEST_2M_VM_QEMU)]
async fn vm_boots_with_4k_host_and_2m_guest_hugepages_on_qemu() {
    assert_eq!(
        hugepages_total(),
        64,
        "expected 64 guest hugepages with 4K host backing"
    );
}

#[n_vm::test]
async fn tokio_test_current_thread_default() {
    let contents = tokio::fs::read_to_string("/proc/version").await.unwrap();
    assert!(contents.contains("Linux"));
}

#[n_vm::test(config = MULTI_THREAD_VM)]
async fn tokio_test_multi_thread() {
    let handle = tokio::spawn(async { tokio::fs::read_to_string("/proc/version").await.unwrap() });
    let contents = handle.await.unwrap();
    assert!(contents.contains("Linux"));
}

/// Everything [`CorpusPolicy::Fuzz`] changes about a guest, in one boot.
///
/// Two claims, kept together because the second costs nothing once the VM
/// is up and a fuzz target of its own would be announced to
/// `cargo bolero list` as one containing no `check!`.
///
/// **The writable window is exactly one directory wide.**
///
/// This is the security boundary that makes a writable share acceptable at
/// all: a fuzz target is deliberately provoking misbehaviour, so it must be
/// able to save inputs without being able to damage the rest of the
/// developer's source tree.  The split is enforced by *which virtiofs daemon
/// serves which path* -- the root daemon runs `--readonly` and the corpus
/// daemon's `--shared-dir` is the corpus directory alone -- so it holds
/// regardless of what the guest does with its own mount flags.
///
/// This run has no engine, so the corpus falls back to `bolero`'s own
/// `__fuzz__` beside this file.  Under `cargo bolero test` the directories
/// come from the engine instead, and there are two of them.
///
/// **The guest reserves no hugepages.**
///
/// The policy alone decides this -- the config says nothing about
/// hugepages, so `guest_hugepages` is [`GuestHugePageConfig::Auto`].  See
/// `VmConfig::hugepage_reservation` for why the two roles want opposite
/// answers.
#[n_vm::test]
fn corpus_is_writable_and_rest_of_workspace_is_not() {
    #[n_vm::config]
    const _: _ = VmConfigBuilder::default()
        .corpus(CorpusPolicy::Fuzz)
        .build();

    assert_eq!(
        hugepages_total(),
        0,
        "a fuzz target should boot with no hugepage reservation",
    );

    let cwd = std::env::current_dir().expect("workspace should be the working directory");

    let corpus = cwd.join("n-vm/tests/__fuzz__");
    let probe = corpus.join(".write_probe");
    std::fs::write(&probe, b"probe").expect("the corpus directory must be writable");
    std::fs::remove_file(&probe).expect("the corpus probe must be removable");

    // Anything else under the workspace is served by the read-only daemon.
    for path in [cwd.join(".write_probe"), cwd.join("n-vm/.write_probe")] {
        let err =
            std::fs::write(&path, b"probe").expect_err("only the corpus directory may be writable");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::ReadOnlyFilesystem,
            "writing {path:?} should fail as read-only, got {err}",
        );
    }
}

// -- The initramfs boot path ------------------------------------------
//
// These pin QEMU so they can run under the `modular` profile, whose kernel
// has virtiofs as a module and so can only reach its root through an
// initramfs (`N_VM_PROFILE=modular`).  Under a direct-boot profile they
// still run and assert the same invariants, which is the point: the guest
// is supposed to look identical either way, and only the route to it
// differs.

/// The root must be the read-only virtiofs share, not the writable rootfs
/// the initramfs started in.
///
/// This is the check that the `switch_root` actually happened.  If the
/// pre-init failed to move the new root over `/`, the guest would still be
/// sitting in a perfectly functional tmpfs and almost everything else would
/// keep working -- so a test that merely boots proves much less than it
/// appears to.
#[n_vm::test(config = QEMU_VM)]
fn root_is_read_only_after_switch_root() {
    let err = std::fs::File::create_new("/some.file").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::ReadOnlyFilesystem);
}

/// `n-it`'s own mounts land on the new root, not the abandoned one.
#[n_vm::test(config = QEMU_VM)]
fn n_it_mounts_survive_switch_root() {
    std::fs::File::create_new("/run/probe").expect("/run should be a writable tmpfs");
    assert!(
        std::path::Path::new("/proc/self").exists(),
        "procfs mounted"
    );
    assert!(
        std::path::Path::new("/sys/kernel").exists(),
        "sysfs mounted"
    );
}

// -- The inline `#[n_vm::config]` form --------------------------------
//
// `config = PATH` still works and every test above still uses it.  These two
// exist to pin what the inline form adds: a configuration written at the call
// site, in ordinary Rust, that still reaches the guest.

/// A module parameter declared inline reaches the guest's command line.
///
/// Asserts on `/proc/cmdline` rather than on the config value.  The value is
/// what the host tier *asked* for; the command line is what the guest was
/// actually booted with, and everything this form changed sits between the
/// two -- the const is lifted out of the body by the macro, folded into the
/// generated `VmConfig`, and rendered by `build_kernel_cmdline`.
///
/// The type is spelled `_` on purpose: the placeholder is illegal in a real
/// const item (E0121), and this passes only because the macro deletes the
/// item before rustc ever resolves it.
#[n_vm::test]
fn an_inline_config_reaches_the_guest_cmdline() {
    #[n_vm::config]
    const _: _ = VmConfigBuilder::default()
        .guest_hugepages(GuestHugePageConfig::None)
        .module_params(&[ModuleParam::new("vfio-pci", "disable_idle_d3", "1")])
        .build();

    let cmdline = std::fs::read_to_string("/proc/cmdline").expect("procfs should be mounted");
    assert!(
        cmdline.contains("vfio-pci.disable_idle_d3=1"),
        "declared module parameter is missing from {cmdline:?}",
    );
    assert_eq!(
        hugepages_total(),
        0,
        "inline guest_hugepages(None) should have reached the guest",
    );
}

/// The same VM as `GUEST_2M_HUGEPAGES_VM`, written inline.
///
/// Kept alongside the `config = PATH` test it mirrors
/// (`vm_boots_with_2m_guest_hugepages`) so that the two forms are known to
/// produce the same guest rather than assumed to.  Spelled with an explicit
/// type, which is the form that also compiles outside this macro.
#[n_vm::test]
fn an_inline_config_matches_the_named_const_it_mirrors() {
    #[n_vm::config]
    const _: _ = VmConfigBuilder::default()
        .guest_hugepages(GuestHugePageConfig::Allocate {
            size: GuestHugePageSize::Huge2M,
            count: 64,
        })
        .kernel_features(&[features::HUGETLBFS])
        .build();

    assert_eq!(
        hugepages_total(),
        64,
        "expected 64 guest hugepages from the inline reservation"
    );
}

/// No `#[n_vm::config]`, no `config = PATH`: the plain form still boots.
///
/// The path the other two are measured against, and the one every test
/// written before either form existed takes.  Kept explicit because "we did
/// not break the default" is otherwise only ever asserted incidentally, by
/// tests that are checking something else.
#[n_vm::test]
fn a_default_vm() {
    assert!(
        std::path::Path::new("/proc/self").exists(),
        "a default VM should still boot a guest with procfs mounted",
    );
}

// -- What the machine is made of --------------------------------------
//
// Each of these asserts from inside the booted guest rather than against
// the arguments the harness produced.  An argument records what was asked
// for; a hypervisor that silently declined it -- or accepted it and built
// something else -- leaves every unit test green.

/// Total memory as the guest sees it, in KiB.
fn mem_total_kib() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .expect("guest has /proc/meminfo")
        .lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse().ok())
        .expect("MemTotal is a number")
}

/// How many CPUs the guest brought online.
fn online_cpus() -> usize {
    std::fs::read_to_string("/proc/cpuinfo")
        .expect("guest has /proc/cpuinfo")
        .lines()
        .filter(|l| l.starts_with("processor"))
        .count()
}

/// Every interface the guest enumerated, as `(name, MAC)`, sorted.
///
/// Loopback is dropped: it is not a NIC and it has no MAC worth naming.
fn guest_links() -> Vec<(String, String)> {
    let mut links: Vec<(String, String)> = std::fs::read_dir("/sys/class/net")
        .expect("guest has /sys/class/net")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name != "lo")
        .map(|name| {
            let mac = std::fs::read_to_string(format!("/sys/class/net/{name}/address"))
                .unwrap_or_default()
                .trim()
                .to_ascii_uppercase();
            (name, mac)
        })
        .collect();
    links.sort();
    links
}

/// The kernel driver bound to each interface, sorted.
///
/// This, rather than the MAC, is what says the guest saw a *different
/// device*: the harness derives every MAC the same way whatever the model
/// is, so a machine that presented one device three times would still show
/// three distinct addresses.
fn guest_nic_drivers() -> Vec<String> {
    let mut drivers: Vec<String> = guest_links()
        .into_iter()
        .filter_map(|(name, _)| {
            std::fs::read_link(format!("/sys/class/net/{name}/device/driver"))
                .ok()?
                .file_name()
                .map(|d| d.to_string_lossy().into_owned())
        })
        .collect();
    drivers.sort();
    drivers
}

/// The VM is the size it asked for, not the size this crate used to hard-code.
#[n_vm::test]
fn a_vm_is_the_size_it_asked_for() {
    #[n_vm::config]
    const _: _ = VmConfigBuilder::default().memory_mib(2048).vcpus(2).build();

    assert_eq!(online_cpus(), 2, "the guest should have brought up 2 vCPUs");

    // A band, not an equality: the guest kernel's own reservations come off
    // MemTotal before userspace ever sees it, so the exact figure is a
    // property of the kernel rather than of the lever under test.  What
    // matters is that it is the 2 GiB that was asked for and not the 1 GiB
    // default.
    let mib = mem_total_kib() / 1024;
    assert!(
        (1536..=2048).contains(&mib),
        "a 2048 MiB VM reported {mib} MiB of RAM",
    );
}

/// The same lever, on the other hypervisor.
#[n_vm::test]
fn a_vm_is_the_size_it_asked_for_on_qemu() {
    #[n_vm::config]
    const _: _ = VmConfigBuilder::default()
        .kernel_profile(n_vm::kernel_profiles::QEMU)
        .memory_mib(2048)
        .vcpus(2)
        .build();

    assert_eq!(online_cpus(), 2);
    let mib = mem_total_kib() / 1024;
    assert!(
        (1536..=2048).contains(&mib),
        "a 2048 MiB VM reported {mib} MiB of RAM",
    );
}

/// The fabric is as wide as the test said.
///
/// **Pinned to QEMU, and not because the lever is.** A fabric link does not
/// reach a cloud-hypervisor guest at all: they sit on PCI segment 1 and that
/// guest enumerates nothing there, with or without the vIOMMU.  That
/// predates this lever -- the two links the VM has always had were equally
/// invisible -- so this names the profile that shows the interfaces rather
/// than asserting something known to be false.
#[n_vm::test]
fn a_vm_gets_the_fabric_links_it_asked_for() {
    #[n_vm::config]
    const _: _ = VmConfigBuilder::default()
        .kernel_profile(n_vm::kernel_profiles::QEMU)
        .fabric_nics(4)
        .build();

    // Sorted by address rather than left in device order: which interface
    // the kernel names `eth0` is up to the kernel, and this is asserting
    // which links exist, not what they were called.
    let mut macs: Vec<String> = guest_links().into_iter().map(|(_, mac)| mac).collect();
    macs.sort();
    assert_eq!(
        macs,
        vec![
            "02:CA:FE:BA:BE:01",
            "02:CA:FE:BA:BE:02",
            "02:CA:FE:BA:BE:03",
            "02:CA:FE:BA:BE:04",
            "02:DE:AD:BE:EF:01",
        ],
        "expected four fabric links plus management",
    );
}

/// A test that never touches the network can decline the fabric entirely.
///
/// Each link is a TAP device, a virtio device and a queue pair, all set up
/// before the guest runs, so this is the cheapest VM the harness can build.
#[n_vm::test]
fn a_vm_can_decline_its_fabric_links() {
    #[n_vm::config]
    const _: _ = VmConfigBuilder::default()
        .kernel_profile(n_vm::kernel_profiles::QEMU)
        .fabric_nics(0)
        .build();

    let links = guest_links();
    assert_eq!(links.len(), 1, "management only, but found {links:?}");
    assert_eq!(links[0].1, "02:DE:AD:BE:EF:01");
}

/// One VM, three device models, so "the second NIC" and "the virtio NIC"
/// name different devices.
///
/// This is the machine a startup-sequence test needs.  The failure it is
/// looking for is a program that identifies a NIC by ordinal, or by whatever
/// `/sys` happens to list first, and unbinds a device it did not mean to --
/// on this system, that is how the management link gets taken away and the
/// host needs a physical reboot.  On a machine where every NIC is the same
/// device there is no wrong one to pick, so a uniform fabric cannot see it.
///
/// No backend is pinned: an emulated model is one only QEMU has, so the
/// configuration selects it on its own.
#[n_vm::test]
fn a_vm_can_present_several_nic_models_at_once() {
    #[n_vm::config]
    const _: _ = VmConfigBuilder::default()
        .fabric_nic_models(&[
            n_vm::NicModel::VirtioNet,
            n_vm::NicModel::E1000,
            n_vm::NicModel::E1000E,
        ])
        // Declared, because a kernel missing one of these does not fail --
        // it presents the device and binds nothing, which reads here as
        // "the model never reached the guest" when it did.
        .kernel_features(&[features::VIRTIO_NET, features::E1000, features::E1000E])
        // Named rather than left to `RequestedBackend::Qemu`.  A pinned
        // backend that the run's profile does not offer resolves to a
        // *skip*, and a skip is reported as a pass -- so this test would
        // have quietly asserted nothing on every default run.  Naming the
        // profile says what the test is for, and outranks `N_VM_PROFILE`.
        .kernel_profile(n_vm::kernel_profiles::QEMU)
        .build();

    assert_eq!(
        guest_nic_drivers(),
        vec!["e1000", "e1000e", "virtio_net", "virtio_net"],
        "the guest should have bound three different drivers",
    );
}

/// The kernel a test names is the kernel it gets.
///
/// `N_VM_PROFILE` points a suite that has no opinion at another
/// environment; a test that depends on a *modular* kernel has an opinion,
/// and this is how it says so.
#[n_vm::test]
fn a_vm_boots_the_kernel_profile_it_named() {
    #[n_vm::config]
    const _: _ = VmConfigBuilder::default()
        .kernel_profile(n_vm::kernel_profiles::FLATCAR)
        .build();

    let version = std::fs::read_to_string("/proc/version").expect("guest has /proc/version");
    assert!(
        version.to_ascii_lowercase().contains("flatcar"),
        "expected a flatcar kernel, got {version}",
    );
}
