// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use n_vm::{GuestHugePageConfig, GuestHugePageSize, HostPageSize, VmConfig, features};

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

/// Standard 4 KiB host pages, so the VM needs no hugetlbfs reservation on
/// the host.
const HOST_4K_VM: VmConfig = VmConfig {
    host_page_size: HostPageSize::Standard,
    ..VmConfig::DEFAULT
};

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

#[n_vm::test(qemu, config = IOMMU_VM)]
fn test_which_runs_in_vm_with_qemu_iommu() {
    assert_eq!(2 + 2, 4);
}

#[n_vm::test(config = HOST_4K_VM)]
fn vm_boots_with_standard_host_pages() {
    assert!(std::path::Path::new("/proc/meminfo").exists());
}

#[n_vm::test(qemu, config = HOST_4K_VM)]
fn vm_boots_with_standard_host_pages_on_qemu() {
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

#[n_vm::test(qemu, config = HOST_4K_GUEST_2M_VM)]
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

#[n_vm::test(multi_thread, worker_threads = 2)]
async fn tokio_test_multi_thread() {
    let handle = tokio::spawn(async { tokio::fs::read_to_string("/proc/version").await.unwrap() });
    let contents = handle.await.unwrap();
    assert!(contents.contains("Linux"));
}

/// The writable corpus window must be exactly one directory wide.
///
/// This is the security boundary that makes `#[corpus]` acceptable at all:
/// a fuzz target is deliberately provoking misbehaviour, so it must be able
/// to save inputs without being able to damage the rest of the developer's
/// source tree.  The split is enforced by *which virtiofs daemon serves
/// which path* -- the root daemon runs `--readonly` and the corpus daemon's
/// `--shared-dir` is the corpus directory alone -- so it holds regardless of
/// what the guest does with its own mount flags.
#[n_vm::test]
#[n_vm::corpus]
fn corpus_is_writable_and_rest_of_workspace_is_not() {
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
#[n_vm::test(qemu, config = HOST_4K_VM)]
fn root_is_read_only_after_switch_root() {
    let err = std::fs::File::create_new("/some.file").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::ReadOnlyFilesystem);
}

/// `n-it`'s own mounts land on the new root, not the abandoned one.
#[n_vm::test(qemu, config = HOST_4K_VM)]
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
