// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use n_vm::{GuestHugePageConfig, GuestHugePageSize, HostPageSize, VmConfig, features};

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
