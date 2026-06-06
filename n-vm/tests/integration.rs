use n_vm::in_vm;

fn hugepages_total() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .unwrap()
        .lines()
        .find(|l| l.starts_with("HugePages_Total:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

#[in_vm]
#[test]
fn test_which_runs_in_vm() {
    assert_eq!(2 + 2, 4);
}

#[in_vm]
#[should_panic]
#[test]
#[allow(unreachable_code)]
fn test_which_runs_in_vm_control() {
    assert_eq!(2 + 2, 4);
    panic!("deliberate panic");
}

#[in_vm]
#[test]
fn root_filesystem_in_vm_is_read_only() {
    let error = std::fs::File::create_new("/some.file").unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ReadOnlyFilesystem);
}

#[in_vm]
#[test]
fn run_filesystem_in_vm_is_read_write() {
    std::fs::File::create_new("/run/some.file").unwrap();
}

#[in_vm]
#[test]
fn tmp_filesystem_in_vm_is_read_write() {
    std::fs::File::create_new("/tmp/some.file").unwrap();
}

#[in_vm]
#[test]
#[hypervisor(iommu)]
fn test_which_runs_in_vm_with_iommu() {
    assert_eq!(2 + 2, 4);
}

#[in_vm(qemu)]
#[test]
#[hypervisor(iommu)]
fn test_which_runs_in_vm_with_qemu_iommu() {
    assert_eq!(2 + 2, 4);
}

#[in_vm]
#[test]
#[hypervisor(host_pages = "4k")]
fn vm_boots_with_standard_host_pages() {
    assert!(std::path::Path::new("/proc/meminfo").exists());
}

#[in_vm(qemu)]
#[test]
#[hypervisor(host_pages = "4k")]
fn vm_boots_with_standard_host_pages_on_qemu() {
    assert!(std::path::Path::new("/proc/meminfo").exists());
}

#[in_vm]
#[test]
#[guest(hugepage_size = "none")]
fn vm_boots_without_guest_hugepages() {
    assert_eq!(
        hugepages_total(),
        0,
        "expected no guest hugepages when hugepage_size = none"
    );
}

#[in_vm]
#[test]
#[guest(hugepage_size = "2m", hugepage_count = 64)]
fn vm_boots_with_2m_guest_hugepages() {
    assert_eq!(
        hugepages_total(),
        64,
        "expected 64 guest hugepages from kernel reservation"
    );
}

#[in_vm(qemu)]
#[test]
#[hypervisor(iommu, host_pages = "4k")]
#[guest(hugepage_size = "2m", hugepage_count = 64)]
async fn vm_boots_with_4k_host_and_2m_guest_hugepages_on_qemu() {
    assert_eq!(
        hugepages_total(),
        64,
        "expected 64 guest hugepages with 4K host backing"
    );
}

#[in_vm]
#[tokio::test]
async fn tokio_test_current_thread_default() {
    let contents = tokio::fs::read_to_string("/proc/version").await.unwrap();
    assert!(contents.contains("Linux"));
}

#[in_vm]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tokio_test_multi_thread() {
    let handle = tokio::spawn(async { tokio::fs::read_to_string("/proc/version").await.unwrap() });
    let contents = handle.await.unwrap();
    assert!(contents.contains("Linux"));
}
