// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Cloud-hypervisor [`HypervisorBackend`] implementation.
//!
//! This module encapsulates all
//! [cloud-hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor)-specific
//! concerns:
//!
//! - **VM configuration** -- translating [`TestVmParams`] into a
//!   cloud-hypervisor [`VmConfig`] via focused sub-builders.
//! - **Process spawning** -- launching the `cloud-hypervisor` binary with
//!   an `--event-monitor` pipe and `--api-socket`.
//! - **Lifecycle control** -- creating and booting the VM via the REST API,
//!   and performing best-effort shutdown.
//! - **Event monitoring** -- delegating to [`events::watch`] to consume
//!   the event stream and produce a [`HypervisorVerdict`].
//!
//! Nothing in this module is used by the generic [`TestVm`](crate::vm::TestVm)
//! machinery except through the [`HypervisorBackend`] trait.
//!
//! The [`events`] submodule contains the cloud-hypervisor event monitor
//! JSON stream decoder and the [`events::watch`] function that consumes
//! the event stream.

pub mod error;
pub(crate) mod events;

pub use self::error::CloudHypervisorError;

use std::os::unix::io::RawFd;
use std::process::Stdio;
use std::sync::Arc;

use cloud_hypervisor_client::apis::DefaultApi;
use cloud_hypervisor_client::models::console_config::Mode;
use cloud_hypervisor_client::models::{
    ConsoleConfig, CpuTopology, CpusConfig, FsConfig, MemoryConfig, NetConfig, PayloadConfig,
    PlatformConfig, VmConfig, VsockConfig,
};
use command_fds::{CommandFdExt, FdMapping};
use n_vm_protocol::{
    CLOUD_HYPERVISOR_BINARY_PATH, HYPERVISOR_API_SOCKET_PATH, KERNEL_CONSOLE_SOCKET_PATH,
    KERNEL_IMAGE_PATH, VHOST_VSOCK_SOCKET_PATH, VIRTIOFS_ROOT_TAG, VIRTIOFSD_SOCKET_PATH,
    VsockChannel,
};
use tracing::{debug, error};

use crate::abort_on_drop::AbortOnDrop;
use crate::backend::{HypervisorBackend, LaunchedHypervisor};
use crate::config;
use crate::error::VmError;
use crate::vm::{TestVmParams, check_hugepages_accessible, check_kvm_accessible, wait_for_socket};

// ── Constants ────────────────────────────────────────────────────────

/// The fd number used for the cloud-hypervisor event monitor pipe.
///
/// This is the child-side fd that cloud-hypervisor writes events to.
/// It must match the `--event-monitor fd=N` argument.
const EVENT_MONITOR_FD: RawFd = 3;

// ── Public types ─────────────────────────────────────────────────────

/// Cloud-hypervisor [`HypervisorBackend`] implementation.
///
/// Launches a cloud-hypervisor VMM process, configures and boots the VM
/// via its REST API, monitors lifecycle events through the
/// `--event-monitor` pipe, and performs shutdown via the REST API.
#[derive(Debug)]
pub struct CloudHypervisor;

/// Lifecycle controller for a running cloud-hypervisor instance.
///
/// Wraps the generated REST API client behind a mutex (the generated
/// client's methods take `&self` but are not `Sync`).
pub struct CloudHypervisorController {
    client: Arc<tokio::sync::Mutex<dyn DefaultApi>>,
}

/// Collected event log from cloud-hypervisor's `--event-monitor` stream.
///
/// This newtype wraps the raw event vector so that the generic
/// [`VmTestOutput`](crate::vm::VmTestOutput) can store and display
/// backend-specific event data through the [`Display`](std::fmt::Display)
/// bound on [`HypervisorBackend::EventLog`].
///
/// The [`Display`](std::fmt::Display) implementation produces one line per
/// event in a human-readable format suitable for test failure diagnostics.
#[derive(Debug, Default)]
pub struct CloudHypervisorEventLog(pub Vec<events::Event>);

impl std::fmt::Display for CloudHypervisorEventLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for event in &self.0 {
            writeln!(
                f,
                "[{:?}] {:?} - {:?} {:?}",
                event.timestamp, event.source, event.event, event.properties
            )?;
        }
        Ok(())
    }
}

// ── Error conversion ─────────────────────────────────────────────────

impl From<CloudHypervisorError> for VmError {
    fn from(err: CloudHypervisorError) -> Self {
        VmError::Backend(Box::new(err))
    }
}

// ── HypervisorBackend ────────────────────────────────────────────────

impl HypervisorBackend for CloudHypervisor {
    const NAME: &str = "cloud-hypervisor";

    type EventLog = CloudHypervisorEventLog;
    type Controller = CloudHypervisorController;

    async fn launch(params: &TestVmParams<'_>) -> Result<LaunchedHypervisor<Self>, VmError> {
        let (child, event_receiver) =
            spawn_hypervisor_process(params.vm_config.host_page_size).await?;

        let config = build_vm_config(params);

        let client = Arc::new(tokio::sync::Mutex::new(
            cloud_hypervisor_client::socket_based_api_client(HYPERVISOR_API_SOCKET_PATH),
        ));

        client.lock().await.create_vm(config).await.map_err(|e| {
            CloudHypervisorError::VmCreate {
                reason: format!("{e:?}"),
            }
        })?;

        let event_watcher = AbortOnDrop::spawn(async {
            let (events, verdict) = events::watch(event_receiver).await;
            (CloudHypervisorEventLog(events), verdict)
        });

        client
            .lock()
            .await
            .boot_vm()
            .await
            .map_err(|e| CloudHypervisorError::VmBoot {
                reason: format!("{e:?}"),
            })?;

        Ok(LaunchedHypervisor {
            child,
            event_watcher,
            controller: CloudHypervisorController { client },
        })
    }

    async fn shutdown(controller: &Self::Controller) {
        // In the normal path the VM has already powered off (n-it calls
        // reboot(RB_POWER_OFF) or aborts), so these calls will fail
        // harmlessly.  But if the guest init hangs or the shutdown path
        // fails, these calls break the deadlock that would otherwise occur
        // when `collect` waits for the hypervisor process to exit.
        if let Err(err) = controller.client.lock().await.shutdown_vm().await as Result<(), _> {
            debug!("vm shutdown: {err}");
        }
        if let Err(err) = controller.client.lock().await.shutdown_vmm().await as Result<(), _> {
            debug!("vmm shutdown: {err}");
        }
    }

    fn spawn_vsock_reader(channel: &VsockChannel) -> Result<AbortOnDrop<String>, VmError> {
        let path = channel.listener_path();
        let label = channel.label;
        let listen =
            tokio::net::UnixListener::bind(&path).map_err(|source| VmError::VsockBind {
                label,
                path: path.clone(),
                source,
            })?;
        Ok(AbortOnDrop::spawn(async move {
            let connection = match listen.accept().await {
                Ok((stream, _)) => stream,
                Err(e) => {
                    error!("failed to accept {label} vsock connection: {e}");
                    return format!(
                        "!!!{} UNAVAILABLE: accept failed: {e}!!!",
                        label.to_uppercase()
                    );
                }
            };
            config::read_vsock_stream(connection, label).await
        }))
    }
}

// ── Process spawning ─────────────────────────────────────────────────

/// Creates the event-monitor pipe, verifies `/dev/kvm`, spawns the
/// cloud-hypervisor binary, and waits for the API socket to appear.
///
/// Returns the child process handle and the event-monitor pipe receiver
/// (which is consumed by [`hypervisor::watch`]).
async fn spawn_hypervisor_process(
    host_page_size: config::HostPageSize,
) -> Result<(tokio::process::Child, tokio::net::unix::pipe::Receiver), VmError> {
    let (event_sender, event_receiver) =
        tokio::net::unix::pipe::pipe().map_err(CloudHypervisorError::EventPipe)?;
    let event_sender = event_sender
        .into_blocking_fd()
        .map_err(CloudHypervisorError::EventSenderFd)?;

    check_kvm_accessible().await?;
    check_hugepages_accessible(host_page_size).await?;

    let hypervisor = tokio::process::Command::new(CLOUD_HYPERVISOR_BINARY_PATH)
        .args([
            "--api-socket",
            format!("path={HYPERVISOR_API_SOCKET_PATH}").as_str(),
            "--event-monitor",
            format!("fd={EVENT_MONITOR_FD}").as_str(),
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .fd_mappings(vec![FdMapping {
            parent_fd: event_sender,
            child_fd: EVENT_MONITOR_FD,
        }])
        .map_err(|e| CloudHypervisorError::FdMapping(format!("{e:?}")))?
        .spawn()
        .map_err(VmError::HypervisorSpawn)?;

    // The first VMM event becoming readable indicates the hypervisor has
    // started.  We then poll until the API socket appears on the
    // filesystem.
    event_receiver
        .readable()
        .await
        .map_err(CloudHypervisorError::EventMonitorNotReadable)?;
    wait_for_socket(HYPERVISOR_API_SOCKET_PATH).await?;

    Ok((hypervisor, event_receiver))
}

// ── VM configuration builders ────────────────────────────────────────
//
// Each builder is a focused function responsible for a single aspect of
// the cloud-hypervisor `VmConfig`.  They can be tested and evolved
// independently; `build_vm_config` composes them into the final config.

/// Builds the complete cloud-hypervisor [`VmConfig`] for a test run.
///
/// The virtio-console is disabled (`Mode::Off`) because test
/// stdout/stderr are forwarded via dedicated
/// [`VsockChannel`](n_vm_protocol::VsockChannel)s instead.
fn build_vm_config(params: &TestVmParams<'_>) -> VmConfig {
    // Cloud-hypervisor only supports virtio-net -- it has no emulated NIC
    // models.  The proc macro prevents incompatible combinations at compile
    // time, so this is a belt-and-suspenders check for callers that bypass
    // the macro (e.g. direct `TestVm::<CloudHypervisor>::launch()` calls).
    debug_assert!(
        !params.vm_config.nic_model.requires_qemu(),
        "cloud-hypervisor does not support NIC model {:?}; \
         use #[in_vm(qemu)] for emulated NIC models",
        params.vm_config.nic_model,
    );

    VmConfig {
        payload: build_payload_config(params),
        vsock: Some(VsockConfig {
            cid: params.vsock.cid.as_raw() as _,
            socket: VHOST_VSOCK_SOCKET_PATH.into(),
            pci_segment: Some(0),
            ..Default::default()
        }),
        cpus: Some(build_cpu_config()),
        memory: Some(build_memory_config(params.vm_config.host_page_size)),
        net: Some(build_network_configs(params.vm_config.iommu)),
        fs: Some(build_fs_config()),
        // The virtio-console is disabled: test stdout/stderr travel
        // over dedicated VsockChannels (TEST_STDOUT / TEST_STDERR).
        console: Some(ConsoleConfig::new(Mode::Off)),
        serial: Some(ConsoleConfig {
            mode: Mode::Socket,
            socket: Some(KERNEL_CONSOLE_SOCKET_PATH.into()),
            ..Default::default()
        }),
        iommu: Some(params.vm_config.iommu),
        watchdog: Some(true),
        platform: Some(build_platform_config(params)),
        pvpanic: Some(true),
        // Landlock is disabled: the Docker container already provides
        // filesystem isolation, and Landlock's allow-list (which only
        // covers VM_RUN_DIR) would block access to /dev/net/tun and
        // other device nodes that cloud-hypervisor needs.
        landlock_enable: Some(false),
        ..Default::default()
    }
}

/// Builds the kernel payload configuration, including the kernel command
/// line that passes the test binary path and name to the init system.
fn build_payload_config(params: &TestVmParams<'_>) -> PayloadConfig {
    PayloadConfig {
        firmware: None,
        kernel: Some(KERNEL_IMAGE_PATH.into()),
        cmdline: Some(config::build_kernel_cmdline(
            &params.vm_bin_path,
            params.test_name,
            &params.vsock,
            params.vm_config.iommu,
            &params.vm_config.guest_hugepages,
        )),
        ..Default::default()
    }
}

/// Builds the CPU topology: 6 vCPUs arranged as 3 dies × 1 core × 2
/// threads.
fn build_cpu_config() -> CpusConfig {
    CpusConfig {
        boot_vcpus: config::VM_VCPUS as i32,
        max_vcpus: config::VM_VCPUS as i32,
        topology: Some(CpuTopology {
            threads_per_core: Some(config::VM_THREADS_PER_CORE as i32),
            cores_per_die: Some(config::VM_CORES_PER_DIE as i32),
            dies_per_package: Some(config::VM_DIES_PER_PACKAGE as i32),
            packages: Some(config::VM_SOCKETS as i32),
        }),
        ..Default::default()
    }
}

/// Builds the memory configuration with sharing support and optional
/// hugepage backing based on the [`HostPageSize`](config::HostPageSize).
///
/// - [`Standard`](config::HostPageSize::Standard) -- `shared=on`,
///   `hugepages=off`, `thp=off`.  No hugetlbfs mount required.
/// - [`Huge2M`](config::HostPageSize::Huge2M) /
///   [`Huge1G`](config::HostPageSize::Huge1G) -- `shared=on`,
///   `hugepages=on` with the matching page size, `thp=off`.
///
/// `shared=on` is always set because virtiofsd (vhost-user-fs) requires
/// `MAP_SHARED` memory to access the guest address space from a
/// separate process.
///
/// THP (transparent huge pages) is always off.  Cloud-hypervisor's THP
/// hint only applies to private anonymous memory (`shared=off`), so it
/// has no effect when `shared=on`.
fn build_memory_config(host_page_size: config::HostPageSize) -> MemoryConfig {
    let (hugepages, hugepage_size) = if host_page_size.requires_hugepages() {
        (Some(true), Some(host_page_size.bytes()))
    } else {
        (Some(false), None)
    };
    MemoryConfig {
        size: config::VM_MEMORY_BYTES,
        mergeable: Some(true),
        shared: Some(true),
        hugepages,
        hugepage_size,
        thp: Some(false),
        ..Default::default()
    }
}

/// Builds the network interface configurations.
///
/// Returns three interfaces:
/// - **mgmt** -- management network on PCI segment 0 (1500 MTU).
/// - **fabric1** / **fabric2** -- fabric-facing interfaces on PCI
///   segment 1 (9500 MTU jumbo frames).
///
/// When `iommu` is `true`, the fabric interfaces (PCI segment 1) have
/// their per-device `iommu` flag set so that cloud-hypervisor places
/// them behind the virtual IOMMU.
/// The management interface remains on PCI segment 0, which is outside
/// the IOMMU segments configured in [`build_platform_config`].
fn build_network_configs(iommu: bool) -> Vec<NetConfig> {
    // Per-device IOMMU flag for devices on the IOMMU-protected PCI
    // segment.  `None` leaves the field at its default (no IOMMU),
    // `Some(true)` opts the device into DMA remapping.
    let fabric_iommu = if iommu { Some(true) } else { None };

    vec![
        NetConfig {
            tap: Some(config::IFACE_MGMT.tap.into()),
            ip: Some(config::IFACE_MGMT.host_ipv6.to_string()),
            mask: Some("ffff:ffff:ffff:ffff::".into()),
            mac: Some(config::IFACE_MGMT.mac.into()),
            mtu: Some(config::MGMT_MTU),
            id: Some(config::IFACE_MGMT.id.into()),
            pci_segment: Some(0),
            queue_size: Some(config::MGMT_QUEUE_SIZE),
            ..Default::default()
        },
        NetConfig {
            tap: Some(config::IFACE_FABRIC1.tap.into()),
            ip: Some(config::IFACE_FABRIC1.host_ipv6.to_string()),
            mask: Some("ffff:ffff:ffff:ffff::".into()),
            mac: Some(config::IFACE_FABRIC1.mac.into()),
            mtu: Some(config::FABRIC_MTU),
            id: Some(config::IFACE_FABRIC1.id.into()),
            pci_segment: Some(1),
            queue_size: Some(config::FABRIC_QUEUE_SIZE),
            iommu: fabric_iommu,
            ..Default::default()
        },
        NetConfig {
            tap: Some(config::IFACE_FABRIC2.tap.into()),
            ip: Some(config::IFACE_FABRIC2.host_ipv6.to_string()),
            mask: Some("ffff:ffff:ffff:ffff::".into()),
            mac: Some(config::IFACE_FABRIC2.mac.into()),
            mtu: Some(config::FABRIC_MTU),
            id: Some(config::IFACE_FABRIC2.id.into()),
            pci_segment: Some(1),
            queue_size: Some(config::FABRIC_QUEUE_SIZE),
            iommu: fabric_iommu,
            ..Default::default()
        },
    ]
}

/// Builds the virtiofs filesystem configuration for sharing the container
/// filesystem into the VM.
fn build_fs_config() -> Vec<FsConfig> {
    vec![FsConfig {
        tag: VIRTIOFS_ROOT_TAG.into(),
        socket: VIRTIOFSD_SOCKET_PATH.into(),
        num_queues: 1,
        queue_size: config::VIRTIOFS_QUEUE_SIZE as i32,
        id: Some(VIRTIOFS_ROOT_TAG.into()),
        ..Default::default()
    }]
}

/// Builds the platform metadata configuration, embedding the test binary
/// name and test name in OEM strings for identification.
///
/// When `params.iommu` is `true`, PCI segment 1 (the fabric-facing
/// segment) is placed behind the virtual IOMMU with a 48-bit address
/// width.
/// Segment 0 (management, vsock, virtiofs, serial) remains outside the
/// IOMMU so that these infrastructure devices are not subject to DMA
/// remapping overhead.
fn build_platform_config(params: &TestVmParams<'_>) -> PlatformConfig {
    // Only populate IOMMU segment and address-width fields when the
    // caller has requested vIOMMU support.  Leaving them as `None` when
    // iommu is disabled avoids sending unnecessary (and potentially
    // confusing) configuration to the hypervisor.
    let (iommu_segments, iommu_address_width) = if params.vm_config.iommu {
        (Some(vec![1]), Some(48))
    } else {
        (None, None)
    };

    PlatformConfig {
        serial_number: Some("dataplane-test".into()),
        uuid: Some("dff9c8dd-492d-4148-a007-7931f94db852".into()), // arbitrary uuid4
        oem_strings: Some(vec![
            format!("exe={}", params.bin_name),
            format!("test={}", params.test_name),
        ]),
        num_pci_segments: Some(2),
        iommu_segments,
        iommu_address_width,
        ..Default::default()
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::config::{
        self, FABRIC_MTU, FABRIC_QUEUE_SIZE, MGMT_MTU, MGMT_QUEUE_SIZE, VM_MEMORY_BYTES,
    };
    use n_vm_protocol::INIT_BINARY_PATH;
    const VIRTIOFS_QUEUE_SIZE: i32 = crate::config::VIRTIOFS_QUEUE_SIZE as i32;

    /// Builds a representative [`TestVmParams`] for use in config builder
    /// tests.  The values are arbitrary but realistic.
    fn sample_params() -> TestVmParams<'static> {
        TestVmParams {
            full_bin_path: Path::new("/target/debug/deps/my_test-abc123"),
            vm_bin_path: format!("/{}/my_test-abc123", n_vm_protocol::VM_TEST_BIN_DIR),
            bin_name: "my_test-abc123",
            test_name: "tests::my_test",
            vm_config: config::VmConfig::default(),
            vsock: n_vm_protocol::VsockAllocation::with_defaults(),
        }
    }

    // ── Payload config ───────────────────────────────────────────────

    #[test]
    fn payload_config_uses_kernel_image_path() {
        let params = sample_params();
        let payload = build_payload_config(&params);
        assert_eq!(payload.kernel.as_deref(), Some(KERNEL_IMAGE_PATH));
    }

    #[test]
    fn payload_config_embeds_test_binary_in_cmdline() {
        let params = sample_params();
        let payload = build_payload_config(&params);
        let cmdline = payload.cmdline.as_deref().expect("cmdline should be set");
        let expected = format!("/{}/my_test-abc123", n_vm_protocol::VM_TEST_BIN_DIR);
        assert!(
            cmdline.contains(&expected),
            "cmdline should contain the VM-side binary path ({expected}): {cmdline}",
        );
    }

    #[test]
    fn payload_config_embeds_test_name_in_cmdline() {
        let params = sample_params();
        let payload = build_payload_config(&params);
        let cmdline = payload.cmdline.as_deref().expect("cmdline should be set");
        assert!(
            cmdline.contains("tests::my_test"),
            "cmdline should contain the test name: {cmdline}",
        );
    }

    #[test]
    fn payload_config_sets_init_binary() {
        let params = sample_params();
        let payload = build_payload_config(&params);
        let cmdline = payload.cmdline.as_deref().expect("cmdline should be set");
        assert!(
            cmdline.contains(&format!("init={INIT_BINARY_PATH}")),
            "cmdline should specify the init binary: {cmdline}",
        );
    }

    #[test]
    fn payload_config_enables_hugepages_on_cmdline() {
        let params = sample_params();
        let payload = build_payload_config(&params);
        let cmdline = payload.cmdline.as_deref().expect("cmdline should be set");
        assert!(
            cmdline.contains("hugepages=1"),
            "cmdline should configure hugepage count: {cmdline}",
        );
        assert!(
            cmdline.contains("hugepagesz=1G"),
            "cmdline should configure hugepage size: {cmdline}",
        );
    }

    #[test]
    fn payload_config_passes_exact_flag_to_test_harness() {
        let params = sample_params();
        let payload = build_payload_config(&params);
        let cmdline = payload.cmdline.as_deref().expect("cmdline should be set");
        assert!(
            cmdline.contains("--exact"),
            "cmdline should pass --exact to the test harness: {cmdline}",
        );
        assert!(
            cmdline.contains("--no-capture"),
            "cmdline should pass --no-capture to the test harness: {cmdline}",
        );
    }

    #[test]
    fn payload_config_embeds_vsock_port_parameters() {
        let params = sample_params();
        let payload = build_payload_config(&params);
        let cmdline = payload.cmdline.as_deref().expect("cmdline should be set");
        let fragment = params.vsock.kernel_cmdline_fragment();
        assert!(
            cmdline.contains(&fragment),
            "cmdline should contain vsock port parameters ({fragment}): {cmdline}",
        );
    }

    // ── CPU config ───────────────────────────────────────────────────

    #[test]
    fn cpu_config_has_six_vcpus() {
        let cpus = build_cpu_config();
        assert_eq!(cpus.boot_vcpus, 6);
        assert_eq!(cpus.max_vcpus, 6);
    }

    #[test]
    fn cpu_topology_is_three_dies_by_one_core_by_two_threads() {
        let cpus = build_cpu_config();
        let topo = cpus.topology.expect("topology should be set");
        assert_eq!(topo.threads_per_core, Some(2));
        assert_eq!(topo.cores_per_die, Some(1));
        assert_eq!(topo.dies_per_package, Some(3));
        assert_eq!(topo.packages, Some(1));
        // Sanity: product of topology should equal boot_vcpus.
        let total = topo.threads_per_core.unwrap()
            * topo.cores_per_die.unwrap()
            * topo.dies_per_package.unwrap()
            * topo.packages.unwrap();
        assert_eq!(
            total, cpus.boot_vcpus,
            "topology product ({total}) should match boot_vcpus ({})",
            cpus.boot_vcpus,
        );
    }

    // ── Memory config ────────────────────────────────────────────────

    #[test]
    fn memory_config_has_expected_size() {
        let mem = build_memory_config(config::HostPageSize::default());
        assert_eq!(mem.size, VM_MEMORY_BYTES);
    }

    #[test]
    fn memory_config_enables_hugepages_and_sharing_for_1g() {
        let mem = build_memory_config(config::HostPageSize::Huge1G);
        assert_eq!(mem.hugepages, Some(true));
        assert_eq!(mem.hugepage_size, Some(1024 * 1024 * 1024));
        assert_eq!(
            mem.shared,
            Some(true),
            "shared memory is required for virtiofs"
        );
        assert_eq!(mem.mergeable, Some(true));
        assert_eq!(mem.thp, Some(false));
    }

    #[test]
    fn memory_config_enables_hugepages_and_sharing_for_2m() {
        let mem = build_memory_config(config::HostPageSize::Huge2M);
        assert_eq!(mem.hugepages, Some(true));
        assert_eq!(mem.hugepage_size, Some(2 * 1024 * 1024));
        assert_eq!(
            mem.shared,
            Some(true),
            "shared memory is required for virtiofs"
        );
    }

    #[test]
    fn memory_config_disables_hugepages_for_standard_pages() {
        let mem = build_memory_config(config::HostPageSize::Standard);
        assert_eq!(mem.hugepages, Some(false));
        assert_eq!(mem.hugepage_size, None);
        assert_eq!(
            mem.shared,
            Some(true),
            "shared memory is required for virtiofs even without hugepages"
        );
        assert_eq!(mem.thp, Some(false));
    }

    // ── Network config ───────────────────────────────────────────────

    #[test]
    fn network_config_has_three_interfaces() {
        let nets = build_network_configs(false);
        assert_eq!(nets.len(), 3);
    }

    #[test]
    fn mgmt_interface_is_on_pci_segment_zero_with_standard_mtu() {
        let nets = build_network_configs(false);
        let mgmt = nets
            .iter()
            .find(|n| n.id.as_deref() == Some("mgmt"))
            .expect("should have a 'mgmt' interface");
        assert_eq!(mgmt.pci_segment, Some(0));
        assert_eq!(mgmt.mtu, Some(MGMT_MTU));
        assert_eq!(mgmt.queue_size, Some(MGMT_QUEUE_SIZE));
    }

    #[test]
    fn fabric_interfaces_are_on_pci_segment_one_with_jumbo_mtu() {
        let nets = build_network_configs(false);
        for name in &["fabric1", "fabric2"] {
            let iface = nets
                .iter()
                .find(|n| n.id.as_deref() == Some(*name))
                .unwrap_or_else(|| panic!("should have a '{name}' interface"));
            assert_eq!(iface.pci_segment, Some(1), "{name} PCI segment");
            assert_eq!(iface.mtu, Some(FABRIC_MTU), "{name} MTU");
            assert_eq!(
                iface.queue_size,
                Some(FABRIC_QUEUE_SIZE),
                "{name} queue size"
            );
        }
    }

    #[test]
    fn all_interfaces_have_unique_mac_addresses() {
        let nets = build_network_configs(false);
        let macs: Vec<_> = nets.iter().filter_map(|n| n.mac.as_deref()).collect();
        assert_eq!(macs.len(), 3, "all interfaces should have MAC addresses");
        let mut deduped = macs.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(
            macs.len(),
            deduped.len(),
            "all MAC addresses should be unique"
        );
    }

    #[test]
    fn all_interfaces_have_unique_tap_names() {
        let nets = build_network_configs(false);
        let taps: Vec<_> = nets.iter().filter_map(|n| n.tap.as_deref()).collect();
        assert_eq!(taps.len(), 3, "all interfaces should have tap names");
        let mut deduped = taps.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(taps.len(), deduped.len(), "all tap names should be unique");
    }

    // ── Filesystem config ────────────────────────────────────────────

    #[test]
    fn fs_config_uses_virtiofs_root_tag_and_socket() {
        let fs = build_fs_config();
        assert_eq!(fs.len(), 1);
        let entry = &fs[0];
        assert_eq!(entry.tag, VIRTIOFS_ROOT_TAG);
        assert_eq!(entry.socket, VIRTIOFSD_SOCKET_PATH);
        assert_eq!(entry.queue_size, VIRTIOFS_QUEUE_SIZE);
    }

    // ── Platform config ──────────────────────────────────────────────

    #[test]
    fn platform_config_embeds_binary_and_test_name_in_oem_strings() {
        let params = sample_params();
        let platform = build_platform_config(&params);
        let oem = platform.oem_strings.expect("oem_strings should be set");
        assert!(
            oem.iter().any(|s| s == "exe=my_test-abc123"),
            "OEM strings should contain the binary name: {oem:?}",
        );
        assert!(
            oem.iter().any(|s| s == "test=tests::my_test"),
            "OEM strings should contain the test name: {oem:?}",
        );
    }

    #[test]
    fn platform_config_has_two_pci_segments() {
        let params = sample_params();
        let platform = build_platform_config(&params);
        assert_eq!(platform.num_pci_segments, Some(2));
    }

    // ── Composed VmConfig ────────────────────────────────────────────

    #[test]
    fn vm_config_disables_virtio_console() {
        let params = sample_params();
        let config = build_vm_config(&params);
        let console = config.console.expect("console should be set");
        assert_eq!(console.mode, Mode::Off);
    }

    #[test]
    fn vm_config_serial_uses_socket_mode() {
        let params = sample_params();
        let config = build_vm_config(&params);
        let serial = config.serial.expect("serial should be set");
        assert_eq!(serial.mode, Mode::Socket);
        assert_eq!(serial.socket.as_deref(), Some(KERNEL_CONSOLE_SOCKET_PATH));
    }

    #[test]
    fn vm_config_vsock_uses_guest_cid() {
        let params = sample_params();
        let config = build_vm_config(&params);
        let vsock = config.vsock.expect("vsock should be set");
        assert_eq!(vsock.cid, params.vsock.cid.as_raw() as i64);
        assert_eq!(vsock.socket, VHOST_VSOCK_SOCKET_PATH);
    }

    #[test]
    fn vm_config_enables_safety_features() {
        let params = sample_params();
        let config = build_vm_config(&params);
        assert_eq!(config.watchdog, Some(true), "watchdog should be enabled");
        assert_eq!(config.pvpanic, Some(true), "pvpanic should be enabled");
        assert_eq!(
            config.iommu,
            Some(false),
            "iommu should be disabled when not requested"
        );
    }

    // ── vIOMMU configuration ─────────────────────────────────────────

    /// Helper that returns [`TestVmParams`] with vIOMMU enabled.
    fn sample_params_iommu() -> TestVmParams<'static> {
        let mut params = sample_params();
        params.vm_config.iommu = true;
        params
    }

    #[test]
    fn vm_config_enables_iommu_when_requested() {
        let params = sample_params_iommu();
        let config = build_vm_config(&params);
        assert_eq!(
            config.iommu,
            Some(true),
            "iommu should be enabled when requested"
        );
    }

    #[test]
    fn platform_config_has_iommu_segments_when_enabled() {
        let params = sample_params_iommu();
        let platform = build_platform_config(&params);
        assert_eq!(
            platform.iommu_segments,
            Some(vec![1]),
            "PCI segment 1 (fabric) should be behind the vIOMMU"
        );
        assert_eq!(
            platform.iommu_address_width,
            Some(48),
            "IOMMU address width should be 48 bits"
        );
    }

    #[test]
    fn platform_config_has_no_iommu_segments_when_disabled() {
        let params = sample_params();
        let platform = build_platform_config(&params);
        assert_eq!(
            platform.iommu_segments, None,
            "iommu_segments should be None when iommu is disabled"
        );
        assert_eq!(
            platform.iommu_address_width, None,
            "iommu_address_width should be None when iommu is disabled"
        );
    }

    #[test]
    fn fabric_interfaces_have_iommu_when_enabled() {
        let nets = build_network_configs(true);
        let fabric1 = &nets[1];
        let fabric2 = &nets[2];
        assert_eq!(
            fabric1.iommu,
            Some(true),
            "fabric1 should have per-device iommu enabled"
        );
        assert_eq!(
            fabric2.iommu,
            Some(true),
            "fabric2 should have per-device iommu enabled"
        );
    }

    #[test]
    fn mgmt_interface_has_no_iommu_even_when_enabled() {
        let nets = build_network_configs(true);
        let mgmt = &nets[0];
        assert_eq!(
            mgmt.iommu, None,
            "mgmt interface on segment 0 should not have per-device iommu"
        );
    }

    #[test]
    fn fabric_interfaces_have_no_iommu_when_disabled() {
        let nets = build_network_configs(false);
        let fabric1 = &nets[1];
        let fabric2 = &nets[2];
        assert_eq!(
            fabric1.iommu, None,
            "fabric1 should not have per-device iommu when disabled"
        );
        assert_eq!(
            fabric2.iommu, None,
            "fabric2 should not have per-device iommu when disabled"
        );
    }

    #[test]
    fn vm_config_disables_landlock() {
        let params = sample_params();
        let config = build_vm_config(&params);
        // Landlock is disabled because the Docker container already
        // provides filesystem isolation, and the allow-list would block
        // access to /dev/net/tun and other device nodes.
        assert_eq!(config.landlock_enable, Some(false));
    }

    // ── Event log display ────────────────────────────────────────────

    #[test]
    fn empty_event_log_displays_nothing() {
        let log = CloudHypervisorEventLog(vec![]);
        assert_eq!(log.to_string(), "");
    }

    #[test]
    fn event_log_displays_one_line_per_event() {
        use std::collections::BTreeMap;
        use std::time::Duration;

        let log = CloudHypervisorEventLog(vec![
            events::Event {
                timestamp: Duration::from_secs(0),
                source: events::Source::Vmm,
                event: events::EventType::Starting,
                properties: BTreeMap::new(),
            },
            events::Event {
                timestamp: Duration::from_secs(1),
                source: events::Source::Vmm,
                event: events::EventType::Shutdown,
                properties: BTreeMap::new(),
            },
        ]);
        let output = log.to_string();
        let lines: Vec<_> = output.lines().collect();
        assert_eq!(lines.len(), 2, "should have one line per event: {output}");
    }
}
