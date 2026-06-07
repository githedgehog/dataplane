// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! QEMU [`HypervisorBackend`] implementation.
//!
//! This module encapsulates all
//! [QEMU](https://www.qemu.org/)-specific concerns:
//!
//! - **VM configuration** -- translating [`TestVmParams`] into QEMU
//!   command-line arguments via focused sub-builders.
//! - **Process spawning** -- launching `qemu-system-x86_64` with the
//!   assembled arguments; QEMU boots the VM immediately on process start
//!   (unlike cloud-hypervisor, which separates VMM startup from VM boot).
//! - **Lifecycle control** -- connecting to the QMP (QEMU Machine
//!   Protocol) socket for shutdown commands.
//! - **Event monitoring** -- consuming async QMP events (`SHUTDOWN`,
//!   `GUEST_PANICKED`, etc.) and producing a [`HypervisorVerdict`].
//!
//! Nothing in this module is used by the generic [`TestVm`](crate::vm::TestVm)
//! machinery except through the [`HypervisorBackend`] trait.
//!
//! # Architecture differences from cloud-hypervisor
//!
//! | Concern    | cloud-hypervisor                   | QEMU                            |
//! |------------|------------------------------------|---------------------------------|
//! | Boot model | `create_vm` + `boot_vm` REST       | Boots on process start          |
//! | Control    | REST API over Unix socket          | QMP (JSON-RPC) over Unix socket |
//! | Events     | `--event-monitor fd=N` pipe        | QMP async events                |
//! | Shutdown   | `shutdown_vm()` + `shutdown_vmm()` | `system_powerdown` + `quit`     |
//! | Config     | JSON `VmConfig` body               | Command-line arguments          |
//!
//! # vsock bridging
//!
//! Cloud-hypervisor has a built-in vhost-user-vsock implementation that
//! transparently maps guest vsock connections to host-side Unix sockets
//! at `$VHOST_SOCKET_$PORT`.  Its
//! [`spawn_vsock_reader`](crate::backend::HypervisorBackend::spawn_vsock_reader)
//! implementation binds [`UnixListener`](tokio::net::UnixListener)s at
//! those paths.
//!
//! QEMU's `vhost-vsock-pci` device uses the kernel's vhost-vsock module
//! instead, which surfaces guest connections as `AF_VSOCK` sockets on
//! the host.  This backend's
//! [`spawn_vsock_reader`](Qemu::spawn_vsock_reader) implementation uses
//! [`tokio_vsock::VsockListener`] bound to `VMADDR_CID_ANY` on the
//! channel's port, so the kernel routes guest vsock connections directly
//! to the listener without any intermediate Unix socket mapping.
//!
//! The [`qmp`] submodule contains the QMP protocol client and wire types.

pub mod error;
pub(crate) mod qmp;

pub use self::error::QemuError;

use std::process::Stdio;
use std::sync::Arc;

use n_vm_protocol::{
    HYPERVISOR_API_SOCKET_PATH, KERNEL_CONSOLE_SOCKET_PATH, VIRTIOFS_ROOT_TAG,
    VIRTIOFSD_SOCKET_PATH, VsockAllocation, VsockChannel,
};
use tracing::{debug, error, warn};

use crate::abort_on_drop::AbortOnDrop;
use crate::backend::{HypervisorBackend, HypervisorVerdict, LaunchedHypervisor};
use crate::config;
use crate::error::VmError;
use crate::vm::{TestVmParams, check_hugepages_accessible, check_kvm_accessible, wait_for_socket};

use self::qmp::{EventDisplay, QmpCommandName, QmpConnection, QmpEventStream, QmpWriter};

// ── Public types ─────────────────────────────────────────────────────

/// QEMU [`HypervisorBackend`] implementation.
///
/// Launches a `qemu-system-x86_64` process that boots the VM immediately,
/// monitors lifecycle events through the QMP socket, and performs shutdown
/// via QMP commands.
#[derive(Debug)]
pub struct Qemu;

/// Lifecycle controller for a running QEMU instance.
///
/// Wraps a [`QmpWriter`] behind a mutex for interior mutability, since
/// the [`HypervisorBackend::shutdown`] method takes `&Self::Controller`.
pub struct QemuController {
    writer: Arc<tokio::sync::Mutex<QmpWriter>>,
}

/// Collected QMP event log from a QEMU VM's lifetime.
///
/// This newtype wraps the raw event vector so that the generic
/// [`VmTestOutput`](crate::vm::VmTestOutput) can store and display
/// backend-specific event data through the [`Display`](std::fmt::Display)
/// bound on [`HypervisorBackend::EventLog`].
///
/// The [`Display`](std::fmt::Display) implementation produces one line per
/// event in a human-readable format suitable for test failure diagnostics.
#[derive(Debug, Default)]
pub struct QemuEventLog(pub Vec<qapi_qmp::Event>);

impl std::fmt::Display for QemuEventLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for event in &self.0 {
            let ts = event.timestamp();
            write!(f, "[{ts:?}] ")?;
            writeln!(f, "{}", EventDisplay(event))?;
        }
        Ok(())
    }
}

// ── Error conversion ─────────────────────────────────────────────────

impl From<QemuError> for VmError {
    fn from(err: QemuError) -> Self {
        VmError::Backend(Box::new(err))
    }
}

// ── HypervisorBackend ────────────────────────────────────────────────

impl HypervisorBackend for Qemu {
    const NAME: &str = "qemu";
    const CAN_EMULATE: bool = true;

    type EventLog = QemuEventLog;
    type Controller = QemuController;

    async fn launch(params: &TestVmParams<'_>) -> Result<LaunchedHypervisor<Self>, VmError> {
        let (child, qmp_conn) = spawn_qemu_process(params).await?;

        // QEMU's `-netdev tap,script=no` creates the TAPs but leaves them
        // DOWN with no addresses.  Bring them UP and assign IPv6 link-local
        // addresses so that NDP traffic flows and rx tests have something
        // to receive.
        configure_host_taps().await?;

        let (writer, event_stream) = qmp_conn.into_split();

        let event_watcher = AbortOnDrop::spawn(async {
            let (events, verdict) = watch_events(event_stream).await;
            (QemuEventLog(events), verdict)
        });

        Ok(LaunchedHypervisor {
            child,
            event_watcher,
            controller: QemuController {
                writer: Arc::new(tokio::sync::Mutex::new(writer)),
            },
        })
    }

    async fn shutdown(controller: &Self::Controller) {
        // In the normal path the VM has already powered off (n-it calls
        // reboot(RB_POWER_OFF) or aborts), and QEMU is paused due to
        // -no-shutdown.  These commands break that pause and exit QEMU.
        //
        // If the guest init hangs, `system_powerdown` sends an ACPI power
        // button event, and `quit` forcefully terminates the VMM.
        let mut writer = controller.writer.lock().await;
        writer
            .send_command_fire_and_forget(QmpCommandName::SystemPowerdown)
            .await;
        writer
            .send_command_fire_and_forget(QmpCommandName::Quit)
            .await;
    }

    fn spawn_vsock_reader(channel: &VsockChannel) -> Result<AbortOnDrop<String>, VmError> {
        let port = channel.port.as_raw();
        let label = channel.label;

        // Bind an AF_VSOCK listener on VMADDR_CID_ANY so the kernel's
        // vhost-vsock module will route guest connections to us.
        let addr = tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_ANY, port);
        let listener =
            tokio_vsock::VsockListener::bind(addr).map_err(|source| VmError::VsockBind {
                label,
                path: format!("vsock://any:{port}").into(),
                source,
            })?;

        Ok(AbortOnDrop::spawn(async move {
            let connection = match listener.accept().await {
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

// ── Event monitoring ─────────────────────────────────────────────────

/// Consumes the QMP event stream and returns the collected events along
/// with a [`HypervisorVerdict`].
///
/// Event collection terminates when:
/// - A `SHUTDOWN` event is received (normal completion).
/// - A `GUEST_PANICKED` event is received (remaining events are drained
///   for up to [`POST_PANIC_DRAIN_TIMEOUT`]).
/// - The stream ends (socket closed / QEMU exited).
///
/// The verdict is computed by [`compute_verdict`] from the collected
/// events and a flag tracking whether any stream-level errors occurred.
async fn watch_events(mut stream: QmpEventStream) -> (Vec<qapi_qmp::Event>, HypervisorVerdict) {
    let mut log = Vec::with_capacity(16);
    let mut had_errors = false;

    loop {
        match stream.next_event().await {
            Ok(Some(event)) => {
                let is_shutdown = matches!(event, qapi_qmp::Event::SHUTDOWN { .. });
                let is_panic = matches!(event, qapi_qmp::Event::GUEST_PANICKED { .. });
                log.push(event);

                if is_shutdown || is_panic {
                    if is_panic {
                        drain_after_panic(&mut stream, &mut log).await;
                    }
                    break;
                }
            }
            Ok(None) => {
                // Stream closed -- QEMU exited.
                break;
            }
            Err(err) => {
                warn!("QMP event stream error (marking as failure): {err:#?}");
                had_errors = true;
            }
        }
    }

    let verdict = compute_verdict(&log, had_errors);
    (log, verdict)
}

/// Drains remaining QMP events for up to [`POST_PANIC_DRAIN_TIMEOUT`]
/// after a guest panic, appending them to `log`.
///
/// This gives QEMU time to emit subsequent events (e.g. `SHUTDOWN`) that
/// aid diagnosis.
async fn drain_after_panic(stream: &mut QmpEventStream, log: &mut Vec<qapi_qmp::Event>) {
    let deadline = tokio::time::sleep(config::POST_PANIC_DRAIN_TIMEOUT);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            result = stream.next_event() => {
                match result {
                    Ok(Some(event)) => log.push(event),
                    Ok(None) => break,
                    Err(err) => {
                        warn!("QMP event error during post-panic drain: {err:#?}");
                    }
                }
            }
            () = &mut deadline => break,
        }
    }
}

/// Computes the [`HypervisorVerdict`] from collected QMP events and a
/// flag indicating whether any stream-level errors occurred.
///
/// This is a **pure function** extracted from [`watch_events`] so that
/// verdict logic can be unit-tested with hand-crafted event sequences
/// without needing a socket or tokio runtime.
///
/// The verdict is [`CleanShutdown`](HypervisorVerdict::CleanShutdown)
/// only if **all** of the following hold:
///
/// 1. A `SHUTDOWN` event was received.
/// 2. No `GUEST_PANICKED` event preceded the shutdown in the event log.
/// 3. No stream-level errors occurred (indicated by `had_stream_errors`).
///
/// Otherwise the verdict is [`Failure`](HypervisorVerdict::Failure).
pub fn compute_verdict(events: &[qapi_qmp::Event], had_stream_errors: bool) -> HypervisorVerdict {
    let mut tainted = had_stream_errors;

    for event in events {
        match event {
            qapi_qmp::Event::SHUTDOWN { .. } => {
                return if tainted {
                    HypervisorVerdict::Failure
                } else {
                    HypervisorVerdict::CleanShutdown
                };
            }
            qapi_qmp::Event::GUEST_PANICKED { .. } => {
                tainted = true;
            }
            _ => {}
        }
    }

    // Stream ended without a SHUTDOWN event.
    HypervisorVerdict::Failure
}

// ── Host-side TAP configuration ───────────────────────────────────────

/// Prefix length for the IPv6 link-local addresses assigned to TAPs.
const TAP_IPV6_PREFIX_LEN: u8 = config::TAP_IPV6_PREFIX_LEN;

/// Configures host-side TAP interfaces after QEMU creates them.
///
/// Cloud-hypervisor performs this automatically via `NetConfig.ip` /
/// `NetConfig.mask`, but QEMU's `-netdev tap` only creates the TAP
/// device — it does not assign addresses or bring the link up.
///
/// This function uses rtnetlink to:
///
/// 1. Look up each TAP by name to obtain its interface index.
/// 2. Bring the link administratively UP.
/// 3. Assign the configured IPv6 link-local address with a /64 prefix.
///
/// These addresses generate NDP traffic (Neighbor Solicitation /
/// Neighbor Advertisement) on the TAPs, which is essential for Phase 1
/// rx validation tests — without traffic on the host side, the DPDK
/// guest has nothing to receive.
async fn configure_host_taps() -> Result<(), QemuError> {
    let (connection, handle, _) = rtnetlink::new_connection().map_err(|e| QemuError::TapSetup {
        tap: "<connection>".into(),
        reason: format!("failed to open netlink connection: {e}"),
    })?;

    // Spawn the netlink connection handler as a background task.
    // It runs until all Handle clones are dropped.
    tokio::spawn(connection);

    for iface in config::ALL_IFACES {
        let tap_name = iface.tap;

        // Look up the TAP by name to get its interface index.
        let mut links = handle
            .link()
            .get()
            .match_name(tap_name.to_string())
            .execute();

        use futures::TryStreamExt;
        let link = links.try_next().await.map_err(|e| QemuError::TapSetup {
            tap: tap_name.into(),
            reason: format!("failed to look up TAP device: {e}"),
        })?;

        let link = link.ok_or_else(|| QemuError::TapSetup {
            tap: tap_name.into(),
            reason: "TAP device not found (QEMU may not have created it yet)".into(),
        })?;

        let index = link.header.index;

        // Bring the TAP up.
        handle
            .link()
            .set(rtnetlink::LinkUnspec::new_with_index(index).up().build())
            .execute()
            .await
            .map_err(|e| QemuError::TapSetup {
                tap: tap_name.into(),
                reason: format!("failed to bring TAP up: {e}"),
            })?;

        // Assign the IPv6 link-local address.
        handle
            .address()
            .add(
                index,
                std::net::IpAddr::V6(iface.host_ipv6),
                TAP_IPV6_PREFIX_LEN,
            )
            .execute()
            .await
            .map_err(|e| QemuError::TapSetup {
                tap: tap_name.into(),
                reason: format!(
                    "failed to add IPv6 address {}/{}: {e}",
                    iface.host_ipv6, TAP_IPV6_PREFIX_LEN,
                ),
            })?;

        debug!(
            tap = tap_name,
            index,
            ipv6 = %iface.host_ipv6,
            prefix_len = TAP_IPV6_PREFIX_LEN,
            "configured host-side TAP",
        );
    }

    Ok(())
}

// ── Process spawning ─────────────────────────────────────────────────

/// Verifies KVM and hugepage accessibility, spawns the QEMU process,
/// waits for the QMP socket, and establishes the QMP connection.
///
/// QEMU boots the VM immediately on process start (no separate
/// `create_vm` / `boot_vm` calls), so by the time the QMP connection is
/// established the VM is either running or has already failed to boot.
///
/// If the QMP socket appears but the connection or negotiation fails
/// (e.g. QEMU crashes during early init), this function attempts to
/// drain the child's stderr and log it before returning the error.
/// Without this, the QEMU error output would be silently lost because
/// the `dispatch` layer panics on [`VmError`] before the normal
/// [`collect`](crate::vm::TestVm::collect) phase runs.
async fn spawn_qemu_process(
    params: &TestVmParams<'_>,
) -> Result<(tokio::process::Child, QmpConnection), VmError> {
    // KVM is only needed under hardware acceleration; a TCG (cross-arch)
    // guest does not touch /dev/kvm.
    if params.accel == config::Accel::Kvm {
        check_kvm_accessible().await?;
    }
    check_hugepages_accessible(params.vm_config.host_page_size).await?;

    let args = build_qemu_args(params);

    let qemu_binary = config::Arch::current().qemu_system_binary();
    debug!("spawning QEMU: {qemu_binary} {}", args.join(" "));

    let mut child = tokio::process::Command::new(qemu_binary)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(VmError::HypervisorSpawn)?;

    // Wait for QEMU to create the QMP socket, then connect and negotiate.
    // If either step fails, try to capture QEMU's stderr so the developer
    // can see why QEMU crashed rather than just "Connection reset by peer".
    let socket_result = wait_for_socket(HYPERVISOR_API_SOCKET_PATH).await;
    if let Err(err) = socket_result {
        config::drain_child_stderr(&mut child, "QEMU").await;
        return Err(err);
    }

    match QmpConnection::connect(HYPERVISOR_API_SOCKET_PATH).await {
        Ok(qmp) => Ok((child, qmp)),
        Err(qmp_err) => {
            config::drain_child_stderr(&mut child, "QEMU").await;
            Err(qmp_err.into())
        }
    }
}

// ── CLI argument builders ────────────────────────────────────────────
//
// Each builder is a focused function responsible for a single aspect of
// the QEMU command line.  They can be tested and evolved independently;
// `build_qemu_args` composes them into the final argument vector.
//
// Arguments are pushed onto a `Vec<String>` rather than returned, so
// callers can compose multiple builders without intermediate allocation.

/// Builds the complete QEMU argument vector for a test run.
fn build_qemu_args(params: &TestVmParams<'_>) -> Vec<String> {
    let iommu = params.vm_config.iommu;
    let mut args = Vec::with_capacity(64);
    push_machine_args(&mut args, iommu, params.accel);
    push_cpu_args(&mut args);
    push_memory_args(&mut args, params.vm_config.host_page_size);
    push_iommu_args(&mut args, iommu);
    push_kernel_args(&mut args, params);
    push_fs_args(&mut args);
    push_vsock_args(&mut args, &params.vsock, iommu);
    push_network_args(&mut args, iommu, params.vm_config.nic_model);
    push_serial_args(&mut args);
    push_qmp_args(&mut args);
    push_platform_args(&mut args, params);
    push_misc_args(&mut args);
    args
}

/// Machine type and acceleration.
///
/// When `iommu` is `true`, adds `kernel-irqchip=split` to the machine
/// options.  This is required for the Intel IOMMU's interrupt remapping
/// to function: in split irqchip mode the in-kernel PIC/IOAPIC is
/// disabled so that interrupt routing goes through the emulated IOMMU.
///
/// Under [`Accel::Kvm`] the machine uses `accel=kvm` with `-enable-kvm`
/// and `-cpu host`.  Under [`Accel::Tcg`] (cross-arch guest) it uses
/// `accel=tcg` with `-cpu max` and omits `-enable-kvm`.
///
/// Note: the `q35` machine type and Intel-IOMMU interrupt-remapping
/// assumptions here are still x86_64-specific; an aarch64 guest needs the
/// `virt` machine and a different IOMMU/irqchip story (a follow-up).
fn push_machine_args(args: &mut Vec<String>, iommu: bool, accel: config::Accel) {
    let arch = config::Arch::current();
    let accel_opt = match accel {
        config::Accel::Kvm => "accel=kvm",
        config::Accel::Tcg => "accel=tcg",
    };
    let mut machine = format!("{base},{accel_opt}", base = arch.qemu_machine_base());
    // Intel IOMMU interrupt remapping requires split irqchip (x86 only).
    if iommu && arch.supports_virtual_iommu() {
        machine.push_str(",kernel-irqchip=split");
    }
    if accel == config::Accel::Kvm {
        args.push("-enable-kvm".into());
    }
    args.extend([
        "-machine".into(),
        machine,
        "-cpu".into(),
        // `host` requires KVM; `max` is the richest TCG-emulable CPU model.
        match accel {
            config::Accel::Kvm => "host".into(),
            config::Accel::Tcg => "max".into(),
        },
    ]);
}

/// CPU count and topology.
///
/// Matches the cloud-hypervisor backend: 6 vCPUs arranged as
/// 1 socket × 3 dies × 1 core × 2 threads.
fn push_cpu_args(args: &mut Vec<String>) {
    // The `-smp dies=` level is x86-specific; `smp_topology` omits it on
    // aarch64 while preserving the total vCPU count.
    args.extend(["-smp".into(), config::Arch::current().smp_topology()]);
}

/// Memory configuration with hugepage backing and sharing.
/// Shared memory backend with optional hugepage backing.
///
/// - [`Standard`](config::HostPageSize::Standard) -- uses
///   `memory-backend-memfd` with `share=on`.  No hugetlbfs mount
///   required.
/// - [`Huge2M`](config::HostPageSize::Huge2M) /
///   [`Huge1G`](config::HostPageSize::Huge1G) -- uses
///   `memory-backend-file` backed by `/dev/hugepages` with `share=on`
///   and `prealloc=on` (ensures hugepages are allocated at VM start
///   rather than on first access).
///
/// `share=on` is always set because virtiofsd (vhost-user-fs-pci)
/// requires `MAP_SHARED` memory to access the guest address space from
/// a separate process.
///
/// The `-numa node,memdev=mem0` argument assigns the memory backend to
/// a NUMA node, which is how QEMU associates a memory backend with the
/// guest's address space.
fn push_memory_args(args: &mut Vec<String>, host_page_size: config::HostPageSize) {
    let mib = config::VM_MEMORY_MIB;
    let backend = if host_page_size.requires_hugepages() {
        format!(
            "memory-backend-file,id=mem0,size={mib}M,\
             mem-path=/dev/hugepages,share=on,prealloc=on"
        )
    } else {
        format!("memory-backend-memfd,id=mem0,size={mib}M,share=on")
    };
    args.extend([
        "-m".into(),
        format!("{mib}M"),
        "-object".into(),
        backend,
        "-numa".into(),
        "node,memdev=mem0".into(),
    ]);
}

/// Intel IOMMU device for DMA remapping.
///
/// When `iommu` is `true`, adds an `intel-iommu` device with:
///
/// - **`intremap=on`** -- interrupt remapping, required for proper MSI
///   isolation between devices.
/// - **`device-iotlb=on`** -- device-side IOTLB for Address Translation
///   Services (ATS), enabling virtio devices with `ats=on` to cache
///   IOMMU translations on the device side.
/// - **`caching-mode=on`** -- required for vhost-based devices (e.g.
///   `vhost-user-fs-pci`) that perform DMA from a separate process
///   without going through QEMU's emulated IOMMU data path.
///
/// The machine type must use `kernel-irqchip=split` (see
/// [`push_machine_args`]) for interrupt remapping to function.
///
/// Unlike cloud-hypervisor's per-segment IOMMU model, QEMU's Intel
/// IOMMU covers the entire PCI topology.  Individual virtio devices
/// opt in via `iommu_platform=on,ats=on` on their device strings (see
/// [`push_network_args`], [`push_vsock_args`]).
///
/// The `vhost-user-fs-pci` device does **not** support
/// `iommu_platform`; vhost-user devices perform DMA from a separate
/// userspace process rather than through QEMU's emulated IOMMU data
/// path.  `caching-mode=on` on the Intel IOMMU handles this case.
fn push_iommu_args(args: &mut Vec<String>, iommu: bool) {
    if iommu {
        args.extend([
            "-device".into(),
            "intel-iommu,intremap=on,device-iotlb=on,caching-mode=on".into(),
        ]);
    }
}

/// Kernel image and command line.
///
/// The kernel command line is built by [`config::build_kernel_cmdline`],
/// shared with the cloud-hypervisor backend to ensure both backends
/// present an identical guest environment.
///
/// When `params.vm_config.iommu` is `true`, the VFIO no-IOMMU escape
/// hatch is omitted so that VFIO is forced to use the virtual IOMMU
/// for DMA remapping — which is the purpose of the vIOMMU test
/// configuration.
fn push_kernel_args(args: &mut Vec<String>, params: &TestVmParams<'_>) {
    let cmdline = config::build_kernel_cmdline(
        &params.vm_bin_path,
        params.test_name,
        &params.vsock,
        params.vm_config.iommu,
        &params.vm_config.guest_hugepages,
    );

    args.extend([
        "-kernel".into(),
        config::Arch::current().kernel_image_path().into(),
        "-append".into(),
        cmdline,
    ]);
}

/// Virtiofs filesystem device for sharing the container filesystem.
///
/// Uses `vhost-user-fs-pci` with a chardev pointing at the virtiofsd
/// socket, matching the cloud-hypervisor backend's filesystem
/// configuration.
///
/// The `vhost-user-fs-pci` device does **not** support
/// `iommu_platform=on` because vhost-user devices perform DMA from a
/// separate userspace process (virtiofsd) rather than through QEMU's
/// emulated IOMMU data path.  The Intel IOMMU's `caching-mode=on`
/// (set in [`push_iommu_args`]) covers this case instead.
fn push_fs_args(args: &mut Vec<String>) {
    args.extend([
        "-chardev".into(),
        format!("socket,id=virtiofs0,path={VIRTIOFSD_SOCKET_PATH}"),
        "-device".into(),
        format!(
            "vhost-user-fs-pci,queue-size={qs},\
             chardev=virtiofs0,tag={VIRTIOFS_ROOT_TAG}",
            qs = config::VIRTIOFS_QUEUE_SIZE,
        ),
    ]);
}

/// Vsock device for guest-to-host communication.
///
/// Always uses `vhost-vsock-pci-non-transitional` (virtio 1.0+ only)
/// because the test environment targets modern kernels and there is no
/// need to exercise the legacy virtio transport path.
///
/// When `iommu` is `true`, adds `iommu_platform=on,ats=on` so that
/// vsock I/O is routed through the virtual IOMMU.
///
/// # Limitations
///
/// See the [module-level documentation](self) for the vsock bridging
/// limitation: this device uses kernel vhost-vsock (AF_VSOCK on the
/// host), while the [`TestVm`](crate::vm::TestVm) infrastructure
/// expects Unix sockets at `$VHOST_SOCKET_$PORT` paths.
fn push_vsock_args(args: &mut Vec<String>, vsock: &VsockAllocation, iommu: bool) {
    let iommu_suffix = if iommu {
        ",iommu_platform=on,ats=on"
    } else {
        ""
    };
    args.extend([
        "-device".into(),
        format!(
            "vhost-vsock-pci-non-transitional,guest-cid={}{iommu_suffix}",
            vsock.cid.as_raw()
        ),
    ]);
}

/// Network interfaces.
///
/// Creates three TAP-backed virtio-net-pci devices matching the
/// cloud-hypervisor backend:
///
/// - **mgmt** -- management network.
/// - **fabric1** / **fabric2** -- fabric-facing interfaces.
///
/// Note: QEMU's virtio-net-pci device does not support an MTU property
/// on the command line.  TAP MTU must be configured separately (e.g. via
/// `ip link set`) if non-default MTU is required.  The cloud-hypervisor
/// backend sets MTU in the device configuration, which cloud-hypervisor
/// applies to the TAP devices automatically.
///
/// # NIC model selection
///
/// The `nic_model` parameter selects the QEMU device type:
///
/// - [`VirtioNet`](config::NicModel::VirtioNet) --
///   `virtio-net-pci-non-transitional` (virtio 1.0+ only).  When
///   `iommu` is `true`, adds `iommu_platform=on,ats=on` so that
///   network I/O is routed through the virtual IOMMU.
///
/// - [`E1000`](config::NicModel::E1000) -- Intel 82540EM (`e1000`).
///   This is a fully emulated legacy NIC.  It does not support
///   `iommu_platform` or ATS (not a virtio device), but DMA is still
///   remapped by the Intel IOMMU when present because the IOMMU covers
///   the entire PCI topology.
///
/// - [`E1000E`](config::NicModel::E1000E) -- Intel 82574L (`e1000e`).
///   A newer emulated Intel GbE NIC with improved feature support
///   (MSI-X, hardware offloads).  Like `e1000`, it does not support
///   `iommu_platform` or ATS but sits behind the Intel IOMMU on the
///   PCI bus.
fn push_network_args(args: &mut Vec<String>, iommu: bool, nic_model: config::NicModel) {
    for iface in config::ALL_IFACES {
        // The TAP netdev is the same regardless of the front-end device
        // model -- it just bridges a host TAP interface into the guest.
        args.extend([
            "-netdev".into(),
            format!(
                "tap,id=nd-{id},ifname={tap},script=no,downscript=no",
                id = iface.id,
                tap = iface.tap,
            ),
        ]);

        // The front-end device string depends on the NIC model.
        let device_str = match nic_model {
            config::NicModel::VirtioNet => {
                let iommu_suffix = if iommu {
                    ",iommu_platform=on,ats=on"
                } else {
                    ""
                };
                format!(
                    "virtio-net-pci-non-transitional,netdev=nd-{id},mac={mac}{iommu_suffix}",
                    id = iface.id,
                    mac = iface.mac,
                )
            }
            config::NicModel::E1000 => {
                // e1000 is a legacy emulated NIC -- no iommu_platform or
                // ATS support.  The Intel IOMMU still intercepts DMA from
                // this device when present on the PCI bus.
                format!(
                    "e1000,netdev=nd-{id},mac={mac}",
                    id = iface.id,
                    mac = iface.mac,
                )
            }
            config::NicModel::E1000E => {
                // e1000e (Intel 82574L) is a newer emulated NIC with
                // MSI-X and hardware offloads.  Same IOMMU story as
                // e1000: no iommu_platform/ATS, but DMA is remapped
                // by the Intel IOMMU when present.
                format!(
                    "e1000e,netdev=nd-{id},mac={mac}",
                    id = iface.id,
                    mac = iface.mac,
                )
            }
        };

        args.extend(["-device".into(), device_str]);
    }
}

/// Serial console on a Unix socket.
///
/// QEMU creates the socket in server mode (`server=on`) and does not
/// block waiting for a client (`wait=off`).  Console output is buffered
/// until the container tier's kernel-log reader connects.
fn push_serial_args(args: &mut Vec<String>) {
    args.extend([
        "-serial".into(),
        format!("unix:{KERNEL_CONSOLE_SOCKET_PATH},server=on,wait=off"),
    ]);
}

/// QMP control socket for lifecycle commands and event monitoring.
///
/// Creates a chardev socket in server mode and attaches a QMP monitor
/// to it.  The container tier connects to this socket after the QEMU
/// process starts.
fn push_qmp_args(args: &mut Vec<String>) {
    args.extend([
        "-chardev".into(),
        format!("socket,id=qmp0,path={HYPERVISOR_API_SOCKET_PATH},server=on,wait=off"),
        "-mon".into(),
        "chardev=qmp0,mode=control".into(),
    ]);
}

/// SMBIOS tables for test identification and miscellaneous platform
/// settings.
///
/// Embeds the test binary name and test name in SMBIOS OEM strings
/// (type 11), matching the cloud-hypervisor backend's
/// `PlatformConfig.oem_strings`.  Also sets a serial number and UUID
/// in the system information table (type 1).
fn push_platform_args(args: &mut Vec<String>, params: &TestVmParams<'_>) {
    args.extend([
        "-smbios".into(),
        "type=1,serial=dataplane-test,uuid=dff9c8dd-492d-4148-a007-7931f94db852".into(),
        "-smbios".into(),
        format!(
            "type=11,value=exe={bin_name},value=test={test_name}",
            bin_name = params.bin_name,
            test_name = params.test_name,
        ),
    ]);
}

/// Miscellaneous flags.
///
/// - `-display none` -- suppress graphical output.
/// - `-no-reboot` -- exit on guest reboot rather than restarting.
/// - `-no-shutdown` -- pause on guest shutdown rather than exiting, so
///   the QMP event watcher has time to capture the `SHUTDOWN` event
///   before the socket closes.  The [`shutdown`](Qemu::shutdown) method
///   sends `quit` to terminate the paused VMM.
/// - `-device pvpanic` -- enable guest panic detection via the pvpanic
///   PCI device.  When the guest kernel panics, QEMU emits a
///   `GUEST_PANICKED` QMP event.
fn push_misc_args(args: &mut Vec<String>) {
    args.extend([
        "-display".into(),
        "none".into(),
        "-no-reboot".into(),
        "-no-shutdown".into(),
        "-device".into(),
        config::Arch::current().pvpanic_device().into(),
    ]);
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::config::VM_MEMORY_MIB;
    use n_vm_protocol::INIT_BINARY_PATH;

    const VIRTIOFS_QUEUE_SIZE: u32 = crate::config::VIRTIOFS_QUEUE_SIZE;

    /// Builds a representative [`TestVmParams`] for use in CLI builder
    /// tests.  The values are arbitrary but realistic.
    fn sample_params() -> TestVmParams<'static> {
        TestVmParams {
            full_bin_path: Path::new("/deps/my_test-abc123"),
            vm_bin_path: format!("/{}/my_test-abc123", n_vm_protocol::VM_TEST_BIN_DIR),
            bin_name: "my_test-abc123",
            test_name: "module::test_name",
            vm_config: config::VmConfig::default(),
            accel: config::Accel::Kvm,
            vsock: n_vm_protocol::VsockAllocation::with_defaults(),
        }
    }

    // ── Machine and CPU ──────────────────────────────────────────────

    #[test]
    fn machine_args_enable_kvm_with_q35() {
        let mut args = Vec::new();
        push_machine_args(&mut args, false, config::Accel::Kvm);
        assert!(args.contains(&"-enable-kvm".to_string()));
        assert!(args.contains(&"q35,accel=kvm".to_string()));
        assert!(args.contains(&"host".to_string()));
    }

    #[test]
    fn machine_args_use_tcg_without_kvm() {
        let mut args = Vec::new();
        push_machine_args(&mut args, false, config::Accel::Tcg);
        assert!(
            !args.contains(&"-enable-kvm".to_string()),
            "TCG must not pass -enable-kvm: {args:?}",
        );
        assert!(args.contains(&"q35,accel=tcg".to_string()), "{args:?}");
        assert!(
            args.contains(&"max".to_string()),
            "TCG should use -cpu max, not host: {args:?}",
        );
        assert!(
            !args.contains(&"host".to_string()),
            "TCG must not use -cpu host: {args:?}",
        );
    }

    #[test]
    fn cpu_args_have_six_vcpus() {
        let mut args = Vec::new();
        push_cpu_args(&mut args);
        let smp = &args[1];
        assert!(smp.starts_with("6,"), "expected 6 vCPUs: {smp}");
    }

    #[test]
    fn cpu_topology_matches_cloud_hypervisor() {
        let mut args = Vec::new();
        push_cpu_args(&mut args);
        let smp = &args[1];
        assert!(smp.contains("sockets=1"), "{smp}");
        assert!(smp.contains("dies=3"), "{smp}");
        assert!(smp.contains("cores=1"), "{smp}");
        assert!(smp.contains("threads=2"), "{smp}");
    }

    // ── Memory ───────────────────────────────────────────────────────

    #[test]
    fn memory_args_set_ram_size() {
        let mut args = Vec::new();
        push_memory_args(&mut args, config::HostPageSize::default());
        let idx = args.iter().position(|a| a == "-m").unwrap();
        assert_eq!(args[idx + 1], format!("{VM_MEMORY_MIB}M"));
    }

    #[test]
    fn memory_args_use_hugepages_with_sharing_for_1g() {
        let mut args = Vec::new();
        push_memory_args(&mut args, config::HostPageSize::Huge1G);
        let obj = args
            .iter()
            .find(|a| a.starts_with("memory-backend-file"))
            .unwrap();
        assert!(obj.contains("size=1024M"), "{obj}");
        assert!(obj.contains("mem-path=/dev/hugepages"), "{obj}");
        assert!(obj.contains("share=on"), "{obj}");
        assert!(obj.contains("prealloc=on"), "{obj}");
    }

    #[test]
    fn memory_args_use_hugepages_with_sharing_for_2m() {
        let mut args = Vec::new();
        push_memory_args(&mut args, config::HostPageSize::Huge2M);
        let obj = args
            .iter()
            .find(|a| a.starts_with("memory-backend-file"))
            .unwrap();
        assert!(obj.contains("mem-path=/dev/hugepages"), "{obj}");
        assert!(obj.contains("share=on"), "{obj}");
        assert!(obj.contains("prealloc=on"), "{obj}");
    }

    #[test]
    fn memory_args_use_memfd_for_standard_pages() {
        let mut args = Vec::new();
        push_memory_args(&mut args, config::HostPageSize::Standard);
        let obj = args
            .iter()
            .find(|a| a.starts_with("memory-backend-memfd"))
            .expect("standard pages should use memory-backend-memfd");
        assert!(obj.contains("share=on"), "{obj}");
        assert!(
            !obj.contains("hugepages"),
            "standard pages should not reference hugepages: {obj}"
        );
    }

    #[test]
    fn memory_args_include_numa_node() {
        let mut args = Vec::new();
        push_memory_args(&mut args, config::HostPageSize::default());
        assert!(args.contains(&"node,memdev=mem0".to_string()));
    }

    // ── Kernel ───────────────────────────────────────────────────────

    #[test]
    fn kernel_args_use_kernel_image_path() {
        let mut args = Vec::new();
        push_kernel_args(&mut args, &sample_params());
        let idx = args.iter().position(|a| a == "-kernel").unwrap();
        assert_eq!(args[idx + 1], config::Arch::current().kernel_image_path());
    }

    #[test]
    fn kernel_cmdline_embeds_test_binary_and_name() {
        let mut args = Vec::new();
        push_kernel_args(&mut args, &sample_params());
        let idx = args.iter().position(|a| a == "-append").unwrap();
        let cmdline = &args[idx + 1];
        let expected = format!("/{}/my_test-abc123", n_vm_protocol::VM_TEST_BIN_DIR);
        assert!(
            cmdline.contains(&expected),
            "cmdline should contain the VM-side binary path ({expected}): {cmdline}",
        );
        assert!(cmdline.contains("module::test_name"), "{cmdline}");
    }

    #[test]
    fn kernel_cmdline_sets_init_binary() {
        let mut args = Vec::new();
        push_kernel_args(&mut args, &sample_params());
        let idx = args.iter().position(|a| a == "-append").unwrap();
        let cmdline = &args[idx + 1];
        assert!(
            cmdline.contains(&format!("init={INIT_BINARY_PATH}")),
            "{cmdline}"
        );
    }

    #[test]
    fn kernel_cmdline_enables_hugepages() {
        let mut args = Vec::new();
        push_kernel_args(&mut args, &sample_params());
        let idx = args.iter().position(|a| a == "-append").unwrap();
        let cmdline = &args[idx + 1];
        assert!(cmdline.contains("default_hugepagesz=1G"), "{cmdline}");
        assert!(cmdline.contains("hugepagesz=1G"), "{cmdline}");
        assert!(cmdline.contains("hugepages=1"), "{cmdline}");
    }

    #[test]
    fn kernel_cmdline_passes_exact_flag() {
        let mut args = Vec::new();
        push_kernel_args(&mut args, &sample_params());
        let idx = args.iter().position(|a| a == "-append").unwrap();
        let cmdline = &args[idx + 1];
        assert!(cmdline.contains("--exact"), "{cmdline}");
        assert!(cmdline.contains("--no-capture"), "{cmdline}");
        assert!(cmdline.contains("--format=terse"), "{cmdline}");
    }

    #[test]
    fn kernel_cmdline_embeds_vsock_port_parameters() {
        let params = sample_params();
        let mut args = Vec::new();
        push_kernel_args(&mut args, &params);
        let idx = args.iter().position(|a| a == "-append").unwrap();
        let cmdline = &args[idx + 1];
        let fragment = params.vsock.kernel_cmdline_fragment();
        assert!(
            cmdline.contains(&fragment),
            "kernel cmdline should contain vsock port parameters ({fragment}): {cmdline}",
        );
    }

    // ── Filesystem ───────────────────────────────────────────────────

    #[test]
    fn fs_args_use_virtiofs_tag_and_socket() {
        let mut args = Vec::new();
        push_fs_args(&mut args);
        let chardev = args
            .iter()
            .find(|a| a.starts_with("socket,id=virtiofs0"))
            .unwrap();
        assert!(chardev.contains(VIRTIOFSD_SOCKET_PATH), "{chardev}");
        let device = args
            .iter()
            .find(|a| a.starts_with("vhost-user-fs-pci"))
            .unwrap();
        assert!(device.contains(VIRTIOFS_ROOT_TAG), "{device}");
        assert!(
            device.contains(&format!("queue-size={VIRTIOFS_QUEUE_SIZE}")),
            "{device}"
        );
    }

    // ── vsock ────────────────────────────────────────────────────────

    #[test]
    fn vsock_args_use_guest_cid() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let mut args = Vec::new();
        push_vsock_args(&mut args, &vsock, false);
        let device = args
            .iter()
            .find(|a| a.starts_with("vhost-vsock-pci"))
            .unwrap();
        assert!(
            device.contains(&format!("guest-cid={}", vsock.cid.as_raw())),
            "{device}"
        );
    }

    // ── Network ──────────────────────────────────────────────────────

    #[test]
    fn network_args_have_three_interfaces() {
        let mut args = Vec::new();
        push_network_args(&mut args, false, config::NicModel::VirtioNet);
        let netdev_count = args.iter().filter(|a| a.starts_with("tap,")).count();
        let device_count = args
            .iter()
            .filter(|a| a.starts_with("virtio-net-pci-non-transitional,"))
            .count();
        assert_eq!(netdev_count, 3);
        assert_eq!(device_count, 3);
    }

    #[test]
    fn all_interfaces_have_unique_mac_addresses() {
        let mut args = Vec::new();
        push_network_args(&mut args, false, config::NicModel::VirtioNet);
        let macs: Vec<&str> = args
            .iter()
            .filter_map(|a| {
                a.split(',')
                    .find(|part| part.starts_with("mac="))
                    .map(|p| &p[4..])
            })
            .collect();
        assert_eq!(macs.len(), 3);
        let mut unique = macs.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 3, "MAC addresses must be unique: {macs:?}");
    }

    #[test]
    fn all_interfaces_have_unique_tap_names() {
        let mut args = Vec::new();
        push_network_args(&mut args, false, config::NicModel::VirtioNet);
        let taps: Vec<&str> = args
            .iter()
            .filter_map(|a| {
                a.split(',')
                    .find(|part| part.starts_with("ifname="))
                    .map(|p| &p[7..])
            })
            .collect();
        assert_eq!(taps.len(), 3);
        let mut unique = taps.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 3, "TAP names must be unique: {taps:?}");
    }

    // ── Serial ───────────────────────────────────────────────────────

    #[test]
    fn serial_args_use_socket_mode() {
        let mut args = Vec::new();
        push_serial_args(&mut args);
        let serial = args.iter().find(|a| a.starts_with("unix:")).unwrap();
        assert!(serial.contains(KERNEL_CONSOLE_SOCKET_PATH), "{serial}");
        assert!(serial.contains("server=on"), "{serial}");
        assert!(serial.contains("wait=off"), "{serial}");
    }

    // ── QMP ──────────────────────────────────────────────────────────

    #[test]
    fn qmp_args_create_control_socket() {
        let mut args = Vec::new();
        push_qmp_args(&mut args);
        let chardev = args
            .iter()
            .find(|a| a.starts_with("socket,id=qmp0"))
            .unwrap();
        assert!(chardev.contains(HYPERVISOR_API_SOCKET_PATH), "{chardev}");
        assert!(chardev.contains("server=on"), "{chardev}");
        assert!(chardev.contains("wait=off"), "{chardev}");
        assert!(args.contains(&"chardev=qmp0,mode=control".to_string()));
    }

    // ── Platform / SMBIOS ────────────────────────────────────────────

    #[test]
    fn platform_args_embed_binary_and_test_name() {
        let mut args = Vec::new();
        push_platform_args(&mut args, &sample_params());
        let oem = args.iter().find(|a| a.starts_with("type=11,")).unwrap();
        assert!(oem.contains("exe=my_test-abc123"), "{oem}");
        assert!(oem.contains("test=module::test_name"), "{oem}");
    }

    #[test]
    fn platform_args_set_serial_and_uuid() {
        let mut args = Vec::new();
        push_platform_args(&mut args, &sample_params());
        let sys = args.iter().find(|a| a.starts_with("type=1,")).unwrap();
        assert!(sys.contains("serial=dataplane-test"), "{sys}");
        assert!(sys.contains("uuid="), "{sys}");
    }

    // ── Misc ─────────────────────────────────────────────────────────

    #[test]
    fn misc_args_disable_display() {
        let mut args = Vec::new();
        push_misc_args(&mut args);
        assert!(args.contains(&"none".to_string()));
    }

    #[test]
    fn misc_args_enable_no_reboot_and_no_shutdown() {
        let mut args = Vec::new();
        push_misc_args(&mut args);
        assert!(args.contains(&"-no-reboot".to_string()));
        assert!(args.contains(&"-no-shutdown".to_string()));
    }

    #[test]
    fn misc_args_enable_pvpanic() {
        let mut args = Vec::new();
        push_misc_args(&mut args);
        assert!(args.contains(&"pvpanic".to_string()));
    }

    // ── Full arg vector ──────────────────────────────────────────────

    #[test]
    fn build_qemu_args_is_nonempty() {
        let args = build_qemu_args(&sample_params());
        assert!(!args.is_empty());
    }

    // ── vIOMMU configuration ─────────────────────────────────────────

    /// Helper that returns [`TestVmParams`] with vIOMMU enabled.
    fn sample_params_iommu() -> TestVmParams<'static> {
        let mut params = sample_params();
        params.vm_config.iommu = true;
        params
    }

    #[test]
    fn machine_args_use_irqchip_split_when_iommu_enabled() {
        let mut args = Vec::new();
        push_machine_args(&mut args, true, config::Accel::Kvm);
        assert!(
            args.contains(&"q35,accel=kvm,kernel-irqchip=split".to_string()),
            "iommu requires kernel-irqchip=split: {args:?}",
        );
    }

    #[test]
    fn machine_args_omit_irqchip_split_when_iommu_disabled() {
        let mut args = Vec::new();
        push_machine_args(&mut args, false, config::Accel::Kvm);
        assert!(
            args.contains(&"q35,accel=kvm".to_string()),
            "no kernel-irqchip=split without iommu: {args:?}",
        );
        assert!(
            !args.iter().any(|a| a.contains("kernel-irqchip")),
            "should not mention kernel-irqchip when iommu is disabled",
        );
    }

    #[test]
    fn iommu_args_present_when_enabled() {
        let mut args = Vec::new();
        push_iommu_args(&mut args, true);
        let device = args
            .iter()
            .find(|a| a.starts_with("intel-iommu"))
            .expect("should have an intel-iommu device");
        assert!(device.contains("intremap=on"), "{device}");
        assert!(device.contains("device-iotlb=on"), "{device}");
        assert!(device.contains("caching-mode=on"), "{device}");
    }

    #[test]
    fn iommu_args_absent_when_disabled() {
        let mut args = Vec::new();
        push_iommu_args(&mut args, false);
        assert!(args.is_empty(), "no IOMMU args when disabled");
    }

    #[test]
    fn network_devices_have_iommu_platform_when_enabled() {
        let mut args = Vec::new();
        push_network_args(&mut args, true, config::NicModel::VirtioNet);
        let devices: Vec<&String> = args
            .iter()
            .filter(|a| a.starts_with("virtio-net-pci-non-transitional,"))
            .collect();
        assert_eq!(devices.len(), 3);
        for dev in &devices {
            assert!(
                dev.contains("iommu_platform=on"),
                "device should have iommu_platform=on: {dev}",
            );
            assert!(dev.contains("ats=on"), "device should have ats=on: {dev}",);
        }
    }

    #[test]
    fn network_devices_omit_iommu_platform_when_disabled() {
        let mut args = Vec::new();
        push_network_args(&mut args, false, config::NicModel::VirtioNet);
        for arg in &args {
            assert!(
                !arg.contains("iommu_platform"),
                "should not contain iommu_platform when disabled: {arg}",
            );
        }
    }

    // ── e1000 NIC model ──────────────────────────────────────────────

    #[test]
    fn e1000_default_devices_as_virtio() {
        // e1000 requires_qemu but is not virtio -- sanity check.
        assert!(!config::NicModel::E1000.is_virtio());
        assert!(config::NicModel::E1000.requires_qemu());
    }

    #[test]
    fn e1000_network_args_have_three_interfaces() {
        let mut args = Vec::new();
        push_network_args(&mut args, false, config::NicModel::E1000);
        let netdev_count = args.iter().filter(|a| a.starts_with("tap,")).count();
        let device_count = args.iter().filter(|a| a.starts_with("e1000,")).count();
        assert_eq!(netdev_count, 3);
        assert_eq!(device_count, 3);
    }

    #[test]
    fn e1000_devices_have_no_iommu_platform_even_when_enabled() {
        let mut args = Vec::new();
        push_network_args(&mut args, true, config::NicModel::E1000);
        let devices: Vec<&String> = args.iter().filter(|a| a.starts_with("e1000,")).collect();
        assert_eq!(devices.len(), 3);
        for dev in &devices {
            assert!(
                !dev.contains("iommu_platform"),
                "e1000 should not have iommu_platform: {dev}",
            );
            assert!(!dev.contains("ats="), "e1000 should not have ats: {dev}",);
        }
    }

    #[test]
    fn e1000_devices_have_correct_mac_addresses() {
        let mut args = Vec::new();
        push_network_args(&mut args, false, config::NicModel::E1000);
        let macs: Vec<&str> = args
            .iter()
            .filter_map(|a| {
                a.split(',')
                    .find(|part| part.starts_with("mac="))
                    .map(|p| &p[4..])
            })
            .collect();
        assert_eq!(macs.len(), 3);
        let mut unique = macs.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            3,
            "e1000 MAC addresses must be unique: {macs:?}"
        );
    }

    #[test]
    fn e1000_network_args_use_same_tap_devices_as_virtio() {
        let mut virtio_args = Vec::new();
        push_network_args(&mut virtio_args, false, config::NicModel::VirtioNet);
        let mut e1000_args = Vec::new();
        push_network_args(&mut e1000_args, false, config::NicModel::E1000);

        let virtio_taps: Vec<&String> = virtio_args
            .iter()
            .filter(|a| a.starts_with("tap,"))
            .collect();
        let e1000_taps: Vec<&String> = e1000_args
            .iter()
            .filter(|a| a.starts_with("tap,"))
            .collect();
        assert_eq!(
            virtio_taps, e1000_taps,
            "TAP netdevs should be identical regardless of NIC model",
        );
    }

    // ── e1000e NIC model ─────────────────────────────────────────────

    #[test]
    fn e1000e_default_devices_as_virtio() {
        // e1000e requires_qemu but is not virtio -- sanity check.
        assert!(!config::NicModel::E1000E.is_virtio());
        assert!(config::NicModel::E1000E.requires_qemu());
    }

    #[test]
    fn e1000e_network_args_have_three_interfaces() {
        let mut args = Vec::new();
        push_network_args(&mut args, false, config::NicModel::E1000E);
        let netdev_count = args.iter().filter(|a| a.starts_with("tap,")).count();
        let device_count = args.iter().filter(|a| a.starts_with("e1000e,")).count();
        assert_eq!(netdev_count, 3);
        assert_eq!(device_count, 3);
    }

    #[test]
    fn e1000e_devices_have_no_iommu_platform_even_when_enabled() {
        let mut args = Vec::new();
        push_network_args(&mut args, true, config::NicModel::E1000E);
        let devices: Vec<&String> = args.iter().filter(|a| a.starts_with("e1000e,")).collect();
        assert_eq!(devices.len(), 3);
        for dev in &devices {
            assert!(
                !dev.contains("iommu_platform"),
                "e1000e should not have iommu_platform: {dev}",
            );
            assert!(!dev.contains("ats="), "e1000e should not have ats: {dev}",);
        }
    }

    #[test]
    fn e1000e_devices_have_correct_mac_addresses() {
        let mut args = Vec::new();
        push_network_args(&mut args, false, config::NicModel::E1000E);
        let macs: Vec<&str> = args
            .iter()
            .filter_map(|a| {
                a.split(',')
                    .find(|part| part.starts_with("mac="))
                    .map(|p| &p[4..])
            })
            .collect();
        assert_eq!(macs.len(), 3);
        let mut unique = macs.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            3,
            "e1000e MAC addresses must be unique: {macs:?}"
        );
    }

    #[test]
    fn e1000e_network_args_use_same_tap_devices_as_virtio() {
        let mut virtio_args = Vec::new();
        push_network_args(&mut virtio_args, false, config::NicModel::VirtioNet);
        let mut e1000e_args = Vec::new();
        push_network_args(&mut e1000e_args, false, config::NicModel::E1000E);

        let virtio_taps: Vec<&String> = virtio_args
            .iter()
            .filter(|a| a.starts_with("tap,"))
            .collect();
        let e1000e_taps: Vec<&String> = e1000e_args
            .iter()
            .filter(|a| a.starts_with("tap,"))
            .collect();
        assert_eq!(
            virtio_taps, e1000e_taps,
            "TAP netdevs should be identical regardless of NIC model",
        );
    }

    #[test]
    fn fs_device_never_has_iommu_platform() {
        let mut args = Vec::new();
        push_fs_args(&mut args);
        let device = args
            .iter()
            .find(|a| a.starts_with("vhost-user-fs-pci"))
            .unwrap();
        assert!(
            !device.contains("iommu_platform"),
            "vhost-user-fs-pci does not support iommu_platform: {device}",
        );
    }

    #[test]
    fn vsock_device_has_iommu_platform_when_enabled() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let mut args = Vec::new();
        push_vsock_args(&mut args, &vsock, true);
        let device = args
            .iter()
            .find(|a| a.starts_with("vhost-vsock-pci-non-transitional"))
            .unwrap();
        assert!(
            device.contains("iommu_platform=on,ats=on"),
            "vsock device should have iommu_platform: {device}",
        );
    }

    #[test]
    fn vsock_device_omits_iommu_platform_when_disabled() {
        let vsock = n_vm_protocol::VsockAllocation::with_defaults();
        let mut args = Vec::new();
        push_vsock_args(&mut args, &vsock, false);
        let device = args
            .iter()
            .find(|a| a.starts_with("vhost-vsock-pci-non-transitional,"))
            .unwrap();
        assert!(
            !device.contains("iommu_platform"),
            "vsock device should not have iommu_platform when disabled: {device}",
        );
    }

    #[test]
    fn full_args_with_iommu_contain_intel_iommu_device() {
        let args = build_qemu_args(&sample_params_iommu());
        assert!(
            args.iter().any(|a| a.starts_with("intel-iommu")),
            "full arg vector should contain intel-iommu device when iommu=true",
        );
    }

    #[test]
    fn full_args_without_iommu_omit_intel_iommu_device() {
        let args = build_qemu_args(&sample_params());
        assert!(
            !args.iter().any(|a| a.contains("intel-iommu")),
            "full arg vector should not contain intel-iommu when iommu=false",
        );
    }

    // ── Event log display ────────────────────────────────────────────

    #[test]
    fn empty_event_log_displays_nothing() {
        let log = QemuEventLog(vec![]);
        assert_eq!(format!("{log}"), "");
    }

    #[test]
    fn event_log_displays_one_line_per_event() {
        let log = QemuEventLog(vec![
            qapi_qmp::Event::SHUTDOWN {
                data: qapi_qmp::SHUTDOWN {
                    guest: true,
                    reason: qapi_qmp::ShutdownCause::guest_shutdown,
                },
                timestamp: serde_json::from_str(r#"{"seconds": 1, "microseconds": 0}"#).unwrap(),
            },
            qapi_qmp::Event::STOP {
                data: qapi_qmp::STOP {},
                timestamp: serde_json::from_str(r#"{"seconds": 2, "microseconds": 0}"#).unwrap(),
            },
        ]);
        let output = format!("{log}");
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2, "expected 2 lines:\n{output}");
        assert!(lines[0].contains("SHUTDOWN"), "{}", lines[0]);
        assert!(lines[1].contains("STOP"), "{}", lines[1]);
    }

    // ── Verdict computation ──────────────────────────────────────────

    /// A zero-valued timestamp for use in test events.
    fn ts() -> qapi_spec::Timestamp {
        serde_json::from_str(r#"{"seconds": 0, "microseconds": 0}"#).unwrap()
    }

    fn resume_event() -> qapi_qmp::Event {
        qapi_qmp::Event::RESUME {
            data: qapi_qmp::RESUME {},
            timestamp: ts(),
        }
    }

    fn shutdown_event() -> qapi_qmp::Event {
        qapi_qmp::Event::SHUTDOWN {
            data: qapi_qmp::SHUTDOWN {
                guest: true,
                reason: qapi_qmp::ShutdownCause::guest_shutdown,
            },
            timestamp: ts(),
        }
    }

    fn panic_event() -> qapi_qmp::Event {
        qapi_qmp::Event::GUEST_PANICKED {
            data: qapi_qmp::GUEST_PANICKED {
                action: qapi_qmp::GuestPanicAction::pause,
                info: None,
            },
            timestamp: ts(),
        }
    }

    #[test]
    fn clean_shutdown_without_errors() {
        let events = vec![resume_event(), shutdown_event()];
        assert_eq!(
            compute_verdict(&events, false),
            HypervisorVerdict::CleanShutdown,
        );
    }

    #[test]
    fn shutdown_with_stream_errors_is_failure() {
        let events = vec![resume_event(), shutdown_event()];
        assert_eq!(compute_verdict(&events, true), HypervisorVerdict::Failure);
    }

    #[test]
    fn panic_before_shutdown_is_failure() {
        let events = vec![resume_event(), panic_event(), shutdown_event()];
        assert_eq!(compute_verdict(&events, false), HypervisorVerdict::Failure);
    }

    #[test]
    fn panic_without_shutdown_is_failure() {
        let events = vec![resume_event(), panic_event()];
        assert_eq!(compute_verdict(&events, false), HypervisorVerdict::Failure);
    }

    #[test]
    fn stream_ended_without_shutdown_is_failure() {
        let events = vec![resume_event()];
        assert_eq!(compute_verdict(&events, false), HypervisorVerdict::Failure);
    }

    #[test]
    fn empty_event_log_is_failure() {
        assert_eq!(compute_verdict(&[], false), HypervisorVerdict::Failure);
    }

    #[test]
    fn events_after_shutdown_are_ignored_for_verdict() {
        let events = vec![resume_event(), shutdown_event(), panic_event()];
        assert_eq!(
            compute_verdict(&events, false),
            HypervisorVerdict::CleanShutdown,
        );
    }
}
