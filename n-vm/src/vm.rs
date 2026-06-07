// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! VM lifecycle management for the container tier.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use n_vm_protocol::{
    KERNEL_CONSOLE_SOCKET_PATH, TestResult, VIRTIOFS_ROOT_TAG, VIRTIOFSD_BINARY_PATH,
    VIRTIOFSD_SOCKET_PATH, VM_ROOT_SHARE_PATH, VsockAllocation, VsockChannel, VsockCid, VsockPort,
};
use rand::RngExt;
use tokio::io::AsyncReadExt;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::abort_on_drop::AbortOnDrop;
use crate::backend::{HypervisorBackend, HypervisorVerdict};
use crate::config;
use crate::error::VmError;

/// Maximum number of poll iterations before giving up on a socket.
const SOCKET_POLL_MAX_ATTEMPTS: u32 = 100;

/// Interval between socket existence checks.
const SOCKET_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Maximum time a KVM-accelerated VM test is allowed to run before forced
/// shutdown.
const VM_TEST_TIMEOUT_KVM: Duration = Duration::from_secs(60);

/// Maximum time a TCG (software-emulated, cross-arch) VM test is allowed to
/// run before forced shutdown.  TCG is far slower than KVM -- a guest
/// kernel boot alone can take tens of seconds -- so this is much larger.
const VM_TEST_TIMEOUT_TCG: Duration = Duration::from_secs(300);

/// The test timeout for the given acceleration mode.
fn vm_test_timeout(accel: config::Accel) -> Duration {
    match accel {
        config::Accel::Kvm => VM_TEST_TIMEOUT_KVM,
        config::Accel::Tcg => VM_TEST_TIMEOUT_TCG,
    }
}

/// Polls the filesystem until `path` exists, returning an error on timeout
/// or I/O failure.
pub(crate) async fn wait_for_socket(path: impl AsRef<Path>) -> Result<(), VmError> {
    let path = path.as_ref();
    for _ in 0..SOCKET_POLL_MAX_ATTEMPTS {
        match tokio::fs::try_exists(path).await {
            Ok(true) => return Ok(()),
            Ok(false) => {
                tokio::time::sleep(SOCKET_POLL_INTERVAL).await;
            }
            Err(err) => {
                return Err(VmError::SocketPoll {
                    path: path.to_path_buf(),
                    source: err,
                });
            }
        }
    }
    Err(VmError::SocketTimeout {
        path: path.to_path_buf(),
        timeout: SOCKET_POLL_INTERVAL.saturating_mul(SOCKET_POLL_MAX_ATTEMPTS),
    })
}

/// Verifies that `/dev/kvm` is accessible inside the container.
///
/// # Errors
///
/// Returns [`VmError::KvmNotAccessible`] if `/dev/kvm` does not exist or
/// cannot be stat'd.
pub(crate) async fn check_kvm_accessible() -> Result<(), VmError> {
    match tokio::fs::try_exists("/dev/kvm").await {
        Ok(true) => Ok(()),
        Ok(false) => Err(VmError::KvmNotAccessible(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "/dev/kvm does not exist",
        ))),
        Err(err) => Err(VmError::KvmNotAccessible(err)),
    }
}

/// Verifies that `/dev/hugepages` is accessible when host hugepages are needed.
///
/// # Errors
///
/// Returns [`VmError::HugepagesNotAccessible`] if `/dev/hugepages` does
/// not exist or cannot be stat'd and the host page size requires it.
pub(crate) async fn check_hugepages_accessible(
    host_page_size: config::HostPageSize,
) -> Result<(), VmError> {
    if !host_page_size.requires_hugepages() {
        return Ok(());
    }
    match tokio::fs::try_exists("/dev/hugepages").await {
        Ok(true) => Ok(()),
        Ok(false) => Err(VmError::HugepagesNotAccessible(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "/dev/hugepages does not exist; ensure hugetlbfs is mounted on the host \
             and propagated into the container",
        ))),
        Err(err) => Err(VmError::HugepagesNotAccessible(err)),
    }
}

/// Collected stdout and stderr from a child process.
pub struct ProcessOutput {
    /// Whether the process exited successfully (status code 0).
    pub success: bool,
    /// Captured stdout as a lossy UTF-8 string.
    pub stdout: String,
    /// Captured stderr as a lossy UTF-8 string.
    pub stderr: String,
}

impl ProcessOutput {
    /// Waits for a child process to exit and collects its stdout/stderr as
    /// UTF-8 strings.
    async fn from_child(child: tokio::process::Child, label: &str) -> Self {
        match child.wait_with_output().await {
            Ok(output) => Self {
                success: output.status.success(),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            },
            Err(err) => {
                error!("failed to collect {label} output: {err}");
                Self {
                    success: false,
                    stdout: String::new(),
                    stderr: format!("!!!OUTPUT UNAVAILABLE: {err}!!!"),
                }
            }
        }
    }

    /// Awaits a [`JoinHandle<String>`], returning a fallback message on failure.
    async fn join_task_or_fallback(handle: JoinHandle<String>, label: &str) -> String {
        match handle.await {
            Ok(output) => output,
            Err(err) => {
                error!("failed to join {label} task: {err}");
                format!("!!!{} UNAVAILABLE: {err}!!!", label.to_uppercase())
            }
        }
    }

    /// Formats stdout and stderr sections with the given label prefix.
    fn fmt_sections(&self, f: &mut std::fmt::Formatter<'_>, label: &str) -> std::fmt::Result {
        writeln!(f, "--------------- {label} stdout ---------------")?;
        writeln!(f, "{}", self.stdout)?;
        writeln!(f, "--------------- {label} stderr ---------------")?;
        writeln!(f, "{}", self.stderr)
    }
}

/// Parameters that vary per test invocation.
pub struct TestVmParams<'a> {
    /// Full path to the test binary (e.g. `/path/to/deps/my_test-abc123`).
    pub full_bin_path: &'a Path,
    /// Path to the test binary as seen by the VM guest.
    pub vm_bin_path: String,
    /// Short binary name (filename component only, e.g. `my_test-abc123`).
    pub bin_name: &'a str,
    /// Fully-qualified test name (e.g. `module::test_name`).
    pub test_name: &'a str,
    /// VM configuration controlling memory, hugepages, IOMMU, and NICs.
    pub vm_config: config::VmConfig,
    /// Acceleration mode (KVM for same-arch, TCG for a cross-arch guest).
    pub accel: config::Accel,
    /// Dynamically-allocated vsock resources for this VM instance.
    pub vsock: VsockAllocation,
}

/// Collected output from a test that ran inside a VM.
pub struct VmTestOutput<B: HypervisorBackend> {
    /// Whether the test passed and all infrastructure exited successfully.
    pub success: bool,
    /// Captured stdout and stderr from the test process (via vsock).
    pub test: ProcessOutput,
    /// Kernel serial console output (from the guest's `ttyS0`).
    pub console: String,
    /// Tracing output from the `n-it` init system, streamed via vsock.
    pub init_trace: String,
    /// Captured stdout, stderr, and exit status of the hypervisor process.
    pub hypervisor: ProcessOutput,
    /// Hypervisor lifecycle events collected during the VM's lifetime.
    pub hypervisor_events: B::EventLog,
    /// Captured stdout, stderr, and exit status of the virtiofsd process.
    pub virtiofsd: ProcessOutput,
}

impl<B: HypervisorBackend> std::fmt::Display for VmTestOutput<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=============== in_vm TEST RESULTS ===============")?;
        writeln!(f, "--------------- {} events ---------------", B::NAME)?;
        write!(f, "{}", self.hypervisor_events)?;
        self.hypervisor.fmt_sections(f, B::NAME)?;
        self.virtiofsd.fmt_sections(f, "virtiofsd")?;
        writeln!(f, "--------------- linux console ---------------")?;
        writeln!(f, "{}", self.console)?;
        writeln!(f, "--------------- init system ---------------")?;
        writeln!(f, "{}", self.init_trace)?;
        self.test.fmt_sections(f, "test")?;
        Ok(())
    }
}

/// Owns all long-lived resources for a running test VM.
pub struct TestVm<B: HypervisorBackend> {
    /// The hypervisor child process.
    hypervisor: tokio::process::Child,
    /// The virtiofsd child process.
    virtiofsd: tokio::process::Child,
    /// Backend-specific handle for lifecycle control.
    controller: B::Controller,
    /// Background task watching hypervisor lifecycle events.
    event_watcher: AbortOnDrop<(B::EventLog, HypervisorVerdict)>,
    /// Background task collecting init system tracing output via vsock.
    init_trace: AbortOnDrop<String>,
    /// Background task collecting test process stdout via vsock.
    test_stdout: AbortOnDrop<String>,
    /// Background task collecting test process stderr via vsock.
    test_stderr: AbortOnDrop<String>,
    /// Background task collecting the structured pass/fail verdict via vsock.
    test_result: AbortOnDrop<String>,
    /// Background task collecting kernel serial console output.
    kernel_log: AbortOnDrop<String>,
    /// Acceleration mode, used to scale the test timeout (TCG is slower).
    accel: config::Accel,
}

impl<B: HypervisorBackend> TestVm<B> {
    /// Spawns virtiofsd for the read-only VM root share.
    async fn launch_virtiofsd(path: impl AsRef<Path>) -> Result<tokio::process::Child, VmError> {
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        tokio::process::Command::new(VIRTIOFSD_BINARY_PATH)
            .arg("--shared-dir")
            .arg(path.as_ref())
            .arg("--readonly")
            .arg("--tag")
            .arg(VIRTIOFS_ROOT_TAG)
            .arg("--socket-path")
            .arg(VIRTIOFSD_SOCKET_PATH)
            .arg("--announce-submounts")
            .arg("--sandbox=none")
            .arg("--rlimit-nofile=0")
            .arg(format!(
                "--translate-uid=squash-host:0:{uid}:{MAX}",
                MAX = u32::MAX
            ))
            .arg(format!(
                "--translate-gid=squash-host:0:{gid}:{MAX}",
                MAX = u32::MAX
            ))
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(VmError::VirtiofsdSpawn)
    }

    /// Spawns a background task that reads the kernel serial console.
    fn spawn_kernel_log_reader() -> AbortOnDrop<String> {
        AbortOnDrop::spawn(async move {
            if let Err(e) = wait_for_socket(KERNEL_CONSOLE_SOCKET_PATH).await {
                return format!("!!!KERNEL LOG UNAVAILABLE: socket not ready: {e}!!!");
            }
            match tokio::net::UnixStream::connect(KERNEL_CONSOLE_SOCKET_PATH).await {
                Ok(mut stream) => {
                    let mut log = String::with_capacity(16_384);
                    if let Err(e) = stream.read_to_string(&mut log).await {
                        warn!("error reading kernel console: {e}");
                    }
                    log
                }
                Err(e) => format!("!!!KERNEL LOG UNAVAILABLE: connect failed: {e}!!!"),
            }
        })
    }

    /// Prepares the environment and boots the VM.
    pub async fn launch(params: &TestVmParams<'_>) -> Result<Self, VmError> {
        params
            .vm_config
            .validate_memory_alignment()
            .unwrap_or_else(|msg| panic!("VM configuration error: {msg}"));

        // The virtual-IOMMU configuration is x86-only for now (Intel IOMMU);
        // aarch64 SMMUv3 wiring is a follow-up.  Fail loudly rather than
        // emitting a config that silently lacks the requested IOMMU.
        let arch = config::Arch::current();
        assert!(
            !params.vm_config.iommu || arch.supports_virtual_iommu(),
            "VM configuration error: virtual IOMMU (iommu = true) is not supported on {arch:?} yet",
        );

        let mut virtiofsd = Self::launch_virtiofsd(VM_ROOT_SHARE_PATH).await?;

        // virtiofsd creates its socket asynchronously after process start.
        if let Err(err) = wait_for_socket(VIRTIOFSD_SOCKET_PATH).await {
            config::drain_child_stderr(&mut virtiofsd, "virtiofsd").await;
            return Err(err);
        }

        // Bind readers before boot so guest-side vsock connects succeed.
        let init_trace = B::spawn_vsock_reader(&params.vsock.init_trace)?;
        let test_stdout = B::spawn_vsock_reader(&params.vsock.test_stdout)?;
        let test_stderr = B::spawn_vsock_reader(&params.vsock.test_stderr)?;
        let test_result = B::spawn_vsock_reader(&params.vsock.result)?;

        let launched = B::launch(params).await?;

        let kernel_log = Self::spawn_kernel_log_reader();

        Ok(Self {
            hypervisor: launched.child,
            virtiofsd,
            controller: launched.controller,
            event_watcher: launched.event_watcher,
            init_trace,
            test_stdout,
            test_stderr,
            test_result,
            kernel_log,
            accel: params.accel,
        })
    }

    /// Waits for the test to finish and collects output from all subsystems.
    pub async fn collect(self) -> VmTestOutput<B> {
        let Self {
            hypervisor,
            virtiofsd,
            controller,
            event_watcher,
            init_trace,
            test_stdout,
            test_stderr,
            test_result,
            kernel_log,
            accel,
        } = self;

        let event_watcher = event_watcher.into_inner();
        let init_trace = init_trace.into_inner();
        let test_stdout = test_stdout.into_inner();
        let test_stderr = test_stderr.into_inner();
        let test_result = test_result.into_inner();
        let kernel_log = kernel_log.into_inner();

        // Wait for a terminal event, or force shutdown on timeout.  The
        // timeout is scaled to the acceleration mode: TCG (cross-arch
        // emulation) is much slower than KVM.
        let timeout = vm_test_timeout(accel);
        let (hypervisor_events, hypervisor_verdict) = tokio::select! {
            biased;
            result = event_watcher => {
                match result {
                    Ok(r) => r,
                    Err(err) => {
                        error!("hypervisor event watcher task failed: {err}");
                        (B::EventLog::default(), HypervisorVerdict::Failure)
                    }
                }
            }
            _ = tokio::time::sleep(timeout) => {
                warn!(
                    "VM test did not complete within {timeout:?} ({accel:?}); \
                     forcing hypervisor shutdown to collect diagnostics"
                );
                (B::EventLog::default(), HypervisorVerdict::Failure)
            }
        };

        B::shutdown(&controller).await;

        const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

        let init_trace = drain_or_fallback(init_trace, "init system trace", DRAIN_TIMEOUT).await;
        let test_stdout = drain_or_fallback(test_stdout, "test stdout", DRAIN_TIMEOUT).await;
        let test_stderr = drain_or_fallback(test_stderr, "test stderr", DRAIN_TIMEOUT).await;
        let test_result = drain_or_fallback(test_result, "test result", DRAIN_TIMEOUT).await;

        let hypervisor_output = ProcessOutput::from_child(hypervisor, B::NAME).await;

        let kernel_log = drain_or_fallback(kernel_log, "kernel log", DRAIN_TIMEOUT).await;

        let virtiofsd_output = ProcessOutput::from_child(virtiofsd, "virtiofsd").await;

        // The guest init system reports the verdict explicitly over the
        // result channel.  An absent or unparseable verdict is a FAILURE:
        // the guest never confirmed success, so we must not pass.
        let test_passed = match TestResult::parse(&test_result) {
            Some(result) => {
                if !result.passed {
                    warn!("guest reported test failure: {}", result.detail);
                }
                result.passed
            }
            None => {
                error!(
                    "no parseable test verdict from guest (channel contents: {test_result:?}); \
                     treating as failure"
                );
                false
            }
        };

        let test_output = ProcessOutput {
            success: test_passed,
            stdout: test_stdout,
            stderr: test_stderr,
        };

        VmTestOutput {
            success: test_output.success
                && virtiofsd_output.success
                && hypervisor_verdict.is_success()
                && hypervisor_output.success,
            test: test_output,
            console: kernel_log,
            init_trace,
            hypervisor: hypervisor_output,
            hypervisor_events,
            virtiofsd: virtiofsd_output,
        }
    }
}

/// Awaits a string-producing task with a timeout and fallback message.
async fn drain_or_fallback(handle: JoinHandle<String>, label: &str, timeout: Duration) -> String {
    match tokio::time::timeout(timeout, ProcessOutput::join_task_or_fallback(handle, label)).await {
        Ok(output) => output,
        Err(_) => {
            warn!("{label} did not complete within {timeout:?} after shutdown");
            format!(
                "!!!{} UNAVAILABLE: timed out after shutdown!!!",
                label.to_uppercase()
            )
        }
    }
}

/// Allocates a random CID and four consecutive vsock ports.
fn allocate_vsock_resources() -> VsockAllocation {
    let mut rng = rand::rng();

    let cid = rng.random_range(VsockCid::GUEST_MIN.as_raw()..=VsockCid::GUEST_MAX.as_raw());

    // Reserve trace, stdout, stderr, and result.
    let port_max = VsockPort::DYNAMIC_MAX.as_raw() - 3;
    let port_base = rng.random_range(VsockPort::DYNAMIC_MIN.as_raw()..=port_max);

    VsockAllocation {
        cid: VsockCid::new(cid),
        init_trace: VsockChannel {
            port: VsockPort::new(port_base),
            label: "init-trace",
        },
        test_stdout: VsockChannel {
            port: VsockPort::new(port_base + 1),
            label: "test-stdout",
        },
        test_stderr: VsockChannel {
            port: VsockPort::new(port_base + 2),
            label: "test-stderr",
        },
        result: VsockChannel {
            port: VsockPort::new(port_base + 3),
            label: "test-result",
        },
    }
}

/// Launches a VM, runs the test, and collects output.
///
/// # Errors
///
/// Returns [`VmError`] if any part of the VM launch sequence fails.
/// Output collection is best-effort and never fails -- see
/// [`TestVm::collect`].
pub async fn run_in_vm<B: HypervisorBackend, F: FnOnce()>(
    _: F,
    vm_config: config::VmConfig,
    accel: config::Accel,
) -> Result<VmTestOutput<B>, VmError> {
    let identity = crate::test_identity::TestIdentity::resolve::<F>();
    let test_name = identity.test_name;

    let full_bin_path = std::env::args().next().ok_or(VmError::MissingArgv)?;
    let (_, bin_name) =
        full_bin_path
            .rsplit_once("/")
            .ok_or_else(|| VmError::InvalidBinaryPath {
                path: PathBuf::from(&full_bin_path),
            })?;

    let vm_bin_path = format!("/{}/{bin_name}", n_vm_protocol::VM_TEST_BIN_DIR);

    let vsock = allocate_vsock_resources();
    info!("allocated vsock resources: {vsock}");

    let params = TestVmParams {
        full_bin_path: Path::new(&full_bin_path),
        vm_bin_path,
        bin_name,
        test_name,
        vm_config,
        accel,
        vsock,
    };

    let vm = TestVm::<B>::launch(&params).await?;
    Ok(vm.collect().await)
}
