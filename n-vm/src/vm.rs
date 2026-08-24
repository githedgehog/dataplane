// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! VM lifecycle management for the container tier.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use n_vm_protocol::{
    KERNEL_CONSOLE_SOCKET_PATH, TestResult, VIRTIOFS_ROOT_TAG, VIRTIOFSD_BINARY_PATH,
    VIRTIOFSD_SOCKET_PATH, VM_GUEST_CID, VM_ROOT_SHARE_PATH, VsockAllocation, VsockChannel,
    VsockCid, VsockPort,
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

/// What a KVM-accelerated VM gets on top of the work it was asked to do.
///
/// Boot, the guest's own start-up, corpus load, shutdown and drain -- plus an
/// ordinary test body, which declares nothing and is expected to fit here.
const VM_OVERHEAD_ALLOWANCE_KVM: Duration = Duration::from_secs(60);

/// The same for TCG (software-emulated, cross-arch), which is far slower --
/// a guest kernel boot alone can take tens of seconds.
const VM_OVERHEAD_ALLOWANCE_TCG: Duration = Duration::from_secs(300);

/// The VM's overhead allowance for the given acceleration mode.
const fn vm_overhead_allowance(accel: config::Accel) -> Duration {
    match accel {
        config::Accel::Kvm => VM_OVERHEAD_ALLOWANCE_KVM,
        config::Accel::Tcg => VM_OVERHEAD_ALLOWANCE_TCG,
    }
}

/// How long the VM may run before it is shut down by force.
///
/// The container has to be bigger than what it contains.  A budget that
/// merely equalled the work would kill the guest inside its last second,
/// which for a fuzz campaign means losing the crash it was in the middle of
/// writing out -- libfuzzer saves artifacts from `DeathCallback`, after the
/// abort, so a VM killed at the wire reports nothing at all.
///
/// So the allowance is added to the declared work rather than competing with
/// it.  `guest_budget` of zero -- nothing declared, which is nearly every
/// test -- leaves this exactly where it has always been.
fn vm_test_timeout(accel: config::Accel, guest_budget: Duration) -> Duration {
    vm_overhead_allowance(accel).saturating_add(guest_budget)
}

/// The longest the guest's work was declared to take.
///
/// Two sources, and the VM has to outlast both: a test can declare a limit in
/// its `VmConfig`, and a fuzzing engine can declare a campaign length that
/// only exists at run time, arriving via
/// [`ENV_ENGINE_TIME_LIMIT`](n_vm_protocol::ENV_ENGINE_TIME_LIMIT) from the
/// host tier.
///
/// The two are alternatives rather than addends: they describe one stretch of
/// work, so the longer wins.
///
/// `engine_limit` is passed in rather than read here, matching
/// [`Accel::from_env`](config::Accel::from_env) and for the same reason --
/// the environment is the caller's to look at, and a pure function of its
/// value is one a test can exercise without mutating the process.
fn guest_budget(vm_config: &config::VmConfig, engine_limit: Option<&str>) -> Duration {
    let declared = vm_config.guest_time_limit.unwrap_or(Duration::ZERO);
    let from_engine = engine_limit
        .and_then(|secs| secs.parse::<u64>().ok())
        .map_or(Duration::ZERO, Duration::from_secs);
    declared.max(from_engine)
}

/// The complete argument list for a virtiofsd serving one share.
///
/// A pure function of its inputs, matching the QEMU argument builders, so the
/// policy below is asserted by unit tests instead of only being observable by
/// booting a VM and seeing whether the guest survives.
///
/// # Why `--cache=always` on the read-only share
///
/// virtiofsd's default is `auto`, and `auto` corrupts the guest's
/// file-backed pages.  Every binary the guest runs -- `ld.so`, `libc`, the
/// test binary itself -- is mmapped from this share, and there is no DAX
/// window (neither this virtiofsd nor QEMU 11's `vhost-user-fs-pci` supports
/// one), so those mappings are served out of the guest page cache over FUSE.
/// An aarch64 guest then executes and dereferences stale or partially-filled
/// pages: garbage relocations, pointers with their low word zeroed, jumps
/// into `.rodata`.  It reproduced 5/5 and was independent of the guest kernel
/// config.
///
/// `always` is not a preference among several working settings; it is the
/// only one that works.  Swept on aarch64, one test per policy, everything
/// else held fixed:
///
/// | policy     | aarch64            | x86_64 |
/// |------------|--------------------|--------|
/// | `auto`     | guest faults       | passes |
/// | `always`   | passes             | passes |
/// | `never`    | guest faults       | passes |
/// | `metadata` | guest faults       | passes |
///
/// So the trigger is not specifically `auto`'s timeout-driven revalidation:
/// `never` and `metadata` do not cache file contents in the guest at all and
/// fail the same way, and adding `--allow-mmap` does not rescue either.  What
/// the three failing policies share is that a file page can have to be
/// fetched more than once.  `always` tells the guest its page cache is
/// authoritative, so a page is read once and never refilled -- and refilling
/// is what goes wrong.
///
/// Sound here because the share is read-only for the guest *and* immutable on
/// the host: a /nix/store closure plus the workspace, neither of which
/// changes while a VM is up.
///
/// Every policy passes on x86_64, which is why this went unnoticed for so
/// long, and is the trap for anyone tempted to loosen it: the setting reads
/// like a performance tunable and relaxing it looks fine locally while
/// breaking only the emulated guest.  Do not change it without re-running
/// that sweep on aarch64, which
/// [`N_VM_VIRTIOFS_CACHE`](n_vm_protocol::ENV_VIRTIOFS_CACHE) exists to make
/// cheap.
///
/// The writable corpus share keeps virtiofsd's default: it must stay coherent
/// with the host that reads results back afterwards.
///
/// `cache_override` is the caller's
/// [`N_VM_VIRTIOFS_CACHE`](n_vm_protocol::ENV_VIRTIOFS_CACHE), read at the
/// call site rather than here so this stays a pure function: reading the
/// environment inside it would make its own tests depend on whatever the
/// suite happens to run under.
fn virtiofsd_args(
    path: &Path,
    tag: &str,
    socket: &str,
    writable: bool,
    cache_override: Option<&str>,
) -> Vec<String> {
    let uid = nix::unistd::getuid().as_raw();
    let gid = nix::unistd::getgid().as_raw();

    let mut args = vec!["--shared-dir".to_owned(), path.display().to_string()];

    if !writable {
        args.push("--readonly".to_owned());

        let cache = cache_override.unwrap_or("always");
        // `metadata` and `never` refuse to mmap a shared file unless asked,
        // and the guest cannot execute a binary it cannot mmap.  Passed only
        // for those two, so the default path is unchanged and a sweep
        // compares each policy at its best rather than failing one on a flag
        // it needed.
        if cache == "metadata" || cache == "never" {
            args.push("--allow-mmap".to_owned());
        }
        args.push(format!("--cache={cache}"));
    }

    args.extend([
        "--tag".to_owned(),
        tag.to_owned(),
        "--socket-path".to_owned(),
        socket.to_owned(),
        "--announce-submounts".to_owned(),
        "--sandbox=none".to_owned(),
        "--rlimit-nofile=0".to_owned(),
        format!("--translate-uid=squash-host:0:{uid}:{MAX}", MAX = u32::MAX),
        format!("--translate-gid=squash-host:0:{gid}:{MAX}", MAX = u32::MAX),
    ]);

    args
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
    memory_bytes: i64,
) -> Result<(), VmError> {
    let Some(pool) = host_page_size.pool_dir() else {
        return Ok(());
    };

    // The *pool*, not `/dev/hugepages`.
    //
    // Both backends allocate through `memfd` with `MFD_HUGE_*` now, so no
    // hugetlbfs mount is involved at all.  The old check tested whether that
    // mount existed, which passed happily on a host whose pool was empty --
    // precisely the case it was supposed to catch, and one that surfaced
    // instead as `unable to map backing store for guest RAM` from deep
    // inside QEMU.
    let free_path = format!("{pool}/free_hugepages");
    let free = match tokio::fs::read_to_string(&free_path).await {
        Ok(contents) => contents.trim().parse::<u64>().unwrap_or(0),
        Err(err) => {
            return Err(VmError::HugepagesNotAccessible(std::io::Error::new(
                err.kind(),
                format!(
                    "cannot read {free_path}: {err}; this kernel may not support \
                     {size}-byte hugepages",
                    size = host_page_size.bytes(),
                ),
            )));
        }
    };

    let page = host_page_size.bytes();
    let needed = (memory_bytes + page - 1) / page;
    if (free as i64) < needed {
        return Err(VmError::HugepagesNotAccessible(std::io::Error::other(
            format!(
                "the {size}-byte hugepage pool has {free} free page(s); this VM needs \
                 {needed}.  Reserve them on the host, e.g. \
                 `echo {needed} > {pool}/nr_hugepages`",
                size = host_page_size.bytes(),
            ),
        )));
    }
    Ok(())
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
        write_tagged(f, &format!("{label}.out"), &self.stdout)?;
        writeln!(f, "--------------- {label} stderr ---------------")?;
        write_tagged(f, &format!("{label}.err"), &self.stderr)
    }
}

/// Write a captured stream with every line naming where it came from.
///
/// The section headers below are not enough on their own. This whole report is one string,
/// printed after the guest has exited, while the host tier keeps writing to the same file
/// descriptor -- so a line appearing between two headers is not evidence that it came from
/// between them. That is not hypothetical: a libfuzzer banner belonging to a *host-side* target
/// was read as the guest's, and the mistake survived several rounds of looking at it, because
/// position inside the markers was the only evidence available.
///
/// Every channel here already arrives separately -- the guest's stdout, stderr, `n-it` trace and
/// result each have their own vsock port, and the console and hypervisor are separate captures.
/// They were only ever merged at this last step. Tagging costs one prefix per line and makes the
/// merge reversible by anyone reading it, including with `grep`.
fn write_tagged(f: &mut std::fmt::Formatter<'_>, tag: &str, body: &str) -> std::fmt::Result {
    if body.is_empty() {
        return Ok(());
    }
    for line in body.lines() {
        writeln!(f, "[{tag}] {line}")?;
    }
    Ok(())
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
    /// Guest CPU architecture (= the test binary's target arch).  Threaded
    /// explicitly so the arg lowering is a pure function of (config, arch,
    /// accel) and testable for every ISA on any build host.
    pub arch: config::Arch,
    /// Container-absolute path to the initramfs, when the profile's kernel
    /// cannot reach its own root.
    ///
    /// `None` for a direct boot, which is the case whenever the root
    /// filesystem transport is built in.
    pub initramfs: Option<String>,
    /// How this kernel reaches its root filesystem.
    ///
    /// Threaded through because it changes the kernel command line, not
    /// just which files are passed: an initramfs boot skips
    /// `prepare_namespace` entirely, so `root=` and `rootfstype=` are never
    /// read and naming them would be misleading.
    pub boot: crate::kernel_manifest::BootMode,
    /// Container-absolute path to the guest kernel image, resolved from the
    /// kernel manifest before launch.
    ///
    /// Threaded through as a resolved value rather than looked up in the
    /// backends for the same reason `arch` is: it keeps the argument
    /// lowering a pure function of its inputs, so both backends can be
    /// tested for any kernel on any host without a manifest on disk.
    pub kernel_image: String,
    /// Acceleration mode (KVM for same-arch, TCG for a cross-arch guest).
    pub accel: config::Accel,
    /// Dynamically-allocated vsock resources for this VM instance.
    pub vsock: VsockAllocation,
    /// The writable shares this run has, and where the guest mounts them.
    ///
    /// Resolved once before launch rather than probed here, so that the
    /// devices the hypervisor is given and the daemons that back them come
    /// from one answer.  A device without its daemon does not fail: the
    /// hypervisor blocks forever on a vhost-user socket nothing serves.
    pub shares: Vec<config::ActiveShare>,
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
        writeln!(f, "=============== n_vm::test RESULTS ===============")?;
        writeln!(f, "--------------- {} events ---------------", B::NAME)?;
        write!(f, "{}", self.hypervisor_events)?;
        self.hypervisor.fmt_sections(f, B::NAME)?;
        self.virtiofsd.fmt_sections(f, "virtiofsd")?;
        writeln!(f, "--------------- linux console ---------------")?;
        write_tagged(f, "console", &self.console)?;
        writeln!(f, "--------------- init system ---------------")?;
        write_tagged(f, "n-it", &self.init_trace)?;
        self.test.fmt_sections(f, "guest")?;
        Ok(())
    }
}

/// Owns all long-lived resources for a running test VM.
pub struct TestVm<B: HypervisorBackend> {
    /// The hypervisor child process.
    hypervisor: tokio::process::Child,
    /// The virtiofsd child process serving the read-only root share.
    virtiofsd: tokio::process::Child,
    /// One virtiofsd child process per writable share, in
    /// [`n_vm_protocol::WRITABLE_SHARES`] order.
    ///
    /// Empty for an ordinary test.  Held only so that `kill_on_drop` tears
    /// the daemons down with the VM.
    _share_virtiofsd: Vec<tokio::process::Child>,
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
    /// How long the guest's work was declared to take, resolved at launch.
    guest_budget: Duration,
}

impl<B: HypervisorBackend> TestVm<B> {
    /// Spawns a virtiofs daemon for one share.
    ///
    /// `writable` is the security boundary for the corpus share, and it is
    /// deliberately enforced here rather than by the guest's mount flags: a
    /// fuzz target exists to drive code into misbehaving against a real
    /// kernel, so a guest-side `mount -o remount,rw` must not be able to
    /// reach the developer's source tree.  The root daemon keeps
    /// `--readonly` and therefore cannot write anywhere at all; the corpus
    /// daemon can write, but its `--shared-dir` is a single `__fuzz__`
    /// directory, so there is nothing else for it to reach.
    async fn launch_virtiofsd(
        path: impl AsRef<Path>,
        tag: &str,
        socket: &str,
        writable: bool,
    ) -> Result<tokio::process::Child, VmError> {
        let cache_override = std::env::var(n_vm_protocol::ENV_VIRTIOFS_CACHE)
            .ok()
            .filter(|v| !v.is_empty());
        let mut command = tokio::process::Command::new(VIRTIOFSD_BINARY_PATH);
        command
            .args(virtiofsd_args(
                path.as_ref(),
                tag,
                socket,
                writable,
                cache_override.as_deref(),
            ))
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true);
        command.spawn().map_err(VmError::VirtiofsdSpawn)
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
            .map_err(|reason| VmError::InvalidConfig { reason })?;

        // Unsupported capability/ISA combinations (e.g. vIOMMU on aarch64)
        // are resolved to a graceful skip in the host tier before we ever
        // reach launch -- see `run_test_in_vm`.  A debug assert documents
        // the invariant without re-introducing a hard runtime failure.
        debug_assert!(
            !params.vm_config.iommu || params.arch.supports_virtual_iommu(),
            "vIOMMU requested on {:?}, which has no vIOMMU lowering; the host \
             tier should have skipped this test",
            params.arch,
        );

        let mut virtiofsd = Self::launch_virtiofsd(
            VM_ROOT_SHARE_PATH,
            VIRTIOFS_ROOT_TAG,
            VIRTIOFSD_SOCKET_PATH,
            false,
        )
        .await?;

        // virtiofsd creates its socket asynchronously after process start.
        if let Err(err) = wait_for_socket(VIRTIOFSD_SOCKET_PATH).await {
            config::drain_child_stderr(&mut virtiofsd, "virtiofsd").await;
            return Err(err);
        }

        // One writable daemon per share the host tier opened.  Driven by
        // `params.shares` rather than by probing the filesystem again: the
        // hypervisor is about to be given exactly one device per entry, and
        // a device whose daemon is missing hangs the boot on a vhost-user
        // socket that never appears.
        let mut share_virtiofsd = Vec::with_capacity(params.shares.len());
        for active in &params.shares {
            let mut child = Self::launch_virtiofsd(
                active.share.container_path,
                active.share.tag,
                active.share.socket_path,
                true,
            )
            .await?;
            if let Err(err) = wait_for_socket(active.share.socket_path).await {
                let label = format!("virtiofsd-{role}", role = active.share.role);
                config::drain_child_stderr(&mut child, &label).await;
                return Err(err);
            }
            share_virtiofsd.push(child);
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
            _share_virtiofsd: share_virtiofsd,
            controller: launched.controller,
            event_watcher: launched.event_watcher,
            init_trace,
            test_stdout,
            test_stderr,
            test_result,
            kernel_log,
            accel: params.accel,
            guest_budget: guest_budget(
                &params.vm_config,
                std::env::var(n_vm_protocol::ENV_ENGINE_TIME_LIMIT)
                    .ok()
                    .as_deref(),
            ),
        })
    }

    /// Waits for the test to finish and collects output from all subsystems.
    pub async fn collect(self) -> VmTestOutput<B> {
        let Self {
            hypervisor,
            virtiofsd,
            // Dropped here, which kills the writable daemons now that the
            // guest is finished with them.  Their output is not collected:
            // each serves a single directory and has no verdict to report.
            _share_virtiofsd,
            controller,
            event_watcher,
            init_trace,
            test_stdout,
            test_stderr,
            test_result,
            kernel_log,
            accel,
            guest_budget,
        } = self;

        let event_watcher = event_watcher.into_inner();
        let init_trace = init_trace.into_inner();
        let test_stdout = test_stdout.into_inner();
        let test_stderr = test_stderr.into_inner();
        let test_result = test_result.into_inner();
        let kernel_log = kernel_log.into_inner();

        // Wait for a terminal event, or force shutdown on timeout.  The
        // budget is the work the guest was given plus the allowance for the
        // acceleration mode, which also covers boot -- TCG (cross-arch
        // emulation) is much slower than KVM.
        let timeout = vm_test_timeout(accel, guest_budget);
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
                    "VM test did not complete within {timeout:?} ({accel:?} \
                     allowance {allowance:?} + declared work {guest_budget:?}); \
                     forcing hypervisor shutdown to collect diagnostics",
                    allowance = vm_overhead_allowance(accel),
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

    // CIDs are host-global; skip VM_GUEST_CID (== GUEST_MIN) so dynamic
    // allocations never collide with the legacy static CID used by
    // `VsockAllocation::with_defaults()`.
    let cid_min = VM_GUEST_CID.as_raw() + 1;
    let cid = rng.random_range(cid_min..=VsockCid::GUEST_MAX.as_raw());

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

    // The guest arch is this binary's target arch.
    let arch = config::Arch::current();

    // Which kernels exist is a fact about the nix build, so it is read from
    // the manifest nix materialized into `testroot` rather than hardcoded
    // here.  Resolved once, before launch, so a bad manifest fails with a
    // manifest error instead of a VM that boots nothing.
    let manifest = crate::kernel_manifest::KernelManifest::load()?;
    let (profile_name, profile) = manifest.selected(accel == config::Accel::Tcg)?;
    profile.check_arch(profile_name, arch)?;
    info!(
        "using kernel profile `{profile_name}` ({hypervisor}, {kernel})",
        hypervisor = profile.hypervisor,
        kernel = profile.kernel,
    );

    // Check what the test says it needs against what this kernel actually
    // has, before booting.  A missing symbol otherwise surfaces as whatever
    // the feature's absence breaks -- an ioctl returning ENOTTY, a filter
    // that will not attach -- several tiers away from the cause.
    //
    // Skipped when the manifest records no config: that is a gap in the
    // profile, not a licence to ignore what the test asked for, so it is
    // logged rather than passing quietly.
    if !vm_config.kernel_features.is_empty() {
        match &profile.config {
            Some(path) => {
                let kernel_config =
                    crate::kernel_config::KernelConfig::load(std::path::Path::new(path))?;
                let unmet = crate::kernel_feature::unmet_requirements(
                    vm_config.kernel_features,
                    &kernel_config,
                );
                if !unmet.is_empty() {
                    return Err(VmError::KernelFeaturesUnmet {
                        missing: unmet.into_iter().map(|u| u.symbol).collect(),
                    });
                }
            }
            None => warn!(
                "kernel profile `{profile_name}` records no config, so the \
                 {n} feature(s) this test requires cannot be verified",
                n = vm_config.kernel_features.len(),
            ),
        }
    }

    let params = TestVmParams {
        full_bin_path: Path::new(&full_bin_path),
        vm_bin_path,
        bin_name,
        test_name,
        vm_config,
        arch,
        kernel_image: profile.kernel.clone(),
        initramfs: profile.initramfs.clone(),
        boot: profile.boot,
        accel,
        vsock,
        shares: config::ActiveShare::resolve(),
    };

    let vm = TestVm::<B>::launch(&params).await?;
    Ok(vm.collect().await)
}

#[cfg(test)]
mod timeout_tests {
    use super::*;

    /// Nothing declared is the ordinary case, and it must leave the budget
    /// exactly where it was before any of this existed.
    #[test]
    fn an_ordinary_test_gets_what_it_always_got() {
        assert_eq!(
            vm_test_timeout(config::Accel::Kvm, Duration::ZERO),
            VM_OVERHEAD_ALLOWANCE_KVM,
        );
        assert_eq!(
            vm_test_timeout(config::Accel::Tcg, Duration::ZERO),
            VM_OVERHEAD_ALLOWANCE_TCG,
        );
    }

    /// The container has to be bigger than what it contains.  A ten-minute
    /// campaign in a ten-minute VM is the bug this exists to prevent.
    #[test]
    fn the_budget_always_exceeds_the_work() {
        for secs in [1, 60, 600, 36_000] {
            let work = Duration::from_secs(secs);
            for accel in [config::Accel::Kvm, config::Accel::Tcg] {
                assert!(
                    vm_test_timeout(accel, work) > work,
                    "{accel:?}: {secs}s of work must not get a {secs}s VM",
                );
            }
        }
    }

    #[test]
    fn declared_work_is_added_to_the_allowance() {
        assert_eq!(
            vm_test_timeout(config::Accel::Kvm, Duration::from_secs(600)),
            VM_OVERHEAD_ALLOWANCE_KVM + Duration::from_secs(600),
        );
    }

    /// The two sources are alternatives, not addends: a campaign running
    /// inside a test that also declared a limit takes the longer of the two,
    /// because it is one stretch of work described twice.
    #[test]
    fn the_longer_of_the_two_declarations_wins() {
        let declared = config::VmConfig {
            guest_time_limit: Some(Duration::from_secs(600)),
            ..config::VmConfig::DEFAULT
        };
        assert_eq!(
            guest_budget(&declared, Some("60")),
            Duration::from_secs(600),
            "a short campaign must not shrink a longer declared limit",
        );
        assert_eq!(
            guest_budget(&declared, Some("900")),
            Duration::from_secs(900),
            "a long campaign must not be capped by a shorter declared limit",
        );
        assert_eq!(guest_budget(&declared, None), Duration::from_secs(600));
    }

    #[test]
    fn a_test_that_declares_nothing_declares_nothing() {
        let default = config::VmConfig::DEFAULT;
        assert_eq!(guest_budget(&default, None), Duration::ZERO);
        assert_eq!(
            guest_budget(&default, Some("600")),
            Duration::from_secs(600),
            "a campaign alone is enough to extend the budget",
        );
    }

    /// A malformed value must not silently read as "no work declared" for a
    /// campaign that is genuinely running -- but it is the host tier that
    /// writes it, from a parsed `Duration`, so this is only reachable if
    /// something else set it.
    #[test]
    fn a_malformed_engine_limit_falls_back_to_declaring_nothing() {
        assert_eq!(
            guest_budget(&config::VmConfig::DEFAULT, Some("ages")),
            Duration::ZERO,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(writable: bool, cache: Option<&str>) -> Vec<String> {
        virtiofsd_args(
            Path::new("/share"),
            "root",
            "/run/virtiofsd.sock",
            writable,
            cache,
        )
    }

    /// The read-only share must be served with `--cache=always`.
    ///
    /// The one assertion standing between us and a repeat of the bug that
    /// made every aarch64 test fail.  Worth a unit test rather than only the
    /// in-guest coverage, because the in-guest symptom is the guest dying in
    /// `ld.so` before any test body runs -- which reads as "the VM is broken"
    /// and sends the next person looking at kernel configs, as it did.
    #[test]
    fn read_only_share_is_served_with_cache_always() {
        let args = args(false, None);
        assert!(
            args.contains(&"--cache=always".to_owned()),
            "read-only share must be `--cache=always`; see the sweep in \
             `virtiofsd_args`: {args:?}",
        );
        assert!(args.contains(&"--readonly".to_owned()), "{args:?}");
    }

    /// The writable corpus share keeps virtiofsd's default.
    ///
    /// `always` would tell the guest its cache is authoritative for a
    /// directory the host reads back afterwards.  It is also how the corpus
    /// share was first broken: applying the override to both daemons made the
    /// corpus read-only to the guest.
    #[test]
    fn writable_share_gets_no_cache_policy() {
        let args = args(true, None);
        assert!(
            !args.iter().any(|a| a.starts_with("--cache")),
            "writable share must keep virtiofsd's default: {args:?}",
        );
        assert!(
            !args.contains(&"--readonly".to_owned()),
            "the corpus share is writable: {args:?}",
        );
    }

    /// The override reaches virtiofsd, which is what makes a policy sweep a
    /// single build plus an environment variable.
    #[test]
    fn cache_override_is_honoured() {
        assert!(args(false, Some("auto")).contains(&"--cache=auto".to_owned()));
        assert!(args(false, Some("never")).contains(&"--cache=never".to_owned()));
    }

    /// The restrictive policies get `--allow-mmap`, and only they do.
    ///
    /// Without it they refuse to mmap a shared file and the guest cannot
    /// execute anything, so a sweep would fail them on a missing flag rather
    /// than on the property being measured.  (It does not save them: both
    /// still fault on aarch64.)
    #[test]
    fn only_restrictive_policies_allow_mmap() {
        for policy in ["metadata", "never"] {
            assert!(
                args(false, Some(policy)).contains(&"--allow-mmap".to_owned()),
                "{policy} needs --allow-mmap to serve an executable",
            );
        }
        for policy in ["always", "auto"] {
            assert!(
                !args(false, Some(policy)).contains(&"--allow-mmap".to_owned()),
                "{policy} caches contents and does not need --allow-mmap",
            );
        }
    }

    /// The corpus share's isolation is `--shared-dir`, not guest mount flags:
    /// a fuzz target that remounts rw must still reach only `__fuzz__`.
    #[test]
    fn each_share_is_scoped_to_its_own_directory() {
        let args = args(true, None);
        let i = args
            .iter()
            .position(|a| a == "--shared-dir")
            .expect("present");
        assert_eq!(args[i + 1], "/share", "{args:?}");
    }
}
