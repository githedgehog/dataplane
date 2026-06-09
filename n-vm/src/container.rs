//! Docker container management for the host tier of `#[in_vm]` tests.

use std::path::PathBuf;

use bollard::models::{
    ContainerCreateBody, DeviceMapping, HostConfig, MountBindOptions, RestartPolicy,
    RestartPolicyNameEnum,
};
use bollard::query_parameters::{
    CreateContainerOptions, InspectContainerOptions, RemoveContainerOptionsBuilder,
    StartContainerOptions,
};
use n_vm_protocol::{
    CONTAINER_PLATFORM, ENV_ACCEL, ENV_BACKEND, ENV_IN_TEST_CONTAINER, ENV_MARKER_VALUE,
    ScratchRoots, VM_ROOT_SHARE_PATH, VM_RUN_DIR, VM_TEST_BIN_DIR,
};
use tokio::sync::oneshot;
use tokio_stream::StreamExt;
use tracing::warn;

use crate::backend::{BackendResolution, EffectiveBackend, RequestedBackend, is_cross_arch};
use crate::config::Accel;
use crate::error::ContainerError;

/// Docker image tag for the locally-created empty container image.
///
/// Created on-demand by [`ensure_scratch_image`] if it does not already
/// exist.  Not pulled from a registry.
const SCRATCH_IMAGE_TAG: &str = "dataplane-test-scratch:local";

/// Linux capabilities required inside the test container.
const REQUIRED_CAPS: [&str; 16] = [
    "SETPCAP",          // modify own capability bounding set (capset(2))
    "SETUID",           // virtiofsd UID mapping (--translate-uid)
    "SETGID",           // drop supplemental groups (setgroups(2))
    "CHOWN",            // serve chown/fchown FUSE ops
    "DAC_OVERRIDE",     // bypass file read/write/execute permission checks
    "DAC_READ_SEARCH",  // bypass directory read and execute permission checks
    "FOWNER",           // bypass checks requiring file UID == process UID
    "FSETID",           // preserve set-user-ID / set-group-ID bits
    "MKNOD",            // serve mknod FUSE ops (device special files)
    "SETFCAP",          // serve file-capability xattrs
    "SYS_RESOURCE",     // override RLIMIT_NOFILE (--rlimit-nofile=0)
    "SYS_RAWIO",        // raw I/O port access (af-packet, DPDK)
    "IPC_LOCK",         // mlock hugepage-backed guest memory
    "NET_ADMIN",        // tap device creation, interface configuration
    "NET_RAW",          // raw socket access in network tests
    "NET_BIND_SERVICE", // vsock listeners
];

/// Device nodes that must be mapped into the container.
const REQUIRED_DEVICES: [&str; 4] = [
    "/dev/kvm",         // to launch VMs
    "/dev/vhost-vsock", // for vsock communication with the VM
    "/dev/vhost-net",   // for vhost-net backed network interfaces
    "/dev/net/tun",     // for tap device creation
];

/// The result of running a test inside a Docker container.
#[derive(Debug)]
pub struct ContainerTestResult {
    /// The exit code of the container's main process, if available.
    pub exit_code: Option<i64>,
}

/// The outcome of the host tier: the test ran in a container, or it was
/// skipped because the requested backend cannot run on this host.
#[derive(Debug)]
pub enum ContainerOutcome {
    /// The test ran; carries the container's exit status.
    Ran(ContainerTestResult),
    /// The test was skipped (e.g. cloud-hypervisor requested for a
    /// cross-architecture guest).  `reason` is shown to the developer.
    Skipped {
        /// Human-readable explanation for the skip.
        reason: String,
    },
}

/// Parameters that vary per test invocation.
struct ContainerParams {
    /// Full path to the test binary (e.g. `/path/to/deps/my_test-abc123`).
    bin_path: PathBuf,
    /// Canonicalized directory that contains the test binary.
    bin_dir: PathBuf,
    /// Fully-qualified test name (e.g. `module::test_name`).
    test_name: String,
    /// Effective UID of the calling process.
    uid: nix::unistd::Uid,
    /// Effective GID of the calling process.
    gid: nix::unistd::Gid,
    /// Groups owning required device nodes and the Docker socket.
    device_groups: Vec<nix::unistd::Gid>,
    /// Resolved `testroot` and `vmroot` directories.
    scratch_roots: ScratchRoots,
}

impl ContainerParams {
    /// Resolves all parameters needed to configure the test container.
    ///
    /// # Errors
    ///
    /// Returns a [`ContainerError`] if any filesystem lookup or validation
    /// step fails.
    fn resolve<F: FnOnce()>() -> Result<Self, ContainerError> {
        let identity = crate::test_identity::TestIdentity::resolve::<F>();
        let test_name = identity.test_name;

        let bin_path =
            std::fs::read_link("/proc/self/exe").map_err(ContainerError::BinaryPathRead)?;

        let bin_parent = bin_path
            .parent()
            .ok_or_else(|| ContainerError::NoParentDirectory {
                path: bin_path.clone(),
            })?;

        let bin_dir =
            std::fs::canonicalize(bin_parent).map_err(ContainerError::BinaryPathCanonicalize)?;

        // Docker mount sources, targets, and commands require UTF-8 strings.
        if bin_dir.to_str().is_none() {
            return Err(ContainerError::NonUtf8Path { path: bin_dir });
        }
        if bin_path.to_str().is_none() {
            return Err(ContainerError::NonUtf8Path { path: bin_path });
        }

        let device_groups = Self::resolve_device_groups()?;

        let scratch_roots = ScratchRoots::resolve().map_err(ContainerError::ScratchRootResolve)?;

        Ok(Self {
            bin_path,
            bin_dir,
            test_name: test_name.to_owned(),
            uid: nix::unistd::getuid(),
            gid: nix::unistd::getgid(),
            device_groups,
            scratch_roots,
        })
    }

    /// Resolves the groups that own [`REQUIRED_DEVICES`] and the Docker socket.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::DeviceNotAccessible`] if any required
    /// device or the Docker socket cannot be `stat`'d.
    fn resolve_device_groups() -> Result<Vec<nix::unistd::Gid>, ContainerError> {
        use std::os::unix::fs::MetadataExt;

        // Non-Unix Docker endpoints have no local socket group to add.
        let docker_socket_path: Option<String> = match std::env::var("DOCKER_HOST") {
            Ok(host) => match host.strip_prefix("unix://") {
                Some(path) => Some(path.to_string()),
                // Non-Unix schemes (e.g. tcp://) have no local socket.
                None if host.contains("://") => None,
                // Bare path with no scheme -- treat as a Unix socket path.
                None => Some(host),
            },
            Err(_) => Some("/var/run/docker.sock".into()),
        };

        let required_files: Vec<String> = REQUIRED_DEVICES
            .iter()
            .map(|&s| s.to_string())
            .chain(docker_socket_path)
            .collect();

        let mut groups: Vec<nix::unistd::Gid> = required_files
            .iter()
            .map(|path| {
                std::fs::metadata(path)
                    .map(|m| nix::unistd::Gid::from_raw(m.gid()))
                    .map_err(|source| ContainerError::DeviceNotAccessible {
                        path: PathBuf::from(path),
                        source,
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        groups.sort_unstable_by_key(|g| g.as_raw());
        groups.dedup_by_key(|g| g.as_raw());
        Ok(groups)
    }

    /// Returns the test binary path as a UTF-8 string slice.
    fn bin_path_str(&self) -> &str {
        self.bin_path
            .to_str()
            .expect("validated as UTF-8 in resolve()")
    }

    /// Returns the test binary directory as a UTF-8 string slice.
    fn bin_dir_str(&self) -> &str {
        self.bin_dir
            .to_str()
            .expect("validated as UTF-8 in resolve()")
    }

    /// Returns the Docker image tag for the test container.
    fn container_image(&self) -> &'static str {
        SCRATCH_IMAGE_TAG
    }

    /// Builds the [`ContainerCreateBody`] for this test invocation.
    ///
    /// `backend` and `accel` are the host-tier-resolved choices, passed to
    /// the container tier via [`ENV_BACKEND`] / [`ENV_ACCEL`] so it can
    /// dispatch to the right hypervisor without a compile-time pick.
    fn build_config(
        &self,
        backend: EffectiveBackend,
        accel: Accel,
        qemu_user: Option<&str>,
    ) -> ContainerCreateBody {
        ContainerCreateBody {
            entrypoint: None,
            cmd: Some(self.build_test_command(qemu_user)),
            image: Some(self.container_image().to_owned()),
            network_disabled: Some(true),
            env: Some(vec![
                format!("{ENV_IN_TEST_CONTAINER}={ENV_MARKER_VALUE}"),
                format!("{ENV_BACKEND}={}", backend.as_env()),
                format!("{ENV_ACCEL}={}", accel.as_env()),
                "RUST_BACKTRACE=1".into(),
            ]),
            user: Some("0:0".into()),
            host_config: Some(HostConfig {
                devices: Some(Self::build_device_mappings()),
                group_add: Some(
                    self.device_groups
                        .iter()
                        .map(|g| g.as_raw().to_string())
                        .collect(),
                ),
                init: Some(true),
                network_mode: Some("none".into()),
                restart_policy: Some(RestartPolicy {
                    name: Some(RestartPolicyNameEnum::NO),
                    ..Default::default()
                }),
                auto_remove: Some(false),
                readonly_rootfs: Some(true),
                mounts: Some(self.build_mounts()),
                tmpfs: Some(self.build_tmpfs()),
                privileged: Some(false),
                cap_add: Some(REQUIRED_CAPS.iter().map(|&c| c.into()).collect()),
                cap_drop: Some(vec!["ALL".into()]),
                // QEMU needs AF_VSOCK sockets, and virtiofsd needs FUSE
                // operations Docker's default seccomp/AppArmor profiles block.
                security_opt: Some(vec![
                    "seccomp=unconfined".into(),
                    "apparmor=unconfined".into(),
                ]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Builds Docker device mappings from [`REQUIRED_DEVICES`].
    fn build_device_mappings() -> Vec<DeviceMapping> {
        REQUIRED_DEVICES
            .iter()
            .map(|&path| DeviceMapping {
                path_on_host: Some(path.into()),
                path_in_container: Some(path.into()),
                cgroup_permissions: Some("rwm".into()),
            })
            .collect()
    }

    /// Builds the test binary command line for the container entrypoint.
    ///
    /// When `qemu_user` is `Some`, the binary is a foreign architecture
    /// relative to the container, so it is run under that user-mode QEMU
    /// interpreter -- mirroring how `scripts/test-runner.sh` wraps the
    /// host-tier invocation (`qemu-<arch> <bin> ...`).  The interpreter is
    /// an absolute `/nix/store` path, available in the container via the
    /// bind-mounted store, so no host `binfmt_misc` registration is needed.
    fn build_test_command(&self, qemu_user: Option<&str>) -> Vec<String> {
        let mut cmd = Vec::new();
        if let Some(interp) = qemu_user {
            cmd.push(interp.to_owned());
        }
        cmd.extend([
            self.bin_path_str().to_owned(),
            self.test_name.clone(),
            "--exact".into(),
            "--no-capture".into(),
            "--format=terse".into(),
        ]);
        cmd
    }

    /// Builds the bind mounts for the test binary directory.
    fn build_mounts(&self) -> Vec<bollard::models::Mount> {
        let bin_dir = self.bin_dir_str();
        let mut mounts = vec![
            Self::read_only_bind_mount(bin_dir, bin_dir.to_owned()),
            Self::read_only_bind_mount(bin_dir, format!("{VM_ROOT_SHARE_PATH}/{VM_TEST_BIN_DIR}")),
        ];

        mounts.extend(Self::build_scratch_mounts(&self.scratch_roots));

        mounts
    }

    /// Builds the additional bind mounts required in scratch mode.
    fn build_scratch_mounts(roots: &ScratchRoots) -> Vec<bollard::models::Mount> {
        let test_root = roots
            .test_root
            .to_str()
            .expect("test_root validated as canonicalized path");
        let vm_root = roots
            .vm_root
            .to_str()
            .expect("vm_root validated as canonicalized path");

        let mut mounts = Vec::new();

        mounts.push(Self::read_only_bind_mount(
            "/nix/store",
            "/nix/store".to_owned(),
        ));

        // Mount each first-level testroot entry at the container root.
        if let Ok(entries) = std::fs::read_dir(&roots.test_root) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                let path = entry.path();
                if path.is_dir() || path.is_file() {
                    mounts.push(Self::read_only_bind_mount(
                        &format!("{test_root}/{name}"),
                        format!("/{name}"),
                    ));
                }
            }
        }

        mounts.push(Self::read_only_bind_mount(
            vm_root,
            VM_ROOT_SHARE_PATH.to_owned(),
        ));

        // Guest binaries keep /nix/store rpaths; expose the real store via virtiofs.
        mounts.push(Self::read_only_bind_mount(
            "/nix/store",
            format!("{VM_ROOT_SHARE_PATH}/nix/store"),
        ));

        // QEMU and cloud-hypervisor allocate hugepage-backed memory here.
        mounts.push(Self::rw_bind_mount(
            "/dev/hugepages",
            "/dev/hugepages".to_owned(),
        ));

        mounts
    }

    /// Builds the tmpfs mounts for the container.
    fn build_tmpfs(&self) -> std::collections::HashMap<String, String> {
        let mut map = std::collections::HashMap::new();
        map.insert(
            VM_RUN_DIR.into(),
            format!(
                "nodev,noexec,nosuid,uid={uid},gid={gid}",
                uid = self.uid.as_raw(),
                gid = self.gid.as_raw(),
            ),
        );
        map
    }

    /// Creates a read-only private bind mount from `source` to `target`.
    fn read_only_bind_mount(source: &str, target: String) -> bollard::models::Mount {
        bollard::models::Mount {
            source: Some(source.into()),
            target: Some(target),
            typ: Some(bollard::models::MountTypeEnum::BIND),
            read_only: Some(true),
            bind_options: Some(MountBindOptions {
                propagation: Some(bollard::models::MountBindOptionsPropagationEnum::PRIVATE),
                non_recursive: Some(true),
                create_mountpoint: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Creates a read-write private bind mount from `source` to `target`.
    fn rw_bind_mount(source: &str, target: String) -> bollard::models::Mount {
        bollard::models::Mount {
            source: Some(source.into()),
            target: Some(target),
            typ: Some(bollard::models::MountTypeEnum::BIND),
            read_only: Some(false),
            bind_options: Some(MountBindOptions {
                propagation: Some(bollard::models::MountBindOptionsPropagationEnum::PRIVATE),
                non_recursive: Some(true),
                create_mountpoint: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        }
    }
}

/// Ensures the scratch Docker image exists locally.
///
/// # Errors
///
/// Returns [`ContainerError::ScratchImageCreate`] if the image does not
/// exist and cannot be created.
async fn ensure_scratch_image(client: &bollard::Docker) -> Result<(), ContainerError> {
    if client.inspect_image(SCRATCH_IMAGE_TAG).await.is_ok() {
        return Ok(());
    }

    tracing::info!(
        image = SCRATCH_IMAGE_TAG,
        "creating scratch Docker image for test infrastructure",
    );

    // A valid empty tar archive is two 512-byte end-of-archive records
    // (1024 zero bytes total).  Importing this produces a Docker image
    // with a single empty layer.
    let mut child = tokio::process::Command::new("docker")
        .args(["import", "-", SCRATCH_IMAGE_TAG])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            ContainerError::ScratchImageCreate(format!("failed to spawn `docker import`: {e}"))
        })?;

    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        if let Err(e) = stdin.write_all(&[0u8; 1024]).await {
            // Keep going: the exit-status check below still catches the
            // failure; this just preserves the underlying I/O cause.
            tracing::warn!("failed to write empty tar to `docker import` stdin: {e}");
        }
        // Dropping stdin closes the pipe, signaling EOF to `docker import`.
    }

    let output = child.wait_with_output().await.map_err(|e| {
        ContainerError::ScratchImageCreate(format!("failed to wait for `docker import`: {e}"))
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ContainerError::ScratchImageCreate(format!(
            "`docker import` exited with {}: {stderr}",
            output.status,
        )));
    }

    Ok(())
}

/// A dedicated thread that stands ready to perform emergency container
/// cleanup when the [`ContainerGuard`] is dropped without explicit cleanup.
///
/// The thread blocks on a [`oneshot::Receiver`].  There are two outcomes:
///
/// - **Normal path**: The sender is dropped without sending (via
///   [`defuse`](Self::defuse)).  The receiver returns `Err`, the thread
///   exits immediately, and no cleanup is performed.
/// - **Emergency path**: The [`ContainerGuard::drop`] impl sends the
///   container ID through the channel.  The thread receives it, builds a
///   minimal tokio runtime, and force-removes the container via the Docker
///   API.
///
/// # Why `std::thread` instead of `tokio::task`?
///
/// [`run_test_in_vm`] uses a single-threaded tokio runtime.  During panic
/// unwinding, the runtime may be shutting down, so a `tokio::task::spawn`
/// from [`Drop`] is unreliable.  A dedicated OS thread with its own
/// runtime is fully decoupled from the caller's async context.
struct CleanupThread {
    /// Send the container ID to request emergency cleanup.
    /// Drop without sending to signal "all clear."
    tx: Option<oneshot::Sender<String>>,
    /// Handle to the cleanup thread.  Joined on defuse; detached on
    /// emergency trigger (so that [`Drop`] does not block).
    thread: Option<std::thread::JoinHandle<()>>,
}

impl CleanupThread {
    /// Spawns the cleanup thread with its own clone of the Docker client.
    ///
    /// The thread blocks immediately on the [`oneshot::Receiver`] and does
    /// no work until either [`trigger`](Self::trigger) or
    /// [`defuse`](Self::defuse) is called (or the sender is dropped).
    fn spawn(client: bollard::Docker) -> Self {
        let (tx, rx) = oneshot::channel::<String>();

        let thread = std::thread::Builder::new()
            .name("container-cleanup".into())
            .spawn(move || {
                // Block until we know whether cleanup is needed.
                let container_id = match rx.blocking_recv() {
                    Ok(id) => id,
                    // Sender dropped without sending -- explicit cleanup
                    // already happened, nothing to do.
                    Err(_) => return,
                };

                tracing::warn!(
                    %container_id,
                    "performing emergency container cleanup",
                );

                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        tracing::error!(
                            %container_id,
                            error = %e,
                            "failed to build emergency cleanup runtime; \
                             manual removal needed (e.g. `docker rm -f {container_id}`)",
                        );
                        return;
                    }
                };

                rt.block_on(async {
                    let opts = RemoveContainerOptionsBuilder::default().force(true).build();
                    match client.remove_container(&container_id, Some(opts)).await {
                        Ok(()) => tracing::warn!(
                            %container_id,
                            "emergency container cleanup succeeded",
                        ),
                        Err(e) => tracing::error!(
                            %container_id,
                            error = %e,
                            "emergency container cleanup failed; \
                             manual removal may be needed \
                             (e.g. `docker rm -f {container_id}`)",
                        ),
                    }
                });
            })
            .expect("failed to spawn container cleanup thread");

        Self {
            tx: Some(tx),
            thread: Some(thread),
        }
    }

    /// Signal that explicit cleanup was performed; the thread will exit
    /// without doing anything.
    ///
    /// Drops the sender (so the receiver sees `RecvError`) and joins the
    /// thread, which should return almost immediately.
    fn defuse(&mut self) {
        // Drop the sender without sending -- the receiver unblocks with
        // Err(RecvError) and the thread exits.
        self.tx.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }

    /// Send the container ID to trigger emergency cleanup.
    ///
    /// The thread is *detached* (not joined) so that [`Drop`] does not
    /// block waiting for the Docker API call.  The cleanup proceeds in the
    /// background.
    fn trigger(&mut self, container_id: String) {
        if let Some(tx) = self.tx.take() {
            // The only way send() fails is if the receiver was already
            // dropped (thread exited), in which case there is nothing to
            // do.
            let _ = tx.send(container_id);
        }
        // Detach the thread -- don't block Drop on the Docker API call.
        self.thread.take();
    }
}

/// RAII guard that owns a running Docker container and provides lifecycle
/// methods.
///
/// The expected usage is:
///
/// 1. [`create_and_start`](Self::create_and_start) -- create the container
///    and return an armed guard.
/// 2. [`stream_logs`](Self::stream_logs) -- forward container
///    stdout/stderr to the host.
/// 3. [`into_result`](Self::into_result) -- inspect the exit status,
///    remove the container, and defuse the guard.
///
/// If the guard is dropped *without* calling `into_result` (e.g. due to a
/// panic or an early return inserted by a future refactor), the [`Drop`]
/// impl sends the container ID to a [`CleanupThread`] which force-removes
/// the container via the Docker API.
///
/// # Async cleanup via sync Drop
///
/// Rust does not support async `Drop`.  This guard bridges the gap by
/// using a [`tokio::sync::oneshot`] channel whose
/// [`Sender::send`](oneshot::Sender::send) is synchronous (not async),
/// making it safe to call from [`Drop`].  A dedicated [`std::thread`]
/// receives the message and performs the async Docker API call in its own
/// minimal tokio runtime -- fully decoupled from whatever runtime (if any)
/// the caller is using.
struct ContainerGuard<'a> {
    client: &'a bollard::Docker,
    container_id: String,
    /// Background thread that will force-remove the container if we send
    /// it the container ID.  Defused on the normal path.
    cleanup: CleanupThread,
    /// Set to `true` once explicit cleanup has been performed via
    /// [`into_result`](Self::into_result).
    defused: bool,
}

impl<'a> ContainerGuard<'a> {
    /// Creates a Docker container from the given configuration, starts it,
    /// and returns an armed guard.
    ///
    /// This combines container creation, guard construction, and starting
    /// into a single step so that the container _never_ exists without a
    /// guard to clean it up -- even if the start request fails after the
    /// container was created.
    ///
    /// A [`CleanupThread`] is spawned that will stand by to force-remove
    /// the container if this guard is dropped without calling
    /// [`into_result`](Self::into_result).
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::ContainerCreate`] or
    /// [`ContainerError::ContainerStart`] if the Docker daemon rejects the
    /// request.
    async fn create_and_start(
        client: &'a bollard::Docker,
        config: ContainerCreateBody,
    ) -> Result<ContainerGuard<'a>, ContainerError> {
        let container = client
            .create_container(
                Some(CreateContainerOptions {
                    name: None,
                    platform: CONTAINER_PLATFORM.into(),
                }),
                config,
            )
            .await
            .map_err(ContainerError::ContainerCreate)?;

        // Arm the guard as soon as the container exists.  If the start
        // below fails, the guard drops with `defused == false` and the
        // cleanup thread force-removes the created-but-never-started
        // container instead of leaking it.
        let cleanup = CleanupThread::spawn(client.clone());
        let guard = Self {
            client,
            container_id: container.id,
            cleanup,
            defused: false,
        };

        guard
            .client
            .start_container(&guard.container_id, None::<StartContainerOptions>)
            .await
            .map_err(ContainerError::ContainerStart)?;

        Ok(guard)
    }

    /// Streams container stdout/stderr to the host's stdout/stderr until
    /// the container exits.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::LogStream`] if the log stream encounters
    /// an error from the Docker daemon.
    async fn stream_logs(&self) -> Result<(), ContainerError> {
        let mut logs = self.client.logs(
            &self.container_id,
            Some(bollard::query_parameters::LogsOptions {
                follow: true,
                stdout: true,
                stderr: true,
                tail: "all".into(),
                ..Default::default()
            }),
        );

        while let Some(log) = logs.next().await {
            match log {
                Ok(msg) => match msg {
                    bollard::container::LogOutput::StdErr { message } => {
                        eprint!("{}", String::from_utf8_lossy(&message));
                    }
                    bollard::container::LogOutput::StdOut { message }
                    | bollard::container::LogOutput::Console { message } => {
                        print!("{}", String::from_utf8_lossy(&message));
                    }
                    bollard::container::LogOutput::StdIn { .. } => {
                        warn!("unexpected StdIn log entry from Docker");
                    }
                },
                Err(e) => {
                    return Err(ContainerError::LogStream(e));
                }
            }
        }

        Ok(())
    }

    /// Performs the explicit inspect + remove lifecycle.
    ///
    /// This defuses the [`CleanupThread`] (so its background thread exits
    /// without doing anything) and marks the guard so that its [`Drop`]
    /// impl is a no-op.  Returns the container's exit status on success.
    async fn into_result(mut self) -> Result<ContainerTestResult, ContainerError> {
        let result = self.collect_and_cleanup().await?;
        // Disarm the safety nets only after the container is actually
        // removed.  If `collect_and_cleanup` returned early (inspect
        // failure or missing state) the `?` above propagates while
        // `defused` is still false, so `Drop` triggers emergency removal
        // rather than leaking the container.
        self.defused = true;
        self.cleanup.defuse();
        Ok(result)
    }

    /// Inspects the container's exit status and removes it.
    ///
    /// # Errors
    ///
    /// Returns a [`ContainerError`] if the container cannot be inspected
    /// or removed, or if the inspection response is missing the container
    /// state.
    async fn collect_and_cleanup(&self) -> Result<ContainerTestResult, ContainerError> {
        let state = self
            .client
            .inspect_container(&self.container_id, None::<InspectContainerOptions>)
            .await
            .map_err(ContainerError::ContainerInspect)?
            .state
            .ok_or(ContainerError::MissingState)?;

        // Force removal: if we got here with the container still running
        // (e.g. the log stream died before the container exited), a plain
        // remove would fail with HTTP 409 and obscure the real error.
        self.client
            .remove_container(
                &self.container_id,
                Some(RemoveContainerOptionsBuilder::default().force(true).build()),
            )
            .await
            .map_err(ContainerError::ContainerRemove)?;

        Ok(ContainerTestResult {
            exit_code: state.exit_code,
        })
    }
}

impl Drop for ContainerGuard<'_> {
    fn drop(&mut self) {
        if !self.defused {
            tracing::error!(
                container_id = %self.container_id,
                "ContainerGuard dropped without explicit cleanup; \
                 dispatching emergency container removal",
            );
            self.cleanup.trigger(self.container_id.clone());
        }
    }
}

/// Launches a Docker container and re-runs the current test binary inside it.
///
/// This is the **host-tier** entry point, called from the code generated by
/// `#[in_vm]` when neither `IN_VM` nor `IN_TEST_CONTAINER` is set (i.e. a
/// normal `cargo test` invocation).  It:
///
/// 1. Resolves the test identity, binary paths, and device group ownership
///    via [`ContainerParams::resolve`].
/// 2. Builds the Docker container configuration via
///    [`ContainerParams::build_config`].
/// 3. Creates and starts the container via
///    [`ContainerGuard::create_and_start`].
/// 4. Streams container stdout/stderr to the host via
///    [`ContainerGuard::stream_logs`].
/// 5. Collects the exit status and removes the container via
///    [`ContainerGuard::into_result`].
///
/// The type parameter `F` is used only to derive the test name via
/// [`std::any::type_name`]; the function itself is never called in this tier.
///
/// # Errors
///
/// Returns [`ContainerError`] if any part of the container lifecycle fails
/// (Docker connection, container creation/start, log streaming, inspection,
/// or cleanup).
pub fn run_test_in_vm<F: FnOnce()>(
    _test_fn: F,
    requested: RequestedBackend,
    vm_config: crate::config::VmConfig,
) -> Result<ContainerOutcome, ContainerError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime for test container");

    runtime.block_on(async {
        let params = ContainerParams::resolve::<F>()?;

        let client =
            bollard::Docker::connect_with_unix_defaults().map_err(ContainerError::DockerConnect)?;

        // Resolve the backend and acceleration mode against the Docker
        // daemon's real architecture.  qemu-user fakes `uname`, so the
        // daemon's self-reported arch -- not the in-process `uname` -- is
        // the reliable host signal.
        let daemon_arch = query_daemon_arch(&client).await?;
        let cross = is_cross_arch(&daemon_arch, std::env::consts::ARCH);
        let (backend, accel) = match requested.resolve(cross) {
            BackendResolution::Run { backend, accel } => (backend, accel),
            BackendResolution::Skip { reason } => {
                return Ok(ContainerOutcome::Skipped { reason });
            }
        };

        // Skip a test that requests a capability the guest ISA can't
        // provide (rather than panicking deep in launch).  The guest ISA is
        // this binary's target arch.  Currently the only such capability is
        // the virtual IOMMU (no aarch64 SMMUv3 lowering yet); as more ISA-
        // divergent capabilities are added, their support checks belong
        // here alongside it.
        let guest_arch = crate::config::Arch::current();
        if vm_config.iommu && !guest_arch.supports_virtual_iommu() {
            return Ok(ContainerOutcome::Skipped {
                reason: format!("virtual IOMMU (iommu = true) is not supported on {guest_arch:?}"),
            });
        }

        // For a cross-arch guest, the container (daemon arch) cannot exec
        // the foreign test binary directly, so run it under user-mode QEMU
        // -- the same `qemu-<arch>` interpreter `scripts/test-runner.sh`
        // uses for the host tier.  Resolved to an absolute /nix/store path
        // (reachable in the container via the bind-mounted store), which
        // avoids any host binfmt_misc dependency.
        let qemu_user = if cross {
            let name = format!("qemu-{}", std::env::consts::ARCH);
            Some(find_on_path(&name).ok_or(ContainerError::QemuUserNotFound { name })?)
        } else {
            None
        };
        tracing::info!(
            daemon_arch = %daemon_arch,
            target_arch = std::env::consts::ARCH,
            ?backend,
            ?accel,
            qemu_user = ?qemu_user,
            "resolved hypervisor backend for this host",
        );

        // Ensure the empty Docker image exists before building the
        // container config (which references it by tag).
        ensure_scratch_image(&client).await?;

        let config = params.build_config(backend, accel, qemu_user.as_deref());

        // The guard is armed at creation -- if anything between here and
        // the explicit cleanup panics or returns early, the CleanupThread
        // will force-remove the container.
        let guard = ContainerGuard::create_and_start(&client, config).await?;

        let log_result = guard.stream_logs().await;

        // Explicit cleanup -- inspects the exit status and removes the
        // container.  This defuses the guard so its Drop is a no-op.
        let cleanup_result = guard.into_result().await;

        // Propagate the log streaming error first if it occurred -- it is
        // the root cause.  But if cleanup also failed, log that error so
        // the container leak is visible even though we cannot return both
        // errors.
        if let (Err(log_err), Err(cleanup_err)) = (&log_result, &cleanup_result) {
            tracing::error!(
                %log_err,
                %cleanup_err,
                "both log streaming and container cleanup failed; \
                 propagating log error, but the container may have leaked",
            );
        }
        log_result?;
        cleanup_result.map(ContainerOutcome::Ran)
    })
}

/// Queries the Docker daemon's architecture (e.g. `"x86_64"`, `"aarch64"`).
///
/// The daemon runs natively on the host, so this is reliable even when the
/// caller is an emulated (qemu-user) foreign-arch binary.
///
/// # Errors
///
/// Returns [`ContainerError::DockerInfo`] if the query fails, or
/// [`ContainerError::DockerArchUnknown`] if the daemon does not report an
/// architecture.
async fn query_daemon_arch(client: &bollard::Docker) -> Result<String, ContainerError> {
    client
        .info()
        .await
        .map_err(ContainerError::DockerInfo)?
        .architecture
        .ok_or(ContainerError::DockerArchUnknown)
}

/// Resolves an executable to its absolute path by searching `$PATH`.
///
/// Used to find the `qemu-<arch>` user-mode interpreter for cross-arch
/// tests; the resolved `/nix/store` path is reachable inside the container
/// via the bind-mounted store.
fn find_on_path(program: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
        .and_then(|p| p.to_str().map(ToOwned::to_owned))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a representative [`ContainerParams`] for use in config
    /// builder tests without hitting the filesystem or process table.
    fn sample_params() -> ContainerParams {
        ContainerParams {
            bin_path: PathBuf::from("/target/debug/deps/my_test-abc123"),
            bin_dir: PathBuf::from("/target/debug/deps"),
            test_name: "tests::my_test".into(),
            uid: nix::unistd::Uid::from_raw(1000),
            gid: nix::unistd::Gid::from_raw(1000),
            device_groups: vec![
                nix::unistd::Gid::from_raw(36),
                nix::unistd::Gid::from_raw(108),
            ],
            scratch_roots: ScratchRoots {
                test_root: PathBuf::from("/nix/store/fake-test-root"),
                vm_root: PathBuf::from("/nix/store/fake-vm-root"),
            },
        }
    }

    #[test]
    fn config_uses_scratch_image() {
        let config =
            sample_params().build_config(EffectiveBackend::CloudHypervisor, Accel::Kvm, None);
        assert_eq!(config.image.as_deref(), Some(SCRATCH_IMAGE_TAG));
    }

    #[test]
    fn test_command_wraps_with_qemu_when_cross() {
        let p = sample_params();
        let native = p.build_test_command(None);
        assert_eq!(
            native[0],
            p.bin_path_str(),
            "native runs the binary directly"
        );

        let interp = "/nix/store/x-qemu-user/bin/qemu-aarch64";
        let cross = p.build_test_command(Some(interp));
        assert_eq!(
            cross[0], interp,
            "cross prepends the user-mode QEMU interpreter"
        );
        assert_eq!(cross[1], p.bin_path_str(), "binary follows the interpreter");
        // The remaining args (test name, --exact, ...) are identical.
        assert_eq!(cross[2..], native[1..]);
    }

    #[test]
    fn config_propagates_backend_and_accel_env() {
        let config = sample_params().build_config(EffectiveBackend::Qemu, Accel::Tcg, None);
        let env = config.env.as_ref().expect("env");
        assert!(
            env.iter().any(|e| e == "N_VM_BACKEND=qemu"),
            "expected N_VM_BACKEND=qemu in {env:?}",
        );
        assert!(
            env.iter().any(|e| e == "N_VM_ACCEL=tcg"),
            "expected N_VM_ACCEL=tcg in {env:?}",
        );
    }

    #[test]
    fn config_disables_networking() {
        let config =
            sample_params().build_config(EffectiveBackend::CloudHypervisor, Accel::Kvm, None);
        assert_eq!(config.network_disabled, Some(true));
        let host = config.host_config.as_ref().expect("host_config");
        assert_eq!(host.network_mode.as_deref(), Some("none"));
    }

    #[test]
    fn config_sets_environment_variables() {
        let config =
            sample_params().build_config(EffectiveBackend::CloudHypervisor, Accel::Kvm, None);
        let env = config.env.as_ref().expect("env should be set");
        let expected = format!("{ENV_IN_TEST_CONTAINER}={ENV_MARKER_VALUE}");
        assert!(
            env.contains(&expected),
            "env should contain {expected}: {env:?}",
        );
        assert!(
            env.iter().any(|e| e == "RUST_BACKTRACE=1"),
            "env should enable RUST_BACKTRACE: {env:?}",
        );
    }

    #[test]
    fn config_runs_as_root() {
        let config =
            sample_params().build_config(EffectiveBackend::CloudHypervisor, Accel::Kvm, None);
        // The container runs as root so that capabilities in the
        // bounding set are effective without ambient-cap gymnastics.
        assert_eq!(config.user.as_deref(), Some("0:0"));
    }

    #[test]
    fn config_passes_device_groups() {
        let params = sample_params();
        let config = params.build_config(EffectiveBackend::CloudHypervisor, Accel::Kvm, None);
        let host = config.host_config.as_ref().expect("host_config");
        let groups = host.group_add.as_ref().expect("group_add");
        // The sample_params use GIDs 36 and 108.
        assert!(groups.contains(&"36".to_string()));
        assert!(groups.contains(&"108".to_string()));
    }

    #[test]
    fn config_is_unprivileged_with_minimal_caps() {
        let config =
            sample_params().build_config(EffectiveBackend::CloudHypervisor, Accel::Kvm, None);
        let host = config.host_config.as_ref().expect("host_config");
        assert_eq!(host.privileged, Some(false));

        // All default caps are dropped; only REQUIRED_CAPS are added back.
        let drop = host.cap_drop.as_ref().expect("cap_drop");
        assert_eq!(drop, &["ALL"], "cap_drop should drop ALL capabilities");

        let caps = host.cap_add.as_ref().expect("cap_add");
        for required in &REQUIRED_CAPS {
            assert!(
                caps.iter().any(|c| c == *required),
                "missing required capability: {required}",
            );
        }

        // Seccomp must be disabled so that AF_VSOCK sockets (family 40)
        // are not blocked by Docker's default seccomp profile.
        let security = host.security_opt.as_ref().expect("security_opt");
        assert!(
            security.iter().any(|s| s == "seccomp=unconfined"),
            "security_opt should contain seccomp=unconfined: {security:?}",
        );

        // AppArmor must be disabled so that virtiofsd can initialise
        // its FUSE filesystem server.  Docker's `docker-default`
        // AppArmor profile restricts operations that virtiofsd needs,
        // causing it to exit before creating its Unix socket.
        assert!(
            security.iter().any(|s| s == "apparmor=unconfined"),
            "security_opt should contain apparmor=unconfined: {security:?}",
        );
    }

    #[test]
    fn config_has_readonly_rootfs() {
        let config =
            sample_params().build_config(EffectiveBackend::CloudHypervisor, Accel::Kvm, None);
        let host = config.host_config.as_ref().expect("host_config");
        assert_eq!(host.readonly_rootfs, Some(true));
    }

    #[test]
    fn config_does_not_auto_remove_and_never_restarts() {
        let config =
            sample_params().build_config(EffectiveBackend::CloudHypervisor, Accel::Kvm, None);
        let host = config.host_config.as_ref().expect("host_config");
        assert_eq!(host.auto_remove, Some(false));
        let restart = host.restart_policy.as_ref().expect("restart_policy");
        assert_eq!(restart.name, Some(RestartPolicyNameEnum::NO));
    }

    #[test]
    fn device_mappings_cover_all_required_devices() {
        let mappings = ContainerParams::build_device_mappings();
        assert_eq!(mappings.len(), REQUIRED_DEVICES.len());
        for device in &REQUIRED_DEVICES {
            let found = mappings.iter().any(|m| {
                m.path_on_host.as_deref() == Some(*device)
                    && m.path_in_container.as_deref() == Some(*device)
            });
            assert!(found, "missing device mapping for {device}");
        }
    }

    #[test]
    fn device_mappings_have_full_permissions() {
        let mappings = ContainerParams::build_device_mappings();
        for mapping in &mappings {
            assert_eq!(
                mapping.cgroup_permissions.as_deref(),
                Some("rwm"),
                "device {:?} should have rwm permissions",
                mapping.path_on_host,
            );
        }
    }

    #[test]
    fn test_command_starts_with_binary_path() {
        let params = sample_params();
        let cmd = params.build_test_command(None);
        assert_eq!(cmd[0], "/target/debug/deps/my_test-abc123");
    }

    #[test]
    fn test_command_passes_test_name_with_exact() {
        let params = sample_params();
        let cmd = params.build_test_command(None);
        assert_eq!(cmd[1], "tests::my_test");
        assert!(cmd.contains(&"--exact".to_string()));
        assert!(cmd.contains(&"--no-capture".to_string()));
        assert!(cmd.contains(&"--format=terse".to_string()));
    }

    #[test]
    fn mounts_include_bin_dir_at_original_path() {
        let params = sample_params();
        let mounts = params.build_mounts();
        let direct = mounts
            .iter()
            .find(|m| m.target.as_deref() == Some("/target/debug/deps"));
        assert!(
            direct.is_some(),
            "should mount bin_dir at its original path"
        );
        let direct = direct.unwrap();
        assert_eq!(direct.source.as_deref(), Some("/target/debug/deps"));
        assert_eq!(direct.read_only, Some(true));
    }

    #[test]
    fn mounts_include_bin_dir_at_vm_test_bin_dir() {
        let params = sample_params();
        let mounts = params.build_mounts();
        let expected_target = format!("{VM_ROOT_SHARE_PATH}/{VM_TEST_BIN_DIR}");
        let mirror = mounts
            .iter()
            .find(|m| m.target.as_deref() == Some(expected_target.as_str()));
        assert!(
            mirror.is_some(),
            "should mount bin_dir at {expected_target}",
        );
        let mirror = mirror.unwrap();
        assert_eq!(mirror.source.as_deref(), Some("/target/debug/deps"));
        assert_eq!(mirror.read_only, Some(true));
    }

    #[test]
    fn scratch_mounts_include_nix_store() {
        let roots = ScratchRoots {
            test_root: PathBuf::from("/nix/store/fake-test-root"),
            vm_root: PathBuf::from("/nix/store/fake-vm-root"),
        };
        let mounts = ContainerParams::build_scratch_mounts(&roots);
        let nix_mount = mounts
            .iter()
            .find(|m| m.target.as_deref() == Some("/nix/store"));
        assert!(
            nix_mount.is_some(),
            "scratch mounts should include /nix/store",
        );
        let nix_mount = nix_mount.unwrap();
        assert_eq!(nix_mount.source.as_deref(), Some("/nix/store"));
        assert_eq!(nix_mount.read_only, Some(true));
    }

    #[test]
    fn scratch_mounts_include_vm_root() {
        let roots = ScratchRoots {
            test_root: PathBuf::from("/nix/store/fake-test-root"),
            vm_root: PathBuf::from("/nix/store/fake-vm-root"),
        };
        let mounts = ContainerParams::build_scratch_mounts(&roots);
        let vm_mount = mounts
            .iter()
            .find(|m| m.target.as_deref() == Some(VM_ROOT_SHARE_PATH));
        assert!(
            vm_mount.is_some(),
            "scratch mounts should include {VM_ROOT_SHARE_PATH}",
        );
        let vm_mount = vm_mount.unwrap();
        assert_eq!(vm_mount.source.as_deref(), Some("/nix/store/fake-vm-root"),);
        assert_eq!(vm_mount.read_only, Some(true));
    }

    #[test]
    fn scratch_mounts_are_bind_mounts_with_expected_permissions() {
        let roots = ScratchRoots {
            test_root: PathBuf::from("/nix/store/fake-test-root"),
            vm_root: PathBuf::from("/nix/store/fake-vm-root"),
        };
        let mounts = ContainerParams::build_scratch_mounts(&roots);
        // At minimum we expect /nix/store, /vm.root, and /dev/hugepages.
        // testroot subdirectory mounts depend on what's on disk, so
        // we can't assert an exact count, but we can verify invariants
        // on whatever mounts are returned.
        assert!(
            mounts.len() >= 3,
            "scratch mounts should have at least /nix/store, /vm.root, and /dev/hugepages, got {}",
            mounts.len(),
        );
        // /dev/hugepages is the only read-write mount; everything else
        // should be read-only.
        for mount in &mounts {
            assert_eq!(
                mount.typ,
                Some(bollard::models::MountTypeEnum::BIND),
                "all scratch mounts should be bind mounts",
            );
            let target = mount.target.as_deref().unwrap_or("");
            if target == "/dev/hugepages" {
                assert_eq!(
                    mount.read_only,
                    Some(false),
                    "/dev/hugepages must be read-write for hugepage allocation",
                );
            } else {
                assert_eq!(
                    mount.read_only,
                    Some(true),
                    "scratch mount {target} should be read-only",
                );
            }
        }
    }

    #[test]
    fn scratch_mounts_include_hugepages() {
        let roots = ScratchRoots {
            test_root: PathBuf::from("/nix/store/fake-test-root"),
            vm_root: PathBuf::from("/nix/store/fake-vm-root"),
        };
        let mounts = ContainerParams::build_scratch_mounts(&roots);
        let hp_mount = mounts
            .iter()
            .find(|m| m.target.as_deref() == Some("/dev/hugepages"));
        assert!(
            hp_mount.is_some(),
            "scratch mounts should include /dev/hugepages",
        );
        let hp_mount = hp_mount.unwrap();
        assert_eq!(hp_mount.source.as_deref(), Some("/dev/hugepages"));
        assert_eq!(
            hp_mount.read_only,
            Some(false),
            "/dev/hugepages must be read-write",
        );
    }

    #[test]
    fn all_mounts_are_private_non_recursive_bind_mounts() {
        let params = sample_params();
        let mounts = params.build_mounts();
        for mount in &mounts {
            assert_eq!(mount.typ, Some(bollard::models::MountTypeEnum::BIND),);
            let opts = mount.bind_options.as_ref().expect("bind_options");
            assert_eq!(
                opts.propagation,
                Some(bollard::models::MountBindOptionsPropagationEnum::PRIVATE),
            );
            assert_eq!(opts.non_recursive, Some(true));
            assert_eq!(opts.create_mountpoint, Some(true));
        }
    }

    #[test]
    fn tmpfs_mounts_vm_run_dir_with_security_flags() {
        let params = sample_params();
        let tmpfs = params.build_tmpfs();
        assert_eq!(tmpfs.len(), 1);
        let opts = tmpfs.get(VM_RUN_DIR).expect("should have VM_RUN_DIR entry");
        assert!(opts.contains("nodev"), "tmpfs should be nodev: {opts}");
        assert!(opts.contains("noexec"), "tmpfs should be noexec: {opts}");
        assert!(opts.contains("nosuid"), "tmpfs should be nosuid: {opts}");
        assert!(opts.contains("uid=1000"), "tmpfs should set uid: {opts}");
        assert!(opts.contains("gid=1000"), "tmpfs should set gid: {opts}");
    }

    #[test]
    fn read_only_bind_mount_sets_expected_fields() {
        let mount = ContainerParams::read_only_bind_mount("/src/dir", "/dst/dir".to_string());
        assert_eq!(mount.source.as_deref(), Some("/src/dir"));
        assert_eq!(mount.target.as_deref(), Some("/dst/dir"));
        assert_eq!(mount.read_only, Some(true));
        assert_eq!(mount.typ, Some(bollard::models::MountTypeEnum::BIND));
    }

    #[test]
    fn required_caps_has_no_duplicates() {
        let mut sorted = REQUIRED_CAPS.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            REQUIRED_CAPS.len(),
            "REQUIRED_CAPS contains duplicates",
        );
    }

    #[test]
    fn required_devices_has_no_duplicates() {
        let mut sorted = REQUIRED_DEVICES.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            REQUIRED_DEVICES.len(),
            "REQUIRED_DEVICES contains duplicates",
        );
    }

    #[test]
    fn required_devices_are_all_absolute_paths() {
        for device in &REQUIRED_DEVICES {
            assert!(
                device.starts_with('/'),
                "device path should be absolute: {device}",
            );
        }
    }
}
