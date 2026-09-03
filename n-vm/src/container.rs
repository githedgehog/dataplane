// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Docker container management for the host tier of `#[n_vm::test]` tests.

use std::path::{Path, PathBuf};

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
    ENV_WORKSPACE, LABEL_HOST_PID, LABEL_OWNER, LABEL_OWNER_VALUE, LABEL_TEST, ScratchRoots,
    VM_ENV_DIR, VM_ROOT_SHARE_PATH, VM_RUN_DIR, VM_TEST_BIN_DIR, VM_WORKSPACE_DIR,
};
use tokio::sync::oneshot;
use tokio_stream::StreamExt;
use tracing::warn;

use crate::backend::{BackendResolution, EffectiveBackend, is_cross_arch};
use crate::config::Accel;
use crate::error::ContainerError;

/// Resolves the host cargo workspace root to share with the guest.
///
/// Prefers [`ENV_WORKSPACE`]; otherwise walks up from the current directory
/// for a `Cargo.toml` declaring `[workspace]`.  The walk is required because
/// cargo runs a test with the working directory set to the *package* root,
/// while `file!()` is recorded relative to the *workspace* root.
///
/// Returns `None` when no workspace is found, which is not an error: a
/// caller outside a cargo workspace simply gets no `/workspace` in the
/// guest.
/// How long the fuzzing engine says this run's campaign will take, in whole
/// seconds.
///
/// Derived from the forwarded engine arguments rather than declared, because
/// nothing compiled into the test knows it: `cargo bolero test -T 10min`
/// chooses it at the command line, and the test binary learns it from
/// `BOLERO_LIBFUZZER_ARGS`.
///
/// The workspace remap does not apply -- this reads a duration, not a path --
/// so it deliberately looks at the raw value rather than at what
/// `write_forwarded_env` will carry into the guest.
fn engine_time_limit() -> Option<u64> {
    let args = std::env::var(n_vm_protocol::ENV_LIBFUZZER_ARGS).ok()?;
    n_vm_protocol::max_total_time(&args).map(|d| d.as_secs())
}

/// A writable share the host tier has decided to open.
///
/// The host half of [`crate::config::ActiveShare`]: this side knows the host
/// directory to bind-mount, the other side knows only what arrived.
struct ResolvedShare {
    share: n_vm_protocol::WritableShare,
    host_dir: PathBuf,
    guest_path: String,
}

/// Chooses which host directories a fuzz target may write to.
///
/// The engine is asked first, and answers for both windows.  `cargo-bolero`
/// computes them from `--corpus-dir` and from its own `fuzz_dir()`
/// derivation, and puts them on the command line it hands to libfuzzer --
/// so they are already decided by the time this tier runs, and deriving
/// them independently here would mean reimplementing that derivation and
/// drifting from it.  That drift is exactly what broke persistence: `n-vm`
/// made `__fuzz__` writable while `just fuzz` pointed the corpus at
/// `.fuzz-corpus/<target>`, which the read-only share then served, so every
/// campaign started from `0 files found` and saved nothing.
///
/// Without an engine there is no command line to read, and the corpus falls
/// back to `bolero`'s own default beside the test.  There is no crashes
/// window in that case: the fallback directory encloses both.
///
/// `engine` is passed in rather than read here so this stays a pure
/// function of its inputs, matching [`Accel::from_env`]'s convention -- a
/// test of it should not have to mutate the process environment.
///
/// # Errors
///
/// A test that asked for a corpus and cannot be given one is an error, not
/// a warning.  The guest has no way to report "I had no writable corpus" --
/// the write just lands on the read-only root share and surfaces as a bare
/// `ReadOnlyFilesystem` several tiers from the cause, which is how the
/// remapped-`file!()` bug hid.
fn plan_writable_shares(
    vm_config: &crate::config::VmConfig,
    engine: &str,
    workspace: &Path,
) -> Result<Vec<(n_vm_protocol::WritableShare, PathBuf)>, ContainerError> {
    if !vm_config.is_fuzz_target() {
        return Ok(Vec::new());
    }
    let dirs = n_vm_protocol::fuzz_dirs(engine);

    // A relative directory is resolved against the workspace, which is the
    // guest's working directory too -- so the same string names the same
    // place on both sides.
    let absolute = |dir: &str| {
        let path = Path::new(dir);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            workspace.join(path)
        }
    };

    let corpus = match dirs.corpus {
        Some(dir) => absolute(dir),
        None => {
            let (file, crate_dir) = vm_config.source_file.unwrap_or(("<none>", "<none>"));
            let rel = vm_config.corpus_rel_dir().ok_or_else(|| {
                ContainerError::CorpusDirUnresolvable {
                    file: file.to_owned(),
                    crate_dir: crate_dir.to_owned(),
                }
            })?;
            workspace.join(rel)
        }
    };

    // `WRITABLE_SHARES` order, which every tier relies on: the container
    // resolves in it, and the QEMU backend numbers chardevs by it.
    Ok([
        (n_vm_protocol::CORPUS_SHARE, Some(corpus)),
        (n_vm_protocol::CRASHES_SHARE, dirs.crashes.map(absolute)),
    ]
    .into_iter()
    .filter_map(|(share, dir)| dir.map(|dir| (share, dir)))
    .collect())
}

/// Creates the planned directories and works out where the guest sees them.
///
/// # Errors
///
/// Propagates [`plan_writable_shares`], and reports a directory that cannot
/// be created.
fn resolve_writable_shares(
    vm_config: &crate::config::VmConfig,
) -> Result<Vec<ResolvedShare>, ContainerError> {
    if !vm_config.is_fuzz_target() {
        return Ok(Vec::new());
    }
    let workspace = workspace_root().ok_or(ContainerError::CorpusWithoutWorkspace)?;
    let host_root = workspace.to_str().unwrap_or_default();

    // The raw value, before `write_forwarded_env` rewrites it: these are
    // host paths, and this tier is the only one that can act on them.
    let engine = std::env::var(n_vm_protocol::ENV_LIBFUZZER_ARGS).unwrap_or_default();

    plan_writable_shares(vm_config, &engine, &workspace)?
        .into_iter()
        .map(|(share, host_dir)| {
            // Created here, as the invoking user: the guest sees the
            // workspace read-only and so cannot create it, and creating it
            // here keeps ownership right without relying on virtiofsd's uid
            // squashing for the directory itself.
            std::fs::create_dir_all(&host_dir).map_err(|source| {
                ContainerError::CorpusDirCreate {
                    path: host_dir.clone(),
                    source,
                }
            })?;
            let guest_path = n_vm_protocol::remap_workspace_paths(
                host_dir.to_str().unwrap_or_default(),
                host_root,
            );
            Ok(ResolvedShare {
                share,
                host_dir,
                guest_path,
            })
        })
        .collect()
}

fn workspace_root() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var(ENV_WORKSPACE) {
        let path = PathBuf::from(dir);
        return path.canonicalize().ok().or(Some(path));
    }

    let cwd = std::env::current_dir().ok()?;
    cwd.ancestors()
        .find(|dir| {
            let manifest = dir.join("Cargo.toml");
            std::fs::read_to_string(&manifest).is_ok_and(|text| {
                text.lines()
                    .any(|line| line.trim_start().starts_with("[workspace"))
            })
        })
        .map(Path::to_path_buf)
}

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
        shares: &[ResolvedShare],
        env_host_dir: Option<&Path>,
    ) -> ContainerCreateBody {
        ContainerCreateBody {
            entrypoint: None,
            cmd: Some(self.build_test_command(qemu_user)),
            image: Some(self.container_image().to_owned()),
            network_disabled: Some(true),
            // Marks the container as ours so `n-vm-reap` can find it later.
            // A SIGKILL leaves no chance to clean up in-process, so something
            // has to be able to identify the remains after the fact; matching
            // on image or name would not do, since the scratch image is
            // shared and names come from the daemon.
            labels: Some(
                [
                    (LABEL_OWNER.to_owned(), LABEL_OWNER_VALUE.to_owned()),
                    (LABEL_TEST.to_owned(), self.test_name.clone()),
                    (LABEL_HOST_PID.to_owned(), std::process::id().to_string()),
                ]
                .into_iter()
                .collect(),
            ),
            env: Some(
                vec![
                    format!("{ENV_IN_TEST_CONTAINER}={ENV_MARKER_VALUE}"),
                    format!("{ENV_BACKEND}={}", backend.as_env()),
                    format!("{ENV_ACCEL}={}", accel.as_env()),
                    "RUST_BACKTRACE=1".into(),
                ]
                .into_iter()
                // Forwarded only when set: an absent variable must leave the
                // container tier on the manifest's default rather than on an
                // empty string that names no profile.
                .chain(
                    std::env::var(n_vm_protocol::ENV_PROFILE)
                        .ok()
                        .filter(|v| !v.is_empty())
                        .map(|v| format!("{}={v}", n_vm_protocol::ENV_PROFILE)),
                )
                // How long the engine says the guest's work will take.  Read
                // from *this* tier's environment because that is where the
                // fuzz supervisor set it; the container tier never sees the
                // invocation that chose it.  Absent when nothing declared
                // one, which leaves the VM budget exactly where it was.
                .chain(
                    engine_time_limit()
                        .map(|secs| format!("{}={secs}", n_vm_protocol::ENV_ENGINE_TIME_LIMIT)),
                )
                // Where each writable window lands in the guest.  Only the
                // host tier can know this: the guest path is a host path put
                // through the workspace remap, and the container has never
                // seen the host's workspace.
                .chain(
                    shares
                        .iter()
                        .map(|active| format!("{}={}", active.share.env_key, active.guest_path)),
                )
                // Same "only when set" discipline: virtiofsd runs in this
                // tier, so the override has to reach it here.
                .chain(
                    std::env::var(n_vm_protocol::ENV_VIRTIOFS_CACHE)
                        .ok()
                        .filter(|v| !v.is_empty())
                        .map(|v| format!("{}={v}", n_vm_protocol::ENV_VIRTIOFS_CACHE)),
                )
                .collect(),
            ),
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
                mounts: Some(self.build_mounts(shares, env_host_dir)),
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
    fn build_mounts(
        &self,
        shares: &[ResolvedShare],
        env_host_dir: Option<&Path>,
    ) -> Vec<bollard::models::Mount> {
        let bin_dir = self.bin_dir_str();
        let mut mounts = vec![
            Self::read_only_bind_mount(bin_dir, bin_dir.to_owned()),
            Self::read_only_bind_mount(bin_dir, format!("{VM_ROOT_SHARE_PATH}/{VM_TEST_BIN_DIR}")),
        ];

        // The forwarded environment, read-only: the guest only reads it, and
        // the root share is served `--readonly` regardless.  A directory
        // rather than the file itself, because the `vmroot` derivation can
        // only pre-create a directory as a mount point.
        if let Some(env_dir) = env_host_dir
            && let Some(env_dir) = env_dir.to_str()
        {
            mounts.push(Self::read_only_bind_mount(
                env_dir,
                format!("{VM_ROOT_SHARE_PATH}/{VM_ENV_DIR}"),
            ));
        }

        mounts.extend(Self::build_scratch_mounts(&self.scratch_roots, shares));

        mounts
    }

    /// Writes the variables this tier should carry into the guest, returning
    /// the host directory to bind-mount at [`VM_ENV_DIR`].
    ///
    /// `Ok(None)` when there is nothing to forward, so the ordinary case
    /// adds no file and no mount.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::EnvFileWrite`] if the file cannot be
    /// written.  Deliberately an error rather than a warning that carries
    /// on, per `development/code/error-handling.md`: the guest cannot report
    /// "I was given no environment", and a bolero test that loses
    /// `BOLERO_LIBFUZZER_ARGS` does not fail -- it quietly stops fuzzing and
    /// still passes.  This is the only place the loss is visible.
    /// The directory to write a forwarded-environment directory into.
    ///
    /// `<share>/tmp` when a host share is configured, else the ordinary
    /// temporary directory.
    fn env_parent_dir() -> PathBuf {
        match n_vm_protocol::host_share_dir() {
            Some(share) => PathBuf::from(share).join(n_vm_protocol::HOST_SHARE_TMP_SUBDIR),
            None => std::env::temp_dir(),
        }
    }

    fn write_forwarded_env(
        &self,
        rss_limit_mib: Option<u32>,
    ) -> Result<Option<PathBuf>, ContainerError> {
        let extra = std::env::var(n_vm_protocol::ENV_FORWARD).ok();
        // Values are rewritten, not just carried. A forwarded variable that names a host path
        // points nowhere in the guest, where the workspace lives at `/workspace` rather than at
        // whatever it is called here -- see `remap_workspace_paths`, and `BOLERO_LIBFUZZER_ARGS`
        // for why it matters.
        let host_root = workspace_root()
            .and_then(|root| root.to_str().map(str::to_owned))
            .unwrap_or_default();
        let mut vars: Vec<(String, String)> = std::env::vars()
            .filter(|(name, _)| n_vm_protocol::is_forwarded(name, extra.as_deref()))
            .map(|(name, value)| {
                let value = n_vm_protocol::remap_workspace_paths(&value, &host_root);
                // The one forwarded value this tier reads rather than carries. A libfuzzer
                // command line can ask the fuzzer to supervise copies of itself, which in the
                // guest means `system(3)` against a root that has no shell -- see
                // `strip_multiprocess_flags`.
                let value = if name == n_vm_protocol::ENV_LIBFUZZER_ARGS {
                    let value = n_vm_protocol::strip_multiprocess_flags(&value);
                    // The other thing this tier decides rather than carries.
                    // libfuzzer's default `-rss_limit_mb` is twice the
                    // default guest, so it is the guest kernel that notices
                    // the growth first -- and it kills the engine, which
                    // loses the input that caused it.
                    match rss_limit_mib {
                        Some(limit) => n_vm_protocol::with_rss_limit(&value, limit),
                        None => value,
                    }
                } else {
                    value
                };
                (name, value)
            })
            .collect();
        if vars.is_empty() {
            return Ok(None);
        }
        // Stable order, so the same environment produces the same bytes and
        // this stays out of the way when diffing a failing run against a
        // passing one.
        vars.sort();

        // Keyed by pid and test name: nextest runs each test in its own
        // process and several containers are created in parallel, so a
        // shared path would race.
        // Under the share directory when there is one: this path is a bind
        // mount source, so the daemon has to be able to resolve it, and a
        // container-local /tmp is exactly what it cannot. Getting this wrong
        // is silent in the worst way -- the daemon would create an empty
        // directory and the guest would come up with no environment at all,
        // which is the loss the doc comment above says nothing else can
        // report.
        let dir = Self::env_parent_dir().join(format!(
            "n-vm-env-{}-{}",
            std::process::id(),
            self.test_name.replace("::", "_"),
        ));
        let path = dir.join(n_vm_protocol::ENV_FILE_NAME);

        let encoded =
            n_vm_protocol::encode_environ(vars.iter().map(|(k, v)| (k.as_str(), v.as_str())));

        std::fs::create_dir_all(&dir)
            .and_then(|()| std::fs::write(&path, &encoded))
            .map_err(|source| ContainerError::EnvFileWrite {
                path: path.clone(),
                source,
            })?;

        tracing::debug!(
            "forwarding {} variable(s) to the guest via {}: {}",
            vars.len(),
            path.display(),
            vars.iter()
                .map(|(k, _)| k.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        );

        Ok(Some(dir))
    }

    /// Builds the additional bind mounts required in scratch mode.
    fn build_scratch_mounts(
        roots: &ScratchRoots,
        shares: &[ResolvedShare],
    ) -> Vec<bollard::models::Mount> {
        let test_root = roots
            .test_root
            .to_str()
            .expect("test_root validated as canonicalized path");
        let vm_root = roots
            .vm_root
            .to_str()
            .expect("vm_root validated as canonicalized path");

        let mut mounts = Vec::new();

        // The *source* of every mount below is resolved by the daemon, which
        // may be outside this container; the target is not. So sources go
        // through `host_visible_path` and targets stay as the guest expects.
        mounts.push(Self::read_only_bind_mount(
            &n_vm_protocol::host_visible_path(n_vm_protocol::NIX_STORE_DIR),
            n_vm_protocol::NIX_STORE_DIR.to_owned(),
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
                        &n_vm_protocol::host_visible_path(&format!("{test_root}/{name}")),
                        format!("/{name}"),
                    ));
                }
            }
        }

        mounts.push(Self::read_only_bind_mount(
            &n_vm_protocol::host_visible_path(vm_root),
            VM_ROOT_SHARE_PATH.to_owned(),
        ));

        // Guest binaries keep /nix/store rpaths; expose the real store via virtiofs.
        mounts.push(Self::read_only_bind_mount(
            &n_vm_protocol::host_visible_path(n_vm_protocol::NIX_STORE_DIR),
            format!("{VM_ROOT_SHARE_PATH}/nix/store"),
        ));

        // QEMU and cloud-hypervisor allocate hugepage-backed memory here.
        mounts.push(Self::rw_bind_mount(
            "/dev/hugepages",
            "/dev/hugepages".to_owned(),
        ));

        // The cargo workspace, so that compile-time-captured relative paths
        // (`file!()`) resolve in the guest -- see `VM_WORKSPACE_DIR`.
        //
        // Read-only, matching what the guest actually gets: virtiofsd serves
        // the whole share with `--readonly`, so a read-write bind mount here
        // would claim an access the guest does not have.  Enough for reading
        // an existing corpus; persisting newly-generated inputs back to the
        // host tree needs the virtiofsd flag relaxed as well.
        //
        // Absent for an out-of-workspace caller, in which case the guest
        // simply has no /workspace and `n-it` leaves the working directory
        // alone.
        if let Some(workspace) = workspace_root()
            && let Some(workspace) = workspace.to_str()
        {
            mounts.push(Self::read_only_bind_mount(
                workspace,
                format!("{VM_ROOT_SHARE_PATH}/{VM_WORKSPACE_DIR}"),
            ));
        }

        // The writable windows, one bind mount each.  Mounted *outside* the
        // root share so that the read-only virtiofs daemon never serves
        // them: a separate daemon shares each path and only that path,
        // which keeps the read/write split enforced by the server rather
        // than by the guest's mount flags.
        for active in shares {
            if let Some(host) = active.host_dir.to_str() {
                mounts.push(Self::rw_bind_mount(
                    host,
                    active.share.container_path.to_owned(),
                ));
            }
        }

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

                // `eprintln!` rather than `tracing` throughout: this thread
                // belongs to the host tier, and `init_tracing` runs in the
                // container tier only, so a `tracing` event here reaches
                // nobody.  These lines are the sole record that a container
                // was left behind and dealt with -- the one place where
                // going unread is worse than being ugly.
                eprintln!("n-vm: performing emergency cleanup of container {container_id}");

                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        eprintln!(
                            "n-vm: failed to build emergency cleanup runtime ({e}); \
                             manual removal needed (e.g. `docker rm -f {container_id}`)",
                        );
                        return;
                    }
                };

                rt.block_on(async {
                    let opts = RemoveContainerOptionsBuilder::default().force(true).build();
                    match client.remove_container(&container_id, Some(opts)).await {
                        Ok(()) => eprintln!(
                            "n-vm: emergency cleanup of container {container_id} succeeded",
                        ),
                        Err(e) => eprintln!(
                            "n-vm: emergency cleanup of container {container_id} failed ({e}); \
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

    /// Force-removes the container in response to a termination signal, then
    /// ends this process.  Never returns.
    ///
    /// Every other cleanup route here runs from [`Drop`] -- the guard's own
    /// impl, and the [`CleanupThread`] it dispatches to.  That covers panics
    /// and early returns, because both unwind.  A signal does not: the
    /// default disposition for `SIGTERM` terminates the process outright, so
    /// no destructor runs and neither safety net fires.
    ///
    /// Two things leak without this, and the smaller one is the one that
    /// looks worse.  The container *record* survives, because
    /// `auto_remove` is deliberately `false`, and accumulates one entry per
    /// killed run.  More importantly the container keeps *running*: it is
    /// owned by the daemon, not by this process, so it plays the test out to
    /// the end with nothing left to collect the result.  For a test that is
    /// a few seconds; for a fuzz target it is the whole `-max_total_time`
    /// budget, which means a runner's own timeout would not actually stop
    /// the work it just gave up waiting for.
    ///
    /// Removal is forced, since the container is by definition still running.
    /// Reports through `eprintln!` rather than `tracing` because this tier
    /// has no subscriber: [`init_tracing`](crate::dispatch) runs in the
    /// container, not on the host, which is why the surrounding host-tier
    /// code prints directly too.  A cleanup notice that goes nowhere is
    /// worse than none, since it is the only record that the container was
    /// dealt with.
    async fn abort_on_signal(&mut self, signal: &str) -> ! {
        eprintln!(
            "n-vm: {signal} received; force-removing container {}",
            self.container_id,
        );

        match self
            .client
            .remove_container(
                &self.container_id,
                Some(RemoveContainerOptionsBuilder::default().force(true).build()),
            )
            .await
        {
            Ok(()) => {
                // Disarm both nets: there is nothing left to remove, and the
                // process is about to end anyway.
                self.defused = true;
                self.cleanup.defuse();
            }
            Err(e) => eprintln!(
                "n-vm: force-removal of container {} after {signal} failed: {e}; \
                 manual removal may be needed (e.g. `docker rm -f {}`)",
                self.container_id, self.container_id,
            ),
        }

        // `128 + signo`, the shell's convention for a signal death.  Chosen
        // over resetting the disposition and re-raising because that needs
        // `unsafe`, and nothing downstream distinguishes the two: a runner
        // sees a non-zero status either way.
        std::process::exit(128 + signal_number(signal));
    }
}

/// The signal number behind one of the names [`await_termination`] reports.
///
/// Only those two names are ever passed; an unrecognised one still yields a
/// failing status rather than pretending the run succeeded.
fn signal_number(signal: &str) -> i32 {
    match signal {
        "SIGINT" => nix::sys::signal::Signal::SIGINT as i32,
        "SIGTERM" => nix::sys::signal::Signal::SIGTERM as i32,
        _ => nix::sys::signal::Signal::SIGTERM as i32,
    }
}

/// Handlers for the signals that should end a run early.
///
/// `SIGINT` is watched alongside `SIGTERM` because an interactive Ctrl-C
/// leaks exactly the same way a runner's timeout does.
struct TerminationSignals {
    sigterm: tokio::signal::unix::Signal,
    sigint: tokio::signal::unix::Signal,
}

impl TerminationSignals {
    /// Registers both handlers.
    ///
    /// Separated from [`recv`](Self::recv) so that registration -- the only
    /// fallible part -- happens before the race it feeds, rather than inside
    /// it where a failure would have to unwind a log stream already underway.
    ///
    /// # Errors
    ///
    /// Returns [`ContainerError::SignalHandler`] if either handler cannot be
    /// registered.
    fn install() -> Result<Self, ContainerError> {
        use tokio::signal::unix::{SignalKind, signal};

        Ok(Self {
            sigterm: signal(SignalKind::terminate()).map_err(ContainerError::SignalHandler)?,
            sigint: signal(SignalKind::interrupt()).map_err(ContainerError::SignalHandler)?,
        })
    }

    /// Resolves when either signal arrives, naming it.
    async fn recv(&mut self) -> &'static str {
        tokio::select! {
            _ = self.sigterm.recv() => "SIGTERM",
            _ = self.sigint.recv() => "SIGINT",
        }
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

/// The hypervisor the selected kernel profile runs on.
///
/// `None` when it cannot be determined -- an unreadable or malformed
/// manifest -- which is deliberately *not* treated as a mismatch.  The
/// container tier reads the same file and reports that failure with a far
/// better message; skipping here would disguise a broken `testroot` as a
/// routine environment mismatch.
///
/// Read from `testroot` on the host because this is the last tier where a
/// skip can still be expressed; inside the container the only outcomes left
/// are pass and fail.
fn profile_backend(
    roots: &n_vm_protocol::ScratchRoots,
    declared: Option<&str>,
    emulation_required: bool,
) -> Option<EffectiveBackend> {
    let path = roots
        .test_root
        .join(n_vm_protocol::KERNEL_MANIFEST_PATH.trim_start_matches('/'));
    let manifest = crate::kernel_manifest::KernelManifest::load_from(&path).ok()?;
    let (name, profile) = manifest.selected(declared, emulation_required).ok()?;
    profile.backend(name).ok()
}

/// Reports a test that named a kernel profile and a backend that disagree.
///
/// A failure rather than a skip, which is what
/// [`RequestedBackend::resolve`](crate::backend::RequestedBackend::resolve)
/// would produce.  Skipping is right when the profile came from
/// `N_VM_PROFILE`: the run asked for an environment this test cannot use.
/// It is wrong when the test wrote both halves itself, because a skip is
/// reported as a pass -- so the test would go green having run nothing,
/// and the contradiction would never be seen.
///
/// `None` when the test named no profile (nothing to contradict), pinned no
/// backend (nothing contradicts it), or the two agree.
fn profile_backend_conflict(
    declared_profile: Option<&str>,
    requested: crate::backend::RequestedBackend,
    profile: Option<EffectiveBackend>,
) -> Option<ContainerError> {
    use crate::backend::RequestedBackend;

    let name = declared_profile?;
    let profile_backend = profile?;
    let requested = match requested {
        RequestedBackend::Default => return None,
        RequestedBackend::Qemu => EffectiveBackend::Qemu,
        RequestedBackend::CloudHypervisor => EffectiveBackend::CloudHypervisor,
    };
    (requested != profile_backend).then(|| ContainerError::ProfileContradictsBackend {
        profile: name.to_owned(),
        profile_backend,
        requested,
    })
}

/// Launches a Docker container and re-runs the current test binary inside it.
///
/// This is the **host-tier** entry point, called from the code generated by
/// `#[n_vm::test]` when neither `IN_VM` nor `IN_TEST_CONTAINER` is set (i.e. a
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
    vm_config: crate::config::VmConfig,
) -> Result<ContainerOutcome, ContainerError> {
    let requested = vm_config.backend;
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
        let needs_qemu = vm_config.first_qemu_only_nic().is_some();
        // The selected profile decides the hypervisor unless the test asked
        // for a specific one.  Read here rather than in the container tier
        // because this is the last place a skip can be expressed.
        let profile = profile_backend(&params.scratch_roots, vm_config.kernel_profile, cross);

        if let Some(conflict) =
            profile_backend_conflict(vm_config.kernel_profile, vm_config.backend, profile)
        {
            return Err(conflict);
        }

        let (backend, accel) = match requested.resolve(cross, needs_qemu, profile) {
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

        // Which windows this run opens, and where each is backed.  See
        // `resolve_writable_shares`.
        let shares = resolve_writable_shares(&vm_config)?;

        // Written before the container is created, so a failure here stops
        // the run rather than producing a guest that silently lost its
        // fuzzing configuration.
        let env_host_dir = params.write_forwarded_env(vm_config.fuzz_rss_limit_mib())?;

        let config = params.build_config(
            backend,
            accel,
            qemu_user.as_deref(),
            &shares,
            env_host_dir.as_deref(),
        );

        // The guard is armed at creation -- if anything between here and
        // the explicit cleanup panics or returns early, the CleanupThread
        // will force-remove the container.
        let mut guard = ContainerGuard::create_and_start(&client, config).await?;

        // Streaming the logs is where this tier spends the test's whole
        // lifetime, so it is also where a termination signal arrives.  Racing
        // the two is what gives a signal any path to cleanup at all; see
        // [`ContainerGuard::abort_on_signal`].
        let log_result = match TerminationSignals::install() {
            Ok(mut signals) => tokio::select! {
                result = guard.stream_logs() => result,
                signal = signals.recv() => guard.abort_on_signal(signal).await,
            },
            // Losing the handlers costs cleanup on a kill, which is worth a
            // warning and not worth failing a run over.
            Err(e) => {
                eprintln!(
                    "n-vm: could not install termination handlers ({e}); \
                     a signal will leak the container",
                );
                guard.stream_logs().await
            }
        };

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
        // Canonicalized, because the result is executed *inside the
        // container*, where only `/nix/store` and the `testroot` entries are
        // mounted.  A `PATH` hit is typically `devroot/bin/<program>`, a
        // symlink in the developer's working tree that does not exist in
        // there -- so handing it over unresolved produces exit code 127 from
        // a binary that is plainly present on the host.
        .and_then(|candidate| std::fs::canonicalize(candidate).ok())
        .and_then(|p| p.to_str().map(ToOwned::to_owned))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Profile / backend agreement ----------------------------------

    use crate::backend::RequestedBackend;

    /// The mistake this exists to catch: both halves named, and they
    /// describe a machine that does not exist.
    #[test]
    fn a_declared_profile_contradicting_a_pinned_backend_is_an_error() {
        let conflict = profile_backend_conflict(
            Some("flatcar"),
            RequestedBackend::CloudHypervisor,
            Some(EffectiveBackend::Qemu),
        );
        assert!(matches!(
            conflict,
            Some(ContainerError::ProfileContradictsBackend { .. })
        ));
    }

    /// Agreement is not a conflict, even though both were named.
    #[test]
    fn a_declared_profile_agreeing_with_its_backend_is_fine() {
        assert!(
            profile_backend_conflict(
                Some("flatcar"),
                RequestedBackend::Qemu,
                Some(EffectiveBackend::Qemu),
            )
            .is_none()
        );
    }

    /// An unpinned backend cannot contradict anything -- the profile
    /// chooses, which is the ordinary way to use the lever.
    #[test]
    fn a_declared_profile_alone_chooses_the_backend() {
        assert!(
            profile_backend_conflict(
                Some("flatcar"),
                RequestedBackend::Default,
                Some(EffectiveBackend::Qemu),
            )
            .is_none()
        );
    }

    /// A profile the *environment* chose is not this function's business:
    /// `resolve` skips that case, and skipping is right because the run,
    /// not the test, asked for an environment the test cannot use.
    #[test]
    fn an_environment_chosen_profile_is_left_to_resolve() {
        assert!(
            profile_backend_conflict(
                None,
                RequestedBackend::CloudHypervisor,
                Some(EffectiveBackend::Qemu),
            )
            .is_none()
        );
    }

    // -- Writable shares ----------------------------------------------

    /// The exact command line observed from `just fuzz reconcile_fuzz`,
    /// with the workspace shortened.
    const ENGINE: &str = "/ws/.fuzz-corpus/reconcile_fuzz \
         /ws/mgmt/tests/__fuzz__/reconcile/crashes \
         -artifact_prefix=/ws/mgmt/tests/__fuzz__/reconcile/crashes/ \
         -timeout=10 -max_total_time=60";

    fn fuzz_config() -> crate::config::VmConfig {
        crate::config::VmConfig {
            corpus: crate::config::CorpusPolicy::Fuzz,
            source_file: Some(("mgmt/tests/reconcile.rs", "/ws/mgmt")),
            ..crate::config::VmConfig::DEFAULT
        }
    }

    /// An ordinary test opens no window at all, which is the property the
    /// whole read-only guest rests on.
    #[test]
    fn a_test_that_is_not_a_fuzz_target_gets_no_writable_share() {
        let plan =
            plan_writable_shares(&crate::config::VmConfig::DEFAULT, ENGINE, Path::new("/ws"))
                .expect("an ordinary test cannot fail to plan");
        assert!(plan.is_empty());
    }

    /// Two windows, in two unrelated trees, taken from the engine.
    ///
    /// The corpus is the one that used to be served read-only, so this is
    /// the case that failed: `0 files found`, and nothing saved.
    #[test]
    fn the_engine_names_both_windows() {
        let plan = plan_writable_shares(&fuzz_config(), ENGINE, Path::new("/ws"))
            .expect("both directories are named");
        let got: Vec<_> = plan
            .iter()
            .map(|(share, dir)| (share.role, dir.to_str().expect("utf-8")))
            .collect();
        assert_eq!(
            got,
            vec![
                ("corpus", "/ws/.fuzz-corpus/reconcile_fuzz"),
                ("crashes", "/ws/mgmt/tests/__fuzz__/reconcile/crashes"),
            ],
        );
    }

    /// Without an engine there is no command line to read, so the corpus
    /// falls back beside the test -- and one window covers both, because
    /// `__fuzz__` encloses the crashes directory too.
    #[test]
    fn without_an_engine_the_corpus_falls_back_beside_the_test() {
        let plan = plan_writable_shares(&fuzz_config(), "", Path::new("/ws"))
            .expect("the fallback is derivable from the source file");
        let got: Vec<_> = plan
            .iter()
            .map(|(share, dir)| (share.role, dir.to_str().expect("utf-8")))
            .collect();
        assert_eq!(got, vec![("corpus", "/ws/mgmt/tests/__fuzz__")]);
    }

    /// A fuzz target whose corpus cannot be derived is an error rather than
    /// a run with nowhere to write: the guest cannot report the difference.
    #[test]
    fn a_fuzz_target_without_a_derivable_corpus_is_an_error() {
        let config = crate::config::VmConfig {
            corpus: crate::config::CorpusPolicy::Fuzz,
            source_file: None,
            ..crate::config::VmConfig::DEFAULT
        };
        let err = plan_writable_shares(&config, "", Path::new("/ws"))
            .expect_err("nothing names a corpus directory");
        assert!(matches!(err, ContainerError::CorpusDirUnresolvable { .. }));
    }

    /// `FUZZ_CORPUS_ROOT` may point anywhere, including outside the
    /// workspace.  The plan takes it as given; `n-it` creates the mount
    /// point in the guest because there is no read-only counterpart to
    /// overmount.
    #[test]
    fn a_corpus_outside_the_workspace_is_taken_as_given() {
        let plan = plan_writable_shares(&fuzz_config(), "/tmp/scratch-corpus", Path::new("/ws"))
            .expect("an absolute path needs no anchor");
        assert_eq!(plan[0].1.to_str().expect("utf-8"), "/tmp/scratch-corpus",);
    }

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
        let config = sample_params().build_config(
            EffectiveBackend::CloudHypervisor,
            Accel::Kvm,
            None,
            &[],
            None,
        );
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
        let config =
            sample_params().build_config(EffectiveBackend::Qemu, Accel::Tcg, None, &[], None);
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
        let config = sample_params().build_config(
            EffectiveBackend::CloudHypervisor,
            Accel::Kvm,
            None,
            &[],
            None,
        );
        assert_eq!(config.network_disabled, Some(true));
        let host = config.host_config.as_ref().expect("host_config");
        assert_eq!(host.network_mode.as_deref(), Some("none"));
    }

    #[test]
    fn config_sets_environment_variables() {
        let config = sample_params().build_config(
            EffectiveBackend::CloudHypervisor,
            Accel::Kvm,
            None,
            &[],
            None,
        );
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
        let config = sample_params().build_config(
            EffectiveBackend::CloudHypervisor,
            Accel::Kvm,
            None,
            &[],
            None,
        );
        // The container runs as root so that capabilities in the
        // bounding set are effective without ambient-cap gymnastics.
        assert_eq!(config.user.as_deref(), Some("0:0"));
    }

    #[test]
    fn config_passes_device_groups() {
        let params = sample_params();
        let config = params.build_config(
            EffectiveBackend::CloudHypervisor,
            Accel::Kvm,
            None,
            &[],
            None,
        );
        let host = config.host_config.as_ref().expect("host_config");
        let groups = host.group_add.as_ref().expect("group_add");
        // The sample_params use GIDs 36 and 108.
        assert!(groups.contains(&"36".to_string()));
        assert!(groups.contains(&"108".to_string()));
    }

    #[test]
    fn config_is_unprivileged_with_minimal_caps() {
        let config = sample_params().build_config(
            EffectiveBackend::CloudHypervisor,
            Accel::Kvm,
            None,
            &[],
            None,
        );
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
        let config = sample_params().build_config(
            EffectiveBackend::CloudHypervisor,
            Accel::Kvm,
            None,
            &[],
            None,
        );
        let host = config.host_config.as_ref().expect("host_config");
        assert_eq!(host.readonly_rootfs, Some(true));
    }

    #[test]
    fn config_does_not_auto_remove_and_never_restarts() {
        let config = sample_params().build_config(
            EffectiveBackend::CloudHypervisor,
            Accel::Kvm,
            None,
            &[],
            None,
        );
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
        let mounts = params.build_mounts(&[], None);
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

    /// The guest builds its child's environment from nothing, so this mount
    /// is the only way anything reaches it.  Without it a bolero test in the
    /// guest silently drops to its random driver and still passes.
    #[test]
    fn mounts_include_the_forwarded_env_dir_when_there_is_one() {
        let params = sample_params();
        let env_dir = std::path::Path::new("/tmp/n-vm-env-1-tests_my_test");
        let mounts = params.build_mounts(&[], Some(env_dir));
        let expected_target = format!("{VM_ROOT_SHARE_PATH}/{VM_ENV_DIR}");
        let mount = mounts
            .iter()
            .find(|m| m.target.as_deref() == Some(expected_target.as_str()))
            .expect("forwarded env dir should be mounted into the root share");
        assert_eq!(
            mount.source.as_deref(),
            Some("/tmp/n-vm-env-1-tests_my_test")
        );
        // Read-only: the guest only reads this, and virtiofsd serves the
        // root share `--readonly` regardless, so a read-write mount would
        // claim an access the guest does not have.
        assert_eq!(mount.read_only, Some(true));
    }

    /// Nothing to forward must add no mount at all, so an ordinary test is
    /// unaffected by this path existing.
    #[test]
    fn no_env_dir_means_no_env_mount() {
        let mounts = sample_params().build_mounts(&[], None);
        let unexpected = format!("{VM_ROOT_SHARE_PATH}/{VM_ENV_DIR}");
        assert!(
            !mounts
                .iter()
                .any(|m| m.target.as_deref() == Some(unexpected.as_str()))
        );
    }

    #[test]
    fn mounts_include_bin_dir_at_vm_test_bin_dir() {
        let params = sample_params();
        let mounts = params.build_mounts(&[], None);
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
        let mounts = ContainerParams::build_scratch_mounts(&roots, &[]);
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
        let mounts = ContainerParams::build_scratch_mounts(&roots, &[]);
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
        let mounts = ContainerParams::build_scratch_mounts(&roots, &[]);
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
        let mounts = ContainerParams::build_scratch_mounts(&roots, &[]);
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
        let mounts = params.build_mounts(&[], None);
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
