// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Shared paths, environment variables, and vsock identifiers for the
//! nested VM test environment.

use std::path::PathBuf;

/// Platform string passed to the Docker engine when creating the container.
pub const CONTAINER_PLATFORM: &str = "linux/amd64";

/// Environment variable pointing to the resolved `testroot` directory.
pub const ENV_TEST_ROOT: &str = "N_VM_TEST_ROOT";

/// Environment variable pointing to the resolved `vmroot` directory.
pub const ENV_VM_ROOT: &str = "N_VM_VM_ROOT";

/// Resolved root directories for the test container infrastructure.
#[derive(Debug, Clone)]
pub struct ScratchRoots {
    /// Absolute path to the `testroot` directory (container-tier tools).
    pub test_root: PathBuf,
    /// Absolute path to the `vmroot` directory (VM guest root filesystem).
    pub vm_root: PathBuf,
}

impl ScratchRoots {
    /// Resolves the `testroot` and `vmroot` directories.
    ///
    /// # Errors
    ///
    /// - [`ScratchRootError::InvalidPath`] if an environment variable is
    ///   set but the path cannot be canonicalized.
    /// - [`ScratchRootError::NotFound`] if neither detection method
    ///   locates both roots.
    pub fn resolve() -> Result<Self, ScratchRootError> {
        if let Some(roots) = Self::from_env()? {
            return Ok(roots);
        }
        if let Some(roots) = Self::from_cwd() {
            return Ok(roots);
        }
        Err(ScratchRootError::NotFound)
    }

    /// Tries to resolve roots from [`ENV_TEST_ROOT`] and [`ENV_VM_ROOT`].
    fn from_env() -> Result<Option<Self>, ScratchRootError> {
        let test_root_raw = match std::env::var(ENV_TEST_ROOT) {
            Ok(v) if !v.is_empty() => v,
            _ => return Ok(None),
        };
        let vm_root_raw = match std::env::var(ENV_VM_ROOT) {
            Ok(v) if !v.is_empty() => v,
            _ => return Ok(None),
        };

        let test_root = std::fs::canonicalize(&test_root_raw).map_err(|source| {
            ScratchRootError::InvalidPath {
                var: ENV_TEST_ROOT,
                path: PathBuf::from(&test_root_raw),
                source,
            }
        })?;
        let vm_root = std::fs::canonicalize(&vm_root_raw).map_err(|source| {
            ScratchRootError::InvalidPath {
                var: ENV_VM_ROOT,
                path: PathBuf::from(&vm_root_raw),
                source,
            }
        })?;

        Ok(Some(Self { test_root, vm_root }))
    }

    /// Tries to find `testroot` and `vmroot` in the current directory.
    fn from_cwd() -> Option<Self> {
        let cwd = std::env::current_dir().ok()?;
        let test_root = std::fs::canonicalize(cwd.join("testroot")).ok()?;
        let vm_root = std::fs::canonicalize(cwd.join("vmroot")).ok()?;
        Some(Self { test_root, vm_root })
    }
}

/// Error resolving the test container root directories.
#[derive(Debug)]
pub enum ScratchRootError {
    /// An environment variable path cannot be canonicalized.
    InvalidPath {
        /// The environment variable name.
        var: &'static str,
        /// The raw path value from the environment.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// Neither environment variables nor CWD detection found both roots.
    NotFound,
}

impl std::fmt::Display for ScratchRootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPath { var, path, .. } => {
                write!(f, "scratch root {var} = {path:?} is not accessible")
            }
            Self::NotFound => {
                write!(
                    f,
                    "could not find testroot/vmroot in the working directory \
                     and {ENV_TEST_ROOT}/{ENV_VM_ROOT} are not set; \
                     run `just setup-roots` from the workspace root"
                )
            }
        }
    }
}

impl std::error::Error for ScratchRootError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPath { source, .. } => Some(source),
            Self::NotFound => None,
        }
    }
}

/// Environment variable set by the init system (`n-it`) inside the VM guest.
pub const ENV_IN_VM: &str = "IN_VM";

/// Environment variable set by the container tier (`n-vm::run_test_in_vm`).
pub const ENV_IN_TEST_CONTAINER: &str = "IN_TEST_CONTAINER";

/// The value used to mark both [`ENV_IN_VM`] and [`ENV_IN_TEST_CONTAINER`]
/// as active.
pub const ENV_MARKER_VALUE: &str = "YES";

/// Environment variable carrying the effective hypervisor backend the
/// container tier should boot (`"qemu"` or `"cloud_hypervisor"`).
///
/// Set by the host tier once it has resolved the backend against the
/// Docker daemon's architecture (see the host-tier dispatch in `n-vm`);
/// read by the container tier so it can dispatch to the right backend
/// without baking the choice in at compile time.
pub const ENV_BACKEND: &str = "N_VM_BACKEND";

/// Environment variable carrying the effective acceleration mode for the
/// container tier (`"kvm"` or `"tcg"`).
///
/// `kvm` when the Docker daemon architecture matches the test binary's
/// target architecture; `tcg` (software emulation) for a cross-arch
/// guest.  Set by the host tier, read by the QEMU backend.
pub const ENV_ACCEL: &str = "N_VM_ACCEL";

/// Docker label marking a container as one this crate created.
///
/// Set on every test container so that a container can be recognised as
/// ours without matching on image or name, neither of which is reliable:
/// the scratch image is shared, and names are assigned by the daemon.
///
/// The reaper (`n-vm-reap`) selects on this label alone, which is what
/// makes bulk removal safe to offer at all -- it can never match a
/// container some other tool on the machine created.
pub const LABEL_OWNER: &str = "dev.githedgehog.n-vm";

/// Value of [`LABEL_OWNER`].  Presence is what matters; the value is fixed
/// so the label can be matched as `key=value` rather than by existence.
pub const LABEL_OWNER_VALUE: &str = "1";

/// Docker label carrying the fully-qualified name of the test the container
/// was launched for.
///
/// Purely diagnostic: a leaked container is far easier to act on when it
/// says which test produced it.
pub const LABEL_TEST: &str = "dev.githedgehog.n-vm.test";

/// Docker label carrying the PID of the host-tier process that created the
/// container.
///
/// This is what lets the reaper distinguish a genuine orphan from a
/// container belonging to a run that is still going: if the recorded PID is
/// gone, nothing is left to collect the container's result.  Treated as a
/// hint rather than proof, since PIDs are reused.
pub const LABEL_HOST_PID: &str = "dev.githedgehog.n-vm.host-pid";

/// A vsock port number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VsockPort(u32);

impl VsockPort {
    /// The smallest port suitable for dynamic allocation.
    pub const DYNAMIC_MIN: Self = Self(1024);

    /// The largest port suitable for dynamic allocation.
    pub const DYNAMIC_MAX: Self = Self(u32::MAX - 1);

    /// Creates a new [`VsockPort`] from a raw port number.
    ///
    /// # Panics
    ///
    /// Panics if `port` is `u32::MAX` (`VMADDR_PORT_ANY`), which has
    /// special kernel semantics (wildcard / "assign any port") and must
    /// not be used as a concrete port number.
    #[must_use]
    pub const fn new(port: u32) -> Self {
        assert!(
            port != u32::MAX,
            "VMADDR_PORT_ANY (u32::MAX) cannot be used as a concrete vsock port"
        );
        Self(port)
    }

    /// Returns the raw `u32` port number.
    #[must_use]
    pub const fn as_raw(self) -> u32 {
        self.0
    }
}

impl std::fmt::Display for VsockPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A vsock context identifier (CID).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VsockCid(u64);

impl VsockCid {
    /// The hypervisor's CID (`VMADDR_CID_HYPERVISOR`).
    pub const HYPERVISOR: Self = Self(0);

    /// Loopback CID (`VMADDR_CID_LOCAL`), analogous to `127.0.0.1`.
    pub const LOCAL: Self = Self(1);

    /// The host CID (`VMADDR_CID_HOST`).
    pub const HOST: Self = Self(2);

    /// The first CID available for guest use.
    pub const GUEST_MIN: Self = Self(3);

    /// The largest CID available for guest use.
    pub const GUEST_MAX: Self = Self(u32::MAX as u64 - 1);

    /// Creates a new [`VsockCid`] from a raw CID value.
    ///
    /// # Panics
    ///
    /// Panics if `cid` is 0 (`VMADDR_CID_HYPERVISOR`), 1
    /// (`VMADDR_CID_LOCAL`), or 2 (`VMADDR_CID_HOST`).  These CIDs have
    /// fixed kernel-level semantics and must not be used as arbitrary guest
    /// identifiers -- use the named constants [`Self::HYPERVISOR`],
    /// [`Self::LOCAL`], or [`Self::HOST`] instead.
    #[must_use]
    pub const fn new(cid: u64) -> Self {
        assert!(
            cid >= 3,
            "CIDs 0 (hypervisor), 1 (local), and 2 (host) are reserved; use the named constants instead"
        );
        Self(cid)
    }

    /// Returns the raw `u64` CID value.
    #[must_use]
    pub const fn as_raw(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for VsockCid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A typed vsock communication channel from VM guest to container host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VsockChannel {
    /// The vsock port number for this channel.
    pub port: VsockPort,
    /// A human-readable label used in log messages and error reports.
    pub label: &'static str,
}

impl VsockChannel {
    /// Channel for the init system's tracing data.
    pub const INIT_TRACE: Self = Self {
        port: VsockPort::new(123_456),
        label: "init-trace",
    };

    /// Channel for the test process's **stdout**.
    pub const TEST_STDOUT: Self = Self {
        port: VsockPort::new(123_457),
        label: "test-stdout",
    };

    /// Channel for the test process's **stderr**.
    pub const TEST_STDERR: Self = Self {
        port: VsockPort::new(123_458),
        label: "test-stderr",
    };

    /// Channel for the structured pass/fail verdict reported by the init
    /// system once the test process has exited.
    pub const TEST_RESULT: Self = Self {
        port: VsockPort::new(123_459),
        label: "test-result",
    };

    /// Returns the Unix socket path the container tier must bind for this
    /// channel.
    pub fn listener_path(&self) -> PathBuf {
        PathBuf::from(format!("{VHOST_VSOCK_SOCKET_PATH}_{}", self.port.as_raw()))
    }
}

impl std::fmt::Display for VsockChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (vsock port {})", self.label, self.port.as_raw())
    }
}

/// The structured pass/fail verdict the guest init system reports to the
/// host over [`VsockChannel::TEST_RESULT`].
///
/// This replaces scraping the test process's stdout for a libtest summary
/// line.  The verdict is computed inside the guest from the test process's
/// exit status (plus the init system's leaked-process / signal policy) and
/// transmitted explicitly, so the host never has to infer pass/fail from
/// free-form output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestResult {
    /// `true` if and only if the test is considered to have passed.
    pub passed: bool,
    /// Human-readable detail (exit code, signal, or reason) for diagnostics.
    pub detail: String,
}

impl TestResult {
    /// Marker prefix identifying a result line on the wire.
    ///
    /// Using a prefix lets the host scan the (possibly noisy) stream for the
    /// verdict line without being confused by other output.
    pub const WIRE_PREFIX: &str = "n-it-result";

    /// Creates a new [`TestResult`].
    #[must_use]
    pub fn new(passed: bool, detail: impl Into<String>) -> Self {
        Self {
            passed,
            detail: detail.into(),
        }
    }

    /// Serializes the verdict to its single-line wire form.
    ///
    /// The detail is flattened to a single line; the trailing newline marks
    /// the end of the record for the reader.
    #[must_use]
    pub fn to_wire(&self) -> String {
        let tag = if self.passed { "pass" } else { "fail" };
        // Trim so the detail round-trips through `parse`, which trims the
        // reconstructed detail.
        let detail = self.detail.replace(['\n', '\r'], " ");
        let detail = detail.trim();
        format!("{prefix} {tag} {detail}\n", prefix = Self::WIRE_PREFIX)
    }

    /// Parses a verdict from a raw stream, scanning for the first line
    /// carrying [`Self::WIRE_PREFIX`].
    ///
    /// Returns `None` if no well-formed result line is present.  Callers
    /// **must** treat `None` as a failure: an absent or garbled verdict
    /// means the guest never reported success.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let body = raw.lines().find_map(|line| {
            // The prefix must start the line (no leading whitespace) and be
            // followed by whitespace separating it from the tag.  Without
            // these boundaries a line like `n-it-resultpass` -- or an
            // indented echo of a result line inside other output -- could
            // falsely strip to a `pass` verdict; a spurious pass is the
            // dangerous direction for a verdict parser.  A trailing `\r`
            // (CRLF console transport) is tolerated via the closing trim.
            let rest = line.strip_prefix(Self::WIRE_PREFIX)?;
            rest.strip_prefix(char::is_whitespace).map(str::trim_start)
        })?;
        let (tag, detail) = match body.split_once(char::is_whitespace) {
            Some((tag, detail)) => (tag, detail.trim()),
            None => (body, ""),
        };
        let passed = match tag {
            "pass" => true,
            "fail" => false,
            _ => return None,
        };
        Some(Self::new(passed, detail))
    }
}

/// Legacy static vsock CID for single-VM tests.
pub const VM_GUEST_CID: VsockCid = VsockCid::new(3);

// Vsock CIDs and AF_VSOCK port bindings are host-global: they are NOT
// namespaced by containers, network namespaces, or cgroups.  When
// multiple test containers launch QEMU in parallel, each VM must use a
// unique CID and unique listener ports to avoid EADDRINUSE collisions.

/// Kernel command-line parameter: init-trace vsock port.
pub const CMDLINE_TRACE_PORT: &str = "n_it.trace_port";

/// Kernel command-line parameter: test-stdout vsock port.
pub const CMDLINE_STDOUT_PORT: &str = "n_it.stdout_port";

/// Kernel command-line parameter: test-stderr vsock port.
pub const CMDLINE_STDERR_PORT: &str = "n_it.stderr_port";

/// Kernel command-line parameter: test-result vsock port.
pub const CMDLINE_RESULT_PORT: &str = "n_it.result_port";

/// Dynamically allocated vsock resources for one VM instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VsockAllocation {
    /// The guest CID passed to the hypervisor's vsock device.
    pub cid: VsockCid,
    /// Channel for the init system's tracing output.
    pub init_trace: VsockChannel,
    /// Channel for the test process's stdout.
    pub test_stdout: VsockChannel,
    /// Channel for the test process's stderr.
    pub test_stderr: VsockChannel,
    /// Channel for the structured pass/fail verdict.
    pub result: VsockChannel,
}

impl VsockAllocation {
    /// Creates an allocation using the legacy static values.
    pub const fn with_defaults() -> Self {
        Self {
            cid: VM_GUEST_CID,
            init_trace: VsockChannel::INIT_TRACE,
            test_stdout: VsockChannel::TEST_STDOUT,
            test_stderr: VsockChannel::TEST_STDERR,
            result: VsockChannel::TEST_RESULT,
        }
    }

    /// Formats the vsock port assignments as kernel command-line parameters.
    pub fn kernel_cmdline_fragment(&self) -> String {
        format!(
            "{CMDLINE_TRACE_PORT}={} {CMDLINE_STDOUT_PORT}={} {CMDLINE_STDERR_PORT}={} \
             {CMDLINE_RESULT_PORT}={}",
            self.init_trace.port.as_raw(),
            self.test_stdout.port.as_raw(),
            self.test_stderr.port.as_raw(),
            self.result.port.as_raw(),
        )
    }

    /// Parses vsock port assignments from a kernel command-line string.
    ///
    /// Returns `None` if any of the three port parameters are missing,
    /// cannot be parsed as `u32`, or would equal `VMADDR_PORT_ANY`.
    pub fn parse_kernel_cmdline(cmdline: &str) -> Option<Self> {
        let mut trace_port: Option<u32> = None;
        let mut stdout_port: Option<u32> = None;
        let mut stderr_port: Option<u32> = None;
        let mut result_port: Option<u32> = None;

        for token in cmdline.split_whitespace() {
            if let Some((key, value)) = token.split_once('=') {
                match key {
                    k if k == CMDLINE_TRACE_PORT => {
                        trace_port = value.parse().ok();
                    }
                    k if k == CMDLINE_STDOUT_PORT => {
                        stdout_port = value.parse().ok();
                    }
                    k if k == CMDLINE_STDERR_PORT => {
                        stderr_port = value.parse().ok();
                    }
                    k if k == CMDLINE_RESULT_PORT => {
                        result_port = value.parse().ok();
                    }
                    _ => {}
                }
            }
        }

        // Filter out VMADDR_PORT_ANY before constructing VsockPort.
        let trace_port = trace_port.filter(|&p| p != u32::MAX)?;
        let stdout_port = stdout_port.filter(|&p| p != u32::MAX)?;
        let stderr_port = stderr_port.filter(|&p| p != u32::MAX)?;
        let result_port = result_port.filter(|&p| p != u32::MAX)?;

        Some(Self {
            cid: VM_GUEST_CID,
            init_trace: VsockChannel {
                port: VsockPort::new(trace_port),
                label: "init-trace",
            },
            test_stdout: VsockChannel {
                port: VsockPort::new(stdout_port),
                label: "test-stdout",
            },
            test_stderr: VsockChannel {
                port: VsockPort::new(stderr_port),
                label: "test-stderr",
            },
            result: VsockChannel {
                port: VsockPort::new(result_port),
                label: "test-result",
            },
        })
    }
}

impl std::fmt::Display for VsockAllocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "cid={}, trace={}, stdout={}, stderr={}, result={}",
            self.cid,
            self.init_trace.port,
            self.test_stdout.port,
            self.test_stderr.port,
            self.result.port,
        )
    }
}

/// Base directory for VM runtime artifacts (sockets, logs, etc.).
pub const VM_RUN_DIR: &str = "/vm";

/// Path to the virtiofsd Unix socket.
pub const VIRTIOFSD_SOCKET_PATH: &str = "/vm/virtiofsd.sock";

/// Path to the vhost-vsock Unix socket used by cloud-hypervisor.
pub const VHOST_VSOCK_SOCKET_PATH: &str = "/vm/vhost.vsock";

/// Path to the hypervisor control-plane Unix socket.
pub const HYPERVISOR_API_SOCKET_PATH: &str = "/vm/hypervisor.sock";

/// Path to the serial/kernel console Unix socket.
pub const KERNEL_CONSOLE_SOCKET_PATH: &str = "/vm/kernel.sock";

/// Root filesystem share path exposed to the VM via virtiofs.
pub const VM_ROOT_SHARE_PATH: &str = "/vm.root";

/// The virtiofs tag used to identify the root filesystem inside the guest.
pub const VIRTIOFS_ROOT_TAG: &str = "root";

/// Path to the Unix socket of the *writable* virtiofs daemon.
///
/// A second daemon exists so the writable window is enforced by the
/// server rather than by guest cooperation.  The root daemon keeps
/// `--readonly`, so it cannot write anywhere no matter what the guest
/// does with its mount flags; this one has no `--readonly` but its
/// `--shared-dir` *is* the corpus directory, so it cannot see anything
/// else.
///
/// The threat model is the point: the reason to fuzz inside a VM is that
/// the test is deliberately trying to make code malfunction against a real
/// kernel.  A guest-side `mount -o remount,rw` must not be able to reach
/// the developer's source tree.
pub const VIRTIOFSD_CORPUS_SOCKET_PATH: &str = "/vm/virtiofsd-corpus.sock";

/// The virtiofs tag identifying the writable corpus share in the guest.
pub const VIRTIOFS_CORPUS_TAG: &str = "corpus";

/// Container path at which the host corpus directory is bind-mounted, so
/// that the writable virtiofs daemon can serve it.
pub const CORPUS_SHARE_PATH: &str = "/vm.corpus";

/// Directory name, relative to a test's source directory, that holds
/// generated fuzz corpora and crash artifacts.
///
/// This is `bolero`'s layout: it writes under
/// `<dir of file!()>/__fuzz__/<name>`.  Granularity is this directory
/// rather than the per-test subdirectory beneath it, because the per-test
/// name comes from `bolero`'s own `fuzz_dir()` derivation (which strips
/// `test_`/`fuzz_` affixes and is computed from the call site's
/// `type_name`).  Depending on that would couple the mount layout to
/// `bolero` internals; a `__fuzz__` directory exists only to hold corpora,
/// so it is already a tight enough blast radius.
pub const CORPUS_DIR_NAME: &str = "__fuzz__";

/// Kernel command-line key carrying the guest path at which the writable
/// corpus share should be mounted.
///
/// Absent when the test did not opt in via `#[corpus]`, in which case
/// `n-it` mounts nothing and the guest stays entirely read-only.
pub const CMDLINE_CORPUS_MOUNT: &str = "n_it.corpus_mount";

/// Well-known directory inside the VM guest where the test binary
/// directory is mounted.
///
/// The `vmroot` nix derivation pre-creates this directory so that Docker
/// can bind-mount the host-side binary directory at
/// `{VM_ROOT_SHARE_PATH}/{VM_TEST_BIN_DIR}` without needing to create
/// intermediate directories on the (read-only) nix store path.
///
/// Inside the VM guest, the test binary is executed as
/// `/{VM_TEST_BIN_DIR}/{binary_name}`.
pub const VM_TEST_BIN_DIR: &str = "test-bin";

/// Well-known directory inside the VM guest where the host's cargo
/// workspace root is mounted read-write, and which `n-it` makes the test
/// process's working directory.
///
/// This exists for tooling that resolves paths captured at compile time.
/// `bolero` is the motivating case: `bolero::check!()` records `file!()`
/// (which cargo makes *workspace-root* relative, e.g.
/// `mgmt/tests/reconcile.rs`) and later canonicalizes it to locate a
/// corpus directory.  Nothing resolves in a guest whose working directory
/// is `/` and which cannot see the source tree, so the test aborts before
/// generating a single input.
///
/// Mounting the workspace at a *fixed* guest path and running the test
/// from it is enough: the relative `file!()` then canonicalizes against
/// this directory.  Matching the host's absolute workspace path inside the
/// guest would also work -- `bolero` falls back to walking
/// `CARGO_MANIFEST_DIR`'s ancestors -- but that path varies per developer
/// and per CI runner, so it cannot be baked into the `vmroot` derivation
/// that has to pre-create the mount point.
///
/// Currently mounted **read-only**: virtiofsd serves the whole root share
/// with `--readonly`, so the guest cannot write here even though the
/// directory appears as its own mount (`--announce-submounts` makes it
/// one).  That is sufficient to read an existing corpus, but generated
/// inputs and crash artifacts cannot yet persist back to the host tree.
pub const VM_WORKSPACE_DIR: &str = "workspace";

/// Environment variable naming the host cargo workspace root to mount at
/// [`VM_WORKSPACE_DIR`].
///
/// When unset, the workspace root is discovered by walking up from the
/// current directory looking for a `Cargo.toml` that declares
/// `[workspace]` -- cargo runs tests with the working directory set to the
/// *package* root, not the workspace root, so the walk is necessary.
pub const ENV_WORKSPACE: &str = "N_VM_WORKSPACE";

// == Forwarded environment ==

/// Well-known guest directory holding the forwarded environment file.
///
/// The host tier writes [`ENV_FILE_NAME`] into a directory it owns and
/// bind-mounts that directory here, read-only, alongside
/// [`VM_TEST_BIN_DIR`].  Like `test-bin`, the mount point is pre-created by
/// the `vmroot` derivation, because Docker cannot `mkdir` inside a
/// read-only nix store path.
///
/// A file rather than the kernel command line: the values are arbitrary
/// (`BOLERO_LIBFUZZER_ARGS` is a space-separated list), and the cmdline has
/// both a length cap and no escaping convention that the guest and the host
/// could be relied on to agree about.
pub const VM_ENV_DIR: &str = "test-env";

/// Name of the forwarded environment file within [`VM_ENV_DIR`].
pub const ENV_FILE_NAME: &str = "environ";

/// Absolute path of the forwarded environment file inside the guest.
pub const GUEST_ENV_FILE: &str = "/test-env/environ";

/// Environment variable prefixes forwarded from the host tier to the guest.
///
/// `BOLERO_*` is the motivating case: a fuzz supervisor configures the
/// engine entirely through the environment (`BOLERO_LIBFUZZER_ARGS`,
/// `BOLERO_TEST_NAME`, `BOLERO_LIBTEST_HARNESS`), and bolero falls back to
/// its brief random driver when it does not see them.  In a guest that
/// received no environment at all, that fallback is indistinguishable from
/// a successful fuzzing run -- it passes, quickly, having fuzzed nothing.
pub const FORWARDED_ENV_PREFIXES: &[&str] = &["BOLERO_"];

/// Comma-separated extra variable names to forward, beyond
/// [`FORWARDED_ENV_PREFIXES`].
pub const ENV_FORWARD: &str = "N_VM_FORWARD_ENV";

/// Whether a variable name should be carried into the guest.
///
/// `extra` is the raw value of [`ENV_FORWARD`], if set.
#[must_use]
pub fn is_forwarded(name: &str, extra: Option<&str>) -> bool {
    if FORWARDED_ENV_PREFIXES.iter().any(|p| name.starts_with(p)) {
        return true;
    }
    extra.is_some_and(|list| {
        list.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .any(|s| s == name)
    })
}

/// Rewrite host workspace paths in a forwarded value so they resolve in the guest.
///
/// The workspace is mounted at [`VM_WORKSPACE_DIR`] rather than at its host path, because that
/// path varies per developer and per CI runner and so cannot be baked into the `vmroot`
/// derivation. Anything forwarded that *names* a host path therefore points nowhere once it
/// arrives.
///
/// `BOLERO_LIBFUZZER_ARGS` is why this exists. `cargo-bolero` computes the corpus and
/// artifact directories on the host and passes them as absolute paths:
///
/// ```text
/// -artifact_prefix=/home/you/src/dataplane/mgmt/tests/__fuzz__/reconcile/crashes/
/// ```
///
/// The guest has that tree at `/workspace/mgmt/tests/__fuzz__/...`, and it is writable there --
/// see the `#[corpus]` share. Without the rewrite the fuzzer ran, found inputs, and wrote them
/// to a directory that did not exist, so nothing ever came back.
///
/// Substring replacement rather than path parsing, because the value is an opaque
/// space-separated argument list in which paths appear both alone and glued to a flag by `=`.
/// A trailing separator on `host_root` is ignored so that `/a/b` and `/a/b/` behave alike.
#[must_use]
pub fn remap_workspace_paths(value: &str, host_root: &str) -> String {
    let host_root = host_root.trim_end_matches('/');
    if host_root.is_empty() {
        return value.to_owned();
    }
    value.replace(host_root, &format!("/{VM_WORKSPACE_DIR}"))
}

/// Encode variables as NUL-separated `KEY=VALUE` records.
///
/// The same shape as `/proc/self/environ`, and for the same reason: NUL is
/// the one byte that cannot appear in an environment variable, so this
/// needs no escaping and cannot be confused by a value containing spaces,
/// newlines, or quotes.
#[must_use]
pub fn encode_environ<'a, I>(vars: I) -> Vec<u8>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut out = Vec::new();
    for (key, value) in vars {
        out.extend_from_slice(key.as_bytes());
        out.push(b'=');
        out.extend_from_slice(value.as_bytes());
        out.push(0);
    }
    out
}

/// Decode what [`encode_environ`] wrote.
///
/// Records that are empty, non-UTF-8, or missing a `=` are skipped rather
/// than aborting the boot: the caller logs what did arrive, which is more
/// useful than failing a VM over one malformed record.
#[must_use]
pub fn decode_environ(bytes: &[u8]) -> Vec<(String, String)> {
    bytes
        .split(|b| *b == 0)
        .filter(|record| !record.is_empty())
        .filter_map(|record| {
            let text = core::str::from_utf8(record).ok()?;
            let (key, value) = text.split_once('=')?;
            if key.is_empty() {
                return None;
            }
            Some((key.to_owned(), value.to_owned()))
        })
        .collect()
}


#[cfg(test)]
mod remap_tests {
    use super::*;

    #[test]
    fn a_host_path_becomes_the_guest_mount() {
        let got = remap_workspace_paths(
            "-artifact_prefix=/home/you/src/dp/mgmt/tests/__fuzz__/crashes/",
            "/home/you/src/dp",
        );
        assert_eq!(got, "-artifact_prefix=/workspace/mgmt/tests/__fuzz__/crashes/");
    }

    #[test]
    fn every_occurrence_is_rewritten() {
        let got = remap_workspace_paths("/w/corpus /w/crashes -x=/w/c/", "/w");
        assert_eq!(got, "/workspace/corpus /workspace/crashes -x=/workspace/c/");
    }

    #[test]
    fn a_trailing_separator_on_the_root_changes_nothing() {
        assert_eq!(
            remap_workspace_paths("/w/corpus", "/w/"),
            remap_workspace_paths("/w/corpus", "/w"),
        );
    }

    /// An out-of-workspace caller has no `/workspace`, and an empty root would otherwise splice
    /// the mount point between every character.
    #[test]
    fn an_empty_root_is_left_alone() {
        assert_eq!(remap_workspace_paths("/w/corpus", ""), "/w/corpus");
    }

    #[test]
    fn a_value_naming_no_host_path_is_untouched() {
        assert_eq!(remap_workspace_paths("-timeout=10 -jobs=1", "/w"), "-timeout=10 -jobs=1");
    }
}

#[cfg(test)]
mod environ_test {
    use super::{decode_environ, encode_environ, is_forwarded};

    /// `BOLERO_LIBFUZZER_ARGS` is a space-separated list of libfuzzer flags,
    /// which is precisely why this is a file and not the kernel cmdline.
    #[test]
    fn round_trips_values_with_spaces() {
        let args = "/corpus /crashes -max_total_time=60 -jobs=4";
        let decoded = decode_environ(&encode_environ([("BOLERO_LIBFUZZER_ARGS", args)]));
        assert_eq!(
            decoded,
            vec![("BOLERO_LIBFUZZER_ARGS".to_owned(), args.to_owned())]
        );
    }

    #[test]
    fn round_trips_awkward_values() {
        let vars = [
            ("A", "has\nnewline"),
            ("B", "has \"quotes\" and 'ticks'"),
            ("C", ""),
            ("D", "trailing="),
        ];
        let decoded = decode_environ(&encode_environ(vars));
        assert_eq!(decoded.len(), 4);
        assert_eq!(decoded[0].1, "has\nnewline");
        assert_eq!(decoded[1].1, "has \"quotes\" and 'ticks'");
        assert_eq!(decoded[2].1, "");
        assert_eq!(decoded[3].1, "trailing=");
    }

    #[test]
    fn skips_malformed_records() {
        assert!(decode_environ(b"NOEQUALS\0").is_empty());
        assert!(decode_environ(b"=value\0").is_empty());
        assert!(decode_environ(b"\0\0\0").is_empty());
    }

    #[test]
    fn forwards_by_prefix_and_explicit_name() {
        assert!(is_forwarded("BOLERO_LIBFUZZER_ARGS", None));
        assert!(is_forwarded("BOLERO_TEST_NAME", None));
        assert!(!is_forwarded("PATH", None));
        assert!(!is_forwarded("HOME", None));
        assert!(is_forwarded("RUST_LOG", Some("RUST_LOG, MY_VAR")));
        assert!(is_forwarded("MY_VAR", Some("RUST_LOG, MY_VAR")));
        assert!(!is_forwarded("OTHER", Some("RUST_LOG, MY_VAR")));
        // An empty or degenerate list must not become "forward everything".
        assert!(!is_forwarded("PATH", Some("")));
        assert!(!is_forwarded("PATH", Some(",,")));
    }
}

// == Binary paths (inside the container) ==

// NOTE: the `qemu-system-<arch>` binary path is architecture-specific and
// lives on `n_vm::Arch::qemu_system_binary`, not here, so the aarch64 path
// can never silently resolve to an x86 default.
//
// The guest kernel image is *not* a constant at all: it is looked up in the
// kernel manifest below, because which kernels exist is a fact about the nix
// build, not about this protocol.

/// Path to the kernel manifest inside the container.
///
/// nix writes this file into `testroot`, and every first-level `testroot`
/// entry is bind-mounted at the container root (see
/// `n_vm::container`), so it lands here.  It declares which guest kernels
/// were built and where their images are -- the single source of truth that
/// keeps the nix build and the Rust test tiers from disagreeing.
///
/// This exists because cargo must never invoke nix: the artifacts are
/// materialized first (`just setup-roots`), and the tests only ever read
/// them.
pub const KERNEL_MANIFEST_PATH: &str = "/n-vm-manifest.json";

/// Selects a kernel profile by name, overriding the manifest's `default`.
///
/// A *run mode*, not a per-test setting: it names the environment the whole
/// invocation runs in, e.g. `N_VM_PROFILE=qemu cargo test`.  Tests that
/// cannot run in the selected environment skip with a reason rather than
/// failing, because "this environment does not suit this test" is a fact
/// about the pairing and not a defect in either.
///
/// Set on the host and forwarded into the container, so both tiers agree on
/// which profile is in play.
pub const ENV_PROFILE: &str = "N_VM_PROFILE";

/// File to append a record to whenever a test is skipped.
///
/// libtest has no run-time "skipped" state -- `#[ignore]` is decided at
/// compile time -- so a test that skips is counted as *passed*, and the
/// reason it printed is swallowed by output capture unless the test also
/// fails.  A suite can therefore report a clean run having actually
/// exercised almost nothing, which is the failure mode this exists to
/// prevent.
///
/// Writing to a file rather than to stderr is what makes the record
/// survive: it is outside libtest's capture, and outside the
/// process-per-test model that nextest uses, so records from a whole run
/// accumulate in one place that CI can assert on.
///
/// One JSON object per line, appended.  Unset means no record is kept,
/// which is the default: this costs nothing when nobody is looking.
pub const ENV_SKIP_LOG: &str = "N_VM_SKIP_LOG";

/// When set to a non-empty value, a skipped test fails instead.
///
/// For a run that is *supposed* to exercise everything -- a release gate
/// against the production kernel, say -- where a skip is not a neutral
/// outcome but a hole in the thing being certified.
///
/// Deliberately not the default: a skip is the correct answer to a genuine
/// mismatch, such as cloud-hypervisor being asked to emulate a foreign
/// architecture.
pub const ENV_STRICT_SKIPS: &str = "N_VM_STRICT_SKIPS";

/// Overrides virtiofsd's `--cache` mode for the guest's read-only share.
///
/// Unset uses `always`, which is what makes an aarch64 guest run at all --
/// see the rationale where virtiofsd is launched.  Set to `auto` or `never`
/// to get virtiofsd's other modes back.
///
/// Exists as a run-time knob rather than a build-time constant because the
/// guest's failure modes are sensitive to the *layout* of the guest test
/// binary: rebuilding `n-vm` to change a virtiofsd flag also changes the
/// binary under test, which confounds the comparison it was meant to make.
/// One build plus this variable keeps the cache mode the only difference
/// between two runs -- which is how `auto` was identified as the cause.
pub const ENV_VIRTIOFS_CACHE: &str = "N_VM_VIRTIOFS_CACHE";

/// Directory holding per-profile kernel artifacts inside the container.
///
/// Paths in the manifest are absolute and already include this prefix; the
/// constant exists so the nix side and the tests agree on one spelling.
pub const KERNELS_DIR: &str = "/kernels";

/// Path to the `n-it` init system binary inside the container.
///
/// This binary is passed as the `init=` kernel command-line argument so
/// that it runs as PID 1 inside the VM guest.
pub const INIT_BINARY_PATH: &str = "/bin/n-it";

/// Path to the virtiofsd binary inside the container.
///
/// virtiofsd shares the container's filesystem into the VM via virtiofs.
pub const VIRTIOFSD_BINARY_PATH: &str = "/bin/virtiofsd";

/// Path to the cloud-hypervisor binary inside the container.
///
/// **Backend-specific**: used only by the
/// [`CloudHypervisor`](../n_vm/cloud_hypervisor/struct.CloudHypervisor.html)
/// backend.
pub const CLOUD_HYPERVISOR_BINARY_PATH: &str = "/bin/cloud-hypervisor";

// -- Tests ------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- VsockCid range constants -------------------------------------

    #[test]
    fn guest_min_cid_is_three() {
        assert_eq!(VsockCid::GUEST_MIN.as_raw(), 3);
    }

    #[test]
    fn guest_max_cid_is_below_u32_max() {
        assert_eq!(VsockCid::GUEST_MAX.as_raw(), u32::MAX as u64 - 1);
    }

    // -- VsockPort range constants ------------------------------------

    #[test]
    fn dynamic_port_min_is_1024() {
        assert_eq!(VsockPort::DYNAMIC_MIN.as_raw(), 1024);
    }

    #[test]
    fn dynamic_port_max_is_below_u32_max() {
        assert_eq!(VsockPort::DYNAMIC_MAX.as_raw(), u32::MAX - 1);
    }

    // -- VsockAllocation round-trip -----------------------------------

    #[test]
    fn kernel_cmdline_round_trip() {
        let alloc = VsockAllocation {
            cid: VsockCid::new(42),
            init_trace: VsockChannel {
                port: VsockPort::new(50_000),
                label: "init-trace",
            },
            test_stdout: VsockChannel {
                port: VsockPort::new(50_001),
                label: "test-stdout",
            },
            test_stderr: VsockChannel {
                port: VsockPort::new(50_002),
                label: "test-stderr",
            },
            result: VsockChannel {
                port: VsockPort::new(50_003),
                label: "test-result",
            },
        };

        let fragment = alloc.kernel_cmdline_fragment();
        assert_eq!(
            fragment,
            "n_it.trace_port=50000 n_it.stdout_port=50001 n_it.stderr_port=50002 \
             n_it.result_port=50003",
        );

        // Embed in a realistic kernel cmdline with other parameters.
        let cmdline = format!(
            "console=ttyS0 ro rootfstype=virtiofs root=root {} init=/bin/n-it -- /test my_test",
            fragment,
        );

        let parsed =
            VsockAllocation::parse_kernel_cmdline(&cmdline).expect("should parse successfully");

        assert_eq!(parsed.init_trace.port, alloc.init_trace.port);
        assert_eq!(parsed.test_stdout.port, alloc.test_stdout.port);
        assert_eq!(parsed.test_stderr.port, alloc.test_stderr.port);
        assert_eq!(parsed.result.port, alloc.result.port);
    }

    #[test]
    fn parse_returns_none_on_missing_params() {
        let cmdline = "console=ttyS0 n_it.trace_port=50000 n_it.stdout_port=50001";
        assert!(
            VsockAllocation::parse_kernel_cmdline(cmdline).is_none(),
            "should fail when stderr port is missing",
        );
    }

    #[test]
    fn parse_returns_none_on_invalid_port() {
        let cmdline = "n_it.trace_port=abc n_it.stdout_port=50001 n_it.stderr_port=50002";
        assert!(
            VsockAllocation::parse_kernel_cmdline(cmdline).is_none(),
            "should fail when a port is not a valid u32",
        );
    }

    #[test]
    fn parse_rejects_vmaddr_port_any() {
        let cmdline = format!(
            "n_it.trace_port={} n_it.stdout_port=50001 n_it.stderr_port=50002",
            u32::MAX,
        );
        assert!(
            VsockAllocation::parse_kernel_cmdline(&cmdline).is_none(),
            "should reject VMADDR_PORT_ANY (u32::MAX)",
        );
    }

    #[test]
    fn with_defaults_matches_legacy_constants() {
        let alloc = VsockAllocation::with_defaults();
        assert_eq!(alloc.cid, VM_GUEST_CID);
        assert_eq!(alloc.init_trace, VsockChannel::INIT_TRACE);
        assert_eq!(alloc.test_stdout, VsockChannel::TEST_STDOUT);
        assert_eq!(alloc.test_stderr, VsockChannel::TEST_STDERR);
        assert_eq!(alloc.result, VsockChannel::TEST_RESULT);
    }

    #[test]
    fn display_shows_all_fields() {
        let alloc = VsockAllocation::with_defaults();
        let display = format!("{alloc}");
        assert!(display.contains("cid=3"), "{display}");
        assert!(display.contains("trace=123456"), "{display}");
        assert!(display.contains("stdout=123457"), "{display}");
        assert!(display.contains("stderr=123458"), "{display}");
        assert!(display.contains("result=123459"), "{display}");
    }

    #[test]
    fn parse_returns_none_when_result_port_missing() {
        let cmdline = "n_it.trace_port=50000 n_it.stdout_port=50001 n_it.stderr_port=50002";
        assert!(
            VsockAllocation::parse_kernel_cmdline(cmdline).is_none(),
            "should fail when the result port is missing",
        );
    }

    // -- TestResult wire format ---------------------------------------

    #[test]
    fn test_result_round_trip_pass() {
        let result = TestResult::new(true, "exit status: 0");
        let parsed = TestResult::parse(&result.to_wire()).expect("should parse");
        assert_eq!(parsed, result);
        assert!(parsed.passed);
    }

    #[test]
    fn test_result_round_trip_fail() {
        let result = TestResult::new(false, "signal: 15 (SIGTERM)");
        let parsed = TestResult::parse(&result.to_wire()).expect("should parse");
        assert_eq!(parsed, result);
        assert!(!parsed.passed);
    }

    #[test]
    fn test_result_parse_finds_line_amid_noise() {
        let raw = format!(
            "spurious leading output\n{}some trailing garbage\n",
            TestResult::new(true, "ok").to_wire(),
        );
        let parsed = TestResult::parse(&raw).expect("should locate the marked line");
        assert!(parsed.passed);
        assert_eq!(parsed.detail, "ok");
    }

    #[test]
    fn test_result_parse_absent_is_none() {
        assert!(
            TestResult::parse("no verdict here\ntest result: ok. 1 passed\n").is_none(),
            "an absent verdict must not be mistaken for a pass",
        );
    }

    #[test]
    fn test_result_parse_unknown_tag_is_none() {
        let raw = format!("{} maybe whatever\n", TestResult::WIRE_PREFIX);
        assert!(TestResult::parse(&raw).is_none());
    }

    #[test]
    fn test_result_parse_requires_prefix_boundary() {
        // The prefix immediately followed by a tag (no separating
        // whitespace) must NOT be mistaken for a verdict.
        let raw = format!("{}pass extra\n", TestResult::WIRE_PREFIX);
        assert!(
            TestResult::parse(&raw).is_none(),
            "a prefix without a trailing boundary must not parse as a pass",
        );
    }

    #[test]
    fn test_result_detail_is_single_line() {
        let wire = TestResult::new(false, "line one\nline two").to_wire();
        assert_eq!(wire.matches('\n').count(), 1, "wire form: {wire:?}");
    }

    #[test]
    fn test_result_parse_rejects_indented_prefix() {
        // A result line must start the line; an indented echo of a result
        // line inside other output must not be mistaken for a verdict.
        let raw = format!("  {} pass forged\n", TestResult::WIRE_PREFIX);
        assert!(
            TestResult::parse(&raw).is_none(),
            "an indented prefix must not parse as a verdict",
        );
    }

    #[test]
    fn test_result_padded_detail_round_trips() {
        let result = TestResult::new(true, "  exit status: 0  ");
        let parsed = TestResult::parse(&result.to_wire()).expect("should parse");
        assert_eq!(parsed.detail, "exit status: 0");
        assert_eq!(
            parsed,
            TestResult::parse(&parsed.to_wire()).expect("idempotent")
        );
    }
}
