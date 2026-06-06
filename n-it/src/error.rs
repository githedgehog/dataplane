//! Dedicated error types for the `n-it` init system subsystems.
//!
//! Each subsystem ([`mount`](crate::mount), [`child`](crate::child))
//! defines its own error type here so that failure modes are explicit in
//! function signatures rather than hidden behind [`fatal!`] or
//! [`Option<()>`].
//!
//! The orchestrator ([`crate::init::InitSystem`]) is responsible for
//! deciding how to handle each error -- typically by logging context and
//! aborting via [`fatal!`].

use std::path::Path;

use n_vm_protocol::VsockChannel;
use nix::errno::Errno;
use nix::sys::signal::Signal;

/// An error that occurred while mounting an essential filesystem.
#[derive(Debug, thiserror::Error)]
pub enum MountError {
    /// The kernel returned `EPERM` -- the init process lacks the required
    /// capability (should never happen for PID 1 in a normal VM).
    #[error("permission denied while mounting {}", .target.display())]
    PermissionDenied {
        /// The mount point path that failed.
        target: &'static Path,
    },

    /// The kernel returned an unrecognised errno during mount.
    #[error("unknown error while mounting {}", .target.display())]
    Unknown {
        /// The mount point path that failed.
        target: &'static Path,
    },

    /// A mount syscall failed with a specific errno.
    #[error("failed to mount {}: {source}", .target.display())]
    Failed {
        /// The mount point path that failed.
        target: &'static Path,
        /// The underlying errno.
        source: Errno,
    },
}

/// An error that occurred while unmounting filesystems during shutdown.
#[derive(Debug, thiserror::Error)]
pub enum UnmountError {
    /// The mount point remained busy after exhausting all retry attempts.
    #[error(
        "{} still busy after {attempts} retries; \
         a leaked process is likely holding a file descriptor open",
        .target.display()
    )]
    BusyExhausted {
        /// The mount point path that could not be unmounted.
        target: &'static Path,
        /// The number of retry attempts made.
        attempts: u32,
    },

    /// The mount point was not actually mounted, or the path is invalid.
    #[error("{} not mounted or invalid", .target.display())]
    NotMounted {
        /// The mount point path.
        target: &'static Path,
    },

    /// An unexpected errno was returned by `umount2`.
    #[error("failed to unmount {}: {source}", .target.display())]
    Failed {
        /// The mount point path that failed.
        target: &'static Path,
        /// The underlying errno.
        source: Errno,
    },
}

/// An error that occurred while spawning the main test process.
#[derive(Debug, thiserror::Error)]
pub enum SpawnError {
    /// No test binary was specified on the kernel command line.
    #[error("no main process specified to init process (expected argv[1])")]
    NoMainProcess,

    /// Failed to connect a vsock stream for child I/O redirection.
    #[error("failed to connect {channel} vsock: {source}")]
    VsockConnect {
        /// The vsock channel that could not be connected.
        channel: VsockChannel,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// The `Command::spawn` call failed.
    #[error("failed to spawn test process: {0}")]
    Spawn(#[from] std::io::Error),

    /// The spawned child exited before we could read its PID.
    #[error("unable to determine PID of spawned test process")]
    NoPid,
}

/// Outcome of reaping orphaned child processes via `waitpid`.
///
/// This replaces the previous `Option<()>` return where `Some(())`
/// meant failure -- a pattern the project guidelines explicitly
/// discourage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReapOutcome {
    /// All reaped processes (if any) exited cleanly with status 0.
    Clean,
    /// At least one reaped process exited with a non-zero status or was
    /// killed by a signal.  This typically indicates the test leaked
    /// child processes.
    LeakedProcesses,
}

impl ReapOutcome {
    /// Returns `true` if all reaped processes exited cleanly.
    #[must_use]
    pub fn is_clean(self) -> bool {
        matches!(self, Self::Clean)
    }
}

/// Outcome of sending a signal to all non-init processes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcastSignalOutcome {
    /// At least one process received the signal.
    Delivered,
    /// No processes were found to signal (`ESRCH`).
    NoProcesses,
}

/// An unrecoverable error when broadcasting a signal.
///
/// `EPERM` from an init system is genuinely fatal -- if PID 1 cannot
/// signal its children the system is in an unrecoverable state.
#[derive(Debug, thiserror::Error)]
pub enum BroadcastSignalError {
    /// The init process was denied permission to signal its children.
    #[error("permission denied when sending {signal:?} to all processes")]
    PermissionDenied {
        /// The signal that could not be delivered.
        signal: Signal,
    },

    /// An unexpected errno was returned by `kill(-1, signal)`.
    #[error("failed to send {signal:?} to all processes: {source}")]
    Failed {
        /// The signal that could not be delivered.
        signal: Signal,
        /// The underlying errno.
        source: Errno,
    },
}

/// Outcome of attempting to terminate all remaining child processes
/// during shutdown.
///
/// This replaces the previous `Option<()>` return type with an explicit
/// three-state enum so callers can distinguish "nothing to do" from
/// "cleaned up" from "gave up."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminateOutcome {
    /// No child processes were remaining at the time of the call.
    NoneRemaining,
    /// Child processes were found and all terminated successfully.
    Terminated,
    /// SIGTERM was sent [`MAX_SIGTERM_ATTEMPTS`](crate::child::MAX_SIGTERM_ATTEMPTS)
    /// times but some processes still did not exit.
    ExhaustedRetries,
}

impl TerminateOutcome {
    /// Returns `true` if no child processes were remaining (the happy path).
    #[must_use]
    pub fn is_clean(self) -> bool {
        matches!(self, Self::NoneRemaining)
    }
}

/// An error encountered while listing child processes from `/proc`.
#[derive(Debug, thiserror::Error)]
pub enum ListChildrenError {
    /// Failed to open `/proc` for reading.
    #[error("failed to read /proc: {0}")]
    ReadDir(std::io::Error),

    /// Failed to read an individual `/proc` directory entry.
    #[error("failed to read /proc entry: {0}")]
    ReadEntry(std::io::Error),

    /// A child PID value overflows `i32` (required by [`Pid::from_raw`]).
    #[error("child pid {pid} overflows i32")]
    PidOverflow {
        /// The PID value that overflowed.
        pid: u32,
    },
}
