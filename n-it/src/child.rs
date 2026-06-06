//! Process lifecycle management for the init system.
//!
//! This module handles spawning the test binary, reaping orphaned processes,
//! forwarding signals, and gracefully terminating remaining children during
//! shutdown.

use std::io::Write;
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::process::Stdio;

use n_vm_protocol::{ENV_IN_VM, ENV_MARKER_VALUE, TestResult};
use nix::errno::Errno;
use nix::sys::signal::{Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;
use tokio::process::{Child, Command};
use tokio::time::{Duration, sleep};
use tokio_vsock::VMADDR_CID_HOST;
use tracing::{debug, error, trace, warn};

use crate::error::{
    BroadcastSignalError, BroadcastSignalOutcome, ListChildrenError, ReapOutcome, SpawnError,
    TerminateOutcome,
};

/// Converts a [`vsock::VsockStream`] into a [`Stdio`] handle by
/// transferring ownership of the underlying file descriptor.
///
/// This encapsulates the only `unsafe` operation in this module into a
/// safe abstraction, per the project's [unsafe code guidelines].
///
/// [unsafe code guidelines]: ../../development/code/unsafe-code.md
fn vsock_stream_to_stdio(stream: vsock::VsockStream) -> Stdio {
    // SAFETY: `VsockStream::into_raw_fd()` returns a valid, owned file
    // descriptor.  `Stdio::from_raw_fd()` takes ownership of it.  The
    // fd is not used after this point.
    unsafe { Stdio::from_raw_fd(stream.into_raw_fd()) }
}

/// Spawns the test binary as the main child process.
///
/// Reads the binary path and test name from the kernel command line
/// arguments (passed via `init=`), sets `IN_VM=YES` so the `#[in_vm]`
/// macro executes the test body directly, and redirects stdout/stderr to
/// dedicated vsock streams ([`VsockChannel::TEST_STDOUT`] and
/// [`VsockChannel::TEST_STDERR`]).
///
/// The container tier must have already bound Unix listeners at the
/// corresponding vsock listener paths before the VM booted, so these
/// connections succeed immediately.
///
/// # Errors
///
/// Returns a [`SpawnError`] if:
/// - No test binary was specified on the command line.
/// - A vsock connection for stdout or stderr cannot be established.
/// - The child process fails to spawn.
/// - The child exits before its PID can be read.
pub async fn spawn_main_process() -> Result<Child, SpawnError> {
    debug!("spawning main process");

    let mut args = std::env::args();
    if args.len() < 2 {
        return Err(SpawnError::NoMainProcess);
    }

    args.next().expect("argv[0] missing"); // skip self

    // Connect vsock streams for stdout and stderr.  The container tier
    // has already bound listeners at the dynamically-allocated ports, so
    // these connections succeed immediately.
    let alloc = crate::vsock_allocation();

    let stdout_addr = vsock::VsockAddr::new(VMADDR_CID_HOST, alloc.test_stdout.port.as_raw());
    let stdout_stream =
        vsock::VsockStream::connect(&stdout_addr).map_err(|e| SpawnError::VsockConnect {
            channel: alloc.test_stdout,
            source: e,
        })?;

    let stderr_addr = vsock::VsockAddr::new(VMADDR_CID_HOST, alloc.test_stderr.port.as_raw());
    let stderr_stream =
        vsock::VsockStream::connect(&stderr_addr).map_err(|e| SpawnError::VsockConnect {
            channel: alloc.test_stderr,
            source: e,
        })?;

    let stdout_stdio = vsock_stream_to_stdio(stdout_stream);
    let stderr_stdio = vsock_stream_to_stdio(stderr_stream);

    let child = Command::new(
        args.next()
            .expect("argv[1] missing: no test binary specified"),
    )
    .args(args)
    .kill_on_drop(true)
    .stdin(Stdio::inherit())
    .stdout(stdout_stdio)
    .stderr(stderr_stdio)
    .env(ENV_IN_VM, ENV_MARKER_VALUE)
    .env("PATH", "/bin")
    .env("LD_LIBRARY_PATH", "/lib")
    .env("RUST_BACKTRACE", "1")
    .spawn()?;

    if let Some(pid) = child.id() {
        debug!("main process spawned with PID: {pid}");
    } else {
        return Err(SpawnError::NoPid);
    }
    Ok(child)
}

/// Reports the structured test verdict to the host over the result vsock
/// channel ([`VsockChannel::TEST_RESULT`]).
///
/// The container tier bound a listener on the result port before the VM
/// booted, so this connect succeeds immediately.  Dropping the stream after
/// the write closes it, signalling EOF to the host's reader.
///
/// This is **best-effort**: a failure to connect, write, or flush is logged
/// but not fatal.  The host treats a missing or unparseable verdict as a
/// test failure, so a dropped report fails safe rather than falsely passing.
pub fn report_result(result: &TestResult) {
    let channel = crate::vsock_allocation().result;
    let addr = vsock::VsockAddr::new(VMADDR_CID_HOST, channel.port.as_raw());
    let wire = result.to_wire();

    match vsock::VsockStream::connect(&addr) {
        Ok(mut stream) => {
            if let Err(e) = stream.write_all(wire.as_bytes()) {
                error!("failed to write test verdict to host on {channel}: {e}");
                return;
            }
            if let Err(e) = stream.flush() {
                error!("failed to flush test verdict to host on {channel}: {e}");
            }
        }
        Err(e) => {
            error!("failed to connect result vsock to host on {channel}: {e}");
        }
    }
}

/// Reaps all orphaned child processes via non-blocking `waitpid`.
///
/// Returns [`ReapOutcome::Clean`] if all reaped processes exited with
/// status 0, or [`ReapOutcome::LeakedProcesses`] if any process exited
/// with a non-zero status or was killed by a signal.
#[tracing::instrument(level = "debug")]
pub fn reap() -> ReapOutcome {
    let mut clean = true;
    const ANY_CHILD: Pid = Pid::from_raw(-1);
    loop {
        match waitpid(ANY_CHILD, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(pid, status)) => {
                if status != 0 {
                    warn!("orphaned process {pid} exited with status {status}");
                    clean = false;
                }
            }
            Ok(WaitStatus::Signaled(pid, signal, _)) => {
                warn!("orphaned process {pid} killed by signal {signal}");
                clean = false;
            }
            Ok(WaitStatus::StillAlive) => {
                break;
            }
            Ok(status) => {
                debug!("unexpected waitpid status in init: {status:?}");
                clean = false;
                continue;
            }
            Err(e) => {
                warn!("unexpected errno from waitpid in init: {e}");
                break;
            }
        }
    }
    if clean {
        ReapOutcome::Clean
    } else {
        ReapOutcome::LeakedProcesses
    }
}

/// Sends a signal to all processes except init (PID 1).
///
/// Uses `kill(-1, signal)` which targets every process the caller has
/// permission to signal.  Returns [`BroadcastSignalOutcome::Delivered`]
/// if at least one process received the signal, or
/// [`BroadcastSignalOutcome::NoProcesses`] if no processes were found
/// (`ESRCH`).
///
/// # Errors
///
/// Returns a [`BroadcastSignalError`] on `EPERM` or unexpected errors,
/// since an init system that cannot signal its children is in an
/// unrecoverable state.
#[tracing::instrument(level = "info")]
pub fn send_signal_to_all_processes(
    signal: Signal,
) -> Result<BroadcastSignalOutcome, BroadcastSignalError> {
    // Using PID -1 means "all processes that the calling process has
    // permission to send signals to".
    match kill(Pid::from_raw(-1), signal) {
        Ok(()) => {
            trace!("successfully sent {signal:?} to all processes");
            Ok(BroadcastSignalOutcome::Delivered)
        }
        Err(Errno::ESRCH) => {
            // No processes found -- this can happen if we're the only
            // process left.
            trace!("no processes found to send {signal:?} to");
            Ok(BroadcastSignalOutcome::NoProcesses)
        }
        Err(Errno::EPERM) => Err(BroadcastSignalError::PermissionDenied { signal }),
        Err(e) => Err(BroadcastSignalError::Failed { signal, source: e }),
    }
}

/// Forwards a signal to a specific process, handling the case where the
/// process has already exited.
///
/// Unlike [`send_signal_to_all_processes`], this targets a single PID and
/// treats `ESRCH` (no such process) as a non-fatal condition -- the child
/// may have exited between the time the signal was received and the time
/// we attempt to forward it.
pub fn forward_signal(pid: Pid, sig: Signal) {
    if let Err(e) = kill(pid, sig) {
        match e {
            Errno::ESRCH => {
                debug!("cannot forward {sig:?}: process {pid} already exited");
            }
            other => {
                error!("failed to forward {sig:?} to process {pid}: {other}");
            }
        }
    }
}

/// The PID of the init process (PID 1).
///
/// Used to filter `/proc` entries when listing direct children of init,
/// and to verify that the binary is running as PID 1 in [`crate::main`].
pub const INIT_PID: u32 = 1;

/// Maximum number of SIGTERM rounds before giving up.
pub const MAX_SIGTERM_ATTEMPTS: u8 = 50;

/// Terminates all remaining child processes with SIGTERM.
///
/// Sends up to [`MAX_SIGTERM_ATTEMPTS`] rounds of SIGTERM (with 10 ms
/// sleeps between rounds), reaping exited processes after each round.
///
/// Returns a [`TerminateOutcome`] describing whether child processes
/// were found and whether they all terminated successfully.
#[tracing::instrument(level = "info")]
pub async fn terminate_remaining_processes() -> TerminateOutcome {
    match list_child_processes().await {
        Ok(children) if children.is_empty() => {
            trace!("no child processes remaining");
            return TerminateOutcome::NoneRemaining;
        }
        Ok(_) => {}
        Err(e) => {
            // If we can't even list children during shutdown, log it and
            // assume the worst -- try to terminate anyway.
            error!("failed to list child processes during shutdown: {e}");
        }
    }

    if !reap().is_clean() {
        warn!("test seems to be leaking processes");
    }

    // Send SIGTERM to all processes.
    let mut sigs: u8 = 0;
    warn!("sending SIGTERM to all remaining processes");
    loop {
        if sigs > MAX_SIGTERM_ATTEMPTS {
            break;
        }

        match send_signal_to_all_processes(Signal::SIGTERM) {
            Ok(BroadcastSignalOutcome::NoProcesses) => {
                debug!("no more processes to signal");
                break;
            }
            Ok(BroadcastSignalOutcome::Delivered) => {}
            Err(e) => {
                // Permission denied or unexpected error from PID 1 is
                // genuinely unrecoverable.
                fatal!("unrecoverable error during shutdown signal broadcast: {e}");
            }
        }

        sigs += 1;
        sleep(Duration::from_millis(10)).await;

        if !reap().is_clean() {
            error!("test is leaking processes");
        }

        match list_child_processes().await {
            Ok(children) if children.is_empty() => {
                debug!("all child processes terminated after {sigs} SIGTERM round(s)");
                return TerminateOutcome::Terminated;
            }
            Ok(_) => {}
            Err(e) => {
                error!("failed to list child processes during termination: {e}");
            }
        }
    }

    error!("maximum SIGTERM attempts reached: test did not shut down correctly");
    TerminateOutcome::ExhaustedRetries
}

/// Lists all direct child processes of init (PPID == 1) by scanning `/proc`.
///
/// # Errors
///
/// Returns a [`ListChildrenError`] if `/proc` cannot be read or a child
/// PID overflows `i32`.
pub async fn list_child_processes() -> Result<Vec<Pid>, ListChildrenError> {
    let mut child_pids = tokio::fs::read_dir("/proc")
        .await
        .map_err(ListChildrenError::ReadDir)?;
    let mut children = vec![];
    while let Some(process) = child_pids
        .next_entry()
        .await
        .map_err(ListChildrenError::ReadEntry)?
    {
        let name = process.file_name();
        let Ok(pid) = name.to_string_lossy().parse::<u32>() else {
            // Non-numeric entries (e.g. /proc/self, /proc/net) are expected
            // and silently skipped.
            continue;
        };
        let stat = tokio::fs::read_to_string(format!("/proc/{pid}/stat")).await;
        let Ok(stat) = stat else {
            // The process may have exited between readdir and this read.
            trace!("could not read /proc/{pid}/stat (process likely exited)");
            continue;
        };
        let Some(ppid_str) = stat.split_whitespace().nth(3) else {
            trace!("/proc/{pid}/stat has unexpected format (missing field 3)");
            continue;
        };
        let Ok(ppid) = ppid_str.parse::<u32>() else {
            trace!("/proc/{pid}/stat field 3 is not a valid u32: {ppid_str:?}");
            continue;
        };
        if ppid == INIT_PID {
            let pid_i32 = i32::try_from(pid).map_err(|_| ListChildrenError::PidOverflow { pid })?;
            children.push(Pid::from_raw(pid_i32));
        }
    }
    Ok(children)
}
