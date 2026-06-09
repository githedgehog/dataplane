//! Init system orchestrator.
//!
//! This module ties together the [`mount`](crate::mount),
//! [`child`](crate::child), and [`signal`](crate::signal) subsystems
//! into the main init system lifecycle:
//!
//! 1. Register signal handlers ([`SignalSet`](crate::signal::SignalSet)).
//! 2. Mount essential filesystems.
//! 3. Spawn the test process.
//! 4. Enter the event loop -- forward signals and wait for exit.
//! 5. Shut down cleanly (terminate children, unmount, power off / abort).
//!
//! Each phase delegates to a focused module, so the orchestrator itself
//! requires only local reasoning about sequencing.
//!
//! **Error handling boundary**: the subsystem modules return typed
//! [`Result`] values and outcome enums.  This orchestrator is the
//! outermost boundary where unrecoverable errors are converted to
//! [`fatal!`] calls (which flush I/O and abort the process).

use std::convert::Infallible;

use n_vm_protocol::TestResult;
use nix::sys::reboot::{RebootMode, reboot};
use nix::unistd::Pid;
use tracing::{debug, error, info};

use crate::child;
use crate::error::TerminateOutcome;
use crate::mount;
use crate::signal::{SIGNAL_TABLE, SignalPolicy, SignalSet};

/// Minimal init system for running tests inside a cloud-hypervisor VM.
///
/// This unit struct groups the top-level orchestration methods.  It is
/// intended to run as PID 1 and delegates filesystem mounting, process
/// lifecycle management, signal forwarding, and clean shutdown to the
/// [`mount`], [`child`], and [`signal`] modules.
#[derive(Debug)]
#[non_exhaustive]
pub struct InitSystem;

impl InitSystem {
    /// Main entry point for the init system.
    ///
    /// Registers signal handlers, mounts filesystems, spawns the test
    /// process, and enters the main event loop.  The event loop forwards
    /// signals to the test process and waits for it to exit, then
    /// initiates shutdown.
    ///
    /// This function never returns (its return type is [`Infallible`]).
    #[tracing::instrument(level = "info")]
    pub async fn run() -> Infallible {
        info!("starting init system");

        debug!("registering signal handlers");
        let mut signals = SignalSet::register(SIGNAL_TABLE);
        debug!("signal handlers registered");

        match tokio::task::spawn_blocking(mount::mount_essential_filesystems).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => fatal!("filesystem setup failed: {e}"),
            Err(e) => fatal!("mount filesystem task panicked: {e}"),
        }

        let mut test_child = match child::spawn_main_process().await {
            Ok(child) => child,
            Err(e) => fatal!("failed to start test process: {e}"),
        };
        let pid = match test_child.id() {
            Some(id) => {
                let id =
                    i32::try_from(id).unwrap_or_else(|_| fatal!("child PID {id} overflows i32"));
                Pid::from_raw(id)
            }
            None => fatal!("unable to determine PID of spawned test process"),
        };

        // `success` may be downgraded by a failure-policy signal while we
        // wait; `outcome` is bound from the break value, which is only
        // reached when the test process exits (the sole break path).
        let mut success = true;

        let outcome = loop {
            tokio::select! {
                result = test_child.wait() => {
                    break match result {
                        Ok(status) if status.success() => {
                            debug!("main process exited successfully with status {status}");
                            format!("test process {status}")
                        }
                        Ok(status) => {
                            error!("main process exited with failure status {status}");
                            success = false;
                            format!("test process {status}")
                        }
                        Err(e) => {
                            error!("main process error: {e}");
                            success = false;
                            format!("error waiting on test process: {e}")
                        }
                    };
                }
                spec = signals.recv() => {
                    match spec.policy {
                        SignalPolicy::Failure => {
                            debug!("received failure signal {}, forwarding and marking failed", spec.label);
                            success = false;
                        }
                        SignalPolicy::Benign => {
                            debug!("forwarding benign signal {}", spec.label);
                        }
                    }
                    child::forward_signal(pid, spec.signal);
                }
            }
        };

        Self::shutdown_system(success, outcome).await
    }

    /// Performs a clean system shutdown.
    ///
    /// 1. Terminates any remaining child processes (leaked processes
    ///    downgrade the verdict to a failure).
    /// 2. Reports the structured pass/fail verdict to the host over the
    ///    result vsock channel.
    /// 3. Unmounts all filesystems and powers off via `reboot(RB_POWER_OFF)`.
    ///
    /// Unlike a conventional init, this *always* powers off cleanly: the
    /// pass/fail signal is carried by the verdict reported in step 2, not by
    /// crashing the guest.  [`fatal!`] (which aborts and surfaces as a guest
    /// panic) is reserved for `n-it`'s own unrecoverable errors -- in those
    /// cases the host sees a missing verdict plus a panic and fails the test.
    ///
    /// This function never returns (its return type is [`Infallible`]).
    #[tracing::instrument(level = "info")]
    async fn shutdown_system(success: bool, outcome: String) -> Infallible {
        info!("beginning system shutdown");

        // Terminate all child processes; leaked processes downgrade success.
        let terminate_outcome = child::terminate_remaining_processes().await;
        let leaked = !terminate_outcome.is_clean();
        let success = !leaked && success;

        if matches!(terminate_outcome, TerminateOutcome::ExhaustedRetries) {
            error!("some child processes could not be terminated");
        }

        let detail = if leaked {
            format!("{outcome}; leaked child processes during shutdown")
        } else {
            outcome
        };

        // Report the verdict to the host before tearing anything down.  This
        // is best-effort: if it fails, the host observes a missing verdict,
        // which it treats as a failure -- the safe default.
        child::report_result(&TestResult::new(success, detail));

        // Final sync, unmount, and power off.
        match tokio::task::spawn_blocking(move || {
            if let Err(e) = mount::unmount_filesystems() {
                fatal!("failed to unmount filesystems: {e}");
            }
            info!(
                "powering off (test {})",
                if success { "passed" } else { "failed" }
            );
            match reboot(RebootMode::RB_POWER_OFF) {
                Ok(_) => unreachable!(),
                Err(e) => {
                    fatal!("failed to power off: {e}");
                }
            }
        })
        .await
        {
            Ok(_) => {
                // Normally unreachable -- the blocking task either powers off
                // or aborts.  Use fatal! to ensure stdio is flushed.
                fatal!("shutdown task returned unexpectedly");
            }
            Err(err) => {
                fatal!("failed to shutdown system: {err}");
            }
        }
    }
}
