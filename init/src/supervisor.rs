// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Supervision of the processes that make up a running gateway.
//!
//! A gateway is not one program. The dataplane forwards packets, FRR decides where they should go,
//! and `frr-agent` carries configuration between them. They share a network namespace, a set of
//! unix sockets and a fate, and something has to hold that arrangement together.
//!
//! # Why not `exec`
//!
//! `dataplane-init` used to prepare the hardware and then `exec` the dataplane, which is the right
//! shape when there is exactly one process to run and nothing to decide afterwards. It stops being
//! the right shape as soon as a second process has to start in the same namespaces, because
//! namespaces are inherited at `fork` and there is nobody left to fork from.
//!
//! Staying resident buys three things that were not previously expressible:
//!
//! 1. **Order.** Nothing outside this process can sequence the startup: a container runtime starts
//!    containers, not programs, and Kubernetes will not order two containers in a pod. Here, zebra
//!    can be made to wait for the dataplane's CPI socket instead of racing it.
//! 2. **Shared fate.** See below.
//! 3. **A namespace that outlives its user.** The datapath network namespace is held by a
//!    descriptor this process owns. Under `exec` the dataplane held it, so a dataplane that died
//!    took the namespace with it -- and recreating it means moving the NICs back out and in again,
//!    which on mlx5 costs a devlink reload, a link flap and a new ifindex.
//!
//! # Shared fate, deliberately
//!
//! Every supervised process is fatal: when one exits, for any reason and with any status, the rest
//! are brought down and this process exits too. Nothing is restarted in place.
//!
//! That is a stronger coupling than running FRR in its own container, and it is the point. FRR's
//! own `watchfrr` restarts individual daemons in place, and a restarted zebra meets the nexthops
//! its predecessor installed and refuses to reuse them -- which is why the gateway's FRR entrypoint
//! has to sweep them by hand before starting. That sweep cannot be deleted while a daemon can be
//! replaced underneath a surviving namespace. Make the namespace die with the daemon and the
//! problem does not arise: the kernel state goes when the namespace does.
//!
//! The cost is honest and worth stating: a bug in `bgpd` now restarts the datapath, where before it
//! would have crash-looped beside a dataplane that kept forwarding on the last FIB it was given.
//! Forwarding on a FIB whose author has died is its own kind of wrong, and the orchestrator above
//! us is the layer that knows whether restarting is better than continuing.
//!
//! # Reaping
//!
//! As PID 1 this process inherits every orphan in the container, so it must reap or the container
//! fills with zombies. That is why children are spawned through [`std::process::Command`] and
//! waited on here rather than through `tokio::process`: `tokio::process` reaps only the children it
//! knows about, and a `waitpid(-1)` loop running beside it would race it for their statuses. One
//! loop owns `waitpid` and dispatches by pid.

use std::io;
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use nix::errno::Errno;
use nix::sys::signal::{Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{self, Pid};
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::{Instant, sleep};
use tracing::{debug, error, info, warn};

/// How long a process is given to respond to `SIGTERM` before it is killed.
///
/// Matched to the ten seconds a container runtime allows between `SIGTERM` and `SIGKILL`, less a
/// margin to finish reaping and exit before the runtime loses patience with us as well.
const GRACE: Duration = Duration::from_secs(8);

/// How often a readiness condition is re-checked.
///
/// Short enough that startup is not visibly delayed, long enough not to spin.
const READY_POLL: Duration = Duration::from_millis(25);

/// Anything that can go wrong starting or supervising a process.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SupervisorError {
    /// The process could not be started at all.
    #[error("could not start {name}: {source}")]
    Spawn {
        /// The name this supervisor knows the process by.
        name: String,
        /// Why the spawn failed.
        #[source]
        source: io::Error,
    },

    /// The process started and then exited before it was ready to be depended on.
    #[error("{name} exited before it was ready ({report})")]
    DiedDuringStartup {
        /// The name this supervisor knows the process by.
        name: String,
        /// How it ended.
        report: Ended,
    },

    /// The process was still running but never met its readiness condition.
    #[error("{name} did not become ready within {}s: {condition}", timeout.as_secs())]
    NeverReady {
        /// The name this supervisor knows the process by.
        name: String,
        /// What was being waited for.
        condition: Ready,
        /// How long it was waited for.
        timeout: Duration,
    },

    /// A signal handler could not be installed, so shutdown could not be made to work.
    #[error("could not listen for {signal}: {source}")]
    SignalHandler {
        /// The signal whose handler could not be installed.
        signal: &'static str,
        /// Why the handler could not be installed.
        #[source]
        source: io::Error,
    },

    /// `waitpid` failed for a reason other than "no children left".
    #[error("could not wait for child processes: {0}")]
    Wait(#[source] Errno),
}

/// How a process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    /// It returned this status from `main`.
    Code(i32),
    /// It was killed by this signal.
    Killed(Signal),
}

impl std::fmt::Display for Ended {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ended::Code(0) => write!(f, "exited cleanly"),
            Ended::Code(code) => write!(f, "exited with status {code}"),
            Ended::Killed(signal) => write!(f, "killed by {signal}"),
        }
    }
}

impl Ended {
    /// The status this process should exit with, having seen a child end this way.
    ///
    /// A child killed by a signal is reported the way a shell reports it, as `128 + signal`, so
    /// that an orchestrator reading our exit status can tell a crash from a clean stop.
    #[must_use]
    pub fn as_exit_code(self) -> i32 {
        match self {
            Ended::Code(code) => code,
            Ended::Killed(signal) => 128 + signal as i32,
        }
    }
}

/// What has to be true before the next process is started.
///
/// Startup order only matters where one process will fail without another, and it always fails the
/// same way: something connects to a socket that is not there yet. So the conditions here are about
/// the artifacts a dependant looks for, not about a process reporting itself healthy -- a process
/// that has opened its socket is ready in the only sense a dependant can observe.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ready {
    /// Start the next process as soon as this one has been spawned.
    Immediately,
    /// Wait for this path to exist, which for a unix socket means it can be connected to.
    Path(PathBuf),
}

impl std::fmt::Display for Ready {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ready::Immediately => write!(f, "nothing to wait for"),
            Ready::Path(path) => write!(f, "waiting for {} to exist", path.display()),
        }
    }
}

/// A process to run, and what it means for it to have started.
#[derive(Debug)]
pub struct Process {
    /// What to call it in logs. Not the executable path: several FRR daemons share a directory and
    /// an operator reading a shutdown log wants to know which one went first.
    pub name: String,
    /// How to start it.
    pub command: Command,
    /// What the next process may wait for.
    pub ready: Ready,
    /// How long to allow for [`Process::ready`] before giving up.
    pub ready_timeout: Duration,
}

impl Process {
    /// A process with no readiness condition, started and immediately depended upon.
    pub fn new(name: impl Into<String>, command: Command) -> Self {
        Self {
            name: name.into(),
            command,
            ready: Ready::Immediately,
            ready_timeout: Duration::from_secs(30),
        }
    }

    /// Wait for `path` to exist before considering this process started.
    #[must_use]
    pub fn ready_when_path_exists(mut self, path: impl Into<PathBuf>) -> Self {
        self.ready = Ready::Path(path.into());
        self
    }
}

/// Why supervision ended.
#[derive(Debug)]
pub enum Outcome {
    /// A supervised process exited. Everything else has been brought down.
    Exited {
        /// Which one went first.
        name: String,
        /// How it ended.
        report: Ended,
    },
    /// A shutdown signal arrived and every process has been brought down.
    Signalled {
        /// The signal that asked us to stop.
        signal: &'static str,
    },
}

/// A process that has been started and not yet reaped.
#[derive(Debug)]
struct Running {
    name: String,
    pid: Pid,
}

/// Runs the processes a gateway is made of, and takes them all down together.
#[derive(Debug, Default)]
pub struct Supervisor {
    /// In start order, so shutdown can run in reverse.
    running: Vec<Running>,
}

impl Supervisor {
    /// A supervisor with nothing to supervise.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a process and wait for it to be ready.
    ///
    /// Returns once the process is running *and* its readiness condition holds, so a caller can
    /// start dependants immediately afterwards without a sleep and without a retry loop in the
    /// dependant.
    ///
    /// # Errors
    ///
    /// Returns [`SupervisorError::Spawn`] if the process could not be started,
    /// [`SupervisorError::DiedDuringStartup`] if it exited while we waited, and
    /// [`SupervisorError::NeverReady`] if it stayed alive without meeting its condition.
    pub async fn start(&mut self, mut process: Process) -> Result<(), SupervisorError> {
        // Its own process group, so shutdown can signal the whole tree rather than just the
        // process we happen to have the pid of. FRR daemons and shell wrappers fork; signalling
        // one pid leaves the rest to be swept up by the broadcast at the end of shutdown, which is
        // a blunter instrument and runs later.
        process.command.process_group(0);

        let child = process
            .command
            .spawn()
            .map_err(|e| SupervisorError::Spawn {
                name: process.name.clone(),
                source: e,
            })?;

        // `Child` is dropped here rather than kept. std's `Child` does not reap on drop, and this
        // supervisor waits on every pid itself; holding it would only offer a second, racing way to
        // do that.
        let pid = Pid::from_raw(
            i32::try_from(child.id()).expect("a pid returned by fork always fits in an i32"),
        );
        drop(child);

        info!("started {} as pid {pid}", process.name);
        self.running.push(Running {
            name: process.name.clone(),
            pid,
        });

        self.await_ready(&process.name, pid, &process.ready, process.ready_timeout)
            .await
    }

    /// Wait until `condition` holds, the process dies, or the timeout expires.
    async fn await_ready(
        &mut self,
        name: &str,
        pid: Pid,
        condition: &Ready,
        timeout: Duration,
    ) -> Result<(), SupervisorError> {
        let Ready::Path(path) = condition else {
            return Ok(());
        };

        debug!("waiting for {name}: {condition}");
        let deadline = Instant::now() + timeout;
        loop {
            if path.exists() {
                debug!("{name} is ready ({} exists)", path.display());
                return Ok(());
            }

            // Checked every round, because a process that dies during startup would otherwise be
            // reported as a timeout -- which sends whoever reads it looking at the wrong thing,
            // and only after they have waited out the timeout to see it.
            if let Some(report) = self.reap_one(pid)? {
                return Err(SupervisorError::DiedDuringStartup {
                    name: name.to_string(),
                    report,
                });
            }

            if Instant::now() >= deadline {
                return Err(SupervisorError::NeverReady {
                    name: name.to_string(),
                    condition: condition.clone(),
                    timeout,
                });
            }
            sleep(READY_POLL).await;
        }
    }

    /// Wait for something to happen, then bring everything down.
    ///
    /// Returns when a supervised process exits or a shutdown signal arrives, having in either case
    /// already terminated whatever was still running.
    ///
    /// # Errors
    ///
    /// Returns [`SupervisorError::SignalHandler`] if the signals that mean "stop" cannot be
    /// listened for. That is fatal rather than degraded: PID 1 has no default disposition for
    /// `SIGTERM`, so a supervisor which failed to install the handler would silently ignore every
    /// request to stop and have to be killed.
    pub async fn supervise(mut self) -> Result<Outcome, SupervisorError> {
        let mut terminate =
            signal(SignalKind::terminate()).map_err(|e| SupervisorError::SignalHandler {
                signal: "SIGTERM",
                source: e,
            })?;
        let mut interrupt =
            signal(SignalKind::interrupt()).map_err(|e| SupervisorError::SignalHandler {
                signal: "SIGINT",
                source: e,
            })?;
        let mut child =
            signal(SignalKind::child()).map_err(|e| SupervisorError::SignalHandler {
                signal: "SIGCHLD",
                source: e,
            })?;

        info!("supervising {} process(es)", self.running.len());

        let outcome = loop {
            tokio::select! {
                _ = child.recv() => {
                    if let Some((name, report)) = self.reap()? {
                        error!("{name} {report}; bringing the gateway down");
                        break Outcome::Exited { name, report };
                    }
                }
                _ = terminate.recv() => break Outcome::Signalled { signal: "SIGTERM" },
                _ = interrupt.recv() => break Outcome::Signalled { signal: "SIGINT" },
            }
        };

        if let Outcome::Signalled { signal } = &outcome {
            info!("received {signal}; stopping the gateway");
        }
        self.shut_down().await?;
        Ok(outcome)
    }

    /// Reap everything that has exited, and report the first supervised process among them.
    ///
    /// Orphans are reaped and forgotten: as PID 1 we inherit processes we never started, and their
    /// deaths say nothing about whether the gateway is still working.
    fn reap(&mut self) -> Result<Option<(String, Ended)>, SupervisorError> {
        let mut first = None;
        loop {
            match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
                // Nothing more has exited, or there is nothing left to exit. Either way this
                // round is done.
                Ok(WaitStatus::StillAlive) | Err(Errno::ECHILD) => return Ok(first),
                Ok(status) => {
                    let Some((pid, report)) = interpret(status) else {
                        // Stopped or continued, not exited.
                        continue;
                    };
                    if let Some(name) = self.forget(pid) {
                        if first.is_none() {
                            first = Some((name, report));
                        } else {
                            debug!("{name} also ended ({report})");
                        }
                    } else {
                        debug!("reaped orphan pid {pid} ({report})");
                    }
                }
                // Interrupted before it could tell us anything; ask again.
                Err(Errno::EINTR) => {}
                Err(e) => return Err(SupervisorError::Wait(e)),
            }
        }
    }

    /// Reap `pid` if it has exited, without disturbing any other child.
    fn reap_one(&mut self, pid: Pid) -> Result<Option<Ended>, SupervisorError> {
        match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
            // Still running, already reaped by someone else, or interrupted before it could say.
            // In all three the caller has learned nothing and should look again.
            Ok(WaitStatus::StillAlive) | Err(Errno::ECHILD | Errno::EINTR) => Ok(None),
            Ok(status) => {
                let Some((reaped, report)) = interpret(status) else {
                    return Ok(None);
                };
                self.forget(reaped);
                Ok(Some(report))
            }
            Err(e) => Err(SupervisorError::Wait(e)),
        }
    }

    /// Drop `pid` from the running set, returning the name it was known by.
    fn forget(&mut self, pid: Pid) -> Option<String> {
        let index = self.running.iter().position(|r| r.pid == pid)?;
        Some(self.running.remove(index).name)
    }

    /// Terminate everything still running, politely and then not.
    async fn shut_down(&mut self) -> Result<(), SupervisorError> {
        // Reverse start order: a process started because another was ready is likely to be talking
        // to it, and stopping the dependant first spares the logs a round of connection errors on
        // the way out.
        for running in self.running.iter().rev() {
            debug!("sending SIGTERM to {} (pid {})", running.name, running.pid);
            signal_group(running.pid, Signal::SIGTERM);
        }

        let deadline = Instant::now() + GRACE;
        while !self.running.is_empty() && Instant::now() < deadline {
            self.reap()?;
            if self.running.is_empty() {
                break;
            }
            sleep(READY_POLL).await;
        }

        for running in &self.running {
            warn!(
                "{} (pid {}) did not stop within {}s; killing it",
                running.name,
                running.pid,
                GRACE.as_secs()
            );
            signal_group(running.pid, Signal::SIGKILL);
        }

        // Whatever is left is something we did not start: a daemon that forked out of its process
        // group, or an orphan inherited from a process that died before we could.
        //
        // Only as PID 1, and the guard is not a formality. `kill(-1, ...)` signals *every process
        // this process is permitted to signal*. As PID 1 of a container's namespace that set is
        // the container, which is exactly what should not outlive us. Anywhere else -- a unit
        // test, a developer running this by hand -- it is every process owned by the same user,
        // which is their login session. This was not hypothetical: without the guard, running the
        // tests below killed the developer's window manager and the terminal they were run from.
        //
        // A supervisor that is not PID 1 also has no orphans to sweep, because it does not
        // inherit any, so there is nothing lost by declining.
        if unistd::getpid().as_raw() == 1 {
            let _ = kill(Pid::from_raw(-1), Signal::SIGTERM);
        } else {
            debug!("not PID 1, so not sweeping for processes we did not start");
        }

        // Drain, so nothing is left unreaped when this process exits and the namespace goes.
        let deadline = Instant::now() + GRACE;
        loop {
            self.reap()?;
            match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) if Instant::now() < deadline => sleep(READY_POLL).await,
                _ => break,
            }
        }

        info!("all supervised processes have stopped");
        Ok(())
    }
}

/// Send `signal` to a whole process group, tolerating a group that has already gone.
fn signal_group(leader: Pid, signal: Signal) {
    // Negating the leader's pid addresses its process group; each child is made a group leader when
    // it is started.
    match kill(Pid::from_raw(-leader.as_raw()), signal) {
        Ok(()) | Err(Errno::ESRCH) => {}
        Err(e) => warn!("could not send {signal} to process group {leader}: {e}"),
    }
}

/// Reduce a wait status to "this pid ended, this way", or `None` if it did not end.
fn interpret(status: WaitStatus) -> Option<(Pid, Ended)> {
    match status {
        WaitStatus::Exited(pid, code) => Some((pid, Ended::Code(code))),
        WaitStatus::Signaled(pid, signal, _) => Some((pid, Ended::Killed(signal))),
        _ => None,
    }
}

/// Look up an executable that a test can rely on being present.
///
/// The container images this runs in ship busybox rather than a full userland, and the development
/// shell ships neither at a fixed path, so the tests below ask the environment instead of
/// hard-coding `/bin/sh`.
#[cfg(test)]
fn tool(name: &str) -> PathBuf {
    let path = std::env::var_os("PATH").expect("PATH is set");
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| panic!("{name} is not on PATH, and these tests need it"))
}

#[cfg(test)]
mod test {
    use super::*;

    /// A command that runs `script` under a shell.
    fn sh(script: &str) -> Command {
        let mut command = Command::new(tool("sh"));
        command.arg("-c").arg(script);
        command
    }

    #[tokio::test]
    async fn a_process_that_exits_takes_the_rest_down_with_it() {
        let mut supervisor = Supervisor::new();
        supervisor
            .start(Process::new("survivor", sh("sleep 600")))
            .await
            .expect("the survivor should start");
        supervisor
            .start(Process::new("quitter", sh("exit 3")))
            .await
            .expect("the quitter should start");

        let outcome = tokio::time::timeout(Duration::from_secs(30), supervisor.supervise())
            .await
            .expect("supervision should end promptly once a process exits")
            .expect("supervision should not fail");

        match outcome {
            Outcome::Exited { name, report } => {
                assert_eq!(name, "quitter");
                assert_eq!(report, Ended::Code(3));
                assert_eq!(report.as_exit_code(), 3);
            }
            other @ Outcome::Signalled { .. } => {
                panic!("expected the quitter to end supervision, got {other:?}")
            }
        }
    }

    #[tokio::test]
    async fn a_killed_process_is_reported_as_killed() {
        let mut supervisor = Supervisor::new();
        supervisor
            .start(Process::new("doomed", sh("kill -9 $$")))
            .await
            .expect("the doomed process should start");

        let outcome = tokio::time::timeout(Duration::from_secs(30), supervisor.supervise())
            .await
            .expect("supervision should end promptly")
            .expect("supervision should not fail");

        match outcome {
            Outcome::Exited { report, .. } => {
                assert_eq!(report, Ended::Killed(Signal::SIGKILL));
                // 128 + 9: what a shell would report, so an orchestrator can tell this from a
                // clean stop.
                assert_eq!(report.as_exit_code(), 137);
            }
            other @ Outcome::Signalled { .. } => panic!("expected a killed process, got {other:?}"),
        }
    }

    /// A path nothing else will collide with, in a directory this test owns.
    ///
    /// Hand-rolled rather than pulled from a crate: this is the only place in `dataplane-init`
    /// that wants a scratch directory, and a dependency is a poor trade for four lines.
    fn scratch_dir(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "dataplane-init-supervisor-{}-{test}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        dir
    }

    #[tokio::test]
    async fn a_dependant_waits_for_the_path_it_needs() {
        let scratch = scratch_dir("ready");
        let socket = scratch.join("cpi.sock");
        let _ = std::fs::remove_file(&socket);

        let mut supervisor = Supervisor::new();
        let started = Instant::now();
        supervisor
            .start(
                Process::new(
                    "slow-starter",
                    sh(&format!("sleep 0.3; : > {}; sleep 600", socket.display())),
                )
                .ready_when_path_exists(&socket),
            )
            .await
            .expect("the slow starter should become ready");

        // The point of the readiness gate: `start` did not return until the artifact a dependant
        // would look for was actually there.
        assert!(socket.exists(), "start returned before the socket existed");
        assert!(
            started.elapsed() >= Duration::from_millis(250),
            "start returned too early to have waited for anything"
        );

        supervisor.shut_down().await.expect("shutdown should work");
        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[tokio::test]
    async fn a_process_that_dies_while_starting_is_reported_as_such() {
        let mut supervisor = Supervisor::new();
        let error = supervisor
            .start(
                Process::new("false-start", sh("exit 7"))
                    .ready_when_path_exists("/definitely/not/a/real/socket"),
            )
            .await
            .expect_err("a process that exits during startup is an error");

        // Specifically *not* a timeout: the distinction is the whole reason the readiness loop
        // checks for death every round rather than only at the end.
        match error {
            SupervisorError::DiedDuringStartup { name, report } => {
                assert_eq!(name, "false-start");
                assert_eq!(report, Ended::Code(7));
            }
            other => panic!("expected DiedDuringStartup, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_process_that_never_becomes_ready_times_out() {
        let mut supervisor = Supervisor::new();
        let mut process = Process::new("never-ready", sh("sleep 600"))
            .ready_when_path_exists("/definitely/not/a/real/socket");
        process.ready_timeout = Duration::from_millis(200);

        let error = supervisor
            .start(process)
            .await
            .expect_err("a process that never becomes ready is an error");

        match error {
            SupervisorError::NeverReady { name, .. } => assert_eq!(name, "never-ready"),
            other => panic!("expected NeverReady, got {other:?}"),
        }

        supervisor.shut_down().await.expect("shutdown should work");
    }

    #[tokio::test]
    async fn shutdown_reaches_a_process_that_ignores_sigterm() {
        let mut supervisor = Supervisor::new();
        // `trap '' TERM` makes the shell ignore SIGTERM entirely, which is the case the SIGKILL
        // stage exists for. Without it this test would pass whether or not that stage worked.
        supervisor
            .start(Process::new("stubborn", sh("trap '' TERM; sleep 600")))
            .await
            .expect("the stubborn process should start");

        let pid = supervisor.running[0].pid;
        tokio::time::timeout(GRACE * 2, supervisor.shut_down())
            .await
            .expect("shutdown should not hang on a process that ignores SIGTERM")
            .expect("shutdown should not fail");

        // Reaped, so the pid is gone rather than a zombie.
        assert_eq!(
            waitpid(pid, Some(WaitPidFlag::WNOHANG)),
            Err(Errno::ECHILD),
            "the stubborn process should have been reaped"
        );
    }

    #[tokio::test]
    async fn an_orphan_is_reaped_without_ending_supervision() {
        let mut supervisor = Supervisor::new();
        // A grandchild that outlives its parent is reparented to us. Supervision must reap it --
        // otherwise PID 1 accumulates zombies -- without treating it as a supervised process
        // having died.
        supervisor
            .start(Process::new(
                "parent",
                sh("sh -c 'sleep 0.2; exit 0' & exit 0"),
            ))
            .await
            .expect("the parent should start");

        let outcome = tokio::time::timeout(Duration::from_secs(30), supervisor.supervise())
            .await
            .expect("supervision should end when the parent exits")
            .expect("supervision should not fail");

        match outcome {
            // The *parent* is what ends supervision. The orphan is reaped in passing.
            Outcome::Exited { name, report } => {
                assert_eq!(name, "parent");
                assert_eq!(report, Ended::Code(0));
            }
            other @ Outcome::Signalled { .. } => {
                panic!("expected the parent to end supervision, got {other:?}")
            }
        }
    }

    /// Shutdown ends by sweeping for processes it did not start, which it does with
    /// `kill(-1, SIGTERM)`. That reaches every process this one may signal -- the container, as
    /// PID 1, but the whole login session anywhere else.
    ///
    /// This test is the guard's only mechanical evidence. If it fails, the sweep has escaped the
    /// `getpid() == 1` check in [`Supervisor::shut_down`], and running this suite on a
    /// workstation will terminate the developer's desktop. It has done so before.
    #[tokio::test]
    async fn shutdown_does_not_reach_processes_we_never_started() {
        // Deliberately not given to the supervisor: it stands in for every process on the machine
        // that has nothing to do with the gateway.
        let mut bystander = sh("sleep 600").spawn().expect("the bystander should start");

        let mut supervisor = Supervisor::new();
        supervisor
            .start(Process::new("ours", sh("sleep 600")))
            .await
            .expect("our own process should start");

        tokio::time::timeout(GRACE * 2, supervisor.shut_down())
            .await
            .expect("shutdown should not hang")
            .expect("shutdown should not fail");

        assert!(
            matches!(bystander.try_wait(), Ok(None)),
            "shutdown signalled a process it did not start; as PID 1 that is the container, but \
             here it is everything this user owns"
        );

        let _ = bystander.kill();
        let _ = bystander.wait();
    }
}
