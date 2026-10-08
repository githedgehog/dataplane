// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Starts and supervises the dataplane, foreground watchfrr, and frr-agent.
//!
//! Any startup failure or unexpected exit of a supervised child is fatal to the
//! gateway. Init shuts down the remaining children and exits for Kubernetes to
//! restart it. SIGTERM and SIGINT request a normal shutdown.
//!
//! FRR manages its own daemons through watchfrr. Init supervises watchfrr itself
//! and reaps any orphans it inherits as PID 1. One waitpid loop owns child statuses
//! so it cannot race a second reaper such as `tokio::process`.

use std::io;
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use futures::FutureExt;
use nix::errno::Errno;
use nix::sys::signal::{Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{self, Pid};
use tokio::signal::unix::{Signal as SignalStream, SignalKind, signal};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use crate::socket;

/// Set to any value to make the supervisor forward `SIGUSR1` to what it supervises.
///
/// A profile-instrumented build writes its counters when it exits, and the dataplane does not
/// exit -- it runs until something kills it, and a kill loses the counters. `SIGUSR1` is the
/// conventional "dump what you have now" signal, so forwarding it gives a way to collect a
/// profile from a process that is still running.
///
/// Opt-in rather than unconditional, because **the default disposition of `SIGUSR1` is to
/// terminate**. Forwarding it to a build with no handler would kill the dataplane, which is a
/// spectacular way to turn a diagnostic into an outage. A build that can handle it says so by
/// setting this; every other build never sees the signal.
///
/// The value names the process to signal, and defaults to [`DEV_PROFILE_DUMP_DEFAULT_TARGET`]
/// when empty. It is a name rather than "everything supervised" on purpose: FRR is supervised
/// here too and reads `SIGUSR1` as "rotate your logs", so a broadcast would quietly do something
/// unrelated to a second process every time we asked for a profile.
pub const DEV_PROFILE_DUMP_ENV: &str = "DATAPLANE_DEV_PROFILE_DUMP";

/// The process [`DEV_PROFILE_DUMP_ENV`] signals when its value does not name one.
pub const DEV_PROFILE_DUMP_DEFAULT_TARGET: &str = "dataplane";

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

    /// A supervised process exited during gateway startup.
    #[error("{name} exited during gateway startup ({report})")]
    DiedDuringStartup {
        /// The name this supervisor knows the process by.
        name: String,
        /// How it ended.
        report: Ended,
    },

    /// A shutdown signal arrived during gateway startup.
    #[error("gateway startup interrupted by {signal}")]
    Interrupted {
        /// The signal that requested shutdown.
        signal: &'static str,
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

    /// A readiness socket could not be checked or had the wrong file type.
    #[error("could not check {name}'s socket {path}: {source}")]
    Socket {
        /// The process waiting to become ready.
        name: String,
        /// The expected socket path.
        path: PathBuf,
        /// Why the check failed.
        #[source]
        source: io::Error,
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
    /// Report an unexpected child exit as failure, even when the child returned zero.
    /// Signal deaths use the shell convention of `128 + signal`.
    #[must_use]
    pub fn as_exit_code(self) -> i32 {
        match self {
            Ended::Code(0) => 1,
            Ended::Code(code) => code,
            Ended::Killed(signal) => 128 + signal as i32,
        }
    }
}

/// What has to be true before the next process is started.
///
/// Socket paths must be cleared before any children start. A new socket shows that
/// the endpoint was bound; it does not establish full service health.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ready {
    /// Start the next process as soon as this one has been spawned.
    Immediately,
    /// Wait for a Unix socket at this path.
    Socket(PathBuf),
}

impl std::fmt::Display for Ready {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ready::Immediately => write!(f, "nothing to wait for"),
            Ready::Socket(path) => write!(f, "waiting for socket {}", path.display()),
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

    /// Wait for a Unix socket at `path` before considering this process started.
    /// The caller must remove any stale socket before spawning children.
    #[must_use]
    pub fn ready_when_socket_exists(mut self, path: impl Into<PathBuf>) -> Self {
        self.ready = Ready::Socket(path.into());
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
#[derive(Debug)]
pub struct Supervisor {
    /// In start order, so shutdown can run in reverse.
    running: Vec<Running>,
    terminate: SignalStream,
    interrupt: SignalStream,
    child: SignalStream,
}

impl Supervisor {
    /// Install signal handlers before any child can exit or shutdown can be requested.
    /// Must be called within a Tokio runtime with signals enabled.
    ///
    /// # Errors
    ///
    /// Returns [`SupervisorError::SignalHandler`] if a handler cannot be installed.
    pub fn new() -> Result<Self, SupervisorError> {
        let listen = |kind, name| {
            signal(kind).map_err(|source| SupervisorError::SignalHandler {
                signal: name,
                source,
            })
        };
        Ok(Self {
            running: Vec::new(),
            terminate: listen(SignalKind::terminate(), "SIGTERM")?,
            interrupt: listen(SignalKind::interrupt(), "SIGINT")?,
            child: listen(SignalKind::child(), "SIGCHLD")?,
        })
    }

    /// Start children in order, supervise them, and shut down on every result.
    /// FRR manages its own daemons; any top-level child failure ends the gateway.
    ///
    /// # Errors
    ///
    /// Returns the startup or supervision failure after attempting shutdown.
    /// A shutdown failure is logged without replacing an earlier failure.
    pub async fn run(
        mut self,
        processes: impl IntoIterator<Item = Process>,
    ) -> Result<Outcome, SupervisorError> {
        let result = async {
            for process in processes {
                self.start(process).await?;
            }
            self.wait().await
        }
        .await;
        let result = match result {
            Err(SupervisorError::Interrupted { signal }) => Ok(Outcome::Signalled { signal }),
            result => result,
        };

        if let Err(shutdown_error) = self.shut_down().await {
            if result.is_ok() {
                return Err(shutdown_error);
            }
            error!("shutdown after gateway failure also failed: {shutdown_error}");
        }
        result
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
    /// [`SupervisorError::DiedDuringStartup`] if any supervised child exited,
    /// [`SupervisorError::Interrupted`] on a shutdown signal,
    /// [`SupervisorError::Socket`] if the readiness path cannot be used, or
    /// [`SupervisorError::NeverReady`] if it stayed alive without meeting its condition.
    async fn start(&mut self, mut process: Process) -> Result<(), SupervisorError> {
        self.check_startup()?;
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

        self.await_ready(&process.name, &process.ready, process.ready_timeout)
            .await
    }

    /// Check all children, including those whose readiness checks already passed.
    fn check_startup(&mut self) -> Result<(), SupervisorError> {
        if let Some((name, report)) = self.reap()? {
            return Err(SupervisorError::DiedDuringStartup { name, report });
        }
        if self.terminate.recv().now_or_never().is_some() {
            return Err(SupervisorError::Interrupted { signal: "SIGTERM" });
        }
        if self.interrupt.recv().now_or_never().is_some() {
            return Err(SupervisorError::Interrupted { signal: "SIGINT" });
        }
        Ok(())
    }

    /// Wait for readiness while observing every child and shutdown signals.
    async fn await_ready(
        &mut self,
        name: &str,
        condition: &Ready,
        timeout: Duration,
    ) -> Result<(), SupervisorError> {
        let Ready::Socket(path) = condition else {
            return Ok(());
        };

        debug!("waiting for {name}: {condition}");
        let deadline = clock::now() + timeout;
        loop {
            self.check_startup()?;
            if socket::exists(path).map_err(|source| SupervisorError::Socket {
                name: name.to_string(),
                path: path.clone(),
                source,
            })? {
                debug!("{name} is ready (socket {} exists)", path.display());
                return Ok(());
            }

            if clock::now() >= deadline {
                return Err(SupervisorError::NeverReady {
                    name: name.to_string(),
                    condition: condition.clone(),
                    timeout,
                });
            }
            tokio::select! {
                _ = self.child.recv() => {}
                _ = self.terminate.recv() => {
                    return Err(SupervisorError::Interrupted { signal: "SIGTERM" });
                }
                _ = self.interrupt.recv() => {
                    return Err(SupervisorError::Interrupted { signal: "SIGINT" });
                }
                () = sleep(READY_POLL) => {}
            }
        }
    }

    /// Wait for a supervised child to exit or a shutdown signal to arrive.
    async fn wait(&mut self) -> Result<Outcome, SupervisorError> {
        info!("supervising {} process(es)", self.running.len());

        // Only listened for when a build has asked for it: see `DEV_PROFILE_DUMP_ENV`. An
        // unwanted `SIGUSR1` would otherwise reach a process whose default action is to die.
        let dump_target = std::env::var(DEV_PROFILE_DUMP_ENV).ok().map(|v| {
            if v.trim().is_empty() {
                DEV_PROFILE_DUMP_DEFAULT_TARGET.to_string()
            } else {
                v.trim().to_string()
            }
        });
        let mut profile_dump = if let Some(target) = &dump_target {
            info!("{DEV_PROFILE_DUMP_ENV} is set: SIGUSR1 will be forwarded to `{target}`");
            Some(signal(SignalKind::user_defined1()).map_err(|e| {
                SupervisorError::SignalHandler {
                    signal: "SIGUSR1",
                    source: e,
                }
            })?)
        } else {
            None
        };

        let outcome = loop {
            // An exit may predate this loop; SIGCHLD notifications may also be coalesced.
            if let Some((name, report)) = self.reap()? {
                error!("{name} {report}; bringing the gateway down");
                break Outcome::Exited { name, report };
            }
            tokio::select! {
                _ = self.child.recv() => {}
                _ = self.terminate.recv() => break Outcome::Signalled { signal: "SIGTERM" },
                _ = self.interrupt.recv() => break Outcome::Signalled { signal: "SIGINT" },
                // Deliberately does not break: this is a request for data, not to stop.
                Some(()) = async {
                    match profile_dump.as_mut() {
                        Some(sig) => sig.recv().await,
                        // Never completes, so the arm is inert when the feature is off.
                        None => std::future::pending().await,
                    }
                } => {
                    // Signal the process itself, not its group: a group signal reaches children
                    // that have no handler for it, and the default disposition kills them.
                    let target = dump_target.as_deref().unwrap_or(DEV_PROFILE_DUMP_DEFAULT_TARGET);
                    let mut found = false;
                    for running in self.running.iter().filter(|r| r.name == target) {
                        found = true;
                        info!("forwarding SIGUSR1 to {} (pid {})", running.name, running.pid);
                        if let Err(e) = kill(running.pid, Signal::SIGUSR1) {
                            warn!("could not signal {} (pid {}): {e}", running.name, running.pid);
                        }
                    }
                    if !found {
                        warn!("{DEV_PROFILE_DUMP_ENV} names `{target}`, which is not supervised");
                    }
                }
            }
        };

        if let Outcome::Signalled { signal } = &outcome {
            info!("received {signal}; stopping the gateway");
        }
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

        let deadline = clock::now() + GRACE;
        while !self.running.is_empty() && clock::now() < deadline {
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

        // As PID 1, also stop daemonized children that escaped their parent's group.
        // Outside PID 1, kill(-1) could signal unrelated processes owned by this user.
        if unistd::getpid().as_raw() == 1 {
            let _ = kill(Pid::from_raw(-1), Signal::SIGTERM);
        } else {
            debug!("not PID 1, so not sweeping for processes we did not start");
        }

        // Drain, so nothing is left unreaped when this process exits and the namespace goes.
        let deadline = clock::now() + GRACE;
        loop {
            self.reap()?;
            match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) if clock::now() < deadline => sleep(READY_POLL).await,
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
    use nix::sys::wait::{Id, waitid};

    /// Each supervisor owns process-wide signals and waitpid, so give each test a process.
    fn run_in_subprocess(name: &str) -> bool {
        const CHILD_TEST: &str = "DATAPLANE_SUPERVISOR_TEST";
        if std::env::var(CHILD_TEST).as_deref() == Ok(name) {
            return false;
        }
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &format!("supervisor::test::{name}"),
                "--nocapture",
            ])
            .env(CHILD_TEST, name)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{name}:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        true
    }

    /// Establish that the child exited without consuming the status the supervisor needs.
    async fn wait_for_exit(pid: Pid) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let status = waitid(
                    Id::Pid(pid),
                    WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT,
                )
                .unwrap();
                if interpret(status).is_some() {
                    return;
                }
                sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("child should exit promptly");
    }

    #[tokio::test]
    async fn an_exit_before_supervision_is_not_lost() {
        if run_in_subprocess("an_exit_before_supervision_is_not_lost") {
            return;
        }
        let mut supervisor = Supervisor::new().unwrap();
        supervisor
            .start(Process::new("early", sh("exit 7")))
            .await
            .unwrap();
        let pid = supervisor.running[0].pid;
        wait_for_exit(pid).await;

        // Even if the notification was already consumed, waitpid must find the exit.
        tokio::time::timeout(Duration::from_secs(2), supervisor.child.recv())
            .await
            .unwrap()
            .unwrap();
        let outcome = tokio::time::timeout(Duration::from_secs(2), supervisor.run([]))
            .await
            .expect("must not wait for another SIGCHLD")
            .unwrap();
        assert!(
            matches!(outcome, Outcome::Exited { name, report: Ended::Code(7) } if name == "early")
        );
        assert_eq!(waitpid(pid, Some(WaitPidFlag::WNOHANG)), Err(Errno::ECHILD));
    }

    #[tokio::test]
    async fn an_exit_prevents_starting_the_next_child() {
        if run_in_subprocess("an_exit_prevents_starting_the_next_child") {
            return;
        }
        let mut supervisor = Supervisor::new().unwrap();
        supervisor
            .start(Process::new("early", sh("exit 7")))
            .await
            .unwrap();
        wait_for_exit(supervisor.running[0].pid).await;

        let result = supervisor
            .start(Process::new("next", sh("sleep 600")))
            .await;
        let nothing_started = supervisor.running.is_empty();
        supervisor.shut_down().await.unwrap();
        assert!(
            matches!(result, Err(SupervisorError::DiedDuringStartup { name, report: Ended::Code(7) }) if name == "early")
        );
        assert!(nothing_started);
    }

    #[tokio::test]
    async fn an_earlier_exit_interrupts_another_childs_readiness() {
        if run_in_subprocess("an_earlier_exit_interrupts_another_childs_readiness") {
            return;
        }
        let mut supervisor = Supervisor::new().unwrap();
        supervisor
            .start(Process::new("earlier", sh("exec sleep 600")))
            .await
            .unwrap();
        let pid = supervisor.running[0].pid;
        let next = Process::new("next", sh("exec sleep 600"))
            .ready_when_socket_exists("/definitely/not/a/real/socket");
        let (result, ()) = tokio::join!(
            biased;
            tokio::time::timeout(Duration::from_secs(2), supervisor.run([next])),
            async { kill(pid, Signal::SIGKILL).unwrap(); }
        );
        assert!(
            matches!(result.expect("must observe earlier children during readiness"),
            Err(SupervisorError::DiedDuringStartup { name, report: Ended::Killed(Signal::SIGKILL) }) if name == "earlier")
        );
        assert_eq!(
            waitpid(None, Some(WaitPidFlag::WNOHANG)),
            Err(Errno::ECHILD)
        );
    }

    #[tokio::test]
    async fn shutdown_signals_interrupt_readiness() {
        if run_in_subprocess("shutdown_signals_interrupt_readiness") {
            return;
        }
        for (signal, expected) in [(Signal::SIGTERM, "SIGTERM"), (Signal::SIGINT, "SIGINT")] {
            let mut supervisor = Supervisor::new().unwrap();
            supervisor
                .start(Process::new("earlier", sh("exec sleep 600")))
                .await
                .unwrap();
            let process = Process::new("starting", sh("exec sleep 600"))
                .ready_when_socket_exists("/definitely/not/a/real/socket");
            let (result, ()) = tokio::join!(
                biased;
                tokio::time::timeout(Duration::from_secs(2), supervisor.run([process])),
                async { kill(unistd::getpid(), signal).unwrap(); }
            );
            assert!(matches!(result.expect("must respond during readiness"),
                Ok(Outcome::Signalled { signal }) if signal == expected));
            assert_eq!(
                waitpid(None, Some(WaitPidFlag::WNOHANG)),
                Err(Errno::ECHILD)
            );
        }
    }

    #[tokio::test]
    async fn a_failed_spawn_stops_started_children() {
        if run_in_subprocess("a_failed_spawn_stops_started_children") {
            return;
        }
        let mut supervisor = Supervisor::new().unwrap();
        supervisor
            .start(Process::new("dataplane", sh("exec sleep 600")))
            .await
            .unwrap();
        let pid = supervisor.running[0].pid;
        let result = supervisor
            .run([Process::new(
                "frr",
                Command::new("/definitely/not/a/real/watchfrr"),
            )])
            .await;

        assert!(
            matches!(result, Err(SupervisorError::Spawn { name, source })
            if name == "frr" && source.raw_os_error() == Some(nix::libc::ENOENT))
        );
        assert_eq!(
            waitpid(None, Some(WaitPidFlag::WNOHANG)),
            Err(Errno::ECHILD)
        );
        assert_eq!(kill(pid, None), Err(Errno::ESRCH));
    }

    /// A command that runs `script` under a shell.
    fn sh(script: &str) -> Command {
        let mut command = Command::new(tool("sh"));
        command.arg("-c").arg(script);
        command
    }

    /// A profile dump reaches only the named process and leaves supervision running.
    #[tokio::test]
    async fn a_forwarded_profile_dump_does_not_stop_the_gateway() {
        if run_in_subprocess("a_forwarded_profile_dump_does_not_stop_the_gateway") {
            return;
        }
        // SAFETY: this test runs alone in a subprocess on a current-thread runtime.
        unsafe { std::env::set_var(DEV_PROFILE_DUMP_ENV, "dumper") };
        let marker = std::env::temp_dir().join(format!("dumped.{}", std::process::id()));
        // A child with no SIGUSR1 handler. It must survive: the default disposition of SIGUSR1
        // is to terminate, so signalling the *group* rather than the process would kill it --
        // which in the real supervisor means killing whatever the dataplane has spawned.
        let orphan_died = std::env::temp_dir().join(format!("childdied.{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let _ = std::fs::remove_file(&orphan_died);

        let mut supervisor = Supervisor::new().unwrap();
        supervisor
            .start(Process::new(
                "dumper",
                // Traps USR1 and keeps going, then exits on its own with a distinctive code:
                // that exit, not a signal, is what ends supervision.
                sh(&format!(
                    "trap 'touch {m}' USR1; sleep 600 & c=$!; i=0; \
                     while [ $i -lt 30 ]; do sleep 0.1; \
                       kill -0 $c 2>/dev/null || {{ touch {d}; break; }}; i=$((i+1)); done; \
                     kill $c 2>/dev/null; exit 7",
                    m = marker.display(),
                    d = orphan_died.display()
                )),
            ))
            .await
            .expect("the dumper should start");

        let pid = std::process::id();
        let signaller = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            // The supervisor listens for SIGUSR1 in this process; it forwards only to `dumper`.
            let _ = kill(Pid::from_raw(pid.cast_signed()), Signal::SIGUSR1);
        });

        let outcome = tokio::time::timeout(Duration::from_secs(30), supervisor.run([]))
            .await
            .expect("supervision should end when the dumper exits, not hang")
            .expect("supervision should not fail");
        signaller.await.expect("the signaller should finish");

        match outcome {
            Outcome::Exited { report, .. } => assert_eq!(
                report,
                Ended::Code(7),
                "the dumper should have run to its own exit"
            ),
            other @ Outcome::Signalled { .. } => {
                panic!("SIGUSR1 must not end supervision; got {other:?}")
            }
        }
        assert!(
            marker.exists(),
            "the supervised process should have received the forwarded SIGUSR1"
        );
        assert!(
            !orphan_died.exists(),
            "SIGUSR1 must go to the process, not its group: a child with no handler was killed"
        );
        let _ = std::fs::remove_file(&marker);
        let _ = std::fs::remove_file(&orphan_died);
        // SAFETY: as above.
        unsafe { std::env::remove_var(DEV_PROFILE_DUMP_ENV) };
    }

    #[tokio::test]
    async fn a_process_that_exits_takes_the_rest_down_with_it() {
        if run_in_subprocess("a_process_that_exits_takes_the_rest_down_with_it") {
            return;
        }
        let mut supervisor = Supervisor::new().unwrap();
        supervisor
            .start(Process::new("survivor", sh("sleep 600")))
            .await
            .expect("the survivor should start");
        supervisor
            .start(Process::new("quitter", sh("exit 3")))
            .await
            .expect("the quitter should start");

        let outcome = tokio::time::timeout(Duration::from_secs(30), supervisor.run([]))
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
        if run_in_subprocess("a_killed_process_is_reported_as_killed") {
            return;
        }
        let mut supervisor = Supervisor::new().unwrap();
        supervisor
            .start(Process::new("doomed", sh("kill -9 $$")))
            .await
            .expect("the doomed process should start");

        let outcome = tokio::time::timeout(Duration::from_secs(30), supervisor.run([]))
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
    async fn a_dependant_waits_for_a_new_socket() {
        if run_in_subprocess("a_dependant_waits_for_a_new_socket") {
            return;
        }
        let scratch = scratch_dir("ready");
        let path = scratch.join("cpi.sock");
        drop(std::os::unix::net::UnixDatagram::bind(&path).unwrap());
        socket::remove_stale(&path).unwrap();

        let mut supervisor = Supervisor::new().unwrap();
        {
            let start = supervisor.start(
                Process::new("slow-starter", sh("exec sleep 600")).ready_when_socket_exists(&path),
            );
            tokio::pin!(start);
            assert!(
                start.as_mut().now_or_never().is_none(),
                "must wait for a new socket"
            );

            let _socket = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
            tokio::time::timeout(Duration::from_secs(2), start)
                .await
                .expect("must observe the new socket")
                .unwrap();
        }
        supervisor.shut_down().await.unwrap();
        std::fs::remove_dir_all(scratch).unwrap();
    }

    #[tokio::test]
    async fn a_regular_file_cannot_satisfy_socket_readiness() {
        if run_in_subprocess("a_regular_file_cannot_satisfy_socket_readiness") {
            return;
        }
        let scratch = scratch_dir("wrong-type");
        let path = scratch.join("cpi.sock");
        std::fs::write(&path, "not a socket").unwrap();
        let supervisor = Supervisor::new().unwrap();
        let error = supervisor
            .run([
                Process::new("earlier", sh("exec sleep 600")),
                Process::new("wrong-type", sh("exec sleep 600")).ready_when_socket_exists(&path),
            ])
            .await
            .unwrap_err();
        assert!(matches!(error, SupervisorError::Socket { name, source, .. }
            if name == "wrong-type" && source.kind() == io::ErrorKind::InvalidInput));
        assert_eq!(
            waitpid(None, Some(WaitPidFlag::WNOHANG)),
            Err(Errno::ECHILD)
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "not a socket");
        std::fs::remove_dir_all(scratch).unwrap();
    }

    #[tokio::test]
    async fn a_process_that_dies_while_starting_is_reported_as_such() {
        if run_in_subprocess("a_process_that_dies_while_starting_is_reported_as_such") {
            return;
        }
        let mut supervisor = Supervisor::new().unwrap();
        supervisor
            .start(Process::new("earlier", sh("exec sleep 600")))
            .await
            .unwrap();
        let error = supervisor
            .run([Process::new("false-start", sh("exit 7"))
                .ready_when_socket_exists("/definitely/not/a/real/socket")])
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
        assert_eq!(
            waitpid(None, Some(WaitPidFlag::WNOHANG)),
            Err(Errno::ECHILD)
        );
    }

    #[tokio::test]
    async fn a_process_that_never_becomes_ready_times_out() {
        if run_in_subprocess("a_process_that_never_becomes_ready_times_out") {
            return;
        }
        let mut supervisor = Supervisor::new().unwrap();
        supervisor
            .start(Process::new("earlier", sh("exec sleep 600")))
            .await
            .unwrap();
        let mut process = Process::new("never-ready", sh("exec sleep 600"))
            .ready_when_socket_exists("/definitely/not/a/real/socket");
        process.ready_timeout = Duration::from_millis(200);

        let error = supervisor
            .run([process])
            .await
            .expect_err("a process that never becomes ready is an error");

        match error {
            SupervisorError::NeverReady { name, .. } => assert_eq!(name, "never-ready"),
            other => panic!("expected NeverReady, got {other:?}"),
        }

        assert_eq!(
            waitpid(None, Some(WaitPidFlag::WNOHANG)),
            Err(Errno::ECHILD)
        );
    }

    #[tokio::test]
    async fn shutdown_reaches_a_process_that_ignores_sigterm() {
        if run_in_subprocess("shutdown_reaches_a_process_that_ignores_sigterm") {
            return;
        }
        let mut supervisor = Supervisor::new().unwrap();
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
        if run_in_subprocess("an_orphan_is_reaped_without_ending_supervision") {
            return;
        }
        let mut supervisor = Supervisor::new().unwrap();
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

        let outcome = tokio::time::timeout(Duration::from_secs(30), supervisor.run([]))
            .await
            .expect("supervision should end when the parent exits")
            .expect("supervision should not fail");

        match outcome {
            // The *parent* is what ends supervision. The orphan is reaped in passing.
            Outcome::Exited { name, report } => {
                assert_eq!(name, "parent");
                assert_eq!(report, Ended::Code(0));
                assert_eq!(report.as_exit_code(), 1);
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
        if run_in_subprocess("shutdown_does_not_reach_processes_we_never_started") {
            return;
        }
        // Deliberately not given to the supervisor: it stands in for every process on the machine
        // that has nothing to do with the gateway.
        let mut bystander = sh("sleep 600").spawn().expect("the bystander should start");

        let mut supervisor = Supervisor::new().unwrap();
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
