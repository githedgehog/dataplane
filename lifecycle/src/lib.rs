// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Process-lifecycle primitives for the dataplane binary.
//!
//! [`Shutdown`] bundles a root [`CancellationToken`] and one [`Subsystem`]
//! per long-lived component. Each subsystem owns a cancel token and a
//! [`TaskTracker`]; [`Shutdown::drain_in_order`] drains them in topological
//! order with per-subsystem deadlines.

#![deny(
    unsafe_code,
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use concurrency::sync::Arc;
use concurrency::sync::atomic::{AtomicBool, Ordering};
use std::future::Future;
use std::time::Duration;

use tokio::sync::mpsc::Receiver;
use tokio::task::JoinHandle;
use tokio::time::error::Elapsed;
use tracing::{error, info, warn};

pub use tokio_util::sync::CancellationToken;
pub use tokio_util::task::TaskTracker;

/// A named, drainable subsystem. Cheap to clone.
#[derive(Clone, Debug)]
pub struct Subsystem {
    /// Stable name used in shutdown logs.
    pub name: &'static str,
    cancel: CancellationToken,
    tasks: TaskTracker,
    root: CancellationToken,
    fatal: Arc<AtomicBool>,
}

impl Subsystem {
    /// Tests/ad-hoc only. Production code: use [`Shutdown::new`] so all
    /// subsystems share one fatal flag.
    #[doc(hidden)]
    #[must_use]
    pub fn new(name: &'static str, root: CancellationToken) -> Self {
        Self::with_fatal(name, root, Arc::new(AtomicBool::new(false)))
    }

    /// Construct a subsystem with an explicit shared fatal flag.
    #[must_use]
    pub fn with_fatal(name: &'static str, root: CancellationToken, fatal: Arc<AtomicBool>) -> Self {
        Self {
            name,
            cancel: CancellationToken::new(),
            tasks: TaskTracker::new(),
            root,
            fatal,
        }
    }

    /// Clone of this subsystem's cancellation token.
    #[must_use]
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// True if this subsystem's cancellation token has been tripped.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// Clone of the process-wide root cancellation token. Use for startup
    /// work — the per-subsystem cancel is tripped after startup returns.
    #[must_use]
    pub fn root_token(&self) -> CancellationToken {
        self.root.clone()
    }

    /// Spawn an async task on `handle`, tracked under this subsystem.
    pub fn spawn_on<F>(&self, future: F, handle: &tokio::runtime::Handle) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.tasks.spawn_on(future, handle)
    }

    /// Spawn `future`; if it exits (normally or by panic) before any
    /// shutdown is requested, call [`Self::report_fatal`]. Use for tasks
    /// whose unexpected exit means the subsystem is broken; for tasks
    /// where silent exit is fine, use [`Self::spawn_on`].
    pub fn spawn_fatal_on_exit<F>(&self, reason: &str, future: F, handle: &tokio::runtime::Handle)
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let cancel = self.cancel.clone();
        let root = self.root.clone();
        let subsystem = self.clone();
        let reason = reason.to_owned();
        // Spawn `inner` detached on the runtime so panics surface via its
        // JoinHandle; only the wrapper is tracked.
        let mut inner = handle.spawn(future);
        self.tasks.spawn_on(
            async move {
                tokio::select! {
                    () = cancel.cancelled() => {
                        inner.abort();
                        let _ = (&mut inner).await;
                    }
                    result = &mut inner => {
                        // Root counts as graceful: during SIGINT, root
                        // trips before this subsystem's cancel.
                        if root.is_cancelled() || cancel.is_cancelled() {
                            return;
                        }
                        match result {
                            Ok(_) => subsystem
                                .report_fatal(&format!("{reason} exited without cancellation")),
                            Err(e) if e.is_panic() => subsystem
                                .report_fatal(&format!("{reason} panicked: {e}")),
                            Err(_) => {}
                        }
                    }
                }
            },
            handle,
        );
    }

    /// Set the fatal flag, trip this subsystem's cancel, trip the root.
    /// Idempotent. Logs at error.
    pub fn report_fatal(&self, reason: &str) {
        error!(subsystem = self.name, reason, "fatal; tripping shutdown");
        self.fatal.store(true, Ordering::Relaxed);
        self.cancel.cancel();
        self.root.cancel();
    }

    /// Cancel this subsystem and wait for tracked tokio tasks. Idempotent.
    ///
    /// Thread-based subsystems (workers, RIO) are not tracked here; their
    /// joins happen at scope-close. The watchdog is their hard bound.
    ///
    /// # Errors
    /// Returns [`Elapsed`] if any tracked task is still running after
    /// `deadline`. Cancel is tripped and tracker closed either way.
    pub async fn drain(&self, deadline: Duration) -> Result<(), Elapsed> {
        self.cancel.cancel();
        self.tasks.close();
        tokio::time::timeout(deadline, self.tasks.wait()).await
    }
}

/// Default drain deadlines. Per-subsystem deadlines bound only the
/// tokio tasks tracked by each [`Subsystem`]; [`TOTAL`] is the absolute
/// process-level ceiling enforced by [`spawn_shutdown_watchdog`].
pub mod default_deadlines {
    use std::time::Duration;
    /// Drain workers' tokio tasks.
    pub const WORKERS: Duration = Duration::from_secs(5);
    /// Drain RIO's tokio tasks.
    pub const ROUTER: Duration = Duration::from_secs(5);
    /// Drain mgmt's tasks (config processor, status updater, watcher).
    pub const MGMT: Duration = Duration::from_secs(5);
    /// Drain metrics; short — a stuck scrape is fine to abandon.
    pub const METRICS: Duration = Duration::from_secs(2);
    /// Hard process-wide ceiling. Independent of the sum above.
    pub const TOTAL: Duration = Duration::from_secs(15);
}

/// Root lifecycle bundle owned by `main`.
#[derive(Debug)]
pub struct Shutdown {
    /// Tripped by `SIGINT`/`SIGTERM` or any subsystem's
    /// [`Subsystem::report_fatal`].
    pub root: CancellationToken,
    fatal: Arc<AtomicBool>,
    /// Data-plane workers.
    pub workers: Subsystem,
    /// Routing/control I/O.
    pub router: Subsystem,
    /// Management plane.
    pub mgmt: Subsystem,
    /// Prometheus endpoint and stats collection.
    pub metrics: Subsystem,
}

impl Shutdown {
    /// Build a `Shutdown` with subsystems pre-wired to one root and one
    /// fatal flag.
    #[must_use]
    pub fn new() -> Self {
        let root = CancellationToken::new();
        let fatal = Arc::new(AtomicBool::new(false));
        Self {
            workers: Subsystem::with_fatal("workers", root.clone(), fatal.clone()),
            router: Subsystem::with_fatal("router", root.clone(), fatal.clone()),
            mgmt: Subsystem::with_fatal("mgmt", root.clone(), fatal.clone()),
            metrics: Subsystem::with_fatal("metrics", root.clone(), fatal.clone()),
            root,
            fatal,
        }
    }

    /// Set the fatal flag and trip the root. Idempotent.
    pub fn fail(&self) {
        self.fatal.store(true, Ordering::Relaxed);
        self.root.cancel();
    }

    /// True if any subsystem reported fatal or `main` called
    /// [`Shutdown::fail`]. Read after drain to choose the exit code.
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        self.fatal.load(Ordering::Relaxed)
    }

    /// Drain in order: workers, router, metrics, mgmt. Workers stop
    /// touching packets before the control plane goes away. Subsystems
    /// that miss their deadline are logged and abandoned.
    pub async fn drain_in_order(&self) {
        Self::drain_one(&self.workers, default_deadlines::WORKERS).await;
        Self::drain_one(&self.router, default_deadlines::ROUTER).await;
        Self::drain_one(&self.metrics, default_deadlines::METRICS).await;
        Self::drain_one(&self.mgmt, default_deadlines::MGMT).await;
    }

    async fn drain_one(sub: &Subsystem, deadline: Duration) {
        if sub.drain(deadline).await.is_ok() {
            info!(subsystem = sub.name, "drained cleanly");
        } else {
            warn!(
                subsystem = sub.name,
                deadline_ms = u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX),
                "drain timed out; abandoning"
            );
        }
    }
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

/// Type to indicate the type of signal that was caught
#[allow(missing_docs)]
#[derive(Debug)]
pub enum DpSignal {
    SIGINT,
    SIGTERM,
    SIGQUIT,
    SIGUSR1,
    SIGUSR2,
    SIGHUP,
    SIGALRM,
    SIGPIPE,
}

/// Spawn a task on `handle` that installs signal listeners for `SIGINT`/`SIGTERM` (and
/// other signals which would otherwise terminate the process by default) and relays `DpSignal`s
/// over a channel to the `Receiver` returned by this function.
///
/// The receiver should trip `root` on `SIGINT`/`SIGTERM`, which will also terminate this task.
///
/// # Errors
/// Returns [`std::io::Error`] if either signal handler install fails.
#[cfg(unix)]
pub fn spawn_signal_catcher(
    handle: &tokio::runtime::Handle,
    root: CancellationToken,
) -> std::io::Result<Receiver<DpSignal>> {
    use tokio::signal::unix::{SignalKind, signal};
    let (tx, rx) = tokio::sync::mpsc::channel::<DpSignal>(10);

    // Install inside the runtime context so the handlers register with
    // its signal driver, not just the EnterGuard.
    let (
        mut sigint,
        mut sigterm,
        mut sigquit,
        mut sigusr1,
        mut sigusr2,
        mut sighup,
        mut sigalrm,
        mut sigpipe,
    ) = {
        let _guard = handle.enter();
        (
            signal(SignalKind::interrupt())?,
            signal(SignalKind::terminate())?,
            signal(SignalKind::quit())?,
            signal(SignalKind::user_defined1())?,
            signal(SignalKind::user_defined2())?,
            signal(SignalKind::hangup())?,
            signal(SignalKind::alarm())?,
            signal(SignalKind::pipe())?,
        )
    };

    handle.spawn(async move {
        loop {
            tokio::select! {
                _ = sigint.recv()  => {
                    let _ = tx.send(DpSignal::SIGINT).await;
                },
                _ = sigterm.recv() => {
                    let _ = tx.send(DpSignal::SIGTERM).await;
                },
                _ = sigquit.recv() => {
                    let _ = tx.send(DpSignal::SIGQUIT).await;
                },
                _ = sigusr1.recv() => {
                    let _ = tx.send(DpSignal::SIGUSR1).await;
                },
                _ = sigusr2.recv() => {
                    let _ = tx.send(DpSignal::SIGUSR2).await;
                },
                _ = sighup.recv() => {
                    let _ = tx.send(DpSignal::SIGHUP).await;
                },
                _ = sigalrm.recv() => {
                    let _ = tx.send(DpSignal::SIGALRM).await;
                },
                _ = sigpipe.recv() => {
                    let _ = tx.send(DpSignal::SIGPIPE).await;
                },

                () = root.cancelled() => break,
            }
        }
        info!("Signal catcher ended");
    });

    Ok(rx)
}

/// Spawn a detached OS thread that calls [`std::process::exit`] `deadline`
/// after `root` is cancelled. Independent of the mgmt runtime so it still
/// fires if the runtime wedges. This is the only bound on a worker thread
/// blocked inside an I/O call that doesn't observe cancellation.
///
/// # Errors
/// Returns [`std::io::Error`] if spawning fails. A runtime-build failure
/// inside the thread is logged and disarms the watchdog (the process then
/// has no hard shutdown ceiling); treat disarm logs as a startup warning.
pub fn spawn_shutdown_watchdog(
    root: CancellationToken,
    deadline: Duration,
    exit_code: i32,
) -> std::io::Result<()> {
    use std::io::Write;
    std::thread::Builder::new()
        .name("shutdown-watchdog".to_string())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    error!(error = %e, "shutdown watchdog runtime failed to start; disarmed");
                    return;
                }
            };
            rt.block_on(root.cancelled());
            drop(rt);
            std::thread::sleep(deadline);
            error!(
                deadline_ms = u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX),
                exit_code, "shutdown exceeded total deadline; aborting"
            );
            // process::exit skips destructors, so flush stderr explicitly.
            let _ = std::io::stderr().flush();
            std::process::exit(exit_code);
        })
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use concurrency::sync::Arc;
    use concurrency::sync::atomic::{AtomicBool, Ordering};

    #[tokio::test]
    async fn drain_completes_when_tasks_observe_cancel() {
        let shutdown = Shutdown::new();
        let mgmt = shutdown.mgmt.clone();
        let cancel = mgmt.cancel_token();
        let observed = Arc::new(AtomicBool::new(false));
        let observed_in_task = observed.clone();

        let handle = tokio::runtime::Handle::current();
        mgmt.spawn_on(
            async move {
                cancel.cancelled().await;
                observed_in_task.store(true, Ordering::SeqCst);
            },
            &handle,
        );

        let result = mgmt.drain(Duration::from_millis(500)).await;
        assert!(result.is_ok());
        assert!(observed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn drain_times_out_when_task_ignores_cancel() {
        let shutdown = Shutdown::new();
        let mgmt = shutdown.mgmt.clone();

        let handle = tokio::runtime::Handle::current();
        mgmt.spawn_on(
            async move {
                tokio::time::sleep(Duration::from_mins(1)).await;
            },
            &handle,
        );

        let result = mgmt.drain(Duration::from_millis(50)).await;
        assert!(result.is_err());
        assert!(mgmt.is_cancelled());
        assert!(mgmt.tasks.is_closed());
    }

    #[tokio::test]
    async fn report_fatal_trips_root_self_cancel_and_fatal_flag() {
        let shutdown = Shutdown::new();
        assert!(!shutdown.is_fatal());
        shutdown.workers.report_fatal("synthetic test failure");

        assert!(shutdown.root.is_cancelled());
        assert!(shutdown.is_fatal());
        assert!(shutdown.workers.is_cancelled());
        assert!(!shutdown.mgmt.is_cancelled());
        assert!(!shutdown.router.is_cancelled());
        assert!(!shutdown.metrics.is_cancelled());
    }

    #[tokio::test]
    async fn shutdown_fail_sets_fatal_and_trips_root() {
        let shutdown = Shutdown::new();
        assert!(!shutdown.is_fatal());
        assert!(!shutdown.root.is_cancelled());

        shutdown.fail();

        assert!(shutdown.is_fatal());
        assert!(shutdown.root.is_cancelled());
    }

    #[tokio::test]
    async fn standalone_subsystem_has_its_own_fatal_flag() {
        let root = CancellationToken::new();
        let a = Subsystem::new("a", root.clone());
        let b = Subsystem::new("b", root);
        a.report_fatal("isolated");
        assert!(a.fatal.load(Ordering::Relaxed));
        assert!(!b.fatal.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn subsystem_cancels_are_independent_of_root() {
        let shutdown = Shutdown::new();
        shutdown.root.cancel();

        assert!(shutdown.root.is_cancelled());
        assert!(!shutdown.workers.is_cancelled());
        assert!(!shutdown.mgmt.is_cancelled());
    }

    #[tokio::test]
    async fn subsystem_root_token_observes_signal_handler_cancel() {
        let shutdown = Shutdown::new();
        let mgmt_root = shutdown.mgmt.root_token();
        assert!(!mgmt_root.is_cancelled());

        shutdown.fail();
        assert!(mgmt_root.is_cancelled());
    }

    #[tokio::test]
    async fn drain_is_idempotent() {
        let shutdown = Shutdown::new();
        let mgmt = shutdown.mgmt.clone();

        let first = mgmt.drain(Duration::from_millis(50)).await;
        let second = mgmt.drain(Duration::from_millis(50)).await;
        assert!(first.is_ok());
        assert!(second.is_ok());
    }

    #[tokio::test]
    async fn spawn_fatal_on_exit_trips_root_on_normal_return() {
        let shutdown = Shutdown::new();
        let handle = tokio::runtime::Handle::current();
        shutdown
            .mgmt
            .spawn_fatal_on_exit("test task", async {}, &handle);

        tokio::time::timeout(Duration::from_millis(500), shutdown.root.cancelled())
            .await
            .expect("root should trip on task exit");
        assert!(shutdown.is_fatal());
    }

    #[tokio::test]
    async fn spawn_fatal_on_exit_trips_root_on_panic() {
        let shutdown = Shutdown::new();
        let handle = tokio::runtime::Handle::current();
        shutdown.mgmt.spawn_fatal_on_exit(
            "test task",
            async {
                panic!("synthetic panic");
            },
            &handle,
        );

        tokio::time::timeout(Duration::from_millis(500), shutdown.root.cancelled())
            .await
            .expect("root should trip on task panic");
        assert!(shutdown.is_fatal());
    }

    #[tokio::test]
    async fn spawn_fatal_on_exit_does_not_trip_when_root_cancelled_first() {
        // Simulates: SIGINT trips root before drain_in_order reaches mgmt.
        // A supervised mgmt task exiting in that window must not flip fatal.
        let shutdown = Shutdown::new();
        let handle = tokio::runtime::Handle::current();
        shutdown.root.cancel();
        shutdown
            .mgmt
            .spawn_fatal_on_exit("test task", async {}, &handle);

        shutdown
            .mgmt
            .drain(Duration::from_millis(500))
            .await
            .unwrap();
        assert!(!shutdown.is_fatal());
    }

    #[tokio::test]
    async fn spawn_fatal_on_exit_does_not_trip_when_cancelled_first() {
        let shutdown = Shutdown::new();
        let handle = tokio::runtime::Handle::current();
        let cancel = shutdown.mgmt.cancel_token();
        shutdown.mgmt.spawn_fatal_on_exit(
            "test task",
            async move {
                cancel.cancelled().await;
            },
            &handle,
        );

        shutdown
            .mgmt
            .drain(Duration::from_millis(500))
            .await
            .unwrap();
        assert!(!shutdown.is_fatal());
    }

    #[tokio::test]
    async fn drain_in_order_completes_when_all_subsystems_observe_cancel() {
        let shutdown = Shutdown::new();
        let handle = tokio::runtime::Handle::current();
        for sub in [
            &shutdown.workers,
            &shutdown.router,
            &shutdown.mgmt,
            &shutdown.metrics,
        ] {
            let cancel = sub.cancel_token();
            sub.spawn_on(async move { cancel.cancelled().await }, &handle);
        }
        shutdown.drain_in_order().await;
        assert!(shutdown.workers.is_cancelled());
        assert!(shutdown.router.is_cancelled());
        assert!(shutdown.mgmt.is_cancelled());
        assert!(shutdown.metrics.is_cancelled());
    }
}
