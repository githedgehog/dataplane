// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Worker supervision shared by the packet drivers.
//!
//! A driver spawns its workers, hands the supervisor one [`WorkerMonitor`] per worker, and
//! the supervisor thread then samples each rx task's [`Watchdog`], publishes a
//! [`DriverStatus`], and joins the workers when they end or the subsystem is cancelled.

#![deny(
    unsafe_code,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::fmt::Display;
use std::ops::Add;
use std::time::Duration;

use concurrency::sync::Arc;
use concurrency::thread;
#[allow(unused_imports)] // used under loom/shuttle backends
use concurrency::thread::BuilderExt;
use concurrency::thread::ScopedJoinHandle;
use lifecycle::Subsystem;
use tracectl::trace_target;
#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

use super::status::{
    DriverStatus, DriverStatusWriter, RxTaskStatus, WorkerEndResult, WorkerId, WorkerState,
    WorkerStatus,
};
use super::watchdog::{Activity, Watchdog};

trace_target!("driver-supervisor", LevelFilter::INFO, &["driver"]);

/// How often, in seconds, an rx task pats its watchdog even if no activity (worst case)
pub(crate) const TASK_PAT_PERIOD: u16 = 2;

/// Slack, in seconds, on top of the pat period before a missed pat is treated as a deadline miss.
pub(crate) const TASK_GRACE_PERIOD: u16 = 4;

/// Interval, in seconds, at which the supervisor will check rx task watchdogs
pub(crate) const TASK_CHECK_PERIOD: u16 = TASK_PAT_PERIOD + TASK_GRACE_PERIOD;

/// Interval, in seconds, at which the supervisor checks rx task activity, ignoring watchdogs
pub(crate) const TASK_POLL_PERIOD: u16 = 1;

/// The supervisor's view of one rx task: the interface it serves and the watchdog it reports on.
#[derive(Clone)]
pub(crate) struct RxTaskMonitor {
    pub(crate) ifname: Arc<str>,
    pub(crate) watchdog: Watchdog,
}

impl RxTaskMonitor {
    #[must_use]
    pub(crate) fn new(ifname: &str) -> Self {
        Self {
            ifname: Arc::from(ifname),
            watchdog: Watchdog::new(),
        }
    }
}

/// The supervisor's handle on one worker thread and its rx tasks.
pub(crate) struct WorkerMonitor<'scope, E> {
    id: WorkerId,
    handle: Option<ScopedJoinHandle<'scope, Result<(), E>>>,
    rx_tasks: Vec<RxTaskMonitor>,
}

impl<'scope, E> WorkerMonitor<'scope, E> {
    #[must_use]
    pub(crate) fn new(
        id: WorkerId,
        handle: ScopedJoinHandle<'scope, Result<(), E>>,
        rx_tasks: Vec<RxTaskMonitor>,
    ) -> Self {
        Self {
            id,
            handle: Some(handle),
            rx_tasks,
        }
    }
}

/// Spawn the supervisor for `monitors` into `scope`.
///
/// `driver` names the driver in the supervisor's thread name and logs. The supervisor
/// just joins-and-logs on worker termination; worker fatal reporting is left to the driver.
///
/// # Errors
///
/// Returns an error if the supervisor thread cannot be spawned.
pub(crate) fn spawn_supervisor<'scope, E: Display + Send + Sync + 'scope>(
    scope: &'scope thread::Scope<'scope, '_>,
    driver: &'static str,
    subsystem: &Subsystem,
    mut monitors: Vec<WorkerMonitor<'scope, E>>,
    status_writer: DriverStatusWriter,
) -> std::io::Result<()> {
    // the two time intervals that matter for liveness detection
    let check_period = Duration::from_secs(u64::from(TASK_CHECK_PERIOD));
    let poll_period = Duration::from_secs(u64::from(TASK_POLL_PERIOD));

    let subsystem = subsystem.clone();

    thread::Builder::new()
        .name(format!("{driver}-worker-supervisor"))
        .spawn_scoped(scope, move || {
            info!("{driver} worker supervisor started");

            // build a vector of worker status from their monitors to expose their state outside of this thread
            // each WorkerStatus contains a list of RxTaskStatus
            let mut workers_status: Vec<WorkerStatus> = monitors
                .iter()
                .map(|monitor| {
                    let mut ws = WorkerStatus::new(monitor.id);
                    ws.rx_tasks = monitor
                        .rx_tasks
                        .iter()
                        .map(|t| RxTaskStatus::new(t.ifname.clone()))
                        .collect();
                    ws
                })
                .collect();

            // the next instant when the rx tasks watchdogs should be checked.
            let mut next_watchdog_check = clock::now().add(check_period);

            loop {
                // check if we must run. Otherwise (got cancelled) join all workers
                if !must_run(driver, &subsystem, &mut monitors, &mut workers_status) {
                    break;
                }

                // check the current time and decide if we should check whether the rx tasks patted the watchdogs.
                // If so, compute the next time we should check them again in the future.
                let now = clock::now();
                let check_watchdog = now >= next_watchdog_check;
                if check_watchdog {
                    while next_watchdog_check <= now {
                        next_watchdog_check = next_watchdog_check.add(check_period);
                    }
                }

                // check each worker using its monitor
                let mut any_running = false;
                for (pos, monitor) in monitors.iter_mut().enumerate() {
                    // get status object for the worker/monitor
                    let wk_status = &mut workers_status[pos];

                    if let Some(handle) = monitor.handle.take() {
                        if handle.is_finished() {
                            // join the worker
                            let result = join_worker(driver, monitor.id, handle);
                            wk_status.state = WorkerState::Terminated(result);
                            wk_status.rx_tasks.iter_mut().for_each(|r| {
                                r.activity = Activity::Idle;
                                r.pps = 0.0;
                            });
                        } else {
                            // worker is running, update its `WorkerStatus` and restore its handle
                            wk_status.state = WorkerState::Running;
                            monitor.handle = Some(handle);
                            any_running = true;

                            // check the worker's rx tasks and update the corresponding status
                            check_worker_rx_tasks(driver, monitor, wk_status, check_watchdog);
                        }
                    } else {
                        // A worker monitor without a handle means that the worker was joined already
                        // We do nothing in this case. The monitor is kept in the list.
                    }
                }

                if !any_running {
                    error!("No more {driver} workers are running!!. Stopping...");
                    break;
                }

                // publish the status of the driver
                status_writer.publish(DriverStatus {
                    workers: workers_status.clone(),
                });

                // sleep for the poll period
                thread::sleep(poll_period);
            }

            // update status on termination. This is in case we
            // want to log the last state
            let last = DriverStatus {
                workers: workers_status.clone(),
            };
            status_writer.publish(last);

            info!("{driver} worker supervisor thread terminated");
        })?;
    Ok(())
}

/// Join a worker given its handle, log how the thread terminated and report the outcome in a `WorkerEndResult`.
/// This method should only be called when we know that a worker has ended (or is about to do so due to cancellation).
/// Otherwise it would block the supervisor.
fn join_worker<E: Display>(
    driver: &str,
    id: WorkerId,
    handle: ScopedJoinHandle<'_, Result<(), E>>,
) -> WorkerEndResult {
    match handle.join() {
        Ok(Ok(())) => {
            info!("{driver} worker {id} exited successfully");
            WorkerEndResult::Ok
        }
        Ok(Err(e)) => {
            error!("{driver} worker {id} exited with error: {e}");
            WorkerEndResult::Failed(e.to_string())
        }
        Err(panic_payload) => {
            let msg = format!("{driver} worker {id} panicked {panic_payload:?}");
            error!("{msg}");
            WorkerEndResult::Panicked(msg)
        }
    }
}

/// Check if the `Subsystem` got cancelled (and we must shutdown). If so,
/// join all of the workers. This will wait for all workers to finish.
/// Returns `true` if the subsystem was cancelled and `false` otherwise.
fn must_run<E: Display>(
    driver: &str,
    subsystem: &Subsystem,
    monitors: &mut [WorkerMonitor<'_, E>],
    workers_status: &mut [WorkerStatus],
) -> bool {
    // we must run if were not cancelled
    if !subsystem.is_cancelled() {
        return true;
    }
    info!("Got cancelled. Will join {driver} worker(s)");
    for (pos, monitor) in monitors.iter_mut().enumerate() {
        if let Some(handle) = monitor.handle.take() {
            let status = &mut workers_status[pos];
            status.state = WorkerState::Terminated(join_worker(driver, monitor.id, handle));
        } else {
            info!(
                "Not joining {driver} worker {} (ended before shutdown)",
                monitor.id
            );
        }
    }
    info!("All {driver} workers joined. Supervisor should terminate soon...");
    false
}

/// Check the activity of the rx tasks for a worker (watchdog, if `check_watchdog` is true)
/// from its `WorkerMonitor` and update the corresponding `WorkerStatus`
#[allow(clippy::cast_precision_loss)]
fn check_worker_rx_tasks<E>(
    driver: &str,
    monitor: &WorkerMonitor<'_, E>,
    wk_status: &mut WorkerStatus,
    check_watchdog: bool,
) {
    for (idx, task) in monitor.rx_tasks.iter().enumerate() {
        let rx_task_status = &mut wk_status.rx_tasks[idx];
        debug_assert_eq!(rx_task_status.ifname, task.ifname);

        // check the rx task activity, and watchdog, if we've been told to do so
        let (counters, activity) = task.watchdog.check_and_clear(check_watchdog);

        // The counters have been cleared by the read above, so accumulate them whatever
        // the activity: dropping them here would lose them for good.
        rx_task_status.accumulate(&counters);

        // update the rx task status
        rx_task_status.activity = activity;
        match rx_task_status.activity {
            Activity::Stuck => {
                rx_task_status.misses += 1;
                rx_task_status.pps = 0.0;
                error!(
                    "RX task for interface {} in {driver} worker {} did not pat the watchdog",
                    task.ifname, monitor.id
                );
            }
            Activity::Active => {
                rx_task_status.pps = counters.rx as f64 / f64::from(TASK_POLL_PERIOD);
                debug!(
                    "{driver} worker {} on {}: rx {} ({:.0} pps), tx {}, pipeline drops {}, \
                     tx drops {}, punt drops {}, parse errors {}",
                    monitor.id,
                    task.ifname,
                    counters.rx,
                    rx_task_status.pps,
                    counters.tx,
                    counters.ppline_drops,
                    counters.tx_drops,
                    counters.punt_drops,
                    counters.parse_errors,
                );
            }
            Activity::Idle => rx_task_status.pps = 0.0,
        }
    }
}
