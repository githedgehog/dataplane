// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Worker supervision shared by the packet drivers.
//!
//! A driver spawns its workers, hands the supervisor one [`WorkerMonitor`] per worker, and
//! the supervisor thread then samples each rx task's [`Watchdog`], publishes a
//! [`DriverStatus`], and joins the workers when they end or the subsystem is cancelled.
//! The status carries each rx task's totals as they stand, not as of the last sample: only
//! activity and rates are the supervisor's to work out.

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
    DriverStatus, DriverStatusWriter, RxQueue, RxTaskStatus, WorkerEndResult, WorkerId,
    WorkerState, WorkerStatus,
};
use super::watchdog::{Activity, RxCounters, Watchdog};

trace_target!("driver-supervisor", LevelFilter::INFO, &["driver"]);

/// How often, in seconds, an rx task pats its watchdog even if no activity (worst case)
pub(crate) const TASK_PAT_PERIOD: u16 = 2;

/// Slack, in seconds, on top of the pat period before a missed pat is treated as a deadline miss.
pub(crate) const TASK_GRACE_PERIOD: u16 = 4;

/// Interval, in seconds, at which the supervisor will check rx task watchdogs
pub(crate) const TASK_CHECK_PERIOD: u16 = TASK_PAT_PERIOD + TASK_GRACE_PERIOD;

/// Interval, in seconds, at which the supervisor checks rx task activity, ignoring watchdogs
pub(crate) const TASK_POLL_PERIOD: u16 = 1;

/// The supervisor's view of one rx task: the port and queue it serves, the watchdog it reports
/// on, and the totals the supervisor last saw there.
#[derive(Clone)]
pub(crate) struct RxTaskMonitor {
    /// The port, by its configured interface name.
    pub(crate) port: Arc<str>,
    pub(crate) queue: RxQueue,
    pub(crate) watchdog: Watchdog,
    seen: RxCounters,
}

impl RxTaskMonitor {
    #[must_use]
    pub(crate) fn new(port: &str, queue: RxQueue) -> Self {
        Self {
            port: Arc::from(port),
            queue,
            watchdog: Watchdog::new(),
            seen: RxCounters::default(),
        }
    }

    /// What the task counted since the supervisor last asked.
    fn counted(&mut self) -> RxCounters {
        let totals = self.watchdog.totals();
        let counted = totals.since(&self.seen);
        self.seen = totals;
        counted
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
/// `publish_counters` runs before the first poll, on each poll, and once after all workers have
/// stopped.
///
/// # Errors
///
/// Returns an error if the supervisor thread cannot be spawned.
pub(crate) fn spawn_supervisor<'scope, E: Display + Send + Sync + 'scope>(
    scope: &'scope thread::Scope<'scope, '_>,
    driver: &'static str,
    max_rx_batch: usize,
    subsystem: &Subsystem,
    mut monitors: Vec<WorkerMonitor<'scope, E>>,
    status_writer: DriverStatusWriter,
    mut publish_counters: impl FnMut() + Send + 'scope,
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
                        .map(|t| RxTaskStatus::new(t.port.clone(), t.queue, t.watchdog.reader()))
                        .collect();
                    ws
                })
                .collect();

            // The workers may have counted already. That is in their totals, but not in a rate:
            // the first is over the first poll period alone.
            for task in monitors.iter_mut().flat_map(|m| &mut m.rx_tasks) {
                task.counted();
            }
            let mut last_poll = clock::now();

            // the next instant when the rx tasks watchdogs should be checked.
            let mut next_watchdog_check = last_poll.add(check_period);

            // Before the first poll, so that the workers can be seen from the start.
            publish_counters();
            status_writer.publish(DriverStatus {
                max_rx_batch,
                workers: workers_status.clone(),
            });

            loop {
                // sleep for the poll period
                thread::sleep(poll_period);

                // check if we must run. Otherwise (got cancelled) join all workers
                if !must_run(driver, &subsystem, &mut monitors, &mut workers_status) {
                    break;
                }

                // check the current time and decide if we should check whether the rx tasks patted the watchdogs.
                // If so, compute the next time we should check them again in the future.
                let now = clock::now();
                // Rates are over the time that actually passed, which a busy machine stretches.
                let elapsed = now.saturating_duration_since(last_poll);
                last_poll = now;
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
                            check_worker_rx_tasks(
                                driver,
                                monitor.id,
                                &mut monitor.rx_tasks,
                                wk_status,
                                check_watchdog,
                                elapsed,
                            );
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

                publish_counters();

                // publish the status of the driver
                status_writer.publish(DriverStatus {
                    max_rx_batch,
                    workers: workers_status.clone(),
                });
            }

            publish_counters();

            // update status on termination. This is in case we
            // want to log the last state
            let last = DriverStatus {
                max_rx_batch,
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

/// Check the activity of a worker's rx tasks (and their watchdogs, if `check_watchdog` is true)
/// and update the corresponding `WorkerStatus`, with rates over `elapsed`, the time since the
/// last check.
#[allow(clippy::cast_precision_loss)]
fn check_worker_rx_tasks(
    driver: &str,
    worker: WorkerId,
    rx_tasks: &mut [RxTaskMonitor],
    wk_status: &mut WorkerStatus,
    check_watchdog: bool,
    elapsed: Duration,
) {
    for (task, rx_task_status) in rx_tasks.iter_mut().zip(&mut wk_status.rx_tasks) {
        debug_assert_eq!(
            (&rx_task_status.port, rx_task_status.queue),
            (&task.port, task.queue)
        );

        let counted = task.counted();
        // Only a check can find a watchdog unpatted: unchecked, it is taken to have been.
        let patted = !check_watchdog || task.watchdog.check_and_rearm();

        // update the rx task status
        rx_task_status.activity = Activity::of(&counted, patted);
        match rx_task_status.activity {
            Activity::Stuck => {
                rx_task_status.misses += 1;
                rx_task_status.pps = 0.0;
                error!(
                    "RX task for the {} queue of {} in {driver} worker {worker} did not pat the \
                     watchdog",
                    task.queue.name(),
                    task.port
                );
            }
            Activity::Active => {
                rx_task_status.pps = if elapsed.is_zero() {
                    0.0
                } else {
                    counted.rx as f64 / elapsed.as_secs_f64()
                };
                debug!(
                    "{driver} worker {worker} on {} ({}): rx {} ({:.0} pps), tx {}, pipeline \
                     drops {}, tx drops {}, punt drops {}, parse errors {}",
                    task.port,
                    task.queue.name(),
                    counted.rx,
                    rx_task_status.pps,
                    counted.tx,
                    counted.ppline_drops,
                    counted.tx_drops,
                    counted.punt_drops,
                    counted.parse_errors,
                );
            }
            Activity::Idle => rx_task_status.pps = 0.0,
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::*;

    /// A rate is what the task received since the last check, over the time elapsed since then.
    /// What it counted before -- before the supervisor started, say -- is in its totals but not in
    /// the rate.
    #[test]
    fn a_rate_is_over_what_was_received_since_the_last_check() {
        bolero::check!()
            .with_type::<(u32, u32, u16)>()
            .for_each(|(before, since, ms)| {
                let elapsed = Duration::from_millis(u64::from(*ms) + 1);
                let mut tasks = vec![RxTaskMonitor::new("eth0", RxQueue::Data)];
                let mut status = WorkerStatus::new(0);
                status.rx_tasks = vec![RxTaskStatus::new(
                    tasks[0].port.clone(),
                    tasks[0].queue,
                    tasks[0].watchdog.reader(),
                )];
                let receive = |rx: u32| RxCounters {
                    rx: rx.into(),
                    ..RxCounters::default()
                };

                tasks[0].watchdog.record(&receive(*before));
                // As the supervisor does before its first poll.
                tasks[0].counted();
                tasks[0].watchdog.record(&receive(*since));
                check_worker_rx_tasks("test", 0, &mut tasks, &mut status, false, elapsed);

                let task = &status.rx_tasks[0];
                let expected = f64::from(*since) / elapsed.as_secs_f64();
                assert!(
                    (task.pps - expected).abs() <= expected * 1e-12,
                    "{} pps, expected {expected}",
                    task.pps
                );
                let busy = *since > 0;
                assert_eq!(task.activity == Activity::Active, busy);
                assert_eq!(
                    task.totals.load().rx,
                    u64::from(*before) + u64::from(*since)
                );
            });
    }
}
