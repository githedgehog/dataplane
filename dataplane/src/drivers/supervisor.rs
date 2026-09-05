// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Supervision of a driver's worker threads.
//!
//! Whatever a driver does with packets, its workers are watched the same way:
//! a worker that ends is joined and reported, one whose rx tasks stop patting
//! their watchdogs is called stuck, and the counters they report are published
//! for the CLI to show. [`supervise`] is that loop, and runs on a thread of
//! the driver's own until the workers subsystem is cancelled or every worker
//! has ended.

#![deny(
    unsafe_code,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::ops::Add;
use std::time::{Duration, Instant};

use concurrency::sync::Arc;
use concurrency::thread;
use concurrency::thread::ScopedJoinHandle;
use lifecycle::Subsystem;
use tracing::{error, info};

use super::status::{
    DriverParams, DriverStatus, DriverStatusWriter, RxTaskStatus, WorkerEndResult, WorkerId,
    WorkerState, WorkerStatus,
};
use super::watchdog::{Activity, Watchdog};

/// What the supervisor watches one of a worker's rx tasks through.
#[derive(Clone)]
pub(crate) struct WorkerIfaceMonitor {
    /// Interface the rx task reads from.
    pub(crate) ifname: Arc<str>,
    /// Watchdog the rx task pats and reports its counters on.
    pub(crate) watchdog: Watchdog,
}

impl WorkerIfaceMonitor {
    #[must_use]
    pub(crate) fn new(ifname: &str) -> Self {
        Self {
            ifname: Arc::from(ifname),
            watchdog: Watchdog::new(),
        }
    }
}

/// What the supervisor watches one worker through: its thread, and a monitor
/// for each of the rx tasks it runs.
pub(crate) struct WorkerMonitor<'scope> {
    /// Which worker this is.
    pub(crate) id: WorkerId,
    /// The worker's thread, taken when it is joined.
    pub(crate) handle: Option<ScopedJoinHandle<'scope, Result<(), std::io::Error>>>,
    /// One monitor per interface the worker reads from.
    pub(crate) intf: Vec<WorkerIfaceMonitor>,
}

impl<'scope> WorkerMonitor<'scope> {
    #[must_use]
    pub(crate) fn new(
        id: WorkerId,
        handle: ScopedJoinHandle<'scope, Result<(), std::io::Error>>,
        intf: Vec<WorkerIfaceMonitor>,
    ) -> Self {
        Self {
            id,
            handle: Some(handle),
            intf,
        }
    }
}

/// Join a worker, log how its thread ended, and report the outcome.
///
/// Only call this once the worker has ended, or is about to because it was
/// cancelled: otherwise it blocks the supervisor.
fn join_worker(
    id: WorkerId,
    handle: ScopedJoinHandle<'_, Result<(), std::io::Error>>,
) -> WorkerEndResult {
    match handle.join() {
        Ok(Ok(())) => {
            info!("Worker {id} exited successfully");
            WorkerEndResult::Ok
        }
        Ok(Err(e)) => {
            error!("Worker {id} exited with error: {e}");
            WorkerEndResult::Failed(e.to_string())
        }
        Err(panic_payload) => {
            let msg = format!("Worker {id} panicked {panic_payload:?}");
            error!("Worker {id} panicked: {msg}");
            WorkerEndResult::Panicked(msg)
        }
    }
}

/// Watch `monitors` until the subsystem is cancelled or no worker is left
/// running, publishing the status of each pass through `status_writer`.
///
/// Worker fatal reporting is not done here: each worker thread holds an
/// `ExitGuard` that reports for it.
pub(crate) fn supervise(
    params: DriverParams,
    subsystem: &Subsystem,
    monitors: &mut [WorkerMonitor<'_>],
    status_writer: &DriverStatusWriter,
) {
    let check_period = Duration::from_secs(u64::from(params.check_period));
    let poll_period = Duration::from_secs(u64::from(params.poll_period));

    // One WorkerStatus per monitor, holding one RxTaskStatus per interface.
    // These are the running totals: the watchdogs are cleared as they are read.
    let mut workers_status: Vec<WorkerStatus> = monitors
        .iter()
        .map(|monitor| {
            let mut status = WorkerStatus::new(monitor.id);
            status.rx_tasks = monitor
                .intf
                .iter()
                .map(|i| RxTaskStatus::new(i.ifname.clone()))
                .collect();
            status
        })
        .collect();

    // When the watchdogs are next due to be checked. Activity is sampled far
    // more often than that, so that the reported rate is a recent one.
    let mut next_watchdog_check = Instant::now().add(check_period);

    loop {
        if !must_run(subsystem, monitors, &mut workers_status) {
            break;
        }

        let now = Instant::now();
        let check_watchdog = now >= next_watchdog_check;
        if check_watchdog {
            while next_watchdog_check <= now {
                next_watchdog_check = next_watchdog_check.add(check_period);
            }
        }

        let mut any_running = false;
        for (pos, monitor) in monitors.iter_mut().enumerate() {
            let Some(wk_status) = workers_status.get_mut(pos) else {
                continue;
            };

            let Some(handle) = monitor.handle.take() else {
                // Already joined on an earlier pass. The monitor stays in the
                // list so the worker keeps its place in the report.
                continue;
            };

            if handle.is_finished() {
                wk_status.state = WorkerState::Terminated(join_worker(monitor.id, handle));
                for rx_task in &mut wk_status.rx_tasks {
                    rx_task.activity = Activity::Idle;
                    rx_task.pps = 0.0;
                }
            } else {
                wk_status.state = WorkerState::Running;
                monitor.handle = Some(handle);
                any_running = true;
                check_worker_rx_tasks(params, monitor, wk_status, check_watchdog);
            }
        }

        if !any_running {
            error!("No more workers are running!!. Stopping...");
            break;
        }

        status_writer.publish(DriverStatus {
            params,
            workers: workers_status.clone(),
        });

        thread::sleep(poll_period);
    }

    // Publish once more on the way out, so the last state is the one a reader
    // sees rather than whatever the final pass happened to leave behind.
    status_writer.publish(DriverStatus {
        params,
        workers: workers_status,
    });
}

/// Whether the supervisor should keep going. If the subsystem was cancelled,
/// join every worker still running first: this waits for all of them.
fn must_run(
    subsystem: &Subsystem,
    monitors: &mut [WorkerMonitor<'_>],
    workers_status: &mut [WorkerStatus],
) -> bool {
    if !subsystem.is_cancelled() {
        return true;
    }

    info!("Got cancelled. Will join worker(s)");
    for (pos, monitor) in monitors.iter_mut().enumerate() {
        match (monitor.handle.take(), workers_status.get_mut(pos)) {
            (Some(handle), Some(status)) => {
                status.state = WorkerState::Terminated(join_worker(monitor.id, handle));
            }
            (Some(handle), None) => {
                let _ = join_worker(monitor.id, handle);
            }
            (None, _) => info!("Not joining worker {} (ended before shutdown)", monitor.id),
        }
    }
    info!("All workers joined. Supervisor should terminate soon...");
    false
}

/// Read the watchdog of each of a worker's rx tasks and fold what it reports
/// into that task's status.
#[allow(clippy::cast_precision_loss)] // packet counts stay well within f64
fn check_worker_rx_tasks(
    params: DriverParams,
    monitor: &WorkerMonitor,
    wk_status: &mut WorkerStatus,
    check_watchdog: bool,
) {
    for (idx, ifm) in monitor.intf.iter().enumerate() {
        let Some(rx_task_status) = wk_status.rx_tasks.get_mut(idx) else {
            continue;
        };
        debug_assert_eq!(rx_task_status.ifname, ifm.ifname);

        let (counters, activity) = ifm.watchdog.check_and_clear(check_watchdog);

        // Reading the watchdog cleared it, so the counters have to be
        // accumulated whatever the activity: dropping them loses them.
        rx_task_status.accumulate(&counters);

        rx_task_status.activity = activity;
        match rx_task_status.activity {
            Activity::Stuck => {
                rx_task_status.misses += 1;
                rx_task_status.pps = 0.0;
                error!(
                    "RX task for interface {} in worker {} did not pat the watchdog",
                    ifm.ifname, monitor.id
                );
            }
            Activity::Active => {
                rx_task_status.pps = counters.rx as f64 / f64::from(params.poll_period);
            }
            Activity::Idle => rx_task_status.pps = 0.0,
        }
    }
}
