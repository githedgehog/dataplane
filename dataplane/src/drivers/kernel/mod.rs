// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Kernel dataplane driver

#![deny(
    unsafe_code,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

mod fanout;
mod kif;
mod worker;

use std::ops::Add;
use std::time::{Duration, Instant};

use concurrency::sync::Arc;
use concurrency::thread;
#[allow(unused_imports)] // used under loom/shuttle backends
use concurrency::thread::BuilderExt;
use concurrency::thread::ScopedJoinHandle;
use lifecycle::Subsystem;
use net::buffer::test_buffer::TestBuffer;
use pipeline::DynPipeline;
use tracectl::trace_target;
#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

use super::DriverError;
use super::status::{
    DriverStatus, DriverStatusWriter, RxTaskStatus, WorkerEndResult, WorkerId, WorkerState,
    WorkerStatus,
};
use super::watchdog::{Activity, Watchdog};
use kif::{Kif, bring_kifs_up};
use worker::Worker;

trace_target!("kernel-driver", LevelFilter::INFO, &["driver"]);

/// AF_PACKET-based kernel driver. Spawns N workers with symmetric-hash
/// fanout and per-worker pipelines.
pub struct DriverKernel;

#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::cast_precision_loss)]
impl DriverKernel {
    /// How often, in seconds, a worker interface pats its watchdog even if no activity (worst case)
    pub(crate) const TASK_PAT_PERIOD: u16 = 2;

    /// Slack, in seconds, on top of the pat period before a missed pat is treated as a deadline miss.
    pub(crate) const TASK_GRACE_PERIOD: u16 = 4;

    /// Interval, in seconds, at which the supervisor will check rx task watchdogs
    pub(crate) const TASK_CHECK_PERIOD: u16 = Self::TASK_PAT_PERIOD + Self::TASK_GRACE_PERIOD;

    /// Interval, in seconds, at which the supervisor checks rx task activity, ignoring watchdogs
    pub(crate) const TASK_POLL_PERIOD: u16 = 1;

    /// Max number of packets that a RX task will attempt to read in one go
    pub(crate) const MAX_RX_PKT_BATCH: usize = 128;

    /// Spawn `num_workers` worker threads into `scope`, each with its own
    /// pipeline. Bails on the first spawn failure; workers that did spawn
    /// drain via the scope join.
    fn spawn_workers_scoped<'scope>(
        scope: &'scope thread::Scope<'scope, '_>,
        workers_subsystem: &Subsystem,
        num_workers: usize,
        setup_pipeline: &Arc<dyn Send + Sync + Fn() -> DynPipeline<TestBuffer>>,
        interfaces: &[Kif],
    ) -> Result<Vec<WorkerMonitor<'scope>>, std::io::Error> {
        let mut monitors: Vec<WorkerMonitor> = Vec::with_capacity(num_workers);

        info!("Spawning {num_workers} workers");

        for workerid in 0..num_workers {
            // create worker
            let worker = Worker::new(
                workerid,
                num_workers,
                setup_pipeline,
                workers_subsystem.clone(),
            );
            // start worker. We get a `WorkerMonitor` on success, which includes
            // an interface monitor for each of its rx tasks
            let wk_monitor = worker.start(scope, interfaces)?;

            // store monitor
            monitors.push(wk_monitor);
        }
        Ok(monitors)
    }

    /// Spawn worker threads + supervisor into `scope`. The scope joins
    /// all driver threads on closure return.
    ///
    /// # Errors
    /// Returns [`DriverError`] on interface setup or thread spawn failure.
    #[allow(clippy::too_many_lines)]
    pub fn start<'scope>(
        scope: &'scope thread::Scope<'scope, '_>,
        workers_subsystem: &Subsystem,
        args: impl IntoIterator<Item = impl AsRef<str> + Clone>,
        num_workers: usize,
        setup_pipeline: &Arc<dyn Send + Sync + Fn() -> DynPipeline<TestBuffer>>,
        status_writer: DriverStatusWriter,
    ) -> Result<(), DriverError> {
        // A current_thread runtime built inside another tokio runtime
        // panics; catch nesting in debug.
        debug_assert!(
            tokio::runtime::Handle::try_current().is_err(),
            "DriverKernel::start must not be invoked from within a tokio runtime context"
        );

        info!("Collecting interfaces from config");
        let interfaces = kif::get_interfaces(args)?;

        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(bring_kifs_up(interfaces.as_slice()))?;

        let mut worker_monitors = Self::spawn_workers_scoped(
            scope,
            workers_subsystem,
            num_workers,
            setup_pipeline,
            interfaces.as_slice(),
        )?;
        debug_assert_eq!(worker_monitors.len(), num_workers);

        let supervisor_subsystem = workers_subsystem.clone();

        // The supervisor loops over worker monitors (which include join handles) and
        // just joins-and-logs on termination; worker fatal reporting is handled by
        // the `ExitGuard` inside each worker thread.
        let supervisor_builder =
            thread::Builder::new().name("kernel-worker-supervisor".to_string());

        // closure to join a worker, log its outcome, and report how it ended
        let join_and_log = |id: WorkerId,
                            handle: ScopedJoinHandle<'scope, Result<(), std::io::Error>>|
         -> WorkerEndResult {
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
        };

        // the two time intervals that matter for liveness detection
        let check_period = Duration::from_secs(u64::from(Self::TASK_CHECK_PERIOD));
        let poll_period = Duration::from_secs(u64::from(Self::TASK_POLL_PERIOD));

        supervisor_builder.spawn_scoped(scope, move || {
            info!("Worker supervisor started");

            // build a vector of worker status from their monitors to expose their state outside of this thread
            // each WorkerStatus contains a list of RxTaskStatus
            let mut workers_status: Vec<WorkerStatus> = worker_monitors.iter().map(|monitor| {
                let mut ws = WorkerStatus::new(monitor.id);
                ws.rx_tasks = monitor.intf.iter().map(|i|RxTaskStatus::new(i.ifname.clone())).collect();
                ws
            }).collect();

            // the next instant when the rx tasks watchdogs should be checked.
            let mut next_watchdog_check = Instant::now().add(check_period);

            loop {
                // If we got cancelled (graceful stop), join all workers and break, ending the supervisor
                if supervisor_subsystem.is_cancelled() {
                    info!("Got cancelled. Will join {} worker(s)", worker_monitors.len());
                    for monitor in &mut worker_monitors {
                        if let Some(handle) = monitor.handle.take() {
                            join_and_log(monitor.id, handle);
                        }
                    }
                    info!("All workers joined. Worker supervisor should terminate soon.");
                    break;
                }

                // check time and decide if we should check whether the rx tasks patted the watchdogs.
                // If so, compute the next time we should check them again in the future.
                let now = Instant::now();
                let check_watchdog = now >= next_watchdog_check;
                if check_watchdog {
                    while next_watchdog_check <= now {
                        next_watchdog_check = next_watchdog_check.add(check_period);
                    }
                }

                let mut any_running = false;
                for (pos, monitor) in worker_monitors.iter_mut().enumerate() {
                    // get status object for the worker/monitor
                    let wk_status = &mut workers_status[pos];

                    if let Some(handle) = monitor.handle.take() {
                        if handle.is_finished() {
                            let result = join_and_log(monitor.id, handle);
                            wk_status.state = WorkerState::Terminated(result);
                            wk_status.rx_tasks.iter_mut().for_each(|r|{
                                    // cosmetic, clear all rx task "instantaneous" state
                                    r.activity = Activity::Idle;
                                    r.pps = 0.0;
                                }
                            );
                        } else {
                            // Update the worker state
                            wk_status.state = WorkerState::Running; // the worker is running
                            monitor.handle = Some(handle); // restore handle (worker is still running)
                            any_running = true; // there is at least this worker running

                            // check the worker's rx tasks and update the corresponding status. The check can
                            // be a regular activity check or a watchdog check, which will check and rearm the
                            // watchdog and complain if the task did not pat it.
                            for (idx, ifm) in monitor.intf.iter().enumerate() {
                                let rx_task_status = &mut wk_status.rx_tasks[idx];
                                debug_assert_eq!(rx_task_status.ifname, ifm.ifname);

                                // check the rx task activity, and watchdog, if we've been told to do so
                                let activity = ifm.watchdog.check_and_clear(check_watchdog);

                                // update the rx task status
                                rx_task_status.activity = activity;
                                match &rx_task_status.activity {
                                    Activity::Stuck => {
                                        rx_task_status.misses += 1;
                                        rx_task_status.pps = 0.0;
                                        error!("RX task for interface {} in worker {} did not pat the watchdog", ifm.ifname, monitor.id);
                                    }
                                    Activity::Active(record) => {
                                        rx_task_status.total_rx += record.rx;
                                        rx_task_status.total_tx += record.tx;
                                        rx_task_status.total_ppline_drops += record.ppline_drops;
                                        rx_task_status.total_tx_drops += record.tx_drops;
                                        rx_task_status.pps = record.rx as f64 / f64::from(Self::TASK_POLL_PERIOD);
                                    }
                                    Activity::Idle => rx_task_status.pps = 0.0,
                                }
                            }
                        }
                    } else {
                        // A worker monitor without a handle means that the worker was joined already
                        // We do nothing in this case. The monitor is kept in the list.
                    }
                }

                // publish the status of the driver
                status_writer.publish(DriverStatus { workers: workers_status.clone() });

                // No more workers running (unexpectedly, there was no cancellation).
                // If there was cancellation, we'll notice in the next round and deal with it.
                if !any_running {
                    error!("No more workers are running!!. Stopping...");
                    break;
                }

                // sleep for the poll period
                thread::sleep(poll_period);
            }
            info!("Worker supervisor thread terminated");
        })?;
        info!("Kernel driver started successfully");
        Ok(())
    }
}

#[derive(Clone)]
struct WorkerIfaceMonitor {
    ifname: Arc<str>,
    watchdog: Watchdog,
}

impl WorkerIfaceMonitor {
    #[must_use]
    fn new(ifname: &str) -> Self {
        Self {
            ifname: Arc::from(ifname),
            watchdog: Watchdog::new(),
        }
    }
}

struct WorkerMonitor<'scope> {
    id: WorkerId,
    handle: Option<ScopedJoinHandle<'scope, Result<(), std::io::Error>>>,
    intf: Vec<WorkerIfaceMonitor>,
}
impl<'scope> WorkerMonitor<'scope> {
    #[must_use]
    fn new(
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
