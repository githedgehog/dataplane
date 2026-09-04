// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK dataplane driver.
//!
//! Poll-mode, run-to-completion: each worker owns one receive and one transmit queue on every port,
//! and for each burst it receives it runs the pipeline and transmits the result from the same
//! thread. Nothing is handed between threads, which is what the buffer type requires -- an `Mbuf`
//! is `!Send`, because it is a bare pointer into a mempool with nothing tying its lifetime to that
//! pool's, and letting one cross a thread boundary unguarded is a use-after-free waiting for
//! teardown to happen.
//!
//! # Shape, and how it differs from the kernel driver
//!
//! [`DriverKernel`](crate::drivers::kernel::DriverKernel) gives each worker a tokio runtime and one
//! async rx task per interface, because `AF_PACKET` reads block. A poll-mode driver has nothing to
//! await: `rte_eth_rx_burst` returns immediately with however many frames were ready. So a worker
//! here is a plain thread running a loop, with no runtime, and one worker services every port
//! rather than one task per interface.
//!
//! # What this does not do yet
//!
//! - **RSS is off**, so every frame lands on receive queue 0 and one worker does all the work. The
//!   per-worker queues are real and exclusively owned either way; spreading across them needs a
//!   *symmetric* hash key, so that both directions of a flow reach the same worker and the flow
//!   table stays per-worker-coherent. That is its own change, and picking the key wrong is a
//!   correctness bug rather than a performance one.
//! - **Ports must have a kernel netdev.** The pipeline names interfaces by kernel `ifindex`, and
//!   this driver takes that from `rte_eth_dev_info.if_index`. That is populated for a bifurcated
//!   driver such as mlx5, where `mlx5_core` keeps the netdev while DPDK attaches through the RDMA
//!   verbs interface. A port bound to `vfio-pci` has no netdev and reports 0, and is rejected at
//!   bring-up with a clear error rather than silently mapping onto interface 0. Supporting those
//!   ports means giving the configuration layer a way to name a port that is not a netdev.
//! - **No hairpin or offloaded forwarding.** Every packet goes through the software pipeline.

mod port;
mod worker;

use std::time::Duration;

use concurrency::sync::Arc;
use concurrency::thread;
#[allow(unused_imports)] // used under loom/shuttle backends
use concurrency::thread::BuilderExt;
use concurrency::thread::ScopedJoinHandle;
use dpdk::mem::Mbuf;
use lifecycle::Subsystem;
use pipeline::DynPipeline;
use tracectl::trace_target;
use tracing::{debug, error, info};

use super::DriverError;
use super::status::{
    DriverStatus, DriverStatusWriter, RxTaskStatus, WorkerEndResult, WorkerId, WorkerState,
    WorkerStatus,
};
use super::watchdog::{Activity, Watchdog};

pub(crate) use port::Port;

trace_target!("dpdk-driver", LevelFilter::INFO, &["driver"]);

/// Poll-mode DPDK driver.
pub struct DriverDpdk;

#[allow(clippy::cast_precision_loss)]
impl DriverDpdk {
    /// Interval, in seconds, at which the supervisor samples worker liveness.
    pub(crate) const TASK_POLL_PERIOD: u16 = 1;

    /// How often, in seconds, a worker is expected to record activity even when idle.
    pub(crate) const TASK_PAT_PERIOD: u16 = 2;

    /// Slack on top of the pat period before a missed pat counts as a deadline miss.
    pub(crate) const TASK_GRACE_PERIOD: u16 = 4;

    /// Interval, in seconds, at which the supervisor checks worker watchdogs.
    pub(crate) const TASK_CHECK_PERIOD: u16 = Self::TASK_PAT_PERIOD + Self::TASK_GRACE_PERIOD;

    /// Bring up every port, deal their queues out to `num_workers` workers, and start them.
    ///
    /// `ports` are configured and started before any worker exists, and the queue handles are moved
    /// into the workers by value. The `'eal` borrow is what keeps this honest: the devices, their
    /// queues and every mbuf drawn from their pools are branded with the EAL's lifetime, so none of
    /// it can outlive the EAL that owns the memory it all lives in.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError`] if a port cannot be brought up, if the queue split fails, or if a
    /// worker thread cannot be spawned.
    pub fn start<'p, 'scope>(
        scope: &'scope thread::Scope<'scope, '_>,
        workers_subsystem: &Subsystem,
        ports: &'p [Port<'_>],
        num_workers: usize,
        setup_pipeline: &Arc<dyn Send + Sync + Fn() -> DynPipeline<'p, Mbuf<'p>> + 'p>,
        status_writer: DriverStatusWriter,
    ) -> Result<(), DriverError>
    where
        'p: 'scope,
    {
        debug_assert!(
            tokio::runtime::Handle::try_current().is_err(),
            "DriverDpdk::start must not be invoked from within a tokio runtime context"
        );

        if ports.is_empty() {
            return Err(DriverError::PortSetup(
                "no DPDK ports were configured; nothing to drive".to_string(),
            ));
        }

        let num_workers = u16::try_from(num_workers).map_err(|_| {
            DriverError::PortSetup(format!(
                "{num_workers} workers is more than a port can queue"
            ))
        })?;
        if num_workers == 0 {
            return Err(DriverError::PortSetup(
                "a DPDK driver with no workers would poll nothing".to_string(),
            ));
        }

        let dealt = port::deal_queues(ports, num_workers)?;

        info!(
            "Starting {num_workers} DPDK worker(s) across {} port(s)",
            ports.len()
        );

        let mut monitors = Vec::with_capacity(dealt.len());
        for (id, queues) in dealt.into_iter().enumerate() {
            let watchdog = Watchdog::new();
            let port_names: Vec<Arc<str>> =
                queues.iter().map(|q| Arc::from(q.name.as_str())).collect();
            let worker = worker::Worker::new(id, queues, watchdog.clone());

            let subsystem = workers_subsystem.clone();
            let setup_pipeline = setup_pipeline.clone();
            let handle = thread::Builder::new()
                .name(format!("dpdk-worker-{id}"))
                .spawn_scoped(scope, move || {
                    worker.run(&subsystem, &setup_pipeline);
                })
                .map_err(|e| {
                    DriverError::PortSetup(format!("failed to spawn DPDK worker {id}: {e}"))
                })?;

            monitors.push(WorkerMonitor {
                id,
                handle: Some(handle),
                watchdog,
                port_names,
            });
        }

        Self::spawn_supervisor(scope, workers_subsystem, monitors, status_writer)
    }

    /// The supervisor thread: samples worker liveness, publishes status, joins on cancellation.
    #[allow(clippy::too_many_lines)]
    fn spawn_supervisor<'scope>(
        scope: &'scope thread::Scope<'scope, '_>,
        workers_subsystem: &Subsystem,
        mut monitors: Vec<WorkerMonitor<'scope>>,
        status_writer: DriverStatusWriter,
    ) -> Result<(), DriverError> {
        let subsystem = workers_subsystem.clone();
        let check_period = Duration::from_secs(u64::from(Self::TASK_CHECK_PERIOD));
        let poll_period = Duration::from_secs(u64::from(Self::TASK_POLL_PERIOD));

        thread::Builder::new()
            .name("dpdk-worker-supervisor".to_string())
            .spawn_scoped(scope, move || {
                info!("DPDK worker supervisor started");

                let mut statuses: Vec<WorkerStatus> = monitors
                    .iter()
                    .map(|m| {
                        let mut status = WorkerStatus::new(m.id);
                        status.rx_tasks = m
                            .port_names
                            .iter()
                            .map(|name| RxTaskStatus::new(name.clone()))
                            .collect();
                        status
                    })
                    .collect();

                let mut next_watchdog_check = std::time::Instant::now() + check_period;

                loop {
                    if subsystem.is_cancelled() {
                        info!("Got cancelled. Will join DPDK worker(s)");
                        for (pos, monitor) in monitors.iter_mut().enumerate() {
                            if let Some(handle) = monitor.handle.take() {
                                statuses[pos].state =
                                    WorkerState::Terminated(join_worker(monitor.id, handle));
                            }
                        }
                        break;
                    }

                    let now = std::time::Instant::now();
                    let check_watchdog = now >= next_watchdog_check;
                    if check_watchdog {
                        while next_watchdog_check <= now {
                            next_watchdog_check += check_period;
                        }
                    }

                    let mut any_running = false;
                    for (pos, monitor) in monitors.iter_mut().enumerate() {
                        let status = &mut statuses[pos];
                        let Some(handle) = monitor.handle.take() else {
                            continue;
                        };
                        if handle.is_finished() {
                            status.state = WorkerState::Terminated(join_worker(monitor.id, handle));
                            for task in &mut status.rx_tasks {
                                task.activity = Activity::Idle;
                                task.pps = 0.0;
                            }
                            continue;
                        }
                        monitor.handle = Some(handle);
                        status.state = WorkerState::Running;
                        any_running = true;

                        // One watchdog per worker, but the status model is per rx task, so the
                        // worker's counters are attributed to its first port. A poll-mode worker
                        // services every port from one loop and does not have per-port liveness to
                        // report; splitting the counters would mean per-queue accounting the
                        // datapath does not currently do.
                        let (counters, activity) = monitor.watchdog.check_and_clear(check_watchdog);
                        if let Some(task) = status.rx_tasks.first_mut() {
                            task.accumulate(&counters);
                            task.activity = activity;
                            match activity {
                                Activity::Stuck => {
                                    task.misses += 1;
                                    task.pps = 0.0;
                                    error!("DPDK worker {} did not pat its watchdog", monitor.id);
                                }
                                Activity::Active => {
                                    task.pps =
                                        counters.rx as f64 / f64::from(Self::TASK_POLL_PERIOD);
                                    debug!(
                                        "DPDK worker {}: rx {} ({:.0} pps), tx {}, pipeline drops \
                                         {}, tx drops {}, parse errors {}",
                                        monitor.id,
                                        counters.rx,
                                        task.pps,
                                        counters.tx,
                                        counters.ppline_drops,
                                        counters.tx_drops,
                                        counters.parse_errors,
                                    );
                                }
                                Activity::Idle => task.pps = 0.0,
                            }
                        }
                    }

                    if !any_running {
                        error!("No DPDK workers are running. Stopping...");
                        break;
                    }

                    status_writer.publish(DriverStatus {
                        workers: statuses.clone(),
                    });
                    thread::sleep(poll_period);
                }

                status_writer.publish(DriverStatus {
                    workers: statuses.clone(),
                });
                info!("DPDK worker supervisor terminated");
            })
            .map_err(|e| {
                DriverError::PortSetup(format!("failed to spawn the DPDK supervisor: {e}"))
            })?;

        info!("DPDK driver started successfully");
        Ok(())
    }
}

/// Join a worker and report how it ended.
fn join_worker(id: WorkerId, handle: ScopedJoinHandle<'_, ()>) -> WorkerEndResult {
    match handle.join() {
        Ok(()) => {
            info!("DPDK worker {id} exited successfully");
            WorkerEndResult::Ok
        }
        Err(panic_payload) => {
            let msg = format!("DPDK worker {id} panicked {panic_payload:?}");
            error!("{msg}");
            WorkerEndResult::Panicked(msg)
        }
    }
}

/// The supervisor's handle on one worker.
struct WorkerMonitor<'scope> {
    id: WorkerId,
    handle: Option<ScopedJoinHandle<'scope, ()>>,
    watchdog: Watchdog,
    port_names: Vec<Arc<str>>,
}
