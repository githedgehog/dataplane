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
//! # How work is spread
//!
//! RSS distributes received frames across the per-worker receive queues by a Toeplitz hash over
//! L3 addresses and L4 ports, so every packet of one flow reaches one worker and nothing within a
//! flow is reordered. Which worker that is does not matter: flow state lives in a single
//! [`FlowTable`](flow_entry::flow_table::FlowTable) shared by every worker, so any worker can
//! service any packet.
//!
//! That is worth stating plainly because the obvious next thought -- "the two directions of a flow
//! must reach the same worker, so the hash has to be symmetric" -- is wrong twice over here. The
//! hardware route is closed (mlx5 rejects any hash function but the default at
//! `rte_eth_dev_configure`; see [`RssConf`](dpdk::dev::RssConf)), and it would not help anyway: a
//! NAT'd flow's reverse packet carries the *translated* tuple, not the reversed one, so no
//! symmetry property the NIC can have would pair the two halves. Shared flow state is what makes
//! that a non-problem.
//!
//! # What this does not do yet
//!
//! - **Ports must have a kernel netdev.** The pipeline names interfaces by kernel `ifindex`, and
//!   this driver takes that from `rte_eth_dev_info.if_index`. That is populated for a bifurcated
//!   driver such as mlx5, where `mlx5_core` keeps the netdev while DPDK attaches through the RDMA
//!   verbs interface. A port bound to `vfio-pci` has no netdev and reports 0, and is rejected at
//!   bring-up with a clear error rather than silently mapping onto interface 0. Supporting those
//!   ports means giving the configuration layer a way to name a port that is not a netdev.
//! - **No hairpin or offloaded forwarding.** Every packet goes through the software pipeline.
//!
//! # The control plane
//!
//! With the kernel driver, FRR shares a namespace with the real NIC and peers through the kernel's
//! own stack. Here the kernel has no NIC, so every control frame is carried across by
//! [`cpbridge`](crate::drivers::cpbridge), which is what makes a tap the kernel's end of each
//! port. See that module for the punt policy and its costs.

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
use stats::PortMetrics;
use tracectl::trace_target;
use tracing::{debug, error, info, warn};

use super::DriverError;
use super::status::{
    DriverStatus, DriverStatusWriter, RxTaskStatus, WorkerEndResult, WorkerId, WorkerState,
    WorkerStatus,
};
use super::watchdog::{Activity, Watchdog};

pub(crate) use crate::drivers::cpbridge::{CpBridge, DatapathEnds, PortIdentity};
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
    /// `bridge` is the datapath's end of the control-plane bridge, if there is one. Its queues are
    /// dealt out alongside the hardware queues, because the two are used from the same loop.
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
        bridge: Option<&mut DatapathEnds>,
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

        let dealt = port::deal_queues(ports, num_workers, bridge)?;

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

        Self::spawn_supervisor(scope, workers_subsystem, monitors, status_writer, ports)
    }

    /// The supervisor thread: samples worker liveness, publishes status and port counters, joins on
    /// cancellation.
    ///
    /// The port counters are polled *here* rather than from the metrics runtime because they are
    /// the only thread that can be. `Dev::stats` needs the device, the devices are branded with
    /// `'eal`, and `Eal` is `!Send` -- so the counters can only be read from a thread inside the
    /// EAL's scope. The metrics server is a tokio task on the management runtime, which is neither.
    #[allow(clippy::too_many_lines)]
    fn spawn_supervisor<'p, 'scope>(
        scope: &'scope thread::Scope<'scope, '_>,
        workers_subsystem: &Subsystem,
        mut monitors: Vec<WorkerMonitor<'scope>>,
        status_writer: DriverStatusWriter,
        ports: &'p [Port<'_>],
    ) -> Result<(), DriverError>
    where
        'p: 'scope,
    {
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

                // Registered once, here, rather than per poll: registration is configuration work
                // and publishing follows traffic. Re-registering each time is what made the VPC
                // collector quadratic.
                let port_metrics: Vec<(&Port<'_>, PortMetrics)> = ports
                    .iter()
                    .map(|port| (port, PortMetrics::new(&port.name)))
                    .collect();
                // A PMD that implements no statistics reports `ENOTSUP` on every call. Complaining
                // once per port beats a line per port per second for the life of the process.
                let mut counters_unavailable: Vec<bool> = vec![false; port_metrics.len()];

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

                    publish_port_counters(&port_metrics, &mut counters_unavailable);

                    status_writer.publish(DriverStatus {
                        workers: statuses.clone(),
                    });
                    thread::sleep(poll_period);
                }

                // One last read on the way out. A run that ends under load leaves its final drop
                // count in the device, and without this the last thing a scrape ever sees is a
                // poll_period old -- which is exactly the interval a shutdown is most interesting.
                publish_port_counters(&port_metrics, &mut counters_unavailable);

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

/// Read every port's device counters and publish them.
///
/// `unavailable` is one flag per port, carried across calls so that a PMD which implements no
/// statistics is complained about once rather than on every poll for the life of the process.
fn publish_port_counters(port_metrics: &[(&Port<'_>, PortMetrics)], unavailable: &mut [bool]) {
    for (slot, (port, metrics)) in port_metrics.iter().enumerate() {
        match port.counters() {
            Ok(counters) => {
                metrics.publish(&counters);
                // A port that starts reporting again after a failure is worth hearing about, so
                // clear the flag rather than latching it.
                unavailable[slot] = false;
            }
            Err(e) => {
                if !unavailable[slot] {
                    unavailable[slot] = true;
                    warn!(
                        "port {} would not report its counters: {e:?}. Receive drops on this port \
                         are now invisible -- an overloaded dataplane will look like an idle wire.",
                        port.name
                    );
                }
            }
        }
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
