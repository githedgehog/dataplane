// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK poll-mode driver.
//!
//! Each worker owns one RX/TX queue pair per port and processes each burst on the
//! receiving thread. Queue handles borrow their devices; mbufs borrow the EAL.
//!
//! RSS spreads flows across per-worker queues. Flow state is shared across workers.
//! Ports need a kernel netdev because the pipeline identifies interfaces by ifindex.
//! Forwarding runs in software; control frames cross per-port TAPs through [`cpbridge`].

mod port;
mod worker;

use std::convert::Infallible;

use concurrency::sync::Arc;
use concurrency::thread;
#[allow(unused_imports)] // used under loom/shuttle backends
use concurrency::thread::BuilderExt;
use dpdk::mem::Mbuf;
use lifecycle::Subsystem;
use pipeline::DynPipeline;
use stats::PortMetrics;
use tracectl::trace_target;
use tracing::{info, warn};

use super::DriverError;
use super::status::DriverStatusWriter;
use super::supervisor::{RxTaskMonitor, WorkerMonitor, spawn_supervisor};

pub(crate) use crate::drivers::cpbridge::{CpBridge, DatapathEnds, PortIdentity};
pub(crate) use port::Port;
use worker::{Worker, WorkerPort};

trace_target!("dpdk-driver", LevelFilter::INFO, &["driver"]);

/// Poll-mode DPDK driver.
pub struct DriverDpdk;

impl DriverDpdk {
    /// Distribute started ports' queues among workers and start the supervisor.
    ///
    /// Queue handles borrow the ports, which must outlive the worker scope.
    /// The timer runtime must keep running until all workers have joined.
    ///
    /// `bridge` is the datapath's end of the control-plane bridge, if there is one. Its queues are
    /// dealt out alongside the hardware queues, because the two are used from the same loop.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid worker counts, missing ports or queues, or thread spawn failures.
    #[allow(clippy::too_many_arguments)]
    pub fn start<'p, 'scope>(
        scope: &'scope thread::Scope<'scope, '_>,
        workers_subsystem: &Subsystem,
        timer_handle: &'scope tokio::runtime::Handle,
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
            let rx_tasks: Vec<RxTaskMonitor> =
                queues.iter().map(|q| RxTaskMonitor::new(&q.name)).collect();
            let worker_ports = queues
                .into_iter()
                .zip(&rx_tasks)
                .map(|(queues, task)| WorkerPort {
                    queues,
                    watchdog: task.watchdog.clone(),
                })
                .collect();
            let worker = Worker::new(id, worker_ports);

            let subsystem = workers_subsystem.clone();
            let setup_pipeline = setup_pipeline.clone();
            let handle = thread::Builder::new()
                .name(format!("dpdk-worker-{id}"))
                .spawn_scoped(scope, move || {
                    worker.run(&subsystem, &setup_pipeline, timer_handle);
                    Ok::<(), Infallible>(())
                })
                .map_err(|e| {
                    DriverError::PortSetup(format!("failed to spawn DPDK worker {id}: {e}"))
                })?;

            monitors.push(WorkerMonitor::new(id, handle, rx_tasks));
        }

        // Register metrics once; the scoped callback keeps the borrowed ports alive while polling.
        let port_metrics: Vec<(&Port<'_>, PortMetrics)> = ports
            .iter()
            .map(|port| (port, PortMetrics::new(&port.name)))
            .collect();
        let mut counters_unavailable = vec![false; port_metrics.len()];
        spawn_supervisor(
            scope,
            "dpdk",
            workers_subsystem,
            monitors,
            status_writer,
            move || publish_port_counters(&port_metrics, &mut counters_unavailable),
        )?;
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
