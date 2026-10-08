// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK poll-mode driver.
//!
//! Each worker owns one RX/TX queue pair per port and processes each burst on the
//! receiving thread. Queue handles borrow their devices; mbufs borrow the EAL.
//!
//! RSS is disabled, so only queue 0 receives traffic. Ports need a kernel netdev
//! because the pipeline identifies interfaces by ifindex. Forwarding runs in software.

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
use tracectl::trace_target;
use tracing::info;

use super::DriverError;
use super::status::DriverStatusWriter;
use super::supervisor::{RxTaskMonitor, WorkerMonitor, spawn_supervisor};

use port::Port;
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
    /// # Errors
    ///
    /// Returns an error for invalid worker counts, missing ports or queues, or thread spawn failures.
    pub fn start<'p, 'scope>(
        scope: &'scope thread::Scope<'scope, '_>,
        workers_subsystem: &Subsystem,
        timer_handle: &'scope tokio::runtime::Handle,
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

        spawn_supervisor(scope, "dpdk", workers_subsystem, monitors, status_writer)?;
        info!("DPDK driver started successfully");
        Ok(())
    }
}
