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
mod sockstats;
mod worker;

use concurrency::sync::Arc;
use concurrency::thread;
#[allow(unused_imports)] // used under loom/shuttle backends
use concurrency::thread::BuilderExt;
use lifecycle::Subsystem;
use net::buffer::test_buffer::TestBuffer;
use pipeline::DynPipeline;
use tracectl::trace_target;
#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

use super::DriverError;
use super::kif::{self, Kif};
use super::status::{DriverParams, DriverStatusWriter};
use super::supervisor::{WorkerMonitor, supervise};
use worker::Worker;

trace_target!("kernel-driver", LevelFilter::INFO, &["driver"]);

/// AF_PACKET-based kernel driver. Spawns N workers with symmetric-hash
/// fanout and per-worker pipelines.
pub struct DriverKernel;

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

    /// What this driver reports about itself alongside its workers' status.
    fn params() -> DriverParams {
        DriverParams {
            name: "kernel",
            rx_batch: Self::MAX_RX_PKT_BATCH,
            poll_period: Self::TASK_POLL_PERIOD,
            pat_period: Self::TASK_PAT_PERIOD,
            check_period: Self::TASK_CHECK_PERIOD,
        }
    }

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
    pub fn start<'scope>(
        scope: &'scope thread::Scope<'scope, '_>,
        workers_subsystem: &Subsystem,
        args: impl IntoIterator<Item = impl AsRef<str> + Clone>,
        num_workers: usize,
        setup_pipeline: &Arc<dyn Send + Sync + Fn() -> DynPipeline<TestBuffer>>,
        status_writer: DriverStatusWriter,
    ) -> Result<(), DriverError> {
        let interfaces = kif::prepare(args)?;

        let mut worker_monitors = Self::spawn_workers_scoped(
            scope,
            workers_subsystem,
            num_workers,
            setup_pipeline,
            interfaces.as_slice(),
        )?;
        debug_assert_eq!(worker_monitors.len(), num_workers);

        // The supervisor loops over worker monitors (which include join handles) and
        // just joins-and-logs on termination; worker fatal reporting is handled by
        // the `ExitGuard` inside each worker thread.
        let supervisor_builder =
            thread::Builder::new().name("kernel-worker-supervisor".to_string());

        let subsystem = workers_subsystem.clone();

        supervisor_builder.spawn_scoped(scope, move || {
            info!("Worker supervisor started");
            supervise(
                Self::params(),
                &subsystem,
                &mut worker_monitors,
                &status_writer,
            );
            info!("Worker supervisor thread terminated");
        })?;
        info!("Kernel driver started successfully");
        Ok(())
    }
}
