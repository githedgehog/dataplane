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
mod sockstats;
mod worker;

use concurrency::sync::Arc;
use concurrency::thread;
use lifecycle::Subsystem;
use net::buffer::test_buffer::TestBuffer;
use pipeline::DynPipeline;
use tracectl::trace_target;
#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

use super::DriverError;
use super::status::DriverStatusWriter;
use super::supervisor::{WorkerMonitor, spawn_supervisor};
use kif::{Kif, bring_kifs_up};
use worker::Worker;

trace_target!("kernel-driver", LevelFilter::INFO, &["driver"]);

/// AF_PACKET-based kernel driver. Spawns N workers with symmetric-hash
/// fanout and per-worker pipelines.
pub struct DriverKernel;

impl DriverKernel {
    /// Max number of packets that a RX task will attempt to read in one go
    pub(crate) const MAX_RX_PKT_BATCH: usize = 128;

    /// Spawn `num_workers` worker threads into `scope`, each with its own
    /// pipeline. Bails on the first spawn failure; workers that did spawn
    /// drain via the scope join.
    fn spawn_workers_scoped<'scope>(
        scope: &'scope thread::Scope<'scope, '_>,
        workers_subsystem: &Subsystem,
        num_workers: usize,
        setup_pipeline: &Arc<dyn Send + Sync + Fn() -> DynPipeline<'static, TestBuffer>>,
        interfaces: &[Kif],
    ) -> Result<Vec<WorkerMonitor<'scope, std::io::Error>>, std::io::Error> {
        let mut monitors = Vec::with_capacity(num_workers);

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
        setup_pipeline: &Arc<dyn Send + Sync + Fn() -> DynPipeline<'static, TestBuffer>>,
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

        let worker_monitors = Self::spawn_workers_scoped(
            scope,
            workers_subsystem,
            num_workers,
            setup_pipeline,
            interfaces.as_slice(),
        )?;
        debug_assert_eq!(worker_monitors.len(), num_workers);

        spawn_supervisor(
            scope,
            "kernel",
            workers_subsystem,
            worker_monitors,
            status_writer,
        )?;
        info!("Kernel driver started successfully");
        Ok(())
    }
}
