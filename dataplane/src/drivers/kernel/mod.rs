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
use kif::{Kif, bring_kifs_up};
use worker::Worker;

trace_target!("kernel-driver", LevelFilter::INFO, &["driver"]);

/// AF_PACKET-based kernel driver. Spawns N workers with symmetric-hash
/// fanout and per-worker pipelines.
pub struct DriverKernel;

#[allow(clippy::cast_possible_truncation)]
impl DriverKernel {
    /// Spawn `num_workers` worker threads into `scope`, each with its own
    /// pipeline. Bails on the first spawn failure; workers that did spawn
    /// drain via the scope join.
    fn spawn_workers_scoped<'scope>(
        scope: &'scope thread::Scope<'scope, '_>,
        workers_subsystem: &Subsystem,
        num_workers: usize,
        setup_pipeline: &Arc<dyn Send + Sync + Fn() -> DynPipeline<TestBuffer>>,
        interfaces: &[Kif],
    ) -> Result<Vec<thread::ScopedJoinHandle<'scope, Result<(), std::io::Error>>>, std::io::Error>
    {
        info!("Spawning {num_workers} workers");
        (0..num_workers)
            .map(|wid| {
                let builder = thread::Builder::new().name(format!("dp-worker-{wid}"));
                Worker::new(wid, num_workers, setup_pipeline, workers_subsystem.clone())
                    .start(scope, builder, interfaces)
            })
            .collect()
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

        let worker_handles = Self::spawn_workers_scoped(
            scope,
            workers_subsystem,
            num_workers,
            setup_pipeline,
            interfaces.as_slice(),
        )?;

        // The supervisor just joins-and-logs; worker fatal reporting is
        // handled by the `ExitGuard` inside each worker thread.
        let supervisor_builder =
            thread::Builder::new().name("kernel-driver-supervisor".to_string());
        supervisor_builder.spawn_scoped(scope, move || {
            for (id, handle) in worker_handles.into_iter().enumerate() {
                info!("Waiting for worker {id} to finish");
                match handle.join() {
                    Ok(Ok(())) => info!("Worker {id} exited successfully"),
                    Ok(Err(e)) => error!("Worker {id} exited with error: {e}"),
                    Err(panic_payload) => error!("Worker {id} panicked: {panic_payload:?}"),
                }
            }
            info!("All workers joined");
        })?;

        Ok(())
    }
}
