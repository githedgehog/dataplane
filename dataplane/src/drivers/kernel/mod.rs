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
use net::buffer::test_buffer::TestBuffer;
use pipeline::DynPipeline;
use tracectl::trace_target;
#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

use kif::Kif;
use worker::Worker;

trace_target!("kernel-driver", LevelFilter::INFO, &["driver"]);

/// Main structure representing the kernel driver.
/// This driver:
///  * receives raw frames via `AF_PACKET`, parses to `Packet<TestBuffer>`
///  * selects a worker by symmetric flow hash
///  * workers run independent pipelines and send processed packets back
///  * dispatcher serializes & transmits on the chosen outgoing interface
pub struct DriverKernel;

#[allow(clippy::cast_possible_truncation)]
impl DriverKernel {
    /// Spawn `workers` processing threads, each with its own pipeline instance.
    ///
    /// Returns:
    ///   - `Arc<Vec<Sender<Packet<TestBuffer>>>>` one sender per worker (dispatcher -> worker)
    ///   - `Receiver<Packet<TestBuffer>>` a single queue for processed packets (worker -> dispatcher)
    fn spawn_workers(
        num_workers: usize,
        setup_pipeline: &Arc<dyn Send + Sync + Fn() -> DynPipeline<TestBuffer>>,
        interfaces: &[Kif],
    ) -> Vec<thread::JoinHandle<Result<(), std::io::Error>>> {
        info!("Spawning {num_workers} workers");
        let mut workers = Vec::new();
        for wid in 0..num_workers {
            let builder = thread::Builder::new().name(format!("dp-worker-{wid}"));
            let mut worker = Worker::new(wid, num_workers, setup_pipeline);
            match worker.start(builder, interfaces) {
                Ok(handle) => workers.push(handle),
                Err(e) => {
                    error!("Failed to start worker {wid}: {e}");
                }
            }
        }
        workers
    }

    /// Starts the kernel driver, spawns worker threads, and runs the dispatcher loop.
    ///
    /// - `args`: kernel driver CLI parameters (e.g., `--interface` list)
    /// - `workers`: number of worker threads / pipelines
    /// - `setup_pipeline`: factory returning a **fresh** `DynPipeline<TestBuffer>` per worker
    #[allow(clippy::too_many_lines)]
    pub fn start(
        stop_tx: std::sync::mpsc::Sender<i32>,
        args: impl IntoIterator<Item = impl AsRef<str> + Clone>,
        num_workers: usize,
        setup_pipeline: &Arc<dyn Send + Sync + Fn() -> DynPipeline<TestBuffer>>,
    ) {
        info!("Collecting interfaces from config");
        let interfaces = match kif::get_interfaces(args) {
            Ok(t) => t,
            Err(e) => {
                error!("Failed to initialize kernel interface table: {e}");
                return;
            }
        };

        // Spawn worker
        let worker_handles =
            Self::spawn_workers(num_workers, setup_pipeline, interfaces.as_slice());

        let control_builder = thread::Builder::new().name("kernel-driver-controller".to_string());
        #[allow(clippy::expect_used)]
        control_builder
            .spawn(move || {
                for (id, handle) in worker_handles.into_iter().enumerate() {
                    info!("Waiting for workers to finish");
                    match handle.join() {
                        Ok(result) => match result {
                            Ok(()) => info!("Worker {id} exited successfully"),
                            Err(e) => error!("Worker {id} exited with error: {e}"),
                        },
                        Err(e) => error!("Unable to spawn worker {id} error: {e:?}"),
                    }
                }

                // Exiting with error as it's not expected for all workers to finish
                error!("All workers finished unexpectedly");
                stop_tx.send(1).expect("Failed to send stop signal");
            })
            .expect("Failed to spawn kernel driver control thread");
    }
}
