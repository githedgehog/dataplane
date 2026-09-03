// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! `AF_XDP` dataplane driver
//!
//! The kernel driver reads packets with `AF_PACKET`, which copies every frame
//! through a socket buffer. This one binds `AF_XDP` sockets instead, so the
//! kernel puts received packets straight into memory shared with the worker
//! that will process them, and takes transmitted ones from the same place.
//!
//! An `AF_XDP` socket is bound to one RX queue of one interface, so the workers
//! are organised by queue: worker `q` owns a socket on queue `q` of every
//! interface, and the queue count of the interfaces decides how many workers
//! there are. Each worker has one UMEM behind all of its sockets, which is
//! what lets it forward a packet from one interface to another without
//! copying it out of the mapping.

#![deny(
    unsafe_code,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

mod worker;

use concurrency::sync::Arc;
use concurrency::thread;
#[allow(unused_imports)] // used under loom/shuttle backends
use concurrency::thread::BuilderExt;
use lifecycle::Subsystem;
use pipeline::DynPipeline;
use tracectl::trace_target;
#[allow(unused)]
use tracing::{debug, error, info, trace, warn};
use xdp::buffer::XdpBuffer;
use xdp::program::Redirect;
use xdp::socket::BATCH_SIZE;

use super::DriverError;
use super::kif::{self, Kif};
use super::status::{DriverParams, DriverStatusWriter};
use super::supervisor::{WorkerMonitor, supervise};
use worker::Worker;

trace_target!("af-xdp-driver", LevelFilter::INFO, &["driver"]);

/// `AF_XDP` driver. Spawns one worker per RX queue, each with a socket on every
/// interface and a pipeline of its own.
pub struct DriverAfXdp;

impl DriverAfXdp {
    /// How often, in seconds, a worker pats its watchdog even if it sees no traffic
    pub(crate) const TASK_PAT_PERIOD: u16 = 2;

    /// Slack, in seconds, on top of the pat period before a missed pat is treated as a deadline miss.
    pub(crate) const TASK_GRACE_PERIOD: u16 = 4;

    /// Interval, in seconds, at which the supervisor will check worker watchdogs
    pub(crate) const TASK_CHECK_PERIOD: u16 = Self::TASK_PAT_PERIOD + Self::TASK_GRACE_PERIOD;

    /// Interval, in seconds, at which the supervisor checks worker activity, ignoring watchdogs
    pub(crate) const TASK_POLL_PERIOD: u16 = 1;

    /// What this driver reports about itself alongside its workers' status.
    fn params() -> DriverParams {
        DriverParams {
            name: "af-xdp",
            rx_batch: BATCH_SIZE,
            poll_period: Self::TASK_POLL_PERIOD,
            pat_period: Self::TASK_PAT_PERIOD,
            check_period: Self::TASK_CHECK_PERIOD,
        }
    }

    /// How many queues every one of `interfaces` has.
    ///
    /// A worker serves the same queue index on all of them, so it is the
    /// smallest queue count that decides how many there can be. Traffic on the
    /// queues above it is left to the kernel stack rather than dropped: the
    /// XDP program only redirects the queues it finds a socket for.
    fn queues_to_serve(interfaces: &[Kif]) -> u32 {
        let smallest = interfaces
            .iter()
            .map(|kif| {
                kif.num_rx_queues().unwrap_or_else(|e| {
                    warn!(
                        "Could not read the queue count of '{}' ({e}); assuming one",
                        kif.name
                    );
                    1
                })
            })
            .min()
            // Not reachable: an empty interface list is refused before this. A
            // worker with nothing to serve would spin, so do not spawn one.
            .unwrap_or(0);

        let smallest = smallest.min(xdp::program::MAX_QUEUES);
        info!(
            "Serving {smallest} RX queue(s) on each of {} interfaces",
            interfaces.len()
        );
        smallest
    }

    /// Spawn one worker per queue into `scope`, each serving that queue on
    /// every interface. Bails on the first spawn failure; workers that did
    /// spawn drain via the scope join.
    fn spawn_workers_scoped<'scope>(
        scope: &'scope thread::Scope<'scope, '_>,
        workers_subsystem: &Subsystem,
        queues: u32,
        interfaces: &[Kif],
        redirect: &Arc<Redirect>,
        setup_pipeline: &Arc<dyn Send + Sync + Fn() -> DynPipeline<XdpBuffer>>,
    ) -> Result<Vec<WorkerMonitor<'scope>>, std::io::Error> {
        let mut monitors: Vec<WorkerMonitor> = Vec::with_capacity(queues as usize);

        info!("Spawning {queues} workers");

        for queue_id in 0..queues {
            let worker = Worker::new(
                queue_id as usize,
                queue_id,
                interfaces,
                redirect,
                setup_pipeline,
                workers_subsystem.clone(),
            );
            monitors.push(worker.start(scope)?);
        }
        Ok(monitors)
    }

    /// Spawn worker threads + supervisor into `scope`. The scope joins
    /// all driver threads on closure return.
    ///
    /// # Errors
    /// Returns [`DriverError`] on interface setup, XDP program load, or thread
    /// spawn failure.
    pub fn start<'scope>(
        scope: &'scope thread::Scope<'scope, '_>,
        workers_subsystem: &Subsystem,
        args: impl IntoIterator<Item = impl AsRef<str> + Clone>,
        setup_pipeline: &Arc<dyn Send + Sync + Fn() -> DynPipeline<XdpBuffer>>,
        status_writer: DriverStatusWriter,
    ) -> Result<(), DriverError> {
        let interfaces = kif::prepare(args)?;

        // Attach whatever is going to redirect packets to our sockets before
        // any of them is bound, so that no worker binds a socket the redirect
        // does not know about.
        let redirect = Arc::new(Redirect::attach(
            interfaces.iter().map(|kif| kif.name.as_str()),
        )?);

        let queues = Self::queues_to_serve(interfaces.as_slice());
        let mut worker_monitors = Self::spawn_workers_scoped(
            scope,
            workers_subsystem,
            queues,
            interfaces.as_slice(),
            &redirect,
            setup_pipeline,
        )?;

        let supervisor_builder =
            thread::Builder::new().name("af-xdp-worker-supervisor".to_string());

        let subsystem = workers_subsystem.clone();

        supervisor_builder.spawn_scoped(scope, move || {
            info!("Worker supervisor started");
            supervise(
                Self::params(),
                &subsystem,
                &mut worker_monitors,
                &status_writer,
            );
            // The XDP programs stay attached for as long as the workers may
            // still be receiving, which is until the supervisor has joined
            // them all.
            drop(redirect);
            info!("Worker supervisor thread terminated");
        })?;
        info!("AF_XDP driver started successfully");
        Ok(())
    }
}
