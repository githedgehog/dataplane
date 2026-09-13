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
use super::cpbridge::{DatapathEnds, PortIdentity};
use super::status::DriverStatusWriter;
use super::supervisor::{WorkerMonitor, spawn_supervisor};
use kif::Kif;
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
        mut cp_ends: Option<&mut DatapathEnds>,
    ) -> Result<Vec<WorkerMonitor<'scope, std::io::Error>>, std::io::Error> {
        use crate::drivers::kernel::worker::BridgedPort;
        let mut monitors = Vec::with_capacity(num_workers);

        info!("Spawning {num_workers} workers");

        // Split once, before any worker exists. The punt sender is cloned to every worker,
        // because any of them may receive a frame the kernel should see; the injection receiver
        // goes to exactly one, because two draining the same queue would interleave a peering
        // session's frames and reorder them. The tap's index goes to all of them -- it is what
        // every worker must stamp on a received packet, not just the one that injects.
        let mut bridge: Vec<BridgedPort> = Vec::new();
        if let Some(ends) = cp_ends.as_mut() {
            for kif in interfaces {
                if let Some(queues) = ends.take(&kif.name) {
                    bridge.push(BridgedPort {
                        name: kif.name.clone(),
                        index: queues.index,
                        punt: queues.punt,
                        inject: queues.inject,
                    });
                }
            }
        }

        for workerid in 0..num_workers {
            // Every worker sees every port, with the injection queue moved out for all but the
            // first.
            let worker_bridge: Vec<BridgedPort> = bridge
                .iter_mut()
                .map(|port| BridgedPort {
                    name: port.name.clone(),
                    index: port.index,
                    punt: port.punt.clone(),
                    inject: if workerid == 0 {
                        port.inject.take()
                    } else {
                        None
                    },
                })
                .collect();

            // create worker
            let worker = Worker::new(
                workerid,
                num_workers,
                setup_pipeline,
                workers_subsystem.clone(),
            );
            // start worker. We get a `WorkerMonitor` on success, which includes
            // an interface monitor for each of its rx tasks
            let wk_monitor = worker.start(scope, interfaces, worker_bridge)?;

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
        args: impl IntoIterator<Item = args::InterfaceArg>,
        num_workers: usize,
        setup_pipeline: &Arc<dyn Send + Sync + Fn() -> DynPipeline<'static, TestBuffer>>,
        status_writer: DriverStatusWriter,
        mut cp_ends: Option<DatapathEnds>,
    ) -> Result<(), DriverError> {
        // A current_thread runtime built inside another tokio runtime
        // panics; catch nesting in debug.
        debug_assert!(
            tokio::runtime::Handle::try_current().is_err(),
            "DriverKernel::start must not be invoked from within a tokio runtime context"
        );

        // This thread is already in the datapath namespace, with a sysfs that reflects it, so
        // discovery and link setup see the interfaces wherever init put them.
        info!("Collecting interfaces from config");
        let config: Vec<_> = args.into_iter().collect();
        let interfaces = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(kif::configure_interfaces(&config))?;

        // Tell the control plane what each interface turned out to be, so its tap can wear the
        // same MAC and MTU. Without the MAC, ARP for this interface resolves to the tap's random
        // address and the peer's frames arrive with a destination this interface will not accept.
        if let Some(ends) = &cp_ends {
            for kif in &interfaces {
                if let Some(mac) = kif.mac {
                    ends.report(PortIdentity {
                        name: kif.name.clone(),
                        mac,
                        mtu: u16::try_from(kif.mtu.unwrap_or(0)).unwrap_or(u16::MAX),
                    });
                } else {
                    warn!(
                        "the kernel reports no MAC for {}, so its tap keeps the one it was given \
                         and ARP for this interface will not resolve",
                        kif.name
                    );
                }
            }
        }

        let worker_monitors = Self::spawn_workers_scoped(
            scope,
            workers_subsystem,
            num_workers,
            setup_pipeline,
            interfaces.as_slice(),
            cp_ends.as_mut(),
        )?;

        // After the workers have claimed theirs, so this names only the taps nothing took.
        if let Some(ends) = &cp_ends {
            ends.report_unclaimed();
        }
        debug_assert_eq!(worker_monitors.len(), num_workers);

        spawn_supervisor(
            scope,
            "kernel",
            workers_subsystem,
            worker_monitors,
            status_writer,
            Self::MAX_RX_PKT_BATCH,
            || {},
        )?;
        info!("Kernel driver started successfully");
        Ok(())
    }
}
