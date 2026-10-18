// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK poll-mode driver.
//!
//! Each worker owns one RX/TX queue pair per port and processes each burst on the
//! receiving thread. Queue handles borrow their devices; mbufs borrow the EAL.
//!
//! RSS spreads flows across per-worker queues. Flow state is shared across workers.
//! The pipeline identifies a port by its tap's ifindex; a port without a tap needs a kernel netdev.
//! A [`PortSource`] is where a port's device comes from, which is all that differs between kinds.
//! Forwarding runs in software; control frames cross per-port TAPs through [`cpbridge`].
//!
//! A control worker owns one more queue pair per port, which the data workers' RSS does not reach:
//! it receives the control plane's traffic there and transmits what the kernel sends.

mod classes;
mod control;
mod placement;
mod port;
mod source;
mod worker;

use std::convert::Infallible;
use std::num::NonZero;

use concurrency::sync::Arc;
use concurrency::thread;
#[allow(unused_imports)] // used under loom/shuttle backends
use concurrency::thread::BuilderExt;
use dpdk::mem::{MBUF_BURST, Mbuf};
use lifecycle::Subsystem;
use lldp::Link;
use pipeline::DynPipeline;
use stats::PortMetrics;
use tokio::sync::watch;
use tracectl::trace_target;
use tracing::{info, warn};
use traffic_control::ControlPlane;

use super::DriverError;
use super::status::DriverStatusWriter;
use super::supervisor::{RxTaskMonitor, WorkerMonitor, spawn_supervisor};

pub(crate) use crate::drivers::cpbridge::{CpBridge, DatapathEnds, PortIdentity};
use control::{ControlPort, ControlWorker};
use placement::{Placement, pin};
pub(crate) use port::Port;
pub(crate) use source::{PciPort, PortSettings, bring_up_ports};
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
    /// `control_plane` is what the control-plane classes are built from; the control worker steers
    /// them to the control queues and follows its changes.
    ///
    /// # Errors
    ///
    /// Returns an error for missing ports or queues, or thread spawn failures.
    #[allow(clippy::too_many_arguments)]
    pub fn start<'p, 'scope>(
        scope: &'scope thread::Scope<'scope, '_>,
        workers_subsystem: &Subsystem,
        timer_handle: &'scope tokio::runtime::Handle,
        ports: &'p [Port<'_>],
        num_workers: NonZero<u16>,
        setup_pipeline: &Arc<dyn Send + Sync + Fn() -> DynPipeline<'p, Mbuf<'p>> + 'p>,
        status_writer: DriverStatusWriter,
        bridge: Option<&mut DatapathEnds>,
        control_plane: watch::Receiver<ControlPlane>,
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

        // Taken before the queues are dealt, which consumes the bridge's ends.
        let mut bridge = bridge;
        let links: Vec<(&Port<'_>, watch::Sender<Link>)> = ports
            .iter()
            .filter_map(|port| {
                let link = bridge.as_deref_mut()?.take_link(&port.name)?;
                Some((port, link))
            })
            .collect();
        let dealt = port::deal_queues(ports, num_workers.get(), bridge)?;

        info!(
            "Starting {num_workers} DPDK worker(s) and a control worker across {} port(s)",
            ports.len()
        );

        let placement = Placement::of_this_process();
        let mut monitors = Vec::with_capacity(dealt.workers.len() + 1);
        for (id, queues) in dealt.workers.into_iter().enumerate() {
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
            let cpus = placement.data.clone();
            let handle = thread::Builder::new()
                .name(format!("dpdk-worker-{id}"))
                .spawn_scoped(scope, move || {
                    // Any exit before shutdown, a panic included, leaves this worker's queues
                    // unpolled, so it is fatal. The guard sees cancellation and stays quiet then.
                    let _guard = subsystem.new_exit_guard(format!("worker {id}"), true);
                    if let Some(cpus) = cpus {
                        pin(&format!("DPDK worker {id}"), &cpus);
                    }
                    worker.run(&subsystem, &setup_pipeline, timer_handle);
                    Ok::<(), Infallible>(())
                })
                .map_err(|e| {
                    DriverError::PortSetup(format!("failed to spawn DPDK worker {id}: {e}"))
                })?;

            monitors.push(WorkerMonitor::new(id, handle, rx_tasks));
        }

        // The control worker is numbered after the data workers.
        monitors.push(spawn_control(
            scope,
            workers_subsystem,
            usize::from(num_workers.get()),
            placement.control,
            dealt.control,
            control_plane,
        )?);

        // Register metrics once; the scoped callback keeps the borrowed ports alive while polling.
        let port_metrics: Vec<(&Port<'_>, PortMetrics)> = ports
            .iter()
            .map(|port| (port, PortMetrics::new(port.name.as_ref())))
            .collect();
        let mut counters_unavailable = vec![false; port_metrics.len()];
        spawn_supervisor(
            scope,
            "dpdk",
            MBUF_BURST,
            workers_subsystem,
            monitors,
            status_writer,
            move || {
                publish_port_counters(&port_metrics, &mut counters_unavailable);
                publish_links(&links);
            },
        )?;
        info!("DPDK driver started successfully");
        Ok(())
    }
}

/// Spawn the control worker over every port's control queues, as worker `id`, on `cpu`.
fn spawn_control<'p, 'eal, 'scope>(
    scope: &'scope thread::Scope<'scope, '_>,
    subsystem: &Subsystem,
    id: usize,
    cpu: Option<usize>,
    control: Vec<port::ControlQueues<'p, 'eal>>,
    control_plane: watch::Receiver<ControlPlane>,
) -> Result<WorkerMonitor<'scope, Infallible>, DriverError>
where
    'p: 'scope,
    'eal: 'scope,
{
    let rx_tasks: Vec<RxTaskMonitor> = control
        .iter()
        .map(|q| RxTaskMonitor::new(&format!("{} (control)", q.name)))
        .collect();
    let ports = control
        .into_iter()
        .zip(&rx_tasks)
        .map(|(queues, task)| ControlPort {
            queues,
            watchdog: task.watchdog.clone(),
        })
        .collect();
    let worker = ControlWorker::new(id, ports, control_plane);
    let subsystem = subsystem.clone();
    let handle = thread::Builder::new()
        .name("dpdk-control".to_string())
        .spawn_scoped(scope, move || {
            // As for the data workers: an exit before shutdown is fatal. Forwarding would carry on
            // without it, but BGP and BFD would not, and nothing else would notice.
            let _guard = subsystem.new_exit_guard("control worker".to_string(), true);
            if let Some(cpu) = cpu {
                pin("the DPDK control worker", &[cpu]);
            }
            worker.run(&subsystem);
            Ok::<(), Infallible>(())
        })
        .map_err(|e| {
            DriverError::PortSetup(format!("failed to spawn the DPDK control worker: {e}"))
        })?;
    Ok(WorkerMonitor::new(id, handle, rx_tasks))
}

/// Publish each port's link state where the control plane can see it.
///
/// Polled, because nothing in the driver asks DPDK for link-state interrupts. A second's latency is
/// well inside what anything watching the link (LLDP's fast start, for one) cares about.
fn publish_links(links: &[(&Port<'_>, watch::Sender<Link>)]) {
    for (port, link) in links {
        let now = match port.dev.link() {
            Ok(status) if status.up => Link::Up,
            Ok(_) => Link::Down,
            // A link that cannot be read is treated as down: nothing should be sent on a port whose
            // state is unknown. The change is logged below, once.
            Err(e) => {
                if *link.borrow() == Link::Up {
                    warn!("port {} would not report its link state: {e:?}", port.name);
                }
                Link::Down
            }
        };
        link.send_if_modified(|was| {
            if *was == now {
                return false;
            }
            info!("port {} link is now {now:?}", port.name);
            *was = now;
            true
        });
    }
}

/// Publish device counters, logging once per port until a failed read recovers.
fn publish_port_counters(port_metrics: &[(&Port<'_>, PortMetrics)], unavailable: &mut [bool]) {
    for (slot, (port, metrics)) in port_metrics.iter().enumerate() {
        match port.counters() {
            Ok(counters) => {
                metrics.publish(&counters);
                // Report a later failure after recovery.
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
