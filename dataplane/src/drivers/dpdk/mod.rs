// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK poll-mode driver.
//!
//! Each worker owns one RX/TX queue pair per port and processes each burst on the
//! receiving thread. Queue handles borrow their devices; mbufs borrow the EAL.
//!
//! RSS spreads flows across per-worker queues. Flow state is shared across workers.
//! Ports need a kernel netdev because the pipeline identifies interfaces by ifindex.
//! Forwarding runs in software; control frames cross per-port TAPs through [`cpbridge`](crate::drivers::cpbridge).
//!
//! A control worker owns one more queue pair per port, which the data workers' RSS does not reach:
//! it receives the control plane's traffic there and transmits what the kernel sends. A port whose
//! device cannot keep traffic off such a queue has none; see [`port`].

mod classes;
mod control;
mod idle;
mod inject;
mod placement;
mod port;
mod worker;
mod xstats;

use crate::packet_processor::PipelineFactory;
use std::convert::Infallible;
use std::num::NonZero;

use args::IdleConfig;

use concurrency::thread;
#[allow(unused_imports)] // used under loom/shuttle backends
use concurrency::thread::BuilderExt;
use dpdk::mem::{MBUF_BURST, Mbuf};
use lifecycle::Subsystem;
use lldp::Link;
use stats::{PortCounters, PortMetrics, PortState, PortStateMetrics, XstatMetrics};
use tokio::sync::watch;
use tracectl::trace_target;
use tracing::{info, warn};
use traffic_control::ControlPlane;

use super::DriverError;
use super::load::Load;
use super::status::{DriverStatusWriter, PortReport, RxQueue};
use super::supervisor::{RxTaskMonitor, WorkerMonitor, spawn_supervisor};

pub(crate) use crate::drivers::cpbridge::{CpBridge, DatapathEnds, PortIdentity};
use control::{ControlPort, ControlWorker};
use placement::{Placement, pin};
pub(crate) use port::{Port, report_links};
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
        ports: &'p [Port<'_>],
        num_workers: NonZero<u16>,
        idle: IdleConfig,
        setup_pipeline: &PipelineFactory<'p, Mbuf<'p>>,
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
            let rx_tasks: Vec<RxTaskMonitor> = queues
                .iter()
                .map(|q| RxTaskMonitor::new(&q.name, RxQueue::Data))
                .collect();
            let worker_ports = queues
                .into_iter()
                .zip(&rx_tasks)
                .map(|(queues, task)| WorkerPort {
                    queues,
                    watchdog: task.watchdog.clone(),
                })
                .collect();
            let load = Load::new(idle.mode);
            let load_reader = load.reader();
            let worker = Worker::new(id, worker_ports, idle, load);

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
                    worker.run(&subsystem, &setup_pipeline);
                    Ok::<(), Infallible>(())
                })
                .map_err(|e| {
                    DriverError::PortSetup(format!("failed to spawn DPDK worker {id}: {e}"))
                })?;

            monitors.push(WorkerMonitor::new(id, handle, rx_tasks).with_load(load_reader));
        }

        // The control worker is numbered after the data workers.
        monitors.push(spawn_control(
            scope,
            workers_subsystem,
            usize::from(num_workers.get()),
            placement.control,
            dealt.control,
            control_plane,
            idle,
        )?);

        // Register metrics once; the scoped callback keeps the borrowed ports alive while polling.
        let port_metrics: Vec<(&Port<'_>, PortMetrics)> = ports
            .iter()
            .map(|port| (port, PortMetrics::new(port.name.as_ref())))
            .collect();
        let mut counters_unavailable = vec![false; port_metrics.len()];
        let mut port_states: Vec<PortTelemetry<'_, '_>> =
            ports.iter().map(PortTelemetry::new).collect();
        spawn_supervisor(
            scope,
            "dpdk",
            MBUF_BURST,
            workers_subsystem,
            monitors,
            status_writer,
            move || {
                let counters = publish_port_counters(&port_metrics, &mut counters_unavailable);
                let reports = publish_port_states(&mut port_states, counters);
                publish_links(&links);
                reports
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
    idle: IdleConfig,
) -> Result<WorkerMonitor<'scope, Infallible>, DriverError>
where
    'p: 'scope,
    'eal: 'scope,
{
    let rx_tasks: Vec<RxTaskMonitor> = control
        .iter()
        .map(|q| RxTaskMonitor::new(&q.name, RxQueue::Control))
        .collect();
    let ports = control
        .into_iter()
        .zip(&rx_tasks)
        .map(|(queues, task)| ControlPort {
            queues,
            watchdog: task.watchdog.clone(),
        })
        .collect();
    let load = Load::new(idle.mode);
    let load_reader = load.reader();
    let worker = ControlWorker::new(id, ports, control_plane, idle, load);
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
    Ok(WorkerMonitor::new(id, handle, rx_tasks).with_load(load_reader))
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

/// What the driver publishes about a port beyond its counters, and what it keeps to do so.
struct PortTelemetry<'p, 'eal> {
    port: &'p Port<'eal>,
    state: PortStateMetrics,
    /// Whether the link was up at the last reading; `None` before the first.
    up: Option<bool>,
    /// Times the link went up or down between readings.
    changes: u64,
    /// The ids and names of the extended statistics published, and where they are read into.
    xstat_ids: Vec<u64>,
    xstat_names: Vec<String>,
    xstat_values: Vec<u64>,
    xstats: XstatMetrics,
    /// Whether the last read of the extended statistics failed, to log a failure once.
    xstats_failed: bool,
}

impl<'p, 'eal> PortTelemetry<'p, 'eal> {
    /// Register a port's state and the extended statistics worth publishing, as its PMD names them.
    fn new(port: &'p Port<'eal>) -> Self {
        let wanted = match port.dev.xstat_names() {
            Ok(names) => xstats::wanted(names),
            Err(e) => {
                info!(
                    "port {} has no extended statistics to publish: {e:?}",
                    port.name
                );
                Vec::new()
            }
        };
        info!(
            "port {} publishes {} extended statistic(s): {}",
            port.name,
            wanted.len(),
            wanted
                .iter()
                .map(|x| x.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        let names: Vec<&str> = wanted.iter().map(|x| x.name.as_str()).collect();
        let xstats = XstatMetrics::new(port.name.as_ref(), &names);
        PortTelemetry {
            port,
            state: PortStateMetrics::new(port.name.as_ref()),
            up: None,
            changes: 0,
            xstat_ids: wanted.iter().map(|x| x.id).collect(),
            xstat_names: wanted.iter().map(|x| x.name.clone()).collect(),
            xstat_values: vec![0; wanted.len()],
            xstats,
            xstats_failed: false,
        }
    }
}

/// Publish each port's link and the occupancy of its pools.
///
/// The link is read here as well as in [`publish_links`], which only covers ports with a tap; a
/// read is a register access, once a second. A link that cannot be read counts as down, as it does
/// there. Changes are counted between readings, so a flap shorter than the polling period is missed.
///
/// Returns a report on each port, with the `counters` read from it, for the driver's status.
fn publish_port_states(
    ports: &mut [PortTelemetry<'_, '_>],
    counters: Vec<Option<PortCounters>>,
) -> Vec<PortReport> {
    let mut reports = Vec::with_capacity(ports.len());
    for (telemetry, counters) in ports.iter_mut().zip(counters) {
        let port = telemetry.port;
        let link = port.dev.link().ok();
        let up = link.is_some_and(|link| link.up);
        if telemetry.up.is_some_and(|was| was != up) {
            telemetry.changes += 1;
        }
        telemetry.up = Some(up);
        let pool = |pool: &dpdk::mem::Pool<'_>| (pool.in_use(), pool.capacity());
        let state = PortState {
            link_up: up,
            speed_mbps: link
                .map(|link| link.speed_mbps)
                .filter(|&speed| speed != u32::MAX),
            link_changes: telemetry.changes,
            rx_pool: pool(&port.rx_pool),
            control_pool: pool(&port.control_pool),
        };
        telemetry.state.publish(&state);

        match port
            .dev
            .xstats(&telemetry.xstat_ids, &mut telemetry.xstat_values)
        {
            Ok(()) => {
                telemetry.xstats.publish(&telemetry.xstat_values);
                telemetry.xstats_failed = false;
            }
            Err(e) => {
                if !telemetry.xstats_failed {
                    warn!(
                        "port {} would not report its extended statistics: {e:?}",
                        port.name
                    );
                }
                telemetry.xstats_failed = true;
            }
        }

        reports.push(PortReport {
            name: port.name.to_string(),
            hardware: port.hardware.clone(),
            mac: port.mac.to_string(),
            mtu: port.mtu,
            link_up: state.link_up,
            speed_mbps: state.speed_mbps,
            link_changes: state.link_changes,
            counters,
            rx_pool: state.rx_pool,
            control_pool: state.control_pool,
            xstats: if telemetry.xstats_failed {
                Vec::new()
            } else {
                telemetry
                    .xstat_names
                    .iter()
                    .cloned()
                    .zip(telemetry.xstat_values.iter().copied())
                    .collect()
            },
        });
    }
    reports
}

/// Publish device counters, logging once per port until a failed read recovers, and return them.
fn publish_port_counters(
    port_metrics: &[(&Port<'_>, PortMetrics)],
    unavailable: &mut [bool],
) -> Vec<Option<PortCounters>> {
    port_metrics
        .iter()
        .enumerate()
        .map(|(slot, (port, metrics))| match port.counters() {
            Ok(counters) => {
                metrics.publish(&counters);
                // Report a later failure after recovery.
                unavailable[slot] = false;
                Some(counters)
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
                None
            }
        })
        .collect()
}
