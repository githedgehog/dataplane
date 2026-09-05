// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! One worker thread, serving one RX queue of every interface.
//!
//! The worker owns a UMEM, a socket per interface bound to its queue, and a
//! pipeline of its own. Its loop is:
//!
//! 1. wait for any of its sockets to have packets, or for the poll to time out
//! 2. take what has arrived off each RX ring as `XdpBuffer`s
//! 3. run them through the pipeline
//! 4. put what comes out on the TX ring of the interface it is destined for
//! 5. hand the frames of dropped packets, and of sent ones, back to the pool,
//!    and top the fill rings back up
//!
//! Nothing here is async: the poll is what the worker blocks on, and its
//! timeout is also what bounds how long the worker takes to notice that it has
//! been cancelled.

use std::io;
use std::time::{Duration, Instant};

use concurrency::sync::Arc;
use concurrency::thread;
#[allow(unused_imports)] // used under loom/shuttle backends
use concurrency::thread::BuilderExt;
use lifecycle::{CancellationToken, Subsystem};
use net::interface::InterfaceIndex;
use net::packet::{DoneReason, Packet};
use pipeline::{DynPipeline, NetworkFunction};
use tracing::{debug, error, info, trace, warn};
use xdp::buffer::XdpBuffer;
use xdp::program::Redirect;
use xdp::socket::{XskConfig, XskSocket, XskUmem};

use crate::drivers::kif::Kif;
use crate::drivers::status::WorkerId;
use crate::drivers::supervisor::{WorkerIfaceMonitor, WorkerMonitor};
use crate::drivers::watchdog::{RxCounters, Watchdog};

/// How long a pass of the loop waits for packets before going round again.
///
/// This is also the worst-case delay between cancellation and the worker
/// noticing it, so it is short enough not to hold up shutdown.
const POLL_TIMEOUT_MS: u16 = 100;

/// How often the kernel's own drop counts are read back.
///
/// Reading them is a syscall, and under load a pass is one batch of packets,
/// so reading every pass would cost one syscall per batch for a number the
/// supervisor only looks at once a second.
const STATISTICS_PERIOD: Duration = Duration::from_millis(500);

/// One interface as the worker sees it: the socket it reads and writes, and
/// the watchdog it reports that interface's traffic on.
struct WorkerInterface {
    /// Interface index, which every packet received here is tagged with.
    ifindex: InterfaceIndex,
    /// The socket bound to this worker's queue of that interface.
    socket: XskSocket,
    /// Watchdog the worker pats and reports this interface's counters on.
    watchdog: Watchdog,
    /// Counters for the pass in progress, reported at the end of it.
    counters: RxCounters,
    /// The kernel's drop count as of the last read. It counts up for the life
    /// of the socket rather than being cleared when it is read, so only the
    /// difference belongs in this pass's counters.
    kernel_drops: u64,
    /// When to read that count again.
    next_statistics: Instant,
}

/// A worker, before it has a thread.
pub(super) struct Worker {
    /// Which worker this is. There is one per queue, so this is the queue too,
    /// but the supervisor names workers by their own index.
    id: WorkerId,
    /// The RX queue this worker serves on every interface.
    queue_id: u32,
    /// The interfaces to serve.
    interfaces: Vec<Kif>,
    /// What redirects packets to this worker's sockets, and which has to be
    /// told about each one as it is bound.
    redirect: Arc<Redirect>,
    /// Builds this worker's pipeline, on the worker's own thread.
    setup_pipeline: Arc<dyn Send + Sync + Fn() -> DynPipeline<XdpBuffer>>,
    /// The workers subsystem, for cancellation and fatal reporting.
    subsystem: Subsystem,
}

impl Worker {
    pub(super) fn new(
        id: WorkerId,
        queue_id: u32,
        interfaces: &[Kif],
        redirect: &Arc<Redirect>,
        setup_pipeline: &Arc<dyn Send + Sync + Fn() -> DynPipeline<XdpBuffer>>,
        subsystem: Subsystem,
    ) -> Self {
        Self {
            id,
            queue_id,
            interfaces: interfaces.to_vec(),
            redirect: redirect.clone(),
            setup_pipeline: setup_pipeline.clone(),
            subsystem,
        }
    }

    /// Put the worker on a thread of `scope` and hand back what the supervisor
    /// watches it through.
    ///
    /// # Errors
    ///
    /// Returns an error if the thread cannot be spawned. Everything the worker
    /// itself sets up is reported from the worker's own thread.
    pub(super) fn start<'scope>(
        self,
        scope: &'scope thread::Scope<'scope, '_>,
    ) -> Result<WorkerMonitor<'scope>, io::Error> {
        let Self {
            id,
            queue_id,
            interfaces,
            redirect,
            setup_pipeline,
            subsystem,
        } = self;

        // The supervisor needs the watchdogs now, and the worker needs the
        // same ones once it is running, so they are made here and shared.
        let ifmonitors: Vec<_> = interfaces
            .iter()
            .map(|kif| WorkerIfaceMonitor::new(&kif.name))
            .collect();
        let worker_ifmonitors = ifmonitors.clone();

        let cancel = subsystem.cancel_token();
        let thread_builder = thread::Builder::new().name(format!("dp-xdp-worker-{id}"));

        let handle = thread_builder.spawn_scoped(scope, move || {
            info!(worker = id, queue = queue_id, "Worker started");

            let mut guard = subsystem.new_exit_guard(format!("worker {id}"), true);

            let result = run(
                id,
                queue_id,
                &interfaces,
                &worker_ifmonitors,
                &redirect,
                &setup_pipeline,
                &cancel,
            );

            if subsystem.is_cancelled() {
                guard.disarm();
            }
            info!(worker = id, "worker exited");
            result
        })?;

        Ok(WorkerMonitor::new(id, handle, ifmonitors))
    }
}

/// Bind this worker's sockets and run its loop until it is cancelled.
fn run(
    id: WorkerId,
    queue_id: u32,
    interfaces: &[Kif],
    ifmonitors: &[WorkerIfaceMonitor],
    redirect: &Redirect,
    setup_pipeline: &Arc<dyn Send + Sync + Fn() -> DynPipeline<XdpBuffer>>,
    cancel: &CancellationToken,
) -> Result<(), io::Error> {
    let config =
        XskConfig::default().for_sockets(u32::try_from(interfaces.len()).unwrap_or(u32::MAX));

    let mut umem = XskUmem::new(config).map_err(io::Error::other)?;

    // Zipped, so the table is in the order of the monitors the supervisor
    // holds and a worker's counters land on the right interface.
    let mut ports: Vec<WorkerInterface> = Vec::with_capacity(interfaces.len());
    for (kif, monitor) in interfaces.iter().zip(ifmonitors) {
        let socket = umem
            .bind(&kif.name, queue_id, redirect)
            .map_err(|e| io::Error::other(format!("{e}")))?;
        ports.push(WorkerInterface {
            ifindex: kif.ifindex,
            socket,
            watchdog: monitor.watchdog.clone(),
            counters: RxCounters::default(),
            kernel_drops: 0,
            next_statistics: Instant::now(),
        });
    }

    let mut pipeline = setup_pipeline();
    // Everything the loop needs room for, allocated once rather than per pass.
    let mut received: Vec<XdpBuffer> = Vec::with_capacity(xdp::socket::BATCH_SIZE);
    let mut processed: Vec<Packet<XdpBuffer>> = Vec::with_capacity(xdp::socket::BATCH_SIZE);
    let mut ready: Vec<bool> = Vec::with_capacity(ports.len());

    info!(
        worker = id,
        queue = queue_id,
        interfaces = ports.len(),
        frames = umem.total_frames(),
        "Worker ready"
    );

    while !cancel.is_cancelled() {
        let any = xdp::socket::wait_for_packets(
            ports.iter().map(|port| &port.socket),
            POLL_TIMEOUT_MS,
            &mut ready,
        )?;

        // Even with nothing to read the rings need servicing: the kernel may
        // have finished transmitting, and the fill rings run down.
        if any {
            for index in 0..ports.len() {
                // Skip the sockets the poll said have nothing; asking anyway
                // reads a cache line the kernel owns.
                if ready.get(index).copied().unwrap_or(true) {
                    let counters = forward_from(
                        id,
                        index,
                        &mut umem,
                        &mut ports,
                        &mut pipeline,
                        &mut received,
                        &mut processed,
                    );
                    if let Some(port) = ports.get_mut(index) {
                        port.counters.rx += counters.rx;
                        port.counters.tx += counters.tx;
                        port.counters.ppline_drops += counters.ppline_drops;
                        port.counters.local += counters.local;
                        port.counters.tx_drops += counters.tx_drops;
                        port.counters.parse_errors += counters.parse_errors;
                    }
                }
            }
        }

        pat_and_service(&mut umem, &mut ports);
    }

    info!(worker = id, queue = queue_id, "Worker cancelled");
    Ok(())
}

/// Take what has arrived on one interface, run it through the pipeline, and
/// send what comes out on whichever interface it is destined for.
fn forward_from(
    id: WorkerId,
    index: usize,
    umem: &mut XskUmem,
    ports: &mut [WorkerInterface],
    pipeline: &mut DynPipeline<XdpBuffer>,
    received: &mut Vec<XdpBuffer>,
    processed: &mut Vec<Packet<XdpBuffer>>,
) -> RxCounters {
    let mut counters = RxCounters::default();

    let Some(port) = ports.get_mut(index) else {
        return counters;
    };

    received.clear();
    let frames = port.socket.recv(umem, received) as u64;
    if frames == 0 {
        return counters;
    }
    let ifindex = port.ifindex;

    let mut parse_errors = 0u64;
    let packets = received
        .drain(..)
        .filter_map(|buffer| match Packet::new(buffer) {
            Ok(mut packet) => {
                // The pipeline routes on where a packet came from, so this has
                // to be set before it reaches the ingress stage.
                packet.meta_mut().iif = Some(ifindex);
                Some(packet)
            }
            Err(e) => {
                parse_errors += 1;
                debug!(worker = id, interface = %ifindex, "Failed to parse packet: {e}");
                None
            }
        });

    // The pipeline borrows the buffers it is given, so what comes out has to
    // be collected before any socket is touched again.
    processed.clear();
    processed.extend(pipeline.process(packets));

    // A frame we could not parse never became a packet, so it is counted as a
    // parse error rather than as something the pipeline dropped.
    let parsed = frames.saturating_sub(parse_errors);
    counters.rx = parsed;
    counters.parse_errors = parse_errors;
    counters.ppline_drops = parsed.saturating_sub(processed.len() as u64);

    for packet in processed.drain(..) {
        match packet.get_done() {
            Some(DoneReason::Delivered) => {
                if transmit(id, umem, ports, packet) {
                    counters.tx += 1;
                } else {
                    counters.tx_drops += 1;
                }
            }
            // The pipeline wants the host stack to have this one, and we
            // cannot give it: nothing in userspace can inject into an
            // interface's receive path. It has to be the XDP program that
            // passes such traffic to the kernel rather than redirecting it
            // here, so counting these counts what the host is missing.
            Some(DoneReason::Local) => counters.local += 1,
            // Anything else the pipeline is done with goes no further.
            _ => {}
        }
    }

    counters
}

/// Send one packet out of the interface its metadata names. Returns whether it
/// went.
fn transmit(
    id: WorkerId,
    umem: &mut XskUmem,
    ports: &mut [WorkerInterface],
    packet: Packet<XdpBuffer>,
) -> bool {
    let Some(oif) = packet.meta().oif else {
        error!(
            worker = id,
            "Missing oif in packet metadata. Will drop packet (pipeline bug)"
        );
        return false;
    };

    // A worker serves a handful of interfaces, so a scan beats hashing.
    let Some(port) = ports.iter_mut().find(|port| port.ifindex == oif) else {
        warn!(worker = id, "TX drop: unknown oif {oif} (driver bug)");
        return false;
    };

    let buffer = match packet.serialize() {
        Ok(buffer) => buffer,
        Err(e) => {
            warn!(worker = id, "Serialize failed: {e:?}");
            return false;
        }
    };

    // The serialized packet is in a UMEM frame of its own, which goes back to
    // the pool when it is dropped at the end of this function; send copies it
    // into the frame it puts on the ring.
    match port.socket.send(umem, buffer.as_ref()) {
        Ok(()) => {
            trace!(
                worker = id,
                "TX {} bytes on interface {}",
                buffer.as_ref().len(),
                port.socket.if_name()
            );
            true
        }
        Err(e) => {
            debug!(
                worker = id,
                "TX failed on interface {}: {e}",
                port.socket.if_name()
            );
            false
        }
    }
}

/// Report the pass that just ended, and give the kernel back what it needs:
/// the frames it has finished with, and free ones to receive into.
fn pat_and_service(umem: &mut XskUmem, ports: &mut [WorkerInterface]) {
    // Frames the pipeline dropped come back over a channel, from wherever they
    // were dropped, and are of no use until they are back on the free list.
    umem.reclaim_dropped();

    for port in ports.iter_mut() {
        if let Err(e) = port.socket.flush_tx() {
            debug!(
                "Could not wake the kernel for TX on {}: {e}",
                port.socket.if_name()
            );
        }
        port.socket.service(umem);

        // The kernel counts what it had to drop because the fill ring was
        // empty; that is ours to know about, not something we ever see. It is
        // a syscall, so it is read on a timer rather than every pass.
        let now = Instant::now();
        if now >= port.next_statistics {
            port.next_statistics = now + STATISTICS_PERIOD;
            match port.socket.statistics() {
                Ok(stats) => {
                    let dropped = stats.rx_dropped();
                    port.counters.kernel_drops += dropped.saturating_sub(port.kernel_drops);
                    port.kernel_drops = dropped;
                }
                Err(e) => debug!(
                    "Could not read socket statistics on {}: {e}",
                    port.socket.if_name()
                ),
            }
        }

        port.watchdog.pat();
        port.watchdog.record(&port.counters);
        port.counters = RxCounters::default();
    }
}
