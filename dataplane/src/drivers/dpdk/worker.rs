// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The per-worker run-to-completion loop: receive a burst, run the pipeline, transmit the result.

use std::collections::HashMap;

use concurrency::sync::Arc;
use dpdk::lcore::LCore;
use dpdk::mem::{MBUF_BURST, Mbuf, MbufArray};
use lifecycle::Subsystem;
use net::buffer::{Append, PacketBufferMut};
use net::headers::TryEth;
use net::interface::InterfaceIndex;
use net::packet::DoneReason;
use net::packet::Packet;
use pipeline::{DynPipeline, NetworkFunction};
use tracing::{debug, error, trace, warn};

use crate::drivers::status::WorkerId;
use crate::drivers::watchdog::{RxCounters, Watchdog};

use super::port::PortQueues;
use crate::drivers::cpbridge::{Disposition, addressed_to, disposition};

#[cfg(all(test, not(feature = "shuttle")))]
mod tests;

/// Yield after this many consecutive polls without traffic on any port.
const IDLE_POLLS_BEFORE_YIELD: u32 = 128;

/// Polls between cancellation checks and watchdog updates.
const CANCEL_CHECK_INTERVAL: u32 = 1024;

/// One port's queue pair as seen by a worker, and the watchdog its traffic is reported on.
pub(crate) struct WorkerPort<'p> {
    pub(crate) queues: PortQueues<'p>,
    pub(crate) watchdog: Watchdog,
}
/// Bound control-plane injection so receiving traffic cannot starve.
const INJECT_PER_POLL: usize = MBUF_BURST;

/// A worker and its exclusively owned queue handles.
pub(crate) struct Worker<'p> {
    id: WorkerId,
    ports: Vec<WorkerPort<'p>>,
}

impl<'p> Worker<'p> {
    pub(crate) fn new(id: WorkerId, ports: Vec<WorkerPort<'p>>) -> Self {
        Self { id, ports }
    }

    /// Run until cancelled, constructing the non-Send pipeline on this thread.
    pub(crate) fn run(
        mut self,
        subsystem: &Subsystem,
        setup_pipeline: &Arc<dyn Send + Sync + Fn() -> DynPipeline<'p, Mbuf<'p>> + 'p>,
        timer_handle: &tokio::runtime::Handle,
    ) {
        // Run flow and NAT timers on the management runtime until worker helpers replace it.
        let _runtime = timer_handle.enter();
        // Register with the EAL before anything allocates. An unregistered thread reports
        // `LCORE_ID_ANY`, and `rte_mempool_default_cache` returns NULL for that -- so every
        // `alloc_bulk` and every mbuf free would go to the shared ring under atomics, on every
        // burst, in both directions. The token releases the id however this thread ends; leaking
        // one strands it for the life of the process.
        //
        // A worker that cannot register is left to run anyway. It is slower, not wrong: the
        // mempool falls back to the ring, which is correct, just contended. Refusing to forward
        // traffic over a performance property would be the worse failure.
        let _lcore = match LCore::register() {
            Ok(lcore) => Some(lcore),
            Err(e) => {
                error!(
                    worker = self.id,
                    "could not register with the EAL ({e:?}); this worker will run without a \
                     per-core mempool cache and will contend on every allocation"
                );
                None
            }
        };

        let mut pipeline = setup_pipeline();

        // Map pipeline output ifindices to this worker's transmit queues.
        let tx_by_if: HashMap<InterfaceIndex, usize> = self
            .ports
            .iter()
            .enumerate()
            .map(|(slot, p)| (p.queues.if_index, slot))
            .collect();

        debug!(
            worker = self.id,
            lcore = dpdk::lcore::LCoreId::current().0,
            "DPDK worker started on {} port(s): {}",
            self.ports.len(),
            self.ports
                .iter()
                .map(|p| p.queues.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );

        let mut idle_polls: u32 = 0;
        let mut polls: u32 = 0;
        // Counters per port, flushed to that port's watchdog.
        let mut counters = vec![RxCounters::default(); self.ports.len()];

        // The burst the pipeline works in, owned by this worker and reused for the life of the
        // thread. Every stage borrows it, so a packet is rewritten where it lies instead of being
        // moved from stage to stage, and the allocation happens once rather than once per poll.
        let mut burst: Vec<Packet<Mbuf<'p>>> = Vec::with_capacity(dpdk::mem::MBUF_BURST);

        // Likewise for what the PMD hands back. `RxQueue::receive` returns its array by value,
        // which is 64 slots copied on every poll whether or not anything arrived; owning one here
        // and refilling it makes an empty poll cost nothing but the poll.
        let mut rx_mbufs: MbufArray<'p> = MbufArray::new_empty();

        loop {
            polls = polls.wrapping_add(1);
            if polls.is_multiple_of(CANCEL_CHECK_INTERVAL) {
                if subsystem.is_cancelled() {
                    break;
                }
                self.report(&mut counters);
            }

            let mut saw_frames = false;
            for (slot, counters) in counters.iter_mut().enumerate() {
                if self.poll_one(
                    slot,
                    &tx_by_if,
                    &mut pipeline,
                    &mut burst,
                    &mut rx_mbufs,
                    counters,
                ) {
                    saw_frames = true;
                }
            }

            if saw_frames {
                idle_polls = 0;
            } else {
                idle_polls += 1;
                if idle_polls >= IDLE_POLLS_BEFORE_YIELD {
                    idle_polls = 0;
                    std::thread::yield_now();
                }
            }
        }

        self.report(&mut counters);
        debug!(worker = self.id, "DPDK worker stopping");
    }

    /// Pat every port's watchdog and flush its counters to it.
    fn report(&self, counters: &mut [RxCounters]) {
        for (port, counters) in self.ports.iter().zip(counters) {
            // Pat even when idle; recording zero packets does not establish liveness.
            port.watchdog.pat();
            port.watchdog.record(counters);
            *counters = RxCounters::default();
        }
    }

    /// Do one port's work: inject whatever the kernel has queued, then receive a burst, run it
    /// through the pipeline, and transmit.
    ///
    /// Transmit outcomes are counted against the receiving port, as the kernel driver does.
    /// Returns whether there was anything to do, which is what paces the idle backoff.
    fn poll_one(
        &mut self,
        slot: usize,
        tx_by_if: &HashMap<InterfaceIndex, usize>,
        pipeline: &mut DynPipeline<'p, Mbuf<'p>>,
        burst: &mut Vec<Packet<Mbuf<'p>>>,
        rx_mbufs: &mut MbufArray<'p>,
        counters: &mut RxCounters,
    ) -> bool {
        // Before the receive, and unconditionally: a port with no incoming traffic still has to
        // carry the control plane's outgoing traffic, and a BGP session whose keepalives only left
        // when data happened to arrive would drop on the first quiet hold timer.
        let injected = self.inject(slot, counters);

        self.ports[slot].queues.rx.receive_into(rx_mbufs);
        if rx_mbufs.is_empty() {
            return injected;
        }
        let rx_if = self.ports[slot].queues.if_index;
        process_burst(rx_mbufs.drain_all(), rx_if, pipeline, burst, counters);

        // Batch transmission by output port.
        let mut batches: HashMap<usize, MbufArray<'p>> = HashMap::new();
        // Borrowed for the packet loop rather than cloned per poll: an `mpsc::Sender` clone is an
        // atomic increment, which is not free at burst rates and buys nothing here.
        let port_mac = self.ports[slot].queues.mac;
        let punt = self.ports[slot].queues.punt.as_ref();
        for packet in burst.drain(..) {
            // Who the frame was addressed to, read before the pipeline's verdict is acted on. It is
            // only consulted for verdicts that did not rewrite the ethernet header, so this is the
            // destination the frame arrived with.
            let addressed_to_us = packet
                .try_eth()
                .is_some_and(|eth| addressed_to(eth.destination().inner(), port_mac));

            match disposition(packet.get_done(), addressed_to_us) {
                Disposition::Transmit => {}
                Disposition::Punt => {
                    Self::punt(
                        self.id,
                        &self.ports[slot].queues.name,
                        punt,
                        packet,
                        counters,
                    );
                    continue;
                }
                // A packet the pipeline finished with and the kernel has no business seeing.
                // Dropping it here frees its mbuf.
                Disposition::Drop => {
                    counters.ppline_drops += 1;
                    continue;
                }
            }

            let Some(oif) = packet.meta().oif else {
                warn!(
                    worker = self.id,
                    "pipeline delivered a packet with no oif; dropping (pipeline bug)"
                );
                counters.tx_drops += 1;
                continue;
            };

            let Some(&out_slot) = tx_by_if.get(&oif) else {
                warn!(
                    worker = self.id,
                    "pipeline delivered a packet for interface {oif}, which this driver does not \
                     own; dropping"
                );
                counters.tx_drops += 1;
                continue;
            };

            // Serialize rewritten headers into the original mbuf.
            match packet.serialize() {
                Ok(mbuf) => {
                    let batch = batches.entry(out_slot).or_insert_with(MbufArray::new_empty);
                    if batch.try_push(mbuf).is_err() {
                        // A pipeline that duplicates packets can exceed one transmit burst.
                        error!(
                            worker = self.id,
                            "transmit batch for interface {oif} overflowed one burst; dropping"
                        );
                        counters.tx_drops += 1;
                    }
                }
                Err(e) => {
                    counters.tx_drops += 1;
                    trace!("failed to serialize a packet for transmit: {e:?}");
                }
            }
        }

        for (out_slot, batch) in batches {
            let attempted = batch.len() as u64;
            let unsent = self.ports[out_slot].queues.tx.transmit(batch);
            let refused = unsent.len() as u64;
            counters.tx += attempted - refused;
            if refused > 0 {
                // Dropping the unsent batch frees packets refused under backpressure.
                counters.tx_drops += refused;
                trace!(
                    worker = self.id,
                    "tx queue on {} refused {refused} of {attempted} packets",
                    self.ports[out_slot].queues.name
                );
            }
        }

        true
    }

    /// Hand one frame to the kernel through the ingress port's tap.
    ///
    /// The frame is copied, because that is the only thing it can be: an `Mbuf` is `!Send` and
    /// branded with the EAL's lifetime, and the far end of this channel is a task on the management
    /// runtime. `serialize` first, so what the kernel sees is the frame as the pipeline left it --
    /// the same buffer a transmit would have sent -- rather than the payload without its headers.
    fn punt(
        id: WorkerId,
        port: &str,
        punt: Option<&tokio::sync::mpsc::Sender<crate::drivers::cpbridge::Frame>>,
        packet: Packet<Mbuf<'p>>,
        counters: &mut RxCounters,
    ) {
        // No bridge means no tap to punt to, which is every configuration that did not ask for one.
        // The packet is dropped exactly as it was before this path existed.
        let Some(punt) = punt else {
            return;
        };
        let mbuf = match packet.serialize() {
            Ok(mbuf) => mbuf,
            Err(e) => {
                counters.tx_drops += 1;
                trace!(
                    worker = id,
                    "failed to serialize a frame to punt on {port}: {e:?}"
                );
                return;
            }
        };
        // `try_send` rather than a blocking send: this is the packet path, and there is nothing it
        // may wait for. A full queue means the tap's pump is not keeping up, which is a control
        // plane problem and not a reason to stop forwarding.
        if punt.try_send(mbuf.raw_data().to_vec()).is_err() {
            counters.tx_drops += 1;
            trace!(
                worker = id,
                "punt queue for {port} is full; dropping a frame for the kernel"
            );
        }
    }

    /// Send kernel frames directly through this port, bypassing the forwarding pipeline.
    /// Use a separate burst so forwarded traffic cannot fill the control-plane batch.
    /// Returns whether any frames were injected, for idle backoff accounting.
    fn inject(&mut self, slot: usize, counters: &mut RxCounters) -> bool {
        let queue = &mut self.ports[slot].queues;
        let Some(inject) = queue.inject.as_mut() else {
            return false;
        };

        // Drained into a local buffer first: the mbufs come from a pool this same struct owns, so
        // the receiver's borrow has to end before the allocation begins. Bounded by
        // `INJECT_PER_POLL`, which is also the batch's capacity, so the `try_push` below cannot
        // overflow.
        let mut frames: Vec<crate::drivers::cpbridge::Frame> = Vec::new();
        for _ in 0..INJECT_PER_POLL {
            let Ok(frame) = inject.try_recv() else {
                break;
            };
            frames.push(frame);
        }
        if frames.is_empty() {
            return false;
        }

        // All-or-nothing, which is what the DPDK bulk allocator gives: a partial allocation would
        // have to be unwound by hand.
        let mbufs = match queue.pool.alloc_bulk(frames.len()) {
            Ok(mbufs) => mbufs,
            Err(e) => {
                counters.tx_drops += frames.len() as u64;
                warn!(
                    worker = self.id,
                    "could not allocate {} mbuf(s) to inject on {}: {e}. The control plane's \
                     traffic is being dropped because the port's receive pool is exhausted.",
                    frames.len(),
                    queue.name
                );
                return false;
            }
        };

        // Filled and pushed in one pass, so an mbuf whose frame could not be copied is simply not
        // pushed -- and being owned by this loop, it is freed when the iteration drops it rather
        // than transmitted empty.
        let mut batch = MbufArray::new_empty();
        for (mut mbuf, frame) in mbufs.into_iter().zip(frames) {
            let Ok(len) = u16::try_from(frame.len()) else {
                counters.tx_drops += 1;
                warn!(
                    worker = self.id,
                    "the kernel offered a {} byte frame on {}, which is not a frame; dropping it",
                    frame.len(),
                    queue.name
                );
                continue;
            };
            match mbuf.append(len) {
                Ok(room) => room.copy_from_slice(&frame),
                Err(e) => {
                    counters.tx_drops += 1;
                    warn!(
                        worker = self.id,
                        "the kernel offered a {len} byte frame on {}, which does not fit an mbuf \
                         from its pool ({e}); dropping it. The tap's MTU and the port's disagree.",
                        queue.name
                    );
                    continue;
                }
            }
            if batch.try_push(mbuf).is_err() {
                // Unreachable: at most `INJECT_PER_POLL` frames were drained and that is the
                // batch's capacity. Counted rather than asserted, because losing a control frame is
                // not worth stopping the packet path for.
                counters.tx_drops += 1;
            }
        }

        let attempted = batch.len() as u64;
        if attempted == 0 {
            return false;
        }
        let unsent = queue.tx.transmit(batch);
        let refused = unsent.len() as u64;
        counters.tx += attempted - refused;
        if refused > 0 {
            counters.tx_drops += refused;
            trace!(
                worker = self.id,
                "tx queue on {} refused {refused} of {attempted} injected frame(s)", queue.name
            );
        }
        true
    }
}

/// Parse a burst and retain forwarded packets and possible control-plane traffic.
fn process_burst<Buf: PacketBufferMut>(
    burst: impl ExactSizeIterator<Item = Buf>,
    rx_if: InterfaceIndex,
    pipeline: &mut impl NetworkFunction<Buf>,
    packets: &mut Vec<Packet<Buf>>,
    counters: &mut RxCounters,
) {
    counters.rx += burst.len() as u64;
    packets.clear();
    packets.extend(burst.filter_map(|buffer| match Packet::new(buffer) {
        Ok(mut packet) => {
            packet.meta_mut().iif = Some(rx_if);
            Some(packet)
        }
        Err(e) => {
            counters.parse_errors += 1;
            trace!("failed to parse a received frame: {e:?}");
            None
        }
    }));

    let parsed = packets.len();
    pipeline.process_burst(packets);
    // Some stages remove packets instead of returning a drop verdict.
    counters.ppline_drops += parsed.saturating_sub(packets.len()) as u64;
    packets.retain(|packet| {
        if let Some(
            DoneReason::Delivered
            | DoneReason::Local
            | DoneReason::Unhandled
            | DoneReason::NotIp
            | DoneReason::RouteFailure,
        ) = packet.get_done()
        {
            true
        } else {
            counters.ppline_drops += 1;
            false
        }
    });
}
