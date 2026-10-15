// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The per-worker run-to-completion loop: receive a burst, run the pipeline, transmit the result.

use std::collections::HashMap;

use concurrency::sync::Arc;
use dpdk::lcore::LCore;
use dpdk::mem::{Mbuf, MbufArray};
use lifecycle::Subsystem;
use net::buffer::PacketBufferMut;
use net::headers::{TryEth, TryHeaders};
use net::interface::InterfaceIndex;
use net::packet::Packet;
use pipeline::{DynPipeline, NetworkFunction};
use tracing::{debug, error, trace, warn};
use traffic_control::Key;

use crate::drivers::status::WorkerId;
use crate::drivers::watchdog::{RxCounters, Watchdog};

use super::classes::SoftwareClasses;
use super::control::addressed_to;
use super::port::PortQueues;
use crate::drivers::disposition::Disposition;

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

/// Storage a worker reuses from poll to poll rather than allocating per burst.
struct Scratch<'p> {
    /// The parsed burst; stages borrow and update packets in place.
    burst: Vec<Packet<Mbuf<'p>>>,
    /// Control traffic taken off the data path before the pipeline.
    diverted: Vec<Packet<Mbuf<'p>>>,
    /// The receive array, refilled in place rather than returned by value on every poll.
    rx_mbufs: MbufArray<'p>,
    /// One transmit batch per port slot, indexed like the worker's ports.
    tx_batches: Vec<MbufArray<'p>>,
}

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
        // Registration enables per-lcore mempool caches and releases the id on return or unwind.
        // If registration fails, allocation remains correct through the shared mempool ring.
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

        let mut scratch = Scratch {
            burst: Vec::with_capacity(dpdk::mem::MBUF_BURST),
            diverted: Vec::new(),
            rx_mbufs: MbufArray::new_empty(),
            tx_batches: (0..self.ports.len())
                .map(|_| MbufArray::new_empty())
                .collect(),
        };

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
                if self.poll_one(slot, &tx_by_if, &mut pipeline, &mut scratch, counters) {
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

    /// Do one port's work: receive a burst, run it through the pipeline, and transmit.
    ///
    /// Transmit outcomes are counted against the receiving port, as the kernel driver does.
    /// Returns whether there was anything to do, which is what paces the idle backoff.
    #[allow(clippy::too_many_arguments)] // the reused burst storage is threaded through, not owned
    fn poll_one(
        &mut self,
        slot: usize,
        tx_by_if: &HashMap<InterfaceIndex, usize>,
        pipeline: &mut DynPipeline<'p, Mbuf<'p>>,
        scratch: &mut Scratch<'p>,
        counters: &mut RxCounters,
    ) -> bool {
        let Scratch {
            burst,
            diverted,
            rx_mbufs,
            tx_batches,
        } = scratch;
        self.ports[slot].queues.rx.receive_into(rx_mbufs);
        if rx_mbufs.is_empty() {
            return false;
        }
        let rx_if = self.ports[slot].queues.if_index;
        for mbuf in rx_mbufs.iter() {
            mbuf.prefetch_head();
        }
        let fallback = self.ports[slot].queues.fallback.load();
        process_burst(
            rx_mbufs.drain_all(),
            rx_if,
            pipeline,
            burst,
            fallback.as_deref(),
            diverted,
            counters,
        );
        self.punt_diverted(slot, diverted, counters);

        // Freed in one `rte_pktmbuf_free_bulk` when this goes out of scope.
        let mut dropped: MbufArray<'p> = MbufArray::new_empty();
        // Borrowed for the packet loop rather than cloned per poll: an `mpsc::Sender` clone is an
        // atomic increment, which is not free at burst rates and buys nothing here.
        let punt = self.ports[slot].queues.punt.as_ref();
        for packet in burst.drain(..) {
            match Disposition::of(&packet) {
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
                // A packet the pipeline finished with and the kernel has no business seeing. A
                // burst that outgrew the array (a pipeline can add packets) frees the rest singly.
                Disposition::Drop => {
                    counters.ppline_drops += 1;
                    drop(dropped.try_push(packet.discard()));
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
                    if tx_batches[out_slot].try_push(mbuf).is_err() {
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

        for (out_slot, batch) in tx_batches.iter_mut().enumerate() {
            if batch.is_empty() {
                continue;
            }
            let batch = core::mem::replace(batch, MbufArray::new_empty());
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

    /// Hand the kernel the control traffic taken off the data path, if addressed to the port, on
    /// the channel the control worker punts on.
    fn punt_diverted(
        &self,
        slot: usize,
        diverted: &mut Vec<Packet<Mbuf<'p>>>,
        counters: &mut RxCounters,
    ) {
        let queues = &self.ports[slot].queues;
        for packet in diverted.drain(..) {
            let addressed_to_us = packet
                .try_eth()
                .is_some_and(|eth| addressed_to(eth.destination().inner(), queues.mac.inner()));
            if addressed_to_us {
                Self::punt(
                    self.id,
                    &queues.name,
                    queues.control_punt.as_ref(),
                    packet,
                    counters,
                );
            } else {
                counters.ppline_drops += 1;
            }
        }
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
        // DPDK owns the port, so the kernel never sees this frame: count it as a punt drop.
        let Some(punt) = punt else {
            counters.punt_drops += 1;
            return;
        };
        let mbuf = match packet.serialize() {
            Ok(mbuf) => mbuf,
            Err(e) => {
                counters.punt_drops += 1;
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
            counters.punt_drops += 1;
            trace!(
                worker = id,
                "punt queue for {port} is full; dropping a frame for the kernel"
            );
        }
    }
}

/// Parse a burst and run it through the pipeline.
///
/// Control traffic of the `early` classes, which the NIC does not steer to the control queue, is
/// moved to `diverted` before the pipeline sees it. Every other packet comes back, whatever its
/// verdict: the caller counts and frees the drops, in bulk.
fn process_burst<Buf: PacketBufferMut>(
    burst: impl ExactSizeIterator<Item = Buf>,
    rx_if: InterfaceIndex,
    pipeline: &mut impl NetworkFunction<Buf>,
    packets: &mut Vec<Packet<Buf>>,
    early: Option<&SoftwareClasses>,
    diverted: &mut Vec<Packet<Buf>>,
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

    diverted.clear();
    if let Some(early) = early {
        diverted.extend(packets.extract_if(.., |packet| {
            Key::of(packet.headers()).is_ok_and(|key| early.matches(&key))
        }));
    }

    let parsed = packets.len();
    pipeline.process_burst(packets);
    // Stages mark packets to drop rather than removing them, so a drop is always counted.
    debug_assert!(
        packets.len() >= parsed,
        "the pipeline removed {} packet(s) instead of marking them dropped",
        parsed - packets.len()
    );
}
