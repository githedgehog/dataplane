// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The per-worker run-to-completion loop: receive a burst, run the pipeline, transmit the result.

use std::collections::HashMap;

use concurrency::sync::Arc;
use dpdk::mem::{Mbuf, MbufArray};
use lifecycle::Subsystem;
use net::buffer::PacketBufferMut;
use net::interface::InterfaceIndex;
use net::packet::{DoneReason, Packet};
use pipeline::{DynPipeline, NetworkFunction};
use tracing::{debug, error, trace, warn};

use crate::drivers::status::WorkerId;
use crate::drivers::watchdog::{RxCounters, Watchdog};

use super::port::PortQueues;

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
                if self.poll_one(slot, &tx_by_if, &mut pipeline, counters) {
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

    /// Receive one burst from the port in `slot`, run it through the pipeline, and transmit.
    ///
    /// Transmit outcomes are counted against the receiving port, as the kernel driver does.
    /// Returns whether any frame was received, which is what paces the idle backoff.
    fn poll_one(
        &mut self,
        slot: usize,
        tx_by_if: &HashMap<InterfaceIndex, usize>,
        pipeline: &mut DynPipeline<'p, Mbuf<'p>>,
        counters: &mut RxCounters,
    ) -> bool {
        let burst = self.ports[slot].queues.rx.receive();
        if burst.is_empty() {
            return false;
        }
        let rx_if = self.ports[slot].queues.if_index;
        let processed = process_burst(burst.into_iter(), rx_if, pipeline, counters);

        // Batch transmission by output port.
        let mut batches: HashMap<usize, MbufArray<'p>> = HashMap::new();
        for packet in processed {
            match packet.get_done() {
                Some(DoneReason::Delivered) => {}
                // Locally consumed packets release their mbufs here.
                _ => continue,
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
}

/// Parse a burst and retain packets delivered to an interface or the local stack.
fn process_burst<Buf: PacketBufferMut>(
    burst: impl ExactSizeIterator<Item = Buf>,
    rx_if: InterfaceIndex,
    pipeline: &mut impl NetworkFunction<Buf>,
    counters: &mut RxCounters,
) -> Vec<Packet<Buf>> {
    counters.rx += burst.len() as u64;
    let mut packets: Vec<_> = burst
        .filter_map(|buffer| match Packet::new(buffer) {
            Ok(mut packet) => {
                packet.meta_mut().iif = Some(rx_if);
                Some(packet)
            }
            Err(e) => {
                counters.parse_errors += 1;
                trace!("failed to parse a received frame: {e:?}");
                None
            }
        })
        .collect();

    let parsed = packets.len();
    pipeline.process_burst(&mut packets);
    // Some stages remove packets instead of returning a drop verdict.
    counters.ppline_drops += parsed.saturating_sub(packets.len()) as u64;
    packets.retain(|packet| {
        if let Some(DoneReason::Delivered | DoneReason::Local) = packet.get_done() {
            true
        } else {
            counters.ppline_drops += 1;
            false
        }
    });
    packets
}
