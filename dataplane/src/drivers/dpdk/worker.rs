// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The per-worker run-to-completion loop: receive a burst, run the pipeline, transmit the result.

use std::collections::HashMap;

use concurrency::sync::Arc;
use dpdk::mem::{Mbuf, MbufArray};
use lifecycle::Subsystem;
use net::interface::InterfaceIndex;
use net::packet::{DoneReason, Packet};
use pipeline::{DynPipeline, NetworkFunction};
use tracing::{debug, error, trace, warn};

use crate::drivers::status::WorkerId;
use crate::drivers::watchdog::{RxCounters, Watchdog};

use super::port::PortQueues;

/// How many consecutive empty polls across every port before the worker yields its timeslice.
///
/// A busy-poll loop is the right shape for a datapath under load and the wrong shape for a
/// developer's workstation, where it pins a core at 100% doing nothing. Yielding after a run of
/// idle polls costs nothing when traffic is flowing (the counter resets on the first frame) and
/// keeps an idle dataplane from looking like a runaway process.
///
/// This is a spike-grade compromise. A production build wants the choice to be explicit --
/// busy-poll for latency, or sleep/interrupt-driven for density -- not inferred from a constant.
const IDLE_POLLS_BEFORE_YIELD: u32 = 128;

/// How often the worker checks whether it has been told to stop, in polls.
///
/// Checking a `CancellationToken` is an atomic load, which is cheap but not free at burst rates, so
/// it is amortised. The interval bounds shutdown latency at this many polls, which is microseconds.
const CANCEL_CHECK_INTERVAL: u32 = 1024;

/// Everything one worker owns for the duration of the run.
///
/// The queues are held by value. That is not incidental: `rte_eth_rx_burst` and `rte_eth_tx_burst`
/// are not safe to call concurrently on one queue, and taking the handles out of the device once
/// and moving them here makes sharing one unrepresentable rather than merely discouraged.
pub(crate) struct Worker<'p> {
    id: WorkerId,
    queues: Vec<PortQueues<'p>>,
    watchdog: Watchdog,
}

impl<'p> Worker<'p> {
    pub(crate) fn new(id: WorkerId, queues: Vec<PortQueues<'p>>, watchdog: Watchdog) -> Self {
        Self {
            id,
            queues,
            watchdog,
        }
    }

    /// Run until the subsystem is cancelled.
    ///
    /// The pipeline is built *here*, on the worker's own thread, rather than handed in. A
    /// `DynPipeline<Mbuf>` is `!Send`, because an `Mbuf` is: an mbuf is a bare pointer into a
    /// mempool with nothing tying its lifetime to that pool's, so letting one cross a thread
    /// boundary un-guarded is the use-after-free this crate's `!Send` exists to prevent. The
    /// factory is `Send + Sync` and its product is not, which is exactly the right split -- it is
    /// also why each worker gets its own pipeline instance rather than sharing one.
    pub(crate) fn run(
        mut self,
        subsystem: &Subsystem,
        setup_pipeline: &Arc<dyn Send + Sync + Fn() -> DynPipeline<'p, Mbuf<'p>> + 'p>,
    ) {
        let mut pipeline = setup_pipeline();

        // Where a packet leaving the pipeline should go, by the interface index the pipeline names
        // in `oif`. Built once: the set of ports a worker drives does not change while it runs.
        let tx_by_if: HashMap<InterfaceIndex, usize> = self
            .queues
            .iter()
            .enumerate()
            .map(|(slot, q)| (q.if_index, slot))
            .collect();

        debug!(
            worker = self.id,
            "DPDK worker started on {} port(s): {}",
            self.queues.len(),
            self.queues
                .iter()
                .map(|q| q.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );

        let mut idle_polls: u32 = 0;
        let mut polls: u32 = 0;
        let mut counters = RxCounters::default();

        loop {
            polls = polls.wrapping_add(1);
            if polls.is_multiple_of(CANCEL_CHECK_INTERVAL) {
                if subsystem.is_cancelled() {
                    break;
                }
                // Two distinct things, and only one of them is liveness. `record` accumulates
                // counters; `pat` is the evidence that this loop was scheduled at all. An idle
                // worker records nothing but is perfectly alive, so without the pat the supervisor
                // reports every quiet worker as stuck -- which it did, until it was fixed here.
                self.watchdog.pat();
                self.watchdog.record(&counters);
                counters = RxCounters::default();
            }

            let mut saw_frames = false;
            for slot in 0..self.queues.len() {
                if self.poll_one(slot, &tx_by_if, &mut pipeline, &mut counters) {
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

        self.watchdog.pat();
        self.watchdog.record(&counters);
        debug!(worker = self.id, "DPDK worker stopping");
    }

    /// Receive one burst from the port in `slot`, run it through the pipeline, and transmit.
    ///
    /// Returns whether any frame was received, which is what paces the idle backoff.
    fn poll_one(
        &mut self,
        slot: usize,
        tx_by_if: &HashMap<InterfaceIndex, usize>,
        pipeline: &mut DynPipeline<'p, Mbuf<'p>>,
        counters: &mut RxCounters,
    ) -> bool {
        let burst = self.queues[slot].rx.receive();
        if burst.is_empty() {
            return false;
        }
        // This burst's count, kept separate from `counters.rx`, which is a running total across the
        // whole watchdog interval. Deriving the pipeline's drop count from the running total
        // instead charges every earlier burst again on each poll -- it reported 13247 drops against
        // 200 received frames before this was fixed.
        let received = burst.len() as u64;
        counters.rx += received;

        let rx_if = self.queues[slot].if_index;

        // Parse, stamping each packet with the interface it arrived on -- the pipeline's ingress
        // stage keys everything off `iif`. A frame that does not parse is dropped here and counted;
        // its mbuf is freed by the `Packet::new` error path dropping the buffer.
        let parse_errors = &mut counters.parse_errors;
        let packets = burst
            .into_iter()
            .filter_map(|mbuf| match Packet::new(mbuf) {
                Ok(mut packet) => {
                    packet.meta_mut().iif = Some(rx_if);
                    Some(packet)
                }
                Err(e) => {
                    *parse_errors += 1;
                    trace!("failed to parse a received frame: {e:?}");
                    None
                }
            });

        // Collected rather than streamed into the transmit step because the pipeline is borrowed
        // mutably for as long as its output iterator lives, and transmitting needs a `&mut` on a
        // queue this worker also owns.
        let processed: Vec<Packet<Mbuf<'p>>> = pipeline.process(packets).collect();
        counters.ppline_drops += received.saturating_sub(processed.len() as u64);

        // Group by outbound port, so each port's transmit is one `rte_eth_tx_burst` rather than one
        // per packet. A burst of 64 spread across two ports should cost two transmits, not 64.
        let mut batches: HashMap<usize, MbufArray<'p>> = HashMap::new();
        for packet in processed {
            match packet.get_done() {
                Some(DoneReason::Delivered) => {}
                // Anything else is a packet the pipeline has finished with: dropped by an ACL,
                // consumed as local delivery, or failed. Dropping it here frees its mbuf.
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

            // Writes the rewritten headers back into the mbuf's own memory and hands the mbuf
            // back, so the buffer that leaves is the buffer that arrived: no copy, no second pool.
            match packet.serialize() {
                Ok(mbuf) => {
                    let batch = batches.entry(out_slot).or_insert_with(MbufArray::new_empty);
                    if batch.try_push(mbuf).is_err() {
                        // An `MbufArray` holds one burst. More than that in a single poll means the
                        // pipeline multiplied packets, which nothing does today.
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
            let unsent = self.queues[out_slot].tx.transmit(batch);
            let refused = unsent.len() as u64;
            counters.tx += attempted - refused;
            if refused > 0 {
                // The unsent remainder is freed when it drops. Backpressure on a transmit ring is
                // normal under load; it is only interesting if it persists.
                counters.tx_drops += refused;
                trace!(
                    worker = self.id,
                    "tx queue on {} refused {refused} of {attempted} packets",
                    self.queues[out_slot].name
                );
            }
        }

        true
    }
}
