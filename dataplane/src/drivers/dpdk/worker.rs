// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The per-worker run-to-completion loop: receive a burst, run the pipeline, transmit the result.

use std::collections::HashMap;

use concurrency::sync::Arc;
use dpdk::lcore::LCore;
use dpdk::mem::{MBUF_BURST, Mbuf, MbufArray};
use lifecycle::Subsystem;
use net::buffer::Append;
use net::headers::TryEth;
use net::interface::InterfaceIndex;
use net::packet::Packet;
use pipeline::{DynPipeline, NetworkFunction};
use tracing::{debug, error, trace, warn};

use crate::drivers::status::WorkerId;
use crate::drivers::watchdog::{RxCounters, Watchdog};

use super::port::PortQueues;
use crate::drivers::cpbridge::{Disposition, addressed_to, disposition};

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

/// How many frames the kernel may inject on one port in a single poll.
///
/// A whole burst, which is what a transmit takes at once. The bound is what keeps a control plane
/// that is producing faster than the wire can carry from starving the receive side of this worker's
/// loop: whatever is left stays queued and goes out next poll.
const INJECT_PER_POLL: usize = MBUF_BURST;

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
        // Register with the EAL before anything allocates. An unregistered thread reports
        // `LCORE_ID_ANY`, and `rte_mempool_default_cache` returns NULL for that -- so every
        // `alloc_bulk` and every mbuf free would go to the shared ring under atomics, on every
        // burst, in both directions. The token releases the id however this thread ends; leaking
        // one strands it for the life of the process.
        //
        // It is bound rather than discarded because it is also the capability that unlocks
        // `dpdk::power`: a sleep-until-a-packet-arrives loop is gated on `&LCore`, and this is the
        // only place a worker can get one.
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
            lcore = dpdk::lcore::LCoreId::current().0,
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

    /// Do one port's work: inject whatever the kernel has queued, then receive a burst, run it
    /// through the pipeline, and transmit.
    ///
    /// Returns whether there was anything to do, which is what paces the idle backoff.
    fn poll_one(
        &mut self,
        slot: usize,
        tx_by_if: &HashMap<InterfaceIndex, usize>,
        pipeline: &mut DynPipeline<'p, Mbuf<'p>>,
        counters: &mut RxCounters,
    ) -> bool {
        // Before the receive, and unconditionally: a port with no incoming traffic still has to
        // carry the control plane's outgoing traffic, and a BGP session whose keepalives only left
        // when data happened to arrive would drop on the first quiet hold timer.
        let injected = self.inject(slot, counters);

        let burst = self.queues[slot].rx.receive();
        if burst.is_empty() {
            return injected;
        }
        counters.rx += burst.len() as u64;

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
        // Drops are counted below, by verdict, rather than derived from how many packets the
        // pipeline swallowed. The pipeline no longer swallows any: it hands every packet over with
        // its verdict attached, because only the driver knows whether there is a kernel to punt one
        // to. Deriving the count here would now report zero drops however many packets an ACL
        // rejected.

        // Group by outbound port, so each port's transmit is one `rte_eth_tx_burst` rather than one
        // per packet. A burst of 64 spread across two ports should cost two transmits, not 64.
        let mut batches: HashMap<usize, MbufArray<'p>> = HashMap::new();
        // Borrowed for the packet loop rather than cloned per poll: an `mpsc::Sender` clone is an
        // atomic increment, which is not free at burst rates and buys nothing here.
        let port_mac = self.queues[slot].mac;
        let punt = self.queues[slot].punt.as_ref();
        for packet in processed {
            // Who the frame was addressed to, read before the pipeline's verdict is acted on. It is
            // only consulted for verdicts that did not rewrite the ethernet header, so this is the
            // destination the frame arrived with.
            let addressed_to_us = packet
                .try_eth()
                .is_some_and(|eth| addressed_to(eth.destination().inner(), port_mac));

            match disposition(packet.get_done(), addressed_to_us) {
                Disposition::Transmit => {}
                Disposition::Punt => {
                    Self::punt(self.id, &self.queues[slot].name, punt, packet, counters);
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

    /// Move whatever the kernel has queued for this port onto the wire.
    ///
    /// Returns whether anything was injected, which counts as activity for the idle backoff.
    ///
    /// # Why this bypasses the pipeline
    ///
    /// FRR has already made the forwarding decision. These frames come off a tap that stands in for
    /// this exact port, with the headers the kernel built; running them through the pipeline would
    /// route them a second time, by tables the kernel's own decision was derived from.
    ///
    /// # Why this transmits separately rather than joining the forwarding batch
    ///
    /// A transmit batch holds one burst. Sharing it would let a burst of forwarded traffic crowd
    /// out the control plane -- exactly backwards, since losing a BGP keepalive costs the session
    /// and losing a forwarded packet costs a retransmit. The extra `rte_eth_tx_burst` only happens
    /// when there was something to inject, which at control-plane rates is rare.
    fn inject(&mut self, slot: usize, counters: &mut RxCounters) -> bool {
        let queue = &mut self.queues[slot];
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
