// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The per-worker run-to-completion loop: receive a burst, run the pipeline, transmit the result.
//!
//! Worker 0 also transmits the kernel's frames for ports without control queues; see
//! [`port`](super::port).

use std::collections::HashMap;

use args::IdleConfig;

use dpdk::lcore::LCore;
use dpdk::mem::{Mbuf, MbufArray};
use lifecycle::Subsystem;
use net::buffer::PacketBufferMut;
use net::eth::mac::Mac;
use net::headers::{TryEth, TryHeaders};
use net::interface::InterfaceIndex;
use net::packet::{DoneReason, Packet};
use pipeline::{DynPipeline, NetworkFunction};
use tracing::{debug, error, info, trace, warn};
use traffic_control::Key;

use crate::drivers::load::{Load, LoadMeter, Spent};
use crate::drivers::sparse_log::log_sparsely;
use crate::drivers::status::WorkerId;
use crate::drivers::watchdog::{RxCounters, Watchdog};
use crate::packet_processor::{PipelineFactory, WorkerPipeline, expiry_budget};

use super::classes::SoftwareClasses;
use super::control::addressed_to;
use super::idle::Idle;
use super::pollstats::{self, Knobs, Phase, PollStats, RX_STORAGE};
use super::port::PortQueues;
use crate::drivers::disposition::Disposition;

// Packets move by value through the burst (parsed into it, drained out of it to transmit). The
// compiler copies up to 256 bytes inline and calls `memmove` beyond that: 8 bytes more (264) cost
// some 7 % per packet on the local BF-3 (2026-11-15), in the call and in the store-to-load
// forwarding stalls of reading a packet just copied that way. Keep it within the limit; test-only
// metadata does not count.
const _: () = assert!(
    core::mem::size_of::<net::packet::Packet<Mbuf<'static>>>() - net::packet::TEST_ONLY_BYTES
        <= 256,
    "Packet<Mbuf> outgrew the 256 bytes the compiler copies inline"
);

#[cfg(all(test, not(feature = "shuttle")))]
mod tests;

/// Idle polls between two flow-expiry passes.
const EXPIRY_IDLE_POLLS: u32 = 64;

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
    rx_mbufs: MbufArray<'p, RX_STORAGE>,
    /// The next burst, received halfway through this one when [`Knobs::prefetch_ahead`] is on.
    ahead: MbufArray<'p, RX_STORAGE>,
    /// One transmit batch per port slot, indexed like the worker's ports.
    tx_batches: Vec<MbufArray<'p, RX_STORAGE>>,
}

/// A worker and its exclusively owned queue handles.
pub(crate) struct Worker<'p> {
    id: WorkerId,
    ports: Vec<WorkerPort<'p>>,
    idle: IdleConfig,
    /// Where the worker reports what it spends its time on.
    load: Load,
}

impl<'p> Worker<'p> {
    pub(crate) fn new(
        id: WorkerId,
        ports: Vec<WorkerPort<'p>>,
        idle: IdleConfig,
        load: Load,
    ) -> Self {
        Self {
            id,
            ports,
            idle,
            load,
        }
    }

    /// Run until cancelled, constructing the non-Send pipeline on this thread.
    #[allow(clippy::too_many_lines)] // bench measurements sit beside the loop they measure
    pub(crate) fn run(
        mut self,
        subsystem: &Subsystem,
        setup_pipeline: &PipelineFactory<'p, Mbuf<'p>>,
    ) {
        // No tokio here: flows and NAT mappings expire on this worker's own wheel, which this loop
        // sweeps (see `expire` below).
        // Registration enables per-lcore mempool caches and releases the id on return or unwind.
        // If registration fails, allocation remains correct through the shared mempool ring.
        let lcore = match LCore::register() {
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

        let WorkerPipeline {
            mut pipeline,
            flows,
        } = setup_pipeline();

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

        let mut idle = Idle::new(self.id, self.idle, lcore.as_ref());
        idle.sleep_on_interrupts(
            self.ports
                .iter()
                .map(|p| (&p.queues.rx, p.queues.rx_interrupts)),
            self.ports
                .iter()
                .filter_map(|p| p.queues.injector.as_ref())
                .map(|injector| injector.frames.doorbell()),
        );
        let mut knobs = Knobs::from_env();
        if knobs.prefetch_ahead && self.ports.len() != 1 {
            warn!(
                worker = self.id,
                "prefetch-ahead keeps one burst in hand, so it needs exactly one port; this worker \
                 has {} and polls without it",
                self.ports.len()
            );
            knobs.prefetch_ahead = false;
        }
        let mut stats = PollStats::new(self.id, knobs);
        let mut polls: u32 = 0;
        // Whether the last expiry pass left work over.
        let mut expiry_behind = false;
        // Counters per port, flushed to that port's watchdog.
        let mut counters = vec![RxCounters::default(); self.ports.len()];

        // Started last, so that setting up does not count as time spent.
        let mut meter = LoadMeter::start();
        let mut scratch = Scratch {
            burst: Vec::with_capacity(RX_STORAGE),
            diverted: Vec::new(),
            rx_mbufs: MbufArray::new_empty(),
            ahead: MbufArray::new_empty(),
            tx_batches: (0..self.ports.len())
                .map(|_| MbufArray::new_empty())
                .collect(),
        };

        loop {
            polls = polls.wrapping_add(1);
            // After a long sleep, the periodic work is due, flow expiry included.
            let woke_late = idle.checks_due();
            if polls.is_multiple_of(CANCEL_CHECK_INTERVAL) || woke_late {
                idle.checked();
                if subsystem.is_cancelled() {
                    break;
                }
                self.report(&mut counters);
                meter.flush(&self.load, idle.mode());
                stats.maybe_report();
            }

            let mut saw_frames = false;
            // The queue to watch first if the worker sleeps: one that received, else one whose
            // port only had frames from the kernel to send.
            let mut received = None;
            let mut injected = None;
            for (slot, counters) in counters.iter_mut().enumerate() {
                let had_frames = self.inject(slot, counters);
                if self.poll_one(
                    slot,
                    &tx_by_if,
                    &mut pipeline,
                    &mut scratch,
                    counters,
                    knobs,
                    &mut stats,
                ) {
                    saw_frames = true;
                    received = Some(slot);
                } else if had_frames && injected.is_none() {
                    injected = Some(slot);
                }
            }
            let busy = received.or(injected);

            // Expire flows after bursts, after long sleeps, and periodically while idle.
            // Drain expiry backlogs a budget per poll before sleeping again, so expired flows
            // do not retain table capacity across repeated sleeps.
            if saw_frames
                || woke_late
                || expiry_behind
                || idle.empty_polls().is_multiple_of(EXPIRY_IDLE_POLLS)
            {
                let budget = expiry_budget(dpdk::mem::MBUF_BURST, self.ports.len(), expiry_behind);
                let sweep = flows.expire(clock::now(), budget);
                expiry_behind = sweep.behind();
                meter.expired(sweep.removed, expiry_behind);
                if sweep.removed > 0 {
                    // Removing flows is work even when no packets came and none are left over:
                    // end the pass here, so the idling that follows is timed apart from it.
                    meter.lap(Spent::Busy);
                }
            }

            meter.lap(self.rest(&mut idle, lcore.as_ref(), busy, expiry_behind));
        }

        self.report(&mut counters);
        meter.flush(&self.load, idle.mode());
        let (sleeps, interrupt_sleeps) = idle.sleeps();
        info!(
            worker = self.id,
            sleeps, interrupt_sleeps, "DPDK worker stopping"
        );
    }

    /// Tell `idle` how the pass went -- traffic on queue `busy`, an expiry backlog, or nothing --
    /// and return what the pass was spent on.
    fn rest(
        &self,
        idle: &mut Idle<'p>,
        lcore: Option<&LCore>,
        busy: Option<usize>,
        expiry_behind: bool,
    ) -> Spent {
        if let Some(slot) = busy {
            idle.busy(slot);
            Spent::Busy
        } else if expiry_behind {
            idle.working();
            Spent::Busy
        } else {
            idle.empty(lcore, self.ports.iter().map(|p| &p.queues.rx))
        }
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

    /// Transmit what the kernel sent out of a port without control queues, if this worker is the
    /// one that does. Returns whether there was anything to send.
    fn inject(&mut self, slot: usize, counters: &mut RxCounters) -> bool {
        let queues = &mut self.ports[slot].queues;
        let Some(injector) = queues.injector.as_mut() else {
            return false;
        };
        injector.inject(self.id, &mut queues.tx, counters)
    }

    /// Do one port's work: receive a burst, run it through the pipeline, and transmit.
    ///
    /// Transmit outcomes are counted against the receiving port, as the kernel driver does.
    /// Returns whether there was anything to do, which is what paces the idle backoff.
    // The reused burst storage is threaded through, not owned; and the bench measurements and
    // prefetch-ahead path sit beside the receive they measure.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn poll_one(
        &mut self,
        slot: usize,
        tx_by_if: &HashMap<InterfaceIndex, usize>,
        pipeline: &mut DynPipeline<'p, Mbuf<'p>>,
        scratch: &mut Scratch<'p>,
        counters: &mut RxCounters,
        knobs: Knobs,
        stats: &mut PollStats,
    ) -> bool {
        let Scratch {
            burst,
            diverted,
            rx_mbufs,
            ahead,
            tx_batches,
        } = scratch;
        let received_at = pollstats::stamp();
        // A burst received halfway through the previous one was counted and prefetched then.
        let from_ahead = !ahead.is_empty();
        if from_ahead {
            core::mem::swap(rx_mbufs, ahead);
        } else {
            let rx = &mut self.ports[slot].queues.rx;
            rx.receive_up_to(rx_mbufs, knobs.burst);
            stats.received(received_at, rx_mbufs.len(), false, || rx.pending());
        }
        if rx_mbufs.is_empty() {
            return false;
        }
        counters.burst(rx_mbufs.len(), dpdk::mem::MBUF_BURST);
        let processing = pollstats::stamp();
        if !from_ahead {
            stats.phase(Phase::Rx, received_at, processing);
        }
        let slide = pollstats::postime::slide();
        if slide > 0 {
            pollstats::postime::set_heads(rx_mbufs.iter().map(|m| m.raw_data().as_ptr()));
            for mbuf in rx_mbufs.iter().take(slide) {
                mbuf.prefetch_head_hint(knobs.hint, knobs.lines);
            }
        } else if pollstats::postime::touch() {
            let mut acc = 0u8;
            if pollstats::postime::touch_mode() == 2 {
                // Line 1 first, as a hint: its fetch overlaps the loads of every line 0.
                for mbuf in rx_mbufs.iter() {
                    let head = mbuf.raw_data().as_ptr();
                    for line in 1..knobs.lines {
                        pollstats::postime::prefetch_t1(head.wrapping_add(line * 64));
                    }
                }
                for mbuf in rx_mbufs.iter() {
                    acc ^= pollstats::postime::touch_line(mbuf.raw_data().as_ptr());
                }
            } else {
                for mbuf in rx_mbufs.iter() {
                    let head = mbuf.raw_data().as_ptr();
                    for line in 0..knobs.lines {
                        acc ^= pollstats::postime::touch_line(head.wrapping_add(line * 64));
                    }
                }
            }
            core::hint::black_box(acc);
        } else if knobs.prefetch_head && (!from_ahead || knobs.near_too) {
            for mbuf in rx_mbufs.iter() {
                mbuf.prefetch_head_hint(knobs.hint, knobs.lines);
            }
        }
        let rx_if = self.ports[slot].queues.if_index;
        let fallback = self.ports[slot].queues.fallback.load();
        if knobs.prefetch_ahead && !knobs.ahead_at_tx {
            // Halfway through the stages, take the next burst and start its heads on their way
            // from DRAM, so they arrive while this burst finishes rather than when that one starts.
            let rx = &mut self.ports[slot].queues.rx;
            let split = pipeline.stages() / 2;
            // Calls to the split closure: one per stage from `split`, plus one after the last.
            let stages_left = pipeline.stages() - split + 1;
            let chunks = knobs.ahead_chunks.clamp(1, stages_left);
            let mut mid_rx = None;
            process_burst_with(
                rx_mbufs.drain_all(),
                rx_if,
                burst,
                fallback.as_deref(),
                diverted,
                counters,
                |packets| {
                    pipeline.process_burst_split(packets, split, |i| {
                        // Receive at the split, then prefetch the heads in `chunks` pieces, one
                        // per stage boundary from there; whatever is left goes after the last
                        // stage.
                        if i == 0 {
                            let at = pollstats::stamp();
                            rx.receive_up_to(ahead, knobs.burst);
                            let done = pollstats::stamp();
                            mid_rx = Some((at, done));
                            stats.received(at, ahead.len(), true, || rx.pending());
                        }
                        let per = ahead.len().div_ceil(chunks).max(1);
                        let (from, to) = if i + 1 >= stages_left {
                            (i * per, ahead.len())
                        } else {
                            (i * per, ((i + 1) * per).min(ahead.len()))
                        };
                        for mbuf in ahead.iter().skip(from).take(to.saturating_sub(from)) {
                            mbuf.prefetch_head_hint(knobs.ahead_hint, knobs.lines);
                        }
                    });
                },
            );
            if let Some((at, done)) = mid_rx {
                stats.moved(Phase::Process, Phase::Rx, at, done);
            }
        } else {
            process_burst(
                rx_mbufs.drain_all(),
                rx_if,
                pipeline,
                burst,
                fallback.as_deref(),
                diverted,
                counters,
            );
        }
        self.punt_diverted(slot, diverted, counters);
        if knobs.prefetch_ahead && knobs.ahead_at_tx {
            // Take the next burst before serializing and transmitting this one, and start its
            // heads on their way while this burst's transmit runs.
            let at = pollstats::stamp();
            let rx = &mut self.ports[slot].queues.rx;
            rx.receive_up_to(ahead, knobs.burst);
            for mbuf in ahead.iter() {
                mbuf.prefetch_head_hint(knobs.ahead_hint, knobs.lines);
            }
            let done = pollstats::stamp();
            stats.received(at, ahead.len(), true, || rx.pending());
            stats.moved(Phase::Process, Phase::Rx, at, done);
        }
        let transmitting = pollstats::stamp();
        stats.phase(Phase::Process, processing, transmitting);

        // Freed in one `rte_pktmbuf_free_bulk` when this goes out of scope.
        let mut dropped: MbufArray<'p, RX_STORAGE> = MbufArray::new_empty();
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
                log_sparsely!(warn!(
                    worker = self.id,
                    "pipeline delivered a packet with no oif; dropping (pipeline bug)"
                ));
                counters.tx_drops += 1;
                continue;
            };

            let Some(&out_slot) = tx_by_if.get(&oif) else {
                log_sparsely!(warn!(
                    worker = self.id,
                    "pipeline delivered a packet for interface {oif}, which this driver does not \
                     own; dropping"
                ));
                counters.tx_drops += 1;
                continue;
            };

            // Serialize rewritten headers into the original mbuf.
            match packet.serialize() {
                Ok(mbuf) => {
                    if tx_batches[out_slot].try_push(mbuf).is_err() {
                        // A pipeline that duplicates packets can exceed one transmit burst.
                        log_sparsely!(error!(
                            worker = self.id,
                            "transmit batch for interface {oif} overflowed one burst; dropping"
                        ));
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
        stats.phase(Phase::Tx, transmitting, pollstats::stamp());

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
        for mut packet in diverted.drain(..) {
            if divert_verdict(&mut packet, queues.mac.inner()) {
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

/// Give a packet taken off the data path the verdict the pipeline would have: [`DoneReason::Local`]
/// if it is addressed to the port, for the kernel, and [`DoneReason::MacNotForUs`] if not.
/// Returns whether it is for the kernel.
///
/// A packet dropped without a verdict is reported as an error, once per packet.
fn divert_verdict<Buf: PacketBufferMut>(packet: &mut Packet<Buf>, port: Mac) -> bool {
    let addressed_to_us = packet
        .try_eth()
        .is_some_and(|eth| addressed_to(eth.destination().inner(), port));
    packet.done(if addressed_to_us {
        DoneReason::Local
    } else {
        DoneReason::MacNotForUs
    });
    addressed_to_us
}

/// Parse a burst and run it through the pipeline.
///
/// Control traffic of the `early` classes, which the NIC does not steer to the control queue, is
/// moved to `diverted` before the pipeline sees it. Every other packet comes back, whatever its
/// verdict: the caller counts and frees the drops, in bulk.
/// What the NIC tells about a received frame beyond its bytes.
pub(crate) trait RxContext {
    /// The VNI of the VXLAN the NIC decapsulated, as its MARK: only the NIC's decapsulating rules
    /// mark (see `nic_offload::mlx5`).
    fn nic_decap(&self) -> Option<u32>;
}

impl RxContext for Mbuf<'_> {
    fn nic_decap(&self) -> Option<u32> {
        self.rx_mark()
    }
}

#[cfg(test)]
impl RxContext for net::buffer::TestBuffer {
    fn nic_decap(&self) -> Option<u32> {
        None
    }
}

fn process_burst<Buf: PacketBufferMut + RxContext>(
    burst: impl ExactSizeIterator<Item = Buf>,
    rx_if: InterfaceIndex,
    pipeline: &mut impl NetworkFunction<Buf>,
    packets: &mut Vec<Packet<Buf>>,
    early: Option<&SoftwareClasses>,
    diverted: &mut Vec<Packet<Buf>>,
    counters: &mut RxCounters,
) {
    process_burst_with(
        burst,
        rx_if,
        packets,
        early,
        diverted,
        counters,
        |packets| {
            pipeline.process_burst(packets);
        },
    );
}

/// [`process_burst`], with `run` standing in for the pipeline.
fn process_burst_with<Buf: PacketBufferMut + RxContext>(
    burst: impl ExactSizeIterator<Item = Buf>,
    rx_if: InterfaceIndex,
    packets: &mut Vec<Packet<Buf>>,
    early: Option<&SoftwareClasses>,
    diverted: &mut Vec<Packet<Buf>>,
    counters: &mut RxCounters,
    run: impl FnOnce(&mut Vec<Packet<Buf>>),
) {
    counters.rx += burst.len() as u64;
    packets.clear();
    let timed = pollstats::postime::on();
    let slide = pollstats::postime::slide();
    // Each packet is parsed in its slot rather than built and then moved into one.
    for (pos, buffer) in burst.enumerate() {
        if slide > 0 {
            pollstats::postime::slide_at(pos, slide);
        }
        let t0 = if timed { pollstats::postime::tsc() } else { 0 };
        let decapped = buffer.nic_decap();
        match Packet::parse_into(packets, buffer) {
            Ok(packet) => {
                packet.meta_mut().iif = Some(rx_if);
                if let Some(mark) = decapped {
                    // The NIC took the outer headers off: the frame is the inner one, of this VNI.
                    match net::vxlan::Vni::new_checked(mark) {
                        Ok(vni) => packet.meta_mut().set_nic_decap(vni),
                        Err(_) => packet.done(DoneReason::VxlanDecapFailure),
                    }
                }
            }
            Err(e) => {
                counters.parse_errors += 1;
                trace!("failed to parse a received frame: {e:?}");
            }
        }
        if timed {
            pollstats::postime::parsed(pos, pollstats::postime::tsc() - t0);
        }
    }

    diverted.clear();
    if let Some(early) = early {
        diverted.extend(packets.extract_if(.., |packet| {
            Key::of(packet.headers()).is_ok_and(|key| early.matches(&key))
        }));
    }

    let parsed = packets.len();
    let t0 = if timed { pollstats::postime::tsc() } else { 0 };
    run(packets);
    if timed {
        pollstats::postime::ran(parsed, pollstats::postime::tsc() - t0);
    }
    // Stages mark packets to drop rather than removing them, so a drop is always counted.
    debug_assert!(
        packets.len() >= parsed,
        "the pipeline removed {} packet(s) instead of marking them dropped",
        parsed - packets.len()
    );
}
