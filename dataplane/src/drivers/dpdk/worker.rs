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
use net::buffer::{BufferPool, PacketBufferMut};
use net::eth::mac::Mac;
use net::headers::{TryEth, TryHeaders};
use net::interface::InterfaceIndex;
use net::packet::{DoneReason, Packet, PacketSlot};
use pipeline::{DynPipeline, NetworkFunction};
use tracing::{debug, error, info, trace, warn};
use traffic_control::Key;

use crate::drivers::load::{Load, LoadMeter, Spent};
use crate::drivers::sparse_log::log_sparsely;
use crate::drivers::status::WorkerId;
use crate::drivers::watchdog::{RxCounters, Watchdog};
use crate::packet_processor::{PipelineFactory, WorkerContext, WorkerPipeline, expiry_budget};

use super::classes::SoftwareClasses;
use super::control::addressed_to;
use super::idle::Idle;
use super::port::PortQueues;
use crate::drivers::disposition::Disposition;

// A packet's budget is five cache lines (320 bytes), and `Packet` is aligned to a line
// (`#[repr(align(64))]`). Why (2026-11-27):
// - Past 256 bytes the line count is what costs, not the bytes. A 264-byte packet spans five lines
//   wherever it starts, so 264 already paid for the fifth line; 320 costs no more, and gives the
//   room 264 lacked (`PacketMeta` had none left).
// - Aligned, every packet of a burst has its fields at the same line offsets: a hot field never
//   straddles two lines, and what a stage touches is the same lines for every packet.
// - The inline-copy cliff (256: the compiler calls `memmove` beyond it; 8 bytes over cost some 7 %
//   per packet on the local BF-3, 2026-11-15, when packets moved by value to transmit) is not
//   worth chasing with `#[inline(always)]`: packets no longer move on the hot path (parsed in
//   their slot, transmitted from it: `Packet::drain_in_place`), and overruling the compiler's
//   heuristics everywhere would not stay fixed.
// - Back to four lines means 256 bytes or less; the room is in the TCP header, whose options sit
//   inline (40 bytes). See `notes/match-action-dag/slice1-step4/RESULTS.md`, packet size.
// Test-only metadata does not count.
const _: () = assert!(
    core::mem::size_of::<net::packet::Packet<Mbuf<'static>>>() - net::packet::TEST_ONLY_BYTES
        <= 320,
    "Packet<Mbuf> outgrew five cache lines; see the comment above this assert"
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
    rx_mbufs: MbufArray<'p>,
    /// One transmit batch per port slot, indexed like the worker's ports.
    tx_batches: Vec<MbufArray<'p>>,
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

    /// Run until cancelled, constructing the non-Send pipeline on this thread, with `context`.
    pub(crate) fn run<P: BufferPool<Buf = Mbuf<'p>>>(
        mut self,
        subsystem: &Subsystem,
        setup_pipeline: &PipelineFactory<'p, Mbuf<'p>, P>,
        context: WorkerContext<P>,
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

        let drain = context.drain.clone();
        let WorkerPipeline {
            mut pipeline,
            flows,
        } = setup_pipeline(context);

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
        let mut polls: u32 = 0;
        // Whether the last expiry pass left work over.
        let mut expiry_behind = false;
        // Counters per port, flushed to that port's watchdog.
        let mut counters = vec![RxCounters::default(); self.ports.len()];

        // Started last, so that setting up does not count as time spent.
        let mut meter = LoadMeter::start();
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
            // After a long sleep, the periodic work is due, flow expiry included.
            let woke_late = idle.checks_due();
            if polls.is_multiple_of(CANCEL_CHECK_INTERVAL) || woke_late {
                idle.checked();
                if subsystem.is_cancelled() {
                    break;
                }
                self.report(&mut counters);
                meter.flush(&self.load, idle.mode());
            }

            // poll the port queues this worker is responsible for. Return whether frames were received,
            // whether the pipeline ran for pending work, and the queue to watch first
            let (saw_frames, ran_pending, busy) = self.poll_ports(
                &tx_by_if,
                &mut pipeline,
                &mut scratch,
                &mut counters,
                drain.as_deref(),
            );

            if ran_pending {
                // No buffer was received, but the pipeline was run as it had pending work.
                meter.lap(Spent::Busy);
            }

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

    /// Poll every port once. If no port received anything and the pipeline
    /// reports pending work, run it with an empty burst and transmit the output.
    ///
    /// Returns whether any port received frames, whether the pipeline ran for pending work, and
    /// the queue to watch first if the worker sleeps: one that received, else one whose port only
    /// had frames from the kernel to send, else the first if the run without packets returned some.
    fn poll_ports(
        &mut self,
        tx_by_if: &HashMap<InterfaceIndex, usize>,
        pipeline: &mut DynPipeline<'p, Mbuf<'p>>,
        scratch: &mut Scratch<'p>,
        counters: &mut [RxCounters],
        drain: Option<&dag::generation::Drain>,
    ) -> (bool, bool, Option<usize>) {
        let mut received = None;
        let mut injected = None;
        for (slot, counters) in counters.iter_mut().enumerate() {
            let had_frames = self.inject(slot, counters);
            if self.poll_one(slot, tx_by_if, pipeline, scratch, counters, drain) {
                received = Some(slot);
            } else if had_frames && injected.is_none() {
                injected = Some(slot);
            }
        }

        // If nothing was received and a run of the pipeline is due, run it with an empty burst.
        // Transmit any packet produced by the pipeline. Report whether it ran, which is work, apart
        // from whether it produced any packet, which is what resets the backoff.
        let mut ran_pending = false;
        let mut produced = false;
        if received.is_none()
            && pipeline.must_run()
            && let Some(counters) = counters.first_mut()
        {
            debug_assert!(scratch.burst.is_empty());
            ran_pending = true;
            produced = self.run_pipeline(0, tx_by_if, pipeline, scratch, counters);
        }

        (
            received.is_some(),
            ran_pending,
            received.or(injected).or(produced.then_some(0)),
        )
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
    fn poll_one(
        &mut self,
        slot: usize,
        tx_by_if: &HashMap<InterfaceIndex, usize>,
        pipeline: &mut DynPipeline<'p, Mbuf<'p>>,
        scratch: &mut Scratch<'p>,
        counters: &mut RxCounters,
        drain: Option<&dag::generation::Drain>,
    ) -> bool {
        let rx_mbufs = &mut scratch.rx_mbufs;
        self.ports[slot].queues.rx.receive_into(rx_mbufs);
        if let Some(drain) = drain {
            // Less than a full burst: the queue was left empty.
            drain.polled(
                slot,
                rx_mbufs.len() < dpdk::mem::MBUF_BURST,
                self.ports[slot]
                    .queues
                    .stamps
                    .load(concurrency::sync::atomic::Ordering::Relaxed),
            );
        }
        if rx_mbufs.is_empty() {
            return false;
        }
        counters.burst(rx_mbufs.len(), dpdk::mem::MBUF_BURST);
        let how = dpdk::mem::HeadFetch::DEFAULT;
        how.fetch(rx_mbufs.iter(), |mbuf| head_lines(mbuf.decapsulated()));
        how.fetch(rx_mbufs.iter(), |mbuf| {
            more_head_lines(mbuf.decapsulated(), mbuf.raw_data())
        });
        self.run_pipeline(slot, tx_by_if, pipeline, scratch, counters);
        true
    }

    /// Get the frames received from port `slot` from the scratch receive array and:
    ///    * feed the pipeline with the burst
    ///    * divert packets taken off the data path
    ///    * transmit, punt to kernel or drop the packets
    ///    * account in `counters`
    ///
    /// Returns whether the pipeline returned packets.
    fn run_pipeline(
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
        let queues = &self.ports[slot].queues;
        let fallback = queues.fallback.load();
        process_burst(
            rx_mbufs.drain_all(),
            queues.if_index,
            pipeline,
            burst,
            fallback.as_deref(),
            diverted,
            counters,
        );
        self.punt_diverted(slot, diverted, counters);
        let produced = !burst.is_empty();
        self.transmit(slot, tx_by_if, burst, tx_batches, counters);
        produced
    }

    /// Transmit, punt or drop the packets in the `burst` returned by a pipeline.
    /// Packets for the kernel are punted on the tap of the port in `slot`.
    fn transmit(
        &mut self,
        slot: usize,
        tx_by_if: &HashMap<InterfaceIndex, usize>,
        burst: &mut Vec<Packet<Mbuf<'p>>>,
        tx_batches: &mut [MbufArray<'p>],
        counters: &mut RxCounters,
    ) {
        // Freed in one `rte_pktmbuf_free_bulk` when this goes out of scope.
        let mut dropped: MbufArray<'p> = MbufArray::new_empty();
        // Borrowed for the packet loop rather than cloned per poll: an `mpsc::Sender` clone is an
        // atomic increment, which is not free at burst rates and buys nothing here.
        let punt = self.ports[slot].queues.punt.as_ref();
        // In place: moving a packet out of the burst copies all of it to get at its buffer.
        for packet in Packet::drain_in_place(burst) {
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
            let attempted = batch.len() as u64;
            let sent = self.ports[out_slot].queues.tx.transmit_from(batch) as u64;
            let refused = attempted - sent;
            counters.tx += sent;
            if refused > 0 {
                // Free the packets refused under backpressure; the batch is reused next burst.
                batch.clear();
                counters.tx_drops += refused;
                trace!(
                    worker = self.id,
                    "tx queue on {} refused {refused} of {attempted} packets",
                    self.ports[out_slot].queues.name
                );
            }
        }
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
        for mut packet in Packet::drain_in_place(diverted) {
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
        packet: PacketSlot<'_, Mbuf<'p>>,
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

/// The cache lines of a received frame to bring in before parsing it: all of the head, except for
/// a frame the NIC decapsulated, which starts at its inner Ethernet header. An IPv4 header and the
/// fixed part of a TCP or UDP header end within its first line (TCP options stay unread, see
/// `net::tcp::Tcp`). Without decapsulation, a VXLAN frame's inner IPv4 header starts at byte 64.
fn head_lines(decapsulated: bool) -> core::ops::Range<usize> {
    if decapsulated {
        0..1
    } else {
        0..dpdk::mem::HEAD_LINES
    }
}

/// The rest of the head of a decapsulated frame whose first line, in by now, says it is not IPv4
/// (IPv6, or a VLAN tag): taken after [`head_lines`] for the whole burst, so that the burst's
/// first lines still arrive together.
fn more_head_lines(decapsulated: bool, frame: &[u8]) -> core::ops::Range<usize> {
    const ETHERTYPE: core::ops::Range<usize> = 12..14;
    let ipv4 = net::eth::ethtype::EthType::IPV4.as_u16().to_be_bytes();
    if decapsulated && frame.get(ETHERTYPE) != Some(&ipv4[..]) {
        1..dpdk::mem::HEAD_LINES
    } else {
        0..0
    }
}

/// What the NIC tells about a received frame beyond its bytes (`nic_offload::mlx5`'s layout,
/// `notes/match-action-dag/TRAP-RESUME.md` §3).
pub(crate) trait RxContext {
    /// Whether the NIC decapsulated it: it carries META. A flag in the mbuf's first cache line,
    /// for prefetching before the value (in the second) is read.
    fn decapsulated(&self) -> bool;
    /// What the NIC's decapsulating rule wrote in META: a discriminant (the VNI, for VXLAN).
    fn nic_decap(&self) -> Option<u32>;
    /// What the NIC's trap rule wrote in MARK: the stamp, and where it left the packet.
    fn trap_mark(&self) -> Option<u32>;
}

impl RxContext for Mbuf<'_> {
    fn decapsulated(&self) -> bool {
        self.rx_flags().contains(dpdk::mem::RxFlags::META)
    }

    fn nic_decap(&self) -> Option<u32> {
        self.rx_meta()
    }

    fn trap_mark(&self) -> Option<u32> {
        self.rx_mark()
    }
}

#[cfg(test)]
impl RxContext for net::buffer::TestBuffer {
    fn decapsulated(&self) -> bool {
        false
    }

    fn nic_decap(&self) -> Option<u32> {
        None
    }

    fn trap_mark(&self) -> Option<u32> {
        None
    }
}

/// Parse a burst of buffers and run it through the pipeline.
///
/// Control traffic of the `early` classes, which the NIC does not steer to the control queue, is
/// moved to `diverted` before the pipeline sees it. Every other packet comes back, whatever its
/// verdict, except those that the stages punt: the caller counts and frees the drops, in bulk.
fn process_burst<Buf: PacketBufferMut + RxContext>(
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
    // Each packet is parsed in its slot rather than built and then moved into one.
    for buffer in burst {
        let (decapped, mark) = (buffer.nic_decap(), buffer.trap_mark());
        match Packet::parse_into(packets, buffer) {
            Ok(packet) => {
                packet.meta_mut().iif = Some(rx_if);
                if let Some(meta) = decapped {
                    // The NIC took the outer headers off: the frame is the inner one, of this VNI.
                    match nic_offload::mlx5::vni_of_meta(meta)
                        .and_then(|vni| net::vxlan::Vni::new_checked(vni).ok())
                    {
                        Some(vni) => packet.meta_mut().set_nic_decap(vni),
                        None => packet.done(DoneReason::VxlanDecapFailure),
                    }
                }
                if let Some(bits) = mark {
                    // The configuration generation it was classified under, and where the NIC
                    // left it (T7: a MARK outside the layout is a lowering bug, counted).
                    match net::packet::Mark::from_bits(bits) {
                        Ok(mark) => packet.meta_mut().set_mark(Some(mark)),
                        Err(_) => packet.done(DoneReason::TrapDecode),
                    }
                }
            }
            Err(e) => {
                counters.parse_errors += 1;
                trace!("failed to parse a received frame: {e:?}");
            }
        }
    }

    diverted.clear();
    if let Some(early) = early {
        diverted.extend(packets.extract_if(.., |packet| {
            Key::of(packet.headers()).is_ok_and(|key| early.matches(&key))
        }));
    }

    pipeline.process_burst(packets);
}

#[cfg(test)]
mod head_line_tests {
    use super::{head_lines, more_head_lines};
    use dpdk::mem::CACHE_LINE_BYTES;
    use net::buffer::TestBuffer;
    use net::headers::{TryHeaders, TryTcp};
    use net::packet::{DoneReason, Packet};
    use net::parse::DeParse;

    const TIMESTAMPS: [u8; 12] = [1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0];

    fn eth(ethertype: u16) -> Vec<u8> {
        let mut frame = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2];
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame
    }

    fn tcp(options: &[u8]) -> Vec<u8> {
        let words = u8::try_from((20 + options.len()) / 4).unwrap();
        let mut tcp = vec![
            0x30,
            0x39,
            0,
            80,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            words << 4,
            0x10,
            0xff,
            0xff,
        ];
        tcp.extend_from_slice(&[0, 0, 0, 0]);
        tcp.extend_from_slice(options);
        tcp
    }

    fn udp() -> Vec<u8> {
        vec![0x30, 0x39, 0, 53, 0, 8, 0, 0]
    }

    fn ipv4(protocol: u8, payload: &[u8]) -> Vec<u8> {
        let len = u16::try_from(20 + payload.len()).unwrap().to_be_bytes();
        let mut ip = vec![0x45, 0, len[0], len[1], 0, 1, 0x40, 0, 64, protocol, 0, 0];
        ip.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        ip.extend_from_slice(payload);
        ip
    }

    fn ipv6(next: u8, payload: &[u8]) -> Vec<u8> {
        let len = u16::try_from(payload.len()).unwrap().to_be_bytes();
        let mut ip = vec![0x60, 0, 0, 0, len[0], len[1], next, 64];
        ip.extend_from_slice(&[0xfd; 16]);
        ip.extend_from_slice(&[0xfe; 16]);
        ip.extend_from_slice(payload);
        ip
    }

    /// The bytes of `frame` that parsing it on the fast path reads: its headers, less the TCP
    /// options it leaves unread.
    fn read_by_parse(frame: &[u8]) -> usize {
        let mut burst = Vec::with_capacity(1);
        let packet = Packet::parse_into(&mut burst, TestBuffer::from_raw_data(frame)).unwrap();
        packet.done(DoneReason::Delivered);
        let unread = packet
            .headers()
            .try_tcp()
            .filter(|tcp| tcp.options_unread())
            .map_or(0, |tcp| {
                usize::from(tcp.size().get() - net::tcp::Tcp::MIN_LENGTH.get())
            });
        usize::from(packet.headers().size().get()) - unread
    }

    /// The bytes of `frame` that the two passes over a burst bring in, as if the NIC had
    /// decapsulated it.
    fn fetched_after_decap(frame: &[u8]) -> usize {
        let lines = head_lines(true).end.max(more_head_lines(true, frame).end);
        lines * CACHE_LINE_BYTES
    }

    /// Behind a NIC decapsulation, the head fetch covers everything the parse reads: in one line
    /// for IPv4, Linux's TCP timestamps included, and in two for IPv6 or a VLAN tag.
    #[test]
    fn a_decapsulated_head_is_fetched_whole() {
        let mut vlan = eth(0x8100);
        vlan.extend_from_slice(&[0, 7, 0x08, 0x00]);
        vlan.extend_from_slice(&ipv4(6, &tcp(&TIMESTAMPS)));
        let cases = [
            ("ipv4 tcp", [eth(0x0800), ipv4(6, &tcp(&[]))].concat(), 1),
            (
                "ipv4 tcp timestamps",
                [eth(0x0800), ipv4(6, &tcp(&TIMESTAMPS))].concat(),
                1,
            ),
            ("ipv4 udp", [eth(0x0800), ipv4(17, &udp())].concat(), 1),
            (
                "ipv6 tcp timestamps",
                [eth(0x86dd), ipv6(6, &tcp(&TIMESTAMPS))].concat(),
                2,
            ),
            ("vlan ipv4 tcp", vlan, 2),
        ];
        for (name, frame, lines) in cases {
            assert_eq!(
                fetched_after_decap(&frame),
                lines * CACHE_LINE_BYTES,
                "{name}"
            );
            assert!(
                read_by_parse(&frame) <= fetched_after_decap(&frame),
                "{name}"
            );
        }
    }

    /// A frame the NIC did not decapsulate gets its whole head in the first pass, nothing more.
    #[test]
    fn other_frames_get_the_whole_head_at_once() {
        let frame = [eth(0x86dd), ipv6(6, &tcp(&TIMESTAMPS))].concat();
        assert_eq!(head_lines(false), 0..dpdk::mem::HEAD_LINES);
        assert!(more_head_lines(false, &frame).is_empty());
    }
}
