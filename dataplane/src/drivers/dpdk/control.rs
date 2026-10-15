// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The control worker: the control plane's own queues, off the data path.
//!
//! One thread serves every port's control queues. It receives what the control-plane classes'
//! flow rules steer to the control receive queue and hands it to the kernel without running the
//! pipeline, and it transmits what the kernel sends on the control transmit queue, from the control
//! pool. Neither depends on how busy the data workers are or on the data pool having buffers.

use dpdk::lcore::LCore;
use dpdk::mem::{MBUF_BURST, MbufArray};
use lifecycle::Subsystem;
use net::buffer::Append;
use net::eth::mac::Mac;
use tracing::{debug, error, trace, warn};

use crate::drivers::cpbridge::Frame;
use crate::drivers::status::WorkerId;
use crate::drivers::watchdog::{RxCounters, Watchdog};

use super::port::ControlQueues;

/// Yield after this many consecutive polls without traffic on any port.
const IDLE_POLLS_BEFORE_YIELD: u32 = 128;

/// Polls between cancellation checks and watchdog updates.
const CANCEL_CHECK_INTERVAL: u32 = 1024;

/// Bound control-plane injection so receiving cannot starve.
const INJECT_PER_POLL: usize = MBUF_BURST;

/// One port's control queues as seen by the control worker, and the watchdog its traffic is
/// reported on.
pub(crate) struct ControlPort<'p> {
    pub(crate) queues: ControlQueues<'p>,
    pub(crate) watchdog: Watchdog,
}

/// The control worker and its exclusively owned queue handles.
pub(crate) struct ControlWorker<'p> {
    id: WorkerId,
    ports: Vec<ControlPort<'p>>,
}

impl<'p> ControlWorker<'p> {
    pub(crate) fn new(id: WorkerId, ports: Vec<ControlPort<'p>>) -> Self {
        Self { id, ports }
    }

    /// Run until cancelled.
    pub(crate) fn run(mut self, subsystem: &Subsystem) {
        // Registration enables the per-lcore mempool cache and releases the id on return or unwind.
        let _lcore = match LCore::register() {
            Ok(lcore) => Some(lcore),
            Err(e) => {
                error!(
                    worker = self.id,
                    "the control worker could not register with the EAL ({e:?}); it will run \
                     without a per-core mempool cache"
                );
                None
            }
        };
        debug!(
            worker = self.id,
            "control worker started on {} port(s): {}",
            self.ports.len(),
            self.ports
                .iter()
                .map(|p| p.queues.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );

        let mut idle_polls: u32 = 0;
        let mut polls: u32 = 0;
        let mut counters = vec![RxCounters::default(); self.ports.len()];
        let mut rx_mbufs = MbufArray::new_empty();

        loop {
            polls = polls.wrapping_add(1);
            if polls.is_multiple_of(CANCEL_CHECK_INTERVAL) {
                if subsystem.is_cancelled() {
                    break;
                }
                self.report(&mut counters);
            }

            let mut busy = false;
            for (port, counters) in self.ports.iter_mut().zip(counters.iter_mut()) {
                busy |= inject(self.id, &mut port.queues, counters);
                busy |= receive(self.id, &mut port.queues, &mut rx_mbufs, counters);
            }

            if busy {
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
        debug!(worker = self.id, "control worker stopping");
    }

    /// Pat every port's watchdog and flush its counters to it.
    fn report(&self, counters: &mut [RxCounters]) {
        for (port, counters) in self.ports.iter().zip(counters) {
            port.watchdog.pat();
            port.watchdog.record(counters);
            *counters = RxCounters::default();
        }
    }
}

/// Hand the kernel a burst from the port's control queue. Returns whether there was one.
///
/// Only frames addressed to the port go: the flow rules match protocols, not destination MACs, and
/// a NIC in promiscuous mode also receives frames for others.
fn receive<'p>(
    id: WorkerId,
    queues: &mut ControlQueues<'p>,
    rx_mbufs: &mut MbufArray<'p>,
    counters: &mut RxCounters,
) -> bool {
    let Some(rx) = queues.rx.as_mut() else {
        return false;
    };
    rx.receive_into(rx_mbufs);
    if rx_mbufs.is_empty() {
        return false;
    }
    for mbuf in rx_mbufs.drain_all() {
        counters.rx += 1;
        let frame = mbuf.raw_data();
        if !destination(frame).is_some_and(|dst| addressed_to(dst, queues.mac)) {
            counters.ppline_drops += 1;
            continue;
        }
        // No bridge means no tap to punt to.
        let Some(punt) = queues.punt.as_ref() else {
            continue;
        };
        // Copied, as every punt is: the far end is a task on the management runtime, which an
        // mbuf cannot reach. The mbuf goes back to the control pool when this iteration drops it.
        if punt.try_send(frame.to_vec()).is_err() {
            counters.tx_drops += 1;
            trace!(
                worker = id,
                "punt queue for {} is full; dropping a control frame for the kernel", queues.name
            );
        }
    }
    true
}

/// The destination MAC of an Ethernet frame, if it is long enough to have one.
fn destination(frame: &[u8]) -> Option<Mac> {
    frame.first_chunk::<6>().map(|bytes| Mac(*bytes))
}

/// Send kernel frames directly through the port's control queue, bypassing the forwarding
/// pipeline. Returns whether any frames were injected, for idle backoff accounting.
fn inject(id: WorkerId, queue: &mut ControlQueues<'_>, counters: &mut RxCounters) -> bool {
    let Some(inject) = queue.inject.as_mut() else {
        return false;
    };

    // Drained into a local buffer first: the mbufs come from a pool this same struct owns, so the
    // receiver's borrow has to end before the allocation begins. Bounded by `INJECT_PER_POLL`,
    // which is also the batch's capacity, so the `try_push` below cannot overflow.
    let mut frames: Vec<Frame> = Vec::new();
    for _ in 0..INJECT_PER_POLL {
        let Ok(frame) = inject.try_recv() else {
            break;
        };
        frames.push(frame);
    }
    if frames.is_empty() {
        return false;
    }

    // All-or-nothing, which is what the DPDK bulk allocator gives: a partial allocation would have
    // to be unwound by hand.
    let mbufs = match queue.pool.alloc_bulk(frames.len()) {
        Ok(mbufs) => mbufs,
        Err(e) => {
            counters.tx_drops += frames.len() as u64;
            warn!(
                worker = id,
                "could not allocate {} mbuf(s) to inject on {}: {e}. The control plane's traffic \
                 is being dropped because the port's control pool is exhausted.",
                frames.len(),
                queue.name
            );
            return false;
        }
    };

    // Filled and pushed in one pass, so an mbuf whose frame could not be copied is simply not
    // pushed -- and being owned by this loop, it is freed when the iteration drops it rather than
    // transmitted empty.
    let mut batch = MbufArray::new_empty();
    for (mut mbuf, frame) in mbufs.into_iter().zip(frames) {
        let Ok(len) = u16::try_from(frame.len()) else {
            counters.tx_drops += 1;
            warn!(
                worker = id,
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
                    worker = id,
                    "the kernel offered a {len} byte frame on {}, which does not fit an mbuf from \
                     its pool ({e}); dropping it. The tap's MTU and the port's disagree.",
                    queue.name
                );
                continue;
            }
        }
        if batch.try_push(mbuf).is_err() {
            unreachable!(
                "at most INJECT_PER_POLL frames were drained, and that is the batch's capacity"
            );
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
            worker = id,
            "tx queue on {} refused {refused} of {attempted} injected frame(s)", queue.name
        );
    }
    true
}

/// True if a frame with this destination MAC was addressed to a port with this one.
///
/// Broadcast and multicast count: the peer's ARP request, the fabric's LLDP, and IPv6 neighbour
/// discovery all arrive that way. Only what flow rules steered to the control queue gets here.
fn addressed_to(destination: Mac, port: Mac) -> bool {
    destination == port || destination.is_broadcast() || destination.is_multicast()
}

#[cfg(test)]
mod tests {
    use super::destination;
    use net::eth::mac::Mac;

    #[test]
    fn a_frame_too_short_for_a_destination_has_none() {
        assert_eq!(destination(&[1, 2, 3]), None);
        assert_eq!(
            destination(&[1, 2, 3, 4, 5, 6, 7]),
            Some(Mac([1, 2, 3, 4, 5, 6]))
        );
    }
}

