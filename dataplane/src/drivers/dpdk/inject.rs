// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Transmitting what the kernel sends out of a port, bypassing the forwarding pipeline.
//!
//! The kernel's frames (BGP, BFD, ARP and neighbour replies, LLDP) arrive on the port's tap and are
//! copied into mbufs from the port's control pool. On a port with control queues, the control worker
//! sends them on the control transmit queue; on a port without, data worker 0 sends them on its own
//! transmit queue (see [`port`](super::port)).

use dpdk::mem::{MBUF_BURST, MbufArray, Pool};
use dpdk::queue::tx::TxQueue;
use net::buffer::Append;
use tokio::sync::mpsc;
use tracing::{trace, warn};

use crate::drivers::cpbridge::Frame;
use crate::drivers::status::WorkerId;
use crate::drivers::watchdog::RxCounters;

/// Bound injection per poll, so that a chatty control plane cannot starve receiving.
const INJECT_PER_POLL: usize = MBUF_BURST;

/// One port's frames from the kernel, and the pool they are copied into for transmit.
pub(crate) struct Injector<'p> {
    /// The port, for logs.
    pub(crate) name: String,
    /// The port's control pool.
    pub(crate) pool: Pool<'p>,
    /// Frames the kernel wants the port to transmit.
    pub(crate) frames: mpsc::Receiver<Frame>,
}

impl<'p> Injector<'p> {
    /// Send up to [`INJECT_PER_POLL`] waiting frames on `tx`. Returns whether there were any, for
    /// idle backoff accounting.
    pub(crate) fn inject(
        &mut self,
        id: WorkerId,
        tx: &mut TxQueue<'p>,
        counters: &mut RxCounters,
    ) -> bool {
        // Drained into a local buffer first: the mbufs are allocated all at once below, and the
        // bulk allocator needs the count up front. Bounded by `INJECT_PER_POLL`, which is also the
        // batch's capacity, so the `try_push` below cannot overflow.
        let mut frames: Vec<Frame> = Vec::new();
        for _ in 0..INJECT_PER_POLL {
            let Ok(frame) = self.frames.try_recv() else {
                break;
            };
            frames.push(frame);
        }
        if frames.is_empty() {
            return false;
        }

        // All-or-nothing, which is what the DPDK bulk allocator gives: a partial allocation would
        // have to be unwound by hand.
        let mbufs = match self.pool.alloc_bulk(frames.len()) {
            Ok(mbufs) => mbufs,
            Err(e) => {
                counters.tx_drops += frames.len() as u64;
                warn!(
                    worker = id,
                    "could not allocate {} mbuf(s) to inject on {}: {e}. The control plane's \
                     traffic is being dropped because the port's control pool is exhausted.",
                    frames.len(),
                    self.name
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
                    worker = id,
                    "the kernel offered a {} byte frame on {}, which is not a frame; dropping it",
                    frame.len(),
                    self.name
                );
                continue;
            };
            match mbuf.append(len) {
                Ok(room) => room.copy_from_slice(&frame),
                Err(e) => {
                    counters.tx_drops += 1;
                    warn!(
                        worker = id,
                        "the kernel offered a {len} byte frame on {}, which does not fit an mbuf \
                         from its pool ({e}); dropping it. The tap's MTU and the port's disagree.",
                        self.name
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
        let unsent = tx.transmit(batch);
        let refused = unsent.len() as u64;
        counters.tx += attempted - refused;
        if refused > 0 {
            counters.tx_drops += refused;
            trace!(
                worker = id,
                "tx queue on {} refused {refused} of {attempted} injected frame(s)", self.name
            );
        }
        true
    }
}
