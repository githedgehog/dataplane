// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The control worker: the control plane's own queues, off the data path.
//!
//! One thread serves every port's control queues. It receives what the control-plane classes'
//! flow rules steer to the control receive queue and hands it to the kernel without running the
//! pipeline, and it transmits what the kernel sends on the control transmit queue, from the control
//! pool. Neither depends on how busy the data workers are or on the data pool having buffers.
//!
//! It also keeps every port's classes current, including those of a port without control queues,
//! whose control traffic the data workers take off the data path in software and whose kernel
//! frames data worker 0 transmits.

use concurrency::sync::Arc;
use dpdk::lcore::LCore;
use dpdk::mem::MbufArray;
use dpdk::queue::rx::RxQueueIndex;
use lifecycle::Subsystem;
use net::eth::mac::Mac;
use tokio::sync::watch;
use tracing::{debug, error, info, trace};
use traffic_control::{Class, ClassTable, ControlPlane};

use crate::drivers::status::WorkerId;
use crate::drivers::watchdog::{RxCounters, Watchdog};

use super::classes::{Installed, fall_back};
use super::port::{ControlPair, ControlQueues};

/// Yield after this many consecutive polls without traffic on any port.
const IDLE_POLLS_BEFORE_YIELD: u32 = 128;

/// Polls between cancellation checks and watchdog updates.
const CANCEL_CHECK_INTERVAL: u32 = 1024;

/// One port's control queues as seen by the control worker, and the watchdog its traffic is
/// reported on.
pub(crate) struct ControlPort<'p, 'eal> {
    pub(crate) queues: ControlQueues<'p, 'eal>,
    pub(crate) watchdog: Watchdog,
}

/// The control worker and its exclusively owned queue handles.
pub(crate) struct ControlWorker<'p, 'eal> {
    id: WorkerId,
    ports: Vec<ControlPort<'p, 'eal>>,
    /// The addresses and peers the classes are built from.
    control_plane: watch::Receiver<ControlPlane>,
}

impl<'p, 'eal> ControlWorker<'p, 'eal> {
    pub(crate) fn new(
        id: WorkerId,
        ports: Vec<ControlPort<'p, 'eal>>,
        control_plane: watch::Receiver<ControlPlane>,
    ) -> Self {
        Self {
            id,
            ports,
            control_plane,
        }
    }

    /// Steer each port's control traffic to its control queue, by the classes of the current
    /// control plane, if it has changed since they were last installed.
    fn steer(&mut self, installed: &mut [Installed<'p>]) {
        if !self.control_plane.has_changed().unwrap_or(false) && !installed.is_empty() {
            return;
        }
        let table = Arc::new(ClassTable::new(
            self.control_plane.borrow_and_update().clone(),
        ));
        info!(
            worker = self.id,
            "steering {} control-plane rule(s) per port",
            table.rules().len()
        );
        for (port, installed) in self.ports.iter().zip(installed.iter_mut()) {
            let queues = &port.queues;
            // Without a control queue, every class is taken in software.
            let Some(pair) = queues.pair.as_ref() else {
                fall_back(&queues.fallback, &table, Class::ALL.into_iter().collect());
                continue;
            };
            *installed = std::mem::replace(installed, Installed::none()).update(
                queues.dev,
                &queues.name,
                &table,
                RxQueueIndex(pair.queue),
            );
            fall_back(&queues.fallback, &table, installed.refused().clone());
        }
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
        // The rules go before the queues they steer to are dropped, which is when this returns.
        let mut installed: Vec<Installed<'p>> =
            self.ports.iter().map(|_| Installed::none()).collect();
        self.control_plane.mark_changed();
        self.steer(&mut installed);

        loop {
            polls = polls.wrapping_add(1);
            if polls.is_multiple_of(CANCEL_CHECK_INTERVAL) {
                if subsystem.is_cancelled() {
                    break;
                }
                self.report(&mut counters);
                self.steer(&mut installed);
            }

            let mut busy = false;
            for (port, counters) in self.ports.iter_mut().zip(counters.iter_mut()) {
                let queues = &mut port.queues;
                let Some(pair) = queues.pair.as_mut() else {
                    continue;
                };
                if let Some(injector) = pair.injector.as_mut() {
                    busy |= injector.inject(self.id, &mut pair.tx, counters);
                }
                busy |= receive(self.id, &queues.name, pair, &mut rx_mbufs, counters);
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
    name: &str,
    queues: &mut ControlPair<'p>,
    rx_mbufs: &mut MbufArray<'p>,
    counters: &mut RxCounters,
) -> bool {
    queues.rx.receive_into(rx_mbufs);
    if rx_mbufs.is_empty() {
        return false;
    }
    for mbuf in rx_mbufs.drain_all() {
        counters.rx += 1;
        let frame = mbuf.raw_data();
        if !destination(frame).is_some_and(|dst| addressed_to(dst, queues.mac.inner())) {
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
                "punt queue for {name} is full; dropping a control frame for the kernel"
            );
        }
    }
    true
}

/// The destination MAC of an Ethernet frame, if it is long enough to have one.
fn destination(frame: &[u8]) -> Option<Mac> {
    frame.first_chunk::<6>().map(|bytes| Mac(*bytes))
}

/// True if a frame with this destination MAC was addressed to a port with this one.
///
/// Broadcast and multicast count: the peer's ARP request, the fabric's LLDP, and IPv6 neighbour
/// discovery all arrive that way. Only what flow rules steered to the control queue gets here.
pub(super) fn addressed_to(destination: Mac, port: Mac) -> bool {
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
