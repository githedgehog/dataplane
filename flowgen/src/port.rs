// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK queues as a [`Wire`].

use dpdk::mem::{MbufArray, Pool};
use dpdk::queue::rx::RxQueue;
use dpdk::queue::tx::TxQueue;
use net::buffer::Append;

use crate::drive::Wire;
use crate::ledger::Ledger;
use crate::schedule::Slot;
use crate::sender::{Clock, Sender};

/// The queues a stream is sent and received on, and the pool its frames come from.
pub struct Queues<'q, 'd> {
    /// Where frames are sent.
    pub tx: &'q mut [TxQueue<'d>],
    /// Where they come back.
    pub rx: &'q mut [RxQueue<'d>],
    /// What they are built in.
    pub pool: &'q Pool<'d>,
}

impl Wire for Queues<'_, '_> {
    /// Offer what `sender` would send now, from the pool, spreading flows over the transmit
    /// queues; count what the queues took. Nothing is sent if the pool has nothing to spare,
    /// which is back-pressure from frames still in flight, not an error.
    fn send(&mut self, sender: &mut Sender, ledger: &mut Ledger, clock: &Clock) -> usize {
        let packets = sender.plan(ledger.total_offered());
        if packets.is_empty() {
            return 0;
        }
        let Ok(mut mbufs) = self.pool.alloc_bulk(packets.len()) else {
            sender.deferred(&packets);
            return 0;
        };
        let queues = &mut *self.tx;
        let mut by_queue: Vec<(MbufArray<'_>, Vec<Slot>)> = (0..queues.len())
            .map(|_| (MbufArray::new_empty(), Vec::new()))
            .collect();
        for (mbuf, &slot) in mbufs.drain_all().zip(&packets) {
            let mut mbuf = mbuf;
            let (bytes, queue) = sender.stamp(slot, clock.now_ns());
            let len = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
            match mbuf.append(len) {
                Ok(room) => room.copy_from_slice(bytes),
                Err(_) => continue, // the template outgrew the mbuf: a misconfigured stream
            }
            let queue = queue.min(queues.len().saturating_sub(1));
            let (batch, sent) = &mut by_queue[queue];
            if batch.try_push(mbuf).is_ok() {
                sent.push(slot);
            }
        }
        let mut total = 0;
        for (queue, (batch, packets)) in queues.iter_mut().zip(by_queue) {
            let offered = batch.len();
            let refused = queue.transmit(batch).len();
            let accepted = offered - refused;
            for &slot in &packets[..accepted] {
                sender.accepted(slot, ledger);
            }
            sender.refused(&packets[accepted..], ledger);
            total += accepted;
        }
        total
    }

    /// Send `frame` on the first transmit queue.
    fn send_frame(&mut self, frame: &[u8]) -> bool {
        let (Some(queue), Ok(len)) = (self.tx.first_mut(), u16::try_from(frame.len())) else {
            return false;
        };
        let Ok(mut burst) = self.pool.alloc_bulk(1) else {
            return false;
        };
        for mbuf in &mut burst {
            match mbuf.append(len) {
                Ok(room) => room.copy_from_slice(frame),
                Err(_) => return false,
            }
        }
        queue.transmit(burst).is_empty()
    }

    fn receive(&mut self, deliver: &mut dyn FnMut(&[u8])) -> usize {
        let mut total = 0;
        for queue in self.rx.iter_mut() {
            let burst = queue.receive();
            for mbuf in &burst {
                deliver(mbuf.raw_data());
                total += 1;
            }
        }
        total
    }
}
