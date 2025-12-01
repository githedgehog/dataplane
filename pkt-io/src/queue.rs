// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Packet queues

#![deny(clippy::all, clippy::pedantic)]
#![allow(unused)]

use async_channel::{Receiver, Sender};
use net::buffer::PacketBufferMut;
use net::packet::Packet;
use tracing::error;

/// The type of the objects in a [`PktQueue`]. This alias exists if ever
/// we want to box packets. In any case, ownership of packets is transferred to
/// to/from the queues.
pub(crate) type QueuedPacket<Buf> = Packet<Buf>;

/// A bounded multi-producer, multi-consumer queue of packets. Clones of a queue are handles
/// to the same queue.
pub struct PktQueue<Buf: PacketBufferMut> {
    s: Sender<QueuedPacket<Buf>>,
    r: Receiver<QueuedPacket<Buf>>,
}
impl<Buf: PacketBufferMut> Clone for PktQueue<Buf> {
    fn clone(&self) -> Self {
        Self {
            s: self.s.clone(),
            r: self.r.clone(),
        }
    }
}

impl<Buf: PacketBufferMut> PktQueue<Buf> {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (s, r) = async_channel::bounded(capacity);
        Self { s, r }
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.s.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.s.is_empty()
    }

    /// Get a packet from the queue. If there is none, return `None` without blocking.
    #[must_use]
    pub fn pop(&self) -> Option<QueuedPacket<Buf>> {
        self.r.try_recv().ok()
    }

    /// Get the packets that are in the queue at the time of the call, without blocking.
    /// Packets pushed while the returned iterator is consumed are left in the queue, so that
    /// concurrent producers cannot keep the caller draining the queue indefinitely.
    pub fn pop_ready(&self) -> impl Iterator<Item = QueuedPacket<Buf>> + '_ {
        (0..self.len()).map_while(|_| self.pop())
    }

    /// Push a packet to the queue.
    ///
    /// # Errors
    ///
    /// If the queue is full, the packet is returned back to the caller.
    #[allow(clippy::result_large_err)]
    pub fn push(&self, packet: QueuedPacket<Buf>) -> Result<(), QueuedPacket<Buf>> {
        self.s
            .try_send(packet)
            .map_err(async_channel::TrySendError::into_inner)
    }

    /// Get a packet from the queue. If empty, _asynchronously_ WAIT until there is one.
    #[must_use]
    pub async fn pop_async(&self) -> Option<QueuedPacket<Buf>> {
        self.r.recv().await.ok()
    }

    /// Push a packet to the queue. If the queue is full, this method WAITS until there is room.
    /// This method should only be used in tests. This method cannot fail since the channel
    /// cannot be closed because we keep both a sender and a receiver and never call close.
    #[cfg(test)]
    pub async fn push_async(&self, packet: QueuedPacket<Buf>) {
        self.s.send(packet).await.unwrap_or_else(|_| unreachable!())
    }
}

#[cfg(test)]
mod test {
    use crate::queue::PktQueue;
    use net::buffer::TestBuffer;
    use net::packet::Packet;
    use net::packet::test_utils::build_test_ipv4_packet;
    use tracing::info;
    use tracing_test::traced_test;

    #[test]
    fn test_packet_queue() {
        let queue = PktQueue::<TestBuffer>::new(10);
        let packet = build_test_ipv4_packet(64).unwrap();
        queue.push(packet).unwrap();
        assert!(queue.pop().is_some());
    }

    #[test]
    fn test_packet_queue_pop_ready_is_bounded() {
        let queue = PktQueue::<TestBuffer>::new(10);
        for _ in 0..3 {
            queue.push(build_test_ipv4_packet(64).unwrap()).unwrap();
        }

        // packets pushed while draining must not be popped by the same pop_ready()
        let mut popped = 0;
        for _ in queue.pop_ready() {
            popped += 1;
            queue.push(build_test_ipv4_packet(64).unwrap()).unwrap();
        }
        assert_eq!(popped, 3);
        assert_eq!(queue.len(), 3);
    }

    #[test]
    fn test_packet_queue_clone() {
        let queue = PktQueue::<TestBuffer>::new(10);
        let clone = queue.clone();

        let p1 = build_test_ipv4_packet(64).unwrap();
        queue.push(p1).unwrap();
        assert!(clone.pop().is_some());

        let p2 = build_test_ipv4_packet(64).unwrap();
        clone.push(p2);
        assert!(queue.pop().is_some());
    }

    #[tokio::test]
    async fn test_packet_queue_async() {
        let queue = PktQueue::<TestBuffer>::new(10);
        let packet = build_test_ipv4_packet(64).unwrap();
        queue.push_async(packet).await;
        assert!(queue.pop_async().await.is_some());
    }

    #[traced_test]
    #[tokio::test]
    async fn test_packet_queue_occupancy() {
        const NUM_PACKETS: usize = 50;
        let queue = PktQueue::<TestBuffer>::new(1);
        let packet = build_test_ipv4_packet(64).unwrap();
        let mut pkts: Vec<_> = (1..=NUM_PACKETS)
            .map(|_| packet.deep_copy().expect("Deep copy failed"))
            .collect();

        // spawn task that asynchronously pops packets
        let clone = queue.clone();
        let h = tokio::spawn(async move {
            let mut num = 0;
            loop {
                if let Some(p) = clone.pop_async().await {
                    num += 1;
                    info!("Got packet {num}");
                    if num == NUM_PACKETS {
                        info!("All packets popped. We're done");
                        break;
                    }
                }
            }
        });

        // push all of the packets in the pkts vector, asynchronously
        while let Some(pkt) = pkts.pop() {
            queue.push_async(pkt).await;
        }
        h.await.unwrap();
    }
}
