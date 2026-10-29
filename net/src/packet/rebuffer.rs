// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Traits to allow packet rebuffering between Buf (e.g. Mbuf) and a common heap-allocated TestBuffer.

#![cfg(any(doc, test, feature = "test_buffer"))]

use crate::buffer::{PacketBufferMut, TestBuffer};
use crate::packet::Packet;

/// A buffer type whose packets can be handed off out of a worker as `Packet<TestBuffer>`,
pub trait Rebuffer: PacketBufferMut + Sized {
    /// Type representing a pool from which workers may get buffers of this type
    type Pool;

    /// Convert `packet` into a `Packet<TestBuffer>`, keeping its headers and metadata,
    /// releasing its original buffer.
    fn into_test_buffer(packet: Packet<Self>) -> Packet<TestBuffer>;

    /// Convert a burst of `Packet<TestBuffer>` into packets of this buffer type, with buffers
    /// taken from `pool`, keeping the headers and metadata of the packets.
    /// If not enough buffers can be retrieved from the pool, packets may be marked as dropped
    /// and dropped.
    /// FIXME:
    ///    - this will lead to undercount in the stats.
    ///    - this will cause the returned buffer to hold fewer packets
    fn from_test_buffer(burst: Vec<Packet<TestBuffer>>, pool: &Self::Pool) -> Vec<Packet<Self>>;
}

impl Rebuffer for TestBuffer {
    type Pool = ();
    fn into_test_buffer(packet: Packet<Self>) -> Packet<TestBuffer> {
        packet
    }
    fn from_test_buffer(burst: Vec<Packet<TestBuffer>>, (): &()) -> Vec<Packet<Self>> {
        burst
    }
}

#[cfg(test)]
mod test {
    use super::Rebuffer;
    use crate::buffer::TestBuffer;
    use crate::packet::test_utils::build_test_ipv4_packet;
    use crate::packet::{DoneReason, Packet};

    // the address of a packet's buffer, to tell if a conversion moved or copied it
    fn data_ptr(packet: &Packet<TestBuffer>) -> *const u8 {
        packet.payload().as_ref().as_ptr()
    }

    // give `packet` a verdict, so that dropping it does not log an error
    fn retire(mut packet: Packet<TestBuffer>) {
        packet.done(DoneReason::Delivered);
    }

    #[test]
    fn test_buffer_into_test_buffer_does_not_copy() {
        let packet = build_test_ipv4_packet(64).unwrap();
        let ptr = data_ptr(&packet);
        let converted = <TestBuffer as Rebuffer>::into_test_buffer(packet);
        assert_eq!(data_ptr(&converted), ptr);
        retire(converted);
    }

    #[test]
    fn test_buffer_from_test_buffer_does_not_copy() {
        let burst: Vec<_> = (1..=3)
            .map(|ttl| build_test_ipv4_packet(ttl).unwrap())
            .collect();
        let ptrs: Vec<_> = burst.iter().map(data_ptr).collect();
        let converted = TestBuffer::from_test_buffer(burst, &());
        assert_eq!(converted.iter().map(data_ptr).collect::<Vec<_>>(), ptrs);
        converted.into_iter().for_each(retire);
    }
}
