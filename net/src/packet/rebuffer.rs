// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Traits to allow packet rebuffering between Buf (e.g. Mbuf) and a common
//! heap-allocated `TestBuffer`.

#![cfg(any(doc, test, feature = "test_buffer"))]

use crate::buffer::{PacketBufferMut, TestBuffer};
use crate::packet::Packet;

/// A buffer type whose packets can be handed off out of a worker as `Packet<TestBuffer>`,
pub trait Rebuffer: PacketBufferMut + Sized {
    /// Convert `packet` into a `Packet<TestBuffer>`, keeping headers and metadata and
    /// releasing the original buffer.
    fn into_test_buffer(packet: Packet<Self>) -> Packet<TestBuffer>;

    /// Convert `packet` into a `Packet<Self>` backed by `buf`, keeping its headers and
    /// metadata.
    ///
    /// # Errors
    ///
    /// This method may fail if the packet does not fit in the provided buffer `buf`.
    /// If that happens, the packet is returned anyway with the new buffer so that the
    /// packet can be returned to a pipeline and get accounted.
    #[allow(clippy::result_large_err)]
    fn from_test_buffer(
        packet: Packet<TestBuffer>,
        buf: Self,
    ) -> Result<Packet<Self>, Packet<Self>>;
}

impl Rebuffer for TestBuffer {
    fn into_test_buffer(packet: Packet<Self>) -> Packet<TestBuffer> {
        packet
    }
    fn from_test_buffer(
        packet: Packet<TestBuffer>,
        _buf: Self,
    ) -> Result<Packet<Self>, Packet<Self>> {
        Ok(packet)
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
        let packet = build_test_ipv4_packet(64).unwrap();
        let ptr = data_ptr(&packet);
        let converted = TestBuffer::from_test_buffer(packet, TestBuffer::default()).unwrap();
        assert_eq!(data_ptr(&converted), ptr);
        retire(converted);
    }
}
