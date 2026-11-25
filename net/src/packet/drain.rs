// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Draining a burst of packets without moving them.
//!
//! A [`Packet`] is a few hundred bytes. Taking one out of a burst by value (`Vec::drain`, then a
//! method that consumes it) copies all of it, twice, to get at the few bytes of its buffer. Past
//! the size the compiler copies inline, each of those copies is a `memmove` call, and reading a
//! packet just copied that way stalls on store-to-load forwarding. [`Packet::drain_in_place`] hands
//! out each packet where it lies instead, and takes only its buffer out.

#![allow(unsafe_code)] // a safe abstraction over moving one field out of a packet in place

use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};
use core::ptr::{self, NonNull};

use super::{Packet, SerializeError};
use crate::buffer::PacketBufferMut;

impl<Buf: PacketBufferMut> Packet<Buf> {
    /// Drain `burst` without moving its packets: each comes out as a [`PacketSlot`], a handle on
    /// the packet in its place in the burst.
    ///
    /// The burst is empty from the start, as with [`Vec::drain`], and keeps its capacity.
    /// Packets not yet handed out when the drain is dropped are dropped in place; so is a slot's
    /// packet when the slot is dropped without being consumed.
    pub fn drain_in_place(burst: &mut Vec<Packet<Buf>>) -> DrainInPlace<'_, Buf> {
        let len = burst.len();
        // SAFETY: the packets in `0..len` now belong to the drain, which hands each out or drops
        // it exactly once. Were the drain leaked, they would leak, never be dropped twice.
        unsafe { burst.set_len(0) };
        DrainInPlace {
            base: NonNull::new(burst.as_mut_ptr()).unwrap_or(NonNull::dangling()),
            next: 0,
            len,
            burst: PhantomData,
        }
    }
}

/// The packets of a burst, handed out in place; see [`Packet::drain_in_place`].
pub struct DrainInPlace<'a, Buf: PacketBufferMut> {
    /// The burst's storage. Its packets in `next..len` are live and not yet handed out.
    base: NonNull<Packet<Buf>>,
    next: usize,
    len: usize,
    /// The storage stays borrowed, untouched by anyone else, for as long as any slot lives.
    burst: PhantomData<&'a mut Vec<Packet<Buf>>>,
}

impl<'a, Buf: PacketBufferMut> Iterator for DrainInPlace<'a, Buf> {
    type Item = PacketSlot<'a, Buf>;

    fn next(&mut self) -> Option<PacketSlot<'a, Buf>> {
        if self.next == self.len {
            return None;
        }
        // SAFETY: `next < len`, so this is a live packet of the burst, which no other slot has.
        let packet = unsafe { self.base.add(self.next) };
        self.next += 1;
        Some(PacketSlot {
            packet,
            burst: PhantomData,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.len - self.next;
        (left, Some(left))
    }
}

impl<Buf: PacketBufferMut> ExactSizeIterator for DrainInPlace<'_, Buf> {}

impl<Buf: PacketBufferMut> Drop for DrainInPlace<'_, Buf> {
    fn drop(&mut self) {
        let left = self.len - self.next;
        // SAFETY: the packets in `next..len` are live and were never handed out; nothing reads
        // them after this.
        unsafe {
            ptr::drop_in_place(ptr::slice_from_raw_parts_mut(
                self.base.add(self.next).as_ptr(),
                left,
            ));
        }
        self.next = self.len;
    }
}

/// One packet of a burst being drained, where it lies in the burst; see
/// [`Packet::drain_in_place`].
///
/// It reads and changes the packet through [`Deref`] and [`DerefMut`], and gives up its buffer
/// with [`serialize`](Self::serialize) or [`discard`](Self::discard), which move only the buffer
/// out. Dropped otherwise, it drops its packet in place.
pub struct PacketSlot<'a, Buf: PacketBufferMut> {
    /// A live packet that this slot alone may use.
    packet: NonNull<Packet<Buf>>,
    burst: PhantomData<&'a mut Packet<Buf>>,
}

impl<Buf: PacketBufferMut> PacketSlot<'_, Buf> {
    /// [`Packet::serialize`], in place: write the packet's headers into its buffer and take the
    /// buffer out. On error the packet is marked accordingly and dropped.
    ///
    /// # Errors
    ///
    /// As [`Packet::serialize`].
    pub fn serialize(mut self) -> Result<Buf, SerializeError<()>> {
        self.serialize_or_mark()?;
        Ok(self.into_buffer())
    }

    /// [`Packet::discard`], in place: take the buffer out without writing the headers into it.
    #[must_use]
    pub fn discard(self) -> Buf {
        self.into_buffer()
    }

    /// Take the buffer out of the packet and drop the rest of it in place.
    fn into_buffer(self) -> Buf {
        let this = ManuallyDrop::new(self);
        // SAFETY: the slot alone has this live packet, and `this` keeps its `Drop` from running,
        // so each field is read out or dropped exactly once and the packet is never used again.
        // Naming every field, without `..`, makes a new field a compile error here rather than a
        // leak.
        unsafe {
            let Packet {
                headers,
                payload,
                meta,
                #[cfg(any(test, feature = "checksum-audit"))]
                    transport_checksum_error: _,
            } = &mut *this.packet.as_ptr();
            let payload = ptr::read(payload);
            ptr::drop_in_place(headers);
            ptr::drop_in_place(meta);
            payload
        }
    }
}

impl<Buf: PacketBufferMut> Deref for PacketSlot<'_, Buf> {
    type Target = Packet<Buf>;

    fn deref(&self) -> &Packet<Buf> {
        // SAFETY: a live packet that this slot alone has.
        unsafe { self.packet.as_ref() }
    }
}

impl<Buf: PacketBufferMut> DerefMut for PacketSlot<'_, Buf> {
    fn deref_mut(&mut self) -> &mut Packet<Buf> {
        // SAFETY: a live packet that this slot alone has.
        unsafe { self.packet.as_mut() }
    }
}

impl<Buf: PacketBufferMut> Drop for PacketSlot<'_, Buf> {
    fn drop(&mut self) {
        // SAFETY: a live packet that this slot alone has, never used again.
        unsafe { ptr::drop_in_place(self.packet.as_ptr()) };
    }
}

#[cfg(test)]
mod tests {
    use crate::buffer::TestBuffer;
    use crate::headers::Headers;
    use crate::packet::{DoneReason, Packet};
    use crate::parse::DeParse;

    /// The packet `headers` followed by `payload` parse into, if they parse.
    fn packet(headers: &Headers, payload: &[u8]) -> Option<Packet<TestBuffer>> {
        let mut bytes = vec![0; usize::from(headers.size().get())];
        headers.deparse(&mut bytes).ok()?;
        bytes.extend_from_slice(payload);
        let mut packet = Packet::new(TestBuffer::from_raw_data(&bytes)).ok()?;
        packet.done(DoneReason::Delivered);
        Some(packet)
    }

    fn bytes(serialized: Result<TestBuffer, impl core::fmt::Debug>) -> Option<Vec<u8>> {
        serialized.ok().map(|buf| buf.as_ref().to_vec())
    }

    /// Serializing in place gives what serializing by value gives, packet for packet, and every
    /// packet is accounted for: serialized, discarded, dropped by its slot, or by the drain.
    #[test]
    fn draining_in_place_matches_consuming_by_value() {
        bolero::check!()
            .with_type::<(Vec<(Headers, Vec<u8>)>, u8)>()
            .for_each(|(frames, stop)| {
                let frames = &frames[..frames.len().min(16)];
                let parse = || -> Vec<Packet<TestBuffer>> {
                    frames
                        .iter()
                        .filter_map(|(headers, payload)| {
                            packet(headers, &payload[..payload.len().min(64)])
                        })
                        .collect()
                };
                let expected: Vec<_> = parse()
                    .into_iter()
                    .map(|packet| bytes(packet.serialize()))
                    .collect();

                let mut burst = parse();
                let capacity = burst.capacity();
                let stop = usize::from(*stop) % (burst.len() + 1);
                let mut got = Vec::new();
                for (i, slot) in Packet::drain_in_place(&mut burst).enumerate() {
                    match i % 3 {
                        _ if i == stop => break,
                        0 | 1 => got.push(bytes(slot.serialize())),
                        _ => {
                            drop(slot.discard());
                            got.push(expected[i].clone());
                        }
                    }
                }
                assert_eq!(got[..], expected[..got.len()]);
                assert!(burst.is_empty(), "the drain empties the burst");
                assert_eq!(burst.capacity(), capacity, "and keeps its storage");
            });
    }

    /// A slot dropped unconsumed drops its packet; the burst is reusable afterwards.
    #[test]
    fn an_unconsumed_slot_drops_its_packet_and_the_burst_is_reusable() {
        bolero::check!()
            .with_type::<Vec<(Headers, Vec<u8>)>>()
            .for_each(|frames| {
                let mut burst: Vec<_> = frames
                    .iter()
                    .take(8)
                    .filter_map(|(headers, payload)| packet(headers, payload))
                    .collect();
                for slot in Packet::drain_in_place(&mut burst) {
                    drop(slot);
                }
                assert!(burst.is_empty());
                burst.extend(
                    frames
                        .iter()
                        .take(8)
                        .filter_map(|(headers, payload)| packet(headers, payload)),
                );
                drop(Packet::drain_in_place(&mut burst));
                assert!(burst.is_empty());
            });
    }
}
