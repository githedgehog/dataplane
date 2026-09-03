// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Packet buffer backed by UMEM frames.
//!
//! [`XdpBuffer`] implements the [`PacketBufferMut`] operations, and for a
//! packet that fits in one frame it does so directly on the memory the socket
//! shares with the kernel: the packet crosses the pipeline without being
//! copied. A buffer owns its storage for as long as it lives and hands it back
//! to the pool it came from when dropped.
//!
//! A packet longer than a frame cannot be held that way. The kernel will not
//! register a UMEM with chunks larger than a page, so such a packet arrives
//! split across frames, and the pipeline needs one contiguous run of bytes to
//! parse and rewrite. Those packets are gathered into a buffer of their own,
//! which costs a copy on the way in and another on the way out. Everything
//! that fits in a frame -- which is everything up to
//! [`MAX_FRAME_PACKET_LEN`](crate::umem::MAX_FRAME_PACKET_LEN) -- does not pay
//! either.
//!
//! [`PacketBufferMut`]: net::buffer::PacketBufferMut

#![allow(unsafe_code)] // a frame is addressed through the UMEM region pointer

use concurrency::sync::Arc;
use concurrency::sync::mpsc::Sender;
use net::buffer::{Headroom, Prepend, Tailroom, TrimFromEnd, TrimFromStart};

/// A prepend was asked for more room than the buffer has ahead of the packet.
///
/// `net::buffer` has an error of the same shape, but it is `#[non_exhaustive]`
/// and so cannot be constructed outside that crate.
#[derive(Debug, thiserror::Error)]
#[error("not enough headroom in the packet buffer")]
pub struct NotEnoughHeadRoom;

/// A trim was asked for more bytes than the packet holds. As above, this
/// cannot be `net::buffer::MemoryBufferNotLongEnough`.
#[derive(Debug, thiserror::Error)]
#[error("packet buffer not long enough")]
pub struct BufferNotLongEnough;
use std::fmt;

use crate::umem::UmemRegion;

/// Where a packet's bytes live, and how that storage is given back.
enum Storage {
    /// One UMEM frame, read and written where the kernel put it.
    Frame {
        /// The region the frame is part of. Keeps the mapping alive.
        region: Arc<UmemRegion>,
        /// Byte offset of the frame within the region.
        frame_addr: usize,
        /// Where to hand the frame back on drop.
        free_list: Sender<usize>,
    },
    /// A buffer of its own, for a packet that did not fit in a frame.
    Linear {
        /// The bytes. Taken on drop, and `Some` until then.
        buffer: Option<Box<[u8]>>,
        /// Where to hand them back on drop.
        free_list: Sender<Box<[u8]>>,
    },
}

/// A packet, and the storage holding it.
///
/// ```text
///     base                  data_offset          + data_len        + capacity
///      |                         |                     |                |
///      v                         v                     v                v
///      +-------------------------+---------------------+----------------+
///      |         headroom        |     packet data     |    tailroom    |
///      +-------------------------+---------------------+----------------+
/// ```
///
/// Prepending and trimming move `data_offset` and `data_len` within the
/// storage; nothing is ever moved in memory.
pub struct XdpBuffer {
    /// Where the packet's bytes are.
    storage: Storage,
    /// Size of that storage, in bytes.
    capacity: u16,
    /// Offset of the packet data from the start of the storage.
    data_offset: u16,
    /// Length of the packet data, in bytes.
    data_len: u16,
}

// Buffers are built by the socket; with the `runtime` feature off the crate
// is just the layout, exercised by its own tests.
#[cfg_attr(not(any(feature = "runtime", test)), allow(dead_code))]
impl XdpBuffer {
    /// Wrap the frame at `frame_addr`, holding `data_len` bytes of packet data
    /// at `data_offset`.
    ///
    /// # Safety
    ///
    /// `frame_addr` must be the offset of a frame of `capacity` bytes within
    /// `region`, and the caller must be handing over exclusive ownership of
    /// that frame: neither another buffer nor the kernel may touch it until
    /// this buffer is dropped.
    pub(crate) unsafe fn frame(
        region: Arc<UmemRegion>,
        frame_addr: usize,
        data_offset: u16,
        data_len: u16,
        capacity: u16,
        free_list: Sender<usize>,
    ) -> Self {
        Self {
            storage: Storage::Frame {
                region,
                frame_addr,
                free_list,
            },
            capacity,
            data_offset,
            data_len,
        }
    }

    /// Wrap a buffer of its own, holding `data_len` bytes of packet data at
    /// `data_offset`.
    pub(crate) fn linear(
        buffer: Box<[u8]>,
        data_offset: u16,
        data_len: u16,
        free_list: Sender<Box<[u8]>>,
    ) -> Self {
        let capacity = u16::try_from(buffer.len()).unwrap_or(u16::MAX);
        Self {
            storage: Storage::Linear {
                buffer: Some(buffer),
                free_list,
            },
            capacity,
            data_offset,
            data_len,
        }
    }

    /// Offset of this buffer's frame within the UMEM region, if it has one.
    #[must_use]
    pub fn frame_addr(&self) -> Option<usize> {
        match &self.storage {
            Storage::Frame { frame_addr, .. } => Some(*frame_addr),
            Storage::Linear { .. } => None,
        }
    }

    /// Length of the packet data, in bytes.
    #[must_use]
    pub fn data_len(&self) -> u16 {
        self.data_len
    }

    /// Bytes of the storage the packet is written into, headroom and all.
    ///
    /// Only for the code that fills a buffer as a packet is gathered; the
    /// pipeline sees the packet through `AsRef` and `AsMut`.
    #[cfg(any(feature = "runtime", test))]
    pub(crate) fn storage_mut(&mut self) -> &mut [u8] {
        let capacity = self.capacity as usize;
        match &mut self.storage {
            // SAFETY: the frame is ours alone and is `capacity` bytes long.
            Storage::Frame {
                region, frame_addr, ..
            } => unsafe { std::slice::from_raw_parts_mut(region.ptr_at(*frame_addr), capacity) },
            // `buffer` is only `None` once `drop` has taken it, and nothing
            // can reach a buffer after that.
            Storage::Linear { buffer, .. } => buffer.as_deref_mut().unwrap_or(&mut []),
        }
    }

    /// Pointer to the first byte of packet data.
    #[inline]
    fn data_ptr(&self) -> *mut u8 {
        let offset = self.data_offset as usize;
        match &self.storage {
            // SAFETY: the frame is within the region and ours alone, and
            // `data_offset` is kept within it by everything that moves it.
            Storage::Frame {
                region, frame_addr, ..
            } => unsafe { region.ptr_at(frame_addr + offset) },
            // As in `storage_mut`: `None` is unreachable outside `drop`, and
            // an empty slice's pointer is still valid to offset by zero.
            Storage::Linear { buffer, .. } => {
                let base = buffer.as_deref().unwrap_or(&[]).as_ptr().cast_mut();
                // SAFETY: `data_offset` is within the buffer, as above.
                unsafe { base.add(offset) }
            }
        }
    }
}

impl Drop for XdpBuffer {
    fn drop(&mut self) {
        // A disconnected channel means the pool is being torn down, and the
        // storage goes away with it. Nothing to do about it.
        match &mut self.storage {
            Storage::Frame {
                frame_addr,
                free_list,
                ..
            } => {
                let _ = free_list.send(*frame_addr);
            }
            Storage::Linear { buffer, free_list } => {
                if let Some(buffer) = buffer.take() {
                    let _ = free_list.send(buffer);
                }
            }
        }
    }
}

impl fmt::Debug for XdpBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.storage {
            Storage::Frame { .. } => "frame",
            Storage::Linear { .. } => "linear",
        };
        f.debug_struct("XdpBuffer")
            .field("storage", &kind)
            .field("frame_addr", &self.frame_addr())
            .field("data_offset", &self.data_offset)
            .field("data_len", &self.data_len)
            .field("capacity", &self.capacity)
            .finish()
    }
}

impl AsRef<[u8]> for XdpBuffer {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        // SAFETY: the storage is ours alone, and the data region is within it.
        unsafe { std::slice::from_raw_parts(self.data_ptr(), self.data_len as usize) }
    }
}

impl AsMut<[u8]> for XdpBuffer {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        // SAFETY: as for `as_ref`, and `&mut self` rules out an overlapping
        // shared borrow.
        unsafe { std::slice::from_raw_parts_mut(self.data_ptr(), self.data_len as usize) }
    }
}

impl Headroom for XdpBuffer {
    fn headroom(&self) -> u16 {
        self.data_offset
    }
}

impl Tailroom for XdpBuffer {
    fn tailroom(&self) -> u16 {
        self.capacity
            .saturating_sub(self.data_offset + self.data_len)
    }
}

impl Prepend for XdpBuffer {
    type Error = NotEnoughHeadRoom;

    fn prepend(&mut self, len: u16) -> Result<&mut [u8], Self::Error> {
        if self.headroom() < len {
            return Err(NotEnoughHeadRoom);
        }
        self.data_offset -= len;
        self.data_len += len;
        Ok(self.as_mut())
    }
}

impl TrimFromStart for XdpBuffer {
    type Error = BufferNotLongEnough;

    fn trim_from_start(&mut self, len: u16) -> Result<&mut [u8], Self::Error> {
        if len > self.data_len {
            return Err(BufferNotLongEnough);
        }
        self.data_offset += len;
        self.data_len -= len;
        Ok(self.as_mut())
    }
}

impl TrimFromEnd for XdpBuffer {
    type Error = BufferNotLongEnough;

    fn trim_from_end(&mut self, len: u16) -> Result<&mut [u8], Self::Error> {
        if len > self.data_len {
            return Err(BufferNotLongEnough);
        }
        self.data_len -= len;
        Ok(self.as_mut())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod test {
    use super::{NotEnoughHeadRoom, XdpBuffer};
    use crate::umem::{DATA_OFFSET, FRAME_SIZE, LINEAR_SIZE, MAX_FRAME_PACKET_LEN, UmemRegion};

    use concurrency::sync::Arc;
    use concurrency::sync::mpsc::{Receiver, channel};
    use net::buffer::{Headroom, Prepend, Tailroom, TrimFromEnd, TrimFromStart};

    use std::ptr::NonNull;

    /// A stand-in for a mapped UMEM, backed by a plain allocation. Returned
    /// alongside the backing store, which must outlive the region.
    fn test_region(num_frames: usize) -> (Arc<UmemRegion>, Vec<u8>) {
        let len = num_frames * usize::from(FRAME_SIZE);
        let mut backing = vec![0u8; len];
        let base = NonNull::new(backing.as_mut_ptr()).unwrap();
        // SAFETY: `backing` is `len` bytes and is returned to the caller, who
        // holds it for as long as the region.
        let region = unsafe { UmemRegion::new(base, len) };
        (Arc::new(region), backing)
    }

    /// Build a frame-backed buffer over frame 0 of a fresh region. The
    /// returned channel is where the frame goes when the buffer is dropped.
    fn frame_buffer(data: &[u8]) -> (XdpBuffer, Receiver<usize>, Arc<UmemRegion>, Vec<u8>) {
        let (region, backing) = test_region(1);
        let data_len = u16::try_from(data.len()).expect("test packets fit in a frame");
        let (tx, rx) = channel();
        // SAFETY: frame 0 is within the region and nothing else refers to it.
        let mut buf =
            unsafe { XdpBuffer::frame(region.clone(), 0, DATA_OFFSET, data_len, FRAME_SIZE, tx) };
        buf.as_mut().copy_from_slice(data);
        (buf, rx, region, backing)
    }

    /// Build a buffer of its own, filled the way the socket fills one as it
    /// gathers a packet that arrived across several frames.
    fn linear_buffer(data: &[u8]) -> (XdpBuffer, Receiver<Box<[u8]>>) {
        let data_len = u16::try_from(data.len()).expect("test packets fit");
        let (tx, rx) = channel();
        let mut buf = XdpBuffer::linear(
            vec![0u8; LINEAR_SIZE as usize].into_boxed_slice(),
            DATA_OFFSET,
            data_len,
            tx,
        );
        let start = DATA_OFFSET as usize;
        buf.storage_mut()[start..start + data.len()].copy_from_slice(data);
        (buf, rx)
    }

    #[test]
    fn an_empty_frame_buffer_offers_the_whole_frame() {
        let (buf, _rx, _region, _backing) = frame_buffer(&[]);

        assert_eq!(buf.headroom(), DATA_OFFSET);
        assert_eq!(buf.tailroom(), MAX_FRAME_PACKET_LEN);
        assert_eq!(buf.data_len(), 0);
        assert!(buf.as_ref().is_empty());
    }

    #[test]
    fn data_is_readable_where_it_was_written() {
        let data = b"Hello, AF_XDP!";
        let (buf, _rx, _region, _backing) = frame_buffer(data);
        let len = u16::try_from(data.len()).expect("test packets fit in a frame");

        assert_eq!(buf.as_ref(), data);
        assert_eq!(buf.data_len(), len);
        assert_eq!(buf.headroom(), DATA_OFFSET);
        assert_eq!(buf.tailroom(), MAX_FRAME_PACKET_LEN - len);
    }

    /// A buffer of its own has to behave exactly as one over a frame does, or
    /// a packet would be handled differently for having arrived in fragments.
    #[test]
    fn a_linear_buffer_behaves_as_a_frame_does() {
        let data = [0xAB; 5000];
        let (mut buf, _rx) = linear_buffer(&data);

        assert_eq!(buf.as_ref(), &data[..]);
        assert_eq!(buf.headroom(), DATA_OFFSET);
        assert_eq!(buf.tailroom(), LINEAR_SIZE - DATA_OFFSET - 5000);
        assert!(buf.frame_addr().is_none());

        buf.prepend(14).expect("headroom was available");
        assert_eq!(buf.data_len(), 5014);
        assert_eq!(&buf.as_ref()[14..], &data[..]);

        buf.trim_from_start(14).expect("the bytes are there");
        assert_eq!(buf.as_ref(), &data[..]);
    }

    #[test]
    fn prepend_then_trim_returns_the_buffer_to_where_it_started() {
        let (mut buf, _rx, _region, _backing) = frame_buffer(&[0xAA; 100]);
        let headroom = buf.headroom();
        let len = buf.data_len();

        let slice = buf.prepend(10).expect("headroom was available");
        assert_eq!(slice.len(), (len + 10) as usize);
        assert_eq!(buf.headroom(), headroom - 10);
        assert_eq!(buf.data_len(), len + 10);

        buf.trim_from_start(10).expect("the bytes are there");
        assert_eq!(buf.headroom(), headroom);
        assert_eq!(buf.data_len(), len);

        buf.trim_from_end(50).expect("the bytes are there");
        assert_eq!(buf.data_len(), len - 50);
        assert_eq!(buf.tailroom(), MAX_FRAME_PACKET_LEN - (len - 50));
    }

    #[test]
    fn prepend_beyond_the_start_of_the_storage_is_refused() {
        let (mut buf, _rx, _region, _backing) = frame_buffer(&[0xAA; 100]);

        assert!(matches!(
            buf.prepend(DATA_OFFSET + 1),
            Err(NotEnoughHeadRoom)
        ));
        // The failed prepend left the buffer alone.
        assert_eq!(buf.headroom(), DATA_OFFSET);
        assert_eq!(buf.data_len(), 100);
    }

    #[test]
    fn trimming_more_than_the_packet_holds_is_refused() {
        let (mut buf, _rx, _region, _backing) = frame_buffer(&[0xAA; 10]);

        assert!(buf.trim_from_start(11).is_err());
        assert!(buf.trim_from_end(11).is_err());
        assert_eq!(buf.data_len(), 10);
    }

    #[test]
    fn a_dropped_buffer_hands_its_frame_back() {
        let (buf, rx, _region, _backing) = frame_buffer(&[]);
        drop(buf);
        assert_eq!(rx.try_recv(), Ok(0));
    }

    #[test]
    fn a_dropped_buffer_hands_its_own_storage_back() {
        let (buf, rx) = linear_buffer(&[0xAA; 5000]);
        drop(buf);
        assert_eq!(
            rx.try_recv().expect("the buffer came back").len(),
            LINEAR_SIZE as usize
        );
    }
}
