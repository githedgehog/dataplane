// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Zero-copy packet buffer backed by a single UMEM frame.
//!
//! [`XdpBuffer`] implements the [`PacketBufferMut`] operations directly on the
//! memory the socket shares with the kernel, so a packet crosses the pipeline
//! without ever being copied. A buffer owns its frame for as long as it lives
//! and hands it back to the pool it came from when dropped.
//!
//! [`PacketBufferMut`]: net::buffer::PacketBufferMut

#![allow(unsafe_code)] // the frame is addressed through the UMEM region pointer

use concurrency::sync::Arc;
use concurrency::sync::mpsc::Sender;
use std::fmt;

use net::buffer::{Headroom, Prepend, Tailroom, TrimFromEnd, TrimFromStart};

use crate::umem::UmemRegion;

/// A prepend was asked for more room than the frame has ahead of the packet.
///
/// `net::buffer` has an error of the same shape, but it is `#[non_exhaustive]`
/// and so cannot be constructed outside that crate.
#[derive(Debug, thiserror::Error)]
#[error("not enough headroom in the UMEM frame")]
pub struct NotEnoughHeadRoom;

/// A trim was asked for more bytes than the packet holds. As above, this
/// cannot be `net::buffer::MemoryBufferNotLongEnough`.
#[derive(Debug, thiserror::Error)]
#[error("UMEM frame buffer not long enough")]
pub struct BufferNotLongEnough;

/// A packet held in one UMEM frame.
///
/// ```text
///  frame_addr                data_offset          + data_len       + frame_size
///     |                           |                     |                |
///     v                           v                     v                v
///     +---------------------------+---------------------+----------------+
///     |          headroom         |     packet data     |    tailroom    |
///     +---------------------------+---------------------+----------------+
/// ```
///
/// Prepending and trimming move `data_offset` and `data_len` within the frame;
/// nothing is ever moved in memory. The headroom is the kernel's
/// [`XDP_HEADROOM`](crate::umem::XDP_HEADROOM) reservation, which is ours to
/// use once the frame has been handed to userspace.
pub struct XdpBuffer {
    /// The UMEM region this frame is part of. Keeps the mapping alive.
    region: Arc<UmemRegion>,
    /// Byte offset of the start of this frame within the region.
    frame_addr: usize,
    /// Offset of the packet data from the start of the frame.
    data_offset: u16,
    /// Length of the packet data, in bytes.
    data_len: u16,
    /// Size of the frame, in bytes.
    frame_size: u16,
    /// Where to hand the frame back on drop.
    free_list: Sender<usize>,
}

// Buffers are built by the socket; with the `runtime` feature off the crate
// is just the frame layout, exercised by its own tests.
#[cfg_attr(not(any(feature = "runtime", test)), allow(dead_code))]
impl XdpBuffer {
    /// Wrap the frame at `frame_addr`, holding `data_len` bytes of packet data
    /// at `data_offset`.
    ///
    /// # Safety
    ///
    /// `frame_addr` must be the offset of a frame of `frame_size` bytes within
    /// `region`, and the caller must be handing over exclusive ownership of
    /// that frame: neither another buffer nor the kernel may touch it until
    /// this buffer is dropped.
    pub(crate) unsafe fn new(
        region: Arc<UmemRegion>,
        frame_addr: usize,
        data_offset: u16,
        data_len: u16,
        frame_size: u16,
        free_list: Sender<usize>,
    ) -> Self {
        Self {
            region,
            frame_addr,
            data_offset,
            data_len,
            frame_size,
            free_list,
        }
    }

    /// Offset of this buffer's frame within the UMEM region.
    #[must_use]
    pub fn frame_addr(&self) -> usize {
        self.frame_addr
    }

    /// Length of the packet data, in bytes.
    #[must_use]
    pub fn data_len(&self) -> u16 {
        self.data_len
    }

    /// Pointer to the first byte of packet data.
    #[inline]
    fn data_ptr(&self) -> *mut u8 {
        // SAFETY: `new` promised the frame is within the region and ours
        // alone, and `data_offset` is kept within the frame by every operation
        // that moves it.
        unsafe {
            self.region
                .ptr_at(self.frame_addr + self.data_offset as usize)
        }
    }
}

impl Drop for XdpBuffer {
    fn drop(&mut self) {
        // A disconnected channel means the pool is being torn down, and the
        // frame goes away with the mapping. Nothing to do about it.
        let _ = self.free_list.send(self.frame_addr);
    }
}

impl fmt::Debug for XdpBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XdpBuffer")
            .field("frame_addr", &self.frame_addr)
            .field("data_offset", &self.data_offset)
            .field("data_len", &self.data_len)
            .field("frame_size", &self.frame_size)
            .field("headroom", &self.headroom())
            .field("tailroom", &self.tailroom())
            .finish_non_exhaustive()
    }
}

impl AsRef<[u8]> for XdpBuffer {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        // SAFETY: the frame is ours alone, and the data region is within it.
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
        self.frame_size
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
    use crate::umem::{DATA_OFFSET, FRAME_SIZE, MAX_PACKET_LEN, UmemRegion};

    use net::buffer::{Headroom, Prepend, Tailroom, TrimFromEnd, TrimFromStart};

    use concurrency::sync::Arc;
    use concurrency::sync::mpsc::{Receiver, channel};
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

    /// Build a buffer over frame 0 of a fresh region, holding `data`. The
    /// returned channel is where the frame goes when the buffer is dropped.
    fn test_buffer(data: &[u8]) -> (XdpBuffer, Receiver<usize>, Arc<UmemRegion>, Vec<u8>) {
        let (region, backing) = test_region(1);
        let data_len = u16::try_from(data.len()).expect("test packets fit in a frame");
        let (tx, rx) = channel();
        // SAFETY: frame 0 is within the region and nothing else refers to it.
        let mut buf =
            unsafe { XdpBuffer::new(region.clone(), 0, DATA_OFFSET, data_len, FRAME_SIZE, tx) };
        buf.as_mut().copy_from_slice(data);
        (buf, rx, region, backing)
    }

    #[test]
    fn empty_buffer_offers_the_whole_frame() {
        let (buf, _rx, _region, _backing) = test_buffer(&[]);

        assert_eq!(buf.headroom(), DATA_OFFSET);
        assert_eq!(buf.tailroom(), MAX_PACKET_LEN);
        assert_eq!(buf.data_len(), 0);
        assert!(buf.as_ref().is_empty());
    }

    #[test]
    fn data_is_readable_where_it_was_written() {
        let data = b"Hello, AF_XDP!";
        let (buf, _rx, _region, _backing) = test_buffer(data);

        let len = u16::try_from(data.len()).expect("test packets fit in a frame");
        assert_eq!(buf.as_ref(), data);
        assert_eq!(buf.data_len(), len);
        assert_eq!(buf.headroom(), DATA_OFFSET);
        assert_eq!(buf.tailroom(), MAX_PACKET_LEN - len);
    }

    #[test]
    fn prepend_then_trim_returns_the_buffer_to_where_it_started() {
        let (mut buf, _rx, _region, _backing) = test_buffer(&[0xAA; 100]);
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
        assert_eq!(buf.tailroom(), MAX_PACKET_LEN - (len - 50));
    }

    #[test]
    fn prepend_beyond_the_start_of_the_frame_is_refused() {
        let (mut buf, _rx, _region, _backing) = test_buffer(&[0xAA; 100]);

        buf.trim_from_start(0).expect("trimming nothing succeeds");
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
        let (mut buf, _rx, _region, _backing) = test_buffer(&[0xAA; 10]);

        assert!(buf.trim_from_start(11).is_err());
        assert!(buf.trim_from_end(11).is_err());
        assert_eq!(buf.data_len(), 10);
    }

    #[test]
    fn a_dropped_buffer_hands_its_frame_back() {
        let (buf, rx, _region, _backing) = test_buffer(&[]);
        drop(buf);
        assert_eq!(rx.try_recv(), Ok(0));
    }
}
