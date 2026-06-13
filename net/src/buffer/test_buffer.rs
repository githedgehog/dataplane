// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Toy implementation of [`PacketBuffer`] which is useful for testing.

#![cfg(any(doc, test, feature = "test_buffer"))]

#[cfg(any(test, feature = "bolero"))]
pub use contract::*;

use crate::buffer::{
    Append, DeepCopy, Headroom, MemoryBufferNotLongEnough, NotEnoughHeadRoom, NotEnoughTailRoom,
    NotWritable, PacketLength, Prepend, Tailroom, TrimFromEnd, TrimFromStart, TryAsMut,
};
use core::convert::Infallible;
use tracing::trace;

// only included for doc ref
#[cfg(doc)]
use crate::buffer::PacketBuffer;

// `TestBuffer` deliberately does not implement `Clone`: a real DPDK mbuf cannot be duplicated by a
// bitwise copy.  Use [`DeepCopy::deep_copy`] to duplicate, matching what production buffers support.
/// Toy data structure which implements [`PacketBuffer`]
///
/// The core function of this structure is to facilitate testing by "faking" many useful properties
/// of a real DPDK mbuf (without the need to spin up a full EAL).
#[derive(Debug)]
pub struct TestBuffer {
    /// The first segment of the packet.  Subsequent segments hang off `TestSegment::next`,
    /// modeling a DPDK mbuf chain.  A single-segment buffer is just `head` with `next == None`.
    head: TestSegment,
}

/// One segment of a (possibly multi-segment) [`TestBuffer`], modeling a single mbuf in a chain.
///
/// `room` is a fixed-size data buffer (analogous to an mbuf's data room): it never grows, and the
/// in-use bytes are the window `room[data_off .. data_off + data_len]`.  The bytes before the
/// window are headroom, the bytes after are tailroom.
///
/// The room is a `Box<[u8]>` (uniquely owned) for now.  When refcount sharing (multicast) lands it
/// will become a shareable, refcounted buffer and the writability of a segment will follow its
/// refcount -- the same lifecycle a real mbuf has.
#[derive(Debug)]
struct TestSegment {
    room: Box<[u8]>,
    data_off: u16,
    data_len: u16,
    next: Option<Box<TestSegment>>,
}

impl TestSegment {
    /// Build a single segment whose room is `headroom` zero bytes, then `data`, then `tailroom`
    /// zero bytes.
    fn new(headroom: u16, data: &[u8], tailroom: u16) -> TestSegment {
        let mut room = Vec::with_capacity(headroom as usize + data.len() + tailroom as usize);
        room.resize(headroom as usize, 0);
        room.extend_from_slice(data);
        room.resize(room.len() + tailroom as usize, 0);
        #[allow(clippy::cast_possible_truncation)] // segment data is bounded well below u16::MAX
        let data_len = data.len() as u16;
        TestSegment {
            room: room.into_boxed_slice(),
            data_off: headroom,
            data_len,
            next: None,
        }
    }

    /// The in-use bytes of this segment.
    fn data(&self) -> &[u8] {
        let start = self.data_off as usize;
        &self.room[start..start + self.data_len as usize]
    }

    /// The in-use bytes of this segment, mutably.
    fn data_mut(&mut self) -> &mut [u8] {
        let start = self.data_off as usize;
        let end = start + self.data_len as usize;
        &mut self.room[start..end]
    }

    /// The unused space after the in-use bytes of this segment.
    fn tailroom(&self) -> u16 {
        #[allow(clippy::cast_possible_truncation)] // room length is bounded well below u16::MAX
        let room_len = self.room.len() as u16;
        room_len - self.data_off - self.data_len
    }

    /// The last segment of this chain (recursively); for a lone segment, itself.
    fn last_mut(&mut self) -> &mut TestSegment {
        match self.next {
            Some(ref mut next) => next.last_mut(),
            None => self,
        }
    }

    /// Recursively deep-copy this segment and its tail into a fresh, independent chain.
    fn deep_clone(&self) -> TestSegment {
        TestSegment {
            room: self.room.clone(),
            data_off: self.data_off,
            data_len: self.data_len,
            next: self.next.as_ref().map(|next| Box::new(next.deep_clone())),
        }
    }
}

impl DeepCopy for TestBuffer {
    // A `TestBuffer` is backed by ordinary, uniquely-owned heap memory, so a deep copy cannot fail.
    type Error = Infallible;

    fn deep_copy(&self) -> Result<TestBuffer, Infallible> {
        Ok(TestBuffer {
            head: self.head.deep_clone(),
        })
    }
}

impl Drop for TestBuffer {
    fn drop(&mut self) {
        trace!("Dropping TestBuffer");
    }
}

impl TestBuffer {
    /// The maximum capacity of a `TestBuffer`.
    ///
    /// This is the maximum number of octets that can be stored in a `TestBuffer`.
    ///
    /// This is set to 2048 octets to match the default capacity of a DPDK mbuf.
    pub const CAPACITY: u16 = 2048;
    /// The reserved headroom of a `TestBuffer`.
    pub const HEADROOM: u16 = 96;
    /// The reserved tailroom of a `TestBuffer`.
    pub const TAILROOM: u16 = 96;

    /// Create a new (defaulted) `TestBuffer`: a single full-capacity segment pre-filled with a
    /// recognizable byte pattern (so stray reads stand out), with the standard head/tailroom.
    #[must_use]
    pub fn new() -> TestBuffer {
        let mut room = Vec::with_capacity(TestBuffer::CAPACITY as usize);
        for i in 0..TestBuffer::CAPACITY as usize {
            #[allow(clippy::cast_possible_truncation)] // sound due to bitwise and
            room.push((i & u8::MAX as usize) as u8);
        }
        TestBuffer {
            head: TestSegment {
                room: room.into_boxed_slice(),
                data_off: TestBuffer::HEADROOM,
                data_len: TestBuffer::CAPACITY - TestBuffer::HEADROOM - TestBuffer::TAILROOM,
                next: None,
            },
        }
    }

    /// Create a single-segment `TestBuffer` holding `data`, with the standard head/tailroom.
    #[must_use]
    pub fn from_raw_data(data: &[u8]) -> TestBuffer {
        TestBuffer {
            head: TestSegment::new(TestBuffer::HEADROOM, data, TestBuffer::TAILROOM),
        }
    }

    /// Create a multi-segment `TestBuffer` from one slice per segment, modeling a scattered
    /// (chained) mbuf.  The first segment carries the headroom and the last the tailroom; interior
    /// segments are tight.  Useful for exercising the multi-segment paths a single-segment buffer
    /// cannot reach.
    #[must_use]
    pub fn from_segments(segments: &[&[u8]]) -> TestBuffer {
        let n = segments.len();
        // Build the trailing segments (indices `1..n`) from the tail backward so each owns its
        // `next` before becoming one.
        let mut next: Option<Box<TestSegment>> = None;
        for i in (1..n).rev() {
            let tailroom = if i == n - 1 { TestBuffer::TAILROOM } else { 0 };
            let mut seg = TestSegment::new(0, segments[i], tailroom);
            seg.next = next.take();
            next = Some(Box::new(seg));
        }
        let head_data = segments.first().copied().unwrap_or(&[]);
        // The head carries the tailroom too when it is the only segment.
        let head_tailroom = if n <= 1 { TestBuffer::TAILROOM } else { 0 };
        let mut head = TestSegment::new(TestBuffer::HEADROOM, head_data, head_tailroom);
        head.next = next;
        TestBuffer { head }
    }

    /// The last segment in the chain (the one carrying the tailroom and the end of the packet).
    fn last_mut(&mut self) -> &mut TestSegment {
        self.head.last_mut()
    }
}

impl Default for TestBuffer {
    fn default() -> TestBuffer {
        TestBuffer::new()
    }
}

impl AsRef<[u8]> for TestBuffer {
    fn as_ref(&self) -> &[u8] {
        // The contiguous "head" view: header parsing/deparsing operates here, mirroring how the
        // header stack lives in an mbuf's first segment.
        self.head.data()
    }
}

impl TryAsMut for TestBuffer {
    fn try_as_mut(&mut self) -> Result<&mut [u8], NotWritable> {
        // The head segment's room is uniquely owned (`Box`), so this never fails today.  Once a
        // segment can be shared (refcounted) this will consult the refcount the way `Mbuf` does.
        Ok(self.head.data_mut())
    }
}

impl PacketLength for TestBuffer {
    fn packet_len(&self) -> usize {
        let mut total = 0usize;
        let mut seg = Some(&self.head);
        while let Some(s) = seg {
            total += s.data_len as usize;
            seg = s.next.as_deref();
        }
        total
    }
}

impl Headroom for TestBuffer {
    fn headroom(&self) -> u16 {
        self.head.data_off
    }
}

impl Tailroom for TestBuffer {
    fn tailroom(&self) -> u16 {
        // Tailroom lives in the last segment (the end of the packet).
        let mut seg = &self.head;
        while let Some(next) = seg.next.as_deref() {
            seg = next;
        }
        seg.tailroom()
    }
}

impl Prepend for TestBuffer {
    type Error = NotEnoughHeadRoom;
    fn prepend(&mut self, len: u16) -> Result<&mut [u8], Self::Error> {
        // Prepending grows the front of the head segment into its headroom (mbuf `prepend`).
        if self.head.data_off < len {
            return Err(NotEnoughHeadRoom);
        }
        self.head.data_off -= len;
        self.head.data_len += len;
        Ok(self.head.data_mut())
    }
}

impl Append for TestBuffer {
    type Error = NotEnoughTailRoom;
    fn append(&mut self, len: u16) -> Result<&mut [u8], Self::Error> {
        // Appending grows the back of the last segment into its tailroom (mbuf `append`).
        let last = self.last_mut();
        if last.tailroom() < len {
            return Err(NotEnoughTailRoom);
        }
        last.data_len += len;
        Ok(last.data_mut())
    }
}

impl TrimFromStart for TestBuffer {
    type Error = MemoryBufferNotLongEnough;
    fn trim_from_start(&mut self, len: u16) -> Result<&mut [u8], MemoryBufferNotLongEnough> {
        // Trimming from the start advances the head segment's window (mbuf `adj`), which only
        // operates within the first segment.
        if len > self.head.data_len {
            return Err(MemoryBufferNotLongEnough);
        }
        self.head.data_off += len;
        self.head.data_len -= len;
        Ok(self.head.data_mut())
    }
}

impl TrimFromEnd for TestBuffer {
    type Error = MemoryBufferNotLongEnough;
    fn trim_from_end(&mut self, len: u16) -> Result<&mut [u8], MemoryBufferNotLongEnough> {
        // Trimming from the end shrinks the last segment (mbuf `trim`).
        let last = self.last_mut();
        if len > last.data_len {
            return Err(MemoryBufferNotLongEnough);
        }
        last.data_len -= len;
        Ok(last.data_mut())
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::buffer::TestBuffer;
    use crate::eth::Eth;
    use crate::headers::Headers;
    use crate::parse::DeParse;
    use bolero::generator::bolero_generator::bounded::BoundedValue;
    use bolero::{Driver, TypeGenerator, ValueGenerator};
    use std::num::NonZero;
    use std::ops::Bound;

    /// The minimum length of a generated [`TestBuffer`].
    pub const MIN_LEN: u16 = Eth::HEADER_LEN.get();

    /// [`ValueGenerator`] which produces [`TestBuffer`]s of a specified length.
    #[repr(transparent)]
    pub struct GenerateTestBufferOfLength(NonZero<u16>);

    impl GenerateTestBufferOfLength {
        /// Create a new `GenerateTestBufferOfLength` to generate test buffers of length `len`.
        ///
        /// If `len` is less than [`MIN_LEN`], it will be set to [`MIN_LEN`].
        /// If `len` is greater than [`TestBuffer::CAPACITY`], it will be set to [`TestBuffer::CAPACITY`].
        #[must_use]
        pub fn new(len: u16) -> Self {
            #[allow(unsafe_code)] // sound by construction
            let len = unsafe {
                NonZero::new_unchecked(match len {
                    0..MIN_LEN => MIN_LEN,
                    MIN_LEN..=TestBuffer::CAPACITY => len,
                    _ => TestBuffer::CAPACITY,
                })
            };
            Self(len)
        }
    }

    impl ValueGenerator for GenerateTestBufferOfLength {
        type Output = TestBuffer;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let mut data = Vec::<u8>::with_capacity(self.0.get() as usize);
            for _ in 0..self.0.get() {
                data.push(driver.produce()?);
            }
            Some(TestBuffer::from_raw_data(&data))
        }
    }

    impl TypeGenerator for TestBuffer {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            GenerateTestBufferOfLength::new(driver.produce()?).generate(driver)
        }
    }

    /// [`ValueGenerator`] generator which produces [`TestBuffer`]s between a specified and [`TestBuffer::CAPACITY`].
    #[repr(transparent)]
    pub struct GenerateTestBufferOfMinimumLength(NonZero<u16>);

    impl GenerateTestBufferOfMinimumLength {
        /// Create a new `GenerateTestBufferOfMinimumLength` to generate test buffers of length `min_len` to [`TestBuffer::CAPACITY`].
        ///
        /// If `min_len` is less than [`MIN_LEN`], it will be set to [`MIN_LEN`].
        /// If `min_len` is greater than [`TestBuffer::CAPACITY`], it will be set to [`TestBuffer::CAPACITY`].
        #[must_use]
        pub fn new(min_len: u16) -> Self {
            Self(
                match min_len {
                    0..MIN_LEN => NonZero::new(MIN_LEN),
                    MIN_LEN..=TestBuffer::CAPACITY => NonZero::new(min_len),
                    _ => NonZero::new(TestBuffer::CAPACITY),
                }
                .unwrap_or_else(|| unreachable!()),
            )
        }
    }

    /// [`ValueGenerator`] generator which produces [`TestBuffer`]s between a specified and [`TestBuffer::CAPACITY`].
    #[repr(transparent)]
    pub struct GenerateTestBufferOfMaximumLength(NonZero<u16>);

    impl ValueGenerator for GenerateTestBufferOfMinimumLength {
        type Output = TestBuffer;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            GenerateTestBufferOfLength::new(u16::gen_bounded(
                driver,
                Bound::Included(&self.0.get()),
                Bound::Included(&TestBuffer::CAPACITY),
            )?)
            .generate(driver)
        }
    }

    impl GenerateTestBufferOfMaximumLength {
        /// Create a new `GenerateTestBufferOfMinimumLength` to generate test buffers of length `min_len` to [`TestBuffer::CAPACITY`].
        ///
        /// If `min_len` is less than [`MIN_LEN`], it will be set to [`MIN_LEN`].
        /// If `min_len` is greater than [`TestBuffer::CAPACITY`], it will be set to [`TestBuffer::CAPACITY`].
        #[must_use]
        pub fn new(max_len: u16) -> Self {
            Self(
                NonZero::new(match max_len {
                    0..MIN_LEN => MIN_LEN,
                    MIN_LEN..TestBuffer::CAPACITY => max_len,
                    _ => TestBuffer::CAPACITY,
                })
                .unwrap_or_else(|| unreachable!()),
            )
        }
    }

    impl ValueGenerator for GenerateTestBufferOfMaximumLength {
        type Output = TestBuffer;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            GenerateTestBufferOfLength::new(u16::gen_bounded(
                driver,
                Bound::Included(&MIN_LEN),
                Bound::Included(&self.0.get()),
            )?)
            .generate(driver)
        }
    }

    /// [`ValueGenerator`] generator which produces [`TestBuffer`]s, which contain specified [`Headers`].
    #[repr(transparent)]
    pub struct GenerateTestBufferForHeaders(Headers);

    impl GenerateTestBufferForHeaders {
        /// Create a new `GenerateTestBufferForHeaders` to generate test buffers which contain the specified [`Headers`].
        #[must_use]
        pub fn new(headers: Headers) -> Self {
            Self(headers)
        }
    }

    impl ValueGenerator for GenerateTestBufferForHeaders {
        type Output = TestBuffer;

        fn generate<D: Driver>(&self, _driver: &mut D) -> Option<Self::Output> {
            let mut data = vec![0; self.0.size().get() as usize];
            #[allow(clippy::unwrap_used)] // TEMPORARY
            self.0.deparse(data.as_mut()).unwrap();
            Some(TestBuffer::from_raw_data(&data))
        }
    }
}

#[cfg(test)]
mod multi_seg_tests {
    use super::TestBuffer;
    use crate::buffer::{
        DeepCopy, Headroom, PacketLength, Prepend, Tailroom, TrimFromStart, TryAsMut,
    };

    #[test]
    fn single_segment_packet_len_matches_head() {
        let buf = TestBuffer::from_raw_data(&[1, 2, 3, 4, 5]);
        assert_eq!(buf.packet_len(), 5);
        assert_eq!(buf.as_ref(), &[1, 2, 3, 4, 5]);
        // Single segment: the packet length equals the contiguous head view.
        assert_eq!(buf.packet_len(), buf.as_ref().len());
    }

    #[test]
    fn multi_segment_packet_len_exceeds_head() {
        let seg0: &[u8] = &[10, 11, 12];
        let seg1: &[u8] = &[20, 21];
        let seg2: &[u8] = &[30, 31, 32, 33];
        let buf = TestBuffer::from_segments(&[seg0, seg1, seg2]);

        // `as_ref()` exposes only the head segment...
        assert_eq!(buf.as_ref(), seg0);
        // ...while `packet_len()` sums every segment.
        assert_eq!(buf.packet_len(), seg0.len() + seg1.len() + seg2.len());
        assert!(buf.packet_len() > buf.as_ref().len());

        // Headroom lives on the head; tailroom on the last segment.
        assert_eq!(buf.headroom(), TestBuffer::HEADROOM);
        assert_eq!(buf.tailroom(), TestBuffer::TAILROOM);
    }

    #[test]
    fn deep_copy_preserves_chain_and_is_independent() {
        let buf = TestBuffer::from_segments(&[&[1, 2, 3], &[4, 5]]);
        let mut copy = buf.deep_copy().unwrap();
        assert_eq!(copy.packet_len(), buf.packet_len());
        assert_eq!(copy.as_ref(), buf.as_ref());
        // Mutating the copy's head must not affect the original.
        copy.try_as_mut().unwrap()[0] = 0xff;
        assert_eq!(buf.as_ref()[0], 1);
        assert_eq!(copy.as_ref()[0], 0xff);
    }

    #[test]
    fn prepend_then_trim_operate_on_head() {
        let mut buf = TestBuffer::from_segments(&[&[0xaa, 0xbb], &[0xcc]]);
        let before = buf.packet_len();
        // Prepend grows the head (and the packet) by 2 bytes; write into the new front.
        buf.prepend(2).unwrap()[..2].copy_from_slice(&[1, 2]);
        assert_eq!(buf.packet_len(), before + 2);
        assert_eq!(&buf.as_ref()[..2], &[1, 2]);
        // Trimming from the start removes them again.
        buf.trim_from_start(2).unwrap();
        assert_eq!(buf.packet_len(), before);
        assert_eq!(buf.as_ref(), &[0xaa, 0xbb]);
    }

    #[test]
    fn trim_from_start_cannot_exceed_head_segment() {
        // The head holds 2 bytes; trimming past it is an error (mbuf `adj` is head-only).
        let mut buf = TestBuffer::from_segments(&[&[1, 2], &[3, 4, 5]]);
        assert!(buf.trim_from_start(3).is_err());
    }
}
