// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Toy implementation of [`PacketBuffer`] which is useful for testing.
//!
//! [`PacketBuffer`]: crate::buffer::PacketBuffer

use crate::buffer::{
    Append, Headroom, MemoryBufferNotLongEnough, NotEnoughHeadRoom, NotEnoughTailRoom, Prepend,
    Tailroom, TrimFromEnd, TrimFromStart,
};
use tracing::trace;

// only included for doc ref
#[cfg(doc)]
use crate::buffer::PacketBuffer;

// Caution: do not implement Clone for `TestBuffer`.
// Clone would significantly deviate from the actual mechanics of a DPDK mbuf.
/// Toy data structure which implements [`PacketBuffer`]
///
/// The core function of this structure is to facilitate testing by "faking" many useful properties
/// of a real DPDK mbuf (without the need to spin up a full EAL).
#[derive(Debug)]
pub struct TestBuffer {
    buffer: Vec<u8>,
    headroom: u16,
    tailroom: u16,
}

impl Drop for TestBuffer {
    fn drop(&mut self) {
        trace!("Dropping TestBuffer");
    }
}

impl TestBuffer {
    const CAPACITY: u16 = 2048;
    const HEADROOM: u16 = 96;
    const TAILROOM: u16 = 96;

    /// Create a new (defaulted) `TestBuffer`.
    #[must_use]
    pub fn new() -> TestBuffer {
        let mut buffer = Vec::with_capacity(TestBuffer::CAPACITY as usize);
        let headroom = TestBuffer::HEADROOM;
        let tailroom = TestBuffer::TAILROOM;
        // fill buffer with simple pattern of bytes to help debug any memory access errors
        for i in 0..buffer.capacity() {
            #[allow(clippy::cast_possible_truncation)] // sound due to bitwise and
            buffer.push((i & u8::MAX as usize) as u8);
        }
        TestBuffer {
            buffer,
            headroom,
            tailroom,
        }
    }

    /// Create a new `TestBuffer` from a given slice of octets
    #[must_use]
    pub fn from_raw_data(data: &[u8]) -> TestBuffer {
        let mut buffer = Vec::with_capacity(TestBuffer::CAPACITY as usize);
        buffer.extend_from_slice(&[0; TestBuffer::HEADROOM as usize]);
        buffer.extend_from_slice(data);
        buffer.extend_from_slice(&[0; TestBuffer::TAILROOM as usize]);
        TestBuffer {
            buffer,
            headroom: TestBuffer::HEADROOM,
            tailroom: TestBuffer::TAILROOM,
        }
    }
}

impl Default for TestBuffer {
    fn default() -> TestBuffer {
        TestBuffer::new()
    }
}

impl AsRef<[u8]> for TestBuffer {
    fn as_ref(&self) -> &[u8] {
        let start = self.headroom as usize;
        let end = self.buffer.len() - self.tailroom as usize;
        &self.buffer.as_slice()[start..end]
    }
}

impl AsMut<[u8]> for TestBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        let start = self.headroom as usize;
        let end = self.buffer.len() - self.tailroom as usize;
        &mut self.buffer.as_mut_slice()[start..end]
    }
}

impl Headroom for TestBuffer {
    fn headroom(&self) -> u16 {
        self.headroom
    }
}

impl Tailroom for TestBuffer {
    fn tailroom(&self) -> u16 {
        self.tailroom
    }
}

impl Prepend for TestBuffer {
    type Error = NotEnoughHeadRoom;
    fn prepend(&mut self, len: u16) -> Result<&mut [u8], Self::Error> {
        if self.headroom < len {
            return Err(NotEnoughHeadRoom);
        }
        self.headroom -= len;
        Ok(self.as_mut())
    }
}

impl Append for TestBuffer {
    type Error = NotEnoughTailRoom;
    fn append(&mut self, len: u16) -> Result<&mut [u8], Self::Error> {
        if self.tailroom < len {
            return Err(NotEnoughTailRoom);
        }
        self.tailroom -= len;
        Ok(self.as_mut())
    }
}

impl TrimFromStart for TestBuffer {
    type Error = MemoryBufferNotLongEnough;
    fn trim_from_start(&mut self, len: u16) -> Result<&mut [u8], MemoryBufferNotLongEnough> {
        debug_assert!((self.headroom + self.tailroom) as usize <= self.buffer.len());
        debug_assert!(
            (self.headroom + self.tailroom) as usize + self.as_ref().len() == self.buffer.len()
        );
        if (self.headroom + self.tailroom + len) as usize > self.buffer.len() {
            return Err(MemoryBufferNotLongEnough);
        }
        self.headroom += len;
        Ok(self.as_mut())
    }
}

impl TrimFromEnd for TestBuffer {
    type Error = MemoryBufferNotLongEnough;
    fn trim_from_end(&mut self, len: u16) -> Result<&mut [u8], MemoryBufferNotLongEnough> {
        debug_assert!((self.headroom + self.tailroom) as usize <= self.buffer.len());
        debug_assert!(
            (self.headroom + self.tailroom) as usize + self.as_ref().len() == self.buffer.len()
        );
        if (self.headroom + self.tailroom + len) as usize > self.buffer.len() {
            return Err(MemoryBufferNotLongEnough);
        }
        self.tailroom += len;
        Ok(self.as_mut())
    }
}
