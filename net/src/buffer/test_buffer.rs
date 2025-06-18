// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Toy implementation of [`PacketBuffer`] which is useful for testing.

#[cfg(any(test, feature = "bolero"))]
pub use contract::*;

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
#[derive(Debug, Clone)]
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

    /// Create a new (defaulted) `TestBuffer`.
    #[must_use]
    pub fn new() -> TestBuffer {
        let mut buffer = Vec::with_capacity(TestBuffer::CAPACITY as usize);
        let headroom = TestBuffer::HEADROOM;
        let tailroom = TestBuffer::TAILROOM;
        // fill the test buffer with a simple pattern of bytes to help debug any memory access
        // errors
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
