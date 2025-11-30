// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! [`PacketBuffer`] and related traits

#[cfg(any(doc, test, feature = "test_buffer"))]
pub mod test_buffer;

use core::fmt::Debug;
use std::error::Error;

#[allow(unused_imports)] // re-export
#[cfg(any(doc, test, feature = "test_buffer"))]
pub use test_buffer::*;

/// Super trait representing the abstract operations which may be performed on a packet buffer.
pub trait PacketBuffer: AsRef<[u8]> + Headroom + Debug + 'static {}
impl<T> PacketBuffer for T where T: AsRef<[u8]> + Headroom + Debug + 'static {}

/// Super trait representing the abstract operations which may be performed on mutable a packet buffer.
pub trait PacketBufferMut:
    PacketBuffer + AsMut<[u8]> + Append + Prepend + Send + TrimFromStart + TrimFromEnd + Headroom + Tailroom
{
}

#[allow(missing_docs)]
pub trait Pool<B> {
    fn allocate(&mut self) -> B;
}

impl<T> PacketBufferMut for T where
    T: PacketBuffer
        + AsMut<[u8]>
        + Append
        + Prepend
        + Send
        + TrimFromStart
        + TrimFromEnd
        + Headroom
        + Tailroom
{
}

/// Trait representing the ability to create buffer pools
#[cfg(any(doc, test, feature = "test_buffer"))]
pub trait BufferPool: Send + Sync {
    /// The type of the buffer provided by this type
    type Buffer: PacketBufferMut;

    /// Provide a packet buffer
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if a buffer could not be provided
    fn new_buffer(&self) -> Result<Self::Buffer, crate::buffer::test_buffer::BufferAllocationError>;
}

/// Trait representing the ability to create a new [`BufferPool`]
pub trait NewBufferPool: Sized {
    /// Configuration required to create a buffer pool
    type Config<'a>;
    /// Errors which may occur when creating a buffer pool.
    type Error: std::error::Error;
    /// Create a buffer pool.
    ///
    /// # Errors
    ///
    /// Implementations are expected to return errors if a pool can not
    /// be built to match the supplied configuration.
    fn new_pool(args: Self::Config<'_>) -> Result<Self, Self::Error>;
}

/// Trait representing the ability to get the unused headroom in a packet buffer.
pub trait Headroom {
    /// Get the (unused) headroom in a packet buffer.
    fn headroom(&self) -> u16;
}

/// Trait representing the ability to get the unused tailroom in a packet buffer.
pub trait Tailroom {
    /// Get the (unused) tailroom in a packet buffer.
    fn tailroom(&self) -> u16;
}

/// Trait representing the ability to prepend data to a packet buffer.
pub trait Prepend {
    /// Error which may occur when attempting to prepend data to the buffer.
    type Error: Debug + Error;
    /// Prepend data to the buffer if possible.
    ///
    /// If successful, this method returns a slice to the net start of the buffer.
    /// The contents of the buffer will not be otherwise altered.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if an error occurs while performing this operation.
    /// For example, there may not be enough headroom available.
    fn prepend(&mut self, len: u16) -> Result<&mut [u8], Self::Error>;
}

/// Trait representing the ability to append data to a packet buffer.
pub trait Append {
    /// Error which may occur when attempting to append data to the buffer.
    type Error: Debug;
    /// Append data to the buffer if possible.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if an error occurs while performing this operation.
    /// For example, there may not be enough tailroom available.
    fn append(&mut self, len: u16) -> Result<&mut [u8], Self::Error>;
}

/// Trait representing the ability to trim data from the start of a packet buffer.
pub trait TrimFromStart {
    /// Error which may occur when attempting to trim data from the start of the buffer.
    type Error: Debug;
    /// Trim data from the start of the buffer if possible.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if an error occurs while performing this operation.
    /// For example, the buffer may not have `len` bytes in it to begin with.
    fn trim_from_start(&mut self, len: u16) -> Result<&mut [u8], Self::Error>;
}

/// Trait representing the ability to trim data from the end of a packet buffer.
pub trait TrimFromEnd {
    /// Error which may occur when attempting to trim data from the end of the buffer.
    type Error: Debug;
    /// Trim data from the end of the buffer if possible.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if an error occurs while performing this operation.
    /// For example, the buffer may not have `len` bytes in it to begin with.
    fn trim_from_end(&mut self, len: u16) -> Result<&mut [u8], Self::Error>;
}

/// Error indicating that there is not enough headroom in a memory buffer for the requested
/// operation.
#[non_exhaustive]
#[repr(transparent)]
#[derive(Debug, thiserror::Error)]
#[error("Not enough head room in memory buffer")]
pub struct NotEnoughHeadRoom;

/// Error indicating that there is not enough tailroom in a memory buffer for the requested
/// operation.
#[non_exhaustive]
#[repr(transparent)]
#[derive(Debug, thiserror::Error)]
#[error("Not enough tail room in memory buffer")]
pub struct NotEnoughTailRoom;

/// Error indicating that the buffer is not long enough to perform the requested operation.
#[non_exhaustive]
#[repr(transparent)]
#[derive(Debug, thiserror::Error)]
#[error("MemoryBuffer not long enough to remove required number of bytes")]
pub struct MemoryBufferNotLongEnough;
