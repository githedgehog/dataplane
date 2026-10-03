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

/// Total packet length across all segments.
///
/// [`AsRef<[u8]>`](AsRef) exposes only the contiguous head segment.
pub trait PacketLength {
    /// The total length of the packet in bytes (the sum of every segment's data length).
    fn packet_len(&self) -> usize;

    /// Whether the packet spans more than one segment.
    fn is_chained(&self) -> bool;
}

/// Super trait representing the abstract operations which may be performed on a packet buffer.
///
/// # Why there is no `'static` bound
///
/// There was one, and it made the production buffer type unrepresentable.
///
/// A DPDK `Mbuf` is branded with the lifetime of the `Eal` it was allocated under, so that an mbuf
/// whose `Drop` would free into a dismantled mempool cannot be written. That brand makes it not
/// `'static`, and a `'static` bound here therefore excluded the one buffer the dataplane actually
/// runs on, leaving `TestBuffer` as the only inhabitant of its own abstraction.
///
/// The bound was never a property of packet buffers in any case. It was there to satisfy
/// `DynNetworkFunction: Any`, which backed a runtime downcast of a pipeline stage to its concrete
/// type -- a facility with no production caller. `TypeId` requires `'static` for soundness, so that
/// downcast and a borrowed buffer are mutually exclusive; the downcast was the one that had to go.
pub trait PacketBuffer: AsRef<[u8]> + Headroom + PacketLength + Debug {}
impl<T> PacketBuffer for T where T: AsRef<[u8]> + Headroom + PacketLength + Debug {}

/// Super trait representing the abstract operations which may be performed on mutable a packet buffer.
///
/// # Why there is no `Send` bound
///
/// Also removed, and for a stronger reason than the `'static` one: requiring `Send` here asserted
/// something about DPDK mbufs that is false.
///
/// An `Mbuf` is deliberately `!Send`: mbufs stay on the lcore that received them, where the
/// mempool's per-lcore cache makes allocation and free cheap, and anything leaving the datapath
/// copies out what it needs.
///
/// So the bound could not be satisfied by the real buffer, and demanding it here would have forced
/// an `unsafe impl Send` that contradicts that design. Nothing needed it:
/// removing it produced no error anywhere in the workspace. A network function that genuinely
/// requires its buffers to be `Send` should say so itself rather than conscripting every buffer
/// into the claim.
pub trait PacketBufferMut:
    PacketBuffer + AsMut<[u8]> + Prepend + TrimFromStart + TrimFromEnd + Headroom + Tailroom
{
}
impl<T> PacketBufferMut for T where
    T: PacketBuffer + AsMut<[u8]> + Prepend + TrimFromStart + TrimFromEnd + Headroom + Tailroom
{
}

/// An independent buffer copy, which may fail to allocate.
pub trait DeepCopy: Sized {
    /// Copy failure, such as an exhausted memory pool.
    type Error: Debug;

    /// Produce an independent deep copy of this buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the copy could not be produced.
    fn deep_copy(&self) -> Result<Self, Self::Error>;
}

/// Trait representing the ability to get the unused headroom in a packet buffer.
pub trait Headroom {
    /// Get the (unused) headroom in a packet buffer.
    fn headroom(&self) -> u16;
}

/// Trait representing the ability to get the unused tailroom in a packet buffer.
pub trait Tailroom {
    /// Get the unused space after the last segment.
    fn tailroom(&self) -> u16;
}

/// Trait representing the ability to prepend data to a packet buffer.
pub trait Prepend {
    /// Error which may occur when attempting to prepend data to the buffer.
    type Error: Debug + Error;
    /// Prepend data to the buffer if possible.
    ///
    /// On success, returns the entire head segment, including the prepended bytes.
    /// The contents of the buffer will not be otherwise altered.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if an error occurs while performing this operation.
    /// The buffer is unchanged on failure.
    fn prepend(&mut self, len: u16) -> Result<&mut [u8], Self::Error>;
}

/// Trait representing the ability to append data to a packet buffer.
pub trait Append {
    /// Error which may occur when attempting to append data to the buffer.
    type Error: Debug;
    /// Append data to the last segment and return that entire segment.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if an error occurs while performing this operation.
    /// The buffer is unchanged on failure.
    fn append(&mut self, len: u16) -> Result<&mut [u8], Self::Error>;
}

/// Trait representing the ability to trim data from the start of a packet buffer.
pub trait TrimFromStart {
    /// Error which may occur when attempting to trim data from the start of the buffer.
    type Error: Debug;
    /// Trim within the head segment and return its remaining bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if an error occurs while performing this operation.
    /// The buffer is unchanged if `len` exceeds that segment.
    fn trim_from_start(&mut self, len: u16) -> Result<&mut [u8], Self::Error>;
}

/// Trait representing the ability to trim data from the end of a packet buffer.
pub trait TrimFromEnd {
    /// Error which may occur when attempting to trim data from the end of the buffer.
    type Error: Debug;
    /// Trim within the last segment and return its remaining bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if an error occurs while performing this operation.
    /// The buffer is unchanged if `len` exceeds that segment.
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
