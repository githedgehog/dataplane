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

/// Trait for the total length of a packet, summed across all of its segments.
///
/// This is distinct from the length of the contiguous head view returned by
/// [`AsRef<[u8]>`](AsRef): for a multi-segment buffer the packet is longer than its head segment,
/// while for a single-segment buffer the two are equal.  Length fields (IP total length, UDP
/// length, ...) and any whole-packet sizing must use this rather than `as_ref().len()`.
pub trait PacketLength {
    /// The total length of the packet in bytes (the sum of every segment's data length).
    fn packet_len(&self) -> usize;
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
/// An `Mbuf` is deliberately `!Send`. It is a bare pointer into a mempool with no refcount tying
/// the two together, so an mbuf that escapes to another thread has nothing left proving its pool
/// outlives it -- the bug that produced was a SIGSEGV in `rte_pktmbuf_free` during teardown.
/// Crossing a thread boundary has to go through `Pool::consign`, which attaches a guard to the
/// whole batch and *earns* its `Send`.
///
/// So the bound could not be satisfied by the real buffer, and demanding it here would have forced
/// either an unsound `unsafe impl Send` or a per-mbuf refcount on the datapath. Nothing needed it:
/// removing it produced no error anywhere in the workspace. A network function that genuinely
/// requires its buffers to be `Send` should say so itself rather than conscripting every buffer
/// into the claim.
pub trait PacketBufferMut:
    PacketBuffer + TryAsMut + Prepend + TrimFromStart + TrimFromEnd + Headroom + Tailroom
{
}
impl<T> PacketBufferMut for T where
    T: PacketBuffer + TryAsMut + Prepend + TrimFromStart + TrimFromEnd + Headroom + Tailroom
{
}

/// Error indicating that a packet buffer cannot be mutated because it is not exclusively owned.
///
/// A buffer is shared when it is a reference-counted or indirect DPDK mbuf with more than one
/// holder; writing through it would corrupt the others.  No sharing is created yet, so this does
/// not occur in practice today, but keeping mutable access fallible stops call sites from assuming
/// the exclusive ownership that a future shared/cloned buffer would not have.
#[derive(Debug, thiserror::Error)]
#[error("packet buffer is not exclusively owned and cannot be mutated")]
pub struct NotWritable;

/// Trait for fallibly obtaining mutable access to a packet buffer's bytes.
///
/// This replaces an infallible `AsMut<[u8]>`: an `Mbuf`-backed buffer cannot promise exclusive
/// ownership, so handing out `&mut [u8]` must be allowed to fail.  Reading (via [`AsRef`]) is
/// always permitted.
pub trait TryAsMut {
    /// Get mutable access to the buffer's bytes.
    ///
    /// # Errors
    ///
    /// Returns [`NotWritable`] if the buffer is shared and therefore cannot be mutated in place.
    fn try_as_mut(&mut self) -> Result<&mut [u8], NotWritable>;
}

/// Trait for producing an independent (deep) copy of a packet buffer.
///
/// This is deliberately **not** [`Clone`].  Duplicating a real DPDK mbuf allocates a fresh buffer
/// from a memory pool (which can be exhausted) and copies the bytes; it is fallible and never a
/// trivial bitwise copy.  Keeping duplication explicit and off [`Clone`] stops test buffers from
/// silently expressing a duplication that production `Mbuf`-backed packets cannot.
pub trait DeepCopy: Sized {
    /// Error returned when the copy cannot be produced (for example, the backing pool is
    /// exhausted).
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
