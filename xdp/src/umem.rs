// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Geometry of the UMEM, the memory an `AF_XDP` socket shares with the kernel.
//!
//! The UMEM is one mapping split into equally sized frames. The kernel writes
//! received packets into frames userspace has posted on a fill ring, and reads
//! transmitted ones from frames userspace posts on a TX ring. Userspace reads
//! and writes them in place: there is no copy in or out of the mapping, which
//! is the whole point of `AF_XDP`.

#![allow(unsafe_code)] // the mapping is addressed by pointer; see `UmemRegion`

use std::ptr::NonNull;

/// Size of a UMEM frame, in bytes.
///
/// libxdp rejects frame sizes that are not a power of two. 4096 is a page,
/// which is what the kernel's zero-copy paths are happiest with.
pub const FRAME_SIZE: u16 = 4096;

/// Headroom the kernel reserves ahead of the packet data of every frame
/// (`XDP_PACKET_HEADROOM`).
///
/// It exists so that an XDP program can prepend to a packet before it reaches
/// the socket. Ours does not, so by the time a frame is handed to us the whole
/// of it is spare room the pipeline may prepend into.
pub const XDP_HEADROOM: u16 = 256;

/// Offset of the packet data from the start of a frame.
///
/// The UMEM is registered with no user headroom of its own, so this is just
/// the kernel's own reservation.
pub const DATA_OFFSET: u16 = XDP_HEADROOM;

/// The largest packet a single frame can hold.
pub const MAX_PACKET_LEN: u16 = FRAME_SIZE - DATA_OFFSET;

/// The mapped UMEM region, shared by every frame carved out of it.
///
/// Frames are addressed by their byte offset within the region rather than by
/// pointer, which is also how the kernel names them on the rings. Holding the
/// region in an `Arc` keeps the mapping alive for as long as any buffer still
/// refers to a frame in it.
pub(crate) struct UmemRegion {
    /// Start of the mapped region.
    base: NonNull<u8>,
    /// Length of the mapped region, in bytes.
    len: usize,
}

// SAFETY: a `UmemRegion` is only ever read through `ptr_at`, whose contract
// puts the burden of exclusive access on the caller. The region itself is a
// plain mapping with no interior state to race on.
unsafe impl Send for UmemRegion {}
// SAFETY: see above.
unsafe impl Sync for UmemRegion {}

// The region is built by the socket; see the note on `impl XdpBuffer`.
#[cfg_attr(not(any(feature = "runtime", test)), allow(dead_code))]
impl UmemRegion {
    /// Describe a UMEM region.
    ///
    /// # Safety
    ///
    /// `base` must point to a mapping of at least `len` bytes which stays
    /// mapped for as long as this `UmemRegion`, and any buffer derived from
    /// it, is alive.
    pub(crate) unsafe fn new(base: NonNull<u8>, len: usize) -> Self {
        Self { base, len }
    }

    /// Pointer to the byte at `offset` within the region.
    ///
    /// # Safety
    ///
    /// `offset` must be within the region, and the caller must hold exclusive
    /// access to the frame it falls in: neither another buffer nor the kernel
    /// may be reading or writing it.
    #[inline]
    pub(crate) unsafe fn ptr_at(&self, offset: usize) -> *mut u8 {
        debug_assert!(offset < self.len);
        // SAFETY: the caller promises `offset` is within the region, so the
        // result stays inside the same allocated object.
        unsafe { self.base.as_ptr().add(offset) }
    }
}
