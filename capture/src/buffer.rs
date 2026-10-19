// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The bytes a capture copies out of a packet, in buffers that go back where they came from.

use concurrency::sync::mpsc::{self, Receiver, SyncSender};
use std::num::NonZeroU32;

/// A buffer holding one captured frame, and how much of a frame to keep.
///
/// A pooled buffer goes back to the pool it came from when dropped -- after the writer has written
/// it, or when a full queue drops its record -- so a capture allocates its buffers once and then
/// reuses them.
pub struct CaptureBuffer {
    bytes: Vec<u8>,
    snaplen: Option<NonZeroU32>,
    home: Option<SyncSender<Vec<u8>>>,
}

// By hand: the facade's channel ends are not `Debug` under every concurrency backend.
impl std::fmt::Debug for CaptureBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptureBuffer")
            .field("len", &self.bytes.len())
            .field("snaplen", &self.snaplen)
            .field("pooled", &self.home.is_some())
            .finish()
    }
}

impl CaptureBuffer {
    /// A buffer of its own, returned nowhere, keeping up to `snaplen` bytes of a frame (all of it if
    /// `None`).
    #[must_use]
    pub fn unpooled(snaplen: Option<NonZeroU32>) -> Self {
        CaptureBuffer {
            bytes: Vec::new(),
            snaplen,
            home: None,
        }
    }

    /// How many bytes of a frame to keep; `None` keeps all of it.
    #[must_use]
    pub fn snaplen(&self) -> Option<NonZeroU32> {
        self.snaplen
    }

    /// The captured bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn bytes_mut(&mut self) -> &mut Vec<u8> {
        &mut self.bytes
    }
}

/// A copy is a buffer of its own: it goes back to no pool.
impl Clone for CaptureBuffer {
    fn clone(&self) -> Self {
        CaptureBuffer {
            bytes: self.bytes.clone(),
            snaplen: self.snaplen,
            home: None,
        }
    }
}

impl Drop for CaptureBuffer {
    fn drop(&mut self) {
        if let Some(home) = self.home.take() {
            // Fails only if the pool is gone (its capture ended), and then the buffer is simply freed.
            let _ = home.try_send(std::mem::take(&mut self.bytes));
        }
    }
}

/// The buffers one capture point uses for one capture.
///
/// One per capture point rather than one shared, so that handing out and returning buffers needs no lock
/// a worker could wait on: the writer is the only one returning buffers here, and the capture point the
/// only one taking them. Buffers are allocated as they are first needed, up to `limit`; after that a
/// capture point with none free drops the record rather than allocate or wait.
pub(crate) struct BufferPool {
    free: Receiver<Vec<u8>>,
    home: SyncSender<Vec<u8>>,
    minted: usize,
    limit: usize,
    snaplen: Option<NonZeroU32>,
}

impl std::fmt::Debug for BufferPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufferPool")
            .field("minted", &self.minted)
            .field("limit", &self.limit)
            .field("snaplen", &self.snaplen)
            .finish_non_exhaustive()
    }
}

impl BufferPool {
    /// A pool of up to `limit` buffers, each keeping up to `snaplen` bytes of a frame.
    pub(crate) fn new(limit: usize, snaplen: Option<NonZeroU32>) -> Self {
        let (home, free) = mpsc::sync_channel(limit);
        BufferPool {
            free,
            home,
            minted: 0,
            limit,
            snaplen,
        }
    }

    /// A free buffer, or a new one if fewer than `limit` exist, or `None`.
    pub(crate) fn take(&mut self) -> Option<CaptureBuffer> {
        let bytes = match self.free.try_recv() {
            Ok(bytes) => bytes,
            Err(_) if self.minted < self.limit => {
                self.minted += 1;
                // A capture with a snap length allocates it up front, so that copying never grows it.
                Vec::with_capacity(self.snaplen.map_or(0, |n| n.get() as usize))
            }
            Err(_) => return None,
        };
        Some(CaptureBuffer {
            bytes,
            snaplen: self.snaplen,
            home: Some(self.home.clone()),
        })
    }
}
