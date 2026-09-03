// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! `AF_XDP` sockets and the rings a worker moves packets over.
//!
//! A worker owns one [`XskUmem`] and one [`XskSocket`] per interface it serves.
//! All of its sockets are bound to the same UMEM, which is what lets a packet
//! received on one interface be forwarded out of another without leaving the
//! mapping, and which gives the worker a single pool of free frames to draw
//! from rather than one per interface.
//!
//! A frame moves through the rings like this:
//!
//! ```text
//!                 free frames
//!                 |         ^
//!        fill ring v         \ completion ring
//!            (kernel writes)  \ (kernel has sent)
//!                 |            \
//!             RX ring        TX ring
//!                 |            ^
//!                 v           /
//!            XdpBuffer  ->  pipeline  ->  send()
//!                 \                        (copies into a free frame)
//!                  \ dropped by the pipeline
//!                   -> back to free frames
//! ```
//!
//! A buffer hands its frame back over a channel when it is dropped, wherever
//! in the pipeline that happens; [`XskUmem::reclaim_dropped`] moves those
//! frames back to the free list.

#![allow(unsafe_code)] // ring operations and UMEM access are unsafe by nature

use concurrency::sync::Arc;
use concurrency::sync::mpsc::{Receiver, Sender, channel};
use std::collections::VecDeque;
use std::io::Write;
use std::num::NonZeroU32;
use std::os::fd::BorrowedFd;
use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr::NonNull;

use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use tracing::{debug, info, trace, warn};
use xsk_rs::config::{
    BindFlags, Interface, LibxdpFlags, SocketConfig, SocketConfigBuilder, UmemConfig,
    UmemConfigBuilder,
};
use xsk_rs::socket::{Socket, TxQueue, XdpStatistics};
use xsk_rs::umem::frame::FrameDesc;
use xsk_rs::{CompQueue, FillQueue, RxQueue, Umem};

use crate::buffer::XdpBuffer;
use crate::program::Redirect;
use crate::umem::{
    DATA_OFFSET, FRAME_SIZE, LINEAR_SIZE, MAX_FRAME_PACKET_LEN, MAX_PACKET_LEN, UmemRegion,
};

/// Frames handled in one ring operation.
pub const BATCH_SIZE: usize = 64;

/// The most frames one packet can span, which is what it takes to hold
/// [`MAX_PACKET_LEN`] at [`MAX_FRAME_PACKET_LEN`] a frame.
const MAX_FRAGMENTS: usize = MAX_PACKET_LEN.div_ceil(MAX_FRAME_PACKET_LEN) as usize;

/// The descriptor option that says a packet continues in the next descriptor.
///
/// xsk-rs reads it back through `FrameDesc::has_more_frames`, but does not
/// give a way to set it by name.
const XDP_PKT_CONTD: u32 = 1;

/// Start of the frame the byte at `addr` falls in.
///
/// Masking rather than subtracting the headroom, so that a frame is still
/// found when its packet does not start where the UMEM put it, which is the
/// case for any frame an XDP program has prepended to. Valid because the
/// kernel only takes a power of two frame size.
const fn frame_start(addr: usize) -> usize {
    addr & !(FRAME_SIZE as usize - 1)
}

/// An error, followed by the chain of causes behind it.
///
/// libxdp's errors keep the errno that actually says what went wrong -- a
/// permission problem, a driver that will not do zero-copy -- in their source
/// rather than their message, so reporting only the message loses it.
fn with_causes(error: &dyn std::error::Error) -> String {
    use std::fmt::Write as _;

    let mut message = error.to_string();
    let mut cause = error.source();
    while let Some(error) = cause {
        // Writing to a String cannot fail.
        let _ = write!(message, ": {error}");
        cause = error.source();
    }
    message
}

/// Size of each of the four rings, in descriptors. Must be a power of two.
pub const DEFAULT_RING_SIZE: u32 = 1024;

/// Frames to give the UMEM for each socket bound to it.
///
/// Enough to keep a fill ring full, with the rest covering the frames in
/// flight through the pipeline and on the TX ring.
pub const DEFAULT_FRAMES_PER_SOCKET: u32 = 2048;

/// Buffers kept for packets that arrive across more than one frame.
///
/// Only packets too long for a frame need one, and only for as long as they
/// are in the pipeline, so this is sized for a batch of them in flight rather
/// than for the frame pool.
pub const DEFAULT_LINEAR_BUFFERS: usize = 256;

/// Anything that can go wrong setting up or driving an `AF_XDP` socket.
#[derive(Debug, thiserror::Error)]
pub enum XskError {
    /// The requested geometry is one libxdp or the kernel will not accept.
    #[error("invalid AF_XDP configuration: {0}")]
    Config(String),
    /// The UMEM could not be created.
    #[error("could not create the UMEM: {0}")]
    Umem(String),
    /// The socket could not be created or bound.
    #[error("could not bind an AF_XDP socket to {if_name}:q{queue_id}: {reason}")]
    Bind {
        /// Interface we tried to bind to.
        if_name: String,
        /// Queue we tried to bind to.
        queue_id: u32,
        /// What libxdp reported.
        reason: String,
    },
    /// A syscall failed.
    #[error("AF_XDP I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Every frame is either on a ring or in the pipeline.
    #[error("no free UMEM frames")]
    NoFreeFrames,
    /// The packet does not fit in a frame.
    #[error("packet of {len} bytes exceeds the {MAX_PACKET_LEN} byte frame capacity")]
    PacketTooLong {
        /// Length of the packet we were asked to send.
        len: usize,
    },
    /// The kernel has not caught up with what we already queued.
    #[error("TX ring full")]
    TxRingFull,
}

/// Geometry and bind options shared by every socket on one UMEM.
#[derive(Debug, Clone, Copy)]
pub struct XskConfig {
    /// Number of frames in the UMEM.
    pub frames: u32,
    /// Number of descriptors in each socket's fill ring.
    pub fill_ring_size: u32,
    /// Number of descriptors in each socket's completion ring.
    pub completion_ring_size: u32,
    /// Number of descriptors in each socket's RX ring.
    pub rx_ring_size: u32,
    /// Number of descriptors in each socket's TX ring.
    pub tx_ring_size: u32,
    /// Bind in copy mode without trying zero-copy first.
    pub force_copy: bool,
    /// Buffers to keep for packets that span more than one frame.
    pub linear_buffers: usize,
}

impl Default for XskConfig {
    fn default() -> Self {
        Self {
            frames: DEFAULT_FRAMES_PER_SOCKET,
            fill_ring_size: DEFAULT_RING_SIZE,
            completion_ring_size: DEFAULT_RING_SIZE,
            rx_ring_size: DEFAULT_RING_SIZE,
            tx_ring_size: DEFAULT_RING_SIZE,
            force_copy: false,
            linear_buffers: DEFAULT_LINEAR_BUFFERS,
        }
    }
}

impl XskConfig {
    /// Size the UMEM for `sockets` sockets, leaving the rest as it is.
    #[must_use]
    pub fn for_sockets(mut self, sockets: u32) -> Self {
        self.frames = DEFAULT_FRAMES_PER_SOCKET.saturating_mul(sockets.max(1));
        self
    }

    fn umem_config(self) -> Result<UmemConfig, XskError> {
        UmemConfigBuilder::new()
            .frame_size(
                u32::from(FRAME_SIZE)
                    .try_into()
                    .map_err(|e| XskError::Config(format!("frame size: {e:?}")))?,
            )
            .fill_queue_size(
                self.fill_ring_size
                    .try_into()
                    .map_err(|e| XskError::Config(format!("fill ring size: {e:?}")))?,
            )
            .comp_queue_size(
                self.completion_ring_size
                    .try_into()
                    .map_err(|e| XskError::Config(format!("completion ring size: {e:?}")))?,
            )
            // Our buffers prepend into the kernel's own headroom, which is
            // free once a frame reaches userspace, so we ask for none of our
            // own on top of it.
            .frame_headroom(0)
            .build()
            .map_err(|e| XskError::Config(format!("UMEM: {e}")))
    }

    fn socket_config(self, zero_copy: bool) -> Result<SocketConfig, XskError> {
        let mut builder = SocketConfigBuilder::new();
        builder
            .rx_queue_size(
                self.rx_ring_size
                    .try_into()
                    .map_err(|e| XskError::Config(format!("RX ring size: {e:?}")))?,
            )
            .tx_queue_size(
                self.tx_ring_size
                    .try_into()
                    .map_err(|e| XskError::Config(format!("TX ring size: {e:?}")))?,
            )
            .bind_flags(
                if zero_copy {
                    BindFlags::XDP_ZEROCOPY
                } else {
                    BindFlags::XDP_COPY
                } | BindFlags::XDP_USE_NEED_WAKEUP
                    // Without this the kernel drops anything that does not fit
                    // in one frame rather than splitting it across several,
                    // which is every packet above ~3.8KB.
                    | BindFlags::XDP_USE_SG,
            );

        // We bring our own program, so libxdp must not load one of its own.
        builder.libxdp_flags(LibxdpFlags::XSK_LIBXDP_FLAGS_INHIBIT_PROG_LOAD);

        Ok(builder.build())
    }
}

/// The UMEM a worker's sockets share, and the pool of frames within it.
///
/// Frames are named by their index, which is their offset in the region
/// divided by [`FRAME_SIZE`]. A frame is on exactly one of: the free list, a
/// fill ring, an RX ring, a TX ring, a completion ring, or an [`XdpBuffer`]
/// somewhere in the pipeline.
pub struct XskUmem {
    /// The xsk-rs UMEM. Keeps the mapping alive and owns the frame layout.
    umem: Umem,
    /// The same mapping, addressed by offset, for [`XdpBuffer`] to read.
    region: Arc<UmemRegion>,
    /// One descriptor per frame, indexed by frame index.
    descs: Vec<FrameDesc>,
    /// Frames not currently owned by a ring or a buffer.
    free: VecDeque<usize>,
    /// Handed to each buffer so it can return its frame when dropped.
    returned_tx: Sender<usize>,
    /// The frames buffers have handed back, not yet on the free list.
    returned_rx: Receiver<usize>,
    /// Buffers for packets that span more than one frame.
    linear: Vec<Box<[u8]>>,
    /// Handed to each such buffer so it comes back when dropped.
    linear_tx: Sender<Box<[u8]>>,
    /// The ones handed back, not yet on the free list.
    linear_rx: Receiver<Box<[u8]>>,
    /// Geometry and bind options for the sockets created from this UMEM.
    config: XskConfig,
}

impl XskUmem {
    /// Map a UMEM and carve it into frames, all of them free.
    ///
    /// # Errors
    ///
    /// Returns [`XskError::Config`] if the geometry is not one libxdp accepts,
    /// or [`XskError::Umem`] if the mapping or registration fails.
    pub fn new(config: XskConfig) -> Result<Self, XskError> {
        let umem_config = config.umem_config()?;
        let frames = NonZeroU32::new(config.frames)
            .ok_or_else(|| XskError::Config("a UMEM needs at least one frame".to_owned()))?;

        let (umem, descs) =
            Umem::new(umem_config, frames, false).map_err(|e| XskError::Umem(with_causes(&e)))?;

        let first = descs
            .first()
            .ok_or_else(|| XskError::Umem("UMEM has no frames".to_owned()))?;

        // xsk-rs hands out descriptors, not the base of the mapping, but
        // XdpBuffer works in offsets. The data of the first frame sits exactly
        // `addr` bytes into the mapping, so subtracting gets us back to the
        // start of it.
        let region = {
            let addr = first.addr();
            // SAFETY: `first` belongs to `umem`, and no frame has been given
            // to a ring yet, so nothing else is looking at it.
            let data = unsafe { umem.data(first) };
            let base = data.contents().as_ptr().cast_mut();
            // SAFETY: `base` points `addr` bytes into the mapping, so the
            // subtraction lands on its first byte.
            let base = unsafe { base.sub(addr) };
            let base = NonNull::new(base)
                .ok_or_else(|| XskError::Umem("UMEM starts at a null address".to_owned()))?;
            let len =
                usize::try_from(config.frames).unwrap_or(usize::MAX) * usize::from(FRAME_SIZE);
            // SAFETY: the mapping is `len` bytes and is kept alive by `umem`,
            // which this `XskUmem` owns for as long as the region.
            Arc::new(unsafe { UmemRegion::new(base, len) })
        };

        let (returned_tx, returned_rx) = channel();
        let (linear_tx, linear_rx) = channel();
        let linear = (0..config.linear_buffers)
            .map(|_| vec![0u8; LINEAR_SIZE as usize].into_boxed_slice())
            .collect();

        debug!(
            "UMEM mapped: {} frames of {FRAME_SIZE} bytes ({} MiB)",
            descs.len(),
            (descs.len() * usize::from(FRAME_SIZE)) >> 20,
        );

        Ok(Self {
            umem,
            region,
            free: (0..descs.len()).collect(),
            descs,
            returned_tx,
            returned_rx,
            linear,
            linear_tx,
            linear_rx,
            config,
        })
    }

    /// Bind a socket to `if_name`, queue `queue_id`, fill its RX ring, and
    /// tell `redirect` where the packets of that queue should go.
    ///
    /// The two belong together: a socket bound without telling the redirect
    /// about it is a socket that receives nothing.
    ///
    /// Zero-copy is tried first unless [`XskConfig::force_copy`] is set. A
    /// driver that cannot do zero-copy fails the bind, and we fall back to
    /// copy mode rather than refusing to run.
    ///
    /// # Errors
    ///
    /// Returns [`XskError::Bind`] if neither mode binds, or an I/O error if
    /// the socket cannot be registered with the redirect.
    pub fn bind(
        &mut self,
        if_name: &str,
        queue_id: u32,
        redirect: &Redirect,
    ) -> Result<XskSocket, XskError> {
        let interface: Interface = if_name.parse().map_err(|e| XskError::Bind {
            if_name: if_name.to_owned(),
            queue_id,
            reason: format!("invalid interface name: {e}"),
        })?;

        let bind = |zero_copy: bool| {
            let config = self.config.socket_config(zero_copy)?;
            // SAFETY: every socket we create is bound to a distinct
            // (interface, queue) pair of this UMEM, which is the case libxdp
            // hands fresh fill and completion queues back for.
            unsafe { Socket::new(config, &self.umem, &interface, queue_id) }.map_err(|e| {
                XskError::Bind {
                    if_name: if_name.to_owned(),
                    queue_id,
                    reason: with_causes(&e),
                }
            })
        };

        let (zero_copy, (tx, rx, queues)) = if self.config.force_copy {
            (false, bind(false)?)
        } else {
            match bind(true) {
                Ok(socket) => (true, socket),
                Err(e) => {
                    info!("Zero-copy bind failed ({e}); falling back to copy mode");
                    (false, bind(false)?)
                }
            }
        };

        let (fq, cq) = queues.ok_or_else(|| XskError::Bind {
            if_name: if_name.to_owned(),
            queue_id,
            reason: "libxdp returned no fill and completion queues, which means \
                     the pair is already bound from this UMEM"
                .to_owned(),
        })?;

        info!(
            "AF_XDP socket bound to {if_name}:q{queue_id} in {} mode",
            if zero_copy { "zero-copy" } else { "copy" },
        );

        let mut socket = XskSocket {
            if_name: if_name.to_owned(),
            queue_id,
            fq,
            cq,
            rx,
            tx,
            rx_descs: vec![FrameDesc::default(); BATCH_SIZE],
            cq_descs: vec![FrameDesc::default(); BATCH_SIZE],
            fill_descs: Vec::with_capacity(BATCH_SIZE),
            tx_descs: Vec::with_capacity(MAX_FRAGMENTS),
            rx_packet: Vec::with_capacity(MAX_FRAGMENTS),
            tx_queued: false,
        };

        // Give the kernel somewhere to put the packets it receives; without
        // this the socket is bound but deaf. Never more than half of what is
        // free, though: the frames left over are what packets are transmitted
        // from and what the pipeline holds, and a socket that took the lot
        // would leave the ones bound after it, and every send, with nothing.
        let to_post = (self.config.fill_ring_size as usize).min(self.free.len() / 2);
        let posted = socket.replenish(self, to_post);
        if posted == 0 {
            warn!("No frames left to fill the RX ring of {if_name}:q{queue_id}");
        }

        // Last, because a socket has to be bound before the redirect will take
        // it, and first in the sense that matters: until this happens the
        // socket is bound and deaf, and the packets go to the kernel instead.
        redirect.register(if_name, queue_id, &socket)?;

        Ok(socket)
    }

    /// Move the frames of dropped buffers back to the free list.
    ///
    /// Returns how many frames came back.
    pub fn reclaim_dropped(&mut self) -> usize {
        let mut reclaimed = 0;
        while let Ok(frame_addr) = self.returned_rx.try_recv() {
            self.release(frame_addr);
            reclaimed += 1;
        }
        while let Ok(buffer) = self.linear_rx.try_recv() {
            self.linear.push(buffer);
            reclaimed += 1;
        }
        reclaimed
    }

    /// Number of frames in the UMEM.
    #[must_use]
    pub fn total_frames(&self) -> usize {
        self.descs.len()
    }

    /// Put the frame starting at `frame_addr` back on the free list.
    fn release(&mut self, frame_addr: usize) {
        let index = frame_addr / usize::from(FRAME_SIZE);
        if index < self.descs.len() {
            self.free.push_back(index);
        } else {
            // Only reachable if a descriptor came back with an address outside
            // the UMEM, which would mean the ring is corrupt. Losing the frame
            // is better than handing out one that is not ours.
            warn!("Discarding a frame at {frame_addr}, which is outside the UMEM");
        }
    }

    /// Take a frame off the free list, if there is one.
    fn claim(&mut self) -> Option<usize> {
        self.free.pop_front()
    }

    /// Wrap the frame the RX ring just handed us in a buffer.
    #[allow(clippy::cast_possible_truncation)] // a frame holds well under 64KiB
    fn buffer(&self, desc: &FrameDesc) -> XdpBuffer {
        let frame_addr = frame_start(desc.addr());
        let data_offset = (desc.addr() - frame_addr) as u16;
        let data_len = desc.lengths().data() as u16;
        // SAFETY: the frame was just consumed from the RX ring, so the kernel
        // is done with it and no other buffer refers to it. Its address and
        // length come from the descriptor the kernel filled in.
        unsafe {
            XdpBuffer::frame(
                self.region.clone(),
                frame_addr,
                data_offset,
                data_len,
                FRAME_SIZE,
                self.returned_tx.clone(),
            )
        }
    }

    /// Gather a packet that arrived across `descs` into one buffer.
    ///
    /// The pipeline needs the packet as one run of bytes, and the fragments
    /// are in frames that are nowhere near each other, so this is a copy. It
    /// happens only for packets too long for a single frame.
    ///
    /// The frames are handed straight back: unlike the single-frame case, the
    /// buffer that comes out does not hold them.
    ///
    /// Returns `None` if there is no buffer free to gather into, or if the
    /// packet is longer than one can hold, having released the frames either
    /// way.
    fn gather(&mut self, descs: &[FrameDesc]) -> Option<XdpBuffer> {
        let total: usize = descs.iter().map(|desc| desc.lengths().data()).sum();

        let gathered = if total > MAX_PACKET_LEN as usize {
            warn!(
                "Dropping a {total} byte packet, which is longer than the {MAX_PACKET_LEN} \
                 bytes a buffer holds"
            );
            None
        } else if let Some(storage) = self.linear.pop() {
            #[allow(clippy::cast_possible_truncation)] // checked against MAX_PACKET_LEN above
            let mut buffer =
                XdpBuffer::linear(storage, DATA_OFFSET, total as u16, self.linear_tx.clone());
            let start = DATA_OFFSET as usize;
            let storage = buffer.storage_mut();
            let mut at = start;
            for desc in descs {
                let len = desc.lengths().data();
                // SAFETY: the frame was just consumed from the RX ring, so it
                // is ours and holds `len` bytes at `desc.addr()`.
                let fragment =
                    unsafe { std::slice::from_raw_parts(self.region.ptr_at(desc.addr()), len) };
                storage[at..at + len].copy_from_slice(fragment);
                at += len;
            }
            trace!("Gathered a {total} byte packet from {} frames", descs.len());
            Some(buffer)
        } else {
            warn!("Dropping a {total} byte packet: no buffer free to gather it into");
            None
        };

        // The fragments are copied out either way, so the frames go back
        // whether or not a packet came of them.
        for desc in descs {
            self.release(frame_start(desc.addr()));
        }
        gathered
    }

    /// Copy `data` into as many free frames as it needs, and return their
    /// descriptors in the order they must be put on the TX ring.
    ///
    /// A packet that arrived in a frame of this same UMEM is copied into
    /// another one, which the shared UMEM ought to make unnecessary. Sending
    /// the frame where it lies would mean handing the ring a descriptor for
    /// the packet's own address and length, and xsk-rs keeps `FrameDesc`'s
    /// address private and its constructor crate-internal; the only way to
    /// give a descriptor a length is to write through a cursor at the frame's
    /// fixed data offset, which is this copy. Avoiding it needs a change
    /// upstream, or dropping to libxdp-sys.
    ///
    /// A packet that fits in one frame takes one, which is the common case.
    /// One that does not is split, and every descriptor but the last is marked
    /// as having more to come, which is how the kernel is told they are one
    /// packet.
    ///
    /// The frames are handed back on failure, so a caller that gets an error
    /// has leaked nothing.
    fn stage(&mut self, data: &[u8], staged: &mut Vec<FrameDesc>) -> Result<(), XskError> {
        if data.len() > MAX_PACKET_LEN as usize {
            return Err(XskError::PacketTooLong { len: data.len() });
        }

        staged.clear();
        let mut rest = data;
        while !rest.is_empty() {
            let Some(index) = self.claim() else {
                self.unstage(staged);
                return Err(XskError::NoFreeFrames);
            };
            let take = rest.len().min(MAX_FRAME_PACKET_LEN as usize);
            let (fragment, remainder) = rest.split_at(take);
            rest = remainder;

            // SAFETY: the frame was just taken off the free list, so neither
            // the kernel nor a buffer is looking at it.
            let written = {
                let desc = &mut self.descs[index];
                let mut data_mut = unsafe { self.umem.data_mut(desc) };
                let mut cursor = data_mut.cursor();
                // The frame may have carried a longer packet before; writing
                // starts where the cursor is, and the descriptor's length is
                // where it ends.
                cursor.set_pos(0);
                cursor.write_all(fragment)
            };
            if let Err(e) = written {
                self.free.push_back(index);
                self.unstage(staged);
                return Err(XskError::Io(e));
            }

            let mut desc = self.descs[index];
            // Every fragment but the last says there is more to come. The last
            // one is fixed up below, once we know it is the last.
            desc.set_options(XDP_PKT_CONTD);
            staged.push(desc);
        }

        if let Some(last) = staged.last_mut() {
            last.set_options(0);
        }
        Ok(())
    }

    /// Hand staged frames back, for a packet that will not be sent after all.
    fn unstage(&mut self, staged: &mut Vec<FrameDesc>) {
        for desc in staged.drain(..) {
            self.release(frame_start(desc.addr()));
        }
    }
}

/// One `AF_XDP` socket, bound to an (interface, queue) pair./// One `AF_XDP` socket, bound to an (interface, queue) pair.
///
/// The socket borrows the [`XskUmem`] it was bound to for every operation that
/// moves frames, which is what keeps a single free list behind sockets that
/// each have their own rings.
pub struct XskSocket {
    /// Interface this socket is bound to.
    if_name: String,
    /// RX queue this socket is bound to.
    queue_id: u32,
    /// Free frames go here for the kernel to receive into.
    fq: FillQueue,
    /// Sent frames come back here.
    cq: CompQueue,
    /// Received frames come out here.
    rx: RxQueue,
    /// Frames to send go here.
    tx: TxQueue,
    /// Scratch for [`RxQueue::consume`].
    rx_descs: Vec<FrameDesc>,
    /// Scratch for [`CompQueue::consume`].
    cq_descs: Vec<FrameDesc>,
    /// Scratch for [`FillQueue::produce`].
    fill_descs: Vec<FrameDesc>,
    /// Scratch for the descriptors of one packet being sent.
    tx_descs: Vec<FrameDesc>,
    /// Scratch for the descriptors of one packet being received.
    rx_packet: Vec<FrameDesc>,
    /// Whether anything has been put on the TX ring since the last flush.
    tx_queued: bool,
}

impl XskSocket {
    /// Interface this socket is bound to.
    #[must_use]
    pub fn if_name(&self) -> &str {
        &self.if_name
    }

    /// Take up to [`BATCH_SIZE`] received packets off the RX ring, appending
    /// them to `packets`. Returns how many were appended.
    pub fn recv(&mut self, umem: &mut XskUmem, packets: &mut Vec<XdpBuffer>) -> usize {
        // SAFETY: the scratch descriptors belong to no ring; the RX ring
        // overwrites them with the frames it has for us.
        let received = unsafe { self.rx.consume(&mut self.rx_descs) };
        if received == 0 {
            return 0;
        }

        trace!(
            "{}:q{}: {received} frames off the RX ring",
            self.if_name, self.queue_id
        );

        let before = packets.len();
        for desc in &self.rx_descs[..received] {
            let continues = desc.has_more_frames();

            // The common case: a packet that fits one frame, kept where the
            // kernel put it.
            if !continues && self.rx_packet.is_empty() {
                packets.push(umem.buffer(desc));
                continue;
            }

            self.rx_packet.push(*desc);
            if continues && self.rx_packet.len() < MAX_FRAGMENTS {
                continue;
            }

            if continues {
                // More fragments than a packet we can hold has. Give up on it
                // rather than growing without bound on a ring that is telling
                // us something impossible.
                warn!(
                    "{}:q{}: dropping a packet that spans more than {MAX_FRAGMENTS} frames",
                    self.if_name, self.queue_id
                );
                for desc in &self.rx_packet {
                    umem.release(frame_start(desc.addr()));
                }
            } else if let Some(packet) = umem.gather(&self.rx_packet) {
                packets.push(packet);
            }
            self.rx_packet.clear();
        }

        // A packet whose last fragment has not arrived yet stays in
        // `rx_packet` and is finished on the next pass.
        packets.len() - before
    }

    /// Copy `data` into a free frame and put it on the TX ring.
    ///
    /// The kernel is not woken here: call [`flush_tx`](Self::flush_tx) once a
    /// batch has been queued.
    ///
    /// # Errors
    ///
    /// Returns [`XskError::NoFreeFrames`] if the UMEM is exhausted,
    /// [`XskError::PacketTooLong`] if the packet does not fit a frame, or
    /// [`XskError::TxRingFull`] if the kernel has not kept up.
    pub fn send(&mut self, umem: &mut XskUmem, data: &[u8]) -> Result<(), XskError> {
        umem.stage(data, &mut self.tx_descs)?;

        // The fragments of one packet have to be next to each other on the
        // ring, which is what producing them in one go gets us: the ring
        // either takes them all or takes none.
        // SAFETY: every frame is off the free list and holds part of the
        // packet we just wrote, so none is on another ring.
        let queued = unsafe { self.tx.produce(&self.tx_descs) };
        if queued != self.tx_descs.len() {
            umem.unstage(&mut self.tx_descs);
            return Err(XskError::TxRingFull);
        }

        self.tx_descs.clear();
        self.tx_queued = true;
        trace!(
            "{}:q{}: queued {} bytes for transmission in {queued} frame(s)",
            self.if_name,
            self.queue_id,
            data.len()
        );
        Ok(())
    }

    /// Wake the kernel if it is asleep and we have queued something for it.
    ///
    /// # Errors
    ///
    /// Returns the error the wakeup syscall reported.
    pub fn flush_tx(&mut self) -> std::io::Result<()> {
        if !self.tx_queued {
            return Ok(());
        }
        self.tx_queued = false;
        if self.tx.needs_wakeup() {
            self.tx.wakeup()?;
        }
        Ok(())
    }

    /// Reclaim the frames the kernel is done sending and top the fill ring
    /// back up. Call once per pass of the worker loop.
    pub fn service(&mut self, umem: &mut XskUmem) {
        self.collect_completions(umem);
        self.replenish(umem, BATCH_SIZE);
    }

    /// Statistics the kernel keeps for this socket, including the packets it
    /// had to drop for want of a frame on the fill ring.
    ///
    /// # Errors
    ///
    /// Returns the error `getsockopt(2)` reported.
    pub fn statistics(&self) -> std::io::Result<XdpStatistics> {
        self.rx.fd().xdp_statistics()
    }

    /// Move frames the kernel has finished transmitting back to the free list.
    fn collect_completions(&mut self, umem: &mut XskUmem) {
        // SAFETY: the scratch descriptors belong to no ring; the completion
        // ring overwrites them with the frames it is handing back.
        let completed = unsafe { self.cq.consume(&mut self.cq_descs) };
        if completed == 0 {
            return;
        }

        trace!(
            "{}:q{}: {completed} frames off the completion ring",
            self.if_name, self.queue_id
        );
        for desc in &self.cq_descs[..completed] {
            umem.release(frame_start(desc.addr()));
        }
    }

    /// Post up to `count` free frames on the fill ring. Returns how many the
    /// ring took.
    fn replenish(&mut self, umem: &mut XskUmem, count: usize) -> usize {
        // The ring takes all of what it is offered or none of it, so offering
        // more than it has room for would pop frames off the free list only to
        // push every one of them straight back.
        let count = count.min(self.fq.nb_free_exact() as usize);

        self.fill_descs.clear();
        for _ in 0..count {
            let Some(index) = umem.claim() else { break };
            match umem.descs.get(index) {
                Some(desc) => self.fill_descs.push(*desc),
                None => break,
            }
        }
        if self.fill_descs.is_empty() {
            return 0;
        }

        // SAFETY: every frame here came off the free list, so it is on no
        // other ring and no buffer refers to it. They all belong to `umem`,
        // which is the UMEM this socket was bound to.
        let posted = unsafe {
            self.fq
                .produce_and_wakeup(&self.fill_descs, self.rx.fd_mut(), 0)
        }
        .unwrap_or_else(|e| {
            // The frames were still handed over; only the wakeup failed, and
            // the next poll will find them.
            debug!(
                "{}:q{}: could not wake the kernel after filling: {e}",
                self.if_name, self.queue_id
            );
            self.fill_descs.len()
        });

        // A full ring takes nothing at all rather than a prefix, but handle
        // the general case: whatever it refused stays free.
        for desc in &self.fill_descs[posted..] {
            umem.release(frame_start(desc.addr()));
        }

        if posted > 0 {
            trace!(
                "{}:q{}: {posted} frames onto the fill ring",
                self.if_name, self.queue_id
            );
        }
        posted
    }
}

impl AsRawFd for XskSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.rx.fd().as_raw_fd()
    }
}

/// Wait until any of `sockets` has packets, or `timeout_ms` elapses.
///
/// `ready` is filled with one flag per socket, in the order they were given,
/// saying which of them the kernel has something for. Returns whether any of
/// them does.
///
/// # Errors
///
/// Returns the error `poll(2)` reported, except that an interrupted call is
/// reported as nothing being ready: the caller is expected to come round
/// again, and it may want to look at why it was interrupted first.
pub fn wait_for_packets<'a>(
    sockets: impl IntoIterator<Item = &'a XskSocket>,
    timeout_ms: u16,
    ready: &mut Vec<bool>,
) -> std::io::Result<bool> {
    let mut fds: Vec<PollFd> = sockets
        .into_iter()
        .map(|socket| {
            // SAFETY: the socket owns the descriptor and outlives the borrow,
            // which does not leave this function.
            let fd = unsafe { BorrowedFd::borrow_raw(socket.as_raw_fd()) };
            PollFd::new(fd, PollFlags::POLLIN)
        })
        .collect();

    let woken = match poll(&mut fds, PollTimeout::from(timeout_ms)) {
        Ok(woken) => woken,
        Err(nix::errno::Errno::EINTR) => 0,
        Err(e) => return Err(e.into()),
    };

    ready.clear();
    ready.extend(fds.iter().map(|fd| {
        fd.revents()
            .is_some_and(|events| events.contains(PollFlags::POLLIN))
    }));
    Ok(woken > 0)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod test {
    use super::{frame_start, with_causes};
    use crate::umem::{DATA_OFFSET, FRAME_SIZE};

    /// Whatever the kernel puts in a descriptor, we have to be able to say
    /// which frame it names, including when the packet does not start where
    /// the UMEM put it.
    #[test]
    fn every_address_in_a_frame_names_that_frame() {
        let frame = 7 * usize::from(FRAME_SIZE);

        assert_eq!(frame_start(frame), frame);
        assert_eq!(frame_start(frame + usize::from(DATA_OFFSET)), frame);
        assert_eq!(frame_start(frame + usize::from(FRAME_SIZE) - 1), frame);
        // One past the end is the next frame, not this one.
        assert_eq!(
            frame_start(frame + usize::from(FRAME_SIZE)),
            frame + usize::from(FRAME_SIZE)
        );
    }

    /// libxdp keeps the errno in the source of its errors, and that is the
    /// part an operator needs, so it has to reach the log.
    #[test]
    fn the_cause_of_an_error_is_reported_with_it() {
        #[derive(Debug, thiserror::Error)]
        #[error("could not bind")]
        struct Outer(#[source] std::io::Error);

        let error = Outer(std::io::Error::from_raw_os_error(1));
        let reported = with_causes(&error);

        assert!(reported.starts_with("could not bind: "), "{reported}");
        assert!(reported.contains("Operation not permitted"), "{reported}");
    }
}
