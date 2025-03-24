// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(missing_docs)] // temporary allowance

//! High-level packet structure

mod display;
mod hash;
mod meta;
#[cfg(any(test, feature = "test_buffer"))]
pub mod test_utils;
pub mod utils;

use crate::buffer::PacketBufferMut;
use crate::eth::EthError;
use crate::headers::{AbstractHeaders, AbstractHeadersMut, Headers, TryHeaders, TryHeadersMut};
use crate::parse::{DeParse, DeParseError, Parse, ParseError};
use std::cmp::Ordering;
use std::num::NonZero;
use tracing::{error, warn};

#[allow(unused_imports)] // re-export
pub use hash::*;
#[allow(unused_imports)] // re-export
pub use meta::*;

#[derive(Debug)]
pub struct Packet<Buf: PacketBufferMut> {
    headers: Headers,
    /// The total number of bytes _originally_ consumed when parsing this packet
    /// Mutations to `packet` can cause the re-serialized size of the packet to grow or shrink.
    consumed: NonZero<u16>,
    mbuf: Option<Buf>,
    // packet metadata added by stages to drive other stages down the pipeline
    meta: PacketMeta,
}
#[derive(Debug, thiserror::Error)]
pub struct InvalidPacket<Buf: PacketBufferMut> {
    #[allow(unused)]
    mbuf: Buf,
    #[source]
    error: ParseError<EthError>,
}

#[allow(dead_code)]
impl<Buf: PacketBufferMut> Packet<Buf> {
    /// Create a new packet from a buffer
    ///
    /// # Errors
    ///
    /// If the supplied buffer fails to parse, this method will return an [`InvalidPacket`] error.
    pub fn new(mbuf: Buf) -> Result<Packet<Buf>, InvalidPacket<Buf>> {
        let (headers, consumed) = match Headers::parse(mbuf.as_ref()) {
            Ok((packet, consumed)) => (packet, consumed),
            Err(error) => {
                return Err(InvalidPacket { mbuf, error });
            }
        };
        Ok(Packet {
            headers,
            consumed,
            meta: PacketMeta::default(),
            mbuf: Some(mbuf),
        })
    }

    /// Take ownership of the memory buffer of a Packet
    pub fn take_buf(&mut self) -> Option<Buf> {
        self.mbuf.take()
    }

    /// Reserialize the packet into a buffer (consuming self).
    ///
    /// # Panics
    ///
    /// This method should never panic baring programmer error.
    pub fn reserialize(mut self) -> Buf {
        // TODO: prove that these unreachable statements are optimized out
        // The `unreachable` statements in the first block should be easily optimized out, but best
        // to confirm.

        // warn if packet has a drop reason != Delivered
        self.get_done().inspect(|reason| {
            if *reason != DoneReason::Delivered {
                warn!("Serializing a packet that should be dropped");
            }
        });

        // set the drop action to delivered, since this is terminal.
        self.done(DoneReason::Delivered);

        let needed = self.headers.size();
        #[allow(clippy::expect_used)] // TODO: this should not be necessary
        let mut mbuf = self.take_buf().expect("Packet without buffer");
        let mut mbuf = match needed.cmp(&self.consumed) {
            Ordering::Equal => mbuf,
            Ordering::Less => {
                let prepend = needed.get() - self.consumed.get();
                match mbuf.prepend(prepend) {
                    Ok(_) => {}
                    Err(e) => unreachable!("configuration error: {:?}", e),
                }
                mbuf
            }
            Ordering::Greater => {
                let trim = self.consumed.get() - needed.get();
                assert!(
                    !trim > self.headers.size().get(),
                    "attempting to trim a nonsensical amount of data: {trim}"
                );
                match mbuf.trim_from_start(trim) {
                    Ok(_) => {}
                    Err(e) => unreachable!("configuration error: {:?}", e),
                }
                mbuf
            }
        };
        // TODO: prove that these unreachable statements are optimized out
        // This may be _very_ hard to do since the compiler may not have perfect
        // visibility here.
        match self.headers.deparse(mbuf.as_mut()) {
            Ok(_) => mbuf,
            Err(DeParseError::Length(fatal)) => unreachable!("{fatal:?}", fatal = fatal),
            Err(DeParseError::Invalid(())) => unreachable!("invalid write operation"),
            Err(DeParseError::BufferTooLong(len)) => {
                unreachable!("buffer too long: {len}", len = len)
            }
        }
    }

    /// Explicitly mark a packet as done, indicating the reason. Broadly, there are 2 types of reasons
    ///  - The packet is to be dropped due to the indicated reason.
    ///  - The packet has been processed and is marked as done to prevent later stages from processing it.
    pub fn done(&mut self, reason: DoneReason) {
        if self.meta.done.is_none() {
            self.meta.done = Some(reason);
        }
    }

    /// This behaves like method `done()` but overwrites the reason or veredict. This is useful when a stage is
    /// allowed, by design, to override the decisions taken by prior stages. For instance, a forwarding stage
    /// may determine that the processing of a packet is completed and mark a packet as done in order to skip
    /// other stages in the pipeline (like another forwarding stage). A subsequent firewalling stage should be
    /// allowed to: 1) ignore the prior reason 2) override it (e.g. to drop the packet).
    pub fn done_force(&mut self, reason: DoneReason) {
        self.meta.done = Some(reason);
    }

    /// Remove the done marking for a packet
    pub fn done_clear(&mut self) {
        self.meta.done.take();
    }

    /// Tell if a packet has been marked as done.
    pub fn is_done(&self) -> bool {
        self.meta.done.is_some()
    }

    /// Get the reason why a packet has been marked as done.
    pub fn get_done(&self) -> Option<DoneReason> {
        self.meta.done
    }

    #[allow(dead_code)]
    /// Wraps a packet in an `Option` depending on the metadata:
    /// If [`Packet`] is to be dropped, returns `None`. Else, `Some`.
    pub fn enforce(self) -> Option<Self> {
        #[cfg(test)]
        if self.meta.keep {
            // ignore the request to drop and keep the packet instead.
            return Some(self);
        }
        match self.get_done() {
            Some(DoneReason::Delivered) | None => Some(self),
            Some(_) => None,
        }
    }

    /// Get a reference to the headers of this `Packet`
    pub fn get_headers(&self) -> &Headers {
        &self.headers
    }

    /// Get a reference to the consumed value of this `Packet`
    pub fn get_consumed(&self) -> NonZero<u16> {
        self.consumed
    }

    /// Get a reference to the buffer of this `Packet`
    pub fn get_buf(&self) -> &Option<Buf> {
        &self.mbuf
    }

    /// Get a an immutable reference to the metadata of this `Packet`
    pub fn get_meta(&self) -> &PacketMeta {
        &self.meta
    }

    /// Get a an mutable reference to the metadata of this `Packet`
    pub fn get_meta_mut(&mut self) -> &mut PacketMeta {
        &mut self.meta
    }
}

impl<Buf: PacketBufferMut> TryHeaders for Packet<Buf> {
    fn headers(&self) -> &impl AbstractHeaders {
        &self.headers
    }
}

impl<Buf: PacketBufferMut> TryHeadersMut for Packet<Buf> {
    fn headers_mut(&mut self) -> &mut impl AbstractHeadersMut {
        &mut self.headers
    }
}

impl<Buf: PacketBufferMut> Drop for Packet<Buf> {
    fn drop(&mut self) {
        if self.meta.done.is_none() {
            error!("Dropped packet without specifying reason");
            // This should be a panic!(). Leaving it as just a log
            // until related features adopt this, if adopted.
        }
    }
}
