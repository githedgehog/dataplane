// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Packet struct and methods

mod display;
mod hash;
mod meta;

#[cfg(any(doc, test, feature = "test_buffer"))]
pub mod test_utils;

use crate::buffer::{Headroom, PacketBufferMut, Prepend, Tailroom, TrimFromStart};
use crate::eth::EthError;
use crate::headers::{AbstractHeaders, AbstractHeadersMut, Headers, TryHeaders, TryHeadersMut};
use crate::parse::{DeParse, Parse, ParseError};

#[allow(unused_imports)] // re-export
pub use hash::*;
#[allow(unused_imports)] // re-export
pub use meta::*;
use std::num::NonZero;

mod utils;

/// A parsed (see [`Parse`]) ethernet packet.
#[derive(Debug)]
pub struct Packet<Buf: PacketBufferMut> {
    headers: Headers,
    payload: Buf,
    /// packet metadata added by stages to drive other stages down the pipeline
    pub meta: PacketMeta,
}

/// Errors which may occur when failing to produce a [`Packet`]
#[derive(Debug, thiserror::Error)]
pub struct InvalidPacket<Buf: PacketBufferMut> {
    #[allow(unused)]
    mbuf: Buf,
    #[source]
    error: ParseError<EthError>,
}

impl<Buf: PacketBufferMut> Packet<Buf> {
    /// Map a `PacketBufferMut` to a `Packet` if the buffer contains a valid ethernet packet.
    ///
    /// # Errors
    ///
    /// Returns an [`InvalidPacket`] error the buffer does not parse as an ethernet frame.
    pub fn new(mut mbuf: Buf) -> Result<Packet<Buf>, InvalidPacket<Buf>> {
        let (headers, consumed) = match Headers::parse(mbuf.as_ref()) {
            Ok((headers, consumed)) => (headers, consumed),
            Err(error) => {
                return Err(InvalidPacket { mbuf, error });
            }
        };
        mbuf.trim_from_start(consumed.get())
            .unwrap_or_else(|_| unreachable!());
        Ok(Packet {
            headers,
            payload: mbuf,
            meta: PacketMeta::default(),
        })
    }

    /// Get a reference to the payload of this packet
    pub fn payload(&self) -> &Buf {
        &self.payload
    }

    /// Get the length of the packet's payload
    ///
    /// # Note
    ///
    /// Manipulating the parsed headers _does not_ change the length returned by this method.
    #[allow(clippy::cast_possible_truncation)] // checked in ctor
    #[must_use]
    pub fn payload_len(&self) -> u16 {
        self.payload.as_ref().len() as u16
    }

    /// Get the length of the packet's current headers.
    ///
    /// # Note
    ///
    /// Manipulating the parsed headers _does_ change the length returned by this method.
    pub fn header_len(&self) -> NonZero<u16> {
        self.headers.size()
    }

    /// Update the packet's buffer based on any changes to the packets [`Headers`].
    ///
    /// # Errors
    ///
    /// Returns a [`Prepend::Error`] error if the packet does not have enough headroom to
    /// serialize.
    pub fn serialize(mut self) -> Result<Buf, <Buf as Prepend>::Error> {
        let needed = self.headers.size().get();
        let buf = self.payload.prepend(needed)?;
        self.headers
            .deparse(buf)
            .unwrap_or_else(|e| unreachable!("{e:?}", e = e));
        Ok(self.payload)
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

impl<Buf: PacketBufferMut> TrimFromStart for Packet<Buf> {
    type Error = <Buf as TrimFromStart>::Error;

    fn trim_from_start(&mut self, len: u16) -> Result<&mut [u8], Self::Error> {
        self.payload.trim_from_start(len)
    }
}

impl<Buf: PacketBufferMut> Headroom for Packet<Buf> {
    fn headroom(&self) -> u16 {
        self.payload.headroom()
    }
}

impl<Buf: PacketBufferMut> Tailroom for Packet<Buf> {
    fn tailroom(&self) -> u16 {
        self.payload().tailroom()
    }
}

#[allow(dead_code)]
impl<Buf: PacketBufferMut> Packet<Buf> {
    /// Explicitly mark a packet as done, indicating the reason. Broadly, there are 2 types of reasons
    ///  - The packet is to be dropped due to the indicated reason.
    ///  - The packet has been processed and is marked as done to prevent later stages from processing it.
    pub fn done(&mut self, reason: DoneReason) {
        if self.meta.done.is_none() {
            self.meta.done = Some(reason);
        }
    }

    /// This behaves like the `done()` method but overwrites the reason or verdict. This is useful when a stage is
    /// allowed, by design, to override the decisions taken by prior stages. For instance, a forwarding stage
    /// may determine that the processing of a packet is completed and mark a packet as done in order to skip
    /// other stages in the pipeline (like another forwarding stage). A subsequent firewalling stage should be
    /// allowed to: 1) ignore the prior reason 2) override it (e.g., to drop the packet).
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

    /// Get a reference to the headers of this `Packet`
    pub fn get_headers(&self) -> &Headers {
        &self.headers
    }

    /// Get an immutable reference to the metadata of this `Packet`
    pub fn get_meta(&self) -> &PacketMeta {
        &self.meta
    }

    /// Get a mutable reference to the metadata of this `Packet`
    pub fn get_meta_mut(&mut self) -> &mut PacketMeta {
        &mut self.meta
    }
}
