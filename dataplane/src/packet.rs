// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::packet_meta::{DropReason, PacketMeta};
use net::buffer::PacketBufferMut;
use net::eth::EthError;
use net::headers::{AbstractHeaders, AbstractHeadersMut, Headers, TryHeaders, TryHeadersMut};
use net::parse::{DeParse, DeParseError, Parse, ParseError};
use std::cmp::Ordering;
use std::num::NonZero;
use tracing::error;

#[derive(Debug)]
pub struct Packet<Buf: PacketBufferMut> {
    headers: Headers,
    /// The total number of bytes _originally_ consumed when parsing this packet
    /// Mutations to `packet` can cause the re-serialized size of the packet to grow or shrink.
    consumed: NonZero<u16>,
    mbuf: Option<Buf>,
    // packet metadata added by stages to drive other stages down the pipeline
    pub meta: PacketMeta,
}
#[derive(Debug, thiserror::Error)]
pub struct InvalidPacket<Buf: PacketBufferMut> {
    #[allow(unused)]
    mbuf: Buf,
    #[source]
    error: ParseError<EthError>,
}

impl<Buf: PacketBufferMut> Packet<Buf> {
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

    pub(crate) fn reserialize(mut self) -> Buf {
        // TODO: prove that these unreachable statements are optimized out
        // The `unreachable` statements in the first block should be easily optimized out, but best
        // to confirm.
        let needed = self.headers.size();
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

    #[allow(dead_code)]
    /// Explicitly mark a packet as to be dropped, indicating the reason.
    pub fn pkt_drop(&mut self, reason: DropReason) {
        self.meta.drop = Some(reason);
    }

    #[allow(dead_code)]
    /// Tell if a packet has been marked as 'to drop'.
    pub fn dropped(&self) -> bool {
        self.meta.drop.is_some()
    }

    #[allow(dead_code)]
    /// Wraps a packet in an Option<Packet> depending on the metadata:
    /// If the [`Packet`] is to be dropped, returns `None`.
    /// Else, `Some(packet)`.
    ///
    /// This method consumes Self. If the packet was marked as
    /// dropped, this will actually drop it.
    /// The method is intended to use in NFs within closures of `filter_map()`
    /// where internal processing functions need not return anything but signal
    /// the desire to drop a packet by calling method[`pkt_drop()`].
    /// ```
    ///     fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
    ///        &'a mut self,
    ///        input: Input,
    ///     ) -> impl Iterator<Item = Packet<Buf>> + 'a {
    ///        input.filter_map(|mut packet| {
    ///        some_function_that_may_drop_pkt(&mut packet);
    ///        packet.fate()
    ///    })
    ///   }
    /// ```
    /// If a stage would opt not to drop a packet but defer this action, it should
    /// simply replace `packet.fate()` by Some(packet). The packet annotation would
    /// allow  dropping it later on. E.g. a pipeline could have a last stage that
    /// could execute something like:
    /// ```
    ///        input.filter_map(|mut packet| packet.fate() )
    /// ```
    /// .. or a variation to collect statistics.
    pub fn fate(self) -> Option<Self> {
        if self.dropped() {
            #[cfg(test)]
            if self.meta.keep {
                // ignore the request to drop and keep the packet instead.
                return Some(self);
            }
            None
        } else {
            Some(self)
        }
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
        if self.meta.drop.is_none() {
            error!("Dropped packet without specifying reason");
            // This should be a panic!(). Leaving it as just a log
            // until related features adopt this, if adopted.
        }
    }
}
