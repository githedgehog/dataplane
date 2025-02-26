// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use net::buffer::PacketBufferMut;
use net::eth::EthError;
use net::headers::{AbstractHeaders, AbstractHeadersMut, Headers, TryHeaders, TryHeadersMut};
use net::parse::{DeParse, DeParseError, Parse, ParseError};
use std::cmp::Ordering;
use std::num::NonZero;

#[derive(Debug)]
pub struct Packet<Buf: PacketBufferMut> {
    headers: Headers,
    /// The total number of bytes _originally_ consumed when parsing this packet
    /// Mutations to `packet` can cause the re-serialized size of the packet to grow or shrink.
    consumed: NonZero<u16>,
    pub mbuf: Buf, // TODO: find a way to make this private
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
            mbuf,
        })
    }

    pub(crate) fn reserialize(self) -> Buf {
        // TODO: prove that these unreachable statements are optimized out
        // The `unreachable` statements in the first block should be easily optimized out, but best
        // to confirm.
        let needed = self.headers.size();
        let mut mbuf = self.mbuf;
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
