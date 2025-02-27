// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Packet struct and methods

use crate::buffer::{Headroom, PacketBufferMut, Prepend, TrimFromStart};
use crate::eth::EthError;
use crate::headers::{
    AbstractHeaders, AbstractHeadersMut, Headers, TryHeaders, TryHeadersMut, TryIp, TryUdp,
    TryVxlan,
};
use crate::parse::{DeParse, DeParseError, Parse, ParseError};
use crate::vxlan::Vxlan;
use core::fmt::Debug;
use std::cmp::Ordering;
use std::num::NonZero;

/// A parsed (see [`Parse`]) ethernet packet.
#[derive(Debug)]
pub struct Packet<Buf: PacketBufferMut> {
    headers: Headers,
    /// The total number of bytes _originally_ consumed when parsing this packet
    /// Mutations to `packet` can cause the re-serialized size of the packet to grow or shrink.
    consumed: NonZero<u16>,
    mbuf: Buf, // TODO: find a way to make this private
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
    pub fn new(mbuf: Buf) -> Result<Packet<Buf>, InvalidPacket<Buf>> {
        let (headers, consumed) = match Headers::parse(mbuf.as_ref()) {
            Ok((headers, consumed)) => (headers, consumed),
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

    /// If the [`Packet`] is [`Vxlan`], then this method
    ///
    /// 1. strips the outer headers
    /// 2. parses the inner headers
    /// 3. adjusts the [`Buf`] to start at the beginning of the inner frame.
    /// 3. mutates self to use the newly parsed headers
    /// 4. returns the (now removed) [`Vxlan`] header.
    ///
    /// # Errors
    ///
    /// * returns `None` (and does not modify `self`) if the packet is not [`Vxlan`].
    /// * returns `Some(Err(InvalidPacket<Buf>))` if the inner packet cannot be parsed as a legal
    ///   frame.  In this case, `self` will not be modified.
    ///
    /// # Example
    ///
    /// ```
    /// # use net::buffer::PacketBufferMut;
    /// # use net::headers::TryHeaders;
    /// # use net::packet::Packet;
    /// #
    /// # fn with_received_mbuf<Buf: PacketBufferMut>(buf: Buf) {
    /// #   let mut packet = Packet::new(buf).unwrap();
    /// match packet.vxlan_decap() {
    ///     Some(Ok(vxlan)) => {
    ///         println!("We got a vni with value {vni}", vni = vxlan.vni());
    ///         println!("the inner packet headers are {headers:?}", headers = packet.headers());
    ///     }
    ///     Some(Err(bad)) => {
    ///         eprintln!("oh no, the inner packet is bad: {bad:?}");
    ///     }
    ///     None => {
    ///         eprintln!("sorry friend, this isn't a VXLAN packet")
    ///     }
    /// }
    /// # }
    /// ```
    pub fn vxlan_decap(&mut self) -> Option<Result<Vxlan, ParseError<EthError>>> {
        match self.headers.try_vxlan() {
            None => None,
            Some(vxlan) => {
                let header_size = self.headers.size().get() as usize;
                if self.mbuf.as_ref().len() < header_size {
                    // This can only happen if the parser or `Buf` is broken.
                    // This outcome indicates that we parsed the headers but that the packet is
                    // smaller than this size of the headers we parsed (which is programmer
                    // error and not recoverable).
                    unreachable!("logic error: packet smaller than parsed headers");
                }
                match Headers::parse(&self.mbuf.as_ref()[header_size..]) {
                    Ok((headers, consumed)) => {
                        // Note: we could call `trim_from_start` earlier in this method since that
                        // method returns the slice we need.  This approach results in less complex
                        // looking code, but we need to preserve the outer packet even if the inner
                        // packet is invalid.
                        // Advancing the start location violates that goal, so we can't get away
                        // with it.
                        #[allow(clippy::cast_possible_truncation)] // u16 to start with
                        match self.mbuf.trim_from_start(header_size as u16) {
                            Ok(_) => {
                                let vxlan = *vxlan;
                                self.consumed = consumed;
                                self.headers = headers;
                                Some(Ok(vxlan))
                            }
                            Err(programmer_err) => {
                                // This most likely indicates a broken implementation of
                                // `PacketBufferMut`
                                unreachable!("{programmer_err:?}", programmer_err = programmer_err);
                            }
                        }
                    }
                    Err(error) => Some(Err(error)),
                }
            }
        }
    }

    /// Encapsulate the packet in the supplied [`Headers`].
    ///
    /// If successful, this method will replace the current [`Packet`]'s [`Headers`] with the
    /// supplied headers.
    ///
    /// # Errors
    ///
    /// Returns an [`Err`] variant if the buffer is unable to [`prepend`] the supplied [`Headers`].
    ///
    /// # Safety
    ///
    /// This method does not confirm that the supplied [`Headers`] are a logical form of
    /// encapsulation.
    /// It is the caller's responsibility to ensure they are constructing the desired [`Packet`].
    ///
    /// This method is principally intended as a building block for other types of (checked)
    /// encapsulation logic.
    /// It is made public to allow other crates to "bring their own encap / decap"
    ///
    /// [`prepend`]: Prepend::prepend
    #[allow(unsafe_code)] // safety requirements documented
    pub unsafe fn encap(&mut self, headers: Headers) -> Result<(), <Buf as Prepend>::Error> {
        self.mbuf.prepend(headers.size().get())?;
        self.consumed = headers.size();
        self.headers = headers;
        Ok(())
    }

    /// Encapsulate the packet in the supplied [`Vxlan`] [`Headers`]
    ///
    /// The supplied [`Headers`] will be validated to ensure they form a VXLAN header.
    ///
    /// # Errors
    ///
    /// If the supplied [`Headers`] have no
    ///
    /// * IP layer, then this method will return an [`VxlanEncapError::NoIp`] `Err`
    /// * UDP layer, then this method will return an [`VxlanEncapError::NoUdp`] `Err`
    /// * Vxlan layer, then this method will return an [`VxlanEncapError::NoVxlan`] `Err`
    ///
    /// If the buffer is unable to prepend the supplied [`Headers`], this method will return a
    /// [`VxlanEncapError::PrependFailed`] `Err`.
    #[allow(clippy::result_large_err)] // no reason to eat the headers
    pub fn encap_vxlan(&mut self, headers: Headers) -> Result<(), VxlanEncapError<Buf>> {
        match (headers.try_ip(), headers.try_udp(), headers.try_vxlan()) {
            (None, _, _) => Err(VxlanEncapError::<Buf>::NoIp(headers)),
            (_, None, _) => Err(VxlanEncapError::<Buf>::NoUdp(headers)),
            (_, _, None) => Err(VxlanEncapError::<Buf>::NoVxlan(headers)),
            (Some(_), Some(_), Some(_)) => {
                #[allow(unsafe_code)] // sound by exhaustion
                unsafe { self.encap(headers) }.map_err(VxlanEncapError::PrependFailed)
            }
        }
    }

    /// Consume the packet and return it as a `Buf`
    ///
    /// # Panics
    ///
    /// Panics if `Buf` does not have enough headroom to serialize the packet.
    pub fn reserialize(self) -> Buf {
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

impl<Buf: PacketBufferMut> TrimFromStart for Packet<Buf> {
    type Error = <Buf as TrimFromStart>::Error;

    fn trim_from_start(&mut self, len: u16) -> Result<&mut [u8], Self::Error> {
        self.mbuf.trim_from_start(len)
    }
}

impl<Buf: PacketBufferMut> Headroom for Packet<Buf> {
    fn headroom(&self) -> u16 {
        self.mbuf.headroom()
    }
}

/// Errors which may occur when encapsulating a packet with VXLAN headers.
#[derive(Debug, thiserror::Error)]
pub enum VxlanEncapError<Buf: PacketBufferMut> {
    /// supplied headers have no IP layer
    #[error("supplied headers have not IP layer")]
    NoIp(Headers),
    /// supplied headers have no UDP layer
    #[error("supplied headers have no UDP layer")]
    NoUdp(Headers),
    /// supplied headers have no VXLAN layer
    #[error("supplied headers have no VXLAN layer")]
    NoVxlan(Headers),
    /// Unable to prepend the supplied headers to the buffer.
    #[error(transparent)]
    PrependFailed(<Buf as Prepend>::Error),
}

//
// #[cfg(all(any(test, feature = "arbitrary"), feature = "test_buffer"))]
// mod contract {
//     use crate::packet::Packet;
//     use bolero::{Driver, ValueGenerator};
//
//     pub struct VxlanPacketGenerator;
//
//     impl ValueGenerator for VxlanPacketGenerator {
//         type Output = Packet;
//
//         fn generate<D: Driver>(&self, _driver: &mut D) -> Option<Self::Output> {
//             todo!()
//         }
//     }
// }
