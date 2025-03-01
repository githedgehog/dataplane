// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Packet struct and methods

use crate::buffer::{Headroom, PacketBufferMut, Prepend, TrimFromStart};
use crate::eth::EthError;
use crate::headers::{
    AbstractHeaders, AbstractHeadersMut, Headers, TryHeaders, TryHeadersMut, TryUdpMut, TryVxlan,
};
use crate::parse::{DeParse, Parse, ParseError};
use crate::udp::Udp;
use crate::vxlan::Vxlan;
use core::fmt::Debug;
use std::num::NonZero;
use tracing::{debug, error};

/// A parsed (see [`Parse`]) ethernet packet.
#[derive(Debug)]
pub struct Packet<Buf: PacketBufferMut> {
    headers: Headers,
    payload: Buf,
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
        })
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
    ///         println!("We got a vni with value {vni}", vni = vxlan.vni().as_u32());
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
            None => {
                debug!("attempted to remove VXLAN header from non-vxlan packet");
                None
            }
            Some(vxlan) => {
                match Headers::parse(self.payload.as_ref()) {
                    Ok((headers, consumed)) => {
                        match self.payload.trim_from_start(consumed.get()) {
                            Ok(_) => {
                                let vxlan = *vxlan;
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
    ///
    /// # Panics
    ///
    /// This method will panic if the resulting mbuf has a UDP length field longer than 2^16
    /// bytes.
    pub fn vxlan_encap(self, mut headers: Headers) -> Result<Self, <Buf as Prepend>::Error> {
        let mbuf = self.serialize()?;
        let len = mbuf.as_ref().len() + (Udp::MIN_LENGTH.get() + Vxlan::MIN_LENGTH.get()) as usize;
        assert!(
            u16::try_from(len).is_ok(),
            "encap would result in frame larger than 2^16 bytes"
        );
        #[allow(clippy::cast_possible_truncation)] // checked
        let len = NonZero::new(len as u16).unwrap_or_else(|| unreachable!());
        match headers.try_udp_mut() {
            None => {
                todo!()
            }
            #[allow(unsafe_code)] // sound usage due to length check
            Some(udp) => unsafe {
                udp.set_length(len);
            },
        }
        let this = Self {
            headers,
            payload: mbuf,
        };
        Ok(this)
    }

    /// Update the packet's buffer based on any changes to the packets [`Headers`].
    ///
    /// # Errors
    ///
    /// Returns a [`Prepend::Error`] error if the packet does not have enough headroom to
    /// serialize.
    pub fn serialize(mut self) -> Result<Buf, <Buf as Prepend>::Error> {
        // TODO: prove that these unreachable statements are optimized out
        // The `unreachable` statements in the first block should be easily optimized out, but best
        // to confirm.
        let needed = self.headers.size();
        let buf = self.payload.prepend(needed.get())?;
        // TODO: prove that these unreachable statements are optimized out
        // This may be _very_ hard to do since the compiler may not have perfect
        // visibility here.
        self.headers
            .deparse(buf)
            .unwrap_or_else(|e| unreachable!("{e:?}", e = e));
        Ok(self.payload)
    }
}

/// Errors which may occur when re-serializing a packet
#[derive(Debug, thiserror::Error)]
pub enum ReserializeError<Buf: PacketBufferMut> {
    /// The packet does not have enough headroom to append the requested amount of data.
    #[error(transparent)]
    PrependError(<Buf as Prepend>::Error),
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
