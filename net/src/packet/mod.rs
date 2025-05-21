// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Packet struct and methods

mod display;
mod hash;
mod meta;

#[cfg(any(doc, test, feature = "test_buffer"))]
pub mod test_utils;

use crate::buffer::{Headroom, PacketBufferMut, Prepend, Tailroom, TrimFromStart};
use crate::eth::Eth;
use crate::eth::EthError;
use crate::headers::{
    AbstractHeaders, AbstractHeadersMut, Headers, Net, TryHeaders, TryHeadersMut, TryIpMut,
    TryUdpMut, TryVxlan,
};
use crate::parse::{DeParse, Parse, ParseError};
use crate::udp::Udp;

use crate::vxlan::{Vxlan, VxlanEncap};
#[allow(unused_imports)] // re-export
pub use hash::*;
#[allow(unused_imports)] // re-export
pub use meta::*;
use std::num::NonZero;
use tracing::debug;

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
            .unwrap_or_else(|e| unreachable!("{:?}", e));
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

    /// Add / Replace Ethernet header
    pub fn set_eth(&mut self, eth: Eth) {
        self.headers.set_eth(eth);
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
    /// 3. adjusts the `Buf` to start at the beginning of the inner frame.
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
    /// # use dataplane_net::buffer::PacketBufferMut;
    /// # use dataplane_net::headers::TryHeaders;
    /// # use dataplane_net::packet::Packet;
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
    /// * The supplied [`Headers`] will be validated to ensure they form a VXLAN header.
    /// * If the supplied headers describe an IPv4 encapsulation, then the IPv4 checksum will be
    ///   updated.
    /// * The IPv4 / IPv6 headers will be updated to correctly describe the length of the packet.
    ///
    /// # Errors
    ///
    /// If the buffer is unable to prepend the supplied [`Headers`], this method will return a
    /// `<Buf as Prepend>::PrependFailed` `Err` variant.
    ///
    /// # Panics
    ///
    /// This method will panic if the resulting mbuf has a UDP length field longer than 2^16
    /// bytes.
    /// This is extremely unlikely in that the maximum mbuf length is far less than that, and we
    /// don't currently support multi-segment packets.
    pub fn vxlan_encap(&mut self, params: &VxlanEncap) -> Result<(), <Buf as Prepend>::Error> {
        let needed = self.headers.size().get();
        let buf = self.payload.prepend(needed)?;
        self.headers
            .deparse(buf)
            .unwrap_or_else(|e| unreachable!("{e:?}", e = e));

        let len = self.payload.as_ref().len()
            + (Udp::MIN_LENGTH.get() + Vxlan::MIN_LENGTH.get()) as usize;
        assert!(
            u16::try_from(len).is_ok(),
            "encap would result in frame larger than 2^16 bytes"
        );
        #[allow(clippy::cast_possible_truncation)] // checked
        let udp_len = NonZero::new(len as u16).unwrap_or_else(|| unreachable!());
        let mut headers = params.headers().clone();
        let Some(udp) = headers.try_udp_mut() else {
            unreachable!("programmer error: no udp header in vxlan encap operation?");
        };
        #[allow(unsafe_code)] // sound usage due to length check
        unsafe {
            udp.set_length(udp_len)
        };
        udp.set_checksum(0);
        match headers.try_ip_mut() {
            None => unreachable!(),
            Some(Net::Ipv6(ipv6)) => {
                // TODO: include net_ext headers in length if included
                #[allow(unsafe_code)] // sound usage by construction
                unsafe {
                    ipv6.set_payload_length(udp_len.get());
                }
            }
            Some(Net::Ipv4(ipv4)) => {
                // TODO: this isn't _technically_ unreachable
                ipv4.set_payload_len(udp_len.get())
                    .unwrap_or_else(|e| unreachable!("{:?}", e));
                ipv4.update_checksum();
            }
        }
        self.headers = headers;
        Ok(())
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
}
