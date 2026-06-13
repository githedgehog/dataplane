// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Packet struct and methods

#![cfg(unix)]

mod display;
mod hash;
mod meta;
mod stats;
mod stats_display;

pub mod icmp_err;

pub use stats::PacketStats;

#[cfg(any(test, feature = "bolero"))]
pub use contract::*;

#[cfg(any(doc, test, feature = "test_buffer"))]
pub mod test_utils;

use crate::buffer::{DeepCopy, Headroom, PacketBufferMut, Prepend, Tailroom, TrimFromStart};
use crate::eth::Eth;
use crate::eth::EthError;
use crate::flows::{FlowInfo, FlowStatus};
use crate::headers::{
    EmbeddedHeaders, Headers, Net, Transport, TryEmbeddedHeaders, TryEmbeddedHeadersMut,
    TryHeaders, TryHeadersMut, TryIpMut, TryVxlan,
};
use crate::ip::{dscp::Dscp, ecn::Ecn};
use crate::parse::{DeParse, DeParseError, Parse, ParseError};
use crate::udp::{Udp, UdpChecksum};

use crate::checksum::Checksum;
use crate::vxlan::{Vxlan, VxlanEncap};
use concurrency::sync::Arc;
#[allow(unused_imports)] // re-export
pub use hash::*;
#[allow(unused_imports)] // re-export
pub use meta::*;
use std::num::NonZero;

pub mod utils;

/// A parsed (see [`Parse`]) ethernet packet.
///
/// `Packet` deliberately does not implement [`Clone`]: duplicating the payload buffer is a deep,
/// fallible operation (see [`DeepCopy`]).  Use [`Packet::deep_copy`] to duplicate a packet.
#[derive(Debug)]
pub struct Packet<Buf: PacketBufferMut> {
    headers: Headers,
    payload: Buf,
    /// packet metadata added by stages to drive other stages down the pipeline
    pub(crate) meta: PacketMeta,
}

impl<Buf: PacketBufferMut + DeepCopy> Packet<Buf> {
    /// Produce an independent deep copy of this packet: the parsed headers and metadata are cloned
    /// and the payload buffer is deep-copied (see [`DeepCopy`]).
    ///
    /// This is the explicit replacement for `Clone`, which `Packet` does not implement because
    /// duplicating an `Mbuf`-backed payload is a fallible, allocating operation.
    ///
    /// # Errors
    ///
    /// Returns the payload buffer's [`DeepCopy::Error`] if the buffer could not be copied (for an
    /// `Mbuf`, this means the backing pool was exhausted).
    pub fn deep_copy(&self) -> Result<Packet<Buf>, <Buf as DeepCopy>::Error> {
        Ok(Packet {
            headers: self.headers.clone(),
            payload: self.payload.deep_copy()?,
            meta: self.meta.clone(),
        })
    }
}

/// Errors which may occur when failing to produce a [`Packet`]
#[derive(Debug, thiserror::Error)]
pub struct InvalidPacket<Buf: PacketBufferMut> {
    #[allow(unused)]
    mbuf: Buf,
    #[source]
    error: ParseError<EthError>,
}

/// Errors which may occur when failing update a buffer from a [`Packet`]
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum SerializeError<E> {
    #[error("Not enough headroom")]
    NoHeadRoom,
    #[error("De-parsing error: {0}")]
    DeparseError(DeParseError<E>),
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
            meta: PacketMeta::new(true), /* keep the packet until destructor */
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
        self.payload.packet_len() as u16
    }

    /// Get the length of the packet's current headers.
    ///
    /// # Note
    ///
    /// Manipulating the parsed headers _does_ change the length returned by this method.
    pub fn header_len(&self) -> NonZero<u16> {
        self.headers.size()
    }

    /// Get total packet length.
    #[must_use]
    pub fn total_len(&self) -> u16 {
        self.payload_len() + self.header_len().get()
    }

    /// Return the active flow-info for the packet, if any.
    pub fn active_flow_info(&self) -> Option<&Arc<FlowInfo>> {
        let Some(flow_info) = &self.meta().flow_info else {
            return None;
        };
        let status = flow_info.status();
        if status != FlowStatus::Active {
            return None;
        }
        Some(flow_info)
    }

    /// Invalidate the flow that a packet refers to if any, and the related flow
    pub fn invalidate_flows(&self) {
        if let Some(flow_info) = self.meta().flow_info.as_ref() {
            flow_info.invalidate_pair();
        }
    }

    #[inline]
    fn underlay_qos_from_outer_headers(headers: &Headers) -> (Option<Dscp>, Option<Ecn>) {
        match &headers.net {
            Some(Net::Ipv4(ipv4)) => (Some(Dscp::from(ipv4.dscp())), Some(Ecn::from(ipv4.ecn()))),
            Some(Net::Ipv6(ipv6)) => (Some(Dscp::from(ipv6.dscp())), Some(Ecn::from(ipv6.ecn()))),
            None => (None, None),
        }
    }

    #[inline]
    fn apply_outer_qos_to_ip_headers(headers: &mut Headers, meta: &PacketMeta, udp_len: u16) {
        match headers.try_ip_mut() {
            None => unreachable!(),
            Some(Net::Ipv6(ipv6)) => {
                if let Some(dscp) = meta.dscp {
                    ipv6.set_dscp(dscp);
                }
                if let Some(ecn) = meta.ecn {
                    ipv6.set_ecn(ecn);
                }
                ipv6.set_payload_length(udp_len);
            }
            Some(Net::Ipv4(ipv4)) => {
                if let Some(dscp) = meta.dscp {
                    ipv4.set_dscp(dscp);
                }
                if let Some(ecn) = meta.ecn {
                    ipv4.set_ecn(ecn);
                }
                ipv4.set_payload_len(udp_len)
                    .unwrap_or_else(|e| unreachable!("{:?}", e));
                ipv4.update_checksum(&())
                    .unwrap_or_else(|()| unreachable!()); // updating IPv4 checksum never fails
            }
        }
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
            None => None,
            Some(vxlan) => {
                // Preserve underlay QoS markings before stripping the outer headers.
                //
                // We intentionally preserve *outer* DSCP/ECN (fabric-visible) rather than anything
                // inner. This enables decap -> re-encap paths to keep spine/underlay QoS consistent.
                let (dscp, ecn) = Self::underlay_qos_from_outer_headers(&self.headers);

                match Headers::parse(self.payload.as_ref()) {
                    Ok((headers, consumed)) => match self.payload.trim_from_start(consumed.get()) {
                        Ok(_) => {
                            let vxlan = *vxlan;

                            // only if parse succeeds to mutate self
                            self.meta.dscp = dscp;
                            self.meta.ecn = ecn;
                            self.headers = headers;

                            Some(Ok(vxlan))
                        }
                        Err(programmer_err) => {
                            // This most likely indicates a broken implementation of
                            // `PacketBufferMut`
                            unreachable!("{programmer_err:?}", programmer_err = programmer_err);
                        }
                    },
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
        // refresh checksums if told to. N.B. this is DISABLED as the (single) caller does this.
        // TODO: decide if this should be done here or not.
        #[allow(clippy::overly_complex_bool_expr)]
        if false && self.meta().checksum_refresh() {
            self.update_checksums();
        }
        //compute room required
        let needed = self.headers.size().get();
        let buf = self.payload.prepend(needed)?;
        self.headers
            .deparse(buf)
            .unwrap_or_else(|e| unreachable!("{e:?}", e = e));

        let len =
            self.payload.packet_len() + (Udp::MIN_LENGTH.get() + Vxlan::MIN_LENGTH.get()) as usize;
        assert!(
            u16::try_from(len).is_ok(),
            "encap would result in frame larger than 2^16 bytes"
        );

        // compute UDP entropy source port for UDP header
        let udp_src_port = self
            .packet_hash_vxlan()
            .try_into()
            .unwrap_or_else(|_| unreachable!());

        // build UDP header for Vxlan, setting ports, length and checksum.
        let mut udp = Udp::new(udp_src_port, Vxlan::PORT);
        #[allow(clippy::cast_possible_truncation)] // checked
        let udp_len = NonZero::new(len as u16).unwrap_or_else(|| unreachable!());
        #[allow(unsafe_code)] // sound usage due to length check
        unsafe {
            udp.set_length(udp_len);
        }

        // the VXLAN spec says that the checksum SHOULD be zero
        udp.set_checksum(UdpChecksum::ZERO)
            .unwrap_or_else(|()| unreachable!()); // setting UDP checksum never fails

        let mut headers = params.headers().clone();
        headers.transport = Some(Transport::Udp(udp));

        Self::apply_outer_qos_to_ip_headers(&mut headers, &self.meta, udp_len.get());

        self.headers = headers;
        Ok(())
    }

    /// Update the network and transport checksums based on the current headers.
    pub fn update_checksums(&mut self) -> &mut Self {
        let payload = self.payload.as_ref();
        let payload = match self.headers.transport_payload_len() {
            Some(len) if len <= payload.len() => &payload[..len],
            _ => payload,
        };
        self.headers.update_checksums(payload);
        self.meta_mut().set_checksum_refresh(false);
        self
    }

    /// Consume a [`Packet`] and update its buffer based on any changes to its [`Headers`].
    ///
    /// # Errors
    ///
    /// This method returns `SerializeError::NoHeadRoom`if the packet does not have enough headroom to
    /// serialize or `SerializeError::DeparseError` if it does, but the de-parsing the `Packet` failed.
    #[inline]
    pub(crate) fn do_serialize(&mut self) -> Result<(), SerializeError<()>> {
        self.update_checksums();
        let needed = self.headers.size().get();
        let buf = self
            .payload
            .prepend(needed)
            .map_err(|_| SerializeError::NoHeadRoom)?;
        self.headers
            .deparse(buf)
            .map_err(SerializeError::DeparseError)?;

        Ok(())
    }

    /// Consume a [`Packet`] and update its buffer based on any changes to its [`Headers`].
    /// On error, mark the packet accordingly.
    ///
    /// # Errors
    ///
    /// This method returns `SerializeError::NoHeadRoom`if the packet does not have enough headroom to
    /// serialize or `SerializeError::DeparseError` if it does, but the de-parsing the `Packet` failed.
    pub fn serialize(mut self) -> Result<Buf, SerializeError<()>> {
        match self.do_serialize() {
            Ok(()) => Ok(self.payload),
            Err(e) => {
                match e {
                    SerializeError::NoHeadRoom => self.done_force(DoneReason::NoHeadRoom),
                    SerializeError::DeparseError(_) => self.done_force(DoneReason::DeparseError),
                }
                Err(e)
            }
        }
    }
}

impl<Buf: PacketBufferMut> TryHeaders for Packet<Buf> {
    fn headers(&self) -> &Headers {
        &self.headers
    }
}

impl<Buf: PacketBufferMut> TryHeadersMut for Packet<Buf> {
    fn headers_mut(&mut self) -> &mut Headers {
        &mut self.headers
    }
}

impl<Buf: PacketBufferMut> TryEmbeddedHeaders for Packet<Buf> {
    fn embedded_headers(&self) -> Option<&EmbeddedHeaders> {
        self.headers.embedded_ip.as_ref()
    }
}

impl<Buf: PacketBufferMut> TryEmbeddedHeadersMut for Packet<Buf> {
    fn embedded_headers_mut(&mut self) -> Option<&mut EmbeddedHeaders> {
        self.headers.embedded_ip.as_mut()
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

    /// Get an immutable reference to the metadata of this `Packet`
    pub fn meta(&self) -> &PacketMeta {
        &self.meta
    }

    /// Get a mutable reference to the metadata of this `Packet`
    pub fn meta_mut(&mut self) -> &mut PacketMeta {
        &mut self.meta
    }

    /// Reset the metadata of this `Packet`
    pub fn meta_reset(&mut self) {
        self.done(DoneReason::Delivered); // this is just to avoid a log from Metadata Drop impl
        *self.meta_mut() = PacketMeta::new(self.meta.keep());
    }

    /// Wraps a packet in an `Option` depending on the metadata:
    /// If [`Packet`] is to be dropped, returns `None`. Else, `Some`.
    pub fn enforce(self) -> Option<Self> {
        if self.meta.keep() {
            // keep packets even if they should be dropped
            return Some(self);
        }
        match self.get_done() {
            Some(DoneReason::Delivered | DoneReason::Local) | None => Some(self),
            Some(_) => None,
        }
    }

    /// Get a reference to the headers of this `Packet`
    pub(crate) fn get_headers(&self) -> &Headers {
        &self.headers
    }
}

#[cfg(any(test, feature = "bolero"))]
/// The fuzz testing contract for the `Packet` type
pub mod contract {
    use crate::buffer::{GenerateTestBufferForHeaders, TestBuffer};
    use crate::eth::GenWithEthType;
    use crate::eth::ethtype::CommonEthType;
    use crate::headers::{
        CommonHeaders, EmbeddedHeaders, EmbeddedTransport, Headers, Net, Transport,
        TryEmbeddedTransport, TryTransport,
    };
    use crate::icmp4::{
        Icmp4EmbeddedHeadersGenerator, Icmp4ErrorMsgGenerator, Icmp4ExtensionStructures,
    };
    use crate::icmp6::{
        Icmp6EmbeddedHeadersGenerator, Icmp6ErrorMsgGenerator, Icmp6ExtensionStructures,
    };
    use crate::ip::NextHeader;
    use crate::ipv4;
    use crate::ipv6;
    use crate::packet::Packet;
    use crate::parse::DeParse;
    use crate::tcp::TruncatedTcp;
    use crate::udp::TruncatedUdp;
    use arrayvec::ArrayVec;
    use bolero::{Driver, TypeGenerator, ValueGenerator};

    impl TypeGenerator for Packet<TestBuffer> {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let headers: Headers = driver.produce()?;
            let test_buffer = GenerateTestBufferForHeaders::new(headers).generate(driver)?;
            Packet::new(test_buffer).ok()
        }
    }

    /// Common packet generator
    pub struct CommonPacket;

    impl ValueGenerator for CommonPacket {
        type Output = Packet<TestBuffer>;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let common_headers = CommonHeaders;
            let headers = common_headers.generate(driver)?;
            let mut net = headers.net.clone();
            #[allow(unsafe_code)]
            match &mut net {
                None => {}
                Some(Net::Ipv4(ip)) => ip.set_payload_len(headers.size().get()).ok()?,
                Some(Net::Ipv6(ip)) => {
                    ip.set_payload_length(headers.size().get());
                }
            }
            let test_buffer = GenerateTestBufferForHeaders::new(headers).generate(driver)?;

            Packet::new(test_buffer).ok()
        }
    }

    enum IcmpExtensionStructures {
        V4(Icmp4ExtensionStructures),
        V6(Icmp6ExtensionStructures),
    }

    impl IcmpExtensionStructures {
        fn size(&self) -> usize {
            match self {
                IcmpExtensionStructures::V4(v4) => v4.size().get() as usize,
                IcmpExtensionStructures::V6(v6) => v6.size().get() as usize,
            }
        }
    }

    /// Common ICMP Error message generator
    pub struct IcmpErrorMsg;

    impl ValueGenerator for IcmpErrorMsg {
        type Output = Packet<TestBuffer>;

        // Note: We intentionally don't set checksums. Call the relevant functions on headers of the
        // generated packet if desired.
        #[allow(clippy::too_many_lines, clippy::unwrap_used)]
        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            // Generate headers

            let common_eth_type: CommonEthType = driver.produce().unwrap();
            let eth = GenWithEthType(common_eth_type.into())
                .generate(driver)
                .unwrap();
            let mut headers = match common_eth_type {
                CommonEthType::Ipv4 => {
                    let ipv4 = ipv4::GenWithNextHeader(NextHeader::ICMP)
                        .generate(driver)
                        .unwrap();
                    let error_msg_generator = Icmp4ErrorMsgGenerator;
                    let icmp4 = error_msg_generator.generate(driver).unwrap();
                    let inner_ip_generator = Icmp4EmbeddedHeadersGenerator;
                    let embedded_ip = inner_ip_generator.generate(driver).unwrap();
                    Headers {
                        eth: Some(eth),
                        vlan: ArrayVec::default(),
                        net: Some(Net::Ipv4(ipv4)),
                        net_ext: ArrayVec::default(),
                        transport: Some(Transport::Icmp4(icmp4)),
                        udp_encap: None,
                        embedded_ip: Some(embedded_ip),
                    }
                }
                CommonEthType::Ipv6 => {
                    let ipv6 = ipv6::GenWithNextHeader(NextHeader::ICMP6)
                        .generate(driver)
                        .unwrap();
                    let error_msg_generator = Icmp6ErrorMsgGenerator;
                    let icmp6 = error_msg_generator.generate(driver).unwrap();
                    let inner_ip_generator = Icmp6EmbeddedHeadersGenerator;
                    let embedded_ip = inner_ip_generator.generate(driver).unwrap();
                    Headers {
                        eth: Some(eth),
                        vlan: ArrayVec::default(),
                        net: Some(Net::Ipv6(ipv6)),
                        net_ext: ArrayVec::default(),
                        transport: Some(Transport::Icmp6(icmp6)),
                        udp_encap: None,
                        embedded_ip: Some(embedded_ip),
                    }
                }
            };

            // Generate payload size and ICMP extensions

            let headers_size = headers.size().get() as usize;
            let mut payload_size = 0;
            let mut extensions = None;
            if let Some(ref inner_ip) = headers.embedded_ip
                && let Some(
                    EmbeddedTransport::Tcp(TruncatedTcp::FullHeader(_))
                    | EmbeddedTransport::Udp(TruncatedUdp::FullHeader(_)),
                ) = inner_ip.try_embedded_transport()
            {
                // The length of the resulting ICMP datagram cannot exceed 576 bytes (RFC 5508)
                payload_size = driver.produce::<usize>()? % (576 - headers_size);
                if payload_size > 0 {
                    extensions = match &headers.transport {
                        Some(Transport::Icmp4(icmp)) => {
                            if icmp.supports_extensions() {
                                driver
                                    .produce::<Icmp4ExtensionStructures>()
                                    .map(IcmpExtensionStructures::V4)
                            } else {
                                None
                            }
                        }
                        Some(Transport::Icmp6(icmp)) => {
                            if icmp.supports_extensions() {
                                driver
                                    .produce::<Icmp6ExtensionStructures>()
                                    .map(IcmpExtensionStructures::V6)
                            } else {
                                None
                            }
                        }
                        _ => unreachable!(),
                    };
                }
            }

            // Compute sizes

            let extensions_size = extensions.as_ref().map_or(0, IcmpExtensionStructures::size);
            let padding_size = match extensions {
                Some(IcmpExtensionStructures::V4(_)) => {
                    Icmp4ExtensionStructures::padding_size(payload_size)
                }
                Some(IcmpExtensionStructures::V6(_)) => {
                    Icmp6ExtensionStructures::padding_size(payload_size)
                }
                None => 0,
            };
            // ICMP header size
            let icmp_header_size = headers.try_transport().unwrap().size().get() as usize;
            // Total packet size
            let total_size = headers_size + payload_size + padding_size + extensions_size;
            // Payload size for outer IP header
            let outer_payload_size =
                icmp_header_size + payload_size + padding_size + extensions_size;
            // Payload size for inner IP header
            let inner_network_header_size = headers
                .embedded_ip
                .as_ref()
                .map_or(0, EmbeddedHeaders::net_headers_len)
                as usize;
            // Payload size for inner TCP/UDP header
            let inner_transport_header_size = headers
                .embedded_ip
                .as_ref()
                .map_or(0, EmbeddedHeaders::transport_headers_len)
                as usize;
            // Theoretical payload size for inner TCP/UDP (inner packet may be truncated)
            let theoretical_inner_payload_size = if payload_size == 0 {
                0
            } else if driver.produce::<bool>()? {
                // Payload is full
                payload_size
            } else {
                // Payload is truncated: return a bigger theoretical payload size value
                1000 - (driver.produce::<usize>()? % 1000) + payload_size
            };
            // Theoretical payload size for inner IP header (inner packet may be truncated)
            let theoretical_inner_net_payload_size =
                theoretical_inner_payload_size + inner_transport_header_size;
            // Offset of ICMP header in packet
            let icmp_header_offset = headers_size
                - headers
                    .eth
                    .as_ref()
                    .map_or(0, |eth| eth.size().get() as usize)
                - headers
                    .net
                    .as_ref()
                    .map_or(0, |net| net.size().get() as usize);
            // Payload size for ICMP header, only used in conjunction with ICMP extensions
            let icmp_payload_size = inner_network_header_size
                + inner_transport_header_size
                + payload_size
                + padding_size;
            // Offset of extensions in packet, or 0 if no extensions are in use
            let extensions_offset =
                total_size - extensions.as_ref().map_or(0, IcmpExtensionStructures::size);

            // Update headers

            // Set outer IP payload/total length
            match headers.net {
                Some(Net::Ipv4(ref mut ipv4)) => {
                    #[allow(clippy::cast_possible_truncation)] // bounded size
                    ipv4.set_payload_len(outer_payload_size as u16).unwrap();
                }
                Some(Net::Ipv6(ref mut ipv6)) => {
                    #[allow(clippy::cast_possible_truncation)] // bounded size
                    ipv6.set_payload_length(outer_payload_size as u16);
                }
                None => {}
            }
            // Set inner IP payload/total length
            #[allow(clippy::cast_possible_truncation)] // bounded size
            headers.embedded_ip.as_mut().map(|embedded_ip| {
                embedded_ip.set_network_payload_length(theoretical_inner_net_payload_size as u16)
            });
            // Set inner transport length
            #[allow(clippy::cast_possible_truncation)] // bounded size
            headers.embedded_ip.as_mut().map(|embedded_ip| {
                embedded_ip.set_transport_payload_length(theoretical_inner_payload_size as u16)
            });

            // Write packet contents to buffer

            let mut data = vec![0; total_size];

            // Write headers
            headers.deparse(data.as_mut()).unwrap();

            // Write payload
            if payload_size > 0 {
                data[headers.size().get() as usize..headers.size().get() as usize + payload_size]
                    .fill(driver.produce().unwrap());
            }

            match extensions {
                Some(IcmpExtensionStructures::V4(ext)) => {
                    // Set padding
                    data[extensions_offset - padding_size..extensions_offset].fill(0);
                    // Write extensions
                    ext.deparse(&mut data[extensions_offset..]).unwrap();
                }
                Some(IcmpExtensionStructures::V6(ext)) => {
                    // Set padding
                    data[extensions_offset - padding_size..extensions_offset].fill(0);
                    // Write extensions
                    ext.deparse(&mut data[extensions_offset..]).unwrap();
                }
                None => {}
            }

            // Set ICMP payload length, if relevant (if we use ICMP extensions). See RFC 4884.
            // FIXME: We don't have header fields to do that without writing directly to the buffer.
            if extensions_size > 0 {
                #[allow(clippy::cast_possible_truncation)] // bounded sizes
                match headers.transport {
                    Some(Transport::Icmp4(_)) => {
                        data[icmp_header_offset + 5] = (icmp_payload_size / 4) as u8;
                    }
                    Some(Transport::Icmp6(_)) => {
                        data[icmp_header_offset + 4] = (icmp_payload_size / 8) as u8;
                    }
                    _ => {}
                }
            }

            Packet::new(TestBuffer::from_raw_data(&data)).ok()
        }
    }
}

#[cfg(test)]
mod qos_roundtrip_tests {
    use crate::headers::{Headers, Net};
    use crate::ip::dscp::Dscp;
    use crate::ip::ecn::Ecn;
    use crate::packet::test_utils::{
        build_test_vxlan_ipv4_packet_with_outer_qos, build_test_vxlan_ipv6_packet_with_outer_qos,
    };
    use crate::udp::UdpEncap;
    use crate::vxlan::{Vni, Vxlan, VxlanEncap};
    use arrayvec::ArrayVec;

    fn make_vxlan_encap_headers_ipv4() -> VxlanEncap {
        let mut ip = crate::ipv4::Ipv4::default();
        ip.set_source(
            crate::ipv4::addr::UnicastIpv4Addr::new("10.0.0.1".parse().unwrap()).unwrap(),
        );
        ip.set_destination("10.0.0.2".parse().unwrap());
        ip.set_ttl(64);
        ip.set_next_header(crate::ip::NextHeader::UDP);

        let headers = Headers {
            eth: None,
            vlan: ArrayVec::default(),
            net: Some(Net::Ipv4(ip)),
            net_ext: ArrayVec::default(),
            transport: None,
            udp_encap: Some(UdpEncap::Vxlan(Vxlan::new(Vni::new_checked(200).unwrap()))),
            embedded_ip: None,
        };
        VxlanEncap::new(headers).unwrap()
    }

    fn make_vxlan_encap_headers_ipv6() -> VxlanEncap {
        let mut ip = crate::ipv6::Ipv6::default();
        ip.set_source(
            crate::ipv6::addr::UnicastIpv6Addr::new("2001:db8::1".parse().unwrap()).unwrap(),
        );
        ip.set_destination("2001:db8::2".parse().unwrap());
        ip.set_hop_limit(64);
        ip.set_next_header(crate::ip::NextHeader::UDP);

        let headers = Headers {
            eth: None,
            vlan: ArrayVec::default(),
            net: Some(Net::Ipv6(ip)),
            net_ext: ArrayVec::default(),
            transport: None,
            udp_encap: Some(UdpEncap::Vxlan(Vxlan::new(Vni::new_checked(200).unwrap()))),
            embedded_ip: None,
        };
        VxlanEncap::new(headers).unwrap()
    }

    #[test]
    fn vxlan_decap_then_encap_preserves_outer_qos_ipv4_underlay() {
        let in_dscp = Dscp::new(46).unwrap();
        let in_ecn = Ecn::new(3).unwrap();

        let mut p = build_test_vxlan_ipv4_packet_with_outer_qos(in_dscp, in_ecn).unwrap();

        // decap stores outer qos in metadata (your implementation does this)
        let _ = p.vxlan_decap().unwrap().unwrap();

        // encap should apply outer qos from metadata to the new underlay header
        let params = make_vxlan_encap_headers_ipv4();
        p.vxlan_encap(&params).unwrap();

        match &p.get_headers().net {
            Some(Net::Ipv4(ipv4)) => {
                assert_eq!(Dscp::from(ipv4.dscp()), in_dscp);
                assert_eq!(Ecn::from(ipv4.ecn()), in_ecn);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn vxlan_decap_then_encap_preserves_outer_qos_ipv6_underlay() {
        let in_dscp = Dscp::new(46).unwrap();
        let in_ecn = Ecn::new(3).unwrap();

        let mut p = build_test_vxlan_ipv6_packet_with_outer_qos(in_dscp, in_ecn).unwrap();

        let _ = p.vxlan_decap().unwrap().unwrap();

        let params = make_vxlan_encap_headers_ipv6();
        p.vxlan_encap(&params).unwrap();

        match &p.get_headers().net {
            Some(Net::Ipv6(ipv6)) => {
                assert_eq!(Dscp::from(ipv6.dscp()), in_dscp);
                assert_eq!(Ecn::from(ipv6.ecn()), in_ecn);
            }
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod padding_tests {
    use crate::buffer::TestBuffer;
    use crate::checksum::Checksum;
    use crate::eth::ethtype::EthType;
    use crate::headers::{Headers, Net, TryHeaders, TryIcmp4, TryIp, TryTcp, TryUdp};
    use crate::packet::Packet;
    use crate::packet::test_utils::make_default_for_eth;
    use crate::tcp::TcpChecksumPayload;
    use crate::udp::UdpChecksumPayload;
    use crate::udp::UdpEncap;
    use crate::vxlan::{Vni, Vxlan, VxlanEncap};
    use arrayvec::ArrayVec;

    const MIN_ETHERNET_FRAME: usize = 60;

    fn frame(protocol: u8, l4: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]); // destination mac
        frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]); // source mac
        frame.extend_from_slice(&[0x08, 0x00]); // ipv4
        frame.extend_from_slice(&[0x45, 0x00]);
        #[allow(clippy::cast_possible_truncation)] // test input is small
        frame.extend_from_slice(&((20 + l4.len()) as u16).to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x40, protocol, 0x00, 0x00]);
        frame.extend_from_slice(&[192, 168, 0, 1]); // source ip
        frame.extend_from_slice(&[192, 168, 0, 2]); // destination ip
        frame.extend_from_slice(l4);
        frame
    }

    fn tcp_ack() -> Vec<u8> {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&1000_u16.to_be_bytes()); // source port
        tcp.extend_from_slice(&2000_u16.to_be_bytes()); // destination port
        tcp.extend_from_slice(&[0, 0, 0, 1]); // sequence number
        tcp.extend_from_slice(&[0, 0, 0, 2]); // acknowledgement number
        tcp.extend_from_slice(&[0x50, 0x10]); // data offset 5, ACK
        tcp.extend_from_slice(&1024_u16.to_be_bytes()); // window
        tcp.extend_from_slice(&[0, 0]); // checksum
        tcp.extend_from_slice(&[0, 0]); // urgent pointer
        tcp
    }

    fn udp(payload: &[u8]) -> Vec<u8> {
        let mut udp = Vec::new();
        udp.extend_from_slice(&1000_u16.to_be_bytes()); // source port
        udp.extend_from_slice(&2000_u16.to_be_bytes()); // destination port
        #[allow(clippy::cast_possible_truncation)] // test input is small
        udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]); // checksum
        udp.extend_from_slice(payload);
        udp
    }

    fn icmp4_echo_request() -> Vec<u8> {
        vec![8, 0, 0, 0, 0x00, 0x2a, 0x00, 0x01]
    }

    fn parse(frame: &[u8]) -> Packet<TestBuffer> {
        Packet::new(TestBuffer::from_raw_data(frame)).expect("frame does not parse")
    }

    fn pad(mut frame: Vec<u8>, filler: u8) -> Vec<u8> {
        assert!(frame.len() < MIN_ETHERNET_FRAME, "frame needs no padding");
        frame.resize(MIN_ETHERNET_FRAME, filler);
        frame
    }

    #[test]
    fn tcp_checksum_excludes_zeroed_ethernet_padding() {
        let mut packet = parse(&pad(frame(6, &tcp_ack()), 0));
        packet.update_checksums();
        let net = packet.headers().try_ip().expect("no ip header").clone();
        packet
            .headers()
            .try_tcp()
            .expect("no tcp header")
            .validate_checksum(&TcpChecksumPayload::new(&net, &[]))
            .expect("padding leaked into the tcp checksum");
    }

    #[test]
    fn udp_checksum_excludes_non_zero_ethernet_padding() {
        let mut packet = parse(&pad(frame(17, &udp(&[])), 0xab));
        packet.update_checksums();
        let net = packet.headers().try_ip().expect("no ip header").clone();
        packet
            .headers()
            .try_udp()
            .expect("no udp header")
            .validate_checksum(&UdpChecksumPayload::new(&net, &[]))
            .expect("padding leaked into the udp checksum");
    }

    #[test]
    fn icmp4_checksum_excludes_non_zero_ethernet_padding() {
        let mut packet = parse(&pad(frame(1, &icmp4_echo_request()), 0xab));
        packet.update_checksums();
        packet
            .headers()
            .try_icmp4()
            .expect("no icmp header")
            .validate_checksum(&[])
            .expect("padding leaked into the icmp checksum");
    }

    #[test]
    fn checksum_still_covers_a_real_payload() {
        let payload: Vec<u8> = (0..32_u8).collect();
        let mut packet = parse(&frame(17, &udp(&payload)));
        assert_eq!(packet.payload().as_ref(), payload.as_slice());
        packet.update_checksums();
        let net = packet.headers().try_ip().expect("no ip header").clone();
        packet
            .headers()
            .try_udp()
            .expect("no udp header")
            .validate_checksum(&UdpChecksumPayload::new(&net, &payload))
            .expect("payload dropped out of the udp checksum");
    }

    #[test]
    fn truncated_payload_does_not_panic() {
        let payload: Vec<u8> = (0..32_u8).collect();
        let mut frame = frame(17, &udp(&payload));
        frame.truncate(frame.len() - 8);
        let mut packet = parse(&frame);
        packet.update_checksums();
    }

    fn tcp(payload: &[u8]) -> Vec<u8> {
        let mut tcp = tcp_ack();
        tcp.extend_from_slice(payload);
        tcp
    }

    fn vxlan_wrap(inner: &[u8]) -> Vec<u8> {
        let mut packet =
            Packet::new(TestBuffer::from_raw_data(inner)).expect("inner frame does not parse");
        packet
            .vxlan_encap(&vxlan_encap_params())
            .expect("vxlan encap failed");
        packet
            .serialize()
            .expect("vxlan frame does not serialize")
            .as_ref()
            .to_vec()
    }

    fn vxlan_encap_params() -> VxlanEncap {
        let mut ip = crate::ipv4::Ipv4::default();
        ip.set_source(
            crate::ipv4::addr::UnicastIpv4Addr::new("10.0.0.1".parse().unwrap()).unwrap(),
        );
        ip.set_destination("10.0.0.2".parse().unwrap());
        ip.set_ttl(64);
        ip.set_next_header(crate::ip::NextHeader::UDP);

        let headers = Headers {
            eth: Some(make_default_for_eth(EthType::IPV4)),
            vlan: ArrayVec::default(),
            net: Some(Net::Ipv4(ip)),
            net_ext: ArrayVec::default(),
            transport: None,
            udp_encap: Some(UdpEncap::Vxlan(Vxlan::new(Vni::new_checked(42).unwrap()))),
            embedded_ip: None,
        };
        VxlanEncap::new(headers).unwrap_or_else(|e| unreachable!("{e:?}"))
    }

    #[test]
    fn vxlan_carries_padding_that_the_inner_checksum_must_ignore() {
        let inner = pad(frame(6, &tcp_ack()), 0xab);
        assert_eq!(
            inner.len(),
            MIN_ETHERNET_FRAME,
            "the inner frame should have been padded"
        );

        let mut packet = parse(&vxlan_wrap(&inner));
        packet
            .vxlan_decap()
            .expect("not a vxlan packet")
            .expect("inner frame does not parse");
        packet.update_checksums();

        let net = packet
            .headers()
            .try_ip()
            .expect("no inner ip header")
            .clone();
        packet
            .headers()
            .try_tcp()
            .expect("no inner tcp header")
            .validate_checksum(&TcpChecksumPayload::new(&net, &[]))
            .expect("inner ethernet padding leaked into the tcp checksum");
    }

    #[test]
    fn trailing_octets_never_enter_a_tcp_checksum() {
        bolero::check!()
            .with_type::<(Vec<u8>, Vec<u8>)>()
            .for_each(|(payload, trailer)| {
                let payload = &payload[..payload.len().min(256)];
                let trailer = &trailer[..trailer.len().min(64)];
                let mut bytes = frame(6, &tcp(payload));
                bytes.extend_from_slice(trailer);
                let Ok(mut packet) = Packet::new(TestBuffer::from_raw_data(&bytes)) else {
                    return;
                };
                packet.update_checksums();
                let net = packet.headers().try_ip().expect("no ip header").clone();
                packet
                    .headers()
                    .try_tcp()
                    .expect("no tcp header")
                    .validate_checksum(&TcpChecksumPayload::new(&net, payload))
                    .expect("trailing octets leaked into the tcp checksum");
            });
    }

    #[test]
    fn trailing_octets_never_enter_a_udp_checksum() {
        bolero::check!()
            .with_type::<(Vec<u8>, Vec<u8>)>()
            .for_each(|(payload, trailer)| {
                let payload = &payload[..payload.len().min(256)];
                let trailer = &trailer[..trailer.len().min(64)];
                let mut bytes = frame(17, &udp(payload));
                bytes.extend_from_slice(trailer);
                let Ok(mut packet) = Packet::new(TestBuffer::from_raw_data(&bytes)) else {
                    return;
                };
                packet.update_checksums();
                let net = packet.headers().try_ip().expect("no ip header").clone();
                packet
                    .headers()
                    .try_udp()
                    .expect("no udp header")
                    .validate_checksum(&UdpChecksumPayload::new(&net, payload))
                    .expect("trailing octets leaked into the udp checksum");
            });
    }

    #[test]
    fn trailing_octets_never_enter_a_vxlan_inner_tcp_checksum() {
        bolero::check!()
            .with_type::<(Vec<u8>, Vec<u8>)>()
            .for_each(|(payload, trailer)| {
                let payload = &payload[..payload.len().min(128)];
                let trailer = &trailer[..trailer.len().min(64)];
                let mut inner = frame(6, &tcp(payload));
                inner.extend_from_slice(trailer);
                let Ok(mut packet) = Packet::new(TestBuffer::from_raw_data(&vxlan_wrap(&inner)))
                else {
                    return;
                };
                let Some(Ok(_)) = packet.vxlan_decap() else {
                    return;
                };
                packet.update_checksums();
                let net = packet
                    .headers()
                    .try_ip()
                    .expect("no inner ip header")
                    .clone();
                packet
                    .headers()
                    .try_tcp()
                    .expect("no inner tcp header")
                    .validate_checksum(&TcpChecksumPayload::new(&net, payload))
                    .expect("inner trailing octets leaked into the tcp checksum");
            });
    }
}
