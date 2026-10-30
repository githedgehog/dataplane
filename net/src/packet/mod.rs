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
use crate::eth::ethtype::EthType;
use crate::eth::mac::{DestinationMac, SourceMac};
use crate::flows::{FlowInfo, FlowStatus};
use crate::headers::{
    EmbeddedHeaders, Headers, Net, Transport, TryEmbeddedHeaders, TryEmbeddedHeadersMut,
    TryHeaders, TryHeadersMut, TryIp, TryIpMut, TryVxlan,
};
use crate::ip::{dscp::Dscp, ecn::Ecn};
use crate::parse::{DeParse, DeParseError, Parse, ParseError};
use crate::udp::{Udp, UdpChecksum};
use crate::vxlan::Vni;

use crate::checksum::Checksum;
use crate::vxlan::{Vxlan, VxlanEncap};
use concurrency::sync::Arc;
#[allow(unused_imports)] // re-export
pub use hash::*;
#[allow(unused_imports)] // re-export
pub use meta::*;
use std::net::IpAddr;
use std::num::NonZero;

pub mod utils;

/// A parsed Ethernet packet. Use [`Packet::deep_copy`] to copy its buffer.
#[derive(Debug)]
pub struct Packet<Buf: PacketBufferMut> {
    headers: Headers,
    payload: Buf,
    /// packet metadata added by stages to drive other stages down the pipeline
    pub(crate) meta: PacketMeta,
    /// Last recorded transport checksum error; see [`Self::assert_transport_checksum_kept`].
    #[cfg(any(test, feature = "checksum-audit"))]
    transport_checksum_error: Option<u16>,
}

impl<Buf: PacketBufferMut + DeepCopy> Packet<Buf> {
    /// Clone the headers and metadata and deep-copy the payload buffer.
    ///
    /// # Errors
    ///
    /// Returns [`DeepCopy::Error`] if the buffer cannot be copied.
    pub fn deep_copy(&self) -> Result<Packet<Buf>, <Buf as DeepCopy>::Error> {
        Ok(Packet {
            headers: self.headers.clone(),
            payload: self.payload.deep_copy()?,
            meta: self.meta.clone(),
            #[cfg(any(test, feature = "checksum-audit"))]
            transport_checksum_error: self.transport_checksum_error,
        })
    }
}

/// Errors which may occur when failing to produce a [`Packet`]
#[derive(Debug, thiserror::Error)]
pub struct InvalidPacket<Buf: PacketBufferMut> {
    #[allow(unused)]
    mbuf: Buf,
    #[source]
    error: InvalidPacketError,
}

#[derive(Debug, thiserror::Error)]
enum InvalidPacketError {
    #[error(transparent)]
    Parse(#[from] ParseError<EthError>),
    // Checksums and other whole-payload consumers read only the head segment.
    #[error("chained packet buffers are not supported")]
    Chained,
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

/// Data read from a VXLAN packet by [`Packet::vxlan_peek`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VxLanPeekedData {
    /// The VNI of the VXLAN header.
    pub vni: Vni,
    /// The source address of the outer IP header.
    pub outer_src_ip: IpAddr,
    /// The destination address of the outer IP header.
    pub outer_dst_ip: IpAddr,
    /// The destination MAC of the inner Ethernet header.
    pub inner_dst_mac: DestinationMac,
    /// The source MAC of the inner Ethernet header.
    pub inner_src_mac: SourceMac,
    /// Whether the inner Ethernet frame is VLAN-tagged.
    /// Note: this could contain the `ArrayVec` of vlans, but I doubt we'd
    /// ever do anything with it. Also, this flag is set only from the
    /// ether type, without actually checking if the inner packet would
    /// have vlans if parsed
    pub inner_vlan_tagged: bool,
}

impl<Buf: PacketBufferMut> Packet<Buf> {
    /// Map a `PacketBufferMut` to a `Packet` if the buffer contains a valid ethernet packet.
    ///
    /// # Errors
    ///
    /// Returns an [`InvalidPacket`] error if the buffer spans more than one segment or does not
    /// parse as an ethernet frame.
    pub fn new(mut mbuf: Buf) -> Result<Packet<Buf>, InvalidPacket<Buf>> {
        if mbuf.is_chained() {
            return Err(InvalidPacket {
                mbuf,
                error: InvalidPacketError::Chained,
            });
        }
        let (headers, consumed) = match Headers::parse(mbuf.as_ref()) {
            Ok((headers, consumed)) => (headers, consumed),
            Err(error) => {
                return Err(InvalidPacket {
                    mbuf,
                    error: error.into(),
                });
            }
        };
        mbuf.trim_from_start(consumed.get())
            .unwrap_or_else(|e| unreachable!("{:?}", e));

        #[cfg_attr(not(any(test, feature = "checksum-audit")), allow(unused_mut))]
        let mut packet = Packet {
            headers,
            payload: mbuf,
            meta: PacketMeta::new(),
            #[cfg(any(test, feature = "checksum-audit"))]
            transport_checksum_error: None,
        };
        #[cfg(any(test, feature = "checksum-audit"))]
        packet.note_transport_checksum();
        Ok(packet)
    }

    /// How far the transport checksum is from valid: the one's-complement difference between it
    /// and what a computation from scratch over the same octets gives. `None` without one to
    /// compare: no transport header, a disabled UDP checksum, or VXLAN.
    #[cfg(any(test, feature = "checksum-audit"))]
    fn transport_checksum_error(&self) -> Option<u16> {
        if self.headers.try_vxlan().is_some() {
            return None;
        }
        let stored = self.headers.transport.as_ref()?.checksum_for_increment()?;
        let mut computed = self.headers.clone();
        let covered = computed.transport_payload_len();
        computed.compute_transport_checksum(self.payload.as_ref(), covered);
        let computed = computed.transport.as_ref()?.checksum_for_increment()?;
        let sum = u32::from(stored) + u32::from(!computed);
        #[allow(clippy::cast_possible_truncation)] // one fold of two 16-bit words fits 16 bits
        let difference = ((sum & 0xffff) + (sum >> 16)) as u16;
        // Both zeros are the same difference.
        Some(if difference == 0 { 0xffff } else { difference })
    }

    /// Record the current transport checksum error as the audit baseline.
    #[cfg(any(test, feature = "checksum-audit"))]
    fn note_transport_checksum(&mut self) {
        self.transport_checksum_error = self.transport_checksum_error();
    }

    /// Compare the transport checksum error with the last recorded baseline, unless a refresh
    /// is pending. This detects changes made without updating the checksum or requesting a refresh.
    ///
    /// # Panics
    ///
    /// Panics if both checksum errors are available and differ, with no refresh pending.
    #[cfg(any(test, feature = "checksum-audit"))]
    fn assert_transport_checksum_kept(&self) {
        if self.meta.checksum_refresh() {
            return;
        }
        if let (Some(before), Some(now)) = (
            self.transport_checksum_error,
            self.transport_checksum_error(),
        ) {
            assert_eq!(
                before, now,
                "a stage changed what the transport checksum covers, and neither folded the change \
                 in nor asked for a refresh: {:?}",
                self.headers
            );
        }
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
                // The setters keep the header checksum current.
                ipv4.set_payload_len(udp_len)
                    .unwrap_or_else(|e| unreachable!("{:?}", e));
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
                            #[cfg(any(test, feature = "checksum-audit"))]
                            self.note_transport_checksum();

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

    /// Peek some data if the packet has a VXLAN encapsulation without mutating the packet
    /// nor performing any actual decapsulation.
    ///
    /// Returns:
    /// - `Ok(None)` if the packet is not VXLAN.
    /// - `Ok(Some(data))` with the [`VxLanPeekedData`] if it is.
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] if the packet is VXLAN but its payload does not start with a valid
    /// Ethernet header.
    pub fn vxlan_peek(&self) -> Result<Option<VxLanPeekedData>, ParseError<EthError>> {
        let Some(vxlan) = self.headers.try_vxlan() else {
            return Ok(None);
        };
        let Some(net) = self.headers.try_ip() else {
            return Ok(None);
        };
        let (inner, _) = Eth::parse(self.payload.as_ref())?;
        Ok(Some(VxLanPeekedData {
            vni: vxlan.vni(),
            outer_src_ip: net.src_addr(),
            outer_dst_ip: net.dst_addr(),
            inner_dst_mac: inner.destination(),
            inner_src_mac: inner.source(),
            // Same ethertypes the header parser treats as VLAN tags (`parse_from_ethertype`).
            inner_vlan_tagged: matches!(
                inner.ether_type(),
                EthType::VLAN | EthType::VLAN_DOUBLE_TAGGED | EthType::VLAN_QINQ
            ),
        }))
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
        #[cfg(any(test, feature = "checksum-audit"))]
        self.assert_transport_checksum_kept();
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
        #[cfg(any(test, feature = "checksum-audit"))]
        self.note_transport_checksum();
        Ok(())
    }

    /// Compute the network and transport checksums from scratch, for a packet built here.
    ///
    /// A forwarded packet should not need this: computing a checksum from scratch makes a packet
    /// that arrived corrupt look intact. See [`Self::refresh_transport_checksum`].
    pub fn update_checksums(&mut self) -> &mut Self {
        let covered = self.headers.transport_payload_len();
        self.headers
            .update_checksums_covering(self.payload.as_ref(), covered);
        self.meta_mut().set_checksum_refresh(false);
        #[cfg(any(test, feature = "checksum-audit"))]
        self.note_transport_checksum();
        self
    }

    /// Attempt to recompute the transport checksum. Stages request this when incremental updates
    /// are insufficient; receive drivers request it for partial or unknown checksum status.
    ///
    /// IPv4 header checksums, including quoted ones, remain unchanged: [`Ipv4`](crate::ipv4::Ipv4)
    /// setters maintain them. Fragmented datagrams retain their transport checksum and pending
    /// [`checksum_refresh`](PacketMeta::checksum_refresh) request. Otherwise the request is cleared,
    /// including when VXLAN or missing headers prevent an update.
    pub fn refresh_transport_checksum(&mut self) -> &mut Self {
        let covered = self.headers.transport_payload_len();
        if self
            .headers
            .refresh_transport_checksum(self.payload.as_ref(), covered)
        {
            self.meta_mut().set_checksum_refresh(false);
        }
        #[cfg(any(test, feature = "checksum-audit"))]
        self.note_transport_checksum();
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
        #[cfg(any(test, feature = "checksum-audit"))]
        self.assert_transport_checksum_kept();
        // IPv4 setters maintain header checksums. Refresh transport checksums only when requested
        // by a stage or receive driver; unnecessary recomputation scans the payload and can mask
        // corruption.
        if self.meta().checksum_refresh() {
            self.refresh_transport_checksum();
        }
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

    /// Consume a [`Packet`] that is being dropped and give back its buffer, without writing its
    /// [`Headers`] into it.
    ///
    /// For callers that release buffers in bulk; the buffer's contents are not meaningful.
    #[must_use]
    pub fn discard(self) -> Buf {
        self.payload
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
        self.headers.embedded_ip.as_deref()
    }
}

impl<Buf: PacketBufferMut> TryEmbeddedHeadersMut for Packet<Buf> {
    fn embedded_headers_mut(&mut self) -> Option<&mut EmbeddedHeaders> {
        self.headers.embedded_ip.as_deref_mut()
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
        *self.meta_mut() = PacketMeta::new();
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
                        vlan: crate::headers::Stack::default(),
                        net: Some(Net::Ipv4(ipv4)),
                        net_ext: crate::headers::Stack::default(),
                        transport: Some(Transport::Icmp4(icmp4)),
                        udp_encap: None,
                        embedded_ip: Some(Box::new(embedded_ip)),
                        lldp: None,
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
                        vlan: crate::headers::Stack::default(),
                        net: Some(Net::Ipv6(ipv6)),
                        net_ext: crate::headers::Stack::default(),
                        transport: Some(Transport::Icmp6(icmp6)),
                        udp_encap: None,
                        embedded_ip: Some(Box::new(embedded_ip)),
                        lldp: None,
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
                .as_deref()
                .map_or(0, EmbeddedHeaders::net_headers_len)
                as usize;
            // Payload size for inner TCP/UDP header
            let inner_transport_header_size = headers
                .embedded_ip
                .as_deref()
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
            headers.embedded_ip.as_deref_mut().map(|embedded_ip| {
                embedded_ip.set_network_payload_length(theoretical_inner_net_payload_size as u16)
            });
            // Set inner transport length
            #[allow(clippy::cast_possible_truncation)] // bounded size
            headers.embedded_ip.as_deref_mut().map(|embedded_ip| {
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
mod vxlan_peek_tests {
    use crate::buffer::TestBuffer;
    use crate::eth::ethtype::EthType;
    use crate::headers::TryHeaders;
    use crate::headers::builder::HeaderStack;
    use crate::ip::dscp::Dscp;
    use crate::ip::ecn::Ecn;
    use crate::ipv4::UnicastIpv4Addr;
    use crate::packet::Packet;
    use crate::packet::test_utils::{
        build_test_ipv4_packet, build_test_vxlan_ipv4_packet_carrying_vni,
    };
    use crate::parse::DeParse;
    use crate::vlan::Vid;
    use crate::vxlan::Vni;
    use std::net::Ipv4Addr;

    #[test]
    fn vxlan_peek_succeeds_without_mutating() {
        let inner = build_test_ipv4_packet(64).unwrap();
        let inner_eth = inner.headers().eth().unwrap().clone();
        let inner_buf = inner.serialize().unwrap();
        let vni = Vni::new_checked(4242).unwrap();
        let packet = build_test_vxlan_ipv4_packet_carrying_vni(
            vni,
            Dscp::new(0).unwrap(),
            Ecn::new(0).unwrap(),
            inner_buf.as_ref(),
        )
        .expect("Failed to build test packet");

        // keep copy of headers prior to peek
        let headers_before = packet.headers().clone();

        let peeked = packet.vxlan_peek().unwrap().unwrap();

        assert_eq!(peeked.vni, vni);
        assert_eq!(peeked.outer_src_ip, packet.ip_source().unwrap());
        assert_eq!(peeked.outer_dst_ip, packet.ip_destination().unwrap());
        assert_eq!(peeked.inner_src_mac, inner_eth.source());
        assert_eq!(peeked.inner_dst_mac, inner_eth.destination());
        assert!(!peeked.inner_vlan_tagged);
        assert_eq!(
            packet.headers(),
            &headers_before,
            "should not modify packet"
        );
    }

    #[test]
    fn vxlan_peek_detects_inner_vlan_tags() {
        let tagged = HeaderStack::new()
            .eth(|eth| {
                eth.set_ether_type(EthType::VLAN);
            })
            .vlan(|v| {
                v.set_vid(Vid::new(4000).unwrap());
            })
            .vlan(|v| {
                v.set_vid(Vid::new(100).unwrap());
            })
            .ipv4(|ip| {
                ip.set_source(UnicastIpv4Addr::new(Ipv4Addr::new(10, 0, 0, 5)).unwrap());
                ip.set_destination(Ipv4Addr::new(20, 0, 0, 5));
                ip.set_ttl(64);
            })
            .build_headers()
            .unwrap();
        let mut buffer = TestBuffer::new();
        tagged.deparse(buffer.as_mut()).unwrap();
        let inner_buf = Packet::new(buffer).unwrap().serialize().unwrap();
        let mut packet = build_test_vxlan_ipv4_packet_carrying_vni(
            Vni::new_checked(100).unwrap(),
            Dscp::new(0).unwrap(),
            Ecn::new(0).unwrap(),
            inner_buf.as_ref(),
        )
        .unwrap();

        let peeked = packet.vxlan_peek().unwrap().unwrap();
        assert!(peeked.inner_vlan_tagged);

        packet.vxlan_decap().unwrap().unwrap();
        assert_eq!(
            peeked.inner_vlan_tagged,
            !packet.headers().vlan().is_empty(),
            "peek and decap disagree on whether the inner frame is tagged"
        );
    }

    #[test]
    fn vxlan_peek_returns_ok_none_if_no_vxlan() {
        let packet = build_test_ipv4_packet(64).expect("Failed to build test packet");
        assert!(packet.vxlan_peek().is_ok_and(|r| r.is_none()));
    }

    #[test]
    fn vxlan_peek_fails_if_inner_packet_is_truncated() {
        let packet = build_test_vxlan_ipv4_packet_carrying_vni(
            Vni::new_checked(100).unwrap(),
            Dscp::new(0).unwrap(),
            Ecn::new(0).unwrap(),
            &[0u8; 6], // some garbage, less than an ethernet header
        )
        .expect("Failed to build test packet");
        assert!(packet.vxlan_peek().is_err());
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
            vlan: crate::headers::Stack::default(),
            net: Some(Net::Ipv4(ip)),
            net_ext: crate::headers::Stack::default(),
            transport: None,
            udp_encap: Some(UdpEncap::Vxlan(Vxlan::new(Vni::new_checked(200).unwrap()))),
            embedded_ip: None,
            lldp: None,
        };
        VxlanEncap::new(headers).unwrap()
    }

    fn make_vxlan_encap_headers_ipv6() -> VxlanEncap {
        let mut ip = crate::ipv6::Ipv6::default();
        ip.set_source(
            crate::ipv6::addr::UnicastIpv6Addr::new(crate::ipv6_doc!("::1").parse().unwrap())
                .unwrap(),
        );
        ip.set_destination(crate::ipv6_doc!("::2").parse().unwrap());
        ip.set_hop_limit(64);
        ip.set_next_header(crate::ip::NextHeader::UDP);

        let headers = Headers {
            eth: None,
            vlan: crate::headers::Stack::default(),
            net: Some(Net::Ipv6(ip)),
            net_ext: crate::headers::Stack::default(),
            transport: None,
            udp_encap: Some(UdpEncap::Vxlan(Vxlan::new(Vni::new_checked(200).unwrap()))),
            embedded_ip: None,
            lldp: None,
        };
        VxlanEncap::new(headers).unwrap()
    }

    #[test]
    fn decapsulation_hands_on_a_vlan_tag_it_was_given() {
        use crate::buffer::TestBuffer;
        use crate::eth::ethtype::EthType;
        use crate::headers::TryHeaders;
        use crate::headers::builder::HeaderStack;
        use crate::ipv4::UnicastIpv4Addr;
        use crate::packet::Packet;
        use crate::packet::test_utils::build_test_vxlan_ipv4_packet_carrying;
        use crate::parse::DeParse;
        use crate::vlan::Vid;
        use std::net::Ipv4Addr;

        let tagged = HeaderStack::new()
            .eth(|eth| {
                eth.set_ether_type(EthType::VLAN);
            })
            .vlan(|v| {
                v.set_vid(Vid::new(4000).unwrap());
            })
            .ipv4(|ip| {
                ip.set_source(UnicastIpv4Addr::new(Ipv4Addr::new(10, 0, 0, 5)).unwrap());
                ip.set_destination(Ipv4Addr::new(20, 0, 0, 5));
                ip.set_ttl(64);
            })
            .build_headers()
            .unwrap();
        let mut buffer = TestBuffer::new();
        tagged.deparse(buffer.as_mut()).unwrap();
        let inner = Packet::new(buffer).unwrap();
        let inner_buf = inner.serialize().unwrap();

        let mut outer = build_test_vxlan_ipv4_packet_carrying(
            Dscp::new(0).unwrap(),
            Ecn::new(0).unwrap(),
            inner_buf.as_ref(),
        )
        .unwrap();
        assert!(
            outer.headers().vlan().is_empty(),
            "the tunnel's own frame is untagged"
        );

        outer.vxlan_decap().unwrap().unwrap();
        assert_eq!(
            outer.headers().vlan().len(),
            1,
            "the inner frame's tag did not survive decapsulation, so nothing downstream can refuse it"
        );
        assert_eq!(outer.headers().vlan()[0].vid(), Vid::new(4000).unwrap());
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

    const MIN_ETHERNET_FRAME: usize = 60;

    pub(super) fn frame(protocol: u8, l4: &[u8]) -> Vec<u8> {
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

    pub(super) fn udp(payload: &[u8]) -> Vec<u8> {
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

    pub(super) fn tcp(payload: &[u8]) -> Vec<u8> {
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
            vlan: crate::headers::Stack::default(),
            net: Some(Net::Ipv4(ip)),
            net_ext: crate::headers::Stack::default(),
            transport: None,
            udp_encap: Some(UdpEncap::Vxlan(Vxlan::new(Vni::new_checked(42).unwrap()))),
            embedded_ip: None,
            lldp: None,
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

#[cfg(test)]
mod serialize_checksum_tests {
    //! What [`Packet::serialize`] does to checksums when forwarding: nothing it does not have to. An
    //! IPv4 header carries the error it arrived with through a TTL decrement, and a transport
    //! checksum is touched only when a stage asked for it.

    use super::padding_tests::{frame, tcp, udp};
    use crate::buffer::TestBuffer;
    use crate::checksum::Checksum;
    use crate::headers::{TryHeaders, TryHeadersMut, TryIp, TryIpv4, TryIpv4Mut, TryTcp};
    use crate::packet::Packet;
    use crate::tcp::TcpChecksumPayload;

    /// Where things sit in a [`frame`]: the IPv4 header after Ethernet, its checksum 10 octets in,
    /// and the transport checksum past the 20-octet IPv4 header, 16 octets into TCP or 6 into UDP.
    const IPV4: std::ops::Range<usize> = 14..34;
    const IPV4_CHECKSUM: usize = 14 + 10;
    const TCP_CHECKSUM: usize = 14 + 20 + 16;
    const UDP_CHECKSUM: usize = 14 + 20 + 6;

    /// One's-complement sum of `bytes` as 16-bit words, with both zeros read as `0xffff`.
    fn ones_complement_sum(bytes: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for word in bytes.as_chunks::<2>().0 {
            sum += u32::from(u16::from_be_bytes(*word));
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        #[allow(clippy::cast_possible_truncation)] // folded to 16 bits above
        match sum as u16 {
            0 => 0xffff,
            sum => sum,
        }
    }

    /// How far the IPv4 header in `frame` is from valid: the sum over the whole header, checksum
    /// included, which is `0xffff` for a valid header and something else for each wrong checksum.
    fn ipv4_error(frame: &[u8]) -> u16 {
        ones_complement_sum(&frame[IPV4])
    }

    /// A frame carrying `payload` over TCP or UDP, with the given IPv4 and transport checksums, or a
    /// valid IPv4 checksum if `ipv4_checksum` is `None`.
    fn input(payload: &[u8], is_udp: bool, ipv4_checksum: Option<u16>, transport: u16) -> Vec<u8> {
        let (mut bytes, at) = if is_udp {
            (frame(17, &udp(payload)), UDP_CHECKSUM)
        } else {
            (frame(6, &tcp(payload)), TCP_CHECKSUM)
        };
        bytes[at..at + 2].copy_from_slice(&transport.to_be_bytes());
        let ipv4_checksum = ipv4_checksum.unwrap_or_else(|| !ones_complement_sum(&bytes[IPV4]));
        bytes[IPV4_CHECKSUM..IPV4_CHECKSUM + 2].copy_from_slice(&ipv4_checksum.to_be_bytes());
        bytes
    }

    /// Forward `bytes` as a router does, decrementing the TTL, and serialize the result, asking for
    /// the transport checksum to be refreshed if `refresh`.
    fn forward(bytes: &[u8], refresh: bool) -> Vec<u8> {
        let mut packet =
            Packet::new(TestBuffer::from_raw_data(bytes)).expect("frame does not parse");
        packet
            .headers_mut()
            .try_ipv4_mut()
            .expect("no ipv4 header")
            .decrement_ttl()
            .expect("ttl already zero");
        if refresh {
            packet.meta_mut().set_checksum_refresh(true);
        }
        packet
            .serialize()
            .expect("does not serialize")
            .as_ref()
            .to_vec()
    }

    fn parse(bytes: &[u8]) -> Packet<TestBuffer> {
        Packet::new(TestBuffer::from_raw_data(bytes)).expect("output does not parse")
    }

    /// The TTL went down by one, and the IPv4 header is exactly as far from valid as it arrived:
    /// valid if it was, and not repaired if it was not.
    fn assert_ipv4_error_carried(input: &[u8], output: &[u8]) {
        let ipv4 = parse(output);
        let ipv4 = ipv4.headers().try_ipv4().expect("no ipv4 header");
        assert_eq!(ipv4.ttl(), 63, "the ttl was not decremented");
        assert_eq!(
            ipv4_error(output),
            ipv4_error(input),
            "the ipv4 header checksum was recomputed rather than adjusted for the ttl"
        );
        if ipv4_error(input) == 0xffff {
            ipv4.validate_checksum(&())
                .expect("a valid ipv4 header came out invalid");
        }
    }

    #[test]
    fn forwarding_changes_only_the_checksums_it_must() {
        // Arbitrary checksums, mostly wrong: refreshing one would read the whole payload, and
        // would make a packet corrupted before it reached us look intact.
        bolero::check!()
            .with_type::<(Vec<u8>, bool, Option<u16>, u16)>()
            .for_each(|(payload, is_udp, ipv4_checksum, transport)| {
                let payload = &payload[..payload.len().min(256)];
                let bytes = input(payload, *is_udp, *ipv4_checksum, *transport);
                let at = if *is_udp { UDP_CHECKSUM } else { TCP_CHECKSUM };

                let out = forward(&bytes, false);
                assert_eq!(
                    out[at..at + 2],
                    bytes[at..at + 2],
                    "serialize rewrote a transport checksum no stage asked it to"
                );
                assert_ipv4_error_carried(&bytes, &out);
            });
    }

    #[test]
    fn a_requested_refresh_recomputes_the_transport_checksum_only() {
        bolero::check!()
            .with_type::<(Vec<u8>, Option<u16>, u16)>()
            .for_each(|(payload, ipv4_checksum, transport)| {
                let payload = &payload[..payload.len().min(256)];
                let bytes = input(payload, false, *ipv4_checksum, *transport);

                let out = forward(&bytes, true);
                let parsed = parse(&out);
                let net = parsed.headers().try_ip().expect("no ip header").clone();
                parsed
                    .headers()
                    .try_tcp()
                    .expect("no tcp header")
                    .validate_checksum(&TcpChecksumPayload::new(&net, payload))
                    .expect("a requested refresh left the tcp checksum stale");
                assert_ipv4_error_carried(&bytes, &out);
            });
    }
}

#[cfg(test)]
mod roundtrip_tests {
    //! A packet leaves as it arrived, except for what a stage changed. Stages keep checksums
    //! current by folding in the words they change, so a header that came back different from how
    //! it arrived, even in bits the parsed headers have no field for, would leave with a checksum
    //! that no longer matches it.
    //!
    //! [`Datagram`] writes frames from arbitrary bytes, fixed up only where the parser insists:
    //! versions, lengths, protocol numbers, unicast sources and non-zero ports, first fragments so
    //! the transport parses, and ICMP types that quote the datagram they are about. Anything may
    //! follow the datagram in the frame.

    use crate::buffer::TestBuffer;
    use crate::headers::{TryHeaders, TryHeadersMut, TryIpv4Mut, TryIpv6Mut};
    use crate::packet::Packet;
    use bolero::TypeGenerator;

    const ETH: usize = 14;
    const TCP: u8 = 6;
    const UDP: u8 = 17;
    const ICMP4: u8 = 1;
    const ICMP6: u8 = 58;
    const VXLAN_PORT: u16 = 4789;

    #[derive(Debug, TypeGenerator)]
    struct Datagram {
        ip: Ip,
        transport: Transport,
        payload: Vec<u8>,
        /// What follows the datagram in the frame: padding, or a trailer.
        trailer: Vec<u8>,
    }

    #[derive(Debug, TypeGenerator)]
    enum Ip {
        V4 {
            header: [u8; 20],
            options: Vec<u8>,
        },
        V6 {
            header: [u8; 40],
            extensions: Vec<Extension>,
        },
    }

    #[derive(Debug, TypeGenerator)]
    enum Extension {
        /// Hop-by-hop options, routing, or destination options: 8 or 16 octets of anything.
        Raw {
            kind: u8,
            body: [u8; 14],
            long: bool,
        },
        Fragment([u8; 8]),
        /// An authentication header with up to three words of integrity check value.
        Auth {
            header: [u8; 24],
            words: u8,
        },
    }

    #[derive(Debug, TypeGenerator)]
    enum Transport {
        Tcp {
            header: [u8; 20],
            options: Vec<u8>,
        },
        Udp([u8; 8]),
        Vxlan {
            udp: [u8; 8],
            vxlan: [u8; 8],
        },
        /// An ICMP message for the IP version around it: an error quoting a datagram if `quoted`.
        Icmp {
            header: [u8; 8],
            quoted: Option<Quoted>,
        },
    }

    /// The start of the datagram an ICMP error is about.
    #[derive(Debug, TypeGenerator)]
    struct Quoted {
        ipv4: ([u8; 20], Vec<u8>),
        ipv6: ([u8; 40], Vec<Extension>),
        transport: QuotedTransport,
        /// Where the quote stops, if it stops inside the transport header.
        cut: Option<u8>,
        payload: Vec<u8>,
        /// How much longer the datagram was than the quote.
        missing: u8,
    }

    #[derive(Debug, TypeGenerator)]
    enum QuotedTransport {
        Tcp { header: [u8; 20], options: Vec<u8> },
        Udp([u8; 8]),
        Icmp([u8; 8]),
    }

    /// A frame, and where its transport header starts.
    struct Frame {
        bytes: Vec<u8>,
        transport: usize,
        /// Where the IP datagram ends, and the trailer starts.
        end: usize,
        protocol: u8,
        ipv6: bool,
        vxlan: bool,
        /// Whether the datagram is a fragment of a larger one.
        fragment: bool,
    }

    fn len16(len: usize) -> [u8; 2] {
        u16::try_from(len)
            .expect("test frames are small")
            .to_be_bytes()
    }

    fn nonzero_port(port: &mut [u8]) {
        if port == [0, 0] {
            port[1] = 1;
        }
    }

    fn ipv4_header(header: &[u8; 20], options: &[u8], protocol: u8, rest: usize) -> Vec<u8> {
        let options = &options[..options.len().min(40) / 4 * 4];
        let mut out = header.to_vec();
        out[0] = 0x45 + u8::try_from(options.len() / 4).expect("at most 10 words");
        out[2..4].copy_from_slice(&len16(20 + options.len() + rest));
        // Any flags, the reserved one included, but no fragment offset, so the transport parses.
        out[6] &= 0xe0;
        out[7] = 0;
        out[9] = protocol;
        out[12] = 10; // a unicast source
        out.extend_from_slice(options);
        out
    }

    fn ipv6_header(
        header: &[u8; 40],
        extensions: &[Extension],
        protocol: u8,
        rest: usize,
    ) -> Vec<u8> {
        let mut chain = Vec::new();
        let mut next = protocol;
        // Up to one more than there is room for, as often as none.
        for extension in extensions.iter().take(extensions.len() % 5).rev() {
            let (kind, mut bytes) = extension.write(next);
            bytes.append(&mut chain);
            chain = bytes;
            next = kind;
        }
        let mut out = header.to_vec();
        out[0] = 0x60 | (out[0] & 0x0f);
        out[4..6].copy_from_slice(&len16(chain.len() + rest));
        out[6] = next;
        if out[8] == 0xff {
            out[8] = 0xfe; // a unicast source
        }
        out.append(&mut chain);
        out
    }

    impl Extension {
        /// This header's protocol number, and its bytes with `next` as the next header.
        fn write(&self, next: u8) -> (u8, Vec<u8>) {
            match self {
                Extension::Raw { kind, body, long } => {
                    let kind = [0, 43, 60][usize::from(*kind) % 3];
                    let mut bytes = vec![next, u8::from(*long)];
                    bytes.extend_from_slice(&body[..if *long { 14 } else { 6 }]);
                    if kind == 43 {
                        // No segments left, so the destination is the final one.
                        bytes[3] = 0;
                    }
                    (kind, bytes)
                }
                Extension::Fragment(header) => {
                    let mut bytes = header.to_vec();
                    bytes[0] = next;
                    bytes[2] = 0;
                    bytes[3] &= 0x07; // the first fragment, so the transport parses
                    (44, bytes)
                }
                Extension::Auth { header, words } => {
                    let words = words % 4;
                    let mut bytes = header[..12 + 4 * usize::from(words)].to_vec();
                    bytes[0] = next;
                    bytes[1] = words + 1;
                    (51, bytes)
                }
            }
        }
    }

    fn tcp(header: &[u8; 20], options: &[u8]) -> Vec<u8> {
        let options = &options[..options.len().min(40) / 4 * 4];
        let mut out = header.to_vec();
        nonzero_port(&mut out[0..2]);
        nonzero_port(&mut out[2..4]);
        let words = u8::try_from(5 + options.len() / 4).expect("at most 15 words");
        out[12] = (words << 4) | (out[12] & 0x0f);
        out.extend_from_slice(options);
        out
    }

    fn udp(header: [u8; 8], rest: usize) -> Vec<u8> {
        let mut out = header.to_vec();
        nonzero_port(&mut out[0..2]);
        nonzero_port(&mut out[2..4]);
        if out[2..4] == VXLAN_PORT.to_be_bytes() {
            out[3] += 1;
        }
        out[4..6].copy_from_slice(&len16(8 + rest));
        out
    }

    /// An ICMP header, its type and code steered towards the ones that mean something.
    fn icmp(header: [u8; 8], ipv6: bool, error: bool) -> Vec<u8> {
        let mut out = header.to_vec();
        let types: &[u8] = match (ipv6, error) {
            (false, true) => &[3, 5, 11, 12],
            (true, true) => &[1, 2, 3, 4],
            (false, false) => &[0, 3, 5, 8, 11, 12, 13, 14],
            (true, false) => &[1, 2, 3, 4, 128, 129, 133, 134, 135, 136, 137],
        };
        if error || out[1] & 0x80 != 0 {
            out[0] = types[usize::from(out[0]) % types.len()];
            out[1] &= 0x0f;
        }
        out
    }

    impl QuotedTransport {
        fn write(&self, ipv6: bool) -> (u8, Vec<u8>) {
            match self {
                QuotedTransport::Tcp { header, options } => (TCP, tcp(header, options)),
                QuotedTransport::Udp(header) => (UDP, header.to_vec()),
                QuotedTransport::Icmp(header) => {
                    (if ipv6 { ICMP6 } else { ICMP4 }, icmp(*header, ipv6, false))
                }
            }
        }
    }

    impl Quoted {
        fn write(&self, ipv6: bool) -> Vec<u8> {
            let (protocol, mut transport) = self.transport.write(ipv6);
            let payload = match self.cut {
                Some(cut) if usize::from(cut) < transport.len() => {
                    transport.truncate(usize::from(cut));
                    &[][..]
                }
                _ => &self.payload[..self.payload.len().min(64)],
            };
            let rest = transport.len() + payload.len() + usize::from(self.missing);
            let mut out = if ipv6 {
                ipv6_header(&self.ipv6.0, &self.ipv6.1, protocol, rest)
            } else {
                ipv4_header(&self.ipv4.0, &self.ipv4.1, protocol, rest)
            };
            out.append(&mut transport);
            out.extend_from_slice(payload);
            out
        }
    }

    impl Datagram {
        fn frame(&self) -> Frame {
            let ipv6 = matches!(self.ip, Ip::V6 { .. });
            let payload = &self.payload[..self.payload.len().min(256)];
            let (protocol, mut segment) = match &self.transport {
                Transport::Tcp { header, options } => (TCP, tcp(header, options)),
                Transport::Udp(header) => (UDP, udp(*header, payload.len())),
                Transport::Vxlan { udp: header, vxlan } => {
                    let mut segment = udp(*header, 8 + payload.len());
                    segment[2..4].copy_from_slice(&VXLAN_PORT.to_be_bytes());
                    let mut vxlan = *vxlan;
                    vxlan[0] |= 0x08; // a VNI is present
                    vxlan[1..4].fill(0);
                    vxlan[7] = 0;
                    if vxlan[4..7] == [0, 0, 0] {
                        vxlan[6] = 1;
                    }
                    segment.extend_from_slice(&vxlan);
                    (UDP, segment)
                }
                Transport::Icmp { header, quoted } => {
                    let mut segment = icmp(*header, ipv6, quoted.is_some());
                    if let Some(quoted) = quoted {
                        segment.append(&mut quoted.write(ipv6));
                    }
                    (if ipv6 { ICMP6 } else { ICMP4 }, segment)
                }
            };
            segment.extend_from_slice(payload);
            let mut bytes = vec![2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2];
            bytes.extend_from_slice(if ipv6 { &[0x86, 0xdd] } else { &[0x08, 0x00] });
            bytes.append(&mut match &self.ip {
                Ip::V4 { header, options } => ipv4_header(header, options, protocol, segment.len()),
                Ip::V6 { header, extensions } => {
                    ipv6_header(header, extensions, protocol, segment.len())
                }
            });
            let transport = bytes.len();
            bytes.append(&mut segment);
            let end = bytes.len();
            bytes.extend_from_slice(&self.trailer[..self.trailer.len().min(16)]);
            let fragment = match &self.ip {
                Ip::V4 { .. } => bytes[ETH + 6] & 0x20 != 0,
                Ip::V6 { extensions, .. } => extensions
                    .iter()
                    .take(extensions.len() % 5)
                    .any(|extension| matches!(extension, Extension::Fragment(header) if header[3] & 1 != 0)),
            };
            Frame {
                bytes,
                transport,
                end,
                protocol,
                ipv6,
                vxlan: matches!(self.transport, Transport::Vxlan { .. }),
                fragment,
            }
        }
    }

    /// One's-complement sum of `bytes` as 16-bit words, an odd octet padded with zero, with both
    /// zeros read as `0xffff`.
    fn ones_complement_sum(bytes: &[u8]) -> u16 {
        let mut sum: u64 = 0;
        for word in bytes.chunks(2) {
            sum += u64::from(u16::from_be_bytes([
                word[0],
                word.get(1).copied().unwrap_or(0),
            ]));
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        match u16::try_from(sum).expect("folded to 16 bits") {
            0 => 0xffff,
            sum => sum,
        }
    }

    /// The sum over the transport checksum's coverage in `frame`, which is `0xffff` if the
    /// transport checksum is valid.
    fn transport_sum(frame: &Frame, bytes: &[u8]) -> u16 {
        let segment = &bytes[frame.transport..frame.end];
        let mut covered = Vec::new();
        if frame.ipv6 {
            covered.extend_from_slice(&bytes[ETH + 8..ETH + 40]);
            covered.extend_from_slice(&u32::try_from(segment.len()).expect("small").to_be_bytes());
            covered.extend_from_slice(&[0, 0, 0, frame.protocol]);
        } else if frame.protocol != ICMP4 {
            covered.extend_from_slice(&bytes[ETH + 12..ETH + 20]);
            covered.extend_from_slice(&[0, frame.protocol]);
            covered.extend_from_slice(&len16(segment.len()));
        }
        covered.extend_from_slice(segment);
        ones_complement_sum(&covered)
    }

    /// Where the transport checksum sits in `frame`.
    fn transport_checksum(frame: &Frame) -> std::ops::Range<usize> {
        let at = frame.transport
            + match frame.protocol {
                TCP => 16,
                UDP => 6,
                _ => 2,
            };
        at..at + 2
    }

    fn parse(bytes: &[u8]) -> Packet<TestBuffer> {
        Packet::new(TestBuffer::from_raw_data(bytes)).expect("frame does not parse")
    }

    fn serialize(packet: Packet<TestBuffer>) -> Vec<u8> {
        packet
            .serialize()
            .expect("does not serialize")
            .as_ref()
            .to_vec()
    }

    /// Decrement the TTL or hop limit, as a router does, and serialize, asking for the transport
    /// checksum to be refreshed if `refresh`. `None` if the TTL or hop limit is already zero.
    fn forward(bytes: &[u8], refresh: bool) -> Option<Vec<u8>> {
        let mut packet = parse(bytes);
        let headers = packet.headers_mut();
        let decremented = match headers.try_ipv4_mut() {
            Some(ipv4) => ipv4.decrement_ttl().is_ok(),
            None => headers
                .try_ipv6_mut()
                .expect("no ip header")
                .decrement_hop_limit()
                .is_ok(),
        };
        if !decremented {
            return None;
        }
        if refresh {
            packet.meta_mut().set_checksum_refresh(true);
        }
        Some(serialize(packet))
    }

    /// The offsets at which `a` and `b` differ, and any difference in length.
    fn differences(a: &[u8], b: &[u8]) -> Vec<usize> {
        let mut at: Vec<usize> = (0..a.len().min(b.len()))
            .filter(|&i| a[i] != b[i])
            .collect();
        at.extend(a.len().min(b.len())..a.len().max(b.len()));
        at
    }

    #[test]
    fn a_packet_no_stage_changed_leaves_as_it_arrived() {
        bolero::check!()
            .with_type::<Datagram>()
            .for_each(|datagram| {
                let frame = datagram.frame();
                let out = serialize(parse(&frame.bytes));
                assert!(
                    out == frame.bytes,
                    "octets {:?} changed: {:02x?} became {:02x?}",
                    differences(&frame.bytes, &out),
                    frame.bytes,
                    out
                );
            });
    }

    #[test]
    fn forwarding_changes_only_the_hop_count_and_the_ipv4_checksum() {
        bolero::check!()
            .with_type::<Datagram>()
            .for_each(|datagram| {
                let frame = datagram.frame();
                let Some(out) = forward(&frame.bytes, false) else {
                    return;
                };
                let allowed: &[usize] = if frame.ipv6 {
                    &[ETH + 7]
                } else {
                    &[ETH + 8, ETH + 10, ETH + 11]
                };
                let changed = differences(&frame.bytes, &out);
                assert!(
                    changed.iter().all(|at| allowed.contains(at)),
                    "octets {changed:?} changed: {:02x?} became {:02x?}",
                    frame.bytes,
                    out
                );
                if !frame.ipv6 {
                    let header = ETH..ETH + usize::from(frame.bytes[ETH] & 0x0f) * 4;
                    assert_eq!(
                        ones_complement_sum(&out[header.clone()]),
                        ones_complement_sum(&frame.bytes[header]),
                        "the ipv4 header is not exactly as far from valid as it arrived"
                    );
                }
            });
    }

    #[test]
    fn a_refreshed_checksum_covers_the_octets_as_written() {
        bolero::check!()
            .with_type::<Datagram>()
            .for_each(|datagram| {
                let frame = datagram.frame();
                // VXLAN's UDP checksum is left alone.
                if frame.vxlan {
                    return;
                }
                let (Some(forwarded), Some(refreshed)) =
                    (forward(&frame.bytes, false), forward(&frame.bytes, true))
                else {
                    return;
                };
                if parse(&frame.bytes).headers().transport().is_none() {
                    // Left in the payload: a header etherparse rejects (a timestamp of the
                    // wrong length), or one past extension headers there was no room for.
                    assert_eq!(
                        refreshed, forwarded,
                        "a refresh changed an unparsed transport"
                    );
                    return;
                }
                if frame.fragment {
                    // Its transport checksum covers octets this fragment does not hold.
                    assert_eq!(
                        refreshed, forwarded,
                        "a refresh recomputed a fragment's transport checksum"
                    );
                    // A skipped fragment refresh must leave the request pending.
                    let mut packet = parse(&frame.bytes);
                    packet.meta_mut().set_checksum_refresh(true);
                    packet.refresh_transport_checksum();
                    assert!(
                        packet.meta().checksum_refresh(),
                        "a refresh that did nothing cleared the request"
                    );
                    return;
                }
                assert_eq!(
                    refreshed.len(),
                    frame.bytes.len(),
                    "a refresh changed the length: {:02x?} became {refreshed:02x?}",
                    frame.bytes
                );
                assert_eq!(
                    transport_sum(&frame, &refreshed),
                    0xffff,
                    "the refreshed checksum does not match the octets written: {refreshed:02x?}"
                );
                let changed = differences(&forwarded, &refreshed);
                let checksum = transport_checksum(&frame);
                assert!(
                    changed.iter().all(|at| checksum.contains(at)),
                    "a refresh changed octets {changed:?} besides the checksum at {checksum:?}"
                );
            });
    }
}
