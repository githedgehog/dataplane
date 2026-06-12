// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! View a packet as an ICMP Error message with an embedded IP packet fragment.

use crate::checksum::{Checksum, ChecksumError};
use crate::headers::{
    EmbeddedTransport, Net, TryEmbeddedHeaders, TryEmbeddedTransport, TryIcmpAny, TryInnerIp, TryIp,
};
use crate::icmp_any::{IcmpAny, IcmpAnyChecksumErrorPlaceholder, IcmpAnyChecksumPayload};
use crate::ipv4::Ipv4;
use crate::packet::{Packet, PacketBufferMut};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
/// Errors that can occur when validating an ICMP error message.
pub enum IcmpErrorPacketError {
    /// The ICMP checksum is not valid.
    #[error("failed to validate ICMP checksum")]
    BadChecksumIcmp(ChecksumError<IcmpAnyChecksumErrorPlaceholder>),
    /// The inner IPv4 checksum is not valid.
    #[error("failed to validate ICMP inner IP checksum")]
    BadChecksumInnerIpv4(ChecksumError<Ipv4>),
}

/// A view of a packet as an ICMP error message with an embedded IP packet fragment.
pub struct IcmpErrorPacket<'a> {
    net: &'a Net,
    icmp: IcmpAny<'a>,
    icmp_payload: Vec<u8>,
    inner_net: &'a Net,
    inner_transport: &'a EmbeddedTransport,
}

impl<'a> IcmpErrorPacket<'a> {
    /// Tries to view the given packet as an ICMP error message with an embedded IP packet fragment.
    pub fn new<Buf: PacketBufferMut>(packet: &'a Packet<Buf>) -> Option<Self> {
        let net = packet.try_ip()?;
        let icmp = packet.try_icmp_any()?;
        let inner_net = packet.try_inner_ip()?;
        let inner_transport = packet.try_embedded_transport()?;
        let icmp_payload = icmp
            .get_payload_for_checksum(Some(packet.embedded_headers()?), packet.payload().as_ref());
        Some(Self {
            net,
            icmp,
            icmp_payload,
            inner_net,
            inner_transport,
        })
    }

    /// The IP header for the embedded packet fragment that caused the ICMP error message to be
    /// generated.
    #[must_use]
    pub fn inner_net(&self) -> &'a Net {
        self.inner_net
    }

    /// The transport header of the embedded packet fragment that caused the ICMP error message to
    /// be generated.
    #[must_use]
    pub fn inner_transport(&self) -> &'a EmbeddedTransport {
        self.inner_transport
    }

    fn checksum_payload(&'a self) -> IcmpAnyChecksumPayload<'a> {
        IcmpAnyChecksumPayload::from_net(self.net, &self.icmp_payload)
    }

    /// Validates the checksums of the ICMP error message and the embedded IP packet fragment.
    ///
    /// # Errors
    ///
    /// - If the ICMP checksum is not valid, returns `IcmpErrorPacketError::BadChecksumIcmp`.
    /// - If the inner IPv4 checksum is not valid, returns
    ///   `IcmpErrorPacketError::BadChecksumInnerIpv4`.
    pub fn validate_checksums(&self) -> Result<(), IcmpErrorPacketError> {
        self.icmp
            .validate_checksum(&self.checksum_payload())
            .map_err(|e| IcmpErrorPacketError::BadChecksumIcmp(e.into()))?;

        if let Net::Ipv4(inner_ipv4) = self.inner_net {
            inner_ipv4
                .validate_checksum(&())
                .map_err(IcmpErrorPacketError::BadChecksumInnerIpv4)?;
        }
        Ok(())
    }
}
