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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::TestBuffer;
    use crate::eth::ethtype::EthType;
    use crate::headers::{EmbeddedHeadersBuilder, Headers, HeadersBuilder, Net, Transport};
    use crate::icmp4::{Icmp4, Icmp4DestUnreachable, Icmp4EchoRequest, Icmp4Type};
    use crate::ip::NextHeader;
    use crate::ipv4::Ipv4;
    use crate::packet::Packet;
    use crate::packet::test_utils::make_default_for_eth;
    use crate::parse::DeParse;
    use crate::tcp::{Tcp, TcpPort};
    use std::net::Ipv4Addr;

    #[test]
    fn test_icmp_error_packet_no_network_layer() {
        // Build a packet without IP header
        let mut headers = HeadersBuilder::default();
        headers.eth(Some(make_default_for_eth(EthType::IPV4)));
        let headers = headers.build().unwrap();
        let mut buffer = TestBuffer::new();
        headers.deparse(buffer.as_mut()).unwrap();
        let packet = Packet::new(buffer).unwrap();

        let icmp_error_packet = IcmpErrorPacket::new(&packet);
        assert!(icmp_error_packet.is_none());
    }

    #[test]
    fn test_icmp_error_packet_no_transport_layer() {
        // Build a packet with IP but no transport
        let mut headers = HeadersBuilder::default();
        let mut ipv4 = Ipv4::default();
        ipv4.set_source(Ipv4Addr::new(1, 2, 3, 4).try_into().unwrap());
        ipv4.set_destination(Ipv4Addr::new(5, 6, 7, 8));
        headers.eth(Some(make_default_for_eth(EthType::IPV4)));
        headers.net(Some(Net::Ipv4(ipv4)));

        let headers = headers.build().unwrap();
        let mut buffer = TestBuffer::new();
        headers.deparse(buffer.as_mut()).unwrap();
        let packet = Packet::new(buffer).unwrap();

        let icmp_error_packet = IcmpErrorPacket::new(&packet);
        assert!(icmp_error_packet.is_none());
    }

    #[test]
    fn test_icmp_error_packet_not_icmp() {
        // Build a TCP packet
        let mut headers = HeadersBuilder::default();
        let mut ipv4 = Ipv4::default();
        ipv4.set_source(Ipv4Addr::new(1, 2, 3, 4).try_into().unwrap());
        ipv4.set_destination(Ipv4Addr::new(5, 6, 7, 8));
        ipv4.set_next_header(NextHeader::TCP);

        let tcp = Tcp::new(
            TcpPort::new_checked(1).unwrap(),
            TcpPort::new_checked(2).unwrap(),
        );

        headers.eth(Some(make_default_for_eth(EthType::IPV4)));
        headers.net(Some(Net::Ipv4(ipv4)));
        headers.transport(Some(Transport::Tcp(tcp)));

        let headers = headers.build().unwrap();
        let mut buffer = TestBuffer::new();
        headers.deparse(buffer.as_mut()).unwrap();
        let packet = Packet::new(buffer).unwrap();

        let icmp_error_packet = IcmpErrorPacket::new(&packet);
        assert!(icmp_error_packet.is_none());
    }

    #[test]
    fn test_icmp_error_packet_query_message() {
        // Build an ICMP Echo Request (query message)
        let mut headers = HeadersBuilder::default();
        let mut ipv4 = Ipv4::default();
        ipv4.set_source(Ipv4Addr::new(1, 2, 3, 4).try_into().unwrap());
        ipv4.set_destination(Ipv4Addr::new(5, 6, 7, 8));
        ipv4.set_next_header(NextHeader::ICMP);

        let icmp = Icmp4::with_type(Icmp4Type::EchoRequest(Icmp4EchoRequest { id: 1, seq: 1 }));
        headers.eth(Some(make_default_for_eth(EthType::IPV4)));
        headers.net(Some(Net::Ipv4(ipv4)));
        headers.transport(Some(Transport::Icmp4(icmp)));

        let headers = headers.build().unwrap();
        let mut buffer = TestBuffer::new();
        headers.deparse(buffer.as_mut()).unwrap();
        let packet = Packet::new(buffer).unwrap();

        let icmp_error_packet = IcmpErrorPacket::new(&packet);
        assert!(icmp_error_packet.is_none());
    }

    #[test]
    fn test_icmp_error_packet_no_embedded_headers() {
        // Build an ICMP error message without embedded headers
        let mut headers = HeadersBuilder::default();
        let mut ipv4 = Ipv4::default();
        ipv4.set_source(Ipv4Addr::new(1, 2, 3, 4).try_into().unwrap());
        ipv4.set_destination(Ipv4Addr::new(5, 6, 7, 8));
        ipv4.set_next_header(NextHeader::ICMP);

        let icmp = Icmp4::with_type(Icmp4Type::DestUnreachable(Icmp4DestUnreachable::Network));
        headers.eth(Some(make_default_for_eth(EthType::IPV4)));
        headers.net(Some(Net::Ipv4(ipv4)));
        headers.transport(Some(Transport::Icmp4(icmp)));

        let headers = headers.build().unwrap();
        let mut buffer = TestBuffer::new();
        headers.deparse(buffer.as_mut()).unwrap();
        let packet = Packet::new(buffer).unwrap();

        let icmp_error_packet = IcmpErrorPacket::new(&packet);
        assert!(icmp_error_packet.is_none());
    }

    #[test]
    fn test_icmp_error_packet_no_embedded_transport() {
        // Build an ICMP error message with embedded IP header, but no embedded transport
        let mut headers = HeadersBuilder::default();
        let mut embedded_headers = EmbeddedHeadersBuilder::default();

        let mut ipv4 = Ipv4::default();
        ipv4.set_source(Ipv4Addr::new(1, 2, 3, 4).try_into().unwrap());
        ipv4.set_destination(Ipv4Addr::new(5, 6, 7, 8));
        ipv4.set_next_header(NextHeader::ICMP);

        let mut inner_ipv4 = Ipv4::default();
        inner_ipv4.set_source(Ipv4Addr::new(10, 20, 30, 40).try_into().unwrap());
        inner_ipv4.set_destination(Ipv4Addr::new(50, 60, 70, 80));

        embedded_headers.net(Some(Net::Ipv4(inner_ipv4)));
        let embedded_headers = embedded_headers.build().unwrap();

        let icmp = Icmp4::with_type(Icmp4Type::DestUnreachable(Icmp4DestUnreachable::Network));
        headers.eth(Some(make_default_for_eth(EthType::IPV4)));
        headers.net(Some(Net::Ipv4(ipv4)));
        headers.transport(Some(Transport::Icmp4(icmp)));
        headers.embedded_ip(Some(embedded_headers));

        let headers = headers.build().unwrap();
        let mut buffer = TestBuffer::new();
        headers.deparse(buffer.as_mut()).unwrap();
        let packet = Packet::new(buffer).unwrap();

        let icmp_error_packet = IcmpErrorPacket::new(&packet);
        assert!(icmp_error_packet.is_none());
    }

    fn get_buffer_for_checksum_test(headers: &Headers) -> TestBuffer {
        // Fill the buffer with zeroes.
        //
        // This is for tests that build an ICMP Error message with no embedded packet fragment, and
        // validate its checksum. To do so, we prepare a packet by building the headers, setting the
        // checksum, then deparsing to a buffer. The checksum for ICMP is computed on the header and
        // the data, and when we set it (icmp.update_checksum(&[])), we pass a pointer to the data.
        // In such tests, there is no embedded packet fragment, so the data is null (&[]). When we
        // deparse the packet, we write the headers to a buffer: If we create the buffer with
        // TestBuffer::new(), it's not filled with zeroes, but with some data simulating some random
        // payload. Instead, create a buffer filled with zeroes, so that any trailing data does not
        // mess up with checksum computation.
        let data = vec![0u8; headers.size().get() as usize];
        TestBuffer::from_raw_data(&data)
    }

    #[test]
    fn test_icmp_error_packet_validate_checksums() {
        // Build an ICMP error message with embedded headers
        let mut headers = HeadersBuilder::default();
        let mut embedded_headers = EmbeddedHeadersBuilder::default();

        let mut ipv4 = Ipv4::default();
        ipv4.set_source(Ipv4Addr::new(1, 2, 3, 4).try_into().unwrap());
        ipv4.set_destination(Ipv4Addr::new(5, 6, 7, 8));
        ipv4.set_next_header(NextHeader::ICMP);

        let mut inner_ipv4 = Ipv4::default();
        inner_ipv4.set_source(Ipv4Addr::new(10, 20, 30, 40).try_into().unwrap());
        inner_ipv4.set_destination(Ipv4Addr::new(50, 60, 70, 80));
        inner_ipv4.set_next_header(NextHeader::TCP);
        inner_ipv4.update_checksum(&()).unwrap();

        let inner_tcp = Tcp::new(
            TcpPort::new_checked(1234).unwrap(),
            TcpPort::new_checked(5678).unwrap(),
        );
        embedded_headers.net(Some(Net::Ipv4(inner_ipv4)));
        embedded_headers.transport(Some(inner_tcp.into()));
        let embedded_headers = embedded_headers.build().unwrap();

        let mut icmp = Icmp4::with_type(Icmp4Type::DestUnreachable(Icmp4DestUnreachable::Network));
        icmp.update_checksum(&icmp.get_payload_for_checksum(Some(&embedded_headers), &[]))
            .unwrap();

        headers.eth(Some(make_default_for_eth(EthType::IPV4)));
        headers.net(Some(Net::Ipv4(ipv4)));
        headers.transport(Some(Transport::Icmp4(icmp)));
        headers.embedded_ip(Some(embedded_headers));

        let headers = headers.build().unwrap();
        let mut buffer = get_buffer_for_checksum_test(&headers);
        headers.deparse(buffer.as_mut()).unwrap();
        let packet = Packet::new(buffer).unwrap();

        let icmp_error_packet = IcmpErrorPacket::new(&packet).unwrap();
        icmp_error_packet.validate_checksums().unwrap();
    }
}
