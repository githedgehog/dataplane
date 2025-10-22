// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::checksum::Checksum;
use crate::eth::EthError;
use crate::headers::{MAX_NET_EXTENSIONS, Net, NetExt};
use crate::icmp4::{Icmp4Checksum, TruncatedIcmp4};
use crate::icmp6::{Icmp6Checksum, TruncatedIcmp6};
use crate::impl_from_for_enum;
use crate::ip_auth::IpAuth;
use crate::ipv4::Ipv4;
use crate::ipv6::{Ipv6, Ipv6Ext};
use crate::parse::{
    DeParse, DeParseError, IllegalBufferLength, IntoNonZeroUSize, LengthError, ParseError,
    ParseHeader, ParseWith, Reader, Writer,
};
use crate::tcp::{TcpChecksum, TcpPort, TruncatedTcp};
#[cfg(any(test, feature = "bolero"))]
use crate::udp::Udp;
use crate::udp::{TruncatedUdp, UdpChecksum, UdpPort};
use arrayvec::ArrayVec;
use core::fmt::Debug;
use derive_builder::Builder;
use std::num::NonZero;
use tracing::debug;

#[cfg(any(test, feature = "bolero"))]
pub use contract::*;

pub enum EmbeddedIpVersion {
    Ipv4,
    Ipv6,
}

// Structure representing the set of headers for an IP packet embedded as the payload for an ICMP
// Error message. We need a dedicated struct and processing, because this packet may be truncated.
// RFC 792 stipulates that an ICMP Error message should embed an IP header and only a minimum of 64
// bits of the IP payload. Section 4.3.2.3 of RFC 1812 recommends an ICMP Error originator include
// as much of the original packet as possible in the payload, as long as the length of the resulting
// ICMP datagram does not exceed 576 bytes.
#[derive(Debug, PartialEq, Eq, Clone, Default, Builder)]
#[builder(default)]
pub struct EmbeddedHeaders {
    net: Option<Net>,
    net_ext: ArrayVec<NetExt, MAX_NET_EXTENSIONS>,
    transport: Option<EmbeddedTransport>,
    full_payload_length: Option<u16>,
}

impl EmbeddedHeaders {
    #[cfg(any(test, feature = "bolero"))]
    pub fn new(
        net: Option<Net>,
        transport: Option<EmbeddedTransport>,
        net_ext: ArrayVec<NetExt, MAX_NET_EXTENSIONS>,
        full_payload_length: Option<u16>,
    ) -> Self {
        Self {
            net,
            transport,
            net_ext,
            full_payload_length,
        }
    }

    #[cfg(any(test, feature = "bolero"))]
    pub fn set_network_payload_length(&mut self, payload_length: u16) -> Option<()> {
        match self.net {
            Some(Net::Ipv4(ref mut ipv4)) => ipv4.set_payload_len(payload_length).ok(),
            Some(Net::Ipv6(ref mut ipv6)) => {
                ipv6.set_payload_length(payload_length);
                Some(())
            }
            None => None,
        }
    }

    #[cfg(any(test, feature = "bolero"))]
    pub fn set_transport_payload_length(&mut self, payload_length: u16) -> Option<()> {
        match self.transport {
            Some(EmbeddedTransport::Udp(TruncatedUdp::FullHeader(ref mut udp))) => {
                #[allow(unsafe_code)] // We use a safe value >= Udp::MIN_LENGTH
                unsafe {
                    udp.set_length(
                        Udp::MIN_LENGTH
                            .get()
                            .checked_add(payload_length)
                            .and_then(NonZero::new)?,
                    );
                }
                Some(())
            }
            _ => None,
        }
    }

    pub fn net_headers_len(&self) -> u16 {
        self.net.as_ref().map(|net| net.size().get()).unwrap_or(0)
    }

    pub fn transport_headers_len(&self) -> u16 {
        self.transport
            .as_ref()
            .map(|transport| transport.size().get())
            .unwrap_or(0)
    }

    pub fn is_full_payload(&self) -> bool {
        self.full_payload_length.is_some()
    }

    pub fn payload_length(&self) -> Option<u16> {
        self.full_payload_length
    }

    pub fn check_full_payload(
        &mut self,
        buf: &[u8],
        remaining: usize,
        headers_size: usize,
        icmp_length: usize,
    ) {
        self.full_payload_length = None;

        match &mut self.transport {
            None
            | Some(EmbeddedTransport::Tcp(TruncatedTcp::PartialHeader(_)))
            | Some(EmbeddedTransport::Udp(TruncatedUdp::PartialHeader(_)))
            | Some(EmbeddedTransport::Icmp4(TruncatedIcmp4::PartialHeader(_)))
            | Some(EmbeddedTransport::Icmp6(TruncatedIcmp6::PartialHeader(_))) => {
                // We couldn't parse the full transport header, of course we don't have the full,
                // valid payload
                return;
            }
            Some(EmbeddedTransport::Tcp(TruncatedTcp::FullHeader(_)))
            | Some(EmbeddedTransport::Udp(TruncatedUdp::FullHeader(_)))
            | Some(EmbeddedTransport::Icmp4(TruncatedIcmp4::FullHeader(_)))
            | Some(EmbeddedTransport::Icmp6(TruncatedIcmp6::FullHeader(_))) => {
                // There's a chance payload is full, keep going
            }
        }

        // We want to compare the total size of the original IP packet with the length of the ICMP
        // payload, knowing that :
        //
        // Is size_ip_packet == size_icmp_payload?
        //
        // But for IPv6 we don't have the size of the full packet in the header, we need to sum up
        // the sizes of all headers and it's painful. Instead, let's use the length of data we've
        // consumed while parsing the ICMP payload. It covers the L3 + L4 headers. The check
        // becomes:
        //
        // Is size_ip_headers + size_ip_payload == size_icmp_payload?
        //
        // Where size_ip_headers is the length consumed, minus the length of the transport header.
        // So in the end, our final check is:
        //
        // Is size_headers_parsed - size_transport_header + size_ip_payload == size_icmp_payload?

        // Find the IP payload length
        let ip_payload_length = match &self.net {
            None => {
                return;
            }
            Some(Net::Ipv4(ip)) => {
                let Ok(ipv4_payload_length) = ip.0.payload_len().map(usize::from) else {
                    return;
                };
                ipv4_payload_length
            }
            Some(Net::Ipv6(ip)) => {
                let ipv6_payload_length = ip.0.payload_length;
                if ipv6_payload_length == 0 {
                    // IPv6 Jumbogram (RFC 2675) - we can't know the payload length and it's
                    // unlikely it's all in the ICMP message payload anyway.
                    return;
                }
                ipv6_payload_length as usize
            }
        };

        // Find the transport header length
        let transport_header_length = match &mut self.transport {
            Some(EmbeddedTransport::Tcp(TruncatedTcp::FullHeader(tcp))) => tcp.header_len().get(),
            Some(EmbeddedTransport::Udp(TruncatedUdp::FullHeader(_))) => 8,
            _ => unreachable!(), // Checked at the beginning of the function
        };

        // Compute the size of the IP headers
        let Some(size_ip_headers) = headers_size.checked_sub(transport_header_length) else {
            return;
        };

        if transport_header_length > ip_payload_length {
            // Transport header is too large to fit within the IP payload size we retrieved from the
            // headers, something is wrong
            return;
        }
        let full_packet_length = size_ip_headers + ip_payload_length;
        let transport_payload_length = ip_payload_length - transport_header_length;

        if icmp_length > 0 {
            // ICMP message may optionally contain the length of the embedded piece of the original
            // IP packet. If this is the case, we just need to check the announced IP packet length
            // against this value.
            //
            // From RFC 4884: The length attribute represents the length of the padded "original
            // datagram" field.
            match self.net {
                Some(Net::Ipv4(_)) => {
                    if icmp_length < full_packet_length {
                        // The embedded message is shorter than the original packet
                        return;
                    }
                    if icmp_length > buf.len() || !icmp_length.is_multiple_of(32) {
                        // Embedded payload is larger than our buffer? Or the size is not a multiple
                        // of 32? Something's wrong
                        return;
                    }
                    let padding_length = icmp_length - full_packet_length;
                    // ICMPv4: Padding is on 32-bit boundaries
                    if padding_length < 32
                        && buf[full_packet_length..icmp_length].iter().all(|b| *b == 0)
                    {
                        self.full_payload_length = Some(transport_payload_length as u16);
                    }
                    return;
                }
                Some(Net::Ipv6(_)) => {
                    if icmp_length < full_packet_length {
                        // The embedded message is shorter than the original packet
                        return;
                    }
                    if icmp_length > buf.len() || !icmp_length.is_multiple_of(64) {
                        // Embedded payload is larger than our buffer? Or the size is not a multiple
                        // of 64? Something's wrong
                        return;
                    }
                    let padding_length = icmp_length - full_packet_length;
                    // ICMPv6: Padding is on 64-bit boundaries
                    if padding_length < 64
                        && buf[full_packet_length..icmp_length].iter().all(|b| *b == 0)
                    {
                        self.full_payload_length = Some(transport_payload_length as u16);
                    }
                    return;
                }
                None => {
                    unreachable!() // Checked earlier in the function
                }
            }
        }

        // Check that the full headers + payload are present
        if full_packet_length == remaining {
            self.full_payload_length = Some(transport_payload_length as u16);
        }
    }
}

impl ParseWith for EmbeddedHeaders {
    type Error = EthError;
    type Param = EmbeddedIpVersion;

    fn parse_with(
        param: Self::Param,
        buf: &[u8],
    ) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        let mut cursor =
            Reader::new(buf).map_err(|IllegalBufferLength(len)| ParseError::BufferTooLong(len))?;
        let mut this = EmbeddedHeaders::default();
        let mut prior = match param {
            EmbeddedIpVersion::Ipv4 => {
                cursor
                    .parse_header::<Ipv4, EmbeddedHeader>()
                    .ok_or(ParseError::Length(LengthError {
                        expected: NonZero::new(1).unwrap_or_else(|| unreachable!()),
                        actual: 0,
                    }))?
            }
            EmbeddedIpVersion::Ipv6 => {
                cursor
                    .parse_header::<Ipv6, EmbeddedHeader>()
                    .ok_or(ParseError::Length(LengthError {
                        expected: NonZero::new(1).unwrap_or_else(|| unreachable!()),
                        actual: 0,
                    }))?
            }
        };
        loop {
            let header = prior.parse_payload(&mut cursor);
            match prior {
                EmbeddedHeader::Ipv4(ipv4) => {
                    this.net = Some(Net::Ipv4(ipv4));
                }
                EmbeddedHeader::Ipv6(ipv6) => {
                    this.net = Some(Net::Ipv6(ipv6));
                }
                EmbeddedHeader::IpAuth(auth) => {
                    this.net_ext.push(NetExt::IpAuth(auth));
                }
                EmbeddedHeader::IpV6Ext(ext) => {
                    this.net_ext.push(NetExt::Ipv6Ext(ext));
                }
                EmbeddedHeader::Tcp(tcp) => {
                    this.transport = Some(EmbeddedTransport::Tcp(tcp));
                }
                EmbeddedHeader::Udp(udp) => {
                    this.transport = Some(EmbeddedTransport::Udp(udp));
                }
            }
            match header {
                None => {
                    break;
                }
                Some(next) => {
                    prior = next;
                }
            }
        }
        #[allow(unsafe_code, clippy::cast_possible_truncation)] // Non zero checked by parse impl
        let consumed = unsafe {
            NonZero::new_unchecked((cursor.inner.len() - cursor.remaining as usize) as u16)
        };
        Ok((this, consumed))
    }
}

impl DeParse for EmbeddedHeaders {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        // TODO(blocking): Deal with ip{v4,v6} extensions
        NonZero::new(self.net_headers_len() + self.transport_headers_len())
            .unwrap_or_else(|| unreachable!())
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        // TODO(blocking): Deal with ip{v4,v6} extensions
        let len = buf.len();
        if len < self.size().into_non_zero_usize().get() {
            return Err(DeParseError::Length(LengthError {
                expected: self.size().into_non_zero_usize(),
                actual: len,
            }));
        }
        let mut cursor = Writer::new(buf)
            .map_err(|IllegalBufferLength(len)| DeParseError::BufferTooLong(len))?;
        match self.net {
            None => {
                #[allow(clippy::cast_possible_truncation)] // length bounded on cursor creation
                return Ok(
                    NonZero::new((cursor.inner.len() - cursor.remaining as usize) as u16)
                        .unwrap_or_else(|| unreachable!()),
                );
            }
            Some(ref net) => {
                cursor.write(net)?;
            }
        }

        match self.transport {
            None => {
                #[allow(clippy::cast_possible_truncation)] // length bounded on cursor creation
                return Ok(
                    NonZero::new((cursor.inner.len() - cursor.remaining as usize) as u16)
                        .unwrap_or_else(|| unreachable!()),
                );
            }
            Some(ref transport) => {
                cursor.write(transport)?;
            }
        }

        #[allow(clippy::cast_possible_truncation)] // length bounded on cursor creation
        Ok(
            NonZero::new((cursor.inner.len() - cursor.remaining as usize) as u16)
                .unwrap_or_else(|| unreachable!()),
        )
    }
}

// Header variants used for the potentially-truncated IP packet fragment embedded in an ICMP Error
// message
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EmbeddedHeader {
    Ipv4(Ipv4),
    Ipv6(Ipv6),
    Tcp(TruncatedTcp),
    Udp(TruncatedUdp),
    IpAuth(IpAuth),
    IpV6Ext(Ipv6Ext), // TODO: break out nested enum.  Nesting is counter productive here
}

impl EmbeddedHeader {
    fn parse_payload(&self, cursor: &mut Reader) -> Option<EmbeddedHeader> {
        use EmbeddedHeader::{IpAuth, IpV6Ext, Ipv4, Ipv6, Tcp, Udp};
        match self {
            Ipv4(ipv4) => ipv4
                .parse_embedded_payload(cursor)
                .map(EmbeddedHeader::from),
            Ipv6(ipv6) => ipv6
                .parse_embedded_payload(cursor)
                .map(EmbeddedHeader::from),
            IpAuth(auth) => auth
                .parse_embedded_payload(cursor)
                .map(EmbeddedHeader::from),
            IpV6Ext(ext) => {
                if let Ipv6(ipv6) = self {
                    ext.parse_embedded_payload(ipv6.next_header(), cursor)
                        .map(EmbeddedHeader::from)
                } else {
                    debug!("ipv6 extension header outside ipv6 header");
                    None
                }
            }
            Tcp(_) | Udp(_) => None,
        }
    }
}

impl_from_for_enum![
    EmbeddedHeader,
    Ipv4(Ipv4),
    Ipv6(Ipv6),
    Udp(TruncatedUdp),
    Tcp(TruncatedTcp),
    IpAuth(IpAuth),
    IpV6Ext(Ipv6Ext)
];

#[derive(Debug, thiserror::Error)]
pub enum EmbeddedHeaderError {
    #[error("No ports used by embedded transport header")]
    NoPorts,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmbeddedTransport {
    Tcp(TruncatedTcp),
    Udp(TruncatedUdp),
    Icmp4(TruncatedIcmp4),
    Icmp6(TruncatedIcmp6),
}

impl EmbeddedTransport {
    pub fn source(&self) -> Option<NonZero<u16>> {
        match self {
            EmbeddedTransport::Tcp(tcp) => Some(tcp.source().into()),
            EmbeddedTransport::Udp(udp) => Some(udp.source().into()),
            _ => None,
        }
    }

    pub fn destination(&self) -> Option<NonZero<u16>> {
        match self {
            EmbeddedTransport::Tcp(tcp) => Some(tcp.destination().into()),
            EmbeddedTransport::Udp(udp) => Some(udp.destination().into()),
            _ => None,
        }
    }

    pub fn set_source(&mut self, port: NonZero<u16>) -> Result<(), EmbeddedHeaderError> {
        match self {
            EmbeddedTransport::Tcp(tcp) => {
                tcp.set_source(TcpPort::new(port));
                Ok(())
            }
            EmbeddedTransport::Udp(udp) => {
                udp.set_source(UdpPort::new(port));
                Ok(())
            }
            _ => Err(EmbeddedHeaderError::NoPorts),
        }
    }

    pub fn set_destination(&mut self, port: NonZero<u16>) -> Result<(), EmbeddedHeaderError> {
        match self {
            EmbeddedTransport::Tcp(tcp) => {
                tcp.set_destination(TcpPort::new(port));
                Ok(())
            }
            EmbeddedTransport::Udp(udp) => {
                udp.set_destination(UdpPort::new(port));
                Ok(())
            }
            _ => Err(EmbeddedHeaderError::NoPorts),
        }
    }

    pub fn checksum(&self) -> Option<u16> {
        match self {
            EmbeddedTransport::Tcp(tcp) => tcp.checksum().map(u16::from),
            EmbeddedTransport::Udp(udp) => udp.checksum().map(u16::from),
            EmbeddedTransport::Icmp4(icmp) => icmp.checksum().map(u16::from),
            EmbeddedTransport::Icmp6(icmp) => icmp.checksum().map(u16::from),
        }
    }

    pub fn update_checksum(&mut self, current_checksum: u16, old_value: u16, new_value: u16) {
        match self {
            EmbeddedTransport::Tcp(tcp) => {
                // Silently ignore errors if transport header is truncated
                let _ = tcp.increment_update_checksum(
                    TcpChecksum::new(current_checksum),
                    old_value,
                    new_value,
                );
            }
            EmbeddedTransport::Udp(udp) => {
                // Silently ignore errors if transport header is truncated
                let _ = udp.increment_update_checksum(
                    UdpChecksum::new(current_checksum),
                    old_value,
                    new_value,
                );
            }
            EmbeddedTransport::Icmp4(icmp) => {
                // Silently ignore errors if transport header is truncated
                let _ = icmp.increment_update_checksum(
                    Icmp4Checksum::new(current_checksum),
                    old_value,
                    new_value,
                );
            }
            EmbeddedTransport::Icmp6(icmp) => {
                // Silently ignore errors if transport header is truncated
                let _ = icmp.increment_update_checksum(
                    Icmp6Checksum::new(current_checksum),
                    old_value,
                    new_value,
                );
            }
        }
    }
}

impl DeParse for EmbeddedTransport {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        match self {
            EmbeddedTransport::Tcp(tcp) => tcp.size(),
            EmbeddedTransport::Udp(udp) => udp.size(),
            EmbeddedTransport::Icmp4(icmp) => icmp.size(),
            EmbeddedTransport::Icmp6(icmp) => icmp.size(),
        }
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        match self {
            EmbeddedTransport::Tcp(tcp) => tcp.deparse(buf),
            EmbeddedTransport::Udp(udp) => udp.deparse(buf),
            EmbeddedTransport::Icmp4(icmp) => icmp.deparse(buf),
            EmbeddedTransport::Icmp6(icmp) => icmp.deparse(buf),
        }
    }
}

// AbstractEmbeddedHeaders, AbstractEmbeddedHeadersMut, and related traits

// IPv4 traits

pub trait TryInnerIpv4 {
    fn try_inner_ipv4(&self) -> Option<&Ipv4>;
}

pub trait TryInnerIpv4Mut {
    fn try_inner_ipv4_mut(&mut self) -> Option<&mut Ipv4>;
}

impl TryInnerIpv4 for EmbeddedHeaders {
    fn try_inner_ipv4(&self) -> Option<&Ipv4> {
        match &self.net {
            Some(Net::Ipv4(header)) => Some(header),
            _ => None,
        }
    }
}

impl TryInnerIpv4Mut for EmbeddedHeaders {
    fn try_inner_ipv4_mut(&mut self) -> Option<&mut Ipv4> {
        match &mut self.net {
            Some(Net::Ipv4(header)) => Some(header),
            _ => None,
        }
    }
}

// IPv6 traits

pub trait TryInnerIpv6 {
    fn try_inner_ipv6(&self) -> Option<&Ipv6>;
}

pub trait TryInnerIpv6Mut {
    fn try_inner_ipv6_mut(&mut self) -> Option<&mut Ipv6>;
}

impl TryInnerIpv6 for EmbeddedHeaders {
    fn try_inner_ipv6(&self) -> Option<&Ipv6> {
        match &self.net {
            Some(Net::Ipv6(header)) => Some(header),
            _ => None,
        }
    }
}

impl TryInnerIpv6Mut for EmbeddedHeaders {
    fn try_inner_ipv6_mut(&mut self) -> Option<&mut Ipv6> {
        match &mut self.net {
            Some(Net::Ipv6(header)) => Some(header),
            _ => None,
        }
    }
}

// IP version-agnostic traits

pub trait TryInnerIp {
    fn try_inner_ip(&self) -> Option<&Net>;
}

pub trait TryInnerIpMut {
    fn try_inner_ip_mut(&mut self) -> Option<&mut Net>;
}

impl TryInnerIp for EmbeddedHeaders {
    fn try_inner_ip(&self) -> Option<&Net> {
        self.net.as_ref()
    }
}

impl TryInnerIpMut for EmbeddedHeaders {
    fn try_inner_ip_mut(&mut self) -> Option<&mut Net> {
        self.net.as_mut()
    }
}

// TCP traits

pub trait TryTruncatedTcp {
    fn try_truncated_tcp(&self) -> Option<&TruncatedTcp>;
}

pub trait TryTruncatedTcpMut {
    fn try_truncated_tcp_mut(&mut self) -> Option<&mut TruncatedTcp>;
}

impl TryTruncatedTcp for EmbeddedHeaders {
    fn try_truncated_tcp(&self) -> Option<&TruncatedTcp> {
        match &self.transport {
            Some(EmbeddedTransport::Tcp(header)) => Some(header),
            _ => None,
        }
    }
}

impl TryTruncatedTcpMut for EmbeddedHeaders {
    fn try_truncated_tcp_mut(&mut self) -> Option<&mut TruncatedTcp> {
        match &mut self.transport {
            Some(EmbeddedTransport::Tcp(header)) => Some(header),
            _ => None,
        }
    }
}

// UDP traits

pub trait TryTruncatedUdp {
    fn try_truncated_udp(&self) -> Option<&TruncatedUdp>;
}

pub trait TryTruncatedUdpMut {
    fn try_truncated_udp_mut(&mut self) -> Option<&mut TruncatedUdp>;
}

impl TryTruncatedUdp for EmbeddedHeaders {
    fn try_truncated_udp(&self) -> Option<&TruncatedUdp> {
        match &self.transport {
            Some(EmbeddedTransport::Udp(header)) => Some(header),
            _ => None,
        }
    }
}

impl TryTruncatedUdpMut for EmbeddedHeaders {
    fn try_truncated_udp_mut(&mut self) -> Option<&mut TruncatedUdp> {
        match &mut self.transport {
            Some(EmbeddedTransport::Udp(header)) => Some(header),
            _ => None,
        }
    }
}

// ICMPv4 traits

pub trait TryTruncatedIcmp4 {
    fn try_truncated_icmp4(&self) -> Option<&TruncatedIcmp4>;
}

pub trait TryTruncatedIcmp4Mut {
    fn try_truncated_icmp4_mut(&mut self) -> Option<&mut TruncatedIcmp4>;
}

impl TryTruncatedIcmp4 for EmbeddedHeaders {
    fn try_truncated_icmp4(&self) -> Option<&TruncatedIcmp4> {
        match &self.transport {
            Some(EmbeddedTransport::Icmp4(header)) => Some(header),
            _ => None,
        }
    }
}

impl TryTruncatedIcmp4Mut for EmbeddedHeaders {
    fn try_truncated_icmp4_mut(&mut self) -> Option<&mut TruncatedIcmp4> {
        match &mut self.transport {
            Some(EmbeddedTransport::Icmp4(header)) => Some(header),
            _ => None,
        }
    }
}

// ICMPv6 traits

pub trait TryTruncatedIcmp6 {
    fn try_truncated_icmp6(&self) -> Option<&TruncatedIcmp6>;
}

pub trait TryTruncatedIcmp6Mut {
    fn try_truncated_icmp6_mut(&mut self) -> Option<&mut TruncatedIcmp6>;
}

impl TryTruncatedIcmp6 for EmbeddedHeaders {
    fn try_truncated_icmp6(&self) -> Option<&TruncatedIcmp6> {
        match &self.transport {
            Some(EmbeddedTransport::Icmp6(header)) => Some(header),
            _ => None,
        }
    }
}

impl TryTruncatedIcmp6Mut for EmbeddedHeaders {
    fn try_truncated_icmp6_mut(&mut self) -> Option<&mut TruncatedIcmp6> {
        match &mut self.transport {
            Some(EmbeddedTransport::Icmp6(header)) => Some(header),
            _ => None,
        }
    }
}

// Generic Transport traits

pub trait TryEmbeddedTransport {
    fn try_embedded_transport(&self) -> Option<&EmbeddedTransport>;
}

pub trait TryEmbeddedTransportMut {
    fn try_embedded_transport_mut(&mut self) -> Option<&mut EmbeddedTransport>;
}

impl TryEmbeddedTransport for EmbeddedHeaders {
    fn try_embedded_transport(&self) -> Option<&EmbeddedTransport> {
        self.transport.as_ref()
    }
}

impl TryEmbeddedTransportMut for EmbeddedHeaders {
    fn try_embedded_transport_mut(&mut self) -> Option<&mut EmbeddedTransport> {
        self.transport.as_mut()
    }
}

pub trait AbstractEmbeddedHeaders:
    Debug
    + TryInnerIpv4
    + TryInnerIpv6
    + TryInnerIp
    + TryTruncatedTcp
    + TryTruncatedUdp
    + TryTruncatedIcmp4
    + TryTruncatedIcmp6
    + TryEmbeddedTransport
    + DeParse
{
}

impl<T> AbstractEmbeddedHeaders for T where
    T: Debug
        + TryInnerIpv4
        + TryInnerIpv6
        + TryInnerIp
        + TryTruncatedTcp
        + TryTruncatedUdp
        + TryTruncatedIcmp4
        + TryTruncatedIcmp6
        + TryEmbeddedTransport
        + DeParse
{
}

pub trait AbstractEmbeddedHeadersMut:
    AbstractEmbeddedHeaders
    + TryInnerIpv4Mut
    + TryInnerIpv6Mut
    + TryInnerIpMut
    + TryTruncatedTcpMut
    + TryTruncatedUdpMut
    + TryTruncatedIcmp4Mut
    + TryTruncatedIcmp6Mut
    + TryEmbeddedTransportMut
{
}

impl<T> AbstractEmbeddedHeadersMut for T where
    T: AbstractEmbeddedHeaders
        + TryInnerIpv4Mut
        + TryInnerIpv6Mut
        + TryInnerIpMut
        + TryTruncatedTcpMut
        + TryTruncatedUdpMut
        + TryTruncatedIcmp4Mut
        + TryTruncatedIcmp6Mut
        + TryEmbeddedTransportMut
{
}

pub trait TryEmbeddedHeaders {
    fn embedded_headers(&self) -> Option<&impl AbstractEmbeddedHeaders>;
}

pub trait TryEmbeddedHeadersMut {
    fn embedded_headers_mut(&mut self) -> Option<&mut impl AbstractEmbeddedHeadersMut>;
}

impl<T> TryInnerIpv4 for T
where
    T: TryEmbeddedHeaders,
{
    fn try_inner_ipv4(&self) -> Option<&Ipv4> {
        self.embedded_headers()?.try_inner_ipv4()
    }
}

impl<T> TryInnerIpv6 for T
where
    T: TryEmbeddedHeaders,
{
    fn try_inner_ipv6(&self) -> Option<&Ipv6> {
        self.embedded_headers()?.try_inner_ipv6()
    }
}

impl<T> TryInnerIp for T
where
    T: TryEmbeddedHeaders,
{
    fn try_inner_ip(&self) -> Option<&Net> {
        self.embedded_headers()?.try_inner_ip()
    }
}

impl<T> TryTruncatedTcp for T
where
    T: TryEmbeddedHeaders,
{
    fn try_truncated_tcp(&self) -> Option<&TruncatedTcp> {
        self.embedded_headers()?.try_truncated_tcp()
    }
}

impl<T> TryTruncatedUdp for T
where
    T: TryEmbeddedHeaders,
{
    fn try_truncated_udp(&self) -> Option<&TruncatedUdp> {
        self.embedded_headers()?.try_truncated_udp()
    }
}

impl<T> TryTruncatedIcmp4 for T
where
    T: TryEmbeddedHeaders,
{
    fn try_truncated_icmp4(&self) -> Option<&TruncatedIcmp4> {
        self.embedded_headers()?.try_truncated_icmp4()
    }
}

impl<T> TryTruncatedIcmp6 for T
where
    T: TryEmbeddedHeaders,
{
    fn try_truncated_icmp6(&self) -> Option<&TruncatedIcmp6> {
        self.embedded_headers()?.try_truncated_icmp6()
    }
}

impl<T> TryEmbeddedTransport for T
where
    T: TryEmbeddedHeaders,
{
    fn try_embedded_transport(&self) -> Option<&EmbeddedTransport> {
        self.embedded_headers()?.try_embedded_transport()
    }
}

impl<T> TryInnerIpv4Mut for T
where
    T: TryEmbeddedHeadersMut,
{
    fn try_inner_ipv4_mut(&mut self) -> Option<&mut Ipv4> {
        self.embedded_headers_mut()?.try_inner_ipv4_mut()
    }
}

impl<T> TryInnerIpv6Mut for T
where
    T: TryEmbeddedHeadersMut,
{
    fn try_inner_ipv6_mut(&mut self) -> Option<&mut Ipv6> {
        self.embedded_headers_mut()?.try_inner_ipv6_mut()
    }
}

impl<T> TryInnerIpMut for T
where
    T: TryEmbeddedHeadersMut,
{
    fn try_inner_ip_mut(&mut self) -> Option<&mut Net> {
        self.embedded_headers_mut()?.try_inner_ip_mut()
    }
}

impl<T> TryTruncatedTcpMut for T
where
    T: TryEmbeddedHeadersMut,
{
    fn try_truncated_tcp_mut(&mut self) -> Option<&mut TruncatedTcp> {
        self.embedded_headers_mut()?.try_truncated_tcp_mut()
    }
}

impl<T> TryTruncatedUdpMut for T
where
    T: TryEmbeddedHeadersMut,
{
    fn try_truncated_udp_mut(&mut self) -> Option<&mut TruncatedUdp> {
        self.embedded_headers_mut()?.try_truncated_udp_mut()
    }
}

impl<T> TryTruncatedIcmp4Mut for T
where
    T: TryEmbeddedHeadersMut,
{
    fn try_truncated_icmp4_mut(&mut self) -> Option<&mut TruncatedIcmp4> {
        self.embedded_headers_mut()?.try_truncated_icmp4_mut()
    }
}

impl<T> TryTruncatedIcmp6Mut for T
where
    T: TryEmbeddedHeadersMut,
{
    fn try_truncated_icmp6_mut(&mut self) -> Option<&mut TruncatedIcmp6> {
        self.embedded_headers_mut()?.try_truncated_icmp6_mut()
    }
}

impl<T> TryEmbeddedTransportMut for T
where
    T: TryEmbeddedHeadersMut,
{
    fn try_embedded_transport_mut(&mut self) -> Option<&mut EmbeddedTransport> {
        self.embedded_headers_mut()?.try_embedded_transport_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{DeParse, ParseWith};
    use etherparse::{IpNumber, Ipv4Header, Ipv6Header, UdpHeader};

    // Test helper functions

    fn create_truncated_ipv4_tcp_packet() -> Vec<u8> {
        // Create a minimal IPv4 + TCP packet (truncated TCP with just ports)
        let mut ipv4_header = Ipv4Header::new(
            8,  // payload length (8 bytes of TCP)
            64, // ttl
            IpNumber::TCP,
            [192, 168, 1, 1],
            [192, 168, 1, 2],
        )
        .unwrap();
        ipv4_header.header_checksum = ipv4_header.calc_header_checksum();

        let mut buf = Vec::new();
        ipv4_header.write(&mut buf).unwrap();

        // Add TCP source and dest ports (minimal 4 bytes for truncated header)
        buf.extend_from_slice(&80u16.to_be_bytes()); // source port
        buf.extend_from_slice(&443u16.to_be_bytes()); // dest port
        // Add 4 more bytes to make 8 bytes total
        buf.extend_from_slice(&[0u8; 4]);

        buf
    }

    fn create_full_ipv4_udp_packet() -> Vec<u8> {
        // Create a minimal IPv4 + UDP packet
        let mut ipv4_header = Ipv4Header::new(
            8,  // payload length (8 bytes of UDP)
            64, // ttl
            IpNumber::UDP,
            [192, 168, 1, 1],
            [192, 168, 1, 2],
        )
        .unwrap();
        ipv4_header.header_checksum = ipv4_header.calc_header_checksum();

        let mut buf = Vec::new();
        ipv4_header.write(&mut buf).unwrap();

        // Add full UDP header (8 bytes)
        let udp_header = UdpHeader {
            source_port: 53,
            destination_port: 53,
            length: 8,
            checksum: 0,
        };
        udp_header.write(&mut buf).unwrap();

        buf
    }

    // Create a minimal IPv6 + TCP packet (truncated TCP with just ports)
    fn create_truncated_ipv6_tcp_packet() -> Vec<u8> {
        let ipv6_header = Ipv6Header {
            traffic_class: 0,
            flow_label: 0.try_into().unwrap(),
            payload_length: 8, // Just TCP ports + 4 bytes
            next_header: IpNumber::TCP,
            hop_limit: 64,
            source: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            destination: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        };

        let mut buf = Vec::new();
        ipv6_header.write(&mut buf).unwrap();

        // Add TCP source and dest ports (minimal 4 bytes for truncated header)
        buf.extend_from_slice(&80u16.to_be_bytes()); // source port
        buf.extend_from_slice(&443u16.to_be_bytes()); // dest port
        // Add 4 more bytes
        buf.extend_from_slice(&[0u8; 4]);

        buf
    }

    // Create a minimal IPv6 + UDP packet
    fn create_full_ipv6_udp_packet() -> Vec<u8> {
        let ipv6_header = Ipv6Header {
            traffic_class: 0,
            flow_label: 0.try_into().unwrap(),
            payload_length: 8, // Just UDP header
            next_header: IpNumber::UDP,
            hop_limit: 64,
            source: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            destination: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        };

        let mut buf = Vec::new();
        ipv6_header.write(&mut buf).unwrap();

        let udp_header = UdpHeader {
            source_port: 53,
            destination_port: 53,
            length: 8,
            checksum: 0,
        };
        udp_header.write(&mut buf).unwrap();

        buf
    }

    // Create IPv4 + full TCP header + 80 bytes payload
    fn create_full_ipv4_tcp_packet_with_payload() -> Vec<u8> {
        let mut ipv4_header = Ipv4Header::new(
            100, // payload length (20 bytes TCP + 80 bytes payload)
            64,  // ttl
            IpNumber::TCP,
            [192, 168, 1, 1],
            [192, 168, 1, 2],
        )
        .unwrap();
        ipv4_header.header_checksum = ipv4_header.calc_header_checksum();

        let mut buf = Vec::new();
        ipv4_header.write(&mut buf).unwrap();

        // Add full TCP header (20 bytes minimum)
        let tcp_header = etherparse::TcpHeader::new(80, 443, 1000, 0);
        tcp_header.write(&mut buf).unwrap();

        // Add 80 bytes fake payload
        buf.extend_from_slice(&[1u8; 80]);

        buf
    }

    // Basic parsing, deparsing checks

    #[test]
    fn test_parse_ipv4_with_truncated_tcp() {
        let buf = create_truncated_ipv4_tcp_packet();

        let result = EmbeddedHeaders::parse_with(EmbeddedIpVersion::Ipv4, &buf);
        assert!(
            result.is_ok(),
            "Failed to parse IPv4 with truncated TCP: {:?}",
            result.err()
        );

        let (headers, consumed) = result.unwrap();
        assert!(headers.net.is_some());
        assert!(headers.transport.is_some());
        assert_eq!(consumed.get(), buf.len() as u16);
    }

    #[test]
    fn test_parse_ipv4_with_full_udp() {
        let buf = create_full_ipv4_udp_packet();

        let result = EmbeddedHeaders::parse_with(EmbeddedIpVersion::Ipv4, &buf);
        assert!(
            result.is_ok(),
            "Failed to parse IPv4 with full UDP: {:?}",
            result.err()
        );

        let (headers, consumed) = result.unwrap();
        assert!(headers.net.is_some());
        assert!(headers.transport.is_some());
        assert_eq!(consumed.get(), buf.len() as u16);
    }

    #[test]
    fn test_parse_ipv6_with_truncated_tcp() {
        let buf = create_truncated_ipv6_tcp_packet();

        let result = EmbeddedHeaders::parse_with(EmbeddedIpVersion::Ipv6, &buf);
        assert!(
            result.is_ok(),
            "Failed to parse IPv6 with truncated TCP: {:?}",
            result.err()
        );

        let (headers, consumed) = result.unwrap();
        assert!(headers.net.is_some());
        assert!(headers.transport.is_some());
        assert_eq!(consumed.get(), buf.len() as u16);
    }

    #[test]
    fn test_parse_ipv6_with_full_udp() {
        let buf = create_full_ipv6_udp_packet();

        let result = EmbeddedHeaders::parse_with(EmbeddedIpVersion::Ipv6, &buf);
        assert!(
            result.is_ok(),
            "Failed to parse IPv6 with full UDP: {:?}",
            result.err()
        );

        let (headers, consumed) = result.unwrap();
        assert!(headers.net.is_some());
        assert!(headers.transport.is_some());
        assert_eq!(consumed.get(), buf.len() as u16);
    }

    #[test]
    fn test_deparse_roundtrip_ipv4_tcp() {
        let buf = create_truncated_ipv4_tcp_packet();

        let (headers, _) = EmbeddedHeaders::parse_with(EmbeddedIpVersion::Ipv4, &buf).unwrap();

        let mut out_buf = vec![0u8; 100];
        let written = headers.deparse(&mut out_buf).unwrap();

        assert_eq!(written.get() as usize, buf.len());
        assert_eq!(&out_buf[..buf.len()], &buf[..]);
    }

    #[test]
    fn test_deparse_roundtrip_ipv4_udp() {
        let buf = create_full_ipv4_udp_packet();

        let (headers, _) = EmbeddedHeaders::parse_with(EmbeddedIpVersion::Ipv4, &buf).unwrap();

        let mut out_buf = vec![0u8; 100];
        let written = headers.deparse(&mut out_buf).unwrap();

        assert_eq!(written.get() as usize, buf.len());
        assert_eq!(&out_buf[..buf.len()], &buf[..]);
    }

    #[test]
    fn test_deparse_roundtrip_ipv6_tcp() {
        let buf = create_truncated_ipv6_tcp_packet();

        let (headers, _) = EmbeddedHeaders::parse_with(EmbeddedIpVersion::Ipv6, &buf).unwrap();

        let mut out_buf = vec![0u8; 100];
        let written = headers.deparse(&mut out_buf).unwrap();

        assert_eq!(written.get() as usize, buf.len());
        assert_eq!(&out_buf[..buf.len()], &buf[..]);
    }

    #[test]
    fn test_deparse_roundtrip_ipv6_udp() {
        let buf = create_full_ipv6_udp_packet();

        let (headers, _) = EmbeddedHeaders::parse_with(EmbeddedIpVersion::Ipv6, &buf).unwrap();

        let mut out_buf = vec![0u8; 100];
        let written = headers.deparse(&mut out_buf).unwrap();

        assert_eq!(written.get() as usize, buf.len());
        assert_eq!(&out_buf[..buf.len()], &buf[..]);
    }

    // Edge cases

    #[test]
    fn test_parse_ipv4_only_no_transport() {
        // Create IPv4 header with no payload
        let mut ipv4_header = Ipv4Header::new(
            20, // total_len (just IPv4 header)
            64, // ttl
            IpNumber::TCP,
            [192, 168, 1, 1],
            [192, 168, 1, 2],
        )
        .unwrap();
        ipv4_header.header_checksum = ipv4_header.calc_header_checksum();

        let mut buf = Vec::new();
        ipv4_header.write(&mut buf).unwrap();

        let result = EmbeddedHeaders::parse_with(EmbeddedIpVersion::Ipv4, &buf);
        assert!(result.is_ok());

        let (headers, _) = result.unwrap();
        assert!(headers.net.is_some());
        assert!(headers.transport.is_none()); // No transport layer
    }

    #[test]
    fn test_parse_ipv6_only_no_transport() {
        // Create IPv6 header with no payload
        let ipv6_header = Ipv6Header {
            traffic_class: 0,
            flow_label: 0.try_into().unwrap(),
            payload_length: 0, // No payload
            next_header: IpNumber::TCP,
            hop_limit: 64,
            source: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            destination: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        };

        let mut buf = Vec::new();
        ipv6_header.write(&mut buf).unwrap();

        let result = EmbeddedHeaders::parse_with(EmbeddedIpVersion::Ipv6, &buf);
        assert!(result.is_ok());

        let (headers, _) = result.unwrap();
        assert!(headers.net.is_some());
        assert!(headers.transport.is_none()); // No transport layer
    }

    #[test]
    fn test_parse_too_short_buffer() {
        // Buffer too short to contain even an IPv4 header
        let buf = vec![0u8; 10];

        let result = EmbeddedHeaders::parse_with(EmbeddedIpVersion::Ipv4, &buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_buffer() {
        let buf = vec![];

        let result = EmbeddedHeaders::parse_with(EmbeddedIpVersion::Ipv4, &buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_size_calculation_ipv4_tcp() {
        let buf = create_truncated_ipv4_tcp_packet();
        let (headers, _) = EmbeddedHeaders::parse_with(EmbeddedIpVersion::Ipv4, &buf).unwrap();

        let size = headers.size();
        assert_eq!(size.get() as usize, buf.len());
    }

    #[test]
    fn test_size_calculation_ipv4_udp() {
        let buf = create_full_ipv4_udp_packet();
        let (headers, _) = EmbeddedHeaders::parse_with(EmbeddedIpVersion::Ipv4, &buf).unwrap();

        let size = headers.size();
        assert_eq!(size.get() as usize, buf.len());
    }

    #[test]
    fn test_size_calculation_ipv6_tcp() {
        let buf = create_truncated_ipv6_tcp_packet();
        let (headers, _) = EmbeddedHeaders::parse_with(EmbeddedIpVersion::Ipv6, &buf).unwrap();

        let size = headers.size();
        assert_eq!(size.get() as usize, buf.len());
    }

    #[test]
    fn test_deparse_buffer_too_small() {
        let buf = create_truncated_ipv4_tcp_packet();
        let (headers, _) = EmbeddedHeaders::parse_with(EmbeddedIpVersion::Ipv4, &buf).unwrap();

        let mut small_buf = vec![0u8; 10]; // Too small
        let result = headers.deparse(&mut small_buf);

        assert!(result.is_err());
    }

    #[test]
    fn test_default_embedded_headers() {
        let headers = EmbeddedHeaders::default();

        assert!(headers.net.is_none());
        assert!(headers.transport.is_none());
        assert!(!headers.is_full_payload());
        assert!(headers.payload_length().is_none());
    }

    #[test]
    fn test_clone_embedded_headers() {
        let buf = create_truncated_ipv4_tcp_packet();
        let (headers, _) = EmbeddedHeaders::parse_with(EmbeddedIpVersion::Ipv4, &buf).unwrap();

        let cloned = headers.clone();

        assert_eq!(headers, cloned);
    }

    #[test]
    fn test_parse_ipv4_with_minimal_tcp_ports_only() {
        // Create IPv4 + just 4 bytes of TCP (source and dest ports only)
        let mut ipv4_header = Ipv4Header::new(
            24, // total_len (20 IPv4 + 4 bytes TCP ports)
            64, // ttl
            IpNumber::TCP,
            [192, 168, 1, 1],
            [192, 168, 1, 2],
        )
        .unwrap();
        ipv4_header.header_checksum = ipv4_header.calc_header_checksum();

        let mut buf = Vec::new();
        ipv4_header.write(&mut buf).unwrap();

        // Add only TCP source and dest ports (4 bytes minimum)
        buf.extend_from_slice(&80u16.to_be_bytes()); // source port
        buf.extend_from_slice(&443u16.to_be_bytes()); // dest port

        let result = EmbeddedHeaders::parse_with(EmbeddedIpVersion::Ipv4, &buf);
        assert!(result.is_ok());

        let (headers, _) = result.unwrap();
        assert!(headers.net.is_some());
        assert!(headers.transport.is_some());
    }

    #[test]
    fn test_parse_ipv4_with_less_than_4_bytes_tcp() {
        // Create IPv4 + less than 4 bytes (should fail to parse transport)
        let mut ipv4_header = Ipv4Header::new(
            22, // total_len (20 IPv4 + 2 bytes - not enough for TCP)
            64, // ttl
            IpNumber::TCP,
            [192, 168, 1, 1],
            [192, 168, 1, 2],
        )
        .unwrap();
        ipv4_header.header_checksum = ipv4_header.calc_header_checksum();

        let mut buf = Vec::new();
        ipv4_header.write(&mut buf).unwrap();

        // Add only 2 bytes (not enough for truncated TCP)
        buf.extend_from_slice(&[0u8; 2]);

        let result = EmbeddedHeaders::parse_with(EmbeddedIpVersion::Ipv4, &buf);
        assert!(result.is_ok());

        let (headers, _) = result.unwrap();
        assert!(headers.net.is_some());
        assert!(headers.transport.is_none()); // Should fail to parse transport
    }

    // Checking whether payload is full

    #[test]
    fn test_check_full_payload_with_no_transport() {
        let mut headers = EmbeddedHeaders::default();
        let buf = vec![0u8; 100];

        headers.check_full_payload(&buf, 100, 20, 0);

        assert!(!headers.is_full_payload());
    }

    #[test]
    fn test_check_full_payload_with_partial_tcp_header() {
        let buf = create_truncated_ipv4_tcp_packet();
        let (mut headers, consumed) =
            EmbeddedHeaders::parse_with(EmbeddedIpVersion::Ipv4, &buf).unwrap();

        // With truncated TCP, full_payload should be false
        headers.check_full_payload(&buf, buf.len(), consumed.get() as usize, 0);

        // Since we only have 8 bytes of TCP (truncated), this should be false
        assert!(!headers.is_full_payload());
    }

    #[test]
    fn test_check_full_payload_incomplete_packet() {
        let buf = create_full_ipv4_tcp_packet_with_payload();
        let (mut headers, consumed) =
            EmbeddedHeaders::parse_with(EmbeddedIpVersion::Ipv4, &buf).unwrap();

        // Pass a smaller remaining size to simulate incomplete packet
        headers.check_full_payload(&buf, buf.len() - 10, consumed.get() as usize, 0);

        // Should be false because remaining doesn't match full_packet_size
        assert!(!headers.is_full_payload());
    }

    #[test]
    fn test_check_full_payload_with_icmp_extensions() {
        let mut buf = create_full_ipv4_tcp_packet_with_payload();

        // We need to pad on a 32-bit word boundary. We have 120 bytes (20 for the IP header, 20 for
        // the TCP header, 80 for the payload), add 8 to reach 128 bytes.
        buf.extend_from_slice(&[0u8; 8]);
        let icmp_payload_length = buf.len();

        // Add fake extension trailers
        buf.extend_from_slice(&[0x55u8; 32]);
        buf.extend_from_slice(&[0xffu8; 32]);

        let (mut headers, consumed) =
            EmbeddedHeaders::parse_with(EmbeddedIpVersion::Ipv4, &buf).unwrap();

        headers.check_full_payload(
            &buf,
            buf.len(),
            consumed.get() as usize,
            icmp_payload_length,
        );

        // Should be true because we have the full payload, as indicated by the length of the ICMP
        // payload
        assert!(headers.is_full_payload());
        assert_eq!(headers.payload_length(), Some(80));

        // Try again by passing a smaller value for the ICMP payload length, not a multiple of 32
        headers.check_full_payload(
            &buf,
            buf.len(),
            consumed.get() as usize,
            icmp_payload_length - 1,
        );
        assert!(!headers.is_full_payload());

        // Try again with a value too small for the ICMP payload length: a valid payload size, but
        // the padding area does not contain zeroed bytes
        headers.check_full_payload(
            &buf,
            buf.len(),
            consumed.get() as usize,
            icmp_payload_length - 32,
        );
        assert!(!headers.is_full_payload());

        // Try again with a value too large for the ICMP payload length
        headers.check_full_payload(
            &buf,
            buf.len(),
            consumed.get() as usize,
            icmp_payload_length + 32,
        );
        assert!(!headers.is_full_payload());
    }

    #[test]
    fn test_check_full_payload_ipv6_jumbogram() {
        // Create IPv6 header with payload_length = 0 (jumbogram)
        let ipv6_header = Ipv6Header {
            traffic_class: 0,
            flow_label: 0.try_into().unwrap(),
            payload_length: 0, // Jumbogram indicator
            next_header: IpNumber::TCP,
            hop_limit: 64,
            source: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            destination: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        };

        let mut buf = Vec::new();
        ipv6_header.write(&mut buf).unwrap();

        // Add full TCP header
        let tcp_header = etherparse::TcpHeader::new(80, 443, 1000, 0);
        tcp_header.write(&mut buf).unwrap();

        let (mut headers, consumed) =
            EmbeddedHeaders::parse_with(EmbeddedIpVersion::Ipv6, &buf).unwrap();

        // Jumbogram should result in full_payload = false
        headers.check_full_payload(&buf, buf.len(), consumed.get() as usize, 0);

        assert!(!headers.is_full_payload());
    }

    #[test]
    fn test_check_full_payload_size_mismatch() {
        let buf = create_full_ipv4_tcp_packet_with_payload();
        let (mut headers, consumed) =
            EmbeddedHeaders::parse_with(EmbeddedIpVersion::Ipv4, &buf).unwrap();

        // Pass wrong remaining size
        headers.check_full_payload(&buf, buf.len() - 10, consumed.get() as usize, 0);

        assert!(!headers.is_full_payload());
    }

    #[test]
    fn test_is_full_payload_initial_state() {
        let buf = create_truncated_ipv4_tcp_packet();
        let (headers, _) = EmbeddedHeaders::parse_with(EmbeddedIpVersion::Ipv4, &buf).unwrap();

        // Before calling check_full_payload, should be false
        assert!(!headers.is_full_payload());
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use super::*;
    use crate::headers::Net;
    use crate::ipv4;
    use crate::ipv6;
    use crate::tcp::TruncatedTcp;
    use crate::udp::TruncatedUdp;
    use bolero::{Driver, ValueGenerator};

    pub struct CommonEmbeddedHeaders;

    impl ValueGenerator for CommonEmbeddedHeaders {
        type Output = EmbeddedHeaders;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let (ipv4_next_header, ipv6_next_header, transport) = match driver.produce::<bool>()? {
                true => (
                    ipv4::CommonNextHeader::Tcp,
                    ipv6::CommonNextHeader::Tcp,
                    EmbeddedTransport::Tcp(driver.produce::<TruncatedTcp>()?),
                ),
                false => (
                    ipv4::CommonNextHeader::Udp,
                    ipv6::CommonNextHeader::Udp,
                    EmbeddedTransport::Udp(driver.produce::<TruncatedUdp>()?),
                ),
            };

            let is_ipv4 = driver.produce::<bool>()?;
            if is_ipv4 {
                let ipv4 = ipv4::GenWithNextHeader(ipv4_next_header.into()).generate(driver)?;
                let headers = EmbeddedHeaders {
                    net: Some(Net::Ipv4(ipv4)),
                    transport: Some(transport),
                    ..Default::default()
                };
                Some(headers)
            } else {
                let ipv6 = ipv6::GenWithNextHeader(ipv6_next_header.into()).generate(driver)?;
                let headers = EmbeddedHeaders {
                    net: Some(Net::Ipv6(ipv6)),
                    transport: Some(transport),
                    ..Default::default()
                };
                Some(headers)
            }
        }
    }
}

#[cfg(test)]
mod tests_fuzzing {
    use super::contract::CommonEmbeddedHeaders;
    use super::*;
    use crate::parse::{DeParse, DeParseError, IntoNonZeroUSize, ParseError, ParseWith};

    fn parse_back_test(headers: &EmbeddedHeaders, ip_version: EmbeddedIpVersion) {
        let mut buffer = [0_u8; 256];
        let bytes_written =
            match headers.deparse(&mut buffer[..headers.size().into_non_zero_usize().get()]) {
                Ok(written) => written,
                Err(DeParseError::Length(e)) => unreachable!("{e:?}", e = e),
                Err(DeParseError::Invalid(e)) => unreachable!("{e:?}", e = e),
                Err(DeParseError::BufferTooLong(_)) => unreachable!(),
            };
        let (parsed, bytes_parsed) = match EmbeddedHeaders::parse_with(
            ip_version,
            &buffer[..bytes_written.into_non_zero_usize().get()],
        ) {
            Ok(k) => k,
            Err(ParseError::Length(e)) => unreachable!("{e:?}", e = e),
            Err(ParseError::Invalid(e)) => unreachable!("{e:?}", e = e),
            Err(ParseError::BufferTooLong(_)) => unreachable!(),
        };
        assert_eq!(headers.net, parsed.net);
        assert_eq!(headers.transport, parsed.transport);
        assert_eq!(bytes_parsed, headers.size());
    }

    #[test]
    fn parse_back_common() {
        bolero::check!()
            .with_generator(CommonEmbeddedHeaders)
            .for_each(|headers: &EmbeddedHeaders| match &headers.net {
                Some(Net::Ipv4(_)) => parse_back_test(headers, EmbeddedIpVersion::Ipv4),
                Some(Net::Ipv6(_)) => parse_back_test(headers, EmbeddedIpVersion::Ipv6),
                None => {
                    unreachable!()
                }
            })
    }
}
