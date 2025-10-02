// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::eth::EthError;
use crate::headers::{MAX_NET_EXTENSIONS, Net, NetExt};
use crate::impl_from_for_enum;
use crate::ip_auth::IpAuth;
use crate::ipv4::Ipv4;
use crate::ipv6::{Ipv6, Ipv6Ext};
use crate::parse::{
    DeParse, DeParseError, IllegalBufferLength, IntoNonZeroUSize, LengthError, ParseError,
    ParseHeader, ParsePayload, ParseWith, Reader, Writer,
};
use crate::tcp::TruncatedTcp;
use crate::udp::TruncatedUdp;
use arrayvec::ArrayVec;
use core::fmt::Debug;
use std::num::NonZero;
use tracing::debug;

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
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct EmbeddedHeaders {
    net: Option<Net>,
    net_ext: ArrayVec<NetExt, MAX_NET_EXTENSIONS>,
    transport: Option<EmbeddedTransport>,
    full_payload: bool,
}

impl EmbeddedHeaders {
    pub fn is_full_payload(&self) -> bool {
        self.full_payload
    }

    pub fn check_full_payload(
        &mut self,
        buf: &[u8],
        remaining: usize,
        headers_size: usize,
        icmp_length: usize,
    ) {
        self.full_payload = false;

        match &mut self.transport {
            None
            | Some(EmbeddedTransport::Tcp(TruncatedTcp::PartialHeader(_)))
            | Some(EmbeddedTransport::Udp(TruncatedUdp::PartialHeader(_))) => {
                // We couldn't parse the full transport header, of course we don't have the full,
                // valid payload
                return;
            }
            Some(EmbeddedTransport::Tcp(TruncatedTcp::FullHeader(_)))
            | Some(EmbeddedTransport::Udp(TruncatedUdp::FullHeader(_))) => {
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

        let full_packet_size = size_ip_headers + ip_payload_length;

        if icmp_length > 0 {
            // ICMP message may optionally contain the length of the embedded piece of the original
            // IP packet. If this is the case, we just need to check the announced IP packet length
            // against this value.
            //
            // From RFC 4884: The length attribute represents the length of the padded "original
            // datagram" field.
            match self.net {
                Some(Net::Ipv4(_)) => {
                    if icmp_length < full_packet_size {
                        // The embedded message is shorter than the original packet
                        return;
                    }
                    if icmp_length > buf.len() || !icmp_length.is_multiple_of(32) {
                        // Embedded payload is larger than our buffer? Or the size is not a multiple
                        // of 32? Something's wrong
                        return;
                    }
                    let padding_length = icmp_length - full_packet_size;
                    // ICMPv4: Padding is on 32-bit boundaries
                    self.full_payload = padding_length < 32
                        && buf[full_packet_size..icmp_length].iter().all(|b| *b == 0);
                    return;
                }
                Some(Net::Ipv6(_)) => {
                    if icmp_length < full_packet_size {
                        // The embedded message is shorter than the original packet
                        return;
                    }
                    if icmp_length > buf.len() || !icmp_length.is_multiple_of(64) {
                        // Embedded payload is larger than our buffer? Or the size is not a multiple
                        // of 64? Something's wrong
                        return;
                    }
                    let padding_length = icmp_length - full_packet_size;
                    // ICMPv6: Padding is on 64-bit boundaries
                    self.full_payload = padding_length < 64
                        && buf[full_packet_size..icmp_length].iter().all(|b| *b == 0);
                    return;
                }
                None => {
                    unreachable!() // Checked earlier in the function
                }
            }
        }

        // Check that the full headers + payload are present
        self.full_payload = full_packet_size == remaining;
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
        let net = match self.net {
            None => 0,
            Some(ref n) => n.size().get(),
        };
        let transport = match self.transport {
            None => 0,
            Some(ref t) => t.size().get(),
        };
        NonZero::new(net + transport).unwrap_or_else(|| unreachable!())
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

impl ParsePayload for EmbeddedHeader {
    type Next = EmbeddedHeader;

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

#[derive(Debug, Clone, PartialEq, Eq)]
enum EmbeddedTransport {
    Tcp(TruncatedTcp),
    Udp(TruncatedUdp),
}

impl DeParse for EmbeddedTransport {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        match self {
            EmbeddedTransport::Tcp(tcp) => tcp.size(),
            EmbeddedTransport::Udp(udp) => udp.size(),
        }
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        match self {
            EmbeddedTransport::Tcp(tcp) => tcp.deparse(buf),
            EmbeddedTransport::Udp(udp) => udp.deparse(buf),
        }
    }
}
