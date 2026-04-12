// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Definition of [`Headers`] and related methods and types.
#![allow(missing_docs)] // temporary

use crate::checksum::Checksum;
use crate::eth::ethtype::EthType;
use crate::eth::{Eth, EthError};
use crate::icmp_any::{IcmpAny, IcmpAnyMut};
use crate::icmp4::Icmp4;
use crate::icmp6::{Icmp6, Icmp6ChecksumPayload};
use crate::impl_from_for_enum;
use crate::ip::{NextHeader, UnicastIpAddr};
use crate::ip_auth::{Ipv4Auth, Ipv6Auth};
use crate::ipv4::Ipv4;
use crate::ipv6::{DestOpts, Fragment, HopByHop, Ipv6, Routing};
use crate::parse::{
    DeParse, DeParseError, IllegalBufferLength, IntoNonZeroUSize, LengthError, Parse, ParseError,
    Reader, Writer,
};
use crate::tcp::{Tcp, TcpChecksumPayload, TcpPort};
use crate::udp::{Udp, UdpChecksumPayload, UdpEncap, UdpPort};
use crate::vlan::{Pcp, Vid, Vlan};
use crate::vxlan::Vxlan;
use arrayvec::ArrayVec;
use core::fmt::Debug;
use derive_builder::Builder;
use std::net::IpAddr;
use std::num::NonZero;
use tracing::{debug, trace};

#[cfg(any(test, feature = "bolero"))]
pub use contract::*;

#[macro_use]
mod accessor_macros;

mod embedded;
pub use embedded::*;

#[cfg(any(test, feature = "builder"))]
pub mod builder;

const MAX_VLANS: usize = 4;
const MAX_NET_EXTENSIONS: usize = 3;

/// A parsed set of network packet headers.
///
/// Fields are crate-private to restrict direct external construction.
/// Use the [`HeadersBuilder`] (via `derive_builder`) for construction
/// and the public accessor methods for reading.
#[derive(Debug, PartialEq, Eq, Clone, Default, Builder)]
#[builder(default)]
pub struct Headers {
    pub(crate) eth: Option<Eth>,
    pub(crate) vlan: ArrayVec<Vlan, MAX_VLANS>,
    pub(crate) net: Option<Net>,
    pub(crate) net_ext: ArrayVec<NetExt, MAX_NET_EXTENSIONS>,
    pub(crate) transport: Option<Transport>,
    pub(crate) udp_encap: Option<UdpEncap>,
    pub(crate) embedded_ip: Option<EmbeddedHeaders>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetError {
    #[error("invalid IP version")]
    InvalidIpVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Net {
    Ipv4(Ipv4),
    Ipv6(Ipv6),
}

impl Net {
    #[must_use]
    pub fn dst_addr(&self) -> IpAddr {
        match self {
            Net::Ipv4(ip) => IpAddr::V4(ip.destination()),
            Net::Ipv6(ip) => IpAddr::V6(ip.destination()),
        }
    }

    #[must_use]
    pub fn src_addr(&self) -> IpAddr {
        match self {
            Net::Ipv4(ip) => IpAddr::V4(ip.source().inner()),
            Net::Ipv6(ip) => IpAddr::V6(ip.source().inner()),
        }
    }

    #[must_use]
    pub fn next_header(&self) -> NextHeader {
        match self {
            Net::Ipv4(ip) => ip.protocol(),
            Net::Ipv6(ip) => ip.next_header(),
        }
    }

    /// Sets the source address of the network header.
    ///
    /// # Errors
    ///
    /// Returns [`NetError::InvalidIpVersion`] if the IP version of `addr` does not match the
    /// IP version of the network header.
    pub fn try_set_source(&mut self, addr: UnicastIpAddr) -> Result<(), NetError> {
        match (self, addr) {
            (Net::Ipv4(ip), UnicastIpAddr::V4(addr)) => {
                ip.set_source(addr);
            }
            (Net::Ipv6(ip), UnicastIpAddr::V6(addr)) => {
                ip.set_source(addr);
            }
            _ => {
                return Err(NetError::InvalidIpVersion);
            }
        }
        Ok(())
    }

    /// Sets the destination address of the network header.
    ///
    /// # Errors
    ///
    /// Returns [`NetError::InvalidIpVersion`] if the IP version of `addr` does not match the
    /// IP version of the network header.
    pub fn try_set_destination(&mut self, addr: IpAddr) -> Result<(), NetError> {
        match (self, addr) {
            (Net::Ipv4(ip), IpAddr::V4(addr)) => {
                ip.set_destination(addr);
            }
            (Net::Ipv6(ip), IpAddr::V6(addr)) => {
                ip.set_destination(addr);
            }
            _ => {
                return Err(NetError::InvalidIpVersion);
            }
        }
        Ok(())
    }
}

impl DeParse for Net {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        match self {
            Net::Ipv4(ip) => ip.size(),
            Net::Ipv6(ip) => ip.size(),
        }
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        match self {
            Net::Ipv4(ip) => ip.deparse(buf),
            Net::Ipv6(ip) => ip.deparse(buf),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetExt {
    /// IPv6 Hop-by-Hop Options (RFC 8200 section 4.3).
    HopByHop(HopByHop),
    /// IPv6 Destination Options (RFC 8200 section 4.6).
    DestOpts(DestOpts),
    /// IPv6 Routing Header (RFC 8200 section 4.4).
    Routing(Routing),
    /// IPv6 Fragment Header (RFC 8200 section 4.5).
    Fragment(Fragment),
    /// IP Authentication Header in IPv4 context (RFC 4302).
    Ipv4Auth(Ipv4Auth),
    /// IP Authentication Header in IPv6 context (RFC 4302).
    Ipv6Auth(Ipv6Auth),
}

impl DeParse for NetExt {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        match self {
            NetExt::HopByHop(h) => h.size(),
            NetExt::DestOpts(h) => h.size(),
            NetExt::Routing(h) => h.size(),
            NetExt::Fragment(h) => h.size(),
            NetExt::Ipv4Auth(h) => h.size(),
            NetExt::Ipv6Auth(h) => h.size(),
        }
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        match self {
            NetExt::HopByHop(h) => h.deparse(buf),
            NetExt::DestOpts(h) => h.deparse(buf),
            NetExt::Routing(h) => h.deparse(buf),
            NetExt::Fragment(h) => h.deparse(buf),
            NetExt::Ipv4Auth(h) => h.deparse(buf),
            NetExt::Ipv6Auth(h) => h.deparse(buf),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    #[error("transport protocol does not use ports")]
    UnsupportedPort,
    #[error("transport protocol does not use identifier")]
    UnsupportedIdentifier,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    Tcp(Tcp),
    Udp(Udp),
    Icmp4(Icmp4),
    Icmp6(Icmp6),
}

impl Net {
    pub(crate) fn update_checksum(&mut self) {
        match self {
            Net::Ipv4(ip) => {
                ip.update_checksum(&()).unwrap_or_else(|()| unreachable!()); // Updating IPv4 checksum never fails
            }
            Net::Ipv6(_) => {}
        }
    }
}

impl Transport {
    pub(crate) fn update_checksum(
        &mut self,
        net: &Net,
        embedded_headers: Option<&EmbeddedHeaders>,
        payload: impl AsRef<[u8]>,
    ) {
        match (net, self) {
            (net, Transport::Tcp(tcp)) => {
                tcp.update_checksum(&TcpChecksumPayload::new(net, payload.as_ref()))
                    .unwrap_or_else(|()| unreachable!()); // Updating TCP checksum never fails
            }
            (net, Transport::Udp(udp)) => {
                udp.update_checksum(&UdpChecksumPayload::new(net, payload.as_ref()))
                    .unwrap_or_else(|()| unreachable!()); // Updating UDP checksum never fails
            }
            (Net::Ipv4(_), Transport::Icmp4(icmp4)) => {
                if icmp4.is_error_message() && embedded_headers.is_some() {
                    let checksum_payload =
                        icmp4.get_payload_for_checksum(embedded_headers, payload.as_ref());
                    icmp4
                        .update_checksum(checksum_payload.as_ref())
                        .unwrap_or_else(|()| unreachable!()); // Updating ICMPv4 checksum never fails
                } else {
                    icmp4
                        .update_checksum(payload.as_ref())
                        .unwrap_or_else(|()| unreachable!()); // Updating ICMPv4 checksum never fails
                }
            }
            (Net::Ipv6(ip), Transport::Icmp6(icmp6)) => {
                if icmp6.is_error_message() && embedded_headers.is_some() {
                    let checksum_payload =
                        icmp6.get_payload_for_checksum(embedded_headers, payload.as_ref());
                    icmp6
                        .update_checksum(&Icmp6ChecksumPayload::new(
                            ip.source().inner(),
                            ip.destination(),
                            checksum_payload.as_ref(),
                        ))
                        .unwrap_or_else(|()| unreachable!()); // Updating ICMPv6 checksum never fails
                } else {
                    icmp6
                        .update_checksum(&Icmp6ChecksumPayload::new(
                            ip.source().inner(),
                            ip.destination(),
                            payload.as_ref(),
                        ))
                        .unwrap_or_else(|()| unreachable!()); // Updating ICMPv6 checksum never fails
                }
            }
            // TODO: statically ensure that this is unreachable
            (Net::Ipv6(_), Transport::Icmp4(_)) => debug!("illegal: icmpv4 in ipv6"),
            (Net::Ipv4(_), Transport::Icmp6(_)) => debug!("illegal: icmpv6 in ipv4"),
        }
    }

    pub(crate) fn size(&self) -> NonZero<u16> {
        match self {
            Transport::Tcp(tcp) => tcp.size(),
            Transport::Udp(udp) => udp.size(),
            Transport::Icmp4(icmp4) => icmp4.size(),
            Transport::Icmp6(icmpv6) => icmpv6.size(),
        }
    }

    /// Returns the source port of the transport header.
    ///
    /// # Returns
    ///
    /// Returns `None` if the transport protocol does not use ports.
    #[must_use]
    pub fn src_port(&self) -> Option<NonZero<u16>> {
        match self {
            Transport::Tcp(tcp) => Some(tcp.source().into()),
            Transport::Udp(udp) => Some(udp.source().into()),
            _ => None,
        }
    }

    /// Returns the destination port of the transport header.
    ///
    /// # Returns
    ///
    /// Returns `None` if the transport protocol does not use ports.
    #[must_use]
    pub fn dst_port(&self) -> Option<NonZero<u16>> {
        match self {
            Transport::Tcp(tcp) => Some(tcp.destination().into()),
            Transport::Udp(udp) => Some(udp.destination().into()),
            _ => None,
        }
    }

    /// Returns the identifier of the transport header.
    ///
    /// # Returns
    ///
    /// Returns `None` if the transport protocol does not use identifiers.
    #[must_use]
    pub fn identifier(&self) -> Option<u16> {
        match self {
            Transport::Icmp4(icmp4) => icmp4.identifier(),
            Transport::Icmp6(icmp6) => icmp6.identifier(),
            _ => None,
        }
    }

    /// Sets the source port of the transport header.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::UnsupportedPort`] if the transport protocol does not use ports.
    pub fn try_set_source(&mut self, port: NonZero<u16>) -> Result<(), TransportError> {
        match self {
            Transport::Tcp(tcp) => {
                tcp.set_source(TcpPort::new(port));
            }
            Transport::Udp(udp) => {
                udp.set_source(UdpPort::new(port));
            }
            _ => {
                return Err(TransportError::UnsupportedPort);
            }
        }
        Ok(())
    }

    /// Sets the destination port of the transport header.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::UnsupportedPort`] if the transport protocol does not use ports.
    pub fn try_set_destination(&mut self, port: NonZero<u16>) -> Result<(), TransportError> {
        match self {
            Transport::Tcp(tcp) => {
                tcp.set_destination(TcpPort::new(port));
            }
            Transport::Udp(udp) => {
                udp.set_destination(UdpPort::new(port));
            }
            _ => {
                return Err(TransportError::UnsupportedPort);
            }
        }
        Ok(())
    }

    /// Sets the ICMP identifier field.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::UnsupportedIdentifier`] if the transport header does not
    /// support identifiers (i.e., TCP or UDP).
    pub fn try_set_identifier(&mut self, identifier: u16) -> Result<(), TransportError> {
        match self {
            Transport::Icmp4(icmp4) => icmp4
                .try_set_identifier(identifier)
                .map_err(|_| TransportError::UnsupportedIdentifier),
            Transport::Icmp6(icmp6) => icmp6
                .try_set_identifier(identifier)
                .map_err(|_| TransportError::UnsupportedIdentifier),
            _ => Err(TransportError::UnsupportedIdentifier),
        }
    }
}

impl DeParse for Transport {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        match self {
            Transport::Tcp(x) => x.size(),
            Transport::Udp(x) => x.size(),
            Transport::Icmp4(x) => x.size(),
            Transport::Icmp6(x) => x.size(),
        }
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        match self {
            Transport::Tcp(x) => x.deparse(buf),
            Transport::Udp(x) => x.deparse(buf),
            Transport::Icmp4(x) => x.deparse(buf),
            Transport::Icmp6(x) => x.deparse(buf),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Header {
    Eth(Eth),
    Vlan(Vlan),
    Ipv4(Ipv4),
    Ipv6(Ipv6),
    Tcp(Tcp),
    Udp(Udp),
    Icmp4(Icmp4),
    Icmp6(Icmp6),
    HopByHop(HopByHop),
    DestOpts(DestOpts),
    Routing(Routing),
    Fragment(Fragment),
    Ipv4Auth(Ipv4Auth),
    Ipv6Auth(Ipv6Auth),
    Encap(UdpEncap),
    EmbeddedIp(EmbeddedHeaders),
}

impl Header {
    fn parse_payload(&self, cursor: &mut Reader) -> Option<Header> {
        match self {
            Header::Eth(eth) => eth.parse_payload(cursor).map(Header::from),
            Header::Vlan(vlan) => vlan.parse_payload(cursor).map(Header::from),
            Header::Ipv4(ipv4) => ipv4.parse_payload(cursor).map(Header::from),
            Header::Ipv6(ipv6) => ipv6.parse_payload(cursor).map(Header::from),
            Header::Ipv4Auth(auth) => auth.parse_payload(cursor),
            Header::Ipv6Auth(auth) => auth.parse_payload(cursor),
            Header::HopByHop(h) => h.parse_payload(cursor),
            Header::DestOpts(h) => h.parse_payload(cursor),
            Header::Routing(h) => h.parse_payload(cursor),
            Header::Fragment(h) => h.parse_payload(cursor),
            Header::Icmp4(icmp4) => icmp4.parse_payload(cursor).map(Header::from),
            Header::Icmp6(icmp6) => icmp6.parse_payload(cursor).map(Header::from),
            Header::Udp(udp) => udp.parse_payload(cursor).map(Header::from),
            Header::Encap(_) | Header::Tcp(_) | Header::EmbeddedIp(_) => None,
        }
    }
}

impl Parse for Headers {
    type Error = EthError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        let mut cursor =
            Reader::new(buf).map_err(|IllegalBufferLength(len)| ParseError::BufferTooLong(len))?;
        let (eth, _) = cursor.parse::<Eth>()?;
        let mut this = Headers {
            eth: Some(eth.clone()),
            net: None,
            transport: None,
            vlan: ArrayVec::default(),
            net_ext: ArrayVec::default(),
            udp_encap: None,
            embedded_ip: None,
        };
        // TODO: after parsing, validate RFC 8200 section 4.1 extension header
        // ordering constraints (e.g. HopByHop must be first and appear at most
        // once, DestOpts may appear at most twice, etc.).  The parser currently
        // accepts any ordering from the wire.  A validate() method or post-parse
        // check would catch malformed chains without rejecting packets outright.
        //
        // TODO: consider returning a parse error instead of silently stopping
        // when MAX_NET_EXTENSIONS is exceeded.  The current `break` exits the
        // entire parse loop, so transport and embedded headers that follow the
        // overflow point are also not parsed.  This matches the MAX_VLANS
        // handling but the caller has no way to detect a partial parse.
        let mut prior = Header::Eth(eth);
        loop {
            let header = prior.parse_payload(&mut cursor);
            match prior {
                Header::Eth(eth) => this.eth = Some(eth),
                Header::Ipv4(ip) => this.net = Some(Net::Ipv4(ip)),
                Header::Ipv6(ip) => this.net = Some(Net::Ipv6(ip)),
                Header::Tcp(tcp) => this.transport = Some(Transport::Tcp(tcp)),
                Header::Udp(udp) => this.transport = Some(Transport::Udp(udp)),
                Header::Icmp4(icmp4) => this.transport = Some(Transport::Icmp4(icmp4)),
                Header::Icmp6(icmp6) => this.transport = Some(Transport::Icmp6(icmp6)),
                Header::Encap(encap) => this.udp_encap = Some(encap),
                Header::Vlan(vlan) => {
                    if this.vlan.len() < MAX_VLANS {
                        this.vlan.push(vlan);
                    } else {
                        break;
                    }
                }
                Header::HopByHop(h) => {
                    if this.net_ext.len() < MAX_NET_EXTENSIONS {
                        this.net_ext.push(NetExt::HopByHop(h));
                    } else {
                        break;
                    }
                }
                Header::DestOpts(h) => {
                    if this.net_ext.len() < MAX_NET_EXTENSIONS {
                        this.net_ext.push(NetExt::DestOpts(h));
                    } else {
                        break;
                    }
                }
                Header::Routing(h) => {
                    if this.net_ext.len() < MAX_NET_EXTENSIONS {
                        this.net_ext.push(NetExt::Routing(h));
                    } else {
                        break;
                    }
                }
                Header::Fragment(h) => {
                    if this.net_ext.len() < MAX_NET_EXTENSIONS {
                        this.net_ext.push(NetExt::Fragment(h));
                    } else {
                        break;
                    }
                }
                Header::Ipv4Auth(h) => {
                    if this.net_ext.len() < MAX_NET_EXTENSIONS {
                        this.net_ext.push(NetExt::Ipv4Auth(h));
                    } else {
                        break;
                    }
                }
                Header::Ipv6Auth(h) => {
                    if this.net_ext.len() < MAX_NET_EXTENSIONS {
                        this.net_ext.push(NetExt::Ipv6Auth(h));
                    } else {
                        break;
                    }
                }
                Header::EmbeddedIp(embedded) => this.embedded_ip = Some(embedded),
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

impl DeParse for Headers {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        let eth = self.eth.as_ref().map_or(0, |x| x.size().get());
        let vlan = self.vlan.iter().map(|v| v.size().get()).sum::<u16>();
        let (net, net_ext) = match self.net {
            None => {
                debug_assert!(self.transport.is_none());
                debug_assert!(
                    self.net_ext.is_empty(),
                    "net_ext headers present without a net header"
                );
                (0, 0)
            }
            Some(ref n) => {
                let net_ext: u16 = self.net_ext.iter().map(|e| e.size().get()).sum();
                (n.size().get(), net_ext)
            }
        };
        let transport = match self.transport {
            None => 0,
            Some(ref t) => t.size().get(),
        };
        let encap = match self.udp_encap {
            None => 0,
            Some(UdpEncap::Vxlan(vx)) => vx.size().get(),
        };
        let embedded_ip = self
            .embedded_ip
            .as_ref()
            .map_or(0, |embedded_header| embedded_header.size().get());
        NonZero::new(eth + vlan + net + net_ext + transport + encap + embedded_ip)
            .unwrap_or_else(|| unreachable!())
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        let len = buf.len();
        if len < self.size().into_non_zero_usize().get() {
            return Err(DeParseError::Length(LengthError {
                expected: self.size().into_non_zero_usize(),
                actual: len,
            }));
        }
        let mut cursor = Writer::new(buf)
            .map_err(|IllegalBufferLength(len)| DeParseError::BufferTooLong(len))?;
        match &self.eth {
            None => {}
            Some(eth) => {
                cursor.write(eth)?;
            }
        }
        for vlan in &self.vlan {
            cursor.write(vlan)?;
        }
        match self.net {
            None => {
                debug_assert!(self.transport.is_none());
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

        for ext in &self.net_ext {
            cursor.write(ext)?;
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

        if let Some(UdpEncap::Vxlan(ref vxlan)) = self.udp_encap {
            if matches!(self.transport, Some(Transport::Udp(_))) {
                cursor.write(vxlan)?;
            } else {
                return Err(DeParseError::Invalid(()));
            }
        }

        if let Some(ref embedded_ip) = self.embedded_ip {
            if matches!(
                self.transport,
                Some(Transport::Icmp4(_) | Transport::Icmp6(_))
            ) {
                cursor.write(embedded_ip)?;
            } else {
                return Err(DeParseError::Invalid(()));
            }
        }

        #[allow(clippy::cast_possible_truncation)] // length bounded on cursor creation
        Ok(
            NonZero::new((cursor.inner.len() - cursor.remaining as usize) as u16)
                .unwrap_or_else(|| unreachable!()),
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PushVlanError {
    #[error("can't push vlan without an ethernet header")]
    NoEthernetHeader,
    #[error("Header already has as many VLAN headers as parser can support (max is {MAX_VLANS})")]
    TooManyVlans,
}

#[derive(Debug, thiserror::Error)]
pub enum PopVlanError {
    #[error("can't pop vlan without an ethernet header")]
    NoEthernetHeader,
}

impl Headers {
    /// Create a new [`Headers`] with the supplied `Eth` header.
    #[must_use]
    pub fn new() -> Headers {
        Headers::default()
    }

    /// Add / Replace Ethernet header
    pub fn set_eth(&mut self, eth: Eth) {
        self.eth = Some(eth);
    }

    // ---- public read accessors ----

    /// Get a reference to the Ethernet header, if present.
    #[must_use]
    pub fn eth(&self) -> Option<&Eth> {
        self.eth.as_ref()
    }

    /// Get a mutable reference to the Ethernet header, if present.
    #[must_use]
    pub fn eth_mut(&mut self) -> Option<&mut Eth> {
        self.eth.as_mut()
    }

    /// Get a reference to the VLAN header stack.
    #[must_use]
    pub fn vlan(&self) -> &ArrayVec<Vlan, MAX_VLANS> {
        &self.vlan
    }

    /// Get a reference to the network (IP) header, if present.
    #[must_use]
    pub fn net(&self) -> Option<&Net> {
        self.net.as_ref()
    }

    /// Get a mutable reference to the network (IP) header, if present.
    #[must_use]
    pub fn net_mut(&mut self) -> Option<&mut Net> {
        self.net.as_mut()
    }

    /// Get a reference to the network extension headers (e.g. IPv6 extensions,
    /// IP Authentication headers).
    #[must_use]
    pub fn net_ext(&self) -> &ArrayVec<NetExt, MAX_NET_EXTENSIONS> {
        &self.net_ext
    }

    /// Get a reference to the transport header, if present.
    #[must_use]
    pub fn transport(&self) -> Option<&Transport> {
        self.transport.as_ref()
    }

    /// Get a mutable reference to the transport header, if present.
    #[must_use]
    pub fn transport_mut(&mut self) -> Option<&mut Transport> {
        self.transport.as_mut()
    }

    /// Replace the network (IP) header, returning the previous value.
    pub fn set_net(&mut self, net: Option<Net>) -> Option<Net> {
        std::mem::replace(&mut self.net, net)
    }

    /// Replace the transport header, returning the previous value.
    pub fn set_transport(&mut self, transport: Option<Transport>) -> Option<Transport> {
        std::mem::replace(&mut self.transport, transport)
    }

    /// Replace the UDP encapsulation header, returning the previous value.
    pub fn set_udp_encap(&mut self, udp_encap: Option<UdpEncap>) -> Option<UdpEncap> {
        std::mem::replace(&mut self.udp_encap, udp_encap)
    }

    /// Get a reference to the UDP encapsulation header, if present.
    #[must_use]
    pub fn udp_encap(&self) -> Option<&UdpEncap> {
        self.udp_encap.as_ref()
    }

    /// Get a mutable reference to the UDP encapsulation header, if present.
    #[must_use]
    pub fn udp_encap_mut(&mut self) -> Option<&mut UdpEncap> {
        self.udp_encap.as_mut()
    }

    /// Get a reference to the embedded IP headers, if present.
    ///
    /// Embedded IP headers appear inside ICMP error messages, which contain a
    /// (potentially truncated) copy of the original offending packet.
    #[must_use]
    pub fn embedded_ip(&self) -> Option<&EmbeddedHeaders> {
        self.embedded_ip.as_ref()
    }

    /// Get a mutable reference to the embedded IP headers, if present.
    #[must_use]
    pub fn embedded_ip_mut(&mut self) -> Option<&mut EmbeddedHeaders> {
        self.embedded_ip.as_mut()
    }

    /// Push a VLAN header to the top of the stack.
    ///
    /// # Errors:
    ///
    /// Will return a [`TooManyVlans`] error if there are already more VLANs in the stack than are
    /// supported in this configuration of the parser.
    /// See [`MAX_VLANS`].
    ///
    /// # Safety:
    ///
    /// This method will create an invalid [`Headers`] if the header you push has an _inner_ ethtype
    /// which does not align with the next header below it.
    ///
    /// This method will create an invalid [`Headers`] if the _outer_ ethtype (i.e., the ethtype of
    /// the [`Eth`] header or prior [`Vlan`] in the stack) is not some flavor of `Vlan` ethtype
    /// (e.g. [`EthType::VLAN`] or [`EthType::VLAN_QINQ`])
    #[allow(unsafe_code)]
    #[allow(dead_code)]
    unsafe fn push_vlan_header_unchecked(&mut self, vlan: Vlan) -> Result<(), PushVlanError> {
        if self.vlan.len() < MAX_VLANS {
            self.vlan.insert(0, vlan);
            Ok(())
        } else {
            Err(PushVlanError::TooManyVlans)
        }
    }

    /// Push a vlan header onto the VLAN stack of this [`Headers`].
    ///
    /// This method will ensure that the `eth` field has its [`EthType`] adjusted to
    /// [`EthType::VLAN`] if there are no [`Vlan`]s on the stack at the time this method was called.
    ///
    /// # Errors
    ///
    /// Returns [`PushVlanError::TooManyVlans`] if there are already [`MAX_VLANS`] VLANs on the
    /// stack.
    /// Returns [`PushVlanError::NoEthernetHeader`] if no Ethernet header is present.
    pub fn push_vlan(&mut self, vid: Vid) -> Result<(), PushVlanError> {
        if self.vlan.len() >= MAX_VLANS {
            return Err(PushVlanError::TooManyVlans);
        }
        match &mut self.eth {
            None => Err(PushVlanError::NoEthernetHeader),
            Some(eth) => {
                let old_eth_type = eth.ether_type();
                eth.set_ether_type(EthType::VLAN);
                let new_vlan_header = Vlan::new(vid, old_eth_type, Pcp::default(), false);
                self.vlan.insert(0, new_vlan_header);
                Ok(())
            }
        }
    }

    /// Pop a vlan header from the stack.
    ///
    /// Returns [`None`] if no [`Vlan`]s are on the stack.
    ///
    /// If `Some` is returned, the popped [`Vlan`]s ethtype is assigned to the `eth` header to
    /// preserve the structure.
    ///
    /// If `None` is returned, the [`Headers`] is not modified.
    ///
    /// # Errors
    ///
    /// Returns [`PopVlanError::NoEthernetHeader`] if no Ethernet header is present.
    pub fn pop_vlan(&mut self) -> Result<Option<Vlan>, PopVlanError> {
        match &mut self.eth {
            None => Err(PopVlanError::NoEthernetHeader),
            Some(eth) => {
                if self.vlan.is_empty() {
                    Ok(None)
                } else {
                    let vlan = self.vlan.remove(0);
                    eth.set_ether_type(vlan.inner_ethtype());
                    Ok(Some(vlan))
                }
            }
        }
    }

    /// update the checksums of the headers
    pub(crate) fn update_checksums(&mut self, payload: impl AsRef<[u8]>) {
        let is_vxlan = self.try_vxlan().is_some();

        let Some(net) = self.net.as_mut() else {
            trace!("no network header: can't update checksum");
            return;
        };
        net.update_checksum();

        if is_vxlan {
            // Only recompute checksum if it is not VXLAN
            return;
        }

        // Update inner IP header checksum, if any, before updating transport checksum.
        // This is because the inner headers are part of transport header's payload, so updating
        // them later would invalidate transport's payload.
        if let Some(inner_ip) = self
            .embedded_ip
            .as_mut()
            .and_then(|ip| ip.try_inner_ip_mut())
        {
            inner_ip.update_checksum();

            // WARNING: We do NOT update ICMP Error message inner transport checksum here!
            // This is because we're not sure the transport header and payload are full, so we want
            // incremental checksum updates that require knowledge of the previous values, if we've
            // changed them (for example: NAT). Leave this to (for example) the NAT code.
        }

        let Some(transport) = self.transport.as_mut() else {
            trace!("no transport header: can't update checksum");
            return;
        };
        transport.update_checksum(net, self.embedded_ip.as_ref(), payload.as_ref());
    }
}

// ---------------------------------------------------------------------------
// Try* accessor traits -- definitions + concrete impls on Headers
// ---------------------------------------------------------------------------

// Field accessors (Option<T> -> as_ref / as_mut)
define_field_accessor!(TryEth::try_eth / TryEthMut::try_eth_mut -> Eth, for Headers => self.eth);
define_field_accessor!(TryIp::try_ip / TryIpMut::try_ip_mut -> Net, for Headers => self.net);
define_field_accessor!(TryTransport::try_transport / TryTransportMut::try_transport_mut -> Transport, for Headers => self.transport);

// Variant accessors (Option<Enum> -> match variant)
define_variant_accessor!(TryIpv4::try_ipv4 / TryIpv4Mut::try_ipv4_mut -> Ipv4, for Headers => self.net, match Net::Ipv4);
define_variant_accessor!(TryIpv6::try_ipv6 / TryIpv6Mut::try_ipv6_mut -> Ipv6, for Headers => self.net, match Net::Ipv6);
define_variant_accessor!(TryTcp::try_tcp / TryTcpMut::try_tcp_mut -> Tcp, for Headers => self.transport, match Transport::Tcp);
define_variant_accessor!(TryUdp::try_udp / TryUdpMut::try_udp_mut -> Udp, for Headers => self.transport, match Transport::Udp);
define_variant_accessor!(TryIcmp4::try_icmp4 / TryIcmp4Mut::try_icmp4_mut -> Icmp4, for Headers => self.transport, match Transport::Icmp4);
define_variant_accessor!(TryIcmp6::try_icmp6 / TryIcmp6Mut::try_icmp6_mut -> Icmp6, for Headers => self.transport, match Transport::Icmp6);
define_variant_accessor!(TryVxlan::try_vxlan / TryVxlanMut::try_vxlan_mut -> Vxlan, for Headers => self.udp_encap, match UdpEncap::Vxlan);

// ICMP version-agnostic traits -- irregular return type, kept hand-written.

pub trait TryIcmpAny {
    fn try_icmp_any(&self) -> Option<IcmpAny<'_>>;
}

pub trait TryIcmpAnyMut {
    fn try_icmp_any_mut(&mut self) -> Option<IcmpAnyMut<'_>>;
}

impl TryIcmpAny for Headers {
    fn try_icmp_any(&self) -> Option<IcmpAny<'_>> {
        match &self.transport {
            Some(Transport::Icmp4(header)) => Some(IcmpAny::V4(header)),
            Some(Transport::Icmp6(header)) => Some(IcmpAny::V6(header)),
            _ => None,
        }
    }
}

impl TryIcmpAnyMut for Headers {
    fn try_icmp_any_mut(&mut self) -> Option<IcmpAnyMut<'_>> {
        match &mut self.transport {
            Some(Transport::Icmp4(header)) => Some(IcmpAnyMut::V4(header)),
            Some(Transport::Icmp6(header)) => Some(IcmpAnyMut::V6(header)),
            _ => None,
        }
    }
}

impl_from_for_enum![
    Header,
    Eth(Eth),
    Vlan(Vlan),
    Ipv4(Ipv4),
    Ipv6(Ipv6),
    Tcp(Tcp),
    Udp(Udp),
    Icmp4(Icmp4),
    Icmp6(Icmp6),
    HopByHop(HopByHop),
    DestOpts(DestOpts),
    Routing(Routing),
    Fragment(Fragment),
    Ipv4Auth(Ipv4Auth),
    Ipv6Auth(Ipv6Auth),
    Encap(UdpEncap),
    EmbeddedIp(EmbeddedHeaders),
];

impl From<Net> for Header {
    fn from(value: Net) -> Self {
        match value {
            Net::Ipv4(ip) => Header::from(ip),
            Net::Ipv6(ip) => Header::from(ip),
        }
    }
}

impl From<Transport> for Header {
    fn from(value: Transport) -> Self {
        match value {
            Transport::Tcp(x) => Header::from(x),
            Transport::Udp(x) => Header::from(x),
            Transport::Icmp4(x) => Header::from(x),
            Transport::Icmp6(x) => Header::from(x),
        }
    }
}

impl From<Vxlan> for Header {
    fn from(value: Vxlan) -> Self {
        Header::Encap(UdpEncap::Vxlan(value))
    }
}

pub trait AbstractHeaders:
    Debug
    + TryEth
    + TryIpv4
    + TryIpv6
    + TryIp
    + TryTcp
    + TryUdp
    + TryIcmp4
    + TryIcmp6
    + TryIcmpAny
    + TryTransport
    + TryVxlan
    + DeParse
{
}

impl<T> AbstractHeaders for T where
    T: Debug
        + TryEth
        + TryIpv4
        + TryIpv6
        + TryIp
        + TryTcp
        + TryUdp
        + TryIcmp4
        + TryIcmp6
        + TryIcmpAny
        + TryTransport
        + TryVxlan
        + DeParse
{
}

pub trait AbstractHeadersMut:
    AbstractHeaders
    + TryEthMut
    + TryIpv4Mut
    + TryIpv6Mut
    + TryIpMut
    + TryTcpMut
    + TryUdpMut
    + TryIcmp4Mut
    + TryIcmp6Mut
    + TryIcmpAnyMut
    + TryTransportMut
    + TryVxlanMut
{
}

impl<T> AbstractHeadersMut for T where
    T: AbstractHeaders
        + TryEthMut
        + TryIpv4Mut
        + TryIpv6Mut
        + TryIpMut
        + TryTcpMut
        + TryUdpMut
        + TryIcmp4Mut
        + TryIcmp6Mut
        + TryIcmpAnyMut
        + TryTransportMut
        + TryVxlanMut
{
}

pub trait TryHeaders {
    fn headers(&self) -> &impl AbstractHeaders;
}

pub trait TryHeadersMut {
    fn headers_mut(&mut self) -> &mut impl AbstractHeadersMut;
}

// ---------------------------------------------------------------------------
// Blanket delegation impls -- forward through TryHeaders / TryHeadersMut
// ---------------------------------------------------------------------------

impl_delegated_accessors! {
    via TryHeaders::headers / TryHeadersMut::headers_mut {
        TryEth::try_eth / TryEthMut::try_eth_mut -> Eth,
        TryIpv4::try_ipv4 / TryIpv4Mut::try_ipv4_mut -> Ipv4,
        TryIpv6::try_ipv6 / TryIpv6Mut::try_ipv6_mut -> Ipv6,
        TryIp::try_ip / TryIpMut::try_ip_mut -> Net,
        TryTcp::try_tcp / TryTcpMut::try_tcp_mut -> Tcp,
        TryUdp::try_udp / TryUdpMut::try_udp_mut -> Udp,
        TryIcmp4::try_icmp4 / TryIcmp4Mut::try_icmp4_mut -> Icmp4,
        TryIcmp6::try_icmp6 / TryIcmp6Mut::try_icmp6_mut -> Icmp6,
        TryTransport::try_transport / TryTransportMut::try_transport_mut -> Transport,
        TryVxlan::try_vxlan / TryVxlanMut::try_vxlan_mut -> Vxlan,
    }
}

// TryIcmpAny delegation -- irregular return type, kept hand-written.

impl<T> TryIcmpAny for T
where
    T: TryHeaders,
{
    fn try_icmp_any(&self) -> Option<IcmpAny<'_>> {
        self.headers().try_icmp_any()
    }
}

impl<T> TryIcmpAnyMut for T
where
    T: TryHeadersMut,
{
    fn try_icmp_any_mut(&mut self) -> Option<IcmpAnyMut<'_>> {
        self.headers_mut().try_icmp_any_mut()
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::eth::ethtype::CommonEthType;
    use crate::eth::{Eth, GenWithEthType};
    use crate::headers::{Headers, Net, Transport};
    use crate::icmp4::Icmp4;
    use crate::icmp6::Icmp6;
    use crate::ipv4;
    use crate::ipv6;
    use crate::parse::{DeParse, Parse};
    use crate::tcp::Tcp;
    use crate::udp::{Udp, UdpEncap};
    use crate::vxlan::Vxlan;
    use arrayvec::ArrayVec;
    use bolero::{Driver, TypeGenerator, ValueGenerator};

    impl TypeGenerator for Headers {
        /// Generate a completely arbitrary value of [`Headers`].
        ///
        /// <div class="warning">
        ///
        /// # Note:
        ///
        /// You are likely looking for [`CommonHeaders`] rather than this method!
        ///
        /// This is _not_ an efficient method of testing "sunny-day" logic of general network
        /// processing code (e.g., routing or NAT).
        /// This method simply generates an arbitrary (fuzzer provided) byte sequence and then
        /// parses it into a [`Headers`] value.
        /// The fuzzer may make good guesses.
        /// However, the space of all values for [`Headers`] is so ponderously large that it may
        /// take the fuzzer a very large number of guesses before it returns valid or interesting
        /// packets for most workloads.
        ///
        /// On the other hand, this method is well suited to testing and hardening the parser
        /// itself since (in theory) every possible value of [`Headers`] can be generated this way.
        /// That is, this `TypeGenerator` should have a full cover property (as all implementations
        /// of `TypeGenerator` should).
        /// It's just that full coverage is likely not what you are looking for.
        /// </div>
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            // In theory, `size_of::<Headers>()` is strictly larger than the serialized
            // representation, so this should always be correct (if not perfectly efficient).
            // The exception is IPv4/6 extension headers (because those values are large and boxed).
            // As a result, we will need to generate more bytes once we want to start testing more
            // exotic packets.  For now, I will double to be safe.
            let mut arbitrary_bytes: [u8; 2 * size_of::<Headers>()] = driver.produce()?;
            let arbitrary_eth: Eth = driver.produce()?;
            // ensure that the start of the arbitrary bytes for some valid ethernet header.
            arbitrary_eth
                .deparse(&mut arbitrary_bytes)
                .unwrap_or_else(|_| unreachable!());
            Some(
                Headers::parse(&arbitrary_bytes)
                    .unwrap_or_else(|_| unreachable!())
                    .0,
            )
        }
    }

    #[allow(dead_code)] // rustc not able to infer we construct this through .with_generator()
    #[repr(transparent)]
    pub struct CommonHeaders;

    impl ValueGenerator for CommonHeaders {
        type Output = Headers;

        #[allow(clippy::too_many_lines)]
        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let common_eth_type: CommonEthType = driver.produce()?;
            let eth = GenWithEthType(common_eth_type.into()).generate(driver)?;
            match common_eth_type {
                CommonEthType::Ipv4 => {
                    let common_next_header: ipv4::CommonNextHeader = driver.produce()?;
                    let ipv4 =
                        ipv4::GenWithNextHeader(common_next_header.into()).generate(driver)?;
                    match common_next_header {
                        ipv4::CommonNextHeader::Tcp => {
                            let tcp: Tcp = driver.produce()?;
                            let headers = Headers {
                                eth: Some(eth),
                                vlan: ArrayVec::default(),
                                net: Some(Net::Ipv4(ipv4)),
                                net_ext: ArrayVec::default(),
                                transport: Some(Transport::Tcp(tcp)),
                                udp_encap: None,
                                embedded_ip: None,
                            };
                            Some(headers)
                        }
                        ipv4::CommonNextHeader::Udp => {
                            let mut udp: Udp = driver.produce()?;
                            let udp_encap = if driver.produce::<bool>()? {
                                udp.set_destination(Vxlan::PORT);
                                Some(UdpEncap::Vxlan(driver.produce()?))
                            } else {
                                None
                            };
                            let headers = Headers {
                                eth: Some(eth),
                                vlan: ArrayVec::default(),
                                net: Some(Net::Ipv4(ipv4)),
                                net_ext: ArrayVec::default(),
                                transport: Some(Transport::Udp(udp)),
                                udp_encap,
                                embedded_ip: None,
                            };
                            Some(headers)
                        }
                        ipv4::CommonNextHeader::Icmp4 => {
                            let icmp: Icmp4 = driver.produce()?;
                            let headers = Headers {
                                eth: Some(eth),
                                vlan: ArrayVec::default(),
                                net: Some(Net::Ipv4(ipv4)),
                                net_ext: ArrayVec::default(),
                                transport: Some(Transport::Icmp4(icmp)),
                                udp_encap: None,
                                embedded_ip: None,
                            };
                            Some(headers)
                        }
                    }
                }
                CommonEthType::Ipv6 => {
                    let common_next_header: ipv6::CommonNextHeader = driver.produce()?;
                    let ipv6 =
                        ipv6::GenWithNextHeader(common_next_header.into()).generate(driver)?;
                    match common_next_header {
                        ipv6::CommonNextHeader::Tcp => {
                            let tcp: Tcp = driver.produce()?;
                            let headers = Headers {
                                eth: Some(eth),
                                vlan: ArrayVec::default(),
                                net: Some(Net::Ipv6(ipv6)),
                                net_ext: ArrayVec::default(),
                                transport: Some(Transport::Tcp(tcp)),
                                udp_encap: None,
                                embedded_ip: None,
                            };
                            Some(headers)
                        }
                        ipv6::CommonNextHeader::Udp => {
                            let mut udp: Udp = driver.produce()?;
                            let udp_encap = if driver.produce::<bool>()? {
                                udp.set_destination(Vxlan::PORT);
                                Some(UdpEncap::Vxlan(driver.produce()?))
                            } else {
                                None
                            };
                            let headers = Headers {
                                eth: Some(eth),
                                vlan: ArrayVec::default(),
                                net: Some(Net::Ipv6(ipv6)),
                                net_ext: ArrayVec::default(),
                                transport: Some(Transport::Udp(udp)),
                                udp_encap,
                                embedded_ip: None,
                            };
                            Some(headers)
                        }
                        ipv6::CommonNextHeader::Icmp6 => {
                            let icmp6: Icmp6 = driver.produce()?;
                            let headers = Headers {
                                eth: Some(eth),
                                vlan: ArrayVec::default(),
                                net: Some(Net::Ipv6(ipv6)),
                                net_ext: ArrayVec::default(),
                                transport: Some(Transport::Icmp6(icmp6)),
                                udp_encap: None,
                                embedded_ip: None,
                            };
                            Some(headers)
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // fine to unwrap in tests
mod test {
    use std::net::Ipv4Addr;

    use crate::checksum::Checksum;
    use crate::headers::Headers;
    use crate::headers::contract::CommonHeaders;
    use crate::icmp4::Icmp4Checksum;
    use crate::parse::{DeParse, DeParseError, IntoNonZeroUSize, Parse, ParseError};

    use super::{Net, Transport};
    #[allow(unused_imports)] // used by ipv6 checksum vector tests
    use crate::checksum::Checksum as _;
    use crate::icmp6::{Icmp6Checksum, Icmp6ChecksumPayload};
    use crate::ipv4::{Ipv4Checksum, UnicastIpv4Addr};
    use crate::tcp::{TcpChecksum, TcpChecksumPayload, TcpPort};
    use crate::udp::{UdpChecksum, UdpChecksumPayload, UdpPort};

    fn parse_back_test(headers: &Headers) {
        let mut buffer = [0_u8; 1024];
        let bytes_written =
            match headers.deparse(&mut buffer[..headers.size().into_non_zero_usize().get()]) {
                Ok(written) => written,
                Err(DeParseError::Length(e)) => unreachable!("{e:?}", e = e),
                Err(DeParseError::Invalid(e)) => unreachable!("{e:?}", e = e),
                Err(DeParseError::BufferTooLong(_)) => unreachable!(),
            };
        let (parsed, bytes_parsed) =
            match Headers::parse(&buffer[..bytes_written.into_non_zero_usize().get()]) {
                Ok(k) => k,
                Err(ParseError::Length(e)) => unreachable!("{e:?}", e = e),
                Err(ParseError::Invalid(e)) => unreachable!("{e:?}", e = e),
                Err(ParseError::BufferTooLong(_)) => unreachable!(),
            };
        assert_eq!(headers, &parsed);
        assert_eq!(bytes_parsed, headers.size());
    }

    #[test]
    fn parse_back() {
        bolero::check!().with_type().for_each(parse_back_test);
    }

    #[test]
    fn parse_back_common() {
        bolero::check!()
            .with_generator(CommonHeaders)
            .for_each(parse_back_test);
    }

    mod sample {
        use crate::checksum::Checksum;
        use crate::eth::Eth;
        use crate::eth::ethtype::EthType;
        use crate::eth::mac::{DestinationMac, Mac, SourceMac};
        use crate::headers::{Headers, HeadersBuilder, Net, Transport};
        use crate::icmp4::Icmp4;
        use crate::icmp4::{Icmp4EchoRequest, Icmp4Type};
        use crate::icmp6::Icmp6;
        use crate::icmp6::{Icmp6EchoRequest, Icmp6Type};
        use crate::ip::NextHeader;
        use crate::ip::dscp::Dscp;
        use crate::ip::ecn::Ecn;
        use crate::ipv4::{Ipv4, UnicastIpv4Addr};
        use crate::ipv6::{Ipv6, UnicastIpv6Addr};
        use crate::parse::DeParse;
        use crate::tcp::Tcp;
        use crate::udp::Udp;
        use std::net::{Ipv4Addr, Ipv6Addr};

        pub(super) fn eth(ethertype: EthType) -> Eth {
            Eth::new(
                SourceMac::new(Mac::from([2, 1, 2, 3, 4, 5])).unwrap(),
                DestinationMac::new(Mac::BROADCAST).unwrap(),
                ethertype,
            )
        }

        pub(super) fn ipv4(next_header: NextHeader) -> Ipv4 {
            let mut ipv4 = Ipv4::default();
            ipv4.set_checksum(0x1234.into())
                .unwrap()
                .set_ecn(Ecn::new(0b11).unwrap())
                .set_dscp(Dscp::MAX)
                .set_source(UnicastIpv4Addr::new(Ipv4Addr::new(192, 168, 1, 1)).unwrap())
                .set_destination(Ipv4Addr::new(192, 168, 1, 2))
                .set_dont_fragment(true)
                .set_next_header(next_header)
                .set_ttl(64);
            ipv4
        }

        pub(super) fn ipv6(next_header: NextHeader) -> Ipv6 {
            let mut ipv6 = Ipv6::default();
            ipv6.set_source(
                UnicastIpv6Addr::new(Ipv6Addr::new(0xfe, 0x80, 0, 0, 0, 0, 0, 1)).unwrap(),
            )
            .set_destination(Ipv6Addr::new(0xfe, 0x80, 0, 0, 0, 0, 0, 2))
            .set_hop_limit(64)
            .set_next_header(next_header);
            ipv6
        }

        pub(super) fn tcp() -> Tcp {
            let mut tcp = Tcp::new(123.try_into().unwrap(), 456.try_into().unwrap());
            tcp.set_syn(true)
                .set_sequence_number(1)
                .set_checksum(1234.into())
                .unwrap();
            tcp
        }

        pub(super) fn udp() -> Udp {
            let mut udp = Udp::new(123.try_into().unwrap(), 456.try_into().unwrap());
            udp.set_checksum(1234.into()).unwrap();
            udp
        }

        pub(super) fn icmp4() -> Icmp4 {
            let mut icmp4 =
                Icmp4::with_type(Icmp4Type::EchoRequest(Icmp4EchoRequest { id: 18, seq: 2 }));
            icmp4.set_checksum(1234.into()).unwrap();
            icmp4
        }

        pub(super) fn icmp6() -> Icmp6 {
            let mut icmp6 =
                Icmp6::with_type(Icmp6Type::EchoRequest(Icmp6EchoRequest { id: 18, seq: 2 }));
            icmp6.set_checksum(1234.into()).unwrap();
            icmp6
        }

        pub(super) fn ipv4_tcp() -> Headers {
            let mut headers = HeadersBuilder::default();
            let mut ipv4 = ipv4(NextHeader::TCP);
            let tcp = tcp();
            ipv4.set_payload_len(tcp.size().get()).unwrap();
            headers
                .eth(Some(eth(EthType::IPV4)))
                .net(Some(Net::Ipv4(ipv4)))
                .transport(Some(Transport::Tcp(tcp)))
                .build()
                .unwrap()
        }

        pub(super) fn ipv4_icmp() -> Headers {
            let mut headers = HeadersBuilder::default();
            headers
                .eth(Some(eth(EthType::IPV4)))
                .net(Some(Net::Ipv4(ipv4(NextHeader::ICMP))))
                .transport(Some(Transport::Icmp4(icmp4())))
                .build()
                .unwrap()
        }

        pub(super) fn ipv4_udp() -> Headers {
            let mut headers = HeadersBuilder::default();
            let mut ipv4 = ipv4(NextHeader::UDP);
            let udp = udp();
            ipv4.set_payload_len(udp.size().get()).unwrap();
            headers
                .eth(Some(eth(EthType::IPV4)))
                .net(Some(Net::Ipv4(ipv4)))
                .transport(Some(Transport::Udp(udp)))
                .build()
                .unwrap()
        }

        pub(super) fn ipv6_tcp() -> Headers {
            let mut headers = HeadersBuilder::default();
            let tcp = tcp();
            let mut ipv6 = ipv6(NextHeader::TCP);
            ipv6.set_payload_length(tcp.size().get());
            headers
                .eth(Some(eth(EthType::IPV6)))
                .net(Some(Net::Ipv6(ipv6)))
                .transport(Some(Transport::Tcp(tcp)))
                .build()
                .unwrap()
        }

        pub(super) fn ipv6_udp() -> Headers {
            let mut headers = HeadersBuilder::default();
            let udp = udp();
            let mut ipv6 = ipv6(NextHeader::UDP);
            ipv6.set_payload_length(udp.size().get());
            headers
                .eth(Some(eth(EthType::IPV6)))
                .net(Some(Net::Ipv6(ipv6)))
                .transport(Some(Transport::Udp(udp)))
                .build()
                .unwrap()
        }

        pub(super) fn ipv6_icmp() -> Headers {
            let mut headers = HeadersBuilder::default();
            let icmp = icmp6();
            let mut ipv6 = ipv6(NextHeader::ICMP6);
            ipv6.set_payload_length(icmp.size().get());
            headers
                .eth(Some(eth(EthType::IPV6)))
                .net(Some(Net::Ipv6(ipv6)))
                .transport(Some(Transport::Icmp6(icmp)))
                .build()
                .unwrap()
        }
    }

    #[allow(clippy::too_many_lines)]
    fn test_checksum(mut headers: Headers) {
        match &headers.transport {
            None => {}
            Some(Transport::Udp(transport)) => {
                let net = headers.net.clone().unwrap();
                transport
                    .validate_checksum(&UdpChecksumPayload::new(&net, &[]))
                    .expect_err("expected invalid checksum");
            }
            Some(Transport::Tcp(transport)) => {
                let net = headers.net.clone().unwrap();
                transport
                    .validate_checksum(&TcpChecksumPayload::new(&net, &[]))
                    .expect_err("expected invalid checksum");
            }
            Some(Transport::Icmp4(transport)) => {
                transport
                    .validate_checksum(&[])
                    .expect_err("expected invalid checksum");
            }
            Some(Transport::Icmp6(transport)) => {
                let net = headers.net.clone().unwrap();
                let (src, dst) = match net {
                    Net::Ipv4(_) => panic!("unexpected ipv4"),
                    Net::Ipv6(ipv6) => (ipv6.source(), ipv6.destination()),
                };
                transport
                    .validate_checksum(&Icmp6ChecksumPayload::new(src.inner(), dst, &[]))
                    .expect_err("expected invalid checksum");
            }
        }

        headers.update_checksums([]);

        match &headers.transport {
            None => {}
            Some(Transport::Udp(transport)) => {
                let net = headers.net.clone().unwrap();
                transport
                    .validate_checksum(&UdpChecksumPayload::new(&net, &[]))
                    .expect("expected valid checksum");
            }
            Some(Transport::Tcp(transport)) => {
                let net = headers.net.clone().unwrap();
                transport
                    .validate_checksum(&TcpChecksumPayload::new(&net, &[]))
                    .expect("expected valid checksum");
            }
            Some(Transport::Icmp4(transport)) => {
                transport
                    .validate_checksum(&[])
                    .expect("expected valid checksum");
            }
            Some(Transport::Icmp6(transport)) => {
                let net = headers.net.clone().unwrap();
                let (src, dst) = match net {
                    Net::Ipv4(_) => panic!("unexpected ipv4"),
                    Net::Ipv6(ipv6) => (ipv6.source(), ipv6.destination()),
                };
                transport
                    .validate_checksum(&Icmp6ChecksumPayload::new(src.inner(), dst, &[]))
                    .expect("expected valid checksum");
            }
        }

        match &headers.transport {
            None => {}
            Some(Transport::Udp(transport)) => {
                let net = headers.net.clone().unwrap();
                transport
                    .validate_checksum(&UdpChecksumPayload::new(&net, &[1]))
                    .expect_err("expected invalid checksum");
            }
            Some(Transport::Tcp(transport)) => {
                let net = headers.net.clone().unwrap();
                transport
                    .validate_checksum(&TcpChecksumPayload::new(&net, &[1]))
                    .expect_err("expected invalid checksum");
            }
            Some(Transport::Icmp4(transport)) => {
                transport
                    .validate_checksum(&[1])
                    .expect_err("expected invalid checksum");
            }
            Some(Transport::Icmp6(transport)) => {
                let net = headers.net.clone().unwrap();
                let (src, dst) = match net {
                    Net::Ipv4(_) => panic!("unexpected ipv4"),
                    Net::Ipv6(ipv6) => (ipv6.source(), ipv6.destination()),
                };
                transport
                    .validate_checksum(&Icmp6ChecksumPayload::new(src.inner(), dst, &[1]))
                    .expect_err("expected invalid checksum");
            }
        }

        // Check incremental updates
        match &mut headers.transport {
            None | Some(Transport::Icmp6(_)) => {}
            Some(Transport::Udp(transport)) => {
                let net = headers.net.clone().unwrap();
                let old_value = transport.source().into();
                let new_value = 235;
                transport.set_source(UdpPort::new_checked(new_value).unwrap());
                let new_checksum = transport.increment_update_checksum(
                    transport.checksum().unwrap(),
                    old_value,
                    new_value,
                );
                transport.set_checksum(new_checksum).unwrap();

                transport
                    .validate_checksum(&UdpChecksumPayload::new(&net, &[]))
                    .expect("expected valid checksum");
            }
            Some(Transport::Tcp(transport)) => {
                let net = headers.net.clone().unwrap();
                let old_value = transport.destination().into();
                let new_value = 116;
                transport.set_destination(TcpPort::new_checked(new_value).unwrap());
                let new_checksum = transport.increment_update_checksum(
                    transport.checksum().unwrap(),
                    old_value,
                    new_value,
                );
                transport.set_checksum(new_checksum).unwrap();

                transport
                    .validate_checksum(&TcpChecksumPayload::new(&net, &[]))
                    .expect("expected valid checksum");
            }
            Some(Transport::Icmp4(_)) => {
                let net = headers.net.clone().unwrap();
                match net {
                    Net::Ipv4(mut ipv4) => {
                        let old_value = ipv4.source().inner().into();
                        let new_value = 0x10_20_30_40; // 16.32.48.64
                        let new_ip = UnicastIpv4Addr::try_from(Ipv4Addr::from(new_value)).unwrap();
                        ipv4.set_source(new_ip);
                        let new_checksum = ipv4.increment_update_checksum_32bit(
                            ipv4.checksum().unwrap(),
                            old_value,
                            new_value,
                        );
                        ipv4.set_checksum(new_checksum).unwrap();
                        ipv4.validate_checksum(&())
                            .expect("expected valid checksum");
                    }
                    Net::Ipv6(_) => panic!("unexpected ipv6"),
                }
            }
        }
    }

    #[test]
    fn test_ipv4_tcp() {
        test_checksum(sample::ipv4_tcp());
    }

    #[test]
    fn test_ipv4_udp() {
        test_checksum(sample::ipv4_udp());
    }

    #[test]
    fn test_ipv4_icmp() {
        test_checksum(sample::ipv4_icmp());
    }

    #[test]
    fn test_ipv6_tcp() {
        test_checksum(sample::ipv6_tcp());
    }

    #[test]
    fn test_ipv6_udp() {
        test_checksum(sample::ipv6_udp());
    }

    #[test]
    fn test_ipv6_icmp() {
        test_checksum(sample::ipv6_icmp());
    }

    #[test]
    fn compare_with_good_ipv4_tcp() {
        struct Comparison<'a> {
            pub good_ipv4: Ipv4Checksum,
            pub good_tcp: TcpChecksum,
            pub payload: &'a [u8],
        }
        let comparisons = [
            Comparison {
                good_ipv4: Ipv4Checksum::new(46717),
                good_tcp: TcpChecksum::new(10827),
                payload: &[],
            },
            Comparison {
                good_ipv4: Ipv4Checksum::new(46717),
                good_tcp: TcpChecksum::new(10570),
                payload: &[1],
            },
            Comparison {
                good_ipv4: Ipv4Checksum::new(46717),
                good_tcp: TcpChecksum::new(10567),
                payload: &[1, 2],
            },
            Comparison {
                good_ipv4: Ipv4Checksum::new(46717),
                good_tcp: TcpChecksum::new(59890),
                payload: &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            },
        ];
        for comparison in comparisons {
            let mut headers = sample::ipv4_tcp();
            headers.update_checksums(comparison.payload);
            match &headers.net {
                Some(net) => match net {
                    Net::Ipv4(ipv4) => {
                        assert_eq!(ipv4.checksum().unwrap(), comparison.good_ipv4);
                        ipv4.validate_checksum(&()).unwrap();
                        match &headers.transport {
                            Some(Transport::Tcp(tcp)) => {
                                assert_eq!(tcp.checksum().unwrap(), comparison.good_tcp);
                                let payload = TcpChecksumPayload::new(net, comparison.payload);
                                tcp.validate_checksum(&payload).unwrap();
                            }
                            _ => unreachable!(),
                        }
                    }
                    Net::Ipv6(_) => unreachable!(),
                },
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn compare_with_good_ipv4_udp() {
        struct Comparison<'a> {
            pub good_ipv4: Ipv4Checksum,
            pub good_udp: UdpChecksum,
            pub payload: &'a [u8],
        }
        let comparisons = [
            Comparison {
                good_ipv4: Ipv4Checksum::new(46718),
                good_udp: UdpChecksum::new(31303),
                payload: &[],
            },
            Comparison {
                good_ipv4: Ipv4Checksum::new(46718),
                good_udp: UdpChecksum::new(31047),
                payload: &[1],
            },
            Comparison {
                good_ipv4: Ipv4Checksum::new(46718),
                good_udp: UdpChecksum::new(31045),
                payload: &[1, 2],
            },
            Comparison {
                good_ipv4: Ipv4Checksum::new(46718),
                good_udp: UdpChecksum::new(14847),
                payload: &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            },
        ];
        for comparison in comparisons {
            let mut headers = sample::ipv4_udp();
            headers.update_checksums(comparison.payload);
            match &headers.net {
                Some(net) => match net {
                    Net::Ipv4(ipv4) => {
                        assert_eq!(ipv4.checksum().unwrap(), comparison.good_ipv4);
                        ipv4.validate_checksum(&()).unwrap();
                        match &headers.transport {
                            Some(Transport::Udp(udp)) => {
                                assert_eq!(udp.checksum().unwrap(), comparison.good_udp);
                                let payload = UdpChecksumPayload::new(net, comparison.payload);
                                udp.validate_checksum(&payload).unwrap();
                            }
                            _ => unreachable!(),
                        }
                    }
                    Net::Ipv6(_) => unreachable!(),
                },
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn compare_with_good_ipv4_icmp() {
        struct Comparison<'a> {
            pub good_ipv4: Ipv4Checksum,
            pub good_icmp: Icmp4Checksum,
            pub payload: &'a [u8],
        }
        let comparisons = [
            Comparison {
                good_ipv4: Ipv4Checksum::new(46762),
                good_icmp: Icmp4Checksum::new(63467),
                payload: &[],
            },
            Comparison {
                good_ipv4: Ipv4Checksum::new(46762),
                good_icmp: Icmp4Checksum::new(63211),
                payload: &[1],
            },
            Comparison {
                good_ipv4: Ipv4Checksum::new(46762),
                good_icmp: Icmp4Checksum::new(63209),
                payload: &[1, 2],
            },
            Comparison {
                good_ipv4: Ipv4Checksum::new(46762),
                good_icmp: Icmp4Checksum::new(47011),
                payload: &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            },
        ];
        for comparison in comparisons {
            let mut headers = sample::ipv4_icmp();
            headers.update_checksums(comparison.payload);
            match &headers.net {
                Some(net) => {
                    if let Net::Ipv4(ipv4) = net {
                        assert_eq!(ipv4.checksum().unwrap(), comparison.good_ipv4);
                        ipv4.validate_checksum(&()).unwrap();
                        match &headers.transport {
                            Some(Transport::Icmp4(icmp)) => {
                                assert_eq!(icmp.checksum().unwrap(), comparison.good_icmp);
                                icmp.validate_checksum(comparison.payload).unwrap();
                            }
                            _ => unreachable!(),
                        }
                    } else {
                        unreachable!()
                    }
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn compare_with_good_ipv6_tcp() {
        struct Comparison<'a> {
            pub good_tcp: TcpChecksum,
            pub payload: &'a [u8],
        }
        let comparisons = [
            Comparison {
                good_tcp: TcpChecksum::new(43680),
                payload: &[],
            },
            Comparison {
                good_tcp: TcpChecksum::new(43423),
                payload: &[1],
            },
            Comparison {
                good_tcp: TcpChecksum::new(43420),
                payload: &[1, 2],
            },
            Comparison {
                good_tcp: TcpChecksum::new(27204),
                payload: &[1, 2, 3, 6, 5, 6, 7, 8, 9, 10, 11, 12, 13, 16, 15, 16],
            },
        ];
        for comparison in comparisons {
            let mut headers = sample::ipv6_tcp();
            headers.update_checksums(comparison.payload);
            match (headers.net, headers.transport) {
                (Some(net), Some(Transport::Tcp(tcp))) => {
                    assert_eq!(tcp.checksum().unwrap(), comparison.good_tcp);
                    let payload = TcpChecksumPayload::new(&net, comparison.payload);
                    tcp.validate_checksum(&payload).unwrap();
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn compare_with_good_ipv6_udp() {
        struct Comparison<'a> {
            pub good_udp: UdpChecksum,
            pub payload: &'a [u8],
        }
        let comparisons = [
            Comparison {
                good_udp: UdpChecksum::new(64156),
                payload: &[],
            },
            Comparison {
                good_udp: UdpChecksum::new(63900),
                payload: &[1],
            },
            Comparison {
                good_udp: UdpChecksum::new(63898),
                payload: &[1, 2],
            },
            Comparison {
                good_udp: UdpChecksum::new(47696),
                payload: &[1, 2, 3, 6, 5, 6, 7, 8, 9, 10, 11, 12, 13, 16, 15, 16],
            },
        ];
        for comparison in comparisons {
            let mut headers = sample::ipv6_udp();
            headers.update_checksums(comparison.payload);
            match (headers.net, headers.transport) {
                (Some(net), Some(Transport::Udp(udp))) => {
                    assert_eq!(udp.checksum().unwrap(), comparison.good_udp);
                    let payload = UdpChecksumPayload::new(&net, comparison.payload);
                    udp.validate_checksum(&payload).unwrap();
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn compare_with_good_ipv6_icmp() {
        struct Comparison<'a> {
            pub good_icmp: Icmp6Checksum,
            pub payload: &'a [u8],
        }
        let comparisons = [
            Comparison {
                good_icmp: Icmp6Checksum::new(31914),
                payload: &[],
            },
            Comparison {
                good_icmp: Icmp6Checksum::new(31657),
                payload: &[1],
            },
            Comparison {
                good_icmp: Icmp6Checksum::new(31654),
                payload: &[1, 2],
            },
            Comparison {
                good_icmp: Icmp6Checksum::new(15438),
                payload: &[1, 2, 3, 6, 5, 6, 7, 8, 9, 10, 11, 12, 13, 16, 15, 16],
            },
        ];
        for comparison in comparisons {
            let mut headers = sample::ipv6_icmp();
            headers.update_checksums(comparison.payload);
            match (headers.net, headers.transport) {
                (Some(Net::Ipv6(ipv6)), Some(Transport::Icmp6(icmp))) => {
                    assert_eq!(icmp.checksum().unwrap(), comparison.good_icmp);
                    let payload = Icmp6ChecksumPayload::new(
                        ipv6.source().inner(),
                        ipv6.destination(),
                        comparison.payload,
                    );
                    icmp.validate_checksum(&payload).unwrap();
                }
                _ => unreachable!(),
            }
        }
    }

    fn build_ipv6_with_hop_by_hop(
        transport_ip_number: etherparse::IpNumber,
        transport_header: &[u8],
    ) -> Vec<u8> {
        // Minimal hop-by-hop options header (8 bytes total): 6-byte payload
        let hop_by_hop =
            etherparse::Ipv6RawExtHeader::new_raw(transport_ip_number, &[0u8; 6]).unwrap();
        let ext_len = 8u16;
        let payload_length = ext_len + u16::try_from(transport_header.len()).unwrap();

        let eth = etherparse::Ethernet2Header {
            source: [0x02, 0xca, 0xfe, 0xba, 0xbe, 0x01],
            destination: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ether_type: etherparse::EtherType::IPV6,
        };
        let ipv6 = etherparse::Ipv6Header {
            traffic_class: 0,
            flow_label: 0.try_into().unwrap(),
            payload_length,
            next_header: etherparse::IpNumber::IPV6_HEADER_HOP_BY_HOP,
            hop_limit: 64,
            source: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            destination: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        };

        let mut buf = Vec::new();
        eth.write(&mut buf).unwrap();
        ipv6.write(&mut buf).unwrap();
        hop_by_hop.write(&mut buf).unwrap();
        buf.extend_from_slice(transport_header);
        buf
    }

    fn minimal_tcp_header_bytes(src: u16, dst: u16) -> [u8; 20] {
        let mut buf = [0u8; 20];
        buf[0..2].copy_from_slice(&src.to_be_bytes());
        buf[2..4].copy_from_slice(&dst.to_be_bytes());
        buf[12] = 5 << 4; // data offset = 5 → 20 bytes
        buf
    }

    #[test]
    fn ipv6_hop_by_hop_tcp_roundtrip() {
        let tcp_bytes = minimal_tcp_header_bytes(80, 443);
        let raw = build_ipv6_with_hop_by_hop(etherparse::IpNumber::TCP, &tcp_bytes);

        let (headers, bytes_parsed) = Headers::parse(&raw).expect("parse failed");

        // The extension header must have been parsed into net_ext.
        assert_eq!(
            headers.net_ext.len(),
            1,
            "expected one IPv6 extension header"
        );
        assert!(
            matches!(headers.net_ext[0], super::NetExt::HopByHop(_)),
            "expected HopByHop variant in net_ext"
        );

        // IPv6 and TCP should be present.
        assert!(matches!(headers.net, Some(Net::Ipv6(_))));
        assert!(matches!(headers.transport, Some(Transport::Tcp(_))));

        // Deparse → reparse round-trip.
        let size = headers.size().into_non_zero_usize().get();
        assert_eq!(bytes_parsed.into_non_zero_usize().get(), size);

        let mut buf = vec![0u8; size];
        let written = headers.deparse(&mut buf).expect("deparse failed");
        assert_eq!(written.into_non_zero_usize().get(), size);

        let (reparsed, _) = Headers::parse(&buf).expect("reparse failed");
        assert_eq!(headers, reparsed);
    }

    #[test]
    fn ipv6_ext_header_included_in_size() {
        let tcp_bytes = minimal_tcp_header_bytes(80, 443);
        let raw = build_ipv6_with_hop_by_hop(etherparse::IpNumber::TCP, &tcp_bytes);

        let (headers, _) = Headers::parse(&raw).expect("parse failed");

        // Eth(14) + IPv6(40) + HopByHop(8) + TCP(20) = 82
        assert_eq!(
            headers.size().get(),
            14 + 40 + 8 + 20,
            "size must include extension header"
        );
    }
}
