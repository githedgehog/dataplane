// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Packet definition
#![allow(missing_docs, clippy::pedantic)] // temporary

use crate::eth::ethtype::EthType;
use crate::eth::{Eth, EthError};
use crate::icmp4::Icmp4;
use crate::icmp6::Icmp6;
use crate::ip_auth::IpAuth;
use crate::ipv4::Ipv4;
use crate::ipv6::{Ipv6, Ipv6Ext};
use crate::parse::{
    DeParse, DeParseError, LengthError, Parse, ParseError, ParsePayload, ParsePayloadWith, Reader,
    Writer,
};
use crate::tcp::Tcp;
use crate::udp::{Udp, UdpEncap};
use crate::vlan::{Pcp, Vid, Vlan};
use crate::vxlan::Vxlan;
use arrayvec::ArrayVec;
use std::num::NonZero;
use tracing::debug;

const MAX_VLANS: usize = 4;
const MAX_NET_EXTENSIONS: usize = 2;

// TODO: remove `pub` from all fields
#[derive(Debug)]
pub struct Packet {
    pub eth: Eth,
    pub vlan: ArrayVec<Vlan, MAX_VLANS>,
    pub net: Option<Net>,
    pub net_ext: ArrayVec<NetExt, MAX_NET_EXTENSIONS>,
    pub transport: Option<Transport>,
    pub udp_encap: Option<UdpEncap>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Net {
    Ipv4(Ipv4),
    Ipv6(Ipv6),
}

impl DeParse for Net {
    type Error = ();

    fn size(&self) -> NonZero<usize> {
        match self {
            Net::Ipv4(ip) => ip.size(),
            Net::Ipv6(ip) => ip.size(),
        }
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<usize>, DeParseError<Self::Error>> {
        match self {
            Net::Ipv4(ip) => ip.deparse(buf),
            Net::Ipv6(ip) => ip.deparse(buf),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetExt {
    IpAuth(IpAuth),
    Ipv6Ext(Ipv6Ext),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    Tcp(Tcp),
    Udp(Udp),
    Icmp4(Icmp4),
    Icmp6(Icmp6),
}

impl DeParse for Transport {
    type Error = ();

    fn size(&self) -> NonZero<usize> {
        match self {
            Transport::Tcp(x) => x.size(),
            Transport::Udp(x) => x.size(),
            Transport::Icmp4(x) => x.size(),
            Transport::Icmp6(x) => x.size(),
        }
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<usize>, DeParseError<Self::Error>> {
        match self {
            Transport::Tcp(x) => x.deparse(buf),
            Transport::Udp(x) => x.deparse(buf),
            Transport::Icmp4(x) => x.deparse(buf),
            Transport::Icmp6(x) => x.deparse(buf),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Header {
    Eth(Eth),
    Vlan(Vlan),
    Ipv4(Ipv4),
    Ipv6(Ipv6),
    Tcp(Tcp),
    Udp(Udp),
    Icmp4(Icmp4),
    Icmp6(Icmp6),
    IpAuth(IpAuth),
    IpV6Ext(Ipv6Ext), // TODO: break out nested enum.  Nesting is counter productive here
    Encap(UdpEncap),
}

impl ParsePayload for Header {
    type Next = Header;

    fn parse_payload(&self, cursor: &mut Reader) -> Option<Header> {
        use Header::{Encap, Eth, Icmp4, Icmp6, IpAuth, IpV6Ext, Ipv4, Ipv6, Tcp, Udp, Vlan};
        match self {
            Eth(eth) => eth.parse_payload(cursor).map(Header::from),
            Vlan(vlan) => vlan.parse_payload(cursor).map(Header::from),
            Ipv4(ipv4) => ipv4.parse_payload(cursor).map(Header::from),
            Ipv6(ipv6) => ipv6.parse_payload(cursor).map(Header::from),
            IpAuth(auth) => auth.parse_payload(cursor).map(Header::from),
            IpV6Ext(ext) => {
                if let Ipv6(ipv6) = self {
                    ext.parse_payload_with(&ipv6.next_header(), cursor)
                        .map(Header::from)
                } else {
                    debug!("ipv6 extension header outside ipv6 packet");
                    None
                }
            }
            Udp(udp) => udp.parse_payload(cursor).map(Header::from),
            Encap(_) | Tcp(_) | Icmp4(_) | Icmp6(_) => None,
        }
    }
}

impl Parse for Packet {
    type Error = EthError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>> {
        let mut cursor = Reader::new(buf);
        let (eth, _) = cursor.parse::<Eth>()?;
        let mut this = Packet {
            eth: eth.clone(),
            net: None,
            transport: None,
            vlan: ArrayVec::default(),
            net_ext: ArrayVec::default(),
            udp_encap: None,
        };
        let mut prior = Header::Eth(eth);
        loop {
            let header = prior.parse_payload(&mut cursor);
            match prior {
                Header::Eth(eth) => this.eth = eth,
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
                Header::IpAuth(auth) => {
                    if this.net_ext.len() < MAX_NET_EXTENSIONS {
                        this.net_ext.push(NetExt::IpAuth(auth));
                    } else {
                        break;
                    }
                }
                Header::IpV6Ext(ext) => {
                    if this.net_ext.len() < MAX_NET_EXTENSIONS {
                        this.net_ext.push(NetExt::Ipv6Ext(ext));
                    } else {
                        break;
                    }
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
        #[allow(unsafe_code)] // Non zero checked by parse impl
        let consumed = unsafe { NonZero::new_unchecked(cursor.inner.len() - cursor.remaining) };
        Ok((this, consumed))
    }
}

impl DeParse for Packet {
    type Error = ();

    fn size(&self) -> NonZero<usize> {
        // TODO(blocking): Deal with ip{v4,v6} extensions
        let eth = self.eth.size().get();
        let vlan = self.vlan.iter().map(|v| v.size().get()).sum::<usize>();
        let net = match self.net {
            None => {
                debug_assert!(self.transport.is_none());
                0
            }
            Some(ref n) => n.size().get(),
        };
        let transport = match self.transport {
            None => 0,
            Some(ref t) => t.size().get(),
        };
        let encap = match self.udp_encap {
            None => 0,
            Some(UdpEncap::Vxlan(vxlan)) => vxlan.size().get(),
        };
        NonZero::new(eth + vlan + net + transport + encap).unwrap_or_else(|| unreachable!())
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<usize>, DeParseError<Self::Error>> {
        // TODO(blocking): Deal with ip{v4,v6} extensions
        let len = buf.len();
        if len < self.size().get() {
            return Err(DeParseError::Length(LengthError {
                expected: self.size(),
                actual: len,
            }));
        }
        let mut cursor = Writer::new(buf);
        cursor.write(&self.eth)?;
        for vlan in self.vlan.iter().rev() {
            cursor.write(vlan)?;
        }
        match self.net {
            None => {
                debug_assert!(self.transport.is_none());
                return Ok(NonZero::new(cursor.inner.len() - cursor.remaining)
                    .unwrap_or_else(|| unreachable!()));
            }
            Some(ref net) => {
                cursor.write(net)?;
            }
        }

        match self.transport {
            None => {
                return Ok(NonZero::new(cursor.inner.len() - cursor.remaining)
                    .unwrap_or_else(|| unreachable!()))
            }
            Some(ref transport) => {
                cursor.write(transport)?;
            }
        }

        match self.udp_encap {
            None => {
                return Ok(NonZero::new(cursor.inner.len() - cursor.remaining)
                    .unwrap_or_else(|| unreachable!()))
            }
            Some(UdpEncap::Vxlan(ref vxlan)) => {
                cursor.write(vxlan)?;
            }
        }
        Ok(NonZero::new(cursor.inner.len() - cursor.remaining).unwrap_or_else(|| unreachable!()))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Packet already has as many VLAN headers as parser can support (max is {MAX_VLANS})")]
pub struct TooManyVlans;

impl Packet {
    /// Create a new packet with the supplied `Eth` header.
    pub fn new(eth: Eth) -> Packet {
        Packet {
            eth,
            vlan: ArrayVec::default(),
            net: None,
            net_ext: ArrayVec::default(),
            transport: None,
            udp_encap: None,
        }
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
    /// This method will create an invalid packet if the header you push has an _inner_ ethtype
    /// which does not align with the next header below it.
    ///
    /// This method will create an invalid packet if the _outer_ ethtype (i.e., the ethtype of the
    /// `Eth` header or prior [`Vlan`] in the stack) is not some flavor of `Vlan` ethtype (e.g.
    /// [`EthType::VLAN`] or [`EthType::VLAN_QINQ`])
    #[allow(unsafe_code)]
    #[allow(dead_code)]
    unsafe fn push_vlan_header_unchecked(&mut self, vlan: Vlan) -> Result<(), TooManyVlans> {
        if self.vlan.len() < MAX_VLANS {
            self.vlan.push(vlan);
            Ok(())
        } else {
            Err(TooManyVlans)
        }
    }

    /// Push a vlan header onto the VLAN stack of this packet.
    ///
    /// This method will ensure that the `eth` field has its [`EthType`] adjusted to
    /// [`EthType::VLAN`] if there are no [`Vlan`]s on the stack at the time this method was called.
    pub fn push_vlan(&mut self, vid: Vid) -> Result<(), TooManyVlans> {
        if self.vlan.len() >= MAX_VLANS {
            return Err(TooManyVlans);
        }
        let old_eth_type = self.eth.ether_type();
        self.eth.set_ether_type(EthType::VLAN);
        let new_vlan_header = Vlan::new(vid, old_eth_type, Pcp::default(), false);
        self.vlan.push(new_vlan_header);
        Ok(())
    }

    /// Pop a vlan header from the stack.
    ///
    /// Returns [`None`] if no [`Vlan`]s are on the stack.
    ///
    /// If `Some` is returned, the popped [`Vlan`]s ethtype is assigned to the `eth` header to
    /// preserve packet structure.
    ///
    /// If `None` is returned, the `Packet` is not modified.
    pub fn pop_vlan(&mut self) -> Option<Vlan> {
        match self.vlan.pop() {
            None => None,
            Some(vlan) => {
                self.eth.set_ether_type(vlan.inner_ethtype());
                Some(vlan)
            }
        }
    }

    pub fn eth(&self) -> &Eth {
        &self.eth
    }

    pub fn eth_mut(&mut self) -> &mut Eth {
        &mut self.eth
    }

    pub fn ipv4(&self) -> Option<&Ipv4> {
        match &self.net {
            Some(Net::Ipv4(header)) => Some(header),
            _ => None,
        }
    }

    pub fn ipv4_mut(&mut self) -> Option<&mut Ipv4> {
        match &mut self.net {
            Some(Net::Ipv4(header)) => Some(header),
            _ => None,
        }
    }

    pub fn ipv6(&self) -> Option<&Ipv6> {
        match &self.net {
            Some(Net::Ipv6(header)) => Some(header),
            _ => None,
        }
    }

    pub fn ipv6_mut(&mut self) -> Option<&mut Ipv6> {
        match &mut self.net {
            Some(Net::Ipv6(header)) => Some(header),
            _ => None,
        }
    }

    pub fn tcp(&self) -> Option<&Tcp> {
        match &self.transport {
            Some(Transport::Tcp(header)) => Some(header),
            _ => None,
        }
    }

    pub fn tcp_mut(&mut self) -> Option<&mut Tcp> {
        match &mut self.transport {
            Some(Transport::Tcp(header)) => Some(header),
            _ => None,
        }
    }

    pub fn udp(&self) -> Option<&Udp> {
        match &self.transport {
            Some(Transport::Udp(header)) => Some(header),
            _ => None,
        }
    }

    pub fn udp_mut(&mut self) -> Option<&mut Udp> {
        match &mut self.transport {
            Some(Transport::Udp(header)) => Some(header),
            _ => None,
        }
    }

    pub fn icmp(&self) -> Option<&Icmp4> {
        match &self.transport {
            Some(Transport::Icmp4(header)) => Some(header),
            _ => None,
        }
    }

    pub fn icmp_mut(&mut self) -> Option<&mut Icmp4> {
        match &mut self.transport {
            Some(Transport::Icmp4(header)) => Some(header),
            _ => None,
        }
    }

    pub fn icmp6(&self) -> Option<&Icmp6> {
        match &self.transport {
            Some(Transport::Icmp6(header)) => Some(header),
            _ => None,
        }
    }

    pub fn icmp6_mut(&mut self) -> Option<&mut Icmp6> {
        match &mut self.transport {
            Some(Transport::Icmp6(header)) => Some(header),
            _ => None,
        }
    }

    pub fn vxlan(&self) -> Option<&Vxlan> {
        match &self.udp_encap {
            Some(UdpEncap::Vxlan(vxlan)) => Some(vxlan),
            _ => None,
        }
    }

    pub fn vxlan_mut(&mut self) -> Option<&mut Vxlan> {
        match &mut self.udp_encap {
            Some(UdpEncap::Vxlan(vxlan)) => Some(vxlan),
            _ => None,
        }
    }
}
