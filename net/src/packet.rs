// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Packet definition
#![allow(missing_docs)] // temporary

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
use crate::udp::Udp;
use crate::vlan::Vlan;
use arrayvec::ArrayVec;
use std::num::NonZero;
use tracing::debug;

const MAX_VLANS: usize = 4;
const MAX_NET_EXTENSIONS: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    eth: Eth,
    net: Option<Net>,
    transport: Option<Transport>,
    vlan: ArrayVec<Vlan, MAX_VLANS>,
    net_ext: ArrayVec<NetExt, MAX_NET_EXTENSIONS>,
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
}

impl ParsePayload for Header {
    type Next = Header;

    fn parse_payload(&self, cursor: &mut Reader) -> Option<Self::Next> {
        use Header::{Eth, Icmp4, Icmp6, IpAuth, IpV6Ext, Ipv4, Ipv6, Tcp, Udp, Vlan};
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
            Tcp(_) | Udp(_) | Icmp4(_) | Icmp6(_) => None,
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
        NonZero::new(eth + vlan + net + transport).unwrap_or_else(|| unreachable!())
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<usize>, DeParseError<Self::Error>> {
        // TODO(blocking): Deal with ip{v4,v6} extensions
        let len = buf.len();
        if len < self.size().get() {
            return Err(DeParseError::Length(LengthError {
                expected: self.size(),
                actual: len,
            }));
        };
        let mut cursor = Writer::new(buf);
        cursor.write(&self.eth)?;
        for vlan in &self.vlan {
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
        };

        match self.transport {
            None => {
                return Ok(NonZero::new(cursor.inner.len() - cursor.remaining)
                    .unwrap_or_else(|| unreachable!()))
            }
            Some(ref transport) => {
                cursor.write(transport)?;
            }
        }
        Ok(NonZero::new(cursor.inner.len() - cursor.remaining).unwrap_or_else(|| unreachable!()))
    }
}
