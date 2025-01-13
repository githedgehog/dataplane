//! Packet definition
#![allow(missing_docs)] // temporary

use crate::header::{Eth, Header, Net, NetExt, Step, Transport, Vlan};
use crate::parse::{Cursor, LengthError, Parse, ParseError};
use arrayvec::ArrayVec;
use std::num::NonZero;

const MAX_VLANS: usize = 4;
const MAX_NET_EXTENSIONS: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    link: Option<Eth>,
    net: Option<Net>,
    transport: Option<Transport>,
    vlan: ArrayVec<Vlan, MAX_VLANS>,
    net_ext: ArrayVec<NetExt, MAX_NET_EXTENSIONS>,
}

impl Parse for Packet {
    type Error = LengthError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>> {
        let mut cursor = Cursor::new(buf);
        let (eth, _) = cursor.parse::<Eth>()?;
        let mut prior = Header::Eth(eth);
        let mut this = Packet {
            link: None,
            net: None,
            transport: None,
            vlan: ArrayVec::default(),
            net_ext: ArrayVec::default(),
        };
        loop {
            let header = prior.step(&mut cursor);
            match prior {
                Header::Eth(eth) => {
                    this.link = Some(eth);
                }
                Header::Vlan(vlan) => {
                    if this.vlan.len() < MAX_VLANS {
                        this.vlan.push(vlan);
                    } else {
                        break;
                    }
                }
                Header::Ipv4(ip) => {
                    this.net = Some(Net::Ipv4(ip));
                }
                Header::Ipv6(ip) => {
                    this.net = Some(Net::Ipv6(ip));
                }
                Header::Tcp(tcp) => {
                    this.transport = Some(Transport::Tcp(tcp));
                }
                Header::Udp(udp) => {
                    this.transport = Some(Transport::Udp(udp));
                }
                Header::Icmp4(icmp4) => {
                    this.transport = Some(Transport::Icmp4(icmp4));
                }
                Header::Icmp6(icmp6) => {
                    this.transport = Some(Transport::Icmp6(icmp6));
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
        let consumed = unsafe { NonZero::new_unchecked(buf.len() - cursor.inner.len()) };
        Ok((this, consumed))
    }
}
