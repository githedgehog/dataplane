// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The parts of a frame that decide its class.

use std::net::{Ipv4Addr, Ipv6Addr};

use net::eth::ethtype::EthType;
use net::eth::mac::Mac;
use net::headers::{Headers, Net, Transport};

/// The fields of a received frame its class depends on, as a NIC's flow rules see them.
///
/// Only the outermost headers count: a VLAN-tagged frame is a [`Frame::Other`] of the tag's type,
/// and the protocol of an IPv6 packet is its header's next header field, whatever extension headers
/// follow.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Key {
    /// The destination MAC address.
    pub dst_mac: Mac,
    /// What the Ethernet header carries.
    pub frame: Frame,
}

/// What an Ethernet header carries.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Frame {
    /// An IPv4 packet (ethertype 0x0800).
    Ipv4(Ip<Ipv4Addr>),
    /// An IPv6 packet (ethertype 0x86dd).
    Ipv6(Ip<Ipv6Addr>),
    /// Anything else, by its ethertype.
    Other(EthType),
}

/// The addressing of an IP packet.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Ip<A> {
    /// The source address.
    pub src: A,
    /// The destination address.
    pub dst: A,
    /// The protocol the IP header names, with its ports when they are known.
    pub l4: L4,
}

/// The protocol an IP header names.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum L4 {
    /// TCP, with the ports of the header that follows the IP header.
    Tcp(Ports),
    /// UDP, with the ports of the header that follows the IP header.
    Udp(Ports),
    /// Any protocol whose ports are not known: one that has none, or TCP or UDP behind extension
    /// headers or in a non-first fragment.
    Proto(u8),
}

/// The source and destination ports of a TCP or UDP header.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Ports {
    /// The source port.
    pub src: u16,
    /// The destination port.
    pub dst: u16,
}

/// A frame without an Ethernet header, which no class can describe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the frame has no Ethernet header")]
pub struct NotEthernet;

impl Key {
    /// The key of the frame `headers` were parsed from.
    ///
    /// # Errors
    ///
    /// [`NotEthernet`] if `headers` has no Ethernet header.
    pub fn of(headers: &Headers) -> Result<Key, NotEthernet> {
        let eth = headers.eth().ok_or(NotEthernet)?;
        let dst_mac = eth.destination().inner();
        if !headers.vlan().is_empty() {
            return Ok(Key {
                dst_mac,
                frame: Frame::Other(eth.ether_type()),
            });
        }
        let frame = match headers.net() {
            Some(Net::Ipv4(ip)) => Frame::Ipv4(Ip {
                src: ip.source().inner(),
                dst: ip.destination(),
                l4: l4(headers, ip.next_header().as_u8()),
            }),
            Some(Net::Ipv6(ip)) => Frame::Ipv6(Ip {
                src: ip.source().inner(),
                dst: ip.destination(),
                l4: l4(headers, ip.next_header().as_u8()),
            }),
            None => Frame::Other(eth.ether_type()),
        };
        Ok(Key { dst_mac, frame })
    }
}

/// The protocol `proto` the IP header of `headers` names, with ports if they follow that header.
fn l4(headers: &Headers, proto: u8) -> L4 {
    // Ports behind extension headers or fragmentation are not where a NIC looks for them.
    if !headers.net_ext().is_empty() || headers.is_non_first_fragment() {
        return L4::Proto(proto);
    }
    let ports = |t: &Transport| {
        Some(Ports {
            src: t.src_port()?.get(),
            dst: t.dst_port()?.get(),
        })
    };
    match headers.transport() {
        Some(t @ Transport::Tcp(_)) => ports(t).map_or(L4::Proto(proto), L4::Tcp),
        Some(t @ Transport::Udp(_)) => ports(t).map_or(L4::Proto(proto), L4::Udp),
        Some(Transport::Icmp4(_) | Transport::Icmp6(_)) | None => L4::Proto(proto),
    }
}

impl L4 {
    /// The protocol number.
    #[must_use]
    pub fn proto(self) -> u8 {
        match self {
            L4::Tcp(_) => TCP,
            L4::Udp(_) => UDP,
            L4::Proto(proto) => proto,
        }
    }
}

/// TCP's protocol number.
pub(crate) const TCP: u8 = 6;
/// UDP's protocol number.
pub(crate) const UDP: u8 = 17;
/// `ICMPv6`'s next header number.
pub(crate) const ICMP6: u8 = 58;
