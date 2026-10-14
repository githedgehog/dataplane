// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Shorthands for building test packets from literals.
//!
//! Addresses, ports, MACs and VNIs are accepted as strings or as their typed
//! values, so a test can say what it means without constructing every type:
//!
//! ```ignore
//! use net::headers::builder::quick::*;
//!
//! // A TCP SYN from 10.0.0.1:12345 to 10.0.0.2:80.
//! let syn = tcp("10.0.0.1:12345", "10.0.0.2:80")
//!     .with(|tcp| { tcp.set_syn(true); })
//!     .build_packet()
//!     .unwrap();
//!
//! // IPv6 works the same; the family comes from the addresses.
//! let dns = udp("[2001:db8::1]:5353", "[2001:db8::2]:53").build_packet().unwrap();
//!
//! // Ports can be strings too, and endpoints can be `(ip, port)` pairs.
//! let web = tcp(("10.0.0.1", "40000"), ("10.0.0.2", "443")).build_packet().unwrap();
//!
//! // Anything the shorthands do not cover is still a `HeaderStack`.
//! let tagged = HeaderStack::new()
//!     .eth_macs("02:00:00:00:00:01", "02:00:00:00:00:02")
//!     .vlan_id(100)
//!     .ipv4_addrs("10.0.0.1", "10.0.0.2")
//!     .udp_ports("5000", 53)
//!     .build_packet()
//!     .unwrap();
//! ```
//!
//! Every shorthand panics, naming the offending literal and the calling line,
//! when a value does not parse or is not valid where it is used (a multicast
//! source address, port 0, ...). This is test-facing code: a bad literal is a
//! bug in the test.
//!
//! IP layers built here carry a TTL / hop limit of [`DEFAULT_TTL`] rather than
//! the blank 0, so they survive a routing stage.

// Test-facing: a literal that does not parse is a bug in the test, and the
// panic names it at the caller's line.
#![allow(clippy::panic)]

use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use super::{HeaderStack, Install, Within};
use crate::eth::Eth;
use crate::eth::mac::{DestinationMac, Mac, SourceMac};
use crate::headers::Headers;
use crate::icmp4::Icmp4EchoRequest;
use crate::icmp6::Icmp6EchoRequest;
use crate::ipv4::Ipv4;
use crate::ipv4::addr::UnicastIpv4Addr;
use crate::ipv6::Ipv6;
use crate::ipv6::addr::UnicastIpv6Addr;
use crate::tcp::Tcp;
use crate::tcp::port::TcpPort;
use crate::udp::Udp;
use crate::udp::port::UdpPort;
use crate::vlan::{Vid, Vlan};
use crate::vxlan::{Vni, Vxlan};

/// TTL / hop limit given to IP layers built by these shorthands.
pub const DEFAULT_TTL: u8 = 64;

// ---------------------------------------------------------------------------
// Literal conversions
// ---------------------------------------------------------------------------

#[track_caller]
fn parse<T>(what: &str, literal: &str) -> T
where
    T: FromStr,
    T::Err: Debug,
{
    match literal.parse() {
        Ok(value) => value,
        Err(e) => panic!("{literal:?} is not a valid {what}: {e:?}"),
    }
}

/// Implement a literal trait for `&str` and `String` by parsing.
macro_rules! from_text {
    ($trait:ident :: $method:ident -> $out:ty, $what:literal) => {
        impl $trait for &str {
            #[track_caller]
            fn $method(self) -> $out {
                parse($what, self)
            }
        }
        impl $trait for String {
            #[track_caller]
            fn $method(self) -> $out {
                parse($what, &self)
            }
        }
    };
}

/// Implement a literal trait for types that convert into the output losslessly.
macro_rules! from_value {
    ($trait:ident :: $method:ident -> $out:ty, $($ty:ty),+) => {
        $(
            impl $trait for $ty {
                fn $method(self) -> $out {
                    self.into()
                }
            }
        )+
    };
}

/// Something that names an IP address of either family: `"10.0.0.1"`,
/// `"2001:db8::1"`, or an [`IpAddr`] / [`Ipv4Addr`] / [`Ipv6Addr`].
pub trait IntoIpAddr {
    /// Produce the address, panicking if it does not parse.
    fn into_ip_addr(self) -> IpAddr;
}
from_text!(IntoIpAddr::into_ip_addr -> IpAddr, "IP address");
from_value!(IntoIpAddr::into_ip_addr -> IpAddr, IpAddr, Ipv4Addr, Ipv6Addr);

/// Something that names an IPv4 address: `"10.0.0.1"`, an [`Ipv4Addr`], or
/// its octets.
pub trait IntoIpv4Addr {
    /// Produce the address, panicking if it does not parse.
    fn into_ipv4_addr(self) -> Ipv4Addr;
}
from_text!(IntoIpv4Addr::into_ipv4_addr -> Ipv4Addr, "IPv4 address");
from_value!(IntoIpv4Addr::into_ipv4_addr -> Ipv4Addr, Ipv4Addr, [u8; 4]);

/// Something that names an IPv6 address: `"2001:db8::1"`, an [`Ipv6Addr`], or
/// its segments.
pub trait IntoIpv6Addr {
    /// Produce the address, panicking if it does not parse.
    fn into_ipv6_addr(self) -> Ipv6Addr;
}
from_text!(IntoIpv6Addr::into_ipv6_addr -> Ipv6Addr, "IPv6 address");
from_value!(IntoIpv6Addr::into_ipv6_addr -> Ipv6Addr, Ipv6Addr, [u16; 8]);

/// Something that names a TCP / UDP port: `80` or `"80"`.
pub trait IntoPort {
    /// Produce the port number, panicking if it does not parse.
    fn into_port(self) -> u16;
}
from_text!(IntoPort::into_port -> u16, "port");
from_value!(IntoPort::into_port -> u16, u16);

/// Something that names a MAC address: `"02:00:00:00:00:01"`, a [`Mac`], or
/// its octets.
pub trait IntoMac {
    /// Produce the address, panicking if it does not parse.
    fn into_mac(self) -> Mac;
}
from_text!(IntoMac::into_mac -> Mac, "MAC address");
impl IntoMac for Mac {
    fn into_mac(self) -> Mac {
        self
    }
}
impl IntoMac for [u8; 6] {
    fn into_mac(self) -> Mac {
        Mac(self)
    }
}

/// Something that names a transport endpoint: `"10.0.0.1:80"`,
/// `"[2001:db8::1]:80"`, a [`SocketAddr`], or an `(address, port)` pair of
/// anything [`IntoIpAddr`] and [`IntoPort`] accept.
pub trait IntoEndpoint {
    /// Produce the endpoint, panicking if it does not parse.
    fn into_endpoint(self) -> SocketAddr;
}
from_text!(IntoEndpoint::into_endpoint -> SocketAddr, "endpoint (address:port)");
impl IntoEndpoint for SocketAddr {
    fn into_endpoint(self) -> SocketAddr {
        self
    }
}
impl<A: IntoIpAddr, P: IntoPort> IntoEndpoint for (A, P) {
    #[track_caller]
    fn into_endpoint(self) -> SocketAddr {
        SocketAddr::new(self.0.into_ip_addr(), self.1.into_port())
    }
}

// Validated forms. Each takes an already-converted value so the panic location
// is the shorthand's caller, not a closure.

#[track_caller]
fn unicast_v4(addr: Ipv4Addr) -> UnicastIpv4Addr {
    UnicastIpv4Addr::new(addr)
        .unwrap_or_else(|_| panic!("{addr} cannot be a source address: it is not unicast"))
}

#[track_caller]
fn unicast_v6(addr: Ipv6Addr) -> UnicastIpv6Addr {
    UnicastIpv6Addr::new(addr)
        .unwrap_or_else(|_| panic!("{addr} cannot be a source address: it is not unicast"))
}

#[track_caller]
fn tcp_port(port: u16) -> TcpPort {
    TcpPort::new_checked(port).unwrap_or_else(|_| panic!("{port} is not a valid TCP port"))
}

#[track_caller]
fn udp_port(port: u16) -> UdpPort {
    UdpPort::new_checked(port).unwrap_or_else(|_| panic!("{port} is not a valid UDP port"))
}

// ---------------------------------------------------------------------------
// Shorthand layer methods
// ---------------------------------------------------------------------------

impl<T> HeaderStack<T>
where
    Headers: Install<T>,
{
    /// Adjust the layer on top of the stack.
    ///
    /// Useful after a shorthand that built the layer for you:
    /// `tcp("10.0.0.1:1", "10.0.0.2:2").with(|tcp| { tcp.set_syn(true); })`.
    #[must_use]
    pub fn with(mut self, f: impl FnOnce(&mut T)) -> Self {
        f(&mut self.working);
        self
    }

    /// Push an `Eth` layer with the given source and destination MACs.
    ///
    /// # Panics
    ///
    /// If a MAC does not parse, or is not valid in its position (e.g. a
    /// multicast source).
    #[track_caller]
    pub fn eth_macs(self, src: impl IntoMac, dst: impl IntoMac) -> HeaderStack<Eth>
    where
        Eth: Within<T>,
    {
        let (src, dst) = (src.into_mac(), dst.into_mac());
        let src =
            SourceMac::new(src).unwrap_or_else(|e| panic!("{src} cannot be a source MAC: {e:?}"));
        let dst = DestinationMac::new(dst)
            .unwrap_or_else(|e| panic!("{dst} cannot be a destination MAC: {e:?}"));
        self.eth(|eth| {
            eth.set_source(src).set_destination(dst);
        })
    }

    /// Push a `Vlan` layer with the given VLAN id.
    ///
    /// # Panics
    ///
    /// If `vid` is not a valid VLAN id (1..=4094).
    #[track_caller]
    pub fn vlan_id(self, vid: u16) -> HeaderStack<Vlan>
    where
        Vlan: Within<T>,
    {
        let vid = Vid::new(vid).unwrap_or_else(|e| panic!("{vid} is not a valid VLAN id: {e:?}"));
        self.vlan(|vlan| {
            vlan.set_vid(vid);
        })
    }

    /// Push an `Ipv4` layer with the given addresses and a TTL of
    /// [`DEFAULT_TTL`].
    ///
    /// # Panics
    ///
    /// If an address does not parse, or the source is not unicast.
    #[track_caller]
    pub fn ipv4_addrs(self, src: impl IntoIpv4Addr, dst: impl IntoIpv4Addr) -> HeaderStack<Ipv4>
    where
        Ipv4: Within<T>,
    {
        let src = unicast_v4(src.into_ipv4_addr());
        let dst = dst.into_ipv4_addr();
        self.ipv4(|ip| {
            ip.set_source(src).set_destination(dst).set_ttl(DEFAULT_TTL);
        })
    }

    /// Push an `Ipv6` layer with the given addresses and a hop limit of
    /// [`DEFAULT_TTL`].
    ///
    /// # Panics
    ///
    /// If an address does not parse, or the source is not unicast.
    #[track_caller]
    pub fn ipv6_addrs(self, src: impl IntoIpv6Addr, dst: impl IntoIpv6Addr) -> HeaderStack<Ipv6>
    where
        Ipv6: Within<T>,
    {
        let src = unicast_v6(src.into_ipv6_addr());
        let dst = dst.into_ipv6_addr();
        self.ipv6(|ip| {
            ip.set_source(src)
                .set_destination(dst)
                .set_hop_limit(DEFAULT_TTL);
        })
    }

    /// Push a `Tcp` layer with the given ports.
    ///
    /// # Panics
    ///
    /// If a port does not parse or is 0.
    #[track_caller]
    pub fn tcp_ports(self, src: impl IntoPort, dst: impl IntoPort) -> HeaderStack<Tcp>
    where
        Tcp: Within<T>,
    {
        let src = tcp_port(src.into_port());
        let dst = tcp_port(dst.into_port());
        self.tcp(|tcp| {
            tcp.set_source(src);
            tcp.set_destination(dst);
        })
    }

    /// Push a `Udp` layer with the given ports.
    ///
    /// # Panics
    ///
    /// If a port does not parse or is 0.
    #[track_caller]
    pub fn udp_ports(self, src: impl IntoPort, dst: impl IntoPort) -> HeaderStack<Udp>
    where
        Udp: Within<T>,
    {
        let src = udp_port(src.into_port());
        let dst = udp_port(dst.into_port());
        self.udp(|udp| {
            udp.set_source(src);
            udp.set_destination(dst);
        })
    }

    /// Push a `Vxlan` layer with the given VNI.
    ///
    /// # Panics
    ///
    /// If `vni` is not a valid VNI.
    #[track_caller]
    pub fn vxlan_vni(self, vni: u32) -> HeaderStack<Vxlan>
    where
        Vxlan: Within<T>,
    {
        let vni =
            Vni::new_checked(vni).unwrap_or_else(|e| panic!("{vni} is not a valid VNI: {e:?}"));
        self.vxlan(|vxlan| *vxlan = Vxlan::new(vni))
    }
}

// ---------------------------------------------------------------------------
// Dedicated packets
// ---------------------------------------------------------------------------

/// Build `Eth` + the IP layer matching the address family, then `$top`.
macro_rules! over_ip {
    ($src:expr, $dst:expr, |$stack:ident| $top:expr) => {
        match ($src, $dst) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                let $stack = HeaderStack::new().eth(|_| {}).ipv4_addrs(src, dst);
                $top
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                let $stack = HeaderStack::new().eth(|_| {}).ipv6_addrs(src, dst);
                $top
            }
            (src, dst) => panic!("{src} and {dst} are different address families"),
        }
    };
}

/// A TCP segment from `src` to `dst` over IPv4 or IPv6, chosen by the
/// addresses.
///
/// ```ignore
/// let packet = tcp("10.0.0.1:12345", "10.0.0.2:80").build_packet().unwrap();
/// ```
///
/// # Panics
///
/// If an endpoint does not parse, the families differ, the source is not
/// unicast, or a port is 0.
#[track_caller]
pub fn tcp(src: impl IntoEndpoint, dst: impl IntoEndpoint) -> HeaderStack<Tcp> {
    let (src, dst) = (src.into_endpoint(), dst.into_endpoint());
    over_ip!(src.ip(), dst.ip(), |stack| stack
        .tcp_ports(src.port(), dst.port()))
}

/// A UDP datagram from `src` to `dst` over IPv4 or IPv6, chosen by the
/// addresses.
///
/// ```ignore
/// let packet = udp("[2001:db8::1]:5353", "[2001:db8::2]:53").build_packet().unwrap();
/// ```
///
/// # Panics
///
/// If an endpoint does not parse, the families differ, the source is not
/// unicast, or a port is 0.
#[track_caller]
pub fn udp(src: impl IntoEndpoint, dst: impl IntoEndpoint) -> HeaderStack<Udp> {
    let (src, dst) = (src.into_endpoint(), dst.into_endpoint());
    over_ip!(src.ip(), dst.ip(), |stack| stack
        .udp_ports(src.port(), dst.port()))
}

/// An `ICMPv4` echo request from `src` to `dst`, with id and sequence 0.
///
/// ```ignore
/// let ping = icmp4_echo_request("10.0.0.1", "10.0.0.2")
///     .with(|echo| echo.id = 7)
///     .build_packet()
///     .unwrap();
/// ```
///
/// # Panics
///
/// If an address does not parse or the source is not unicast.
#[track_caller]
pub fn icmp4_echo_request(
    src: impl IntoIpv4Addr,
    dst: impl IntoIpv4Addr,
) -> HeaderStack<Icmp4EchoRequest> {
    HeaderStack::new()
        .eth(|_| {})
        .ipv4_addrs(src, dst)
        .icmp4(|_| {})
        .echo_request(|_| {})
}

/// An `ICMPv6` echo request from `src` to `dst`, with id and sequence 0.
///
/// # Panics
///
/// If an address does not parse or the source is not unicast.
#[track_caller]
pub fn icmp6_echo_request(
    src: impl IntoIpv6Addr,
    dst: impl IntoIpv6Addr,
) -> HeaderStack<Icmp6EchoRequest> {
    HeaderStack::new()
        .eth(|_| {})
        .ipv6_addrs(src, dst)
        .icmp6(|_| {})
        .echo_request6(|_| {})
}

/// The outer headers of a VXLAN tunnel from VTEP `src` to VTEP `dst` on
/// `vni`.
///
/// Finish with the inner Ethernet frame as payload:
///
/// ```ignore
/// let inner = udp("10.0.0.1:1234", "10.0.0.2:80").build_packet().unwrap();
/// let outer = vxlan("192.0.2.1", "192.0.2.2", 100)
///     .build_packet_with_payload(inner.serialize().unwrap().as_ref())
///     .unwrap();
/// ```
///
/// # Panics
///
/// If an address does not parse, the families differ, the source is not
/// unicast, or `vni` is not a valid VNI.
#[track_caller]
pub fn vxlan(src: impl IntoIpAddr, dst: impl IntoIpAddr, vni: u32) -> HeaderStack<Vxlan> {
    over_ip!(src.into_ip_addr(), dst.into_ip_addr(), |stack| stack
        .udp(|_| {})
        .vxlan_vni(vni))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::TestBuffer;
    use crate::headers::{Net, Transport, TryHeaders};
    use crate::packet::Packet;
    use crate::udp::UdpEncap;

    fn assert_checksums_current(packet: &Packet<TestBuffer>) {
        let mut recomputed = packet.deep_copy().unwrap();
        recomputed.update_checksums();
        assert_eq!(packet.headers(), recomputed.headers(), "stale checksum");
    }

    #[test]
    fn tcp_from_strings() {
        let packet = tcp("10.0.0.1:12345", "10.0.0.2:80")
            .with(|tcp| {
                tcp.set_syn(true);
            })
            .build_packet()
            .unwrap();

        let Some(Net::Ipv4(ip)) = packet.headers().net() else {
            panic!("expected Ipv4");
        };
        assert_eq!(ip.source().inner(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ip.destination(), Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(ip.ttl(), DEFAULT_TTL);
        let Some(Transport::Tcp(tcp)) = packet.headers().transport() else {
            panic!("expected Tcp");
        };
        assert_eq!(tcp.source().as_u16(), 12345);
        assert_eq!(tcp.destination().as_u16(), 80);
        assert!(tcp.syn());
        assert_checksums_current(&packet);
    }

    #[test]
    fn udp_over_ipv6() {
        let packet = udp("[2001:db8::1]:5353", "[2001:db8::2]:53")
            .build_packet()
            .unwrap();

        let Some(Net::Ipv6(ip)) = packet.headers().net() else {
            panic!("expected Ipv6");
        };
        assert_eq!(ip.destination(), "2001:db8::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(ip.hop_limit(), DEFAULT_TTL);
        let Some(Transport::Udp(udp)) = packet.headers().transport() else {
            panic!("expected Udp");
        };
        assert_eq!(udp.destination().as_u16(), 53);
        assert_checksums_current(&packet);
    }

    #[test]
    fn endpoints_as_pairs_with_string_ports() {
        let from_pairs = tcp(("10.0.0.1", "40000"), ("10.0.0.2", 443))
            .build_headers()
            .unwrap();
        let from_text = tcp("10.0.0.1:40000", "10.0.0.2:443")
            .build_headers()
            .unwrap();
        assert_eq!(from_pairs, from_text);
    }

    #[test]
    fn custom_stack_from_shorthands() {
        let packet = HeaderStack::new()
            .eth_macs("02:00:00:00:00:01", "02:00:00:00:00:02")
            .vlan_id(100)
            .ipv4_addrs("10.0.0.1", [10, 0, 0, 2])
            .udp_ports("5000", 53)
            .build_packet()
            .unwrap();

        assert_eq!(packet.headers().vlan()[0].vid(), Vid::new(100).unwrap());
        assert_checksums_current(&packet);
    }

    #[test]
    fn echo_request_with_id() {
        let packet = icmp4_echo_request("10.0.0.1", "10.0.0.2")
            .with(|echo| echo.id = 7)
            .build_packet()
            .unwrap();
        assert_checksums_current(&packet);

        let packet = icmp6_echo_request("2001:db8::1", "2001:db8::2")
            .build_packet()
            .unwrap();
        assert_checksums_current(&packet);
    }

    #[test]
    fn vxlan_carries_inner_frame() {
        let inner = udp("10.0.0.1:1234", "10.0.0.2:80")
            .build_packet()
            .unwrap()
            .serialize()
            .unwrap();
        let outer = vxlan("192.0.2.1", "192.0.2.2", 100)
            .build_packet_with_payload(inner.as_ref())
            .unwrap();

        let Some(UdpEncap::Vxlan(vxlan)) = outer.headers().udp_encap() else {
            panic!("expected Vxlan");
        };
        assert_eq!(vxlan.vni().as_u32(), 100);
        assert_eq!(outer.payload().as_ref(), inner.as_ref());
    }

    #[test]
    #[should_panic(expected = "\"10.0.0.300\" is not a valid IP address")]
    fn bad_address_names_the_literal() {
        let _ = udp(("10.0.0.300", 1), ("10.0.0.2", 2));
    }

    #[test]
    #[should_panic(expected = "different address families")]
    fn mixed_families_are_rejected() {
        let _ = tcp("10.0.0.1:1", "[2001:db8::1]:2");
    }

    #[test]
    #[should_panic(expected = "0 is not a valid TCP port")]
    fn port_zero_is_rejected() {
        let _ = tcp("10.0.0.1:0", "10.0.0.2:80");
    }
}
