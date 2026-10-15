// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Shorthands for building test packets from literals.
//!
//! ```ignore
//! use net::headers::builder::quick::*;
//!
//! let syn = tcp("10.0.0.1:12345", "10.0.0.2:80")
//!     .with(|tcp| { tcp.set_syn(true); })
//!     .build_packet()
//!     .unwrap();
//!
//! let tagged = HeaderStack::new()
//!     .eth_macs("02:00:00:00:00:01", "02:00:00:00:00:02")
//!     .vlan_id(100)
//!     .ipv4_addrs("10.0.0.1", "10.0.0.2")
//!     .udp_ports("5000", 53)
//!     .build_packet()
//!     .unwrap();
//! ```
//!
//! Values can be strings or typed values. A bad value panics at the caller's line.
//! IP layers get a TTL / hop limit of [`DEFAULT_TTL`].

// A bad literal is a bug in the test.
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

/// TTL / hop limit of the IP layers built here.
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

/// Implement a literal trait for types that convert with `into`.
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

/// An IPv4 or IPv6 address, as a string or a std address type.
pub trait IntoIpAddr {
    /// Convert, panicking on a bad value.
    fn into_ip_addr(self) -> IpAddr;
}
from_text!(IntoIpAddr::into_ip_addr -> IpAddr, "IP address");
from_value!(IntoIpAddr::into_ip_addr -> IpAddr, IpAddr, Ipv4Addr, Ipv6Addr);

/// An IPv4 address, as a string, an [`Ipv4Addr`] or octets.
pub trait IntoIpv4Addr {
    /// Convert, panicking on a bad value.
    fn into_ipv4_addr(self) -> Ipv4Addr;
}
from_text!(IntoIpv4Addr::into_ipv4_addr -> Ipv4Addr, "IPv4 address");
from_value!(IntoIpv4Addr::into_ipv4_addr -> Ipv4Addr, Ipv4Addr, [u8; 4]);

/// An IPv6 address, as a string, an [`Ipv6Addr`] or segments.
pub trait IntoIpv6Addr {
    /// Convert, panicking on a bad value.
    fn into_ipv6_addr(self) -> Ipv6Addr;
}
from_text!(IntoIpv6Addr::into_ipv6_addr -> Ipv6Addr, "IPv6 address");
from_value!(IntoIpv6Addr::into_ipv6_addr -> Ipv6Addr, Ipv6Addr, [u16; 8]);

/// A TCP / UDP port, as a number or a string.
pub trait IntoPort {
    /// Convert, panicking on a bad value.
    fn into_port(self) -> u16;
}
from_text!(IntoPort::into_port -> u16, "port");
from_value!(IntoPort::into_port -> u16, u16);

/// A MAC address, as a string, a [`Mac`] or octets.
pub trait IntoMac {
    /// Convert, panicking on a bad value.
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

/// An endpoint: `"10.0.0.1:80"`, `"[2001:db8::1]:80"`, a [`SocketAddr`] or an
/// `(address, port)` pair.
pub trait IntoEndpoint {
    /// Convert, panicking on a bad value.
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

// Checked conversions, done outside closures so a panic points at the caller.

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
    /// Modify the layer on top of the stack.
    #[must_use]
    pub fn with(mut self, f: impl FnOnce(&mut T)) -> Self {
        f(&mut self.working);
        self
    }

    /// Push an `Eth` layer with these MACs.
    ///
    /// # Panics
    ///
    /// On an invalid MAC.
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

    /// Push a `Vlan` layer with this VLAN id.
    ///
    /// # Panics
    ///
    /// On an invalid VLAN id.
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

    /// Push an `Ipv4` layer with these addresses and [`DEFAULT_TTL`].
    ///
    /// # Panics
    ///
    /// On a bad address or a non-unicast source.
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

    /// Push an `Ipv6` layer with these addresses and [`DEFAULT_TTL`].
    ///
    /// # Panics
    ///
    /// On a bad address or a non-unicast source.
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

    /// Push a `Tcp` layer with these ports.
    ///
    /// # Panics
    ///
    /// On a bad port or port 0.
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

    /// Push a `Udp` layer with these ports.
    ///
    /// # Panics
    ///
    /// On a bad port or port 0.
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

    /// Push a `Vxlan` layer with this VNI.
    ///
    /// # Panics
    ///
    /// On an invalid VNI.
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

/// `Eth` and the IP layer matching the addresses, then `$top`.
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

/// A TCP segment over IPv4 or IPv6, following the addresses.
///
/// # Panics
///
/// On a bad endpoint or mixed address families.
#[track_caller]
pub fn tcp(src: impl IntoEndpoint, dst: impl IntoEndpoint) -> HeaderStack<Tcp> {
    let (src, dst) = (src.into_endpoint(), dst.into_endpoint());
    over_ip!(src.ip(), dst.ip(), |stack| stack
        .tcp_ports(src.port(), dst.port()))
}

/// A UDP datagram over IPv4 or IPv6, following the addresses.
///
/// # Panics
///
/// On a bad endpoint or mixed address families.
#[track_caller]
pub fn udp(src: impl IntoEndpoint, dst: impl IntoEndpoint) -> HeaderStack<Udp> {
    let (src, dst) = (src.into_endpoint(), dst.into_endpoint());
    over_ip!(src.ip(), dst.ip(), |stack| stack
        .udp_ports(src.port(), dst.port()))
}

/// An `ICMPv4` echo request with id and sequence 0.
///
/// # Panics
///
/// On a bad address.
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

/// An `ICMPv6` echo request with id and sequence 0.
///
/// # Panics
///
/// On a bad address.
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

/// Outer VXLAN headers between two VTEPs. Pass the inner frame to
/// `build_packet_with_payload`.
///
/// # Panics
///
/// On a bad address, mixed address families or an invalid VNI.
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
