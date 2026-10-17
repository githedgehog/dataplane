// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The class table as match rules, in the shape NIC flow rules take.
//!
//! A NIC cannot run [`ClassTable::classify`](crate::ClassTable::classify): it matches header fields
//! against constants. So the table is also compiled to rules of that kind. Two rules that match
//! the same frame agree on its class, so they need no priorities. What no rule matches is the data
//! plane's.

use std::net::{IpAddr, Ipv6Addr};

use lpm::prefix::{IpPrefix, Ipv4Prefix, Ipv6Prefix};
use net::eth::ethtype::EthType;
use net::eth::mac::Mac;
use net::lldp::NEAREST_BRIDGE;

use crate::key::{Frame, ICMP6, Ip, Key, L4, Ports};
use crate::table::{BFD_MULTIHOP, BFD_SINGLE_HOP, BGP, Class, ControlPlane};

/// One match rule: frames it matches go to the control queue, as its class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// The frames it matches.
    pub pattern: Pattern,
    /// Their class.
    pub class: Class,
}

/// The frames a rule matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pattern {
    /// Non-IP frames of an ethertype, optionally to one destination MAC address.
    Eth {
        /// The destination MAC address, if constrained.
        dst: Option<Mac>,
        /// The ethertype.
        ether_type: EthType,
    },
    /// IPv4 packets.
    Ipv4(IpPattern<Ipv4Prefix>),
    /// IPv6 packets.
    Ipv6(IpPattern<Ipv6Prefix>),
}

/// The IP packets a rule matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpPattern<P: IpPrefix> {
    /// The source address, if constrained.
    pub src: Option<P::Addr>,
    /// The destinations.
    pub dst: P,
    /// The protocol and ports.
    pub l4: L4Pattern,
}

/// The protocols and ports a rule matches.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum L4Pattern {
    /// One protocol, by the number in the IP header.
    Proto(u8),
    /// TCP with a header to match ports in, and these ports where given.
    Tcp {
        /// The source port, if constrained.
        src: Option<u16>,
        /// The destination port, if constrained.
        dst: Option<u16>,
    },
    /// UDP with a header to match ports in, and these ports where given.
    Udp {
        /// The source port, if constrained.
        src: Option<u16>,
        /// The destination port, if constrained.
        dst: Option<u16>,
    },
}

impl Rule {
    /// Whether this rule matches the frame `key` describes.
    #[must_use]
    pub fn matches(&self, key: &Key) -> bool {
        match (&self.pattern, key.frame) {
            (Pattern::Eth { dst, ether_type }, frame) => {
                dst.is_none_or(|dst| dst == key.dst_mac) && *ether_type == ether_type_of(frame)
            }
            (Pattern::Ipv4(pattern), Frame::Ipv4(ip)) => pattern.matches(&ip),
            (Pattern::Ipv6(pattern), Frame::Ipv6(ip)) => pattern.matches(&ip),
            (Pattern::Ipv4(_) | Pattern::Ipv6(_), _) => false,
        }
    }
}

impl<P: IpPrefix> IpPattern<P> {
    fn matches(&self, ip: &Ip<P::Addr>) -> bool {
        self.src.as_ref().is_none_or(|src| *src == ip.src)
            && self.dst.covers_addr(&ip.dst)
            && self.l4.matches(ip.l4)
    }
}

impl L4Pattern {
    fn matches(self, l4: L4) -> bool {
        let ports = |want_src: Option<u16>, want_dst: Option<u16>, Ports { src, dst }: Ports| {
            want_src.is_none_or(|p| p == src) && want_dst.is_none_or(|p| p == dst)
        };
        match (self, l4) {
            (L4Pattern::Proto(proto), l4) => proto == l4.proto(),
            (L4Pattern::Tcp { src, dst }, L4::Tcp(got))
            | (L4Pattern::Udp { src, dst }, L4::Udp(got)) => ports(src, dst, got),
            (L4Pattern::Tcp { .. } | L4Pattern::Udp { .. }, _) => false,
        }
    }
}

/// The ethertype of the Ethernet header in front of `frame`.
fn ether_type_of(frame: Frame) -> EthType {
    match frame {
        Frame::Ipv4(_) => EthType::IPV4,
        Frame::Ipv6(_) => EthType::IPV6,
        Frame::Other(ether_type) => ether_type,
    }
}

/// The rules that steer exactly what [`ClassTable::classify`](crate::ClassTable::classify) assigns
/// a class, for `control`.
pub(crate) fn compile(control: &ControlPlane) -> Vec<Rule> {
    let mut rules = vec![
        protocol(
            Pattern::Eth {
                dst: None,
                ether_type: EthType::ARP,
            },
            Class::Arp,
        ),
        protocol(
            Pattern::Eth {
                dst: Some(NEAREST_BRIDGE),
                ether_type: EthType::LLDP,
            },
            Class::Lldp,
        ),
    ];

    // ICMPv6 to us, neighbour discovery included.
    let icmp6 = |dst| {
        protocol(
            Pattern::Ipv6(IpPattern {
                src: None,
                dst,
                l4: L4Pattern::Proto(ICMP6),
            }),
            Class::Icmpv6,
        )
    };
    rules.push(icmp6(v6_prefix(
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
        10,
    )));
    rules.push(icmp6(v6_prefix(
        Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0),
        8,
    )));
    for local in control.local() {
        if let IpAddr::V6(local) = local {
            rules.push(icmp6(Ipv6Prefix::from(*local)));
        }
    }

    // BGP and BFD, from each neighbour to each local address of its family.
    let sessions = [
        (
            L4Pattern::Tcp {
                src: Some(BGP),
                dst: None,
            },
            Class::Bgp,
        ),
        (
            L4Pattern::Tcp {
                src: None,
                dst: Some(BGP),
            },
            Class::Bgp,
        ),
        (
            L4Pattern::Udp {
                src: None,
                dst: Some(BFD_SINGLE_HOP),
            },
            Class::Bfd,
        ),
        (
            L4Pattern::Udp {
                src: None,
                dst: Some(BFD_MULTIHOP),
            },
            Class::Bfd,
        ),
    ];
    for neighbour in control.neighbours() {
        for local in control.local() {
            for (l4, class) in sessions {
                if let Some(pattern) = ip_pattern(Some(*neighbour), *local, l4) {
                    rules.push(protocol(pattern, class));
                }
            }
        }
    }

    rules
}

/// A rule steering what `pattern` matches as `class`.
fn protocol(pattern: Pattern, class: Class) -> Rule {
    Rule { pattern, class }
}

/// IP packets from `src` to the host `dst` carrying `l4`, if the two are of one family.
fn ip_pattern(src: Option<IpAddr>, dst: IpAddr, l4: L4Pattern) -> Option<Pattern> {
    Some(match dst {
        IpAddr::V4(dst) => {
            let src = match src {
                None => None,
                Some(IpAddr::V4(src)) => Some(src),
                Some(IpAddr::V6(_)) => return None,
            };
            Pattern::Ipv4(IpPattern {
                src,
                dst: Ipv4Prefix::from(dst),
                l4,
            })
        }
        IpAddr::V6(dst) => {
            let src = match src {
                None => None,
                Some(IpAddr::V6(src)) => Some(src),
                Some(IpAddr::V4(_)) => return None,
            };
            Pattern::Ipv6(IpPattern {
                src,
                dst: Ipv6Prefix::from(dst),
                l4,
            })
        }
    })
}

/// The IPv6 prefix `network/len`, for constants known to be valid.
fn v6_prefix(network: Ipv6Addr, len: u8) -> Ipv6Prefix {
    Ipv6Prefix::new(network, len)
        .unwrap_or_else(|_| unreachable!("{network}/{len} is a valid prefix"))
}
