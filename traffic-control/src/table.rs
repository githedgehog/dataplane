// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The control-plane classes and how a frame is sorted into one.

use std::collections::BTreeSet;
use std::fmt::{self, Display};
use std::net::{IpAddr, Ipv6Addr};

use net::eth::ethtype::EthType;
use net::lldp::NEAREST_BRIDGE;

use crate::key::{Frame, ICMP6, Ip, Key, L4, Ports};
use crate::rules::{self, Rule};

/// BGP's TCP port (RFC 4271).
pub(crate) const BGP: u16 = 179;
/// The UDP destination port of single hop BFD control packets (RFC 5881).
pub(crate) const BFD_SINGLE_HOP: u16 = 3784;
/// The UDP destination port of multihop BFD control packets (RFC 5883).
pub(crate) const BFD_MULTIHOP: u16 = 4784;

/// A kind of control-plane traffic, policed and counted on its own.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Class {
    /// BFD control packets from a neighbour to a local address.
    Bfd,
    /// BGP from a neighbour to a local address.
    Bgp,
    /// `ICMPv6` to a local, link-local or multicast address: neighbour discovery among the rest.
    Icmpv6,
    /// ARP.
    Arp,
    /// LLDP to the nearest bridge group address.
    Lldp,
}

impl Class {
    /// Every class.
    pub const ALL: [Class; 5] = [
        Class::Bfd,
        Class::Bgp,
        Class::Icmpv6,
        Class::Arp,
        Class::Lldp,
    ];

    /// The class's name, for counters and the CLI.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Class::Bfd => "bfd",
            Class::Bgp => "bgp",
            Class::Icmpv6 => "icmpv6",
            Class::Arp => "arp",
            Class::Lldp => "lldp",
        }
    }
}

impl Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// What the class table needs to know about the gateway: the addresses it answers on and the
/// peers it runs BGP and BFD with.
///
/// These come from configuration, not the FIB.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ControlPlane {
    local: BTreeSet<IpAddr>,
    neighbours: BTreeSet<IpAddr>,
}

impl ControlPlane {
    /// The gateway's `local` addresses (interface addresses, the VTEP's, BGP update sources) and
    /// its BGP and BFD `neighbours`.
    #[must_use]
    pub fn new(
        local: impl IntoIterator<Item = IpAddr>,
        neighbours: impl IntoIterator<Item = IpAddr>,
    ) -> ControlPlane {
        ControlPlane {
            local: local.into_iter().collect(),
            neighbours: neighbours.into_iter().collect(),
        }
    }

    /// The addresses the gateway answers on.
    #[must_use]
    pub fn local(&self) -> &BTreeSet<IpAddr> {
        &self.local
    }

    /// The BGP and BFD peers.
    #[must_use]
    pub fn neighbours(&self) -> &BTreeSet<IpAddr> {
        &self.neighbours
    }
}

/// The classes of one gateway's control traffic, as a classifier and as NIC rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassTable {
    control: ControlPlane,
    rules: Vec<Rule>,
}

impl ClassTable {
    /// The class table for `control`.
    #[must_use]
    pub fn new(control: ControlPlane) -> ClassTable {
        let rules = rules::compile(&control);
        ClassTable { control, rules }
    }

    /// What the table was built from.
    #[must_use]
    pub fn control(&self) -> &ControlPlane {
        &self.control
    }

    /// The table as match rules, which steer exactly the frames [`classify`](Self::classify)
    /// assigns a class.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// The class of the frame `key` describes, or `None` if it is the data plane's.
    #[must_use]
    pub fn classify(&self, key: &Key) -> Option<Class> {
        match key.frame {
            Frame::Other(EthType::ARP) => Some(Class::Arp),
            Frame::Other(EthType::LLDP) if key.dst_mac == NEAREST_BRIDGE => Some(Class::Lldp),
            Frame::Other(_) => None,
            Frame::Ipv4(ip) => self.classify_ip(ip.src.into(), ip.dst.into(), ip.l4),
            Frame::Ipv6(Ip { dst, l4, .. }) if l4.proto() == ICMP6 && icmp6_to_us(self, dst) => {
                Some(Class::Icmpv6)
            }
            Frame::Ipv6(ip) => self.classify_ip(ip.src.into(), ip.dst.into(), ip.l4),
        }
    }

    /// The class of an IP packet from `src` to `dst` carrying `l4`, `ICMPv6` aside: BGP or BFD
    /// from a neighbour to a local address.
    fn classify_ip(&self, src: IpAddr, dst: IpAddr, l4: L4) -> Option<Class> {
        if !self.control.local.contains(&dst) || !self.control.neighbours.contains(&src) {
            return None;
        }
        match l4 {
            L4::Tcp(Ports { src, dst }) if src == BGP || dst == BGP => Some(Class::Bgp),
            L4::Udp(Ports { dst, .. }) if dst == BFD_SINGLE_HOP || dst == BFD_MULTIHOP => {
                Some(Class::Bfd)
            }
            _ => None,
        }
    }
}

/// Whether `ICMPv6` to `dst` is for the gateway: to one of its addresses, or to a link-local or
/// multicast address, which no router forwards.
fn icmp6_to_us(table: &ClassTable, dst: Ipv6Addr) -> bool {
    dst.is_unicast_link_local() || dst.is_multicast() || table.control.local.contains(&dst.into())
}
