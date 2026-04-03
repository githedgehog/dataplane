// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Individual match field types for ACL rules.
//!
//! Each field is `Option` — `None` means wildcard (don't care).

use net::eth::ethtype::EthType;
use net::ip::NextHeader;
use net::tcp::port::TcpPort;
use net::udp::port::UdpPort;

use crate::range::{Ipv4Prefix, Ipv6Prefix, PortRange};

/// Ethernet-layer match fields.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EthMatch {
    /// `EtherType` to match.  `None` = any.
    pub ether_type: Option<EthType>,
}

/// IPv4-layer match fields.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ipv4Match {
    /// Source prefix.  `None` = any source.
    pub src: Option<Ipv4Prefix>,
    /// Destination prefix.  `None` = any destination.
    pub dst: Option<Ipv4Prefix>,
    /// IP protocol.  Auto-set by [`conform`](super::Within::conform)
    /// when a transport match is stacked, but can also be set explicitly
    /// to match on protocol without caring about transport fields.
    pub protocol: Option<NextHeader>,
}

/// IPv6-layer match fields.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ipv6Match {
    /// Source prefix.  `None` = any source.
    pub src: Option<Ipv6Prefix>,
    /// Destination prefix.  `None` = any destination.
    pub dst: Option<Ipv6Prefix>,
    /// IP next-header / protocol.  Auto-set by [`conform`](super::Within::conform)
    /// when a transport match is stacked.
    pub protocol: Option<NextHeader>,
}

/// TCP-layer match fields.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TcpMatch {
    /// Source port range.  `None` = any source port.
    pub src: Option<PortRange<TcpPort>>,
    /// Destination port range.  `None` = any destination port.
    pub dst: Option<PortRange<TcpPort>>,
}

/// UDP-layer match fields.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UdpMatch {
    /// Source port range.  `None` = any source port.
    pub src: Option<PortRange<UdpPort>>,
    /// Destination port range.  `None` = any destination port.
    pub dst: Option<PortRange<UdpPort>>,
}

/// ICMPv4-layer match fields.
///
/// Uses raw `u8` values rather than the rich `Icmpv4Type` enum because
/// ACL classification operates on numeric type/code values.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Icmp4Match {
    /// ICMP type.  `None` = any type.
    pub icmp_type: Option<u8>,
    /// ICMP code.  `None` = any code.
    pub icmp_code: Option<u8>,
}
