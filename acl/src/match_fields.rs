// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Individual match field types for ACL rules.
//!
//! Each field is [`FieldMatch<T>`] — `Ignore` means the field is not
//! part of this table's schema, `Select(value)` means the field is
//! present and constrained.

use net::eth::ethtype::EthType;
use net::ip::NextHeader;
use net::tcp::port::TcpPort;
use net::udp::port::UdpPort;

use crate::match_expr::FieldMatch;
use crate::range::{Ipv4Prefix, Ipv6Prefix, PortRange};

/// Ethernet-layer match fields.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EthMatch {
    /// `EtherType` constraint.  `Ignore` = field not in table.
    pub ether_type: FieldMatch<EthType>,
}

/// IPv4-layer match fields.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ipv4Match {
    /// Source prefix.  `Ignore` = field not in table.
    pub src: FieldMatch<Ipv4Prefix>,
    /// Destination prefix.  `Ignore` = field not in table.
    pub dst: FieldMatch<Ipv4Prefix>,
    /// IP protocol.  Auto-set to `Select` by
    /// [`conform`](crate::Within::conform) when a transport match is
    /// stacked, but can also be set explicitly.
    pub protocol: FieldMatch<NextHeader>,
}

/// IPv6-layer match fields.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ipv6Match {
    /// Source prefix.  `Ignore` = field not in table.
    pub src: FieldMatch<Ipv6Prefix>,
    /// Destination prefix.  `Ignore` = field not in table.
    pub dst: FieldMatch<Ipv6Prefix>,
    /// IP next-header / protocol.  Auto-set to `Select` by
    /// [`conform`](crate::Within::conform) when a transport match is
    /// stacked.
    pub protocol: FieldMatch<NextHeader>,
}

/// TCP-layer match fields.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TcpMatch {
    /// Source port range.  `Ignore` = field not in table.
    pub src: FieldMatch<PortRange<TcpPort>>,
    /// Destination port range.  `Ignore` = field not in table.
    pub dst: FieldMatch<PortRange<TcpPort>>,
}

/// UDP-layer match fields.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UdpMatch {
    /// Source port range.  `Ignore` = field not in table.
    pub src: FieldMatch<PortRange<UdpPort>>,
    /// Destination port range.  `Ignore` = field not in table.
    pub dst: FieldMatch<PortRange<UdpPort>>,
}

/// `ICMPv4`-layer match fields.
///
/// Uses raw `u8` values rather than the rich `Icmpv4Type` enum because
/// ACL classification operates on numeric type/code values.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Icmp4Match {
    /// ICMP type.  `Ignore` = field not in table.
    pub icmp_type: FieldMatch<u8>,
    /// ICMP code.  `Ignore` = field not in table.
    pub icmp_code: FieldMatch<u8>,
}
