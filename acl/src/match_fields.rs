// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Individual match field types for ACL rules.
//!
//! Each field is [`FieldMatch<T>`]  --  `Ignore` means the field is not
//! part of this table's schema, `Select(value)` means the field is
//! present and constrained.
//!
//! Match fields use **raw/permissive types**  --  not the validated
//! newtypes from `dataplane-net`.  This follows the `rte_flow` principle:
//! matching on protocol-invalid values (port 0, multicast source MAC)
//! is a legitimate use case for hardware-offloaded rejection of
//! malformed frames.

use net::eth::ethtype::EthType;
use net::eth::mac::Mac;
use net::ip::NextHeader;
use net::vlan::{Pcp, Vid};

use std::ops::RangeInclusive;

use crate::match_expr::FieldMatch;
use lpm::prefix::{Ipv4Prefix, Ipv6Prefix};

/// Ethernet-layer match fields.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EthMatch {
    /// Source MAC address.  `Ignore` = field not in table.
    pub src_mac: FieldMatch<Mac>,
    /// Destination MAC address.  `Ignore` = field not in table.
    pub dst_mac: FieldMatch<Mac>,
    /// `EtherType` constraint.  `Ignore` = field not in table.
    pub ether_type: FieldMatch<EthType>,
}

/// VLAN-layer match fields.
///
/// Matches on 802.1Q VLAN tags.  Multiple VLAN matches can be stacked
/// (`QinQ`) by chaining `.vlan()` calls in the builder.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VlanMatch {
    /// VLAN ID (12 bits).  `Ignore` = field not in table.
    pub vid: FieldMatch<Vid>,
    /// Priority Code Point (3 bits).  `Ignore` = field not in table.
    pub pcp: FieldMatch<Pcp>,
    /// Inner `EtherType` / TPID.  `Ignore` = field not in table.
    ///
    /// Auto-set by [`conform`](crate::Within::conform) when an IP
    /// layer or another VLAN is stacked on top.
    pub inner_ether_type: FieldMatch<EthType>,
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
///
/// Ports use raw `u16` (not `TcpPort`) because matching on port 0 is
/// a legitimate use case for rejecting malformed traffic.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TcpMatch {
    /// Source port range.  `Ignore` = field not in table.
    pub src: FieldMatch<RangeInclusive<u16>>,
    /// Destination port range.  `Ignore` = field not in table.
    pub dst: FieldMatch<RangeInclusive<u16>>,
}

/// UDP-layer match fields.
///
/// Ports use raw `u16` (not `UdpPort`) for the same reason as TCP.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UdpMatch {
    /// Source port range.  `Ignore` = field not in table.
    pub src: FieldMatch<RangeInclusive<u16>>,
    /// Destination port range.  `Ignore` = field not in table.
    pub dst: FieldMatch<RangeInclusive<u16>>,
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
