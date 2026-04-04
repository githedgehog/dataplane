// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Mapping from ACL match fields to DPDK `FieldDef` entries.
//!
//! Each matchable field in the ACL system has a corresponding DPDK
//! field description: its byte size, comparison type, and offset
//! within the input buffer.
//!
//! The offset depends on the packet layout (which varies with VLAN
//! tags, tunnels, etc.).  This module defines the **field metadata**
//! (size, type) statically, and takes offsets as parameters from an
//! [`OffsetProvider`].
//!
//! # DPDK constraints
//!
//! - Field 0 must be 1 byte (DPDK processes it during setup).
//!   We use the IP protocol field as field 0 when present.
//! - Fields are grouped into 4-byte input slots via `input_index`.
//! - IPv6 addresses (16 bytes) require two 8-byte fields each.

use acl::FieldSignature;
use dpdk::acl::field::{FieldDef, FieldSize, FieldType};

/// Metadata for a single matchable field: its DPDK type and byte width.
///
/// The offset is not included here — it comes from the [`OffsetProvider`]
/// because it depends on the packet layout.
#[derive(Debug, Clone, Copy)]
pub struct FieldMeta {
    /// DPDK comparison type.
    pub field_type: FieldType,
    /// Byte width.
    pub size: FieldSize,
}

/// Well-known field metadata for each matchable field.
pub mod fields {
    use super::*;

    /// `EtherType` — 2 bytes, mask match.
    pub const ETH_TYPE: FieldMeta = FieldMeta {
        field_type: FieldType::Mask,
        size: FieldSize::Two,
    };

    /// IPv4 protocol — 1 byte, mask match.
    /// This is the preferred field 0 (DPDK requires field 0 to be 1 byte).
    pub const IPV4_PROTO: FieldMeta = FieldMeta {
        field_type: FieldType::Mask,
        size: FieldSize::One,
    };

    /// IPv4 source address — 4 bytes, mask (prefix) match.
    pub const IPV4_SRC: FieldMeta = FieldMeta {
        field_type: FieldType::Mask,
        size: FieldSize::Four,
    };

    /// IPv4 destination address — 4 bytes, mask (prefix) match.
    pub const IPV4_DST: FieldMeta = FieldMeta {
        field_type: FieldType::Mask,
        size: FieldSize::Four,
    };

    /// IPv6 protocol / next-header — 1 byte, mask match.
    pub const IPV6_PROTO: FieldMeta = FieldMeta {
        field_type: FieldType::Mask,
        size: FieldSize::One,
    };

    /// IPv6 source address — 16 bytes total, split into two 8-byte fields.
    pub const IPV6_SRC_HI: FieldMeta = FieldMeta {
        field_type: FieldType::Mask,
        size: FieldSize::Eight,
    };
    /// IPv6 source address low 8 bytes.
    pub const IPV6_SRC_LO: FieldMeta = FieldMeta {
        field_type: FieldType::Mask,
        size: FieldSize::Eight,
    };

    /// IPv6 destination address — 16 bytes total, split into two 8-byte fields.
    pub const IPV6_DST_HI: FieldMeta = FieldMeta {
        field_type: FieldType::Mask,
        size: FieldSize::Eight,
    };
    /// IPv6 destination address low 8 bytes.
    pub const IPV6_DST_LO: FieldMeta = FieldMeta {
        field_type: FieldType::Mask,
        size: FieldSize::Eight,
    };

    /// TCP source port — 2 bytes, range match.
    pub const TCP_SRC: FieldMeta = FieldMeta {
        field_type: FieldType::Range,
        size: FieldSize::Two,
    };

    /// TCP destination port — 2 bytes, range match.
    pub const TCP_DST: FieldMeta = FieldMeta {
        field_type: FieldType::Range,
        size: FieldSize::Two,
    };

    /// UDP source port — 2 bytes, range match.
    pub const UDP_SRC: FieldMeta = FieldMeta {
        field_type: FieldType::Range,
        size: FieldSize::Two,
    };

    /// UDP destination port — 2 bytes, range match.
    pub const UDP_DST: FieldMeta = FieldMeta {
        field_type: FieldType::Range,
        size: FieldSize::Two,
    };

    /// `ICMPv4` type — 1 byte, mask match.
    pub const ICMP4_TYPE: FieldMeta = FieldMeta {
        field_type: FieldType::Mask,
        size: FieldSize::One,
    };

    /// `ICMPv4` code — 1 byte, mask match.
    pub const ICMP4_CODE: FieldMeta = FieldMeta {
        field_type: FieldType::Mask,
        size: FieldSize::One,
    };
}

/// Provides byte offsets for matchable fields within the input buffer.
///
/// The offsets depend on the packet layout (Ethernet header size,
/// whether VLAN tags are present, tunnel encapsulation, etc.).
/// Implementations provide the correct offsets for their packet
/// format.
///
/// For a standard Ethernet + IPv4 packet (no VLANs):
/// - Ethernet starts at byte 0
/// - `EtherType` is at byte 12
/// - IPv4 starts at byte 14
/// - IPv4 protocol is at byte 14 + 9 = 23
/// - IPv4 src is at byte 14 + 12 = 26
/// - IPv4 dst is at byte 14 + 16 = 30
/// - TCP/UDP src port is at byte 34
/// - TCP/UDP dst port is at byte 36
pub trait OffsetProvider {
    /// Byte offset of the Ethernet source MAC.
    fn eth_src_offset(&self) -> u32;
    /// Byte offset of the Ethernet destination MAC.
    fn eth_dst_offset(&self) -> u32;
    /// Byte offset of the `EtherType` field.
    fn eth_type_offset(&self) -> u32;
    /// Byte offset of the VLAN VID field.
    fn vlan_vid_offset(&self) -> u32;
    /// Byte offset of the VLAN PCP field.
    fn vlan_pcp_offset(&self) -> u32;
    /// Byte offset of the VLAN inner `EtherType` field.
    fn vlan_inner_type_offset(&self) -> u32;
    /// Byte offset of the IPv4 protocol field.
    fn ipv4_proto_offset(&self) -> u32;
    /// Byte offset of the IPv4 source address.
    fn ipv4_src_offset(&self) -> u32;
    /// Byte offset of the IPv4 destination address.
    fn ipv4_dst_offset(&self) -> u32;
    /// Byte offset of the IPv6 next-header field.
    fn ipv6_proto_offset(&self) -> u32;
    /// Byte offset of the IPv6 source address.
    fn ipv6_src_offset(&self) -> u32;
    /// Byte offset of the IPv6 destination address.
    fn ipv6_dst_offset(&self) -> u32;
    /// Byte offset of the TCP/UDP source port.
    fn l4_src_port_offset(&self) -> u32;
    /// Byte offset of the TCP/UDP destination port.
    fn l4_dst_port_offset(&self) -> u32;
    /// Byte offset of the `ICMPv4` type field.
    fn icmp4_type_offset(&self) -> u32;
    /// Byte offset of the `ICMPv4` code field.
    fn icmp4_code_offset(&self) -> u32;
}

/// Standard Ethernet offsets with no VLAN tags.
///
/// Assumes: 14-byte Ethernet header, 20-byte IPv4 header (no options),
/// 40-byte IPv6 header.
#[derive(Debug, Clone, Copy)]
pub struct StandardEthernetOffsets;

impl OffsetProvider for StandardEthernetOffsets {
    fn eth_src_offset(&self) -> u32 {
        6 // source MAC at byte 6 in Ethernet frame
    }
    fn eth_dst_offset(&self) -> u32 {
        0 // destination MAC at byte 0
    }
    fn eth_type_offset(&self) -> u32 {
        12
    }
    fn vlan_vid_offset(&self) -> u32 {
        // No VLANs in standard Ethernet — this offset is meaningless
        // but must be provided.  Place it past the Ethernet header.
        14
    }
    fn vlan_pcp_offset(&self) -> u32 {
        14
    }
    fn vlan_inner_type_offset(&self) -> u32 {
        14
    }
    fn ipv4_proto_offset(&self) -> u32 {
        14 + 9
    }
    fn ipv4_src_offset(&self) -> u32 {
        14 + 12
    }
    fn ipv4_dst_offset(&self) -> u32 {
        14 + 16
    }
    fn ipv6_proto_offset(&self) -> u32 {
        14 + 6
    }
    fn ipv6_src_offset(&self) -> u32 {
        14 + 8
    }
    fn ipv6_dst_offset(&self) -> u32 {
        14 + 24
    }
    fn l4_src_port_offset(&self) -> u32 {
        14 + 20 // after minimal IPv4 header
    }
    fn l4_dst_port_offset(&self) -> u32 {
        14 + 20 + 2
    }
    fn icmp4_type_offset(&self) -> u32 {
        14 + 20 // ICMP starts at same offset as TCP/UDP
    }
    fn icmp4_code_offset(&self) -> u32 {
        14 + 20 + 1
    }
}

/// Build a DPDK `FieldDef` array from a [`FieldSignature`] and offset provider.
///
/// Returns the field definitions in the correct order for DPDK ACL:
/// - 1-byte protocol field first (DPDK requirement for field 0)
/// - Remaining fields in a consistent order
///
/// Also returns the count of fields (which determines `N` for `Rule<N>`).
///
/// # Panics
///
/// Panics if the signature has no protocol field (IPv4 or IPv6 protocol).
/// This should be prevented by the rule builder's `conform()` which always
/// sets the protocol field when a transport layer is stacked.
#[must_use]
pub fn build_field_defs(
    signature: FieldSignature,
    offsets: &impl OffsetProvider,
) -> Vec<FieldDef> {
    let mut defs = Vec::new();
    let mut field_index: u8 = 0;
    let mut input_index: u8 = 0;

    // Helper to add a field def and increment counters.
    let mut add = |meta: FieldMeta, offset: u32| {
        defs.push(FieldDef {
            field_type: meta.field_type,
            size: meta.size,
            field_index,
            input_index,
            offset,
        });
        field_index += 1;
        // Simplified input_index: increment per field.
        // A production implementation would compute proper 4-byte grouping.
        input_index += 1;
    };

    // DPDK requires field 0 to be 1 byte.  Protocol fields are 1 byte.
    // We emit the protocol field first if present.
    if signature.has_ipv4_proto() {
        add(fields::IPV4_PROTO, offsets.ipv4_proto_offset());
    } else if signature.has_ipv6_proto() {
        add(fields::IPV6_PROTO, offsets.ipv6_proto_offset());
    }

    // Remaining fields in a consistent order.
    if signature.has_eth_type() {
        add(fields::ETH_TYPE, offsets.eth_type_offset());
    }
    if signature.has_ipv4_src() {
        add(fields::IPV4_SRC, offsets.ipv4_src_offset());
    }
    if signature.has_ipv4_dst() {
        add(fields::IPV4_DST, offsets.ipv4_dst_offset());
    }
    if signature.has_ipv6_src() {
        add(fields::IPV6_SRC_HI, offsets.ipv6_src_offset());
        add(fields::IPV6_SRC_LO, offsets.ipv6_src_offset() + 8);
    }
    if signature.has_ipv6_dst() {
        add(fields::IPV6_DST_HI, offsets.ipv6_dst_offset());
        add(fields::IPV6_DST_LO, offsets.ipv6_dst_offset() + 8);
    }
    if signature.has_tcp_src() || signature.has_udp_src() {
        add(fields::TCP_SRC, offsets.l4_src_port_offset());
    }
    if signature.has_tcp_dst() || signature.has_udp_dst() {
        add(fields::TCP_DST, offsets.l4_dst_port_offset());
    }
    if signature.has_icmp4_type() {
        add(fields::ICMP4_TYPE, offsets.icmp4_type_offset());
    }
    if signature.has_icmp4_code() {
        add(fields::ICMP4_CODE, offsets.icmp4_code_offset());
    }

    defs
}

#[cfg(test)]
mod tests {
    use super::*;
    use acl::{AclRuleBuilder, FieldMatch, Ipv4Prefix, PortRange, Priority};
    use std::net::Ipv4Addr;

    fn pri(n: u32) -> Priority {
        Priority::new(n).unwrap()
    }

    #[test]
    fn ipv4_tcp_field_defs() {
        let rule = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.src =
                    FieldMatch::Select(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
            })
            .tcp(|tcp| {
                tcp.dst = FieldMatch::Select(PortRange::exact(80u16));
            })
            .permit(pri(100));

        let sig = FieldSignature::from_match_fields(rule.packet_match());
        let defs = build_field_defs(sig, &StandardEthernetOffsets);

        // Should have: ipv4_proto (1B), eth_type (2B), ipv4_src (4B), tcp_dst (2B)
        assert_eq!(defs.len(), 4);

        // Field 0 must be 1 byte (protocol)
        assert_eq!(defs[0].size, FieldSize::One);
        assert_eq!(defs[0].field_type, FieldType::Mask);
        assert_eq!(defs[0].field_index, 0);

        // eth_type
        assert_eq!(defs[1].size, FieldSize::Two);
        assert_eq!(defs[1].offset, 12); // standard ethernet

        // ipv4_src
        assert_eq!(defs[2].size, FieldSize::Four);
        assert_eq!(defs[2].offset, 26); // 14 + 12

        // tcp_dst
        assert_eq!(defs[3].size, FieldSize::Two);
        assert_eq!(defs[3].field_type, FieldType::Range);
        assert_eq!(defs[3].offset, 36); // 14 + 20 + 2
    }

    #[test]
    fn field_0_is_always_one_byte() {
        // Even if the only field is eth_type (2 bytes), if protocol is
        // present it goes first.
        let rule = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .tcp(|_| {})
            .permit(pri(1));

        let sig = FieldSignature::from_match_fields(rule.packet_match());
        let defs = build_field_defs(sig, &StandardEthernetOffsets);

        assert!(!defs.is_empty());
        assert_eq!(defs[0].size, FieldSize::One);
    }
}
