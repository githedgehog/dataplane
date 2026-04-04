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

/// Build a DPDK `FieldDef` array from a [`FieldSignature`].
///
/// Fields are laid out in a **compact packed buffer** — each field
/// immediately follows the previous one (with padding to 4-byte
/// boundaries for the setup field).  The returned `FieldDef` array
/// has offsets into this compact buffer, not into the raw Ethernet
/// frame.
///
/// The caller must assemble an input buffer matching this compact
/// layout (see `input::assemble_compact_input`).
///
/// Layout: field 0 (1B) + padding to offset 4, then remaining
/// fields packed sequentially.  This follows the DPDK 5-tuple
/// example pattern.
#[must_use]
pub fn build_field_defs(signature: FieldSignature) -> Vec<FieldDef> {
    // Compact layout:
    //   byte 0: field 0 (1 byte, Bitmask, setup)
    //   byte 1: padding
    //   byte 2+: remaining fields packed contiguously
    //
    // input_index: 0 for setup field, then sequential starting at 1.
    // Following the 5-tuple example pattern from DPDK docs.

    let mut defs = Vec::new();
    let mut field_index: u8 = 0;
    let mut next_offset: u32 = 2;
    let mut next_input_index: u8 = 1;

    // Field 0: setup byte (always present, Bitmask type).
    defs.push(FieldDef {
        field_type: FieldType::Bitmask,
        size: FieldSize::One,
        field_index: 0,
        input_index: 0,
        offset: 0,
    });
    field_index = 1;

    // Pack fields in 5-tuple order: 4-byte fields first (they align
    // naturally with 4-byte fetch groups), then 2-byte fields, then
    // 1-byte fields.  This follows the DPDK 5-tuple example where
    // 4B IPs come before 2B ports.
    let mut remaining: Vec<FieldMeta> = Vec::new();

    // 4-byte fields first
    if signature.has_ipv4_src() {
        remaining.push(fields::IPV4_SRC);
    }
    if signature.has_ipv4_dst() {
        remaining.push(fields::IPV4_DST);
    }
    if signature.has_ipv6_src() {
        remaining.push(fields::IPV6_SRC_HI);
        remaining.push(fields::IPV6_SRC_LO);
    }
    if signature.has_ipv6_dst() {
        remaining.push(fields::IPV6_DST_HI);
        remaining.push(fields::IPV6_DST_LO);
    }
    // 2-byte fields after all 4B/8B fields
    if signature.has_eth_type() {
        remaining.push(fields::ETH_TYPE);
    }
    if signature.has_tcp_src() || signature.has_udp_src() {
        remaining.push(fields::TCP_SRC);
    }
    if signature.has_tcp_dst() || signature.has_udp_dst() {
        remaining.push(fields::TCP_DST);
    }
    if signature.has_icmp4_type() {
        remaining.push(fields::ICMP4_TYPE);
    }
    if signature.has_icmp4_code() {
        remaining.push(fields::ICMP4_CODE);
    }

    for meta in remaining {
        let size_bytes = meta.size as u32;

        // input_index = 1 + (offset - 2) / 4
        // This maps each field to the 4-byte fetch group it belongs to,
        // matching the DPDK 5-tuple example pattern.
        #[allow(clippy::cast_possible_truncation)]
        let input_index = (1 + (next_offset - 2) / 4) as u8;

        defs.push(FieldDef {
            field_type: meta.field_type,
            size: meta.size,
            field_index,
            input_index,
            offset: next_offset,
        });
        field_index += 1;
        next_offset += size_bytes;
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
    fn ipv4_tcp_compact_field_defs() {
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
        let defs = build_field_defs(sig);

        // New order: proto (1B), ipv4_src (4B), eth_type (2B), tcp_dst (2B)
        assert_eq!(defs.len(), 4);

        // Field 0: setup byte at offset 0
        assert_eq!(defs[0].size, FieldSize::One);
        assert_eq!(defs[0].field_type, FieldType::Bitmask);
        assert_eq!(defs[0].field_index, 0);
        assert_eq!(defs[0].input_index, 0);
        assert_eq!(defs[0].offset, 0);

        // Field 1: ipv4_src (4B) at offset 2
        assert_eq!(defs[1].size, FieldSize::Four);
        assert_eq!(defs[1].field_type, FieldType::Mask);
        assert_eq!(defs[1].offset, 2);

        // Field 2: eth_type (2B) at offset 6
        assert_eq!(defs[2].size, FieldSize::Two);
        assert_eq!(defs[2].field_type, FieldType::Mask);
        assert_eq!(defs[2].offset, 6);

        // Field 3: tcp_dst (2B Range) at offset 8
        assert_eq!(defs[3].size, FieldSize::Two);
        assert_eq!(defs[3].field_type, FieldType::Range);
        assert_eq!(defs[3].offset, 8);
    }

    #[test]
    fn field_0_is_always_one_byte() {
        let rule = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .tcp(|_| {})
            .permit(pri(1));

        let sig = FieldSignature::from_match_fields(rule.packet_match());
        let defs = build_field_defs(sig);

        assert!(!defs.is_empty());
        assert_eq!(defs[0].size, FieldSize::One);
        assert_eq!(defs[0].offset, 0);
    }
}
