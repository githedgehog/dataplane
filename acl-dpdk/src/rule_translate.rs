// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Translation from ACL match field values to DPDK `AclField` entries.
//!
//! Given a [`FieldSignature`] (which determines the column layout) and
//! an [`AclRule`], this module produces the ordered `Vec<AclField>` that
//! populates a DPDK `Rule<N>`.
//!
//! The field order must match exactly the order produced by
//! [`build_field_defs`](crate::field_map::build_field_defs) for the
//! same signature.
//!
//! # Byte order
//!
//! DPDK rule field values are in **host byte order**.  Our match field
//! types (`Ipv4Prefix`, `PortRange`, etc.) already store values in host
//! order, so no conversion is needed.

use acl::{
    AclRule, EthMatch, FieldMatch, FieldSignature, Icmp4Match, Ipv4Match, Ipv6Match, Metadata,
    TcpMatch, UdpMatch,
};
use net::ip::NextHeader;
use dpdk::acl::rule::AclField;

/// Translate an [`AclRule`]'s match values into an ordered `Vec<AclField>`.
///
/// The field order matches [`build_field_defs`](crate::field_map::build_field_defs)
/// for the given signature: protocol first (if present), then remaining
/// fields in the canonical order.
///
/// Fields that are `Select` in the signature but `Ignore` in this
/// specific rule produce a wildcard `AclField` (value=0, mask=0).
/// This happens when the compiler merges signature groups or when
/// `conform()` set a field that the rule doesn't further constrain.
#[must_use]
pub fn translate_rule<M: Metadata>(
    signature: FieldSignature,
    rule: &AclRule<M>,
) -> Vec<AclField> {
    let mut fields = Vec::new();
    let pm = rule.packet_match();

    // Field 0: setup byte (always present, 1 byte, Bitmask type).
    if signature.has_ipv4_proto() {
        fields.push(translate_proto(pm.ipv4()));
    } else if signature.has_ipv6_proto() {
        fields.push(translate_proto_v6(pm.ipv6()));
    } else {
        fields.push(translate_wildcard_setup());
    }

    // Remaining fields in the same order as build_field_defs:
    // 4B/8B fields first, then 2B, then 1B.

    // 4-byte fields
    if signature.has_ipv4_src() {
        fields.push(translate_ipv4_prefix(
            pm.ipv4().map(|m| &m.src),
        ));
    }
    if signature.has_ipv4_dst() {
        fields.push(translate_ipv4_prefix(
            pm.ipv4().map(|m| &m.dst),
        ));
    }
    // 8-byte fields
    if signature.has_ipv6_src() {
        let (hi, lo) = translate_ipv6_prefix(pm.ipv6().map(|m| &m.src));
        fields.push(hi);
        fields.push(lo);
    }
    if signature.has_ipv6_dst() {
        let (hi, lo) = translate_ipv6_prefix(pm.ipv6().map(|m| &m.dst));
        fields.push(hi);
        fields.push(lo);
    }
    // 2-byte fields
    if signature.has_eth_type() {
        fields.push(translate_eth_type(pm.eth()));
    }
    if signature.has_tcp_src() {
        fields.push(translate_port_range(
            pm.tcp().map(|m| &m.src),
        ));
    }
    if signature.has_tcp_dst() {
        fields.push(translate_port_range(
            pm.tcp().map(|m| &m.dst),
        ));
    }
    if signature.has_udp_src() {
        fields.push(translate_port_range(
            pm.udp().map(|m| &m.src),
        ));
    }
    if signature.has_udp_dst() {
        fields.push(translate_port_range(
            pm.udp().map(|m| &m.dst),
        ));
    }
    if signature.has_icmp4_type() {
        fields.push(translate_icmp_byte(
            pm.icmp4().map(|m| &m.icmp_type),
        ));
    }
    if signature.has_icmp4_code() {
        fields.push(translate_icmp_byte(
            pm.icmp4().map(|m| &m.icmp_code),
        ));
    }

    fields
}

// ---- Per-field translators ----
//
// Each function takes an Option<&MatchLayer> (None if the layer is absent
// from the rule) and produces an AclField.  If the layer or field is
// absent/Ignore, a wildcard is returned.

/// Convert a [`NextHeader`] to its raw `u8` protocol number.
fn next_header_to_u8(nh: NextHeader) -> u8 {
    let ip_number: etherparse::IpNumber = nh.into();
    u8::from(ip_number)
}

/// Translate IPv4 protocol field.
///
/// Protocol is FieldType::Bitmask (1 byte).  mask_range = bitmask.
/// 0xFF = exact match on all 8 bits.  0 = wildcard.
fn translate_proto(ipv4: Option<&Ipv4Match>) -> AclField {
    match ipv4.and_then(|m| m.protocol.as_select()) {
        Some(nh) => AclField::from_u8(next_header_to_u8(*nh), 0xFF),
        None => AclField::from_u8(0, 0), // wildcard
    }
}

/// Translate IPv6 next-header / protocol field.
fn translate_proto_v6(ipv6: Option<&Ipv6Match>) -> AclField {
    match ipv6.and_then(|m| m.protocol.as_select()) {
        Some(nh) => AclField::from_u8(next_header_to_u8(*nh), 0xFF),
        None => AclField::from_u8(0, 0),
    }
}

/// Translate a wildcard setup byte (when no protocol field is selected).
fn translate_wildcard_setup() -> AclField {
    AclField::from_u8(0, 0) // Bitmask wildcard
}

/// Translate ether_type field.
///
/// FieldType::Mask, 2 bytes.  mask_range = prefix length (16 = exact).
///
/// The value is stored as it would be read by the CPU from the
/// network-order input buffer.  On LE, `[0x08, 0x00]` → `0x0008`.
/// So we convert the host-order value to the CPU's reading of the
/// network-order bytes: `val.to_be()`.
fn translate_eth_type(eth: Option<&EthMatch>) -> AclField {
    match eth.and_then(|m| m.ether_type.as_select()) {
        Some(et) => {
            let val: u16 = (*et).into();
            AclField::from_u16(val, 16)
        }
        None => AclField::wildcard(),
    }
}

/// Translate an IPv4 prefix (src or dst) to a mask-type `AclField`.
///
/// FieldType::Mask, 4 bytes.  mask_range = prefix length (0-32).
///
/// FieldType::Mask, 4 bytes.  mask_range = prefix length (0-32).
/// Value in host byte order (DPDK handles NBO→HBO conversion).
fn translate_ipv4_prefix(
    field: Option<&FieldMatch<acl::Ipv4Prefix>>,
) -> AclField {
    match field.and_then(FieldMatch::as_select) {
        Some(pfx) => {
            AclField::from_u32(
                u32::from(pfx.addr()),
                u32::from(pfx.prefix_len()),
            )
        }
        None => AclField::wildcard(),
    }
}

/// Translate an IPv6 prefix to two 8-byte mask-type `AclField`s (hi, lo).
///
/// FieldType::Mask, 8 bytes each.  For a /48 prefix:
/// - hi field: prefix_len = min(48, 64) = 48
/// - lo field: prefix_len = max(0, 48 - 64) = 0 (wildcard)
fn translate_ipv6_prefix(
    field: Option<&FieldMatch<acl::Ipv6Prefix>>,
) -> (AclField, AclField) {
    match field.and_then(FieldMatch::as_select) {
        Some(pfx) => {
            let addr = u128::from(pfx.addr());
            let plen = pfx.prefix_len();
            let hi_val = (addr >> 64) as u64;
            let hi_plen = u64::from(plen.min(64));
            let lo_val = addr as u64;
            let lo_plen = u64::from(plen.saturating_sub(64));
            (
                AclField::from_u64(hi_val, hi_plen),
                AclField::from_u64(lo_val, lo_plen),
            )
        }
        None => (AclField::wildcard(), AclField::wildcard()),
    }
}

/// Translate a port range field (TCP or UDP).
///
/// FieldType::Range, 2 bytes.  value = low bound, mask_range = high bound.
///
/// Same byte-order reasoning: input buffer has port in network order,
/// CPU reads as native.  Range bounds must match the CPU's reading.
/// Port 80 in buffer = `[0x00, 0x50]`, on LE CPU reads `0x5000`.
/// So: `port.to_be()`.
fn translate_port_range(
    field: Option<&FieldMatch<acl::PortRange<u16>>>,
) -> AclField {
    match field.and_then(FieldMatch::as_select) {
        Some(range) => AclField::from_u16(range.min, range.max),
        None => AclField::from_u16(0, u16::MAX),
    }
}

/// Translate an ICMP type or code byte field.
fn translate_icmp_byte(field: Option<&FieldMatch<u8>>) -> AclField {
    match field.and_then(FieldMatch::as_select) {
        Some(&val) => AclField::from_u8(val, u8::MAX),
        None => AclField::wildcard(),
    }
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
    fn ipv4_tcp_rule_produces_correct_fields() {
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
        let fields = translate_rule(sig, &rule);

        // New order: proto, ipv4_src, eth_type, tcp_dst = 4 fields
        assert_eq!(fields.len(), 4);

        // Field 0: protocol = TCP (6), bitmask = 0xFF
        #[allow(unsafe_code)]
        unsafe {
            assert_eq!(fields[0].value_u8(), 6);
            assert_eq!(fields[0].mask_range_u8(), 0xFF);
        }

        // Field 1: ipv4_src = 10.0.0.0, prefix_len = 8
        #[allow(unsafe_code)]
        unsafe {
            assert_eq!(fields[1].value_u32(), u32::from(Ipv4Addr::new(10, 0, 0, 0)));
            assert_eq!(fields[1].mask_range_u32(), 8); // prefix length
        }

        // Field 2: eth_type = 0x0800, prefix_len = 16
        #[allow(unsafe_code)]
        unsafe {
            assert_eq!(fields[2].value_u16(), 0x0800);
            assert_eq!(fields[2].mask_range_u16(), 16); // prefix length
        }

        // Field 3: tcp_dst = range [80, 80]
        #[allow(unsafe_code)]
        unsafe {
            assert_eq!(fields[3].value_u16(), 80);
            assert_eq!(fields[3].mask_range_u16(), 80);
        }
    }

    #[test]
    fn wildcard_rule_produces_wildcard_fields() {
        // Rule with eth + ipv4 + tcp but no specific constraints
        let rule = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .tcp(|_| {})
            .permit(pri(1));

        let sig = FieldSignature::from_match_fields(rule.packet_match());
        let fields = translate_rule(sig, &rule);

        // Signature has: ipv4_proto + eth_type = 2 fields
        // (no src/dst/ports because they're Ignore)
        assert_eq!(sig.field_count(), 2);
        assert_eq!(fields.len(), 2);

        // Protocol = TCP (6), exact match (set by conform)
        #[allow(unsafe_code)]
        unsafe {
            assert_eq!(fields[0].value_u8(), 6);
        }

        // eth_type = IPv4 (set by conform)
        #[allow(unsafe_code)]
        unsafe {
            assert_eq!(fields[1].value_u16(), 0x0800);
        }
    }
}
