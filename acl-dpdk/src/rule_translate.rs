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

    // Protocol first (DPDK field 0 must be 1 byte).
    if signature.has_ipv4_proto() {
        fields.push(translate_proto(pm.ipv4()));
    } else if signature.has_ipv6_proto() {
        fields.push(translate_proto_v6(pm.ipv6()));
    }

    // Remaining fields in canonical order (must match build_field_defs).
    if signature.has_eth_type() {
        fields.push(translate_eth_type(pm.eth()));
    }
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
    if signature.has_tcp_src() {
        fields.push(translate_port_range_tcp(
            pm.tcp().map(|m| &m.src),
        ));
    }
    if signature.has_tcp_dst() {
        fields.push(translate_port_range_tcp(
            pm.tcp().map(|m| &m.dst),
        ));
    }
    if signature.has_udp_src() {
        fields.push(translate_port_range_udp(
            pm.udp().map(|m| &m.src),
        ));
    }
    if signature.has_udp_dst() {
        fields.push(translate_port_range_udp(
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
fn translate_proto(ipv4: Option<&Ipv4Match>) -> AclField {
    match ipv4.and_then(|m| m.protocol.as_select()) {
        Some(nh) => AclField::from_u8(next_header_to_u8(*nh), u8::MAX),
        None => AclField::wildcard(),
    }
}

/// Translate IPv6 next-header / protocol field.
fn translate_proto_v6(ipv6: Option<&Ipv6Match>) -> AclField {
    match ipv6.and_then(|m| m.protocol.as_select()) {
        Some(nh) => AclField::from_u8(next_header_to_u8(*nh), u8::MAX),
        None => AclField::wildcard(),
    }
}

/// Translate ether_type field.
fn translate_eth_type(eth: Option<&EthMatch>) -> AclField {
    match eth.and_then(|m| m.ether_type.as_select()) {
        Some(et) => {
            let val: u16 = (*et).into();
            AclField::from_u16(val, u16::MAX)
        }
        None => AclField::wildcard(),
    }
}

/// Translate an IPv4 prefix (src or dst) to a mask-type `AclField`.
fn translate_ipv4_prefix(
    field: Option<&FieldMatch<acl::Ipv4Prefix>>,
) -> AclField {
    match field.and_then(FieldMatch::as_select) {
        Some(pfx) => {
            AclField::from_u32(u32::from(pfx.addr()), pfx.mask())
        }
        None => AclField::wildcard(),
    }
}

/// Translate an IPv6 prefix to two 8-byte mask-type `AclField`s (hi, lo).
fn translate_ipv6_prefix(
    field: Option<&FieldMatch<acl::Ipv6Prefix>>,
) -> (AclField, AclField) {
    match field.and_then(FieldMatch::as_select) {
        Some(pfx) => {
            let addr = u128::from(pfx.addr());
            let mask = pfx.mask();
            let hi_val = (addr >> 64) as u64;
            let hi_mask = (mask >> 64) as u64;
            let lo_val = addr as u64;
            let lo_mask = mask as u64;
            (
                AclField::from_u64(hi_val, hi_mask),
                AclField::from_u64(lo_val, lo_mask),
            )
        }
        None => (AclField::wildcard(), AclField::wildcard()),
    }
}

/// Translate a TCP port range field.
fn translate_port_range_tcp(
    field: Option<&FieldMatch<acl::PortRange<net::tcp::port::TcpPort>>>,
) -> AclField {
    match field.and_then(FieldMatch::as_select) {
        Some(range) => AclField::from_u16(range.min.as_u16(), range.max.as_u16()),
        None => AclField::from_u16(0, u16::MAX), // range wildcard: 0..65535
    }
}

/// Translate a UDP port range field.
fn translate_port_range_udp(
    field: Option<&FieldMatch<acl::PortRange<net::udp::port::UdpPort>>>,
) -> AclField {
    match field.and_then(FieldMatch::as_select) {
        Some(range) => AclField::from_u16(range.min.as_u16(), range.max.as_u16()),
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
    use net::tcp::port::TcpPort;
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
                tcp.dst = FieldMatch::Select(PortRange::exact(TcpPort::new_checked(80).unwrap()));
            })
            .permit(pri(100));

        let sig = FieldSignature::from_match_fields(rule.packet_match());
        let fields = translate_rule(sig, &rule);

        // Signature has: ipv4_proto, eth_type, ipv4_src, tcp_dst = 4 fields
        assert_eq!(fields.len(), 4);

        // Field 0: protocol = TCP (6), mask = 0xFF
        #[allow(unsafe_code)]
        unsafe {
            assert_eq!(fields[0].value_u8(), 6); // TCP
            assert_eq!(fields[0].mask_range_u8(), 0xFF);
        }

        // Field 1: eth_type = 0x0800 (IPv4), mask = 0xFFFF
        #[allow(unsafe_code)]
        unsafe {
            assert_eq!(fields[1].value_u16(), 0x0800);
            assert_eq!(fields[1].mask_range_u16(), 0xFFFF);
        }

        // Field 2: ipv4_src = 10.0.0.0, mask = 255.0.0.0 (/8)
        #[allow(unsafe_code)]
        unsafe {
            assert_eq!(fields[2].value_u32(), u32::from(Ipv4Addr::new(10, 0, 0, 0)));
            assert_eq!(fields[2].mask_range_u32(), 0xFF00_0000);
        }

        // Field 3: tcp_dst = range 80..80
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
