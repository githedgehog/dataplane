// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Assemble compact DPDK ACL input buffers from parsed [`Headers`].
//!
//! DPDK ACL classifies against a compact packed buffer, not raw
//! Ethernet frames.  This module builds that buffer by extracting
//! fields from parsed `Headers` and packing them in the same order
//! as [`build_field_defs`](crate::field_map::build_field_defs).
//!
//! The compact layout matches the 5-tuple example pattern from DPDK:
//! byte 0 = protocol (setup field), byte 1 = padding, byte 2+ =
//! remaining fields packed contiguously.

use acl::FieldSignature;
use dpdk::acl::field::FieldSize;
use net::headers::{Headers, Net, Transport};

/// Maximum size of a compact ACL input buffer.
pub const MAX_ACL_INPUT_SIZE: usize = 64;

/// An assembled compact ACL input buffer.
#[derive(Clone)]
pub struct AclInput {
    buf: [u8; MAX_ACL_INPUT_SIZE],
}

impl AclInput {
    /// Raw pointer to the buffer start (for `rte_acl_classify`).
    #[must_use]
    pub fn as_ptr(&self) -> *const u8 {
        self.buf.as_ptr()
    }
}

/// Assemble a compact input buffer for DPDK ACL classification.
///
/// The buffer layout must match the `FieldDef` array from
/// [`build_field_defs`](crate::field_map::build_field_defs) for the
/// same signature.
///
/// Fields are packed in the same order:
/// - Byte 0: protocol (setup field)
/// - Byte 1: padding
/// - Byte 2+: 4B/8B fields, then 2B fields
///
/// For promoted fields (lone 2-byte fields stored as 4-byte in the
/// FieldDefs), the 2 bytes of data are written at the start of the
/// 4-byte slot with 2 bytes of zero padding.
#[must_use]
pub fn assemble_compact_input(headers: &Headers, signature: FieldSignature) -> AclInput {
    let mut buf = [0u8; MAX_ACL_INPUT_SIZE];
    let mut offset: usize = 2; // first real field at byte 2

    // Byte 0: protocol (setup field)
    if signature.has_ipv4_proto() {
        if let Some(Net::Ipv4(ip)) = headers.net() {
            let proto: etherparse::IpNumber = ip.next_header().into();
            buf[0] = u8::from(proto);
        }
    } else if signature.has_ipv6_proto() {
        if let Some(Net::Ipv6(ip)) = headers.net() {
            let proto: etherparse::IpNumber = ip.next_header().into();
            buf[0] = u8::from(proto);
        }
    }
    // byte 1 = padding (already 0)

    // Remaining fields in the same order as build_field_defs:
    // 4B/8B fields first, then 2B (possibly promoted to 4B).

    // 4-byte fields
    if signature.has_ipv4_src() {
        if let Some(Net::Ipv4(ip)) = headers.net() {
            buf[offset..offset + 4].copy_from_slice(&ip.source().inner().octets());
        }
        offset += 4;
    }

    if signature.has_ipv4_dst() {
        if let Some(Net::Ipv4(ip)) = headers.net() {
            buf[offset..offset + 4].copy_from_slice(&ip.destination().octets());
        }
        offset += 4;
    }

    // TODO: ipv6 src/dst (16 bytes each)
    // TODO: vlan fields

    // 2-byte fields — packed in pairs.  If the count is odd, the last
    // one is promoted to 4 bytes (2 data + 2 zero padding).
    // We count them first to know which are promoted.
    let two_byte_count = count_two_byte_fields(signature);

    let mut two_byte_idx = 0;

    if signature.has_eth_type() {
        if let Some(eth) = headers.eth() {
            let et: u16 = eth.ether_type().into();
            buf[offset..offset + 2].copy_from_slice(&et.to_be_bytes());
        }
        offset += field_advance(two_byte_idx, two_byte_count);
        two_byte_idx += 1;
    }

    if signature.has_tcp_src() || signature.has_udp_src() {
        if let Some(Transport::Tcp(tcp)) = headers.transport() {
            buf[offset..offset + 2].copy_from_slice(&tcp.source().as_u16().to_be_bytes());
        } else if let Some(Transport::Udp(udp)) = headers.transport() {
            buf[offset..offset + 2].copy_from_slice(&udp.source().as_u16().to_be_bytes());
        }
        offset += field_advance(two_byte_idx, two_byte_count);
        two_byte_idx += 1;
    }

    if signature.has_tcp_dst() || signature.has_udp_dst() {
        if let Some(Transport::Tcp(tcp)) = headers.transport() {
            buf[offset..offset + 2].copy_from_slice(&tcp.destination().as_u16().to_be_bytes());
        } else if let Some(Transport::Udp(udp)) = headers.transport() {
            buf[offset..offset + 2].copy_from_slice(&udp.destination().as_u16().to_be_bytes());
        }
        offset += field_advance(two_byte_idx, two_byte_count);
        two_byte_idx += 1;
    }

    // TODO: icmp type/code

    let _ = (offset, two_byte_idx); // suppress unused warnings

    AclInput { buf }
}

/// Count the number of 2-byte fields in a signature.
/// Count the number of 2-byte fields in a signature.
///
/// Used by both input assembly and rule translation to determine
/// which fields are promoted.
#[must_use]
pub fn count_two_byte_fields(sig: FieldSignature) -> usize {
    let mut count = 0;
    if sig.has_eth_type() { count += 1; }
    if sig.has_tcp_src() || sig.has_udp_src() { count += 1; }
    if sig.has_tcp_dst() || sig.has_udp_dst() { count += 1; }
    if sig.has_icmp4_type() { count += 1; }
    if sig.has_icmp4_code() { count += 1; }
    count
}

/// Compute the byte advance for the `idx`-th 2-byte field.
///
/// 2-byte fields are packed in pairs within 4-byte words.
/// If the total count is odd, the last field is promoted to 4 bytes.
///
/// - Paired (even idx, not the last odd one): advance 2 bytes
/// - Second in pair (odd idx): advance 2 bytes
/// - Last unpaired (even idx == count - 1, count is odd): advance 4 bytes
fn field_advance(idx: usize, total: usize) -> usize {
    let is_last = idx == total - 1;
    let is_odd_total = total % 2 == 1;
    if is_last && is_odd_total {
        // Last field in odd-count list: promoted to 4 bytes
        4
    } else {
        2
    }
}

/// Check whether the `idx`-th 2-byte field in a signature was
/// promoted to 4 bytes (because it's a lone field at its input_index).
///
/// This happens when `idx` is the last field AND the total 2-byte
/// field count is odd.
#[must_use]
pub fn is_promoted(idx: usize, total_two_byte: usize) -> bool {
    idx == total_two_byte - 1 && total_two_byte % 2 == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use acl::{IpPrefix, AclRuleBuilder, FieldMatch, Ipv4Prefix, Priority};
    use net::headers::builder::HeaderStack;
    use net::tcp::port::TcpPort;
    use std::net::Ipv4Addr;

    fn pri(n: u32) -> Priority {
        Priority::new(n).unwrap()
    }

    #[test]
    fn compact_buffer_ipv4_tcp() {
        let rule = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.src = FieldMatch::Select(
                    Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
                );
            })
            .tcp(|tcp| {
                tcp.dst = FieldMatch::Select(80u16..=80u16);
            })
            .permit(pri(100));

        let sig = acl::FieldSignature::from_match_fields(rule.packet_match());

        let headers = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.set_source(
                    net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(10, 1, 2, 3)).unwrap(),
                );
            })
            .tcp(|tcp| {
                tcp.set_destination(TcpPort::new_checked(80).unwrap());
            })
            .build_headers()
            .unwrap();

        let input = assemble_compact_input(&headers, sig);
        let b = &input.buf;

        // 4 fields: proto, ipv4_src, eth_type + tcp_dst (paired 2B)
        // byte 0: protocol = 6 (TCP)
        assert_eq!(b[0], 6);
        // bytes 2-5: src IP 10.1.2.3 in NBO
        assert_eq!(&b[2..6], &[10, 1, 2, 3]);
        // bytes 6-7: eth_type 0x0800 in NBO
        assert_eq!(&b[6..8], &[0x08, 0x00]);
        // bytes 8-9: tcp_dst 80 in NBO
        assert_eq!(&b[8..10], &[0x00, 0x50]);
    }

    #[test]
    fn compact_buffer_ipv4_only_promoted() {
        // IPv4 src only, no transport.  eth_type is a lone 2-byte field
        // → promoted to 4 bytes in the buffer.
        let rule = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.src = FieldMatch::Select(
                    Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 12).unwrap(),
                );
            })
            .permit(pri(100));

        let sig = acl::FieldSignature::from_match_fields(rule.packet_match());
        assert_eq!(count_two_byte_fields(sig), 1, "should have 1 two-byte field (eth_type)");

        let headers = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.set_source(
                    net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(172, 16, 1, 1)).unwrap(),
                );
            })
            .tcp(|tcp| {
                tcp.set_destination(TcpPort::new_checked(80).unwrap());
            })
            .build_headers()
            .unwrap();

        let input = assemble_compact_input(&headers, sig);
        let b = &input.buf;

        // byte 0: no protocol in signature → 0
        assert_eq!(b[0], 0);
        // bytes 2-5: ipv4_src
        assert_eq!(&b[2..6], &[172, 16, 1, 1]);
        // bytes 6-7: eth_type 0x0800 in NBO
        assert_eq!(&b[6..8], &[0x08, 0x00]);
        // bytes 8-9: zero padding (promoted field)
        assert_eq!(&b[8..10], &[0x00, 0x00]);
    }
}
