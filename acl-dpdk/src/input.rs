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

/// Assemble a compact DPDK ACL input buffer from parsed [`Headers`].
///
/// Fields are packed in the same order as
/// [`build_field_defs`](crate::field_map::build_field_defs):
/// byte 0 = protocol, byte 1 = padding, byte 2+ = remaining fields.
///
/// All multi-byte values are in **network byte order** (big-endian),
/// as required by DPDK ACL input buffers.
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
    // 4B/8B fields first, then 2B, then 1B.

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

    // 2-byte fields
    if signature.has_eth_type() {
        if let Some(eth) = headers.eth() {
            let et: u16 = eth.ether_type().into();
            buf[offset..offset + 2].copy_from_slice(&et.to_be_bytes());
        }
        offset += 2;
    }

    if signature.has_tcp_src() || signature.has_udp_src() {
        if let Some(Transport::Tcp(tcp)) = headers.transport() {
            buf[offset..offset + 2].copy_from_slice(&tcp.source().as_u16().to_be_bytes());
        } else if let Some(Transport::Udp(udp)) = headers.transport() {
            buf[offset..offset + 2].copy_from_slice(&udp.source().as_u16().to_be_bytes());
        }
        offset += 2;
    }

    if signature.has_tcp_dst() || signature.has_udp_dst() {
        if let Some(Transport::Tcp(tcp)) = headers.transport() {
            buf[offset..offset + 2].copy_from_slice(&tcp.destination().as_u16().to_be_bytes());
        } else if let Some(Transport::Udp(udp)) = headers.transport() {
            buf[offset..offset + 2].copy_from_slice(&udp.destination().as_u16().to_be_bytes());
        }
        #[allow(unused_assignments)]
        { offset += 2; }
    }

    // TODO: icmp type/code

    AclInput { buf }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net::headers::builder::HeaderStack;
    use net::tcp::port::TcpPort;
    use std::net::Ipv4Addr;

    #[test]
    fn compact_ipv4_tcp_layout() {
        let headers = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.set_source(
                    net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(10, 1, 2, 3)).unwrap(),
                );
                ip.set_destination(Ipv4Addr::new(192, 168, 1, 1));
            })
            .tcp(|tcp| {
                tcp.set_source(TcpPort::new_checked(12345).unwrap());
                tcp.set_destination(TcpPort::new_checked(80).unwrap());
            })
            .build_headers()
            .unwrap();

        // Build signature matching eth+ipv4+tcp rule with src+dst+proto+ethtype+tcp_dst
        use acl::{AclRuleBuilder, FieldMatch, Ipv4Prefix, PortRange, Priority};
        let rule = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.src =
                    FieldMatch::Select(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
            })
            .tcp(|tcp| {
                tcp.dst = FieldMatch::Select(PortRange::exact(80u16));
            })
            .permit(Priority::new(1).unwrap());
        let sig = FieldSignature::from_match_fields(rule.packet_match());

        let input = assemble_compact_input(&headers, sig);
        let b = &input.buf;

        // New order: proto, ipv4_src, eth_type, tcp_dst
        // byte 0: protocol = 6 (TCP)
        assert_eq!(b[0], 6);
        // byte 1: padding
        // byte 2-5: ipv4 src = 10.1.2.3 (NBO)
        assert_eq!(&b[2..6], &[10, 1, 2, 3]);
        // byte 6-7: ether_type = 0x0800 (big-endian)
        assert_eq!(&b[6..8], &[0x08, 0x00]);
        // byte 8-9: tcp dst = 80 (big-endian)
        assert_eq!(&b[8..10], &80u16.to_be_bytes());
    }
}
