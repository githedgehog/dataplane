// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Assemble DPDK ACL input buffers from parsed [`Headers`].
//!
//! DPDK ACL classifies raw bytes in network byte order.  This module
//! builds a byte buffer from parsed `Headers` values, placing each
//! field at the offset specified by an [`OffsetProvider`].
//!
//! This is the v1 approach (option 2 from the design docs): ~20-60
//! bytes of copy per packet, negligible compared to trie traversal.

use net::headers::{Headers, Net, Transport};

use crate::field_map::OffsetProvider;

/// Maximum size of an ACL input buffer.
///
/// Must be large enough to hold all matchable fields at their maximum
/// offsets.  128 bytes covers standard Ethernet + IPv6 + TCP with room
/// to spare.
pub const MAX_ACL_INPUT_SIZE: usize = 128;

/// An assembled ACL input buffer ready for `rte_acl_classify`.
///
/// Fields are placed at network-byte-order offsets matching the
/// [`OffsetProvider`] used during compilation.
#[derive(Clone)]
pub struct AclInput {
    buf: [u8; MAX_ACL_INPUT_SIZE],
    len: usize,
}

impl AclInput {
    /// The buffer as a byte slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Raw pointer to the buffer start (for `rte_acl_classify`).
    #[must_use]
    pub fn as_ptr(&self) -> *const u8 {
        self.buf.as_ptr()
    }
}

/// Assemble a DPDK ACL input buffer from parsed [`Headers`].
///
/// Places each protocol field at the byte offset specified by `offsets`,
/// in network byte order.  Fields not present in `headers` are left as
/// zero (which DPDK ACL treats as "doesn't match" for mask-type fields
/// with a non-zero mask, and "matches" for wildcard mask=0 fields).
#[must_use]
pub fn assemble_input(headers: &Headers, offsets: &impl OffsetProvider) -> AclInput {
    let mut buf = [0u8; MAX_ACL_INPUT_SIZE];

    // Ethernet
    if let Some(eth) = headers.eth() {
        let src = eth.source().inner();
        let dst = eth.destination().inner();
        let et: u16 = eth.ether_type().into();

        write_bytes(&mut buf, offsets.eth_src_offset(), &src.0);
        write_bytes(&mut buf, offsets.eth_dst_offset(), &dst.0);
        write_u16_be(&mut buf, offsets.eth_type_offset(), et);
    }

    // VLAN (first tag)
    let vlans = headers.vlan();
    if let Some(vlan) = vlans.first() {
        let vid: u16 = vlan.vid().into();
        let pcp: u8 = vlan.pcp().into();
        let inner_et: u16 = vlan.inner_ethtype().into();

        write_u16_be(&mut buf, offsets.vlan_vid_offset(), vid);
        write_u8(&mut buf, offsets.vlan_pcp_offset(), pcp);
        write_u16_be(&mut buf, offsets.vlan_inner_type_offset(), inner_et);
    }

    // IPv4
    if let Some(Net::Ipv4(ip)) = headers.net() {
        let src = ip.source().inner().octets();
        let dst = ip.destination().octets();
        let proto = {
            let ip_number: etherparse::IpNumber = ip.next_header().into();
            u8::from(ip_number)
        };

        write_u8(&mut buf, offsets.ipv4_proto_offset(), proto);
        write_bytes(&mut buf, offsets.ipv4_src_offset(), &src);
        write_bytes(&mut buf, offsets.ipv4_dst_offset(), &dst);
    }

    // IPv6
    if let Some(Net::Ipv6(ip)) = headers.net() {
        let src = ip.source().inner().octets();
        let dst = ip.destination().octets();
        let proto = {
            let ip_number: etherparse::IpNumber = ip.next_header().into();
            u8::from(ip_number)
        };

        write_u8(&mut buf, offsets.ipv6_proto_offset(), proto);
        write_bytes(&mut buf, offsets.ipv6_src_offset(), &src);
        write_bytes(&mut buf, offsets.ipv6_dst_offset(), &dst);
    }

    // TCP
    if let Some(Transport::Tcp(tcp)) = headers.transport() {
        let src = tcp.source().as_u16();
        let dst = tcp.destination().as_u16();

        write_u16_be(&mut buf, offsets.l4_src_port_offset(), src);
        write_u16_be(&mut buf, offsets.l4_dst_port_offset(), dst);
    }

    // UDP
    if let Some(Transport::Udp(udp)) = headers.transport() {
        let src = udp.source().as_u16();
        let dst = udp.destination().as_u16();

        write_u16_be(&mut buf, offsets.l4_src_port_offset(), src);
        write_u16_be(&mut buf, offsets.l4_dst_port_offset(), dst);
    }

    // ICMP — type and code at the same offsets as L4 ports
    // (DPDK ACL treats them as 1-byte fields at the transport offset)
    if let Some(Transport::Icmp4(_icmp)) = headers.transport() {
        // TODO: extract type/code once Icmp4 exposes raw u8 accessors
    }

    // Compute the highest offset written to determine effective length.
    // For simplicity, use the full buffer — DPDK ACL reads only at
    // defined offsets, so unused bytes don't matter.
    AclInput {
        buf,
        len: MAX_ACL_INPUT_SIZE,
    }
}

// ---- Byte-writing helpers ----
// These write to the buffer at a given offset in network byte order.
// Bounds checking is implicit — offsets beyond MAX_ACL_INPUT_SIZE
// are silently ignored (defensive, shouldn't happen with valid offsets).

fn write_u8(buf: &mut [u8; MAX_ACL_INPUT_SIZE], offset: u32, value: u8) {
    let off = offset as usize;
    if off < MAX_ACL_INPUT_SIZE {
        buf[off] = value;
    }
}

fn write_u16_be(buf: &mut [u8; MAX_ACL_INPUT_SIZE], offset: u32, value: u16) {
    let off = offset as usize;
    if off + 1 < MAX_ACL_INPUT_SIZE {
        buf[off..off + 2].copy_from_slice(&value.to_be_bytes());
    }
}

fn write_bytes(buf: &mut [u8; MAX_ACL_INPUT_SIZE], offset: u32, bytes: &[u8]) {
    let off = offset as usize;
    let end = off + bytes.len();
    if end <= MAX_ACL_INPUT_SIZE {
        buf[off..end].copy_from_slice(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field_map::StandardEthernetOffsets;
    use net::headers::builder::HeaderStack;
    use net::tcp::port::TcpPort;
    use std::net::Ipv4Addr;

    #[test]
    fn assemble_ipv4_tcp_packet() {
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

        let offsets = StandardEthernetOffsets;
        let input = assemble_input(&headers, &offsets);
        let buf = input.as_bytes();

        // EthType at offset 12 — should be 0x0800 (IPv4) in network order
        assert_eq!(buf[12], 0x08);
        assert_eq!(buf[13], 0x00);

        // IPv4 protocol at offset 23 — should be 6 (TCP)
        assert_eq!(buf[23], 6);

        // IPv4 src at offset 26 — 10.1.2.3
        assert_eq!(&buf[26..30], &[10, 1, 2, 3]);

        // IPv4 dst at offset 30 — 192.168.1.1
        assert_eq!(&buf[30..34], &[192, 168, 1, 1]);

        // TCP src port at offset 34 — 12345 in network order
        assert_eq!(&buf[34..36], &12345u16.to_be_bytes());

        // TCP dst port at offset 36 — 80 in network order
        assert_eq!(&buf[36..38], &80u16.to_be_bytes());
    }

    #[test]
    fn assemble_empty_headers() {
        let headers = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .tcp(|_| {})
            .build_headers()
            .unwrap();

        let offsets = StandardEthernetOffsets;
        let input = assemble_input(&headers, &offsets);

        // Should not panic, buffer should be valid
        assert_eq!(input.as_bytes().len(), MAX_ACL_INPUT_SIZE);
    }
}
