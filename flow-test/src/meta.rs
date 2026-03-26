// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Packet metadata stamping helpers for pipeline integration tests.
//!
//! The dataplane pipeline uses [`PacketMeta`] flags and fields to route
//! packets through the correct processing stages (NAT, routing, forwarding).
//! In production these flags are set by earlier pipeline stages — for example,
//! the overlay decapsulation stage sets `is_overlay` and populates VPC
//! discriminants.
//!
//! In test harnesses there are no prior pipeline stages: the test itself must
//! stamp the metadata that downstream stages expect.  The helpers in this
//! module encapsulate that knowledge so test authors don't need to
//! reverse-engineer each stage's preconditions.
//!
//! [`PacketMeta`]: net::packet::PacketMeta

use net::buffer::PacketBufferMut;
use net::packet::{Packet, VpcDiscriminant};

/// Stamp `packet` with the metadata that [`StatefulNat`] requires.
///
/// After this call the following metadata fields are set:
///
/// | Field / flag            | Value       | Why                                      |
/// |-------------------------|-------------|------------------------------------------|
/// | `is_overlay`            | `true`      | NAT only processes overlay packets       |
/// | `requires_stateful_nat` | `true`      | Gate checked by `StatefulNat::process`   |
/// | `src_vpcd`              | `src_vpcd`  | Source VPC discriminant for session key   |
/// | `dst_vpcd`              | `dst_vpcd`  | Destination VPC discriminant for session  |
///
/// # What this does **not** set
///
/// * **`flow_info`** — callers must perform a [`FlowTable::lookup`] and
///   attach the result before passing the packet to `StatefulNat::process`
///   when an existing session should be matched.  New sessions are created
///   by the NAT itself when `flow_info` is `None`.
///
/// # Example (sketch — types simplified)
///
/// ```ignore
/// use dataplane_flow_test::meta::stamp_for_stateful_nat;
///
/// let pipe = move |mut pkt| {
///     stamp_for_stateful_nat(&mut pkt, client_vpcd, server_vpcd);
///     // … flow-table lookup, then nat.process(once(pkt)).next()
/// };
/// ```
///
/// [`StatefulNat`]: https://docs.rs/dataplane-nat
/// [`FlowTable::lookup`]: https://docs.rs/dataplane-flow-entry
pub fn stamp_for_stateful_nat<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    src_vpcd: VpcDiscriminant,
    dst_vpcd: VpcDiscriminant,
) {
    let meta = packet.meta_mut();
    meta.set_overlay(true);
    meta.set_stateful_nat(true);
    meta.src_vpcd = Some(src_vpcd);
    meta.dst_vpcd = Some(dst_vpcd);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::frame_to_packet;
    use net::buffer::TestBuffer;
    use net::vxlan::Vni;

    // -- smoltcp wire types (quarantined to test module) --------------------
    use smoltcp::wire::{
        EthernetAddress, EthernetFrame, EthernetProtocol, EthernetRepr, IpProtocol, Ipv4Address,
        Ipv4Packet, Ipv4Repr, UdpPacket, UdpRepr,
    };

    const SRC_MAC: EthernetAddress = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    const DST_MAC: EthernetAddress = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    const SRC_IP: Ipv4Address = Ipv4Address::new(10, 0, 0, 1);
    const DST_IP: Ipv4Address = Ipv4Address::new(10, 0, 0, 2);

    // -- helpers ------------------------------------------------------------

    /// Build a [`VpcDiscriminant`] from a raw VNI value.
    fn test_vpcd(vni_id: u32) -> VpcDiscriminant {
        let vni = Vni::new_checked(vni_id)
            .unwrap_or_else(|_| unreachable!("test VNI {vni_id} is in valid range"));
        VpcDiscriminant::from_vni(vni)
    }

    /// Build a minimal valid Ethernet + IPv4 + UDP frame.
    fn build_udp_frame() -> Vec<u8> {
        let payload: &[u8] = b"test";
        let udp_repr = UdpRepr {
            src_port: 12345,
            dst_port: 80,
        };
        let ip_repr = Ipv4Repr {
            src_addr: SRC_IP,
            dst_addr: DST_IP,
            next_header: IpProtocol::Udp,
            payload_len: udp_repr.header_len() + payload.len(),
            hop_limit: 64,
        };
        let eth_repr = EthernetRepr {
            src_addr: SRC_MAC,
            dst_addr: DST_MAC,
            ethertype: EthernetProtocol::Ipv4,
        };
        let total_len = EthernetFrame::<&[u8]>::header_len()
            + ip_repr.buffer_len()
            + udp_repr.header_len()
            + payload.len();
        let mut buf = vec![0u8; total_len];

        let mut eth = EthernetFrame::new_unchecked(&mut buf);
        eth_repr.emit(&mut eth);

        let mut ip = Ipv4Packet::new_unchecked(eth.payload_mut());
        ip_repr.emit(&mut ip, &smoltcp::phy::ChecksumCapabilities::default());

        let mut udp = UdpPacket::new_unchecked(ip.payload_mut());
        udp_repr.emit(
            &mut udp,
            &SRC_IP.into(),
            &DST_IP.into(),
            payload.len(),
            |target| target.copy_from_slice(payload),
            &smoltcp::phy::ChecksumCapabilities::default(),
        );

        buf
    }

    /// Parse a test frame into a [`Packet<TestBuffer>`].
    fn make_test_packet() -> Packet<TestBuffer> {
        frame_to_packet(&build_udp_frame())
            .unwrap_or_else(|| unreachable!("valid UDP frame should parse"))
    }

    // -- tests --------------------------------------------------------------

    #[test]
    fn stamp_sets_overlay_flag() {
        let mut packet = make_test_packet();
        assert!(
            !packet.meta().is_overlay(),
            "fresh packet should not be overlay"
        );

        stamp_for_stateful_nat(&mut packet, test_vpcd(100), test_vpcd(200));

        assert!(
            packet.meta().is_overlay(),
            "overlay flag should be set after stamping"
        );
    }

    #[test]
    fn stamp_sets_stateful_nat_flag() {
        let mut packet = make_test_packet();
        assert!(
            !packet.meta().requires_stateful_nat(),
            "fresh packet should not require stateful NAT"
        );

        stamp_for_stateful_nat(&mut packet, test_vpcd(100), test_vpcd(200));

        assert!(
            packet.meta().requires_stateful_nat(),
            "stateful NAT flag should be set after stamping"
        );
    }

    #[test]
    fn stamp_sets_vpc_discriminants() {
        let mut packet = make_test_packet();
        assert!(
            packet.meta().src_vpcd.is_none(),
            "fresh packet should not have src_vpcd"
        );
        assert!(
            packet.meta().dst_vpcd.is_none(),
            "fresh packet should not have dst_vpcd"
        );

        stamp_for_stateful_nat(&mut packet, test_vpcd(100), test_vpcd(200));

        assert!(
            packet.meta().src_vpcd.is_some(),
            "src_vpcd should be set after stamping"
        );
        assert!(
            packet.meta().dst_vpcd.is_some(),
            "dst_vpcd should be set after stamping"
        );
    }

    #[test]
    fn stamp_does_not_clear_unrelated_flags() {
        let mut packet = make_test_packet();

        // Set some unrelated flags before stamping.
        packet.meta_mut().set_l2bcast(true);

        stamp_for_stateful_nat(&mut packet, test_vpcd(100), test_vpcd(200));

        assert!(
            packet.meta().is_l2bcast(),
            "unrelated l2bcast flag should be preserved"
        );
    }

    #[test]
    fn stamp_overwrites_previous_discriminants() {
        let mut packet = make_test_packet();

        stamp_for_stateful_nat(&mut packet, test_vpcd(100), test_vpcd(200));
        assert!(packet.meta().src_vpcd.is_some());

        // Stamp again with different VPC IDs.
        stamp_for_stateful_nat(&mut packet, test_vpcd(300), test_vpcd(400));

        // Flags should still be set (idempotent).
        assert!(packet.meta().is_overlay());
        assert!(packet.meta().requires_stateful_nat());
        assert!(packet.meta().src_vpcd.is_some());
        assert!(packet.meta().dst_vpcd.is_some());
    }

    #[test]
    fn stamp_does_not_set_flow_info() {
        let mut packet = make_test_packet();
        stamp_for_stateful_nat(&mut packet, test_vpcd(100), test_vpcd(200));

        assert!(
            packet.meta().flow_info.is_none(),
            "stamp_for_stateful_nat must not set flow_info; callers do that via FlowTable::lookup"
        );
    }
}
