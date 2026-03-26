// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Translation layer between raw Ethernet frames and [`Packet<Buf>`].
//!
//! This module contains the **entire boundary** between the smoltcp world
//! (raw `&[u8]` frames) and the `net` crate world ([`Packet<Buf>`]).
//! Only two functions are exposed:
//!
//! - [`frame_to_packet`]: raw bytes → [`Packet<Buf>`]
//! - [`packet_to_frame`]: [`Packet<Buf>`] → raw bytes
//!
//! By funnelling every conversion through these two functions, we guarantee
//! that smoltcp types never leak into downstream test code.
//!
//! [`Packet<Buf>`]: net::packet::Packet

use net::buffer::FrameBuffer;
use net::packet::Packet;

/// Convert a raw Ethernet frame into a [`Packet<Buf>`].
///
/// Returns `None` if the frame does not parse as a valid Ethernet packet.
#[must_use]
pub fn frame_to_packet<Buf: FrameBuffer>(raw: &[u8]) -> Option<Packet<Buf>> {
    let buf = Buf::from_frame(raw);
    Packet::new(buf).ok()
}

/// Serialize a [`Packet<Buf>`] back to a raw Ethernet frame.
///
/// Returns `None` if serialization fails (e.g. insufficient headroom).
#[must_use]
pub fn packet_to_frame<Buf: FrameBuffer>(packet: Packet<Buf>) -> Option<Vec<u8>> {
    let buf = packet.serialize().ok()?;
    Some(buf.as_ref().to_vec())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use net::buffer::TestBuffer;
    use net::eth::mac::Mac;
    use net::headers::{TryEth, TryHeaders, TryIpv4, TryTcp, TryUdp};

    // -- helpers (smoltcp wire types are confined to this test module) -------

    use smoltcp::wire::{
        EthernetAddress, EthernetFrame, EthernetProtocol, EthernetRepr, IpProtocol, Ipv4Address,
        Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, UdpPacket, UdpRepr,
    };

    const SRC_MAC: EthernetAddress = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    const DST_MAC: EthernetAddress = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    const SRC_IP: Ipv4Address = Ipv4Address::new(10, 0, 0, 1);
    const DST_IP: Ipv4Address = Ipv4Address::new(10, 0, 0, 2);
    const SRC_PORT: u16 = 12345;
    const DST_PORT: u16 = 80;

    /// Build a raw Ethernet frame containing a TCP SYN packet.
    fn build_tcp_syn_frame() -> Vec<u8> {
        let tcp_repr = TcpRepr {
            src_port: SRC_PORT,
            dst_port: DST_PORT,
            control: TcpControl::Syn,
            seq_number: smoltcp::wire::TcpSeqNumber(1000),
            ack_number: None,
            window_len: 65535,
            window_scale: None,
            max_seg_size: Some(1460),
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };

        let ip_repr = Ipv4Repr {
            src_addr: SRC_IP,
            dst_addr: DST_IP,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.header_len(),
            hop_limit: 64,
        };

        let eth_repr = EthernetRepr {
            src_addr: SRC_MAC,
            dst_addr: DST_MAC,
            ethertype: EthernetProtocol::Ipv4,
        };

        let total_len =
            EthernetFrame::<&[u8]>::header_len() + ip_repr.buffer_len() + tcp_repr.header_len();

        let mut buf = vec![0u8; total_len];

        // Ethernet
        let mut eth_frame = EthernetFrame::new_unchecked(&mut buf);
        eth_repr.emit(&mut eth_frame);

        // IPv4
        let ip_payload = eth_frame.payload_mut();
        let mut ip_packet = Ipv4Packet::new_unchecked(ip_payload);
        ip_repr.emit(&mut ip_packet, &smoltcp::phy::ChecksumCapabilities::default());

        // TCP
        let tcp_payload = ip_packet.payload_mut();
        let mut tcp_packet = TcpPacket::new_unchecked(tcp_payload);
        tcp_repr.emit(
            &mut tcp_packet,
            &SRC_IP.into(),
            &DST_IP.into(),
            &smoltcp::phy::ChecksumCapabilities::default(),
        );

        buf
    }

    /// Build a raw Ethernet frame containing a UDP packet with the given payload.
    fn build_udp_frame(payload: &[u8]) -> Vec<u8> {
        let udp_repr = UdpRepr {
            src_port: SRC_PORT,
            dst_port: DST_PORT,
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

        // Ethernet
        let mut eth_frame = EthernetFrame::new_unchecked(&mut buf);
        eth_repr.emit(&mut eth_frame);

        // IPv4
        let ip_buf = eth_frame.payload_mut();
        let mut ip_packet = Ipv4Packet::new_unchecked(ip_buf);
        ip_repr.emit(&mut ip_packet, &smoltcp::phy::ChecksumCapabilities::default());

        // UDP
        let udp_buf = ip_packet.payload_mut();
        let mut udp_packet = UdpPacket::new_unchecked(udp_buf);
        udp_repr.emit(
            &mut udp_packet,
            &SRC_IP.into(),
            &DST_IP.into(),
            payload.len(),
            |target| target.copy_from_slice(payload),
            &smoltcp::phy::ChecksumCapabilities::default(),
        );

        buf
    }

    // -- round-trip tests ---------------------------------------------------

    #[test]
    fn tcp_syn_round_trips_without_data_loss() {
        let original = build_tcp_syn_frame();

        let packet: Packet<TestBuffer> =
            frame_to_packet(&original).unwrap_or_else(|| panic!("failed to parse TCP SYN frame"));

        let serialized =
            packet_to_frame(packet).unwrap_or_else(|| panic!("failed to serialize packet"));

        assert_eq!(
            original, serialized,
            "TCP SYN frame did not round-trip losslessly"
        );
    }

    #[test]
    fn udp_with_payload_round_trips_without_data_loss() {
        let payload = b"hello, flow-test!";
        let original = build_udp_frame(payload);

        let packet: Packet<TestBuffer> =
            frame_to_packet(&original).unwrap_or_else(|| panic!("failed to parse UDP frame"));

        let serialized =
            packet_to_frame(packet).unwrap_or_else(|| panic!("failed to serialize packet"));

        assert_eq!(
            original, serialized,
            "UDP frame did not round-trip losslessly"
        );
    }

    // -- header accessor tests ----------------------------------------------

    #[test]
    fn tcp_syn_frame_has_correct_headers() {
        let frame = build_tcp_syn_frame();
        let packet: Packet<TestBuffer> =
            frame_to_packet(&frame).unwrap_or_else(|| panic!("failed to parse TCP SYN frame"));

        let headers = packet.headers();

        // Ethernet
        let eth = headers.try_eth().unwrap_or_else(|| panic!("missing Eth header"));
        let src_mac = eth.source();
        let dst_mac = eth.destination();
        assert_eq!(
            AsRef::<Mac>::as_ref(&src_mac).as_ref(),
            &SRC_MAC.0,
            "source MAC mismatch"
        );
        assert_eq!(
            AsRef::<Mac>::as_ref(&dst_mac).as_ref(),
            &DST_MAC.0,
            "destination MAC mismatch"
        );

        // IPv4
        let ipv4 = headers
            .try_ipv4()
            .unwrap_or_else(|| panic!("missing IPv4 header"));
        assert_eq!(
            ipv4.source().inner().octets(),
            SRC_IP.octets(),
            "source IP mismatch"
        );
        assert_eq!(
            ipv4.destination().octets(),
            DST_IP.octets(),
            "destination IP mismatch"
        );

        // TCP
        let tcp = headers.try_tcp().unwrap_or_else(|| panic!("missing TCP header"));
        assert_eq!(u16::from(tcp.source()), SRC_PORT, "source port mismatch");
        assert_eq!(u16::from(tcp.destination()), DST_PORT, "destination port mismatch");
        assert!(tcp.syn(), "SYN flag should be set");
    }

    #[test]
    fn udp_frame_has_correct_headers() {
        let frame = build_udp_frame(b"test");
        let packet: Packet<TestBuffer> =
            frame_to_packet(&frame).unwrap_or_else(|| panic!("failed to parse UDP frame"));

        let headers = packet.headers();

        // Ethernet
        assert!(
            headers.try_eth().is_some(),
            "parsed UDP frame should have Eth header"
        );

        // IPv4
        let ipv4 = headers
            .try_ipv4()
            .unwrap_or_else(|| panic!("missing IPv4 header"));
        assert_eq!(ipv4.source().inner().octets(), SRC_IP.octets());
        assert_eq!(ipv4.destination().octets(), DST_IP.octets());

        // UDP
        let udp = headers.try_udp().unwrap_or_else(|| panic!("missing UDP header"));
        assert_eq!(u16::from(udp.source()), SRC_PORT);
        assert_eq!(u16::from(udp.destination()), DST_PORT);

        // Should NOT have TCP
        assert!(headers.try_tcp().is_none(), "UDP frame should not have TCP header");
    }

    // -- error handling tests -----------------------------------------------

    #[test]
    fn garbage_bytes_return_none() {
        let garbage = vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA];
        let result: Option<Packet<TestBuffer>> = frame_to_packet(&garbage);
        assert!(result.is_none(), "garbage bytes should not parse as a Packet");
    }

    #[test]
    fn empty_slice_returns_none() {
        let result: Option<Packet<TestBuffer>> = frame_to_packet(&[]);
        assert!(result.is_none(), "empty slice should not parse as a Packet");
    }

    #[test]
    fn truncated_ethernet_header_returns_none() {
        // An Ethernet header is 14 bytes; provide only 10.
        let short = vec![0u8; 10];
        let result: Option<Packet<TestBuffer>> = frame_to_packet(&short);
        assert!(
            result.is_none(),
            "truncated Ethernet header should not parse"
        );
    }

    #[test]
    fn ethernet_only_frame_parses_without_panic() {
        // A minimal Ethernet frame header (14 bytes) with an IPv4 EtherType
        // but no valid IP payload. We only verify that this does not panic;
        // whether it parses or not depends on the net crate's strictness.
        let eth_repr = EthernetRepr {
            src_addr: SRC_MAC,
            dst_addr: DST_MAC,
            ethertype: EthernetProtocol::Ipv4,
        };

        let mut buf = vec![0u8; EthernetFrame::<&[u8]>::header_len()];
        let mut eth_frame = EthernetFrame::new_unchecked(&mut buf);
        eth_repr.emit(&mut eth_frame);

        let _result: Option<Packet<TestBuffer>> = frame_to_packet(&buf);
    }
}
