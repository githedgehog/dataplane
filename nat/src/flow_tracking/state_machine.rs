// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Small state machines for tracked flows. We use them to know how much to extend the lifetime
//! of flows.

use super::FlowSide;
use crate::common::NatFlowStatus;
use net::buffer::PacketBufferMut;
use net::headers::{TryHeaders, TryTcp};
use net::ip::NextHeader;
use net::packet::Packet;
use net::tcp::Tcp;

fn next_status_udp(side: FlowSide, status: NatFlowStatus) -> NatFlowStatus {
    match side {
        FlowSide::Initiator => match status {
            NatFlowStatus::TwoWay => NatFlowStatus::Established,
            _ => status,
        },
        FlowSide::Responder => match status {
            NatFlowStatus::OneWay => NatFlowStatus::TwoWay,
            _ => status,
        },
    }
}

// Echo requests and replies never terminate a flow here. ICMP errors go through
// `IcmpErrorHandler`, which can remove a one-way mapping on a hard error. RFC 5382
// REQ-10 and RFC 4787 REQ-12 cover errors too, so this function cannot establish
// compliance with either requirement.
#[allow(clippy::match_single_binding)]
fn next_status_icmp(side: FlowSide, status: NatFlowStatus) -> NatFlowStatus {
    let next = match side {
        FlowSide::Initiator => match status {
            _ => status,
        },
        FlowSide::Responder => match status {
            NatFlowStatus::OneWay => NatFlowStatus::TwoWay,
            _ => status,
        },
    };
    if cfg!(debug_assertions)
        && matches!(next, NatFlowStatus::Closed | NatFlowStatus::Reset)
        && !matches!(status, NatFlowStatus::Closed | NatFlowStatus::Reset)
    {
        unreachable!("an ICMP query moved a live flow from {status:?} to {next:?} ({side})");
    }
    next
}

// Note: RST only applies when no other arm matches. For example, RST+ACK from the initiator in
// TwoWay moves the flow to Established, not to Reset.
fn next_status_tcp(side: FlowSide, status: NatFlowStatus, tcp: &Tcp) -> NatFlowStatus {
    match side {
        FlowSide::Initiator => match status {
            NatFlowStatus::TwoWay if !tcp.syn() && tcp.ack() => NatFlowStatus::Established,
            NatFlowStatus::Established if tcp.fin() => NatFlowStatus::CClosing,
            NatFlowStatus::SClosing if !tcp.fin() && tcp.ack() => NatFlowStatus::SHalfClose,
            NatFlowStatus::SClosing if tcp.fin() && tcp.ack() => NatFlowStatus::LastAck,
            NatFlowStatus::SHalfClose if tcp.fin() => NatFlowStatus::LastAck,
            NatFlowStatus::LastAck if tcp.ack() => NatFlowStatus::Closed,
            _other if tcp.rst() => NatFlowStatus::Reset,
            other => other,
        },
        FlowSide::Responder => match status {
            NatFlowStatus::OneWay if tcp.syn() && tcp.ack() => NatFlowStatus::TwoWay,
            NatFlowStatus::Established if tcp.fin() => NatFlowStatus::SClosing,
            NatFlowStatus::CClosing if !tcp.fin() && tcp.ack() => NatFlowStatus::CHalfClose,
            NatFlowStatus::CClosing if tcp.fin() && tcp.ack() => NatFlowStatus::LastAck,
            NatFlowStatus::CHalfClose if tcp.fin() => NatFlowStatus::LastAck,
            NatFlowStatus::LastAck if tcp.ack() => NatFlowStatus::Closed,
            _other if tcp.rst() => NatFlowStatus::Reset,
            other => other,
        },
    }
}

/// Resolve the protocol for flow-state and timeout updates.
/// Returns `None` for non-first fragments and incomplete header chains.
pub(crate) fn transport_proto<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> Option<NextHeader> {
    packet.upper_layer_proto().carried()
}

/// Compute the next status of a flow, given its current status, the packet that hit it, and the
/// side of the connection that sent this packet. If `close_dns` is set, a UDP flow closes on the
/// first reply from a DNS server.
pub(crate) fn next_status<Buf: PacketBufferMut>(
    packet: &Packet<Buf>,
    side: FlowSide,
    status: NatFlowStatus,
    close_dns: bool,
) -> NatFlowStatus {
    // Leave the state unchanged without a resolved protocol.
    let Some(proto) = transport_proto(packet) else {
        return status;
    };

    match proto {
        NextHeader::UDP => {
            let next = next_status_udp(side, status);
            if close_dns {
                close_dns_on_reply(packet, side, next)
            } else {
                next
            }
        }
        NextHeader::ICMP | NextHeader::ICMP6 => next_status_icmp(side, status),
        NextHeader::TCP => {
            if let Some(tcp) = packet.try_tcp() {
                next_status_tcp(side, status, tcp)
            } else {
                status
            }
        }
        _ => status,
    }
}

// Close a UDP flow on the first reply from a DNS server.
//= https://www.rfc-editor.org/rfc/rfc4787#section-4.3
//# a) For specific destination ports in the well-known port range
//# (ports 0-1023), a NAT MAY have shorter UDP mapping timers that
//# are specific to the IANA-registered application running over
//# that specific destination port.
fn close_dns_on_reply<Buf: PacketBufferMut>(
    packet: &Packet<Buf>,
    side: FlowSide,
    status: NatFlowStatus,
) -> NatFlowStatus {
    if side != FlowSide::Responder {
        return status;
    }
    match packet.headers().pat().eth().net().udp().done() {
        Some((_, _, udp)) => match udp.source().as_u16() {
            53 | 853 | 8853 => NatFlowStatus::Closed, // DNS|DNS-over-quic|nextdns
            _ => status,
        },
        _ => status,
    }
}

#[cfg(test)]
mod test {
    use super::transport_proto;
    use net::buffer::TestBuffer;
    use net::headers::TryIp;
    use net::ip::NextHeader;
    use net::packet::Packet;

    #[test]
    fn a_udp_flow_behind_an_extension_header_is_still_udp() {
        const HOP_BY_HOP: u8 = 0;
        const UDP: u8 = 17;

        // One 8-octet Hop-by-Hop header (next=UDP, len=0) followed by an empty datagram.
        let ext = [UDP, 0, 1, 4, 0, 0, 0, 0];
        let udp = [0x04u8, 0xd2, 0, 53, 0, 8, 0, 0];

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]); // dst mac
        bytes.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]); // src mac
        bytes.extend_from_slice(&0x86DDu16.to_be_bytes()); // ethertype ipv6
        bytes.extend_from_slice(&[0x60, 0, 0, 0]); // version, traffic class, flow label
        #[allow(clippy::cast_possible_truncation)]
        bytes.extend_from_slice(&((ext.len() + udp.len()) as u16).to_be_bytes());
        bytes.push(HOP_BY_HOP);
        bytes.push(64); // hop limit
        bytes.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5]);
        bytes.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5]);
        bytes.extend_from_slice(&ext);
        bytes.extend_from_slice(&udp);

        let buffer = TestBuffer::from_raw_data(&bytes);
        let packet: Packet<TestBuffer> = Packet::new(buffer).unwrap_or_else(|_| unreachable!());

        assert_ne!(
            packet.try_ip().map(net::headers::Net::next_header),
            Some(NextHeader::UDP),
            "the fixture must carry an extension header, or it cannot tell the two reads apart"
        );
        assert_eq!(
            transport_proto(&packet),
            Some(NextHeader::UDP),
            "a UDP datagram behind a Hop-by-Hop header was not reported as UDP"
        );
    }
}
