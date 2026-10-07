// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Small state machines for tracked flows. We use them to know how much to extend the lifetime
//! of flows.

use super::{ConnState, FlowSide};
use crate::buffer::PacketBufferMut;
use crate::headers::{TryHeaders, TryTcp};
use crate::ip::NextHeader;
use crate::packet::Packet;
use crate::tcp::Tcp;

fn next_status_udp(side: FlowSide, status: ConnState) -> ConnState {
    match side {
        FlowSide::Initiator => match status {
            ConnState::TwoWay => ConnState::Established,
            _ => status,
        },
        FlowSide::Responder => match status {
            ConnState::OneWay => ConnState::TwoWay,
            _ => status,
        },
    }
}

// Echo requests and replies never terminate a flow here. ICMP errors go through
// `IcmpErrorHandler`, which can remove a one-way mapping on a hard error. RFC 5382
// REQ-10 and RFC 4787 REQ-12 cover errors too, so this function cannot establish
// compliance with either requirement.
#[allow(clippy::match_single_binding)]
fn next_status_icmp(side: FlowSide, status: ConnState) -> ConnState {
    let next = match side {
        FlowSide::Initiator => match status {
            _ => status,
        },
        FlowSide::Responder => match status {
            ConnState::OneWay => ConnState::TwoWay,
            _ => status,
        },
    };
    if cfg!(debug_assertions)
        && matches!(next, ConnState::Closed | ConnState::Reset)
        && !matches!(status, ConnState::Closed | ConnState::Reset)
    {
        unreachable!("an ICMP query moved a live flow from {status:?} to {next:?} ({side})");
    }
    next
}

// Note: RST only applies when no other arm matches. For example, RST+ACK from the initiator in
// TwoWay moves the flow to Established, not to Reset.
fn next_status_tcp(side: FlowSide, status: ConnState, tcp: &Tcp) -> ConnState {
    match side {
        FlowSide::Initiator => match status {
            ConnState::TwoWay if !tcp.syn() && tcp.ack() => ConnState::Established,
            ConnState::Established if tcp.fin() => ConnState::CClosing,
            ConnState::SClosing if !tcp.fin() && tcp.ack() => ConnState::SHalfClose,
            ConnState::SClosing if tcp.fin() && tcp.ack() => ConnState::LastAck,
            ConnState::SHalfClose if tcp.fin() => ConnState::LastAck,
            ConnState::LastAck if tcp.ack() => ConnState::Closed,
            _other if tcp.rst() => ConnState::Reset,
            other => other,
        },
        FlowSide::Responder => match status {
            ConnState::OneWay if tcp.syn() && tcp.ack() => ConnState::TwoWay,
            ConnState::Established if tcp.fin() => ConnState::SClosing,
            ConnState::CClosing if !tcp.fin() && tcp.ack() => ConnState::CHalfClose,
            ConnState::CClosing if tcp.fin() && tcp.ack() => ConnState::LastAck,
            ConnState::CHalfClose if tcp.fin() => ConnState::LastAck,
            ConnState::LastAck if tcp.ack() => ConnState::Closed,
            _other if tcp.rst() => ConnState::Reset,
            other => other,
        },
    }
}

/// Resolve the protocol for flow-state and timeout updates.
/// Returns `None` for non-first fragments and incomplete header chains.
pub fn transport_proto<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> Option<NextHeader> {
    packet.upper_layer_proto().carried()
}

/// Compute the next status of a flow, given its current status, the packet that hit it, and the
/// side of the connection that sent this packet. A UDP flow closes on the first reply from a DNS
/// server.
pub fn next_status<Buf: PacketBufferMut>(
    packet: &Packet<Buf>,
    side: FlowSide,
    status: ConnState,
) -> ConnState {
    // Leave the state unchanged without a resolved protocol.
    let Some(proto) = transport_proto(packet) else {
        return status;
    };

    match proto {
        NextHeader::UDP => close_dns_on_reply(packet, side, next_status_udp(side, status)),
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
    status: ConnState,
) -> ConnState {
    if side != FlowSide::Responder {
        return status;
    }
    match packet.headers().pat().eth().net().udp().done() {
        Some((_, _, udp)) => match udp.source().as_u16() {
            53 => ConnState::Closed, // DNS
            _ => status,
        },
        _ => status,
    }
}

#[cfg(test)]
mod test {
    use super::transport_proto;
    use crate::buffer::TestBuffer;
    use crate::headers::TryIp;
    use crate::ip::NextHeader;
    use crate::packet::Packet;

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
            packet.try_ip().map(crate::headers::Net::next_header),
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
