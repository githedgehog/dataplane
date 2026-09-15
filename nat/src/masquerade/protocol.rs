// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Functions to represent tiny state machines for flows in the context
//! of masquerading. We currently use these to know how much to extend the lifetime of flows
//! for port conservation.

use crate::common::{NatAction, NatFlowStatus};
use crate::masquerade::contract::Requirement;
use crate::masquerade::contract::rfc4787::Req12;
use net::buffer::PacketBufferMut;
use net::headers::{TryHeaders, TryIp, TryTcp};

use net::ip::NextHeader;
use net::packet::Packet;
use net::tcp::Tcp;

impl NatFlowStatus {
    //= https://www.rfc-editor.org/rfc/rfc4787#section-4.3
    //# a) For specific destination ports in the well-known port range
    //# (ports 0-1023), a NAT MAY have shorter UDP mapping timers that
    //# are specific to the IANA-registered application running over
    //# that specific destination port.
    fn udp_status_patch_dnat<Buf: PacketBufferMut>(self, packet: &Packet<Buf>) -> NatFlowStatus {
        match packet.headers().pat().eth().net().udp().done() {
            Some((_, _, udp)) => match udp.source().as_u16() {
                53 | 853 | 8853 => NatFlowStatus::Closed, // DNS|DNS-over-quic|nextdns
                _ => self,
            },
            _ => self,
        }
    }

    // Refine the status of a UDP flow based on the application
    fn udp_status_patch<Buf: PacketBufferMut>(
        self,
        packet: &Packet<Buf>,
        action: NatAction,
    ) -> NatFlowStatus {
        match action {
            NatAction::SrcNat => self,
            NatAction::DstNat => self.udp_status_patch_dnat(packet),
        }
    }
}

fn next_flow_status_udp(action: NatAction, status: NatFlowStatus) -> NatFlowStatus {
    match action {
        NatAction::SrcNat => match status {
            NatFlowStatus::TwoWay => NatFlowStatus::Established,
            _ => status,
        },
        NatAction::DstNat => match status {
            NatFlowStatus::OneWay => NatFlowStatus::TwoWay,
            _ => status,
        },
    }
}

// No arm of this machine reaches a terminal state, so an ICMP *query* -- an Echo or its
// reply -- never ends the flow it belongs to. That is half of RFC 5382 REQ-10 and RFC 4787
// REQ-12, and it is not the half a reader assumes: an ICMP *error* does not come through
// here at all. It goes to `IcmpErrorHandler`, which does tear a one-way mapping down on a
// hard error, so neither requirement is met and neither is recorded here.
#[allow(clippy::match_single_binding)]
fn next_flow_status_icmp(action: NatAction, status: NatFlowStatus) -> NatFlowStatus {
    let next = match action {
        NatAction::SrcNat => match status {
            _ => status,
        },
        NatAction::DstNat => match status {
            NatFlowStatus::OneWay => NatFlowStatus::TwoWay,
            _ => status,
        },
    };
    if cfg!(debug_assertions)
        && let Err(violation) = Req12::new(status, next).check()
    {
        unreachable!(
            "{spec} {id}: {violation} ({action})",
            spec = Req12::SPEC,
            id = Req12::ID
        );
    }
    next
}

fn next_flow_status_tcp(action: NatAction, status: NatFlowStatus, tcp: &Tcp) -> NatFlowStatus {
    match action {
        NatAction::SrcNat => match status {
            NatFlowStatus::TwoWay if !tcp.syn() && tcp.ack() => NatFlowStatus::Established,
            NatFlowStatus::Established if tcp.fin() => NatFlowStatus::CClosing,
            NatFlowStatus::SClosing if !tcp.fin() && tcp.ack() => NatFlowStatus::SHalfClose,
            NatFlowStatus::SClosing if tcp.fin() && tcp.ack() => NatFlowStatus::LastAck,
            NatFlowStatus::SHalfClose if tcp.fin() => NatFlowStatus::LastAck,
            NatFlowStatus::LastAck if tcp.ack() => NatFlowStatus::Closed,
            _other if tcp.rst() => NatFlowStatus::Reset,
            other => other,
        },
        NatAction::DstNat => match status {
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

/// The transport protocol the packet actually carries, or `None` without an IP header.
///
/// `Net::next_header()` names the *first* header after the IP header, which for IPv6 is
/// whatever extension header the sender chose to insert. `upper_layer_proto` walks the
/// chain, fragment header included, and answers the transport; the fallback keeps the old
/// answer for a chain that ran past `MAX_NET_EXTENSIONS`.
///
/// One function rather than the same three lines at each call site: two callers deciding
/// "which protocol is this" independently is a drift waiting to happen, and the two that
/// exist have to agree for the flow a state machine advances and the flow that gets
/// refreshed to be the same flow.
pub(crate) fn transport_proto<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> Option<NextHeader> {
    packet
        .upper_layer_proto()
        .or_else(|| packet.try_ip().map(net::headers::Net::next_header))
}

// Compute the next `NatFlowStatus` of a flow, given the current, the received packet and
// the direction
pub(crate) fn next_flow_status<Buf: PacketBufferMut>(
    packet: &Packet<Buf>,
    action: NatAction,     // action of the flow hit
    status: NatFlowStatus, // current status
) -> NatFlowStatus {
    // A packet without an IP header should not make it here.
    let proto = transport_proto(packet).unwrap_or_else(|| unreachable!());

    match proto {
        NextHeader::UDP => next_flow_status_udp(action, status).udp_status_patch(packet, action),
        NextHeader::ICMP | NextHeader::ICMP6 => next_flow_status_icmp(action, status),
        NextHeader::TCP => {
            if let Some(tcp) = packet.try_tcp() {
                next_flow_status_tcp(action, status, tcp)
            } else {
                status
            }
        }
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

    /// The two masquerade callers must read the transport from the same place.
    ///
    /// For IPv6 the IP header's next-header field names the first *extension* header, and
    /// the sender chooses whether to insert one. `next_flow_status` walks the chain and
    /// `refreshes_while_unanswered` used to read the raw field, so a UDP flow behind a
    /// single Hop-by-Hop header advanced the UDP state machine and then refreshed nothing
    /// while unanswered -- the mapping expired at the one-way timeout no matter how much
    /// the sender sent. Both ask `transport_proto` now; this pins what it must answer.
    ///
    /// Assembled from octets rather than through the header builder because the builder's
    /// buffer API is a moving target across this series and the wire format is not.
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
