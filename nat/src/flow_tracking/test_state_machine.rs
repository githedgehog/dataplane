// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![cfg(test)]

use super::{FlowSide, next_status};
use net::buffer::TestBuffer;
use net::flows::ConnState;
use net::headers::TryTcpMut;
use net::packet::Packet;
use net::packet::test_utils::{
    IcmpEchoDirection, build_test_icmp4_echo, build_test_tcp_ipv4_packet,
    build_test_udp_ipv4_packet,
};

const STATUSES: [ConnState; 10] = [
    ConnState::OneWay,
    ConnState::TwoWay,
    ConnState::Established,
    ConnState::Reset,
    ConnState::CClosing,
    ConnState::SClosing,
    ConnState::CHalfClose,
    ConnState::SHalfClose,
    ConnState::LastAck,
    ConnState::Closed,
];

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Flags {
    syn: bool,
    ack: bool,
    fin: bool,
    rst: bool,
}

impl Flags {
    fn from_bits(bits: u8) -> Self {
        Self {
            syn: bits & 0b1000 != 0,
            ack: bits & 0b0100 != 0,
            fin: bits & 0b0010 != 0,
            rst: bits & 0b0001 != 0,
        }
    }
}

fn tcp_packet(flags: Flags) -> Packet<TestBuffer> {
    let mut packet = build_test_tcp_ipv4_packet("1.1.1.1", "2.2.2.2", 1024, 80);
    {
        let tcp = packet.try_tcp_mut().unwrap_or_else(|| unreachable!());
        tcp.set_syn(flags.syn);
        tcp.set_ack(flags.ack);
        tcp.set_fin(flags.fin);
        tcp.set_rst(flags.rst);
    }
    packet
}

fn udp_packet(source_port: u16) -> Packet<TestBuffer> {
    build_test_udp_ipv4_packet("1.1.1.1", "2.2.2.2", source_port, 80)
}

#[allow(clippy::match_same_arms)]
fn expected_tcp(side: FlowSide, status: ConnState, f: Flags) -> ConnState {
    use ConnState as S;
    let progressed = match (side, status) {
        (FlowSide::Initiator, S::TwoWay) if !f.syn && f.ack => Some(S::Established),
        (FlowSide::Responder, S::OneWay) if f.syn && f.ack => Some(S::TwoWay),

        (FlowSide::Initiator, S::Established) if f.fin => Some(S::CClosing),
        (FlowSide::Responder, S::Established) if f.fin => Some(S::SClosing),

        (FlowSide::Initiator, S::SClosing) if !f.fin && f.ack => Some(S::SHalfClose),
        (FlowSide::Responder, S::CClosing) if !f.fin && f.ack => Some(S::CHalfClose),

        (FlowSide::Initiator, S::SClosing) if f.fin && f.ack => Some(S::LastAck),
        (FlowSide::Responder, S::CClosing) if f.fin && f.ack => Some(S::LastAck),

        (FlowSide::Initiator, S::SHalfClose) if f.fin => Some(S::LastAck),
        (FlowSide::Responder, S::CHalfClose) if f.fin => Some(S::LastAck),

        (_, S::LastAck) if f.ack => Some(S::Closed),

        _ => None,
    };

    match progressed {
        Some(next) => next,
        None if f.rst => S::Reset,
        None => status,
    }
}

#[test]
#[cfg_attr(miri, ignore = "the full close sequence is 69s under miri")]
fn the_tcp_state_machine_follows_the_close_sequence() {
    for side in [FlowSide::Initiator, FlowSide::Responder] {
        for status in STATUSES {
            for bits in 0..16u8 {
                let flags = Flags::from_bits(bits);
                let packet = tcp_packet(flags);
                let got = next_status(&packet, side, status);
                let want = expected_tcp(side, status, flags);
                assert_eq!(
                    got, want,
                    "{side} from {status:?} with {flags:?}: expected {want:?}, got {got:?}"
                );
            }
        }
    }
}

#[test]
fn a_segment_with_no_flags_moves_nothing() {
    let bare = Flags {
        syn: false,
        ack: false,
        fin: false,
        rst: false,
    };
    for side in [FlowSide::Initiator, FlowSide::Responder] {
        for status in STATUSES {
            let packet = tcp_packet(bare);
            assert_eq!(
                next_status(&packet, side, status),
                status,
                "{side} from {status:?} moved on a segment with no flags set"
            );
        }
    }
}

#[test]
fn reset_and_closed_absorb() {
    let rst = Flags {
        syn: false,
        ack: false,
        fin: false,
        rst: true,
    };
    for side in [FlowSide::Initiator, FlowSide::Responder] {
        for bits in 0..16u8 {
            let packet = tcp_packet(Flags::from_bits(bits));
            assert_eq!(
                next_status(&packet, side, ConnState::Reset),
                ConnState::Reset,
                "a reset connection was revived"
            );
        }
        let packet = tcp_packet(rst);
        assert_eq!(
            next_status(&packet, side, ConnState::Closed),
            ConnState::Reset
        );
    }
}

#[test]
fn ordinary_udp_opens_and_settles() {
    let packet = udp_packet(12345);
    assert_eq!(
        next_status(&packet, FlowSide::Responder, ConnState::OneWay),
        ConnState::TwoWay,
        "a reply makes a one-way flow two-way"
    );
    assert_eq!(
        next_status(&packet, FlowSide::Initiator, ConnState::TwoWay),
        ConnState::Established,
        "and the next outbound packet establishes it"
    );
    for status in [ConnState::Established, ConnState::Closed] {
        assert_eq!(
            next_status(&packet, FlowSide::Initiator, status),
            status,
            "an established or closed udp flow does not move outbound"
        );
    }
}

// This tests Echo Reply transitions. RFC 5382 REQ-10 and RFC 4787 REQ-12 also cover
// ICMP errors, which go through `icmp_handler::nf`. This test alone cannot verify
// either requirement.
#[test]
fn an_icmp_reply_makes_a_flow_two_way_and_nothing_more() {
    let packet = build_test_icmp4_echo(
        "1.1.1.1".parse().unwrap_or_else(|_| unreachable!()),
        "2.2.2.2".parse().unwrap_or_else(|_| unreachable!()),
        1,
        IcmpEchoDirection::Reply,
    )
    .unwrap_or_else(|_| unreachable!());

    assert_eq!(
        next_status(&packet, FlowSide::Responder, ConnState::OneWay),
        ConnState::TwoWay,
        "a reply must answer the request"
    );

    for status in STATUSES {
        for side in [FlowSide::Initiator, FlowSide::Responder] {
            let next = next_status(&packet, side, status);
            if side == FlowSide::Responder && status == ConnState::OneWay {
                continue;
            }
            assert_eq!(
                next, status,
                "an icmp packet from the {side} moved a flow in {status:?}"
            );
        }
    }
}

fn rank(status: ConnState) -> u8 {
    use ConnState as S;
    match status {
        S::OneWay => 0,
        S::TwoWay => 1,
        S::Established => 2,
        S::CClosing | S::SClosing => 3,
        S::CHalfClose | S::SHalfClose => 4,
        S::LastAck => 5,
        S::Closed => 6,
        S::Reset => 7,
    }
}

#[test]
fn the_tcp_lifecycle_never_runs_backwards() {
    for side in [FlowSide::Initiator, FlowSide::Responder] {
        for status in STATUSES {
            for bits in 0..16u8 {
                let flags = Flags::from_bits(bits);
                let got = next_status(&tcp_packet(flags), side, status);
                assert!(
                    rank(got) >= rank(status),
                    "{side} from {status:?} with {flags:?} went backwards to {got:?}"
                );
            }
        }
    }
}

#[test]
fn each_direction_owns_its_half_of_the_close() {
    use ConnState as S;
    for status in STATUSES {
        for bits in 0..16u8 {
            let flags = Flags::from_bits(bits);

            let got = next_status(&tcp_packet(flags), FlowSide::Initiator, status);
            if got != status {
                assert!(
                    !matches!(got, S::OneWay | S::TwoWay | S::SClosing | S::CHalfClose),
                    "initiator from {status:?} with {flags:?} produced {got:?}, which belongs to \
                     the server's side of the close"
                );
            }

            let got = next_status(&tcp_packet(flags), FlowSide::Responder, status);
            if got != status {
                assert!(
                    !matches!(
                        got,
                        S::OneWay | S::Established | S::CClosing | S::SHalfClose
                    ),
                    "responder from {status:?} with {flags:?} produced {got:?}, which belongs to \
                     the client's side of the close"
                );
            }
        }
    }
}

#[test]
fn a_reply_from_a_resolver_closes_the_flow_at_once() {
    let source_port = 53u16;
    let packet = udp_packet(source_port);
    assert_eq!(
        next_status(&packet, FlowSide::Responder, ConnState::OneWay),
        ConnState::Closed,
        "a reply from port {source_port} should close the flow"
    );
    assert_eq!(
        next_status(&packet, FlowSide::Initiator, ConnState::TwoWay),
        ConnState::Established,
        "an outbound packet must not be closed by its own source port"
    );
}
