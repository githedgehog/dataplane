// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![cfg(test)]

use crate::common::{NatAction, NatFlowStatus};
use crate::masquerade::protocol::next_flow_status;
use net::buffer::TestBuffer;
use net::headers::TryTcpMut;
use net::packet::Packet;
use net::packet::test_utils::{
    IcmpEchoDirection, build_test_icmp4_echo, build_test_tcp_ipv4_packet,
    build_test_udp_ipv4_packet,
};

const STATUSES: [NatFlowStatus; 10] = [
    NatFlowStatus::OneWay,
    NatFlowStatus::TwoWay,
    NatFlowStatus::Established,
    NatFlowStatus::Reset,
    NatFlowStatus::CClosing,
    NatFlowStatus::SClosing,
    NatFlowStatus::CHalfClose,
    NatFlowStatus::SHalfClose,
    NatFlowStatus::LastAck,
    NatFlowStatus::Closed,
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
fn expected_tcp(action: NatAction, status: NatFlowStatus, f: Flags) -> NatFlowStatus {
    use NatFlowStatus as S;
    let progressed = match (action, status) {
        (NatAction::SrcNat, S::TwoWay) if !f.syn && f.ack => Some(S::Established),
        (NatAction::DstNat, S::OneWay) if f.syn && f.ack => Some(S::TwoWay),

        (NatAction::SrcNat, S::Established) if f.fin => Some(S::CClosing),
        (NatAction::DstNat, S::Established) if f.fin => Some(S::SClosing),

        (NatAction::SrcNat, S::SClosing) if !f.fin && f.ack => Some(S::SHalfClose),
        (NatAction::DstNat, S::CClosing) if !f.fin && f.ack => Some(S::CHalfClose),

        (NatAction::SrcNat, S::SClosing) if f.fin && f.ack => Some(S::LastAck),
        (NatAction::DstNat, S::CClosing) if f.fin && f.ack => Some(S::LastAck),

        (NatAction::SrcNat, S::SHalfClose) if f.fin => Some(S::LastAck),
        (NatAction::DstNat, S::CHalfClose) if f.fin => Some(S::LastAck),

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
fn the_tcp_state_machine_follows_the_close_sequence() {
    for action in [NatAction::SrcNat, NatAction::DstNat] {
        for status in STATUSES {
            for bits in 0..16u8 {
                let flags = Flags::from_bits(bits);
                let packet = tcp_packet(flags);
                let got = next_flow_status(&packet, action, status);
                let want = expected_tcp(action, status, flags);
                assert_eq!(
                    got, want,
                    "{action} from {status:?} with {flags:?}: expected {want:?}, got {got:?}"
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
    for action in [NatAction::SrcNat, NatAction::DstNat] {
        for status in STATUSES {
            let packet = tcp_packet(bare);
            assert_eq!(
                next_flow_status(&packet, action, status),
                status,
                "{action} from {status:?} moved on a segment with no flags set"
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
    for action in [NatAction::SrcNat, NatAction::DstNat] {
        for bits in 0..16u8 {
            let packet = tcp_packet(Flags::from_bits(bits));
            assert_eq!(
                next_flow_status(&packet, action, NatFlowStatus::Reset),
                NatFlowStatus::Reset,
                "a reset connection was revived"
            );
        }
        let packet = tcp_packet(rst);
        assert_eq!(
            next_flow_status(&packet, action, NatFlowStatus::Closed),
            NatFlowStatus::Reset
        );
    }
}

#[test]
fn a_reply_from_a_resolver_closes_the_flow_at_once() {
    for source_port in [53u16, 853, 8853] {
        let packet = udp_packet(source_port);
        assert_eq!(
            next_flow_status(&packet, NatAction::DstNat, NatFlowStatus::OneWay),
            NatFlowStatus::Closed,
            "a reply from port {source_port} should close the flow"
        );
        assert_eq!(
            next_flow_status(&packet, NatAction::SrcNat, NatFlowStatus::TwoWay),
            NatFlowStatus::Established,
            "an outbound packet must not be closed by its own source port"
        );
    }
}

#[test]
fn ordinary_udp_opens_and_settles() {
    let packet = udp_packet(12345);
    assert_eq!(
        next_flow_status(&packet, NatAction::DstNat, NatFlowStatus::OneWay),
        NatFlowStatus::TwoWay,
        "a reply makes a one-way flow two-way"
    );
    assert_eq!(
        next_flow_status(&packet, NatAction::SrcNat, NatFlowStatus::TwoWay),
        NatFlowStatus::Established,
        "and the next outbound packet establishes it"
    );
    for status in [NatFlowStatus::Established, NatFlowStatus::Closed] {
        assert_eq!(
            next_flow_status(&packet, NatAction::SrcNat, status),
            status,
            "an established or closed udp flow does not move outbound"
        );
    }
}

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
        next_flow_status(&packet, NatAction::DstNat, NatFlowStatus::OneWay),
        NatFlowStatus::TwoWay,
        "a reply must answer the request"
    );

    for status in STATUSES {
        assert_eq!(
            next_flow_status(&packet, NatAction::SrcNat, status),
            status,
            "an outbound icmp packet moved a flow in {status:?}"
        );
        if status != NatFlowStatus::OneWay {
            assert_eq!(
                next_flow_status(&packet, NatAction::DstNat, status),
                status,
                "an inbound icmp packet moved a flow in {status:?}"
            );
        }
    }
}
