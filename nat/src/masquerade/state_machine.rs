// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![cfg(test)]

use crate::common::{NatAction, NatFlowStatus};
use crate::masquerade::contract::rfc4787::Req12;
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

/// A second copy of [`next_flow_status_tcp`]'s table, arm for arm.
///
/// Be clear about what the test below it is worth: this is a **regression lock, not an
/// oracle**. It restates the implementation rather than deriving the answer from anything
/// independent, so it cannot tell you the table is *right* -- only that it has not changed
/// without someone editing both copies. In particular it blesses two behaviours that fall out
/// of arm ordering rather than intent: a RST arriving in `LastAck` alongside an ACK is read as
/// a clean close (`Closed`) because the `LastAck if ack` arm precedes the catch-all
/// `_ if rst`, and a RST arriving in `Closed` reopens it as `Reset`.
///
/// The claims with real content are the ones that do not transcribe anything:
/// [`a_segment_with_no_flags_moves_nothing`], [`reset_and_closed_absorb`],
/// [`the_tcp_lifecycle_never_runs_backwards`] and
/// [`each_direction_owns_its_half_of_the_close`]. A transposition of the client and server
/// close arms, for instance, is invisible here and caught there.
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

/// Exhaustive over all 320 (direction, status, flag) triples -- but against a transcription,
/// so read it as a change detector. See [`expected_tcp`].
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

//= https://www.rfc-editor.org/rfc/rfc5382#section-8
//= type=test
//# REQ-10:  Receipt of any sort of ICMP message MUST NOT terminate the
//# NAT mapping or TCP connection for which the ICMP was generated.
//= https://www.rfc-editor.org/rfc/rfc4787#section-9
//= type=test
//# REQ-12:  Receipt of any sort of ICMP message MUST NOT terminate the
//# NAT mapping.
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
        for action in [NatAction::SrcNat, NatAction::DstNat] {
            let next = next_flow_status(&packet, action, status);
            assert_eq!(
                Req12::new(status, next).check(),
                Ok(()),
                "{action} icmp packet terminated a flow in {status:?}"
            );
            if action == NatAction::DstNat && status == NatFlowStatus::OneWay {
                continue;
            }
            assert_eq!(
                next, status,
                "an {action} icmp packet moved a flow in {status:?}"
            );
        }
    }
}

/// Where each status sits in the connection's life, which is deliberately *not* the enum's
/// discriminant order -- `Reset` is 3, between `Established` and `CClosing`. Writing the order
/// out by hand is the point: it states the shape the machine is meant to have instead of
/// reading that shape back out of the type it is testing.
fn rank(status: NatFlowStatus) -> u8 {
    use NatFlowStatus as S;
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

/// A connection only ever moves further through its life, never back towards being open.
///
/// Independent of the transition table: it constrains the table's shape rather than repeating
/// its contents, so it catches an arm that sends a closing flow back to `Established` -- which
/// a transcription of that same arm would happily agree with.
#[test]
fn the_tcp_lifecycle_never_runs_backwards() {
    for action in [NatAction::SrcNat, NatAction::DstNat] {
        for status in STATUSES {
            for bits in 0..16u8 {
                let flags = Flags::from_bits(bits);
                let got = next_flow_status(&tcp_packet(flags), action, status);
                assert!(
                    rank(got) >= rank(status),
                    "{action} from {status:?} with {flags:?} went backwards to {got:?}"
                );
            }
        }
    }
}

/// Neither direction invents the other's half of the close.
///
/// `SrcNat` carries the client's segments, so it may reach the data phase, start the client's
/// close and acknowledge the server's; it must never be the thing that produces the server's
/// closing states. `DstNat` is the mirror. A transposition of the two close arms leaves the
/// machine self-consistent and passes a transcription, and fails here.
#[test]
fn each_direction_owns_its_half_of_the_close() {
    use NatFlowStatus as S;
    for status in STATUSES {
        for bits in 0..16u8 {
            let flags = Flags::from_bits(bits);

            let got = next_flow_status(&tcp_packet(flags), NatAction::SrcNat, status);
            if got != status {
                assert!(
                    !matches!(got, S::OneWay | S::TwoWay | S::SClosing | S::CHalfClose),
                    "SrcNat from {status:?} with {flags:?} produced {got:?}, which belongs to \
                     the server's side of the close"
                );
            }

            let got = next_flow_status(&tcp_packet(flags), NatAction::DstNat, status);
            if got != status {
                assert!(
                    !matches!(
                        got,
                        S::OneWay | S::Established | S::CClosing | S::SHalfClose
                    ),
                    "DstNat from {status:?} with {flags:?} produced {got:?}, which belongs to \
                     the client's side of the close"
                );
            }
        }
    }
}
