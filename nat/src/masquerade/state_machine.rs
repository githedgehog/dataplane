// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The masquerade flow state machine, exhaustively.
//!
//! [`next_flow_status`] decides how a masqueraded connection is progressing: whether it is still
//! opening, established, half-closed, or done. Nothing forwards differently because of it, but the
//! flow's *lifetime* follows from it, and a public address and port are held for as long as the
//! flow lives. A machine that never reaches `Closed` conserves nothing; one that reaches it early
//! releases a tuple another tenant can be handed while the connection is still running -- the
//! failure this branch already fixed once, from the other end.
//!
//! # Why exhaustive rather than drawn
//!
//! The whole input space is 2 actions * 10 statuses * 16 flag combinations = 320 cases for TCP.
//! Sampling that would be perverse: it is small enough to enumerate, and enumeration makes the
//! coverage argument disappear entirely.
//!
//! # Why a table rather than metamorphic relations
//!
//! Elsewhere on this branch the properties avoid restating the implementation, because an oracle
//! that mirrors the code mirrors its bugs. That objection has teeth when the oracle would grow into
//! a second dataplane. Here the "oracle" is the TCP close sequence, which is older than this
//! codebase and will outlive it, so writing it down is specification rather than duplication.
//!
//! The table below is derived from what the flags *mean*, not from what the code does. Where the
//! two disagree the table is what should be argued about.
//!
//! # What this was for
//!
//! `cargo-mutants` found 23 surviving mutants in `protocol.rs` -- very nearly every match guard in
//! `next_flow_status_tcp`, plus the DNS arm of the UDP patch. There were already four TCP tests
//! (`test_masquerade_tcp_establish`, `_reset`, and both close directions); they walk a sequence and
//! check where it ends up, so they never discriminate *which* guard fired. Replacing a guard with
//! `true` left all of them passing.

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

/// Every status the machine can be in.
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

/// The four flags the machine reads, as a bitmask over `syn ack fin rst`.
///
/// Four bools rather than a bitfield on purpose: the table below reads as the close sequence when
/// the flags are named, and as arithmetic when they are not.
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

/// What the TCP close sequence says should happen, written from the flags rather than the code.
///
/// `SrcNat` is a segment from the private side (the client), `DstNat` one from the public side
/// (the server). `C`/`S` in the status names are the side that began the close.
/// The arms are deliberately not collapsed even where two share a body: each states one step of
/// the close sequence, and merging them by outcome would make the sequence unreadable.
#[allow(clippy::match_same_arms)]
fn expected_tcp(action: NatAction, status: NatFlowStatus, f: Flags) -> NatFlowStatus {
    use NatFlowStatus as S;
    let progressed = match (action, status) {
        // The client's first non-SYN acknowledgement completes the handshake.
        (NatAction::SrcNat, S::TwoWay) if !f.syn && f.ack => Some(S::Established),
        // The server's SYN-ACK answers the client's SYN.
        (NatAction::DstNat, S::OneWay) if f.syn && f.ack => Some(S::TwoWay),

        // Whoever sends the first FIN names the closing side.
        (NatAction::SrcNat, S::Established) if f.fin => Some(S::CClosing),
        (NatAction::DstNat, S::Established) if f.fin => Some(S::SClosing),

        // The other side acknowledges the FIN without sending its own: half closed.
        (NatAction::SrcNat, S::SClosing) if !f.fin && f.ack => Some(S::SHalfClose),
        (NatAction::DstNat, S::CClosing) if !f.fin && f.ack => Some(S::CHalfClose),

        // Or acknowledges and closes in the same segment, which skips the half-close.
        (NatAction::SrcNat, S::SClosing) if f.fin && f.ack => Some(S::LastAck),
        (NatAction::DstNat, S::CClosing) if f.fin && f.ack => Some(S::LastAck),

        // The half-closed side finally sends its own FIN.
        (NatAction::SrcNat, S::SHalfClose) if f.fin => Some(S::LastAck),
        (NatAction::DstNat, S::CHalfClose) if f.fin => Some(S::LastAck),

        // And the last acknowledgement finishes it.
        (_, S::LastAck) if f.ack => Some(S::Closed),

        _ => None,
    };

    // A reset ends the connection, but only where no more specific transition applied: a segment
    // carrying both FIN and RST is a close, not an abort.
    match progressed {
        Some(next) => next,
        None if f.rst => S::Reset,
        None => status,
    }
}

/// Every TCP transition, for every status and every flag combination.
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

/// A status only ever moves when a flag asks it to.
///
/// Stated separately from the table because it is the property a guard replaced by `true`
/// violates, and it should be readable without checking the table row by row: a segment carrying
/// none of the four flags is not evidence of anything, and must leave the connection where it was.
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

/// A reset ends a connection that had nowhere else to go, and `Closed` stays closed.
///
/// The absorbing states are what stop a flow from being kept alive indefinitely by stray traffic
/// after it is over, which is the whole point of tracking status for port conservation.
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
        // Closed is absorbing except that a reset re-labels it, which is harmless: both are
        // terminal and both release the tuple.
        let packet = tcp_packet(rst);
        assert_eq!(
            next_flow_status(&packet, action, NatFlowStatus::Closed),
            NatFlowStatus::Reset
        );
    }
}

/// A UDP answer from a resolver closes the flow immediately.
///
/// DNS is a single request and a single reply over a port that is then never used again. Holding
/// the tuple for the ordinary UDP lifetime would tie up a public port per lookup, which on a busy
/// gateway is most of them. The ports are plain DNS, DNS-over-QUIC, and the one `NextDNS` uses.
#[test]
fn a_reply_from_a_resolver_closes_the_flow_at_once() {
    for source_port in [53u16, 853, 8853] {
        let packet = udp_packet(source_port);
        assert_eq!(
            next_flow_status(&packet, NatAction::DstNat, NatFlowStatus::OneWay),
            NatFlowStatus::Closed,
            "a reply from port {source_port} should close the flow"
        );
        // Only inbound: a request *to* a resolver is an ordinary flow.
        assert_eq!(
            next_flow_status(&packet, NatAction::SrcNat, NatFlowStatus::TwoWay),
            NatFlowStatus::Established,
            "an outbound packet must not be closed by its own source port"
        );
    }
}

/// Ordinary UDP opens in two steps and then stays put.
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
//
//= https://www.rfc-editor.org/rfc/rfc4787#section-9
//= type=test
//# REQ-12:  Receipt of any sort of ICMP message MUST NOT terminate the
//# NAT mapping.
/// An ICMP echo reply makes a one-way flow two-way, and nothing else moves.
///
/// ICMP has no flags to read and no close sequence, so the only evidence available is that a packet
/// came back the other way. That single transition is what keeps a ping's flow -- and the public
/// address it holds -- alive for the round trip and no longer.
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

    // Every other status, in both directions, is left exactly where it was: there is no further
    // evidence an icmp exchange can offer.
    //
    // The `Req12` call is the requirement; the `assert_eq!` around it is the stronger local claim
    // that nothing moves at all. Both are wanted -- the requirement is what a reviewer checks
    // against the RFC, and it is the same predicate `next_flow_status_icmp` asserts, so neither
    // can drift from the other without this test failing.
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
