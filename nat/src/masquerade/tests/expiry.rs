// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![cfg(test)]

use super::probe::{Arrival, Fabric, run};
use crate::Masquerade;
use crate::static_nat::probe::build;
use clock::Duration;
use clock::virtual_time::advance;
use config::external::overlay::vpcpeering::VpcExpose;
use config::external::overlay::vpcpeering::contract::{LOCAL_VNI, REMOTE_VNI};
use flow_entry::flow_table::FlowLookup;
use net::buffer::TestBuffer;
use net::packet::Packet;
use net::tcp::TcpFlags;
use net::vxlan::Vni;
use std::net::IpAddr;

const ONEWAY: u64 = crate::Masquerade::MASQUERADE_ONEWAY_TIMEOUT.as_secs();

const PAST_EXPIRY: Duration = Duration::from_secs(ONEWAY * 6);

// A second, scaled like the flow timeouts: well within a one-way UDP flow's lifetime.
const WITHIN_LIFETIME: Duration = Duration::from_secs(crate::common::TIMEOUT_SCALE);

const NEARLY_ESTABLISHED: Duration = Duration::from_secs(100);

const REFRESHED_FOR: Duration = Duration::from_secs(30);

const LONG_SILENCE: Duration =
    crate::masquerade::apalloc::DEFAULT_MASQUERADE_IDLE_TIMEOUT.saturating_mul(2);

fn vni(raw: u32) -> Vni {
    Vni::new_checked(raw).unwrap_or_else(|_| unreachable!())
}

/// Let `by` pass, then expire what is due, as the worker's poll loop would.
async fn pass(masq: &Masquerade, by: Duration) {
    advance(by).await;
    masq.flows().expire_all(clock::now());
}

fn with_paused_clock<F: Future<Output = ()>>(body: impl FnOnce() -> F) {
    clock::virtual_time::Paused::new().block_on(body());
}

fn fabric() -> (Fabric, Vec<VpcExpose>) {
    let exposes = vec![
        VpcExpose::empty()
            .make_masquerade(None)
            .unwrap_or_else(|e| unreachable!("{e}"))
            .ip(lpm::prefix::PrefixWithOptionalPorts::new(
                "10.0.0.0/24".parse().unwrap_or_else(|_| unreachable!()),
                None,
            ))
            .as_range(lpm::prefix::PrefixWithOptionalPorts::new(
                "172.16.0.0/24".parse().unwrap_or_else(|_| unreachable!()),
                None,
            ))
            .unwrap_or_else(|e| unreachable!("{e}")),
    ];
    let fabric = Fabric::build(&exposes).unwrap_or_else(|| unreachable!("a fixed expose builds"));
    (fabric, exposes)
}

fn open_flow(
    lookup: &mut FlowLookup,
    masq: &mut Masquerade,
    source: IpAddr,
    peer: IpAddr,
    sport: u16,
) -> Option<(IpAddr, u16)> {
    let mut packet = build(source, peer, false, sport, 80);
    Arrival::outbound().stamp(&mut packet);
    let out = run(lookup, masq, vec![packet], Some(vni(REMOTE_VNI)));
    if out[0].is_done() {
        return None;
    }
    let addr = out[0].ip_source()?;
    let port = out[0].transport_src_port()?.get();
    (addr != source).then_some((addr, port))
}

fn reply_to(
    lookup: &mut FlowLookup,
    masq: &mut Masquerade,
    peer: IpAddr,
    translated: (IpAddr, u16),
) -> Option<IpAddr> {
    let mut packet = build(peer, translated.0, false, 80, translated.1);
    Arrival::inbound().stamp(&mut packet);
    let out: Vec<Packet<TestBuffer>> = run(lookup, masq, vec![packet], Some(vni(LOCAL_VNI)));
    (!out[0].is_done())
        .then(|| out[0].ip_destination())
        .flatten()
}

//= https://www.rfc-editor.org/rfc/rfc4787#section-8
//= type=exception
//= reason=the pool spills a host onto a second public address at a port-capacity boundary, so the mapping behaviour under exhaustion is not the behaviour before it; measured here
//# REQ-11:  A NAT MUST have deterministic behavior, i.e., it MUST NOT
//# change the NAT translation (Section 4) or the Filtering
//# (Section 5) Behavior at any point in time, or under any particular
//# conditions.
#[test]
#[cfg_attr(miri, ignore = "the 65k-session pool walk is too slow under miri")]
fn pool_exhaustion_splits_a_host_across_public_addresses() {
    use std::collections::{BTreeMap, BTreeSet};
    with_paused_clock(|| async {
        let (fabric, _) = fabric();
        let (mut lookup, mut masq) = fabric.stages();
        let peer = fabric.peer[0];
        let mut given: BTreeMap<IpAddr, BTreeSet<IpAddr>> = BTreeMap::new();

        for sport in 1024..1024 + 256u16 {
            for host in 1..=254u16 {
                let source: IpAddr = format!("10.0.0.{host}")
                    .parse()
                    .unwrap_or_else(|_| unreachable!());
                if let Some((public, _)) = open_flow(&mut lookup, &mut masq, source, peer, sport) {
                    given.entry(source).or_default().insert(public);
                }
            }
        }

        let publics: BTreeSet<_> = given.values().flatten().copied().collect();
        let split = given.values().filter(|a| a.len() > 1).count();
        println!(
            "{} hosts, {} public addresses in use, {split} hosts split",
            given.len(),
            publics.len()
        );
        assert!(
            publics.len() > 1,
            "the pool never spilled to a second address, so this measured nothing about pairing"
        );
        assert_eq!(
            split,
            given.len(),
            "some host kept a single public address across the spill. If pooling has been made \
             Paired, delete this test and the REQ-2 and REQ-11 exceptions it is named by"
        );
    });
}

fn inbound_from(
    lookup: &mut FlowLookup,
    masq: &mut Masquerade,
    from: IpAddr,
    sport: u16,
    translated: (IpAddr, u16),
) -> bool {
    let mut packet = build(from, translated.0, false, sport, translated.1);
    Arrival::inbound().stamp(&mut packet);
    let out: Vec<Packet<TestBuffer>> = run(lookup, masq, vec![packet], Some(vni(LOCAL_VNI)));
    !out[0].is_done()
}

//= https://www.rfc-editor.org/rfc/rfc4787#section-5
//= type=todo
//# REQ-8:  If application transparency is most important, it is
//# RECOMMENDED that a NAT have an "Endpoint-Independent Filtering"
//# behavior.  If a more stringent filtering behavior is most
//# important, it is RECOMMENDED that a NAT have an "Address-Dependent
//# Filtering" behavior.
#[test]
fn only_the_endpoint_a_flow_addressed_can_reply() {
    with_paused_clock(|| async {
        let (fabric, _) = fabric();
        let (mut lookup, mut masq) = fabric.stages();
        let peer = fabric.peer[0];
        let elsewhere = *fabric
            .peer
            .iter()
            .find(|a| **a != peer)
            .unwrap_or_else(|| unreachable!("the fixture offers two peer addresses"));
        let source: IpAddr = "10.0.0.7".parse().unwrap_or_else(|_| unreachable!());

        let translated = open_flow(&mut lookup, &mut masq, source, peer, 1234)
            .unwrap_or_else(|| unreachable!("a fixed private source is masqueraded"));

        assert!(
            inbound_from(&mut lookup, &mut masq, peer, 80, translated),
            "the endpoint the flow addressed could not answer it"
        );
        assert!(
            !inbound_from(&mut lookup, &mut masq, peer, 81, translated),
            "a packet from the right address on the wrong port reached the tenant"
        );
        assert!(
            !inbound_from(&mut lookup, &mut masq, elsewhere, 80, translated),
            "a packet from an address the flow never addressed reached the tenant"
        );
    });
}

#[test]
fn a_flow_inside_its_lifetime_survives() {
    with_paused_clock(|| async {
        let (fabric, _) = fabric();
        let (mut lookup, mut masq) = fabric.stages();
        let peer = fabric.peer[0];
        let source: IpAddr = "10.0.0.7".parse().unwrap_or_else(|_| unreachable!());

        let translated = open_flow(&mut lookup, &mut masq, source, peer, 1234)
            .unwrap_or_else(|| unreachable!("a fixed private source is masqueraded"));

        pass(&masq, WITHIN_LIFETIME).await;

        assert_eq!(
            reply_to(&mut lookup, &mut masq, peer, translated),
            Some(source),
            "a flow one second into a five second lifetime stopped answering"
        );
    });
}

#[test]
fn a_flow_past_its_lifetime_stops_answering() {
    with_paused_clock(|| async {
        let (fabric, _) = fabric();
        let (mut lookup, mut masq) = fabric.stages();
        let peer = fabric.peer[0];
        let source: IpAddr = "10.0.0.7".parse().unwrap_or_else(|_| unreachable!());

        let translated = open_flow(&mut lookup, &mut masq, source, peer, 1234)
            .unwrap_or_else(|| unreachable!("a fixed private source is masqueraded"));

        pass(&masq, PAST_EXPIRY).await;

        let delivered = reply_to(&mut lookup, &mut masq, peer, translated);
        assert_ne!(
            delivered,
            Some(source),
            "an expired flow still delivered its reply, so the timeout is not enforced"
        );
        assert!(
            delivered.is_none(),
            "the reply to an expired flow was forwarded to {delivered:?} instead of being dropped"
        );
    });
}

#[test]
fn traffic_extends_a_flow_past_its_first_deadline() {
    with_paused_clock(|| async {
        let (fabric, _) = fabric();
        let (mut lookup, mut masq) = fabric.stages();
        let peer = fabric.peer[0];
        let source: IpAddr = "10.0.0.7".parse().unwrap_or_else(|_| unreachable!());

        let translated = open_flow(&mut lookup, &mut masq, source, peer, 1234)
            .unwrap_or_else(|| unreachable!("a fixed private source is masqueraded"));

        for _ in 0..4 {
            pass(&masq, WITHIN_LIFETIME).await;
            assert_eq!(
                reply_to(&mut lookup, &mut masq, peer, translated),
                Some(source),
                "a refreshed flow stopped answering while still inside its extended lifetime"
            );
        }
    });
}

//= https://www.rfc-editor.org/rfc/rfc4787#section-4.3
//= type=test
//= reason=held: for established flows; see the OneWay gap recorded in nf.rs
//# REQ-6:  The NAT mapping Refresh Direction MUST have a "NAT Outbound
//# refresh behavior" of "True".
#[test]
fn outbound_traffic_keeps_an_established_mapping_alive() {
    with_paused_clock(|| async {
        let (fabric, _) = fabric();
        let (mut lookup, mut masq) = fabric.stages();
        let peer = fabric.peer[0];
        let source: IpAddr = "10.0.0.7".parse().unwrap_or_else(|_| unreachable!());

        let translated = open_flow(&mut lookup, &mut masq, source, peer, 1234)
            .unwrap_or_else(|| unreachable!("a fixed private source is masqueraded"));
        assert_eq!(
            reply_to(&mut lookup, &mut masq, peer, translated),
            Some(source),
            "the reply that establishes the connection was not delivered"
        );
        assert_eq!(
            open_flow(&mut lookup, &mut masq, source, peer, 1234),
            Some(translated),
            "the packet that establishes the connection changed its translation"
        );

        for step in 1..=3 {
            pass(&masq, NEARLY_ESTABLISHED).await;
            assert_eq!(
                open_flow(&mut lookup, &mut masq, source, peer, 1234),
                Some(translated),
                "at {}s an outbound packet no longer found the mapping",
                step * NEARLY_ESTABLISHED.as_secs()
            );
        }

        pass(&masq, REFRESHED_FOR).await;
        assert_eq!(
            reply_to(&mut lookup, &mut masq, peer, translated),
            Some(source),
            "the mapping did not survive five minutes of outbound traffic, so outbound packets \
             are not refreshing it"
        );

        pass(&masq, LONG_SILENCE).await;
        assert_eq!(
            reply_to(&mut lookup, &mut masq, peer, translated),
            None,
            "a mapping held open by outbound traffic never expired once that traffic stopped"
        );
    });
}

#[test]
fn an_expired_flow_is_never_resurrected() {
    with_paused_clock(|| async {
        let (fabric, _) = fabric();
        let (mut lookup, mut masq) = fabric.stages();
        let peer = fabric.peer[0];
        let first: IpAddr = "10.0.0.7".parse().unwrap_or_else(|_| unreachable!());
        let second: IpAddr = "10.0.0.9".parse().unwrap_or_else(|_| unreachable!());

        let dead = open_flow(&mut lookup, &mut masq, first, peer, 1234)
            .unwrap_or_else(|| unreachable!("a fixed private source is masqueraded"));

        pass(&masq, PAST_EXPIRY).await;

        let live = open_flow(&mut lookup, &mut masq, second, peer, 4321).unwrap_or_else(|| {
            unreachable!(
                "a flow opened after the clock advanced was refused; the deadline and the timer \
                 are on different clocks again"
            )
        });

        assert_eq!(
            reply_to(&mut lookup, &mut masq, peer, live),
            Some(second),
            "a flow opened after the clock advanced could not receive its reply"
        );
        assert_ne!(
            reply_to(&mut lookup, &mut masq, peer, dead),
            Some(first),
            "an expired flow answered again after a later flow had been created"
        );
    });
}

//= https://www.rfc-editor.org/rfc/rfc4787#section-4.3
//= type=test
//# REQ-6:  The NAT mapping Refresh Direction MUST have a "NAT Outbound
//# refresh behavior" of "True".
#[test]
fn outbound_traffic_keeps_an_unanswered_mapping_alive() {
    const STEP: Duration = Duration::from_secs(ONEWAY / 2);
    const REFRESHES: u32 = 2;

    let source: IpAddr = "10.0.0.21".parse().unwrap_or_else(|_| unreachable!());
    let elapsed = Duration::from_secs(u64::from(REFRESHES + 1) * STEP.as_secs());
    assert!(
        elapsed > crate::Masquerade::MASQUERADE_ONEWAY_TIMEOUT,
        "the probe must land past the deadline the first packet set, or neither half proves \
         anything"
    );

    with_paused_clock(|| async {
        let (fabric, _) = fabric();
        let (mut lookup, mut masq) = fabric.stages();
        let peer = fabric.peer[0];

        let translated = open_flow(&mut lookup, &mut masq, source, peer, 5300)
            .unwrap_or_else(|| unreachable!("a fixed private source is masqueraded"));
        for _ in 0..=REFRESHES {
            pass(&masq, STEP).await;
        }
        assert_eq!(
            reply_to(&mut lookup, &mut masq, peer, translated),
            None,
            "a mapping nobody refreshed survived {}s of silence against a {}s timeout, so the \
             treatment below proves nothing",
            elapsed.as_secs(),
            crate::Masquerade::MASQUERADE_ONEWAY_TIMEOUT.as_secs()
        );
    });

    with_paused_clock(|| async {
        let (fabric, _) = fabric();
        let (mut lookup, mut masq) = fabric.stages();
        let peer = fabric.peer[0];

        let translated = open_flow(&mut lookup, &mut masq, source, peer, 5300)
            .unwrap_or_else(|| unreachable!("a fixed private source is masqueraded"));
        for _ in 0..REFRESHES {
            pass(&masq, STEP).await;
            assert_eq!(
                open_flow(&mut lookup, &mut masq, source, peer, 5300),
                Some(translated),
                "the sender was given a different public tuple mid-stream"
            );
        }
        pass(&masq, STEP).await;
        assert_eq!(
            reply_to(&mut lookup, &mut masq, peer, translated),
            Some(source),
            "outbound traffic did not keep an unanswered mapping alive: at t={}s the flow was \
             gone, so a one-way sender loses its public tuple every {}s however much it sends",
            elapsed.as_secs(),
            crate::Masquerade::MASQUERADE_ONEWAY_TIMEOUT.as_secs()
        );
    });
}

#[test]
fn both_halves_of_a_pair_outlive_one_sided_traffic() {
    with_paused_clock(|| async {
        let (fabric, _) = fabric();
        let (mut lookup, mut masq) = fabric.stages();
        let peer = fabric.peer[0];
        let source: IpAddr = "10.0.0.7".parse().unwrap_or_else(|_| unreachable!());

        let translated = open_flow(&mut lookup, &mut masq, source, peer, 1234)
            .unwrap_or_else(|| unreachable!("a fixed private source is masqueraded"));
        assert_eq!(
            fabric.live_flows(),
            2,
            "a masqueraded flow should install a forward and a reverse entry"
        );

        for elapsed in 1..=8 {
            pass(&masq, WITHIN_LIFETIME).await;
            assert_eq!(
                reply_to(&mut lookup, &mut masq, peer, translated),
                Some(source),
                "the flow stopped answering at t={elapsed}s"
            );
            assert_eq!(
                fabric.live_flows(),
                2,
                "at t={elapsed}s one half of the pair had expired under a live connection; the \
                 forward half owns the allocation, so its tuple is now free to be reissued"
            );
        }
    });
}

#[test]
fn a_live_flows_tuple_is_never_reissued() {
    with_paused_clock(|| async {
        let (fabric, _) = fabric();
        let (mut lookup, mut masq) = fabric.stages();
        let peer = fabric.peer[0];
        let first: IpAddr = "10.0.0.10".parse().unwrap_or_else(|_| unreachable!());
        let second: IpAddr = "10.0.0.99".parse().unwrap_or_else(|_| unreachable!());

        let held = open_flow(&mut lookup, &mut masq, first, peer, 2000)
            .unwrap_or_else(|| unreachable!("a fixed private source is masqueraded"));

        for _ in 0..6 {
            pass(&masq, WITHIN_LIFETIME).await;
            assert_eq!(
                reply_to(&mut lookup, &mut masq, peer, held),
                Some(first),
                "the flow being held open stopped answering"
            );
        }

        let other = open_flow(&mut lookup, &mut masq, second, peer, 3000)
            .unwrap_or_else(|| unreachable!("a second private source is masqueraded"));
        assert_ne!(
            other, held,
            "{held:?} is held by a live flow from {first} and was reissued to {second}; replies \
             for {first} will be delivered to {second}"
        );
    });
}

// The idle timeout the gateway that ran out of ports was configured with: long enough that a
// mapping held for it past every close exhausts an address at a few dozen new connections a
// second. Scaled for emulation as the closing timeout is, so that it stays the longer of the two.
const LONG_IDLE_TIMEOUT: Duration = Duration::from_mins(30 * crate::common::TIMEOUT_SCALE);

const CLOSED_HOLD: Duration = crate::Masquerade::MASQUERADE_CLOSED_HOLD;

const CLOSING: Duration = crate::Masquerade::MASQUERADE_CLOSING_TIMEOUT;

fn tcp_fabric() -> Fabric {
    tcp_fabric_idle(LONG_IDLE_TIMEOUT)
}

fn tcp_fabric_idle(idle_timeout: Duration) -> Fabric {
    let exposes = vec![
        VpcExpose::empty()
            .make_masquerade(Some(idle_timeout))
            .unwrap_or_else(|e| unreachable!("{e}"))
            .ip(lpm::prefix::PrefixWithOptionalPorts::new(
                "10.0.0.0/24".parse().unwrap_or_else(|_| unreachable!()),
                None,
            ))
            .as_range(lpm::prefix::PrefixWithOptionalPorts::new(
                "172.16.0.0/24".parse().unwrap_or_else(|_| unreachable!()),
                None,
            ))
            .unwrap_or_else(|e| unreachable!("{e}")),
    ];
    Fabric::build(&exposes).unwrap_or_else(|| unreachable!("a fixed expose builds"))
}

const SYN: TcpFlags = TcpFlags::SYN;
const SYN_ACK: TcpFlags = TcpFlags::SYN.union(TcpFlags::ACK);
const ACK: TcpFlags = TcpFlags::ACK;
const FIN_ACK: TcpFlags = TcpFlags::FIN.union(TcpFlags::ACK);
const RST: TcpFlags = TcpFlags::RST;

fn tcp(
    source: IpAddr,
    destination: IpAddr,
    sport: u16,
    dport: u16,
    flags: TcpFlags,
) -> Packet<TestBuffer> {
    use net::headers::TryTcpMut;
    let mut packet = build(source, destination, true, sport, dport);
    packet
        .try_tcp_mut()
        .unwrap_or_else(|| unreachable!())
        .set_flags(flags);
    packet
}

// A TCP segment from a private host, and the public tuple it left with, if it was translated.
fn tcp_out(
    lookup: &mut FlowLookup,
    masq: &mut Masquerade,
    (source, sport): (IpAddr, u16),
    peer: IpAddr,
    flags: TcpFlags,
) -> Option<(IpAddr, u16)> {
    let mut packet = tcp(source, peer, sport, 80, flags);
    Arrival::outbound().stamp(&mut packet);
    let out = run(lookup, masq, vec![packet], Some(vni(REMOTE_VNI)));
    if out[0].is_done() {
        return None;
    }
    Some((out[0].ip_source()?, out[0].transport_src_port()?.get()))
}

// A TCP segment from the peer to a public tuple; whether it was let through.
fn tcp_in(
    lookup: &mut FlowLookup,
    masq: &mut Masquerade,
    peer: IpAddr,
    translated: (IpAddr, u16),
    flags: TcpFlags,
) -> bool {
    let mut packet = tcp(peer, translated.0, 80, translated.1, flags);
    Arrival::inbound().stamp(&mut packet);
    let out = run(lookup, masq, vec![packet], Some(vni(LOCAL_VNI)));
    !out[0].is_done()
}

fn establish(
    lookup: &mut FlowLookup,
    masq: &mut Masquerade,
    private: (IpAddr, u16),
    peer: IpAddr,
) -> (IpAddr, u16) {
    let translated = tcp_out(lookup, masq, private, peer, SYN)
        .unwrap_or_else(|| unreachable!("a fixed private source is masqueraded"));
    assert!(
        tcp_in(lookup, masq, peer, translated, SYN_ACK),
        "the SYN-ACK was not delivered"
    );
    assert_eq!(
        tcp_out(lookup, masq, private, peer, ACK),
        Some(translated),
        "the handshake's last ACK changed its translation"
    );
    translated
}

#[derive(Debug, Clone, Copy)]
enum Close {
    // The private host resets the connection.
    Reset,
    // The peer resets the connection.
    PeerReset,
    // The private host closes first, the peer closes in turn, and the private host acknowledges.
    Fin,
}

fn close(
    lookup: &mut FlowLookup,
    masq: &mut Masquerade,
    private: (IpAddr, u16),
    peer: IpAddr,
    translated: (IpAddr, u16),
    how: Close,
) {
    match how {
        Close::Reset => {
            tcp_out(lookup, masq, private, peer, RST);
        }
        Close::PeerReset => {
            tcp_in(lookup, masq, peer, translated, RST);
        }
        Close::Fin => {
            tcp_out(lookup, masq, private, peer, FIN_ACK);
            tcp_in(lookup, masq, peer, translated, FIN_ACK);
            tcp_out(lookup, masq, private, peer, ACK);
        }
    }
}

// Open, then close, a connection from `first`, let `after` pass, and open one from `second`:
// return both public tuples. The allocator hands out the lowest free port, so the second
// connection gets the first one's port exactly when that port has been given back.
fn reuse_after_close(how: Close, after: Duration) -> ((IpAddr, u16), (IpAddr, u16)) {
    let mut tuples = None;
    with_paused_clock(|| async {
        let fabric = tcp_fabric();
        let (mut lookup, mut masq) = fabric.stages();
        let peer = fabric.peer[0];
        let first = ("10.0.0.7".parse().unwrap_or_else(|_| unreachable!()), 1234);
        let second = ("10.0.0.9".parse().unwrap_or_else(|_| unreachable!()), 4321);

        let closed = establish(&mut lookup, &mut masq, first, peer);
        close(&mut lookup, &mut masq, first, peer, closed, how);
        // The worker sweeps the closed flow away straight after; the hold starts there.
        pass(&masq, Duration::ZERO).await;
        pass(&masq, after).await;
        let next = tcp_out(&mut lookup, &mut masq, second, peer, SYN)
            .unwrap_or_else(|| unreachable!("a second private source is masqueraded"));
        tuples = Some((closed, next));
    });
    tuples.unwrap_or_else(|| unreachable!("the body ran"))
}

/// A closed connection gives its public port back once the closed hold has passed, not a whole
/// idle timeout later; and not before. Whichever side closed it.
#[test]
fn a_closed_connection_gives_its_port_back_after_the_hold() {
    assert!(
        CLOSED_HOLD < LONG_IDLE_TIMEOUT,
        "the hold must be shorter than the idle timeout for this test to tell them apart"
    );
    let a_little = Duration::from_secs(1);
    for how in [Close::Reset, Close::PeerReset, Close::Fin] {
        let (closed, next) = reuse_after_close(how, CLOSED_HOLD + a_little);
        assert_eq!(
            next,
            closed,
            "after a {how:?} close, the port was not given back {}s later, well short of the \
             {}s idle timeout",
            (CLOSED_HOLD + a_little).as_secs(),
            LONG_IDLE_TIMEOUT.as_secs()
        );

        let (closed, next) = reuse_after_close(how, CLOSED_HOLD.saturating_sub(a_little));
        assert_ne!(
            next, closed,
            "after a {how:?} close, the port was handed out again before the hold had passed"
        );
    }
}

/// Under endpoint-independent mapping, two connections from one private port share a mapping.
/// One closing must not cut the other's mapping short: the open one would keep its own tuple, but
/// the next connection from that port would be given another (RFC 5382 REQ-1).
#[test]
fn closing_one_connection_keeps_a_shared_mapping() {
    with_paused_clock(|| async {
        let fabric = tcp_fabric();
        let (mut lookup, mut masq) = fabric.stages();
        let (peer, other_peer) = (fabric.peer[0], fabric.peer[1]);
        let private = ("10.0.0.7".parse().unwrap_or_else(|_| unreachable!()), 1234);

        let closed = establish(&mut lookup, &mut masq, private, peer);
        let open = establish(&mut lookup, &mut masq, private, other_peer);
        assert_eq!(
            open, closed,
            "sanity: two connections from one private port should share a mapping"
        );

        close(&mut lookup, &mut masq, private, peer, closed, Close::Reset);
        pass(&masq, CLOSED_HOLD + Duration::from_secs(1)).await;
        assert!(
            tcp_in(&mut lookup, &mut masq, other_peer, open, ACK),
            "the connection still open lost its mapping when the other one closed"
        );
        assert_eq!(
            tcp_out(&mut lookup, &mut masq, private, other_peer, ACK),
            Some(open),
            "the connection still open was moved to another public tuple"
        );
        assert_eq!(
            tcp_out(&mut lookup, &mut masq, private, peer, SYN),
            Some(open),
            "a new connection from the private port was given another public tuple while one \
             from it was still open: closing the other connection cut the mapping short"
        );
    });
}

/// A connection half-closed by the private host, with the peer still sending, keeps its mapping for
/// as long as the private host keeps acknowledging: the hold starts when the connection is gone,
/// not at the first FIN. Otherwise the next connection from that private port would be given
/// another public tuple while this one is still in use.
#[test]
fn a_half_closed_connection_keeps_its_mapping_while_in_use() {
    with_paused_clock(|| async {
        let fabric = tcp_fabric();
        let (mut lookup, mut masq) = fabric.stages();
        let (peer, other_peer) = (fabric.peer[0], fabric.peer[1]);
        let private = ("10.0.0.7".parse().unwrap_or_else(|_| unreachable!()), 1234);

        let translated = establish(&mut lookup, &mut masq, private, peer);
        tcp_out(&mut lookup, &mut masq, private, peer, FIN_ACK);
        let step = Duration::from_secs(1);
        let mut passed = Duration::ZERO;
        while passed <= CLOSED_HOLD + step {
            assert!(
                tcp_in(&mut lookup, &mut masq, peer, translated, ACK),
                "the peer's data was dropped {}s into the half-close",
                passed.as_secs()
            );
            assert_eq!(
                tcp_out(&mut lookup, &mut masq, private, peer, ACK),
                Some(translated),
                "the half-closed connection's ACK changed its translation"
            );
            pass(&masq, step).await;
            passed += step;
        }
        assert_eq!(
            tcp_out(&mut lookup, &mut masq, private, other_peer, SYN),
            Some(translated),
            "a new connection from the private port was given another public tuple while a \
             half-closed one from it was still in use"
        );
    });
}

/// A close that never completes: the private host sends its FIN and the peer never answers. The
/// flow goes once the closing timeout has passed without a packet, and the mapping after the hold
/// that starts there: the port is given back well short of the idle timeout. Retransmitted FINs
/// keep the flow, and so the port, for as long as they come.
#[test]
fn an_unanswered_close_gives_its_port_back() {
    assert!(
        CLOSING + CLOSED_HOLD < LONG_IDLE_TIMEOUT / 2,
        "the closing timeout and the hold must be well short of the idle timeout for this test to \
         tell them apart"
    );
    with_paused_clock(|| async {
        let fabric = tcp_fabric();
        let (mut lookup, mut masq) = fabric.stages();
        let peer = fabric.peer[0];
        let first = ("10.0.0.7".parse().unwrap_or_else(|_| unreachable!()), 1234);
        let second = ("10.0.0.9".parse().unwrap_or_else(|_| unreachable!()), 4321);
        let third = ("10.0.0.11".parse().unwrap_or_else(|_| unreachable!()), 5678);
        let a_little = CLOSING / 4;

        let closing = establish(&mut lookup, &mut masq, first, peer);
        tcp_out(&mut lookup, &mut masq, first, peer, FIN_ACK);
        // The FIN again, just short of the closing timeout: the flow is kept from there.
        pass(&masq, CLOSING.saturating_sub(a_little)).await;
        assert_eq!(
            tcp_out(&mut lookup, &mut masq, first, peer, FIN_ACK),
            Some(closing),
            "a retransmitted FIN, inside the closing timeout, changed its translation"
        );
        pass(&masq, CLOSING.saturating_sub(a_little)).await;
        assert!(
            tcp_in(&mut lookup, &mut masq, peer, closing, FIN_ACK),
            "the peer's answer was dropped inside the closing timeout of the last FIN"
        );

        // Nothing more: the private host never acknowledges. The flow goes, then the mapping.
        pass(&masq, CLOSING + a_little).await;
        assert!(
            !tcp_in(&mut lookup, &mut masq, peer, closing, FIN_ACK),
            "the flow of a close left unfinished outlived the closing timeout"
        );
        pass(&masq, CLOSED_HOLD.saturating_sub(a_little * 2)).await;
        assert_ne!(
            tcp_out(&mut lookup, &mut masq, second, peer, SYN),
            Some(closing),
            "the port was handed out again before the hold had passed"
        );
        pass(&masq, a_little * 2).await;
        assert_eq!(
            tcp_out(&mut lookup, &mut masq, third, peer, SYN),
            Some(closing),
            "the port of a close left unfinished was not given back after the closing timeout \
             and the hold, well short of the idle timeout"
        );
    });
}

// Send a SYN from `first`, and again `retry` later, with no answer; let its flow time out and be
// swept away, then `after` pass, and open a connection from `second`: return both public tuples,
// as `reuse_after_close` does.
fn reuse_after_unanswered_syn(retry: Duration, after: Duration) -> ((IpAddr, u16), (IpAddr, u16)) {
    let mut tuples = None;
    with_paused_clock(|| async {
        let fabric = tcp_fabric();
        let (mut lookup, mut masq) = fabric.stages();
        let peer = fabric.peer[0];
        let first = ("10.0.0.7".parse().unwrap_or_else(|_| unreachable!()), 1234);
        let second = ("10.0.0.9".parse().unwrap_or_else(|_| unreachable!()), 4321);

        let unanswered = tcp_out(&mut lookup, &mut masq, first, peer, SYN)
            .unwrap_or_else(|| unreachable!("a fixed private source is masqueraded"));
        pass(&masq, retry).await;
        assert_eq!(
            tcp_out(&mut lookup, &mut masq, first, peer, SYN),
            Some(unanswered),
            "sanity: a retransmitted SYN should keep its translation"
        );
        // The unanswered flow times out a few seconds after the first SYN, and the worker sweeps
        // it away; the hold starts there.
        pass(&masq, Masquerade::MASQUERADE_ONEWAY_TIMEOUT).await;
        pass(&masq, after).await;
        let next = tcp_out(&mut lookup, &mut masq, second, peer, SYN)
            .unwrap_or_else(|| unreachable!("a second private source is masqueraded"));
        tuples = Some((unanswered, next));
    });
    tuples.unwrap_or_else(|| unreachable!("the body ran"))
}

/// A SYN nobody answers gives its public port back once its flow has timed out and the hold has
/// passed, not a whole idle timeout after the last SYN; and not before the hold. A retransmitted
/// SYN refreshes the mapping for the idle timeout, so this also checks the hold brings that in.
#[test]
fn an_unanswered_syn_gives_its_port_back_after_the_hold() {
    assert!(
        CLOSED_HOLD < LONG_IDLE_TIMEOUT,
        "the hold must be shorter than the idle timeout for this test to tell them apart"
    );
    let (retry, a_little) = (Duration::from_secs(1), Duration::from_secs(1));
    let (unanswered, next) = reuse_after_unanswered_syn(retry, CLOSED_HOLD + a_little);
    assert_eq!(
        next,
        unanswered,
        "an unanswered SYN's port was not given back {}s after its flow went, well short of the \
         {}s idle timeout",
        (CLOSED_HOLD + a_little).as_secs(),
        LONG_IDLE_TIMEOUT.as_secs()
    );

    let (unanswered, next) =
        reuse_after_unanswered_syn(retry, CLOSED_HOLD.saturating_sub(a_little));
    assert_ne!(
        next, unanswered,
        "an unanswered SYN's port was handed out again before the hold had passed"
    );
}

/// A half-closed connection whose peer is slow to answer: the private host sends its request and
/// shuts down its side, the peer acknowledges the FIN and only answers well after that. The
/// connection is still open the other way, so the answer gets through, and with the translation the
/// connection always had. The peer here takes most of the 4 minutes RFC 5382 REQ-5 sets as the
/// least a NAT may wait on such a "transitory" connection; a fixed time, not the closing timeout,
/// so that this fails if that timeout is ever made short again.
#[test]
fn a_half_closed_connection_waits_for_a_slow_peer() {
    with_paused_clock(|| async {
        let fabric = tcp_fabric();
        let (mut lookup, mut masq) = fabric.stages();
        let (peer, other_peer) = (fabric.peer[0], fabric.peer[1]);
        let private = ("10.0.0.7".parse().unwrap_or_else(|_| unreachable!()), 1234);

        let translated = establish(&mut lookup, &mut masq, private, peer);
        tcp_out(&mut lookup, &mut masq, private, peer, FIN_ACK);
        assert!(
            tcp_in(&mut lookup, &mut masq, peer, translated, ACK),
            "the peer's acknowledgement of the FIN was dropped"
        );
        let slow = Duration::from_mins(4) - Duration::from_secs(30);
        pass(&masq, slow).await;
        assert!(
            tcp_in(&mut lookup, &mut masq, peer, translated, ACK),
            "the peer's answer, {}s into the half-close, was dropped",
            slow.as_secs()
        );
        assert_eq!(
            tcp_out(&mut lookup, &mut masq, private, peer, ACK),
            Some(translated),
            "the private host's acknowledgement of the late answer changed its translation"
        );
        assert_eq!(
            tcp_out(&mut lookup, &mut masq, private, other_peer, SYN),
            Some(translated),
            "a new connection from the private port was given another public tuple while a \
             half-closed one from it was still in use"
        );
    });
}

/// A configured idle timeout has no upper bound (see GH 1854). An established connection
/// extends its flows to that timeout from now, and a flow's deadline only reaches so far (some
/// 584 years) past the one it started with: past that, extending it would panic, on a worker.
#[test]
fn an_absurd_idle_timeout_never_breaks_an_established_connection() {
    with_paused_clock(|| async {
        let fabric = tcp_fabric_idle(Duration::MAX);
        let (mut lookup, mut masq) = fabric.stages();
        let peer = fabric.peer[0];
        let private = ("10.0.0.7".parse().unwrap_or_else(|_| unreachable!()), 1234);

        let translated = establish(&mut lookup, &mut masq, private, peer);
        pass(&masq, LONG_IDLE_TIMEOUT).await;
        assert!(
            tcp_in(&mut lookup, &mut masq, peer, translated, ACK),
            "the established connection lost its flow well inside its (absurd) idle timeout"
        );
        assert_eq!(
            tcp_out(&mut lookup, &mut masq, private, peer, ACK),
            Some(translated),
            "the established connection changed its translation"
        );
    });
}

/// A connection half-closed by the private host whose peer never closes in turn: the private
/// host gives up on it (Linux drops an orphaned `FIN_WAIT_2` after a minute) and opens a new
/// connection from the same port, to the same peer, while the old one's flow is still kept. The
/// new connection is open, not closing: it keeps its flow for the idle timeout, not the closing
/// timeout. A SYN from outside does not get to end the old connection that way.
#[test]
fn a_new_connection_on_a_closing_ones_tuple_is_not_closing() {
    assert!(
        CLOSING * 2 < LONG_IDLE_TIMEOUT,
        "the closing timeout must be well short of the idle timeout for this test to tell them \
         apart"
    );
    with_paused_clock(|| async {
        let fabric = tcp_fabric();
        let (mut lookup, mut masq) = fabric.stages();
        let peer = fabric.peer[0];
        let private = ("10.0.0.7".parse().unwrap_or_else(|_| unreachable!()), 1234);

        let translated = establish(&mut lookup, &mut masq, private, peer);
        tcp_out(&mut lookup, &mut masq, private, peer, FIN_ACK);
        assert!(
            tcp_in(&mut lookup, &mut masq, peer, translated, ACK),
            "the peer's acknowledgement of the FIN was dropped"
        );
        // A SYN from outside, on the public tuple, is not the private host's to reuse its port:
        // it must not end the connection.
        tcp_in(&mut lookup, &mut masq, peer, translated, SYN);
        assert!(
            tcp_in(&mut lookup, &mut masq, peer, translated, ACK),
            "a SYN from outside ended a half-closed connection"
        );
        pass(&masq, Duration::from_mins(1)).await;
        assert_eq!(
            establish(&mut lookup, &mut masq, private, peer),
            translated,
            "sanity: the new connection should go through the old one's flow"
        );

        let silence = CLOSING * 2;
        pass(&masq, silence).await;
        assert!(
            tcp_in(&mut lookup, &mut masq, peer, translated, ACK),
            "the new connection's flow went after {}s of silence: it was kept for the closing \
             timeout, as the old connection's would have been, not for the idle timeout",
            silence.as_secs()
        );
    });
}
