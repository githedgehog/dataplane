// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![cfg(test)]

use crate::Masquerade;
use crate::masquerade::probe::{Arrival, Fabric, run};
use crate::static_nat::probe::build;
use clock::Duration;
use clock::virtual_time::advance;
use config::external::overlay::vpcpeering::VpcExpose;
use config::external::overlay::vpcpeering::contract::{LOCAL_VNI, REMOTE_VNI};
use flow_entry::flow_table::FlowLookup;
use net::buffer::TestBuffer;
use net::packet::Packet;
use net::vxlan::Vni;
use std::net::IpAddr;

const PAST_EXPIRY: Duration = Duration::from_secs(30);

const WITHIN_LIFETIME: Duration = Duration::from_secs(1);

const NEARLY_ESTABLISHED: Duration = Duration::from_secs(100);

fn vni(raw: u32) -> Vni {
    Vni::new_checked(raw).unwrap_or_else(|_| unreachable!())
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
//= type=test
//= reason=held for the mapping dimension: pairing is unchanged by exhaustion, measured below
//# REQ-11:  A NAT MUST have deterministic behavior, i.e., it MUST NOT
//# change the NAT translation (Section 4) or the Filtering
//# (Section 5) Behavior at any point in time, or under any particular
//# conditions.
#[test]
#[ignore = "characterization probe; run with --ignored --nocapture"]
fn pairing_is_unchanged_by_pool_exhaustion() {
    use std::collections::{BTreeMap, BTreeSet};
    with_paused_clock(|| async {
        let (fabric, _) = fabric();
        let (mut lookup, mut masq) = fabric.stages();
        let peer = fabric.peer[0];
        let mut given: BTreeMap<IpAddr, BTreeSet<IpAddr>> = BTreeMap::new();

        for host in 1..=254u16 {
            let source: IpAddr = format!("10.0.0.{host}")
                .parse()
                .unwrap_or_else(|_| unreachable!());
            for sport in 1024..1024 + 256u16 {
                if let Some((public, _)) = open_flow(&mut lookup, &mut masq, source, peer, sport) {
                    given.entry(source).or_default().insert(public);
                }
            }
        }

        let publics: BTreeSet<_> = given.values().flatten().copied().collect();
        println!(
            "{} hosts, {} public addresses in use",
            given.len(),
            publics.len()
        );
        assert!(
            publics.len() > 1,
            "the pool never spilled to a second address, so this measured nothing about conflict"
        );
        let split: Vec<_> = given.iter().filter(|(_, a)| a.len() > 1).collect();
        assert!(
            split.is_empty(),
            "pooling changed under pressure: {} hosts were given more than one public address, \
             so the behaviour before the spill is not the behaviour after it",
            split.len()
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

        advance(WITHIN_LIFETIME).await;

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

        advance(PAST_EXPIRY).await;

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
            advance(WITHIN_LIFETIME).await;
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
            advance(NEARLY_ESTABLISHED).await;
            assert_eq!(
                open_flow(&mut lookup, &mut masq, source, peer, 1234),
                Some(translated),
                "at {}s an outbound packet no longer found the mapping",
                step * NEARLY_ESTABLISHED.as_secs()
            );
        }

        advance(PAST_EXPIRY).await;
        assert_eq!(
            reply_to(&mut lookup, &mut masq, peer, translated),
            Some(source),
            "the mapping did not survive five minutes of outbound traffic, so outbound packets \
             are not refreshing it"
        );

        advance(Duration::from_mins(5)).await;
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

        advance(PAST_EXPIRY).await;

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
    const STEP: Duration = Duration::from_secs(2);
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
            advance(STEP).await;
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
            advance(STEP).await;
            assert_eq!(
                open_flow(&mut lookup, &mut masq, source, peer, 5300),
                Some(translated),
                "the sender was given a different public tuple mid-stream"
            );
        }
        advance(STEP).await;
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
            advance(WITHIN_LIFETIME).await;
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
            advance(WITHIN_LIFETIME).await;
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
