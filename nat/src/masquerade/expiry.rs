// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Flow expiry, on a clock the test drives.
//!
//! `masquerade::fuzz` deliberately stays inside one flow lifetime, because until the workspace read
//! its deadlines through [`clock`] there was no way to write these. The waits were on tokio's clock
//! and the deadlines were on `std`'s, so a paused clock bought exactly **one** time step: anything
//! created after the first `advance` was born with a deadline already in the past.
//!
//! With both on the same clock, expiry becomes an ordinary subject. These run in zero wall-clock
//! time -- a property covering a minute of flow lifetime costs nothing, where a real-time version
//! would cost a minute per case and be flaky under emulation.
//!
//! # The three dispositions
//!
//! The development guide asks that every piece of live state a configuration change could touch be
//! classified, and expiry is the same question asked of time rather than of configuration:
//!
//! 1. **Preserved** -- a flow inside its lifetime keeps behaving identically.
//! 2. **Invalidated attributably** -- a flow past its lifetime stops translating, and says so rather
//!    than silently forwarding.
//! 3. **Never resurrected** -- an expired flow's translation does not come back to life, and a new
//!    flow that reuses the same public tuple answers to its own source rather than the dead one.
//!
//! The third is the one worth the machinery. It needs at least three epochs -- create, expire,
//! create again -- and a single `advance` cannot express it.

#![cfg(test)]

use crate::Masquerade;
use crate::masquerade::probe::{Arrival, Fabric, run};
use crate::static_nat::probe::build;
use clock::Duration;
use config::external::overlay::vpcpeering::VpcExpose;
use config::external::overlay::vpcpeering::contract::{LOCAL_VNI, REMOTE_VNI};
use flow_entry::flow_table::FlowLookup;
use net::buffer::TestBuffer;
use net::packet::Packet;
use net::vxlan::Vni;
use std::net::IpAddr;

/// Comfortably past `MASQUERADE_ONEWAY_TIMEOUT`, which is the longest a flow lives untouched.
const PAST_EXPIRY: Duration = Duration::from_secs(30);

/// Comfortably inside it.
const WITHIN_LIFETIME: Duration = Duration::from_secs(1);

/// Inside the two-minute established idle timeout, but most of the way through it.
///
/// The step has to be near the timeout or the test proves nothing: a step well inside the lifetime
/// the previous packet already bought would hold with refresh deleted entirely. At 100 seconds
/// against 120, each packet is the only reason the mapping survives to see the next one.
const NEARLY_ESTABLISHED: Duration = Duration::from_secs(100);

fn vni(raw: u32) -> Vni {
    Vni::new_checked(raw).unwrap_or_else(|_| unreachable!())
}

/// A runtime whose clock starts paused and only moves when a property says so.
///
/// `block_on` rather than `enter`, because `tokio::time::advance` is async and because the timer
/// tasks the flow table spawns need the runtime to be driven before they can observe the new time.
/// Everything a property does happens inside this one future.
fn with_paused_clock<F: Future<Output = ()>>(body: impl FnOnce() -> F) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap_or_else(|e| unreachable!("{e}"));
    runtime.block_on(body());
}

/// Move the clock and let every timer that is now due actually run.
///
/// The yields matter. `advance` makes the time visible; it does not run the tasks waiting on it, and
/// a property that checked immediately afterwards would see a flow that is past its deadline but has
/// not yet been told so.
async fn advance(by: Duration) {
    tokio::time::advance(by).await;
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
}

/// A two-vpc masquerade fabric with one expose, which is all expiry needs.
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

/// Send one flow's first packet and report what it was translated to.
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

/// Send the reply to a translated flow and report where it was delivered, if anywhere.
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
/// Address pairing does not change when the pool is under pressure.
///
/// REQ-11 is second order: it is not a requirement about a packet, it is a requirement that the
/// answers to the *other* requirements stay the same. RFC 4787 section 8 says what it is aimed at --
/// NATs that take a different code path once the port they wanted is taken, so their behaviour has a
/// "Primary" form before the first conflict and a "Secondary" form after it.
///
/// Two readings have to be got right before this can be cited at all. "Behavior" means the class
/// from section 4, not the values: section 4.2.1 explicitly permits random port assignment, so the
/// allocator shuffling port blocks is not a violation. And the conflict class section 8 describes --
/// port preservation with a fallback path -- does not exist here, because nothing ever tries to
/// preserve a source port.
///
/// What can still change is address pooling, so that is what this measures: 254 internal hosts,
/// 256 flows each, 65,024 flows against a public /24. The pool does spill -- two public addresses
/// end up in use -- and **no internal host is ever given more than one of them**. Pairing before
/// the spill and pairing after it are the same behaviour, which is REQ-11 for the mapping
/// dimension.
///
/// Ignored by default because it costs about fourteen seconds against a suite that otherwise runs
/// in four. It is a measurement to re-take when the allocator changes, not a guard on every commit.
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

/// Send an inbound packet to a translated tuple from an arbitrary external endpoint.
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
/// Only the endpoint a flow addressed can answer it.
///
/// Three probes against one flow to `3.3.3.1:80` classify the filtering behaviour exactly, in
/// RFC 4787 section 5's terms: the same address and port is delivered, the same address on a
/// different port is dropped, and a different address is dropped. That is
/// **"Address and Port-Dependent Filtering"**, the most restrictive of the three classes.
///
/// REQ-8 is a different species from the requirements around it, and worth reading carefully. It
/// does not state one behaviour; it states two, and picks between them on a priority nobody has
/// written down -- transparency or stringency. We satisfy neither branch, because we are stricter
/// than the stringent one: REQ-8's "more stringent" option is Address-*Dependent* filtering, which
/// would let `3.3.3.1:81` through.
///
/// Stricter than a `SHOULD` asks is still a departure from it, and the honest reading is that this
/// is a consequence of keying the flow table on the whole five-tuple rather than a filtering policy
/// anybody chose. Hence `todo`: what is missing is not code, it is a recorded priority.
///
/// The behaviour itself is worth pinning regardless of how REQ-8 is resolved -- an unsolicited
/// packet reaching a tenant because it guessed a live public tuple is a security failure, and the
/// second and third probes are what rule it out.
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

/// A flow inside its lifetime is unaffected by the passage of time.
///
/// The **preserved** disposition. Stated as a property rather than assumed, because the cheap way to
/// implement expiry -- sweep and drop anything whose deadline has passed -- is also the cheap way to
/// drop something whose deadline has not.
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

/// A flow past its lifetime stops translating, and does not silently forward.
///
/// The **invalidated attributably** disposition. The failure this rules out is not the drop -- a
/// reply to a flow nobody remembers should be dropped -- it is the *pass*: forwarding a packet still
/// addressed to a public tuple into the tenant's network, or back out with no translation, is a leak
/// rather than a timeout.
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

/// Traffic keeps a flow alive past the deadline it started with.
///
/// `reset_expiry_unchecked` is one of the three sites that used to read the wall clock while the
/// timer that consumes its answer read tokio's, so a refresh under a paused clock wrote a deadline
/// in the past and *shortened* the flow's life instead of extending it. That is precisely the
/// confusing failure the facade exists to prevent, and this is the regression test for it.
#[test]
fn traffic_extends_a_flow_past_its_first_deadline() {
    with_paused_clock(|| async {
        let (fabric, _) = fabric();
        let (mut lookup, mut masq) = fabric.stages();
        let peer = fabric.peer[0];
        let source: IpAddr = "10.0.0.7".parse().unwrap_or_else(|_| unreachable!());

        let translated = open_flow(&mut lookup, &mut masq, source, peer, 1234)
            .unwrap_or_else(|| unreachable!("a fixed private source is masqueraded"));

        // Four refreshes a second apart. Each is inside the current lifetime, and together they
        // carry the flow well past the deadline the first packet set.
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
/// Outbound traffic alone keeps an established mapping alive.
///
/// The sibling above refreshes with replies, which is *inbound* refresh -- RFC 4787 REQ-6a, and only
/// a MAY. REQ-6 is a MUST about the outbound direction, and nothing asserted it until this test: the
/// permitted behaviour was covered and the required one was not.
///
/// Three steps of a hundred seconds against a hundred-and-twenty second idle timeout, so each
/// outbound packet is the only reason the mapping survives to see the next. Five minutes elapse in
/// total, with nothing arriving from outside after the single reply that opens the connection.
///
/// The tail is what keeps it honest: having shown traffic holds the mapping open, it stops and shows
/// the mapping does then expire. A flow table that expired nothing would pass the first half and
/// mean nothing by it.
///
/// **This covers established flows.** The unanswered case -- a flow still in `OneWay`, which for UDP
/// is a steady state rather than a transient -- is
/// `outbound_traffic_keeps_an_unanswered_mapping_alive` above. Between them REQ-6 is held for every
/// UDP state a mapping can be alive in.
#[test]
fn outbound_traffic_keeps_an_established_mapping_alive() {
    with_paused_clock(|| async {
        let (fabric, _) = fabric();
        let (mut lookup, mut masq) = fabric.stages();
        let peer = fabric.peer[0];
        let source: IpAddr = "10.0.0.7".parse().unwrap_or_else(|_| unreachable!());

        // Out, in, out: the shortest path to `Established` and the two-minute timer.
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

        // Nothing arrives from outside from here on. Outbound packets only.
        for step in 1..=3 {
            advance(NEARLY_ESTABLISHED).await;
            assert_eq!(
                open_flow(&mut lookup, &mut masq, source, peer, 1234),
                Some(translated),
                "at {}s an outbound packet no longer found the mapping",
                step * NEARLY_ESTABLISHED.as_secs()
            );
        }

        // Probe after longer than a `OneWay` lifetime but well inside an established one. This is
        // what makes the assertion mean "refreshed" rather than "silently torn down and rebuilt":
        // a flow rebuilt by the last outbound packet would be in `OneWay` and already dead here,
        // even if the allocator handed back the identical tuple.
        advance(PAST_EXPIRY).await;
        assert_eq!(
            reply_to(&mut lookup, &mut masq, peer, translated),
            Some(source),
            "the mapping did not survive five minutes of outbound traffic, so outbound packets \
             are not refreshing it"
        );

        // Traffic stops. The mapping must not be immortal.
        advance(Duration::from_mins(5)).await;
        assert_eq!(
            reply_to(&mut lookup, &mut masq, peer, translated),
            None,
            "a mapping held open by outbound traffic never expired once that traffic stopped"
        );
    });
}

/// An expired flow does not come back, and its public tuple may be handed to someone else.
///
/// The **never resurrected** disposition, and the property that needs the whole facade: three
/// epochs, with a flow created *after* time has moved. Before the clock was routed this could not be
/// written at all -- the second flow was born with a deadline in the past and was dead on arrival,
/// which looks exactly like a masquerade bug and is not one.
///
/// Two claims. The dead flow stays dead, and the live one answers to *its own* source: an allocator
/// that reissued the tuple while the old flow's reverse entry lingered would deliver the second
/// tenant's replies to the first.
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

        // Epoch three: a new flow, created after the clock moved.
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

/// Outbound traffic keeps a mapping alive before anything has answered it.
///
/// **The control and the treatment RFC 4787 REQ-6 asks for.** A UDP flow that never gets a reply
/// stays in `NatFlowStatus::OneWay` for life -- `next_flow_status_udp` leaves that state only on an
/// inbound packet -- so it is the steady state of syslog, netflow, telemetry, or a resolver query
/// nobody answers, not a transient. `refresh_masquerade_state` gave it no extension, so such a flow
/// was torn down `MASQUERADE_ONEWAY_TIMEOUT` after its **first** packet however much it sent.
///
/// # The probe has to be a reply, and it has to come after a gap
///
/// The obvious test -- send outbound packets and check the tuple does not change -- is vacuous, and
/// it took writing it to see why: the allocator is deterministic under `set_randomize(false)`, so a
/// flow that is torn down and rebuilt is handed *the same* address and port back. Every
/// outbound-side observable therefore looks identical whether the mapping survived or was
/// recreated.
///
/// What separates them is an inbound packet at a moment when no outbound packet has just recreated
/// the flow. Both halves below run to `t = 6s` against a five-second one-way timeout, and the last
/// outbound packet in the treatment is at `t = 4s` -- so the reply lands past the deadline the
/// *first* packet set and inside the one the *last* packet set. Refreshed, it is delivered; not
/// refreshed, the mapping died at `t = 5s` and it is dropped.
//= https://www.rfc-editor.org/rfc/rfc4787#section-4.3
//= type=test
//# REQ-6:  The NAT mapping Refresh Direction MUST have a "NAT Outbound
//# refresh behavior" of "True".
#[test]
fn outbound_traffic_keeps_an_unanswered_mapping_alive() {
    /// Comfortably inside the one-way lifetime, so each packet lands before the previous deadline.
    const STEP: Duration = Duration::from_secs(2);
    /// Outbound packets before the probe. Two puts the last one at `t = 4s`.
    const REFRESHES: u32 = 2;

    let source: IpAddr = "10.0.0.21".parse().unwrap_or_else(|_| unreachable!());
    let elapsed = Duration::from_secs(u64::from(REFRESHES + 1) * STEP.as_secs());
    assert!(
        elapsed > crate::Masquerade::MASQUERADE_ONEWAY_TIMEOUT,
        "the probe must land past the deadline the first packet set, or neither half proves \
         anything"
    );

    // The control: silence for the same span, and the mapping is gone.
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

    // The treatment: the same span, with outbound packets, and the probe after a gap.
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
        // One more step with nothing sent, so what answers here is the mapping's own lifetime
        // rather than the packet that would have rebuilt it.
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

/// A pair's two halves outlive traffic that only runs one way.
///
/// **This is a regression test for a real defect, fixed in the commit that added it.**
///
/// A masqueraded connection is two flow entries -- forward and reverse -- and `refresh_masquerade_state`
/// used to refresh only the one a packet happened to hit. The partner was refreshed exactly once,
/// on the transition into `Established`. So a connection whose traffic ran mostly one way let the
/// other half expire while it was still in use, and that is the common case rather than a corner:
/// a download, a DNS response, any session that mostly receives.
///
/// What made it serious is *which* half. `MasqueradeState` carries the `Allocation` in the forward
/// entry alone, so the forward half expiring released the address and port while the reverse half
/// went on translating to them. The allocator then handed that tuple to another tenant, whose
/// replies arrived at the first tenant's still-live reverse entry -- two tenants sharing one public
/// tuple, which is a tenant isolation failure rather than a dropped connection.
///
/// It was invisible from the packet path, which is why it needed the flow count: every reply kept
/// being delivered correctly the whole time. Only a *new* flow stealing the tuple showed it, and
/// only after `MASQUERADE_ONEWAY_TIMEOUT` of virtual time -- five seconds of real time and the right
/// allocation pattern, which is why no test had found it.
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

        // Traffic in one direction only, well past the one-way timeout.
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

/// A live flow's public tuple is never reissued to another flow.
///
/// The consequence of the defect above, stated where an operator would feel it. Kept as its own
/// property because it is the claim that matters -- the flow count is the mechanism, this is the
/// outcome -- and because it would also catch a *different* allocator bug that released a tuple for
/// some other reason.
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

        // Keep it alive with one-sided traffic, past the one-way timeout.
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
