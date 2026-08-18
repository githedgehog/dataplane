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

/// A live flow's public tuple is reissued to another flow once its *original* deadline passes.
///
/// **A reproduction of a defect, not a passing property.** Ignored so the branch stays green; run it
/// with `cargo test -p dataplane-nat -- --ignored reissued` to see it fail.
///
/// # What happens
///
/// A flow is opened and then refreshed every second, so it is unambiguously alive -- its replies are
/// delivered correctly throughout. Once `MASQUERADE_ONEWAY_TIMEOUT` of *virtual* time has passed
/// since it was opened, a newly opened flow is handed the same public address and port, and the
/// replies that were reaching the first tenant start reaching the second.
///
/// The threshold is exactly the one-way timeout, measured by bisection:
///
/// | advance | flow alive | tuple reissued |
/// | --- | --- | --- |
/// | 4s | yes | no |
/// | 5s | yes | **yes** |
///
/// So the allocation is being reclaimed on the deadline the flow was *created* with, and the refreshes
/// that keep the flow itself alive do not carry it. `MasqueradeState` holds the `Allocation` in the
/// forward entry only, which is consistent with the forward entry being reclaimed while the reverse
/// entry survives and keeps translating -- but that is where the investigation should start rather
/// than what it has concluded.
///
/// # Why it matters in production
///
/// Production sets `randomize(true)`, and with randomization the same sequence picks a different
/// port, so the collision is unlikely rather than impossible -- it needs the reclaimed port to be
/// drawn again while the old flow still lives, which is a matter of load and range size rather than
/// of correctness. What is wrong in both modes is the underlying state: a flow that is still
/// translating no longer owns the tuple it is translating to. Two tenants sharing a public tuple is
/// a tenant isolation failure, not a performance one.
///
/// This is the class of defect a controllable clock exists to find. Reaching it on the wall clock
/// needs six seconds of real time per attempt and the right allocation pattern; here it is
/// deterministic and costs nothing.
#[test]
#[ignore = "reproduces an unfixed defect: a live flow's tuple is reissued after its original deadline"]
fn a_live_flows_tuple_is_reissued_after_its_original_deadline() {
    with_paused_clock(|| async {
        let (fabric, _) = fabric();
        let (mut lookup, mut masq) = fabric.stages();
        let peer = fabric.peer[0];
        let first: IpAddr = "10.0.0.10".parse().unwrap_or_else(|_| unreachable!());
        let second: IpAddr = "10.0.0.99".parse().unwrap_or_else(|_| unreachable!());

        let translated = open_flow(&mut lookup, &mut masq, first, peer, 2000)
            .unwrap_or_else(|| unreachable!("a fixed private source is masqueraded"));

        // Refresh once a second, past the one-way timeout. The flow is alive the whole way.
        for second_elapsed in 1..=6 {
            advance(WITHIN_LIFETIME).await;
            assert_eq!(
                reply_to(&mut lookup, &mut masq, peer, translated),
                Some(first),
                "the flow stopped answering at t={second_elapsed}s despite being refreshed"
            );
        }

        let other = open_flow(&mut lookup, &mut masq, second, peer, 3000)
            .unwrap_or_else(|| unreachable!("a second private source is masqueraded"));

        assert_ne!(
            other, translated,
            "a live flow's public tuple {translated:?} was reissued to {second}, so replies for \
             {first} will be delivered to {second}"
        );
    });
}
