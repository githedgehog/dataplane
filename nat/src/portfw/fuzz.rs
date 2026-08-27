// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Properties of the port-forwarding network function.
//!
//! The third and last NAT flavour, and the one where the only confirmed configuration bug of
//! this series lived: a port-forwarding expose that validated and could not be built. That was
//! found by reading code and pinned at the *configuration* level. These cover the stage.
//!
//! # Why the direction matters
//!
//! Static NAT and masquerade translate a **source** on the way out. Port forwarding translates a
//! **destination** on the way in, so every property here reads the other half of the five-tuple, and
//! the failure modes are different in kind. A masquerade mistake leaks one tenant's traffic to
//! another; a port-forwarding mistake delivers the outside world to an address inside a tenant that
//! never published it.
//!
//! # No oracle
//!
//! The mapping is positional -- one prefix and port range onto another of the same size, address for
//! address -- so it *could* be predicted. Deliberately not: a prediction here is a second copy of
//! `PortFwEntry`'s arithmetic, and two copies disagree. The properties below are relations and
//! membership tests, as everywhere else in these harnesses.

#![cfg(test)]

use crate::portfw::probe::{Arrival, Fabric, ProbeSpec, run};
use bolero::{Driver, TypeGenerator, ValueGenerator};
use concurrency::sync::atomic::{AtomicUsize, Ordering};
use config::external::overlay::vpcpeering::VpcExpose;
use config::external::overlay::vpcpeering::contract::PortForwardingExposes;
use net::buffer::TestBuffer;
use net::packet::Packet;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::num::NonZero;

// A *ratio*, and no absolute floor -- see `masquerade::fuzz`, where coverage instrumentation
// failed the absolute one on a property that was working.

/// Exposes per configuration. One per protocol key; see `PortForwardingExposes`.
const MAX_EXPOSES: u8 = 2;

/// Packets per configuration.
const PROBES: usize = 8;

#[derive(Debug, Clone, Copy)]
struct Scenario {
    strays: bool,
}

impl ValueGenerator for Scenario {
    type Output = (Vec<VpcExpose>, Vec<ProbeSpec>);

    fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        let exposes = PortForwardingExposes(MAX_EXPOSES).generate(driver)?;
        let mut probes = Vec::with_capacity(PROBES);
        for _ in 0..PROBES {
            let mut probe = ProbeSpec::generate(driver)?;
            if !self.strays {
                probe.clear_stray();
            }
            probes.push(probe);
        }
        Some((exposes, probes))
    }
}

/// Run a property inside a tokio runtime.
///
/// `FlowTable::insert` spawns a per-flow expiry timer, so an insert outside a runtime context
/// panics. Not paused: these properties are about the mapping, and `portfw::expiry` covers time.
fn with_runtime(body: impl FnOnce()) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap_or_else(|e| unreachable!("{e}"));
    let _guard = runtime.enter();
    body();
}

fn fabric(exposes: &[VpcExpose]) -> Option<Fabric> {
    let fabric = Fabric::build(exposes)?;
    fabric.is_probeable().then_some(fabric)
}

/// The destination half of a packet's five-tuple, which is what port forwarding rewrites.
fn destination_of(packet: &Packet<TestBuffer>) -> (IpAddr, u16) {
    (
        packet
            .ip_destination()
            .unwrap_or_else(|| unreachable!("a probe is always an ip packet")),
        packet.transport_dst_port().map_or(0, NonZero::get),
    )
}

/// The source half, for judging a reply.
fn source_of(packet: &Packet<TestBuffer>) -> (IpAddr, u16) {
    (
        packet
            .ip_source()
            .unwrap_or_else(|| unreachable!("a probe is always an ip packet")),
        packet.transport_src_port().map_or(0, NonZero::get),
    )
}

#[derive(Default)]
struct Tally {
    seen: AtomicUsize,
    built: AtomicUsize,
    reached: AtomicUsize,
}

impl Tally {
    /// Assert the run was not vacuous, on a floor relative to what was built rather than an
    /// absolute count, so the guard measures the property rather than the machine.
    fn report(&self, what: &str) {
        let (seen, built, reached) = (
            self.seen.load(Ordering::Relaxed),
            self.built.load(Ordering::Relaxed),
            self.reached.load(Ordering::Relaxed),
        );
        // See `masquerade::fuzz::Tally::report`, which this was copied from and which carries the
        // argument: `check!()` inside a closure returns from the closure, so under
        // `CARGO_BOLERO_SELECT` this runs with every count at zero and refuses the selection.
        if seen == 0 {
            return;
        }
        println!("{what}: {built}/{seen} configurations built, {reached} packets reached it");
        assert!(
            built * 2 >= seen,
            "only {built} of {seen} configurations built, so this checked much less than it looks \
             like it did"
        );
        assert!(
            reached > 0 && reached * 2 >= built,
            "{reached} packets reached the {what} assertion across {built} configurations; this \
             property has gone vacuous"
        );
    }
}

/// Send one inbound packet and report the destination it was forwarded to, if it was.
fn forward(
    fabric: &Fabric,
    lookup: &mut flow_entry::flow_table::FlowLookup,
    pfw: &mut crate::portfw::PortForwarder,
    probe: &crate::portfw::probe::Probe,
) -> Option<(IpAddr, u16)> {
    let before = probe.destination;
    let out = run(lookup, pfw, vec![probe.packet()], probe.arrival.dst_vpcd);
    let _ = fabric;
    if out[0].is_done() {
        return None;
    }
    let after = destination_of(&out[0]);
    (after != before).then_some(after)
}

/// A forwarded packet reaches an address the rule publishes it to, and the reply comes back as the
/// tuple the outside world used.
///
/// The headline property. The reply is the part that matters operationally: a port-forwarded
/// connection whose return traffic is not rewritten back to the published tuple is a connection the
/// client drops, because the reply appears to come from an address it never contacted.
#[test]
fn a_forwarded_packet_answers_as_the_published_tuple() {
    let tally = Tally::default();

    with_runtime(|| {
        bolero::check!()
            .with_generator(Scenario { strays: false })
            .cloned()
            .for_each(|(exposes, probes): (Vec<VpcExpose>, Vec<ProbeSpec>)| {
                tally.seen.fetch_add(1, Ordering::Relaxed);
                let Some(fabric) = fabric(&exposes) else {
                    return;
                };
                tally.built.fetch_add(1, Ordering::Relaxed);
                let (mut lookup, mut pfw) = fabric.stages();

                for spec in &probes {
                    let probe = (*spec).resolve(&fabric);
                    let published = probe.destination;
                    let Some(translated) = forward(&fabric, &mut lookup, &mut pfw, &probe) else {
                        continue;
                    };

                    let back = run(
                        &mut lookup,
                        &mut pfw,
                        vec![probe.reply(translated)],
                        Arrival::outbound().dst_vpcd,
                    );
                    assert_eq!(
                        source_of(&back[0]),
                        published,
                        "{published:?} was forwarded to {translated:?}, and the reply came back \
                         as {:?} instead of the tuple the client used",
                        source_of(&back[0])
                    );
                    tally.reached.fetch_add(1, Ordering::Relaxed);
                }
            });
    });

    tally.report("reversibility");
}

/// A forwarded packet lands inside the private side the rule names.
///
/// The containment claim, and the one that consults the configuration -- legitimately, as a
/// membership test rather than a prediction of which member.
///
/// This is the port-forwarding failure that matters most. A translation landing outside the
/// declared private range delivers unsolicited traffic from outside the fabric to an address inside
/// a tenant that never published it, which is a hole rather than a misroute.
#[test]
fn a_forwarded_packet_lands_inside_the_published_target() {
    let tally = Tally::default();

    with_runtime(|| {
        bolero::check!()
            .with_generator(Scenario { strays: false })
            .cloned()
            .for_each(|(exposes, probes): (Vec<VpcExpose>, Vec<ProbeSpec>)| {
                tally.seen.fetch_add(1, Ordering::Relaxed);
                let Some(fabric) = fabric(&exposes) else {
                    return;
                };
                tally.built.fetch_add(1, Ordering::Relaxed);
                let (mut lookup, mut pfw) = fabric.stages();

                for spec in &probes {
                    let probe = (*spec).resolve(&fabric);
                    let published = probe.destination;
                    let Some((addr, port)) = forward(&fabric, &mut lookup, &mut pfw, &probe) else {
                        continue;
                    };

                    assert!(
                        fabric.is_private(addr, port),
                        "{published:?} was forwarded to {addr}:{port}, which no rule names as a \
                         target; that address never published this service"
                    );
                    tally.reached.fetch_add(1, Ordering::Relaxed);
                }
            });
    });

    tally.report("containment");
}

/// Distinct published tuples reach distinct targets.
///
/// A port-forwarding rule maps one range onto another of the same size, positionally, so it is a
/// bijection by construction. Two published tuples collapsing onto one target would silently merge
/// two services, and the reverse mapping could then only answer one of them.
///
/// Enumerated rather than drawn: a collision is only visible across distinct inputs, and the
/// generator keeps both sides small enough to sweep.
#[test]
fn distinct_published_tuples_reach_distinct_targets() {
    let tally = Tally::default();

    with_runtime(|| {
        bolero::check!()
            .with_generator(Scenario { strays: false })
            .cloned()
            .for_each(|(exposes, _probes): (Vec<VpcExpose>, Vec<ProbeSpec>)| {
                tally.seen.fetch_add(1, Ordering::Relaxed);
                let Some(fabric) = fabric(&exposes) else {
                    return;
                };
                tally.built.fetch_add(1, Ordering::Relaxed);
                let (mut lookup, mut pfw) = fabric.stages();

                let mut taken: BTreeMap<(IpAddr, u16), (IpAddr, u16)> = BTreeMap::new();
                for (public, _private, tcp) in &fabric.rules {
                    let tcp = *tcp;
                    for (addr, port) in public.every() {
                        let mut packet =
                            crate::static_nat::probe::build(fabric.peer[0], addr, tcp, 1024, port);
                        Arrival::inbound().stamp(&mut packet);
                        let out = run(
                            &mut lookup,
                            &mut pfw,
                            vec![packet],
                            Arrival::inbound().dst_vpcd,
                        );
                        if out[0].is_done() {
                            continue;
                        }
                        let after = destination_of(&out[0]);
                        if after == (addr, port) {
                            continue;
                        }
                        if let Some(previous) = taken.insert(after, (addr, port)) {
                            assert_eq!(
                                previous,
                                (addr, port),
                                "published tuples {previous:?} and {:?} both reach {after:?}, so \
                                 two services share one target",
                                (addr, port)
                            );
                        }
                        tally.reached.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
    });

    tally.report("injectivity");
}

/// Nothing is forwarded that the configuration does not publish, or that did not ask to be.
///
/// Every reason a packet may not be forwarded, taken together: the destination is an address no rule
/// publishes, the port is outside the published range, the source vpc keys no rule, or nothing asked
/// for port forwarding at all.
///
/// The port-outside-range case is the sharp one. A rule publishes a *range*, and an off-by-one at
/// either end forwards a port the operator did not open -- which is the whole difference between a
/// port-forwarding rule and an open door.
///
/// # Three gates, not one
///
/// **No single edit opens that door.** A port past the published range is refused independently by
///
///   1. `RangeSet::lookup`, which bounds the sought port above,
///   2. `PortRange::contains` by way of `indexof`, which the mapping consults, and
///   3. the size-matched arithmetic in `map_port_to`, where an index past the source range has no
///      answer in the target range.
///
/// Breaking any one, or any two, still refuses the packet -- the property only fires with all three
/// broken at once. That is defence in depth rather than a redundant check, and it is the reason this
/// property looked vacuous at first: it is not, the code is simply hard to break here.
///
/// One observation from doing it: a packet whose port is outside the published range is dropped with
/// `DoneReason::InternalFailure`, which is not what happened. Nothing is internally broken -- the
/// operator did not publish that port. Attribution, not correctness.
#[test]
fn nothing_is_forwarded_that_was_not_published() {
    let tally = Tally::default();

    with_runtime(|| {
        bolero::check!()
            .with_generator(Scenario { strays: true })
            .cloned()
            .for_each(|(exposes, probes): (Vec<VpcExpose>, Vec<ProbeSpec>)| {
                tally.seen.fetch_add(1, Ordering::Relaxed);
                let Some(fabric) = fabric(&exposes) else {
                    return;
                };
                tally.built.fetch_add(1, Ordering::Relaxed);
                let (mut lookup, mut pfw) = fabric.stages();

                for spec in &probes {
                    let probe = (*spec).resolve(&fabric);
                    if probe.asks_for_forwarding() && probe.published {
                        continue;
                    }
                    let (before, stray) = (probe.destination, probe.stray);
                    let out = run(
                        &mut lookup,
                        &mut pfw,
                        vec![probe.packet()],
                        probe.arrival.dst_vpcd,
                    );

                    // Dropping is a legitimate answer for a packet no rule covers; forwarding it is
                    // not.
                    if !out[0].is_done() {
                        assert_eq!(
                            destination_of(&out[0]),
                            before,
                            "a packet to {before:?} was forwarded although {stray:?} meant no rule \
                             published it"
                        );
                    }
                    tally.reached.fetch_add(1, Ordering::Relaxed);
                }
            });
    });

    tally.report("permission");
}

/// Forwarding a destination leaves the source alone.
///
/// The frame condition. Port forwarding is destination NAT on this path, so a rewritten source would
/// be the stage reaching into the other half of the tuple -- and the reply, which is matched on that
/// source, would then have nowhere to go.
#[test]
fn forwarding_touches_only_the_destination() {
    let tally = Tally::default();

    with_runtime(|| {
        bolero::check!()
            .with_generator(Scenario { strays: false })
            .cloned()
            .for_each(|(exposes, probes): (Vec<VpcExpose>, Vec<ProbeSpec>)| {
                tally.seen.fetch_add(1, Ordering::Relaxed);
                let Some(fabric) = fabric(&exposes) else {
                    return;
                };
                tally.built.fetch_add(1, Ordering::Relaxed);
                let (mut lookup, mut pfw) = fabric.stages();

                for spec in &probes {
                    let probe = (*spec).resolve(&fabric);
                    let expected = (probe.source, probe.sport);
                    let out = run(
                        &mut lookup,
                        &mut pfw,
                        vec![probe.packet()],
                        probe.arrival.dst_vpcd,
                    );
                    if out[0].is_done() {
                        continue;
                    }

                    assert_eq!(
                        source_of(&out[0]),
                        expected,
                        "destination forwarding rewrote the source, so the reply has nowhere to go"
                    );
                    tally.reached.fetch_add(1, Ordering::Relaxed);
                }
            });
    });

    tally.report("frame");
}

/// A flow keeps the target it was first given.
///
/// The first packet of a flow consults the table and writes a flow pair; the second takes the fast
/// path through that pair. A stage that re-resolved would produce a legal-looking packet each time,
/// and a connection whose packets arrive at two different backends is broken in a way no
/// table-level test would see.
#[test]
fn a_forwarded_flow_keeps_its_target() {
    let tally = Tally::default();

    with_runtime(|| {
        bolero::check!()
            .with_generator(Scenario { strays: false })
            .cloned()
            .for_each(|(exposes, probes): (Vec<VpcExpose>, Vec<ProbeSpec>)| {
                tally.seen.fetch_add(1, Ordering::Relaxed);
                let Some(fabric) = fabric(&exposes) else {
                    return;
                };
                tally.built.fetch_add(1, Ordering::Relaxed);
                let (mut lookup, mut pfw) = fabric.stages();

                for spec in &probes {
                    let probe = (*spec).resolve(&fabric);
                    let Some(first) = forward(&fabric, &mut lookup, &mut pfw, &probe) else {
                        continue;
                    };
                    let Some(second) = forward(&fabric, &mut lookup, &mut pfw, &probe) else {
                        panic!(
                            "the second packet of a flow to {:?} was not forwarded at all, though \
                             the first reached {first:?}",
                            probe.destination
                        )
                    };

                    assert_eq!(
                        first, second,
                        "a flow to {:?} reached {first:?} and then {second:?}, so its packets are \
                         split across two backends",
                        probe.destination
                    );
                    tally.reached.fetch_add(1, Ordering::Relaxed);
                }
            });
    });

    tally.report("stability");
}
