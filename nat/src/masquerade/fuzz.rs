// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Properties of the masquerade network function, driven by generated configurations and packets.
//!
//! `static_nat::fuzz` covers a stage that is a pure function of its configuration. This one is not:
//! masquerade's answer for a flow is whatever the allocator handed out the first time it saw it,
//! and every property here is really about that state being kept consistently.
//!
//! # What can be asserted without an oracle
//!
//! Nothing here predicts which address and port a flow will be given -- that is the allocator's
//! business and predicting it would be a second copy of it. What can be said is how the answers
//! relate to each other and to the configuration:
//!
//! * the reply to a translated flow comes back to where the flow started (**reversibility**);
//! * the same flow gets the same answer every time (**stability**);
//! * two flows never get the same answer at once (**exclusivity**);
//! * every answer is inside a range the configuration named (**containment**).
//!
//! Containment is the one that consults the configuration, and legitimately: it is a statement that
//! the output is a member of a declared set, not a prediction of which member. An allocator handing
//! out an address nobody gave it is the failure that check exists for.
//!
//! # No timers
//!
//! Every property completes within one flow lifetime, so none depends on expiry either happening or
//! not. Expiry is a separate subject and needs the explicitly driven clock the development guide
//! asks for, rather than a wall clock a property happens to outrun.

#![cfg(test)]

use crate::masquerade::probe::{Arrival, Fabric, ProbeSpec, Stray, run};
use bolero::{Driver, TypeGenerator, ValueGenerator};
use concurrency::sync::atomic::{AtomicUsize, Ordering};
use config::external::overlay::vpcpeering::VpcExpose;
use config::external::overlay::vpcpeering::contract::MasqueradeExposes;
use net::buffer::TestBuffer;
use net::packet::Packet;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::num::NonZero;

/// Exposes per configuration.
const MAX_EXPOSES: u8 = 3;

// A *ratio*, and no absolute floor. An absolute one measures how fast the machine was: coverage
// instrumentation slowed a run to 3 reaching flows across 1 configuration, which satisfies the
// ratio and failed `reached >= 8`. What the guard is for is a property that has stopped reaching
// its assertion, and a collapse to zero shows up in `reached > 0`.

/// Flows per configuration.
const PROBES: usize = 8;

/// A configuration and a batch of flows to put through it.
#[derive(Debug, Clone, Copy)]
struct Scenario {
    strays: bool,
}

impl ValueGenerator for Scenario {
    type Output = (Vec<VpcExpose>, Vec<ProbeSpec>);

    fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        let exposes = MasqueradeExposes(MAX_EXPOSES).generate(driver)?;

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
/// panics. The existing masquerade tests get one from `#[tokio::test]`; a bolero property's body is
/// synchronous, so it enters a runtime rather than becoming async.
///
/// A current-thread runtime with time enabled, and nothing ever awaits it: the timers exist so that
/// spawning them succeeds, and every property here finishes well inside the shortest flow timeout.
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

/// The source half of a packet's five-tuple.
fn source_of(packet: &Packet<TestBuffer>) -> (IpAddr, u16) {
    (
        packet
            .ip_source()
            .unwrap_or_else(|| unreachable!("a probe is always an ip packet")),
        packet.transport_src_port().map_or(0, NonZero::get),
    )
}

/// The destination half.
fn destination_of(packet: &Packet<TestBuffer>) -> (IpAddr, u16) {
    (
        packet
            .ip_destination()
            .unwrap_or_else(|| unreachable!("a probe is always an ip packet")),
        packet.transport_dst_port().map_or(0, NonZero::get),
    )
}

/// How much of a run actually reached the code under test.
#[derive(Default)]
struct Tally {
    seen: AtomicUsize,
    built: AtomicUsize,
    reached: AtomicUsize,
}

impl Tally {
    /// Assert the run was not vacuous.
    ///
    /// The floor is **relative to the configurations actually built**, not an absolute count, because
    /// an absolute one is really a measure of how fast the machine was. A property that reached
    /// thousands of flows alone can reach a few dozen when it runs beside nine hundred other
    /// tests on a loaded machine or under coverage instrumentation, and a floor tuned to the fast
    /// case then fails for a reason that has nothing to do with the code under test.
    ///
    /// Both counts scale with the iteration budget, so their ratio does not. What the guard is for is
    /// a property that has stopped reaching its assertion at all -- and a collapse to zero is just as
    /// visible in the ratio.
    fn report(&self, what: &str) {
        let (seen, built, reached) = (
            self.seen.load(Ordering::Relaxed),
            self.built.load(Ordering::Relaxed),
            self.reached.load(Ordering::Relaxed),
        );
        // `cargo bolero` runs the test binary once with `CARGO_BOLERO_SELECT` set, purely to find
        // out which fuzz targets it holds. `check!()` registers itself and returns without drawing
        // anything, so this runs with every count at zero -- and the vacuity guard below, right
        // about a property that drew cases and reached none, is wrong about one that never drew a
        // case at all. Asserting on that pass refuses the *selection*, and the target can then
        // never be fuzzed.
        //
        // `static_nat::fuzz` avoids this without a guard, and only by accident: its `check!()` sits
        // at the body scope of `drive_*`, so bolero's `return` leaves the function before `report`
        // runs. Here `check!()` is inside a closure, so the `return` leaves only the closure.
        if seen == 0 {
            return;
        }
        println!("{what}: {built}/{seen} configurations built, {reached} flows reached it");
        assert!(
            built * 2 >= seen,
            "only {built} of {seen} configurations built, so this checked much less than it looks \
             like it did"
        );
        // At least one reaching flows for every two configurations built, and never zero.
        assert!(
            reached > 0 && reached * 2 >= built,
            "{reached} flows reached the {what} assertion across {built} configurations; \
             this property has gone vacuous"
        );
    }
}

/// The reply to a masqueraded flow comes back to where the flow started.
///
/// The stateful analogue of static NAT's round trip, and it works quite differently. There is no
/// second table built from the other side of the peering: the reverse translation exists only
/// because the forward packet created a flow entry holding it, `FlowLookup` finds that entry, and
/// `Masquerade` applies it.
///
/// So this is a statement about state rather than about configuration -- whatever the allocator
/// chose, the entry it wrote down has to describe the inverse of what was done to the packet. A
/// forward translation that is not faithfully recorded is a connection that never gets an answer,
/// which is the characteristic masquerade failure and is invisible to any test of the allocator on
/// its own.
#[test]
fn a_masqueraded_flow_comes_back() {
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
                let (mut lookup, mut masq) = fabric.stages();

                for spec in &probes {
                    let probe = (*spec).resolve(&fabric);
                    let before = (probe.source, probe.sport);
                    let out = run(
                        &mut lookup,
                        &mut masq,
                        vec![probe.packet()],
                        probe.arrival.dst_vpcd,
                    );
                    let after = source_of(&out[0]);
                    if after == before || out[0].is_done() {
                        continue;
                    }

                    let back = run(
                        &mut lookup,
                        &mut masq,
                        vec![probe.reply(after.0, after.1)],
                        Arrival::inbound().dst_vpcd,
                    );
                    assert_eq!(
                        destination_of(&back[0]),
                        before,
                        "{:?} was masqueraded to {after:?}, and the reply came back to {:?}",
                        before,
                        destination_of(&back[0])
                    );
                    tally.reached.fetch_add(1, Ordering::Relaxed);
                }
            });
    });

    tally.report("reversibility");
}

/// A flow keeps the translation it was first given.
///
/// The second packet of a flow takes a different path from the first: the first allocates and
/// writes a flow entry, the second finds that entry and reuses it. A stage that allocated again
/// would still produce a legal-looking packet, and the connection would break in a way nothing at
/// the allocator level could see -- the two allocations are individually correct.
#[test]
fn a_flow_keeps_its_translation() {
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
            let (mut lookup, mut masq) = fabric.stages();

            for spec in &probes {
                let probe = (*spec).resolve(&fabric);
                let before = (probe.source, probe.sport);
                let first = run(&mut lookup, &mut masq, vec![probe.packet()], probe.arrival.dst_vpcd);
                if out_unchanged(&first, before) {
                    continue;
                }
                let second = run(&mut lookup, &mut masq, vec![probe.packet()], probe.arrival.dst_vpcd);

                assert_eq!(
                    source_of(&second[0]),
                    source_of(&first[0]),
                    "the same flow from {before:?} was given {:?} and then {:?}, so its reply can \
                     only reach one of them",
                    source_of(&first[0]),
                    source_of(&second[0])
                );
                tally.reached.fetch_add(1, Ordering::Relaxed);
            }
        });
    });

    tally.report("stability");
}

/// Whether a batch's first packet came out as it went in.
fn out_unchanged(out: &[Packet<TestBuffer>], before: (IpAddr, u16)) -> bool {
    out[0].is_done() || source_of(&out[0]) == before
}

//= https://www.rfc-editor.org/rfc/rfc5382#section-8
//= type=test
//# REQ-7:  A NAT MUST NOT have a "Port assignment" behavior of "Port
//# overloading" for TCP.
/// Two live flows never share a translation.
///
/// The exclusivity claim the allocator exists to keep, stated where it matters: at the stage, over
/// packets, with the flow table in the loop. Two flows sharing an address and port are
/// indistinguishable on the way back, so one of them receives the other's traffic -- a tenant
/// isolation failure rather than a routing one.
///
/// Distinct source *ports* as well as addresses, since masquerade puts many private addresses behind
/// few public ones and the port is what keeps them apart once the addresses have collapsed.
#[test]
fn distinct_flows_do_not_share_a_translation() {
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
            let (mut lookup, mut masq) = fabric.stages();

            let mut taken: BTreeMap<(IpAddr, u16), (IpAddr, u16)> = BTreeMap::new();
            for (index, spec) in probes.iter().enumerate() {
                let mut probe = (*spec).resolve(&fabric);
                // A distinct port per probe, so that repeated draws are still distinct flows and
                // the property is about contention rather than about the draw.
                probe.sport = u16::try_from(1024 + index).unwrap_or(1024);
                let before = (probe.source, probe.sport);
                let out = run(&mut lookup, &mut masq, vec![probe.packet()], probe.arrival.dst_vpcd);
                if out_unchanged(&out, before) {
                    continue;
                }
                let after = source_of(&out[0]);

                if let Some(previous) = taken.insert(after, before) {
                    assert_eq!(
                        previous, before,
                        "flows from {previous:?} and {before:?} were both masqueraded to {after:?}, \
                         so a reply can only reach one of them"
                    );
                }
                tally.reached.fetch_add(1, Ordering::Relaxed);
            }
        });
    });

    tally.report("exclusivity");
}

/// Every translation lands inside a range the configuration named.
///
/// The containment claim, and the one place a property here looks at the configuration. It is a
/// membership test rather than a prediction: which public address a flow gets is the allocator's
/// business, but *some* public address the operator declared is not negotiable.
///
/// An address from outside the declared set is not merely wrong, it is unroutable -- the fabric has
/// no path back to it, so the flow is a blackhole that looks like a successful translation from
/// inside the box.
#[test]
fn a_translation_stays_inside_the_public_range() {
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
                let (mut lookup, mut masq) = fabric.stages();

                for spec in &probes {
                    let probe = (*spec).resolve(&fabric);
                    let before = (probe.source, probe.sport);
                    let out = run(
                        &mut lookup,
                        &mut masq,
                        vec![probe.packet()],
                        probe.arrival.dst_vpcd,
                    );
                    if out_unchanged(&out, before) {
                        continue;
                    }
                    let (addr, port) = source_of(&out[0]);

                    assert!(
                        fabric.is_public(addr),
                        "{before:?} was masqueraded to {addr}:{port}, which no expose offers; the \
                     fabric has no route back to it"
                    );
                    tally.reached.fetch_add(1, Ordering::Relaxed);
                }
            });
    });

    tally.report("containment");
}

/// Nothing is masqueraded that did not ask to be.
///
/// The same precondition claim as static NAT's, over masquerade's own flags. Getting this wrong is
/// worse here than there, because a translation is not just applied but *recorded*: a packet
/// masqueraded without permission leaves a flow entry behind that will keep translating its
/// successors long after the mistaken packet is gone.
#[test]
fn nothing_is_masqueraded_without_permission() {
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
            let (mut lookup, mut masq) = fabric.stages();

            for spec in &probes {
                let probe = (*spec).resolve(&fabric);
                if probe.asks_for_translation() && probe.exposed {
                    continue;
                }
                let before = (probe.source, probe.sport);
                let (stray, arrival) = (probe.stray, probe.arrival);
                let out = run(&mut lookup, &mut masq, vec![probe.packet()], probe.arrival.dst_vpcd);

                // A dropped packet is a legitimate answer for a flow the configuration cannot
                // place; what is not legitimate is translating it.
                if out[0].is_done() {
                    tally.reached.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                assert_eq!(
                    source_of(&out[0]),
                    before,
                    "masquerade translated {before:?} although {stray:?} forbade it; the packet \
                     arrived as {arrival:?}"
                );
                tally.reached.fetch_add(1, Ordering::Relaxed);
            }
        });
    });

    tally.report("permission");
}

/// A flow that cannot be masqueraded is dropped, and says why.
///
/// Same obligation as everywhere else, and masquerade has an unusually rich failure vocabulary --
/// no allocator, allocation refused, capacity exceeded, unsupported protocol -- so the assertion is
/// that *some* reason is attached rather than which. What it rules out is the silent pass, which
/// here means letting a private address out onto the fabric untranslated.
#[test]
fn a_flow_that_cannot_be_masqueraded_says_so() {
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
            let (mut lookup, mut masq) = fabric.stages();

            for spec in &probes {
                let probe = (*spec).resolve(&fabric);
                // The flows the configuration genuinely cannot place: a source it never named, or a
                // vpc pair it has no allocator for. Masquerade must not simply forward these.
                let unplaceable = matches!(
                    probe.stray,
                    Some(Stray::SourceNotExposed | Stray::UnknownSourceVni | Stray::UnknownDestVni)
                );
                if !unplaceable {
                    continue;
                }
                let before = (probe.source, probe.sport);
                let stray = probe.stray;
                let out = run(&mut lookup, &mut masq, vec![probe.packet()], probe.arrival.dst_vpcd);
                let packet = &out[0];

                assert!(
                    packet.is_done(),
                    "a flow from {before:?} with {stray:?} passed masquerade with no verdict, so \
                     a private address reaches the fabric untranslated"
                );
                tally.reached.fetch_add(1, Ordering::Relaxed);
            }
        });
    });

    tally.report("attribution");
}
