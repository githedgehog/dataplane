// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Properties of the static NAT network function, driven by generated configurations and packets.
//!
//! `setup::config_driven` already proves the *mapping* correct by enumeration: it builds the tables
//! a generated expose implies and checks that the two sides pair up one to one. Nothing there
//! touches a packet, a `Packet`'s metadata, or [`StaticNat`] itself.
//!
//! This module covers the rest of the stage, which is the half where the decisions live:
//!
//! * whether the mapping is applied to the packet's headers at all, and to which ones;
//! * whether it is applied when the arrival state does not ask for it, or forbids it;
//! * whether a packet it cannot look up is dropped with a reason or silently; and
//! * whether the two independently built halves of one expose still agree once each has been
//!   applied to a real packet by real code.
//!
//! # No oracle
//!
//! None of these predicts what a source address should translate to. Each is either a metamorphic
//! relation -- a statement about how two runs relate -- or an invariant over one run's output.
//! Following the development guide's decomposition, the `config -> tables` half gets a differential
//! oracle by enumeration and the per-packet half gets relations, and the two compose without
//! anything needing to know the answer in advance. A property here that had to predict an address
//! would be a second copy of `RangeBuilder`, and two copies disagree.
//!
//! # Vacuity
//!
//! The failure mode that matters is not a wrong assertion but an assertion that never runs. A probe
//! that misses every table satisfies most of what follows trivially, and a generated overlay that
//! fails to validate satisfies all of it. Each property counts what it actually exercised and
//! asserts a floor on that count, so a change that quietly stops reaching the code leaves a failing
//! test rather than a green one.

#![cfg(test)]

use crate::static_nat::nf::StaticNat;
use crate::static_nat::probe::{Fabric, ProbeSpec, Stray};
use bolero::{Driver, TypeGenerator, ValueGenerator};
use concurrency::sync::atomic::{AtomicUsize, Ordering};
use config::external::overlay::vpcpeering::VpcExpose;
use config::external::overlay::vpcpeering::contract::StaticNatExposes;
use net::buffer::TestBuffer;
use net::ip::NextHeader;
use net::packet::{DoneReason, Packet};
use pipeline::NetworkFunction;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::num::NonZero;

/// Exposes per configuration. More than one is what makes the tables hold several rules, which is
/// where a longest-prefix match has a choice to get wrong.
const MAX_EXPOSES: u8 = 3;

/// The fewest reaching draws any property may see before it is considered vacuous.
const MIN_REACHED: usize = 8;

/// Probes per configuration. Building the configuration costs far more than resolving a probe
/// against it, so a batch amortizes the expensive half over the interesting one.
const PROBES: usize = 8;

/// A configuration and a batch of packets to put through it.
///
/// The two halves are drawn from the same driver but independently of each other: a [`ProbeSpec`]
/// is indices and raw values, and means something only once [`ProbeSpec::resolve`] interprets it
/// against the fabric the exposes built.
#[derive(Debug, Clone, Copy)]
struct Scenario {
    /// Whether probes may deviate from a packet the configuration translates.
    ///
    /// Off for the properties that are about the mapping surviving the round trip, since a probe
    /// that is meant to miss has nothing to round trip; on for the ones about the stage's own
    /// decisions, which is all a stray exercises.
    strays: bool,
    /// Which flavour of expose to draw.
    exposes: StaticNatExposes,
}

impl Scenario {
    /// Address-to-address exposes, taking the mapping down `AddrTranslationValue`.
    fn addresses(strays: bool) -> Self {
        Self {
            strays,
            exposes: StaticNatExposes::addresses_only(MAX_EXPOSES),
        }
    }

    /// Exposes carrying port ranges, taking the mapping down `PortAddrTranslationValue` instead.
    ///
    /// A separate property per flavour rather than one over a mix. A mixed property reaches each
    /// path eventually; one that asks for a path reaches it every time and says in its name which
    /// one failed.
    fn ports(strays: bool) -> Self {
        Self {
            strays,
            exposes: StaticNatExposes::with_ports(MAX_EXPOSES),
        }
    }
}

impl ValueGenerator for Scenario {
    type Output = (Vec<VpcExpose>, Vec<ProbeSpec>);

    fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        let exposes = self.exposes.generate(driver)?;

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

/// Put a batch through the stage and collect what comes out.
///
/// Nothing is filtered: every probe carries `keep`, so a packet the stage drops still appears in
/// the output with its reason attached. Without that a drop is indistinguishable from a
/// pass-through, and half of what follows could not be stated.
fn run(nf: &mut StaticNat, packets: Vec<Packet<TestBuffer>>) -> Vec<Packet<TestBuffer>> {
    nf.process(packets.into_iter()).collect()
}

/// Build the fabric a scenario describes, or report that the overlay was refused.
///
/// A refusal is legitimate: each expose is valid on its own by construction, but two of them may
/// overlap, and a manifest rejects that. Callers count refusals rather than ignoring them.
fn fabric(exposes: &[VpcExpose]) -> Option<Fabric> {
    let fabric = Fabric::build(exposes)?;
    fabric.is_probeable().then_some(fabric)
}

/// The source half of a packet's five-tuple.
///
/// Address and port together, because that is the granularity static NAT maps at once an expose
/// carries port ranges: comparing addresses alone would call a translation that moved only the port
/// "unchanged", and every property below would then skip it.
fn five_tuple_source(packet: &Packet<TestBuffer>) -> (IpAddr, u16) {
    (
        packet
            .ip_source()
            .unwrap_or_else(|| unreachable!("a probe is always an ip packet")),
        packet.transport_src_port().map_or(0, NonZero::get),
    )
}

/// The destination half, for judging a reply.
fn five_tuple_destination(packet: &Packet<TestBuffer>) -> (IpAddr, u16) {
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
    /// Scenarios drawn.
    seen: AtomicUsize,
    /// Scenarios whose overlay validated and built a non-empty table.
    built: AtomicUsize,
    /// Probes that reached the assertion the property is about.
    reached: AtomicUsize,
}

impl Tally {
    /// Assert the run was not vacuous.
    ///
    /// The floor is **relative to the configurations actually built**, not an absolute count, because
    /// an absolute one is really a measure of how fast the machine was. A property that reached
    /// thousands of probes alone can reach a few dozen when it runs beside nine hundred other
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
        // anything, so this runs with every count at zero -- and the vacuity guard below, which is
        // right about a property that drew cases and reached none, is wrong about one that never
        // drew a case at all. Asserting on that pass refuses the *selection*, so the target can
        // never be fuzzed: the whole of `nat` was unreachable through `just fuzz` until this
        // returned early.
        if seen == 0 {
            return;
        }
        println!("{what}: {built}/{seen} configurations built, {reached} probes reached it");
        assert!(
            built * 2 >= seen,
            "only {built} of {seen} configurations built, so this checked much less than it looks \
             like it did"
        );
        // At least one reaching probes for every two configurations built, and never zero.
        assert!(
            reached >= MIN_REACHED && reached * 2 >= built,
            "{reached} probes reached the {what} assertion across {built} configurations; \
             this property has gone vacuous"
        );
    }
}

/// A translated source comes back to where it started.
///
/// The headline property, and the one that needs two tables. A packet leaving the local vpc has its
/// source rewritten by that vpc's table, which was built from the *local* side of the peering. The
/// reply arrives at the peer, whose table rewrites destinations and was built from the *remote*
/// side of the same peering -- a separate pass over separate data, by a separate code path
/// (`find_dst_mapping` against `dst_nat` rather than `find_src_mapping` against `src_nat`).
///
/// So this is the one statement that ties the two halves together, and it is stated without knowing
/// what either produces: whatever the first one did, the second must undo.
///
/// The development guide names this relation directly -- *translate then reverse is the identity on
/// the five-tuple* -- as the per-packet half of the decomposition.
/// `bolero::check!()` takes its target name from the function it is written in -- `item_path` in
/// `bolero_engine`, which walks up from a marker item defined at the macro site. A `check!()` shared
/// by several tests therefore registers one target named after the *shared* function, which is not
/// a `#[test]` and so resolves to nothing when `cargo bolero` goes to run it. Every property in this
/// module was listed by `cargo bolero list` and none could be selected.
///
/// Expanding the driver into each test puts the `check!()` inside a real test function, so each gets
/// a target of its own. The scenario stays injected and the case body is untouched: what changed is
/// where the macro is expanded, not what the property says.
macro_rules! drive_round_trip {
    ($scenario:expr) => {{
    let tally = Tally::default();

    bolero::check!().with_generator($scenario).cloned().for_each(
        |(exposes, probes): (Vec<VpcExpose>, Vec<ProbeSpec>)| {
            tally.seen.fetch_add(1, Ordering::Relaxed);
            let Some(fabric) = fabric(&exposes) else {
                return;
            };
            tally.built.fetch_add(1, Ordering::Relaxed);
            let mut nf = fabric.nf();

            for spec in &probes {
                let mut probe = (*spec).resolve(&fabric);
                let (source, sport) = (probe.source, probe.sport);
                let out = run(&mut nf, vec![probe.take()]);
                let (translated, translated_port) = five_tuple_source(&out[0]);

                // An exposed source the tables do not cover is not a finding here: the mapping's
                // completeness is proved by enumeration in `setup::config_driven`. This property is
                // about what happens once a translation has occurred.
                if (translated, translated_port) == (source, sport) {
                    continue;
                }

                let back = run(&mut nf, vec![probe.reply(translated, translated_port)]);
                let (returned, returned_port) = five_tuple_destination(&back[0]);

                assert_eq!(
                    (returned, returned_port),
                    (source, sport),
                    "{source}:{sport} translated to {translated}:{translated_port} on the way out, \
                     and the reply came back to {returned}:{returned_port}"
                );
                tally.reached.fetch_add(1, Ordering::Relaxed);
            }
        },
    );

    tally.report("round trip");
}};
}

#[test]
fn a_translated_source_comes_back() {
    drive_round_trip!(Scenario::addresses(false));
}

/// The same, where the mapping moves the port as well as the address.
///
/// A second code path entirely -- `PortAddrTranslationValue` rather than `AddrTranslationValue` --
/// and the harder one, since the two sides may divide their common total between addresses and
/// ports differently. A `/32` carrying 64 ports is a legal answer to a `/30` carrying 16, so the
/// reverse mapping cannot recover the address without also accounting for the port.
#[test]
fn a_translated_source_and_port_come_back() {
    drive_round_trip!(Scenario::ports(false));
}

/// Two sources that differ stay different after translation.
///
/// Static NAT is one-to-one by definition, so a collision is a tenant isolation defect rather than a
/// performance one: two flows arriving at the peer as the same address and port are
/// indistinguishable to everything downstream, including the reverse mapping.
///
/// `setup::config_driven` proves the *table* injective. This proves the stage is, which is a
/// different claim: the table could be right and the write to the packet's headers wrong, and no
/// table-level property would see it.
macro_rules! drive_injectivity {
    ($scenario:expr) => {{
    let tally = Tally::default();

    bolero::check!().with_generator($scenario).cloned().for_each(
        |(exposes, _probes): (Vec<VpcExpose>, Vec<ProbeSpec>)| {
            tally.seen.fetch_add(1, Ordering::Relaxed);
            let Some(fabric) = fabric(&exposes) else {
                return;
            };
            tally.built.fetch_add(1, Ordering::Relaxed);
            let mut nf = fabric.nf();

            // Everything the configuration maps, not the drawn probes: the draws may repeat, and a
            // collision is only visible across distinct inputs.
            let sources = fabric.every_source();
            let batch: Vec<Packet<TestBuffer>> = sources
                .iter()
                .map(|(endpoint, port)| fabric.outbound_to_peer(*endpoint, *port))
                .collect();
            let out = run(&mut nf, batch);

            let mut taken: BTreeMap<(IpAddr, u16), (IpAddr, u16)> = BTreeMap::new();
            for ((endpoint, port), packet) in sources.iter().zip(out.iter()) {
                let before = (endpoint.addr, *port);
                let after = five_tuple_source(packet);
                if after == before {
                    continue;
                }
                if let Some(previous) = taken.insert(after, before) {
                    let (addr, port) = after;
                    let (pa, pp) = previous;
                    let (ba, bp) = before;
                    panic!(
                        "{ba}:{bp} and {pa}:{pp} both translated to {addr}:{port}, so static NAT \
                         is not one to one for {exposes:#?}"
                    );
                }
                tally.reached.fetch_add(1, Ordering::Relaxed);
            }
        },
    );

    tally.report("injectivity");
}};
}

#[test]
fn distinct_sources_stay_distinct() {
    drive_injectivity!(Scenario::addresses(false));
}

/// The same over address-and-port pairs.
///
/// Sweeping addresses alone here would check a diagonal of the space and call it injective: with
/// port ranges the thing the mapping is one to one over is the pair, so two ports on one address
/// colliding is a defect an address-only sweep cannot see.
#[test]
fn distinct_sources_and_ports_stay_distinct() {
    drive_injectivity!(Scenario::ports(false));
}

/// Translating the source leaves everything else alone.
///
/// The frame condition for this stage, and it differs between the two paths -- which is the point of
/// stating it per flavour rather than once. With no port range on the expose the transport ports are
/// part of the frame and a rewrite would be a mapping reaching further than it was configured to;
/// with one they are part of what is being translated, and only the destination and the protocol
/// remain.
///
/// The destination matters in both. The local vpc's table also holds a destination half, built from
/// its peer's manifest; the peer offers no translation, so an outbound packet's destination must come
/// through untouched, and a rewrite would mean the two halves of the table are bleeding into each
/// other.
macro_rules! drive_frame {
    ($scenario:expr) => {{
        let tally = Tally::default();

        bolero::check!()
            .with_generator($scenario)
            .cloned()
            .for_each(|(exposes, probes): (Vec<VpcExpose>, Vec<ProbeSpec>)| {
                tally.seen.fetch_add(1, Ordering::Relaxed);
                let Some(fabric) = fabric(&exposes) else {
                    return;
                };
                tally.built.fetch_add(1, Ordering::Relaxed);
                let mut nf = fabric.nf();

                for spec in &probes {
                    let mut probe = (*spec).resolve(&fabric);
                    let (destination, sport, dport) = (probe.destination, probe.sport, probe.dport);
                    let proto = if probe.tcp {
                        NextHeader::TCP
                    } else {
                        NextHeader::UDP
                    };
                    let out = run(&mut nf, vec![probe.take()]);
                    let packet = &out[0];

                    assert_eq!(
                        packet.ip_destination(),
                        Some(destination),
                        "source translation rewrote the destination"
                    );
                    assert_eq!(
                        packet.transport_dst_port().map(NonZero::get),
                        Some(dport),
                        "source translation rewrote the destination port"
                    );
                    assert_eq!(
                        packet.ip_proto(),
                        Some(proto),
                        "source translation changed the transport protocol"
                    );
                    if !fabric.uses_ports {
                        assert_eq!(
                            packet.transport_src_port().map(NonZero::get),
                            Some(sport),
                            "source translation rewrote the source port, which no expose asked for"
                        );
                    }
                    tally.reached.fetch_add(1, Ordering::Relaxed);
                }
            });

        tally.report("frame");
    }};
}

#[test]
fn translation_touches_only_the_source() {
    drive_frame!(Scenario::addresses(false));
}

#[test]
fn port_translation_touches_only_the_source() {
    drive_frame!(Scenario::ports(false));
}

/// Nothing is translated that did not ask to be.
///
/// The arrival state is the stage's precondition, and every flag in it is a decision an upstream
/// stage made. `requires_static_nat_src` says this packet is to be translated; `is_src_natted` says
/// something already has. Ignoring either means translating a packet twice, or translating one the
/// pipeline had decided to leave alone -- both of which produce an address the reverse mapping
/// cannot undo.
///
/// A source the exposes do not offer is the same claim from the other side: the stage may only act
/// on what the configuration named.
macro_rules! drive_permission {
    ($scenario:expr) => {{
    let tally = Tally::default();

    bolero::check!().with_generator($scenario).cloned().for_each(
        |(exposes, probes): (Vec<VpcExpose>, Vec<ProbeSpec>)| {
            tally.seen.fetch_add(1, Ordering::Relaxed);
            let Some(fabric) = fabric(&exposes) else {
                return;
            };
            tally.built.fetch_add(1, Ordering::Relaxed);
            let mut nf = fabric.nf();

            for spec in &probes {
                let mut probe = (*spec).resolve(&fabric);
                // Every reason a probe may not be translated, taken together: the request was not
                // made, an earlier stage already made it, the annotations needed to answer it are
                // missing or name something the configuration does not have, or the source is an
                // address no expose offers. Whichever it is, the source must come out as it went in.
                if probe.asks_for_translation() && probe.exposed {
                    continue;
                }

                let (source, sport) = (probe.source, probe.sport);
                let (stray, arrival) = (probe.stray, probe.arrival);
                let out = run(&mut nf, vec![probe.take()]);

                assert_eq!(
                    five_tuple_source(&out[0]),
                    (source, sport),
                    "static NAT translated {source}:{sport} although {stray:?} forbade it; the \
                     packet arrived as {arrival:?}"
                );
                tally.reached.fetch_add(1, Ordering::Relaxed);
            }
        },
    );

    tally.report("permission");
}};
}

#[test]
fn nothing_is_translated_without_permission() {
    drive_permission!(Scenario::addresses(true));
}

#[test]
fn no_port_is_translated_without_permission() {
    drive_permission!(Scenario::ports(true));
}

/// A packet the stage cannot look up is dropped, and says why.
///
/// The dataplane's universal obligation, and the cheapest one to state: an outcome the operator can
/// see beats a correct outcome nobody can explain. `DoneReason` is the vocabulary, so the assertion
/// is that the packet carries one and that it is the one that describes what happened.
///
/// A silent pass here is the real failure: a packet whose source vpc is unknown has no table, so
/// letting it through means forwarding untranslated traffic under a configuration that never
/// mentioned it.
macro_rules! drive_attribution {
    ($scenario:expr) => {{
    let tally = Tally::default();

    bolero::check!().with_generator($scenario).cloned().for_each(
        |(exposes, probes): (Vec<VpcExpose>, Vec<ProbeSpec>)| {
            tally.seen.fetch_add(1, Ordering::Relaxed);
            let Some(fabric) = fabric(&exposes) else {
                return;
            };
            tally.built.fetch_add(1, Ordering::Relaxed);
            let mut nf = fabric.nf();

            for spec in &probes {
                let mut probe = (*spec).resolve(&fabric);
                let unroutable = matches!(
                    probe.stray,
                    Some(Stray::NoSourceVni | Stray::UnknownSourceVni)
                );
                if !unroutable {
                    continue;
                }

                let (source, stray) = (probe.source, probe.stray);
                let out = run(&mut nf, vec![probe.take()]);

                let reason = out[0].get_done().unwrap_or_else(|| {
                    panic!(
                        "a packet with {stray:?} passed static NAT with no verdict at all, so \
                         {source} would be forwarded untranslated"
                    )
                });
                assert_eq!(
                    reason,
                    DoneReason::Unroutable,
                    "a packet with {stray:?} was dropped for {reason:?}, which does not describe \
                     what happened to it"
                );
                tally.reached.fetch_add(1, Ordering::Relaxed);
            }
        },
    );

    tally.report("attribution");
}};
}

#[test]
fn a_packet_that_cannot_be_looked_up_says_so() {
    drive_attribution!(Scenario::addresses(true));
}

/// A packet whose five-tuple changed is marked as having changed.
///
/// Static NAT rewrites headers in place and leaves the transport checksum stale, relying on
/// `checksum_refresh` to have a later stage fix it. So the mark is not bookkeeping: a translated
/// packet that is not marked goes out with a checksum for the addresses it no longer carries, and is
/// discarded by the receiver rather than by anything that could report it.
///
/// `is_src_natted` carries the same weight in the other direction -- it is what stops a second NAT
/// stage translating the packet again.
macro_rules! drive_marking {
    ($scenario:expr) => {{
    let tally = Tally::default();

    bolero::check!().with_generator($scenario).cloned().for_each(
        |(exposes, probes): (Vec<VpcExpose>, Vec<ProbeSpec>)| {
            tally.seen.fetch_add(1, Ordering::Relaxed);
            let Some(fabric) = fabric(&exposes) else {
                return;
            };
            tally.built.fetch_add(1, Ordering::Relaxed);
            let mut nf = fabric.nf();

            for spec in &probes {
                let mut probe = (*spec).resolve(&fabric);
                let before = (probe.source, probe.sport);
                let out = run(&mut nf, vec![probe.take()]);
                let packet = &out[0];

                if five_tuple_source(packet) == before {
                    continue;
                }
                let (source, sport) = before;

                assert!(
                    packet.meta().is_src_natted(),
                    "{source}:{sport} was translated without the source-natted mark, so a later \
                     stage would translate it again"
                );
                assert!(
                    packet.meta().checksum_refresh(),
                    "{source}:{sport} was translated without asking for a checksum refresh, so the \
                     packet goes out with a checksum for headers it no longer carries"
                );
                tally.reached.fetch_add(1, Ordering::Relaxed);
            }
        },
    );

    tally.report("marking");
}};
}

#[test]
fn a_modified_packet_is_always_marked() {
    drive_marking!(Scenario::addresses(true));
}

#[test]
fn a_port_modified_packet_is_always_marked() {
    drive_marking!(Scenario::ports(true));
}
