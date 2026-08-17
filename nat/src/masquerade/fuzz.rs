// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

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

const MAX_EXPOSES: u8 = 3;

const MIN_REACHED: usize = 8;

const PROBES: usize = 8;

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

fn source_of(packet: &Packet<TestBuffer>) -> (IpAddr, u16) {
    (
        packet
            .ip_source()
            .unwrap_or_else(|| unreachable!("a probe is always an ip packet")),
        packet.transport_src_port().map_or(0, NonZero::get),
    )
}

fn destination_of(packet: &Packet<TestBuffer>) -> (IpAddr, u16) {
    (
        packet
            .ip_destination()
            .unwrap_or_else(|| unreachable!("a probe is always an ip packet")),
        packet.transport_dst_port().map_or(0, NonZero::get),
    )
}

#[derive(Default)]
struct Tally {
    seen: AtomicUsize,
    built: AtomicUsize,
    reached: AtomicUsize,
}

impl Tally {
    fn report(&self, what: &str) {
        let (seen, built, reached) = (
            self.seen.load(Ordering::Relaxed),
            self.built.load(Ordering::Relaxed),
            self.reached.load(Ordering::Relaxed),
        );
        println!("{what}: {built}/{seen} configurations built, {reached} flows reached it");
        assert!(
            built * 2 >= seen,
            "only {built} of {seen} configurations built, so this checked much less than it looks \
             like it did"
        );
        assert!(
            reached >= MIN_REACHED && reached * 2 >= built,
            "{reached} flows reached the {what} assertion across {built} configurations; \
             this property has gone vacuous"
        );
    }
}

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

fn out_unchanged(out: &[Packet<TestBuffer>], before: (IpAddr, u16)) -> bool {
    out[0].is_done() || source_of(&out[0]) == before
}

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
