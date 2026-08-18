// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

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

const MIN_REACHED: usize = 8;

const MAX_EXPOSES: u8 = 2;

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

fn destination_of(packet: &Packet<TestBuffer>) -> (IpAddr, u16) {
    (
        packet
            .ip_destination()
            .unwrap_or_else(|| unreachable!("a probe is always an ip packet")),
        packet.transport_dst_port().map_or(0, NonZero::get),
    )
}

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
    fn report(&self, what: &str) {
        let (seen, built, reached) = (
            self.seen.load(Ordering::Relaxed),
            self.built.load(Ordering::Relaxed),
            self.reached.load(Ordering::Relaxed),
        );
        println!("{what}: {built}/{seen} configurations built, {reached} packets reached it");
        assert!(
            built * 2 >= seen,
            "only {built} of {seen} configurations built, so this checked much less than it looks \
             like it did"
        );
        assert!(
            reached >= MIN_REACHED && reached * 2 >= built,
            "{reached} packets reached the {what} assertion across {built} configurations; this \
             property has gone vacuous"
        );
    }
}

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
