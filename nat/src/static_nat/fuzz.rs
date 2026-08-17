// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

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
        let exposes = StaticNatExposes(MAX_EXPOSES).generate(driver)?;

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

fn run(nf: &mut StaticNat, packets: Vec<Packet<TestBuffer>>) -> Vec<Packet<TestBuffer>> {
    nf.process(packets.into_iter()).collect()
}

fn fabric(exposes: &[VpcExpose]) -> Option<Fabric> {
    let fabric = Fabric::build(exposes)?;
    fabric.is_probeable().then_some(fabric)
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
        println!("{what}: {built}/{seen} configurations built, {reached} probes reached it");
        assert!(
            built * 2 >= seen,
            "only {built} of {seen} configurations built, so this checked much less than it looks \
             like it did"
        );
        assert!(
            reached >= MIN_REACHED && reached * 2 >= built,
            "{reached} probes reached the {what} assertion across {built} configurations; \
             this property has gone vacuous"
        );
    }
}

#[test]
fn a_translated_source_comes_back() {
    let tally = Tally::default();

    bolero::check!()
        .with_generator(Scenario { strays: false })
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
                let source = probe.source;
                let out = run(&mut nf, vec![probe.take()]);
                let translated = out[0]
                    .ip_source()
                    .unwrap_or_else(|| unreachable!("a probe is always an ip packet"));

                if translated == source {
                    continue;
                }

                let back = run(&mut nf, vec![probe.reply(translated)]);
                let returned = back[0]
                    .ip_destination()
                    .unwrap_or_else(|| unreachable!("a reply is always an ip packet"));

                assert_eq!(
                    returned, source,
                    "{source} translated to {translated} on the way out, and the reply to \
                     {translated} came back to {returned} instead of {source}"
                );
                tally.reached.fetch_add(1, Ordering::Relaxed);
            }
        });

    tally.report("round trip");
}

#[test]
fn distinct_sources_stay_distinct() {
    let tally = Tally::default();

    bolero::check!()
        .with_generator(Scenario { strays: false })
        .cloned()
        .for_each(|(exposes, probes): (Vec<VpcExpose>, Vec<ProbeSpec>)| {
            tally.seen.fetch_add(1, Ordering::Relaxed);
            let Some(fabric) = fabric(&exposes) else {
                return;
            };
            tally.built.fetch_add(1, Ordering::Relaxed);
            let mut nf = fabric.nf();

            let sources = fabric.private.clone();
            let _ = probes;

            let batch: Vec<Packet<TestBuffer>> = sources
                .iter()
                .map(|source| fabric.outbound_to_peer(*source))
                .collect();
            let out = run(&mut nf, batch);

            let mut taken: BTreeMap<IpAddr, IpAddr> = BTreeMap::new();
            for (source, packet) in sources.iter().zip(out.iter()) {
                let translated = packet
                    .ip_source()
                    .unwrap_or_else(|| unreachable!("a probe is always an ip packet"));
                if translated == *source {
                    continue;
                }
                if let Some(previous) = taken.insert(translated, *source) {
                    panic!(
                        "{source} and {previous} both translated to {translated}, so static NAT is \
                         not one to one for {exposes:#?}"
                    );
                }
                tally.reached.fetch_add(1, Ordering::Relaxed);
            }
        });

    tally.report("injectivity");
}

#[test]
fn translation_touches_only_the_source() {
    let tally = Tally::default();

    bolero::check!()
        .with_generator(Scenario { strays: false })
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
                    packet.transport_src_port().map(std::num::NonZero::get),
                    Some(sport),
                    "source translation rewrote the source port, which no expose asked for"
                );
                assert_eq!(
                    packet.transport_dst_port().map(std::num::NonZero::get),
                    Some(dport),
                    "source translation rewrote the destination port"
                );
                assert_eq!(
                    packet.ip_proto(),
                    Some(proto),
                    "source translation changed the transport protocol"
                );
                tally.reached.fetch_add(1, Ordering::Relaxed);
            }
        });

    tally.report("frame");
}

#[test]
fn nothing_is_translated_without_permission() {
    let tally = Tally::default();

    bolero::check!()
        .with_generator(Scenario { strays: true })
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
                if probe.asks_for_translation() && probe.exposed {
                    continue;
                }

                let (source, stray, arrival) = (probe.source, probe.stray, probe.arrival);
                let out = run(&mut nf, vec![probe.take()]);
                let packet = &out[0];

                assert_eq!(
                    packet.ip_source(),
                    Some(source),
                    "static NAT translated {source} although {stray:?} forbade it; the packet \
                     arrived as {arrival:?}"
                );
                tally.reached.fetch_add(1, Ordering::Relaxed);
            }
        });

    tally.report("permission");
}

#[test]
fn a_packet_that_cannot_be_looked_up_says_so() {
    let tally = Tally::default();

    bolero::check!()
        .with_generator(Scenario { strays: true })
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
                let unroutable = matches!(
                    probe.stray,
                    Some(Stray::NoSourceVni | Stray::UnknownSourceVni)
                );
                if !unroutable {
                    continue;
                }

                let (source, stray) = (probe.source, probe.stray);
                let out = run(&mut nf, vec![probe.take()]);
                let packet = &out[0];

                let reason = packet.get_done().unwrap_or_else(|| {
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
        });

    tally.report("attribution");
}

#[test]
fn a_modified_packet_is_always_marked() {
    let tally = Tally::default();

    bolero::check!()
        .with_generator(Scenario { strays: true })
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
                let source = probe.source;
                let out = run(&mut nf, vec![probe.take()]);
                let packet = &out[0];

                let translated = packet
                    .ip_source()
                    .unwrap_or_else(|| unreachable!("a probe is always an ip packet"))
                    != source;
                if !translated {
                    continue;
                }

                assert!(
                    packet.meta().is_src_natted(),
                    "{source} was translated without the source-natted mark, so a later stage \
                     would translate it again"
                );
                assert!(
                    packet.meta().checksum_refresh(),
                    "{source} was translated without asking for a checksum refresh, so the packet \
                     goes out with a checksum for an address it no longer carries"
                );
                tally.reached.fetch_add(1, Ordering::Relaxed);
            }
        });

    tally.report("marking");
}
