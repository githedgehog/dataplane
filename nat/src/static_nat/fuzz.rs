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
use std::num::NonZero;

const MAX_EXPOSES: u8 = 3;

const MIN_REACHED: usize = 8;

const PROBES: usize = 8;

#[derive(Debug, Clone, Copy)]
struct Scenario {
    strays: bool,
    exposes: StaticNatExposes,
}

impl Scenario {
    fn addresses(strays: bool) -> Self {
        Self {
            strays,
            exposes: StaticNatExposes::addresses_only(MAX_EXPOSES),
        }
    }

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

fn run(nf: &mut StaticNat, packets: Vec<Packet<TestBuffer>>) -> Vec<Packet<TestBuffer>> {
    nf.process(packets.into_iter()).collect()
}

fn fabric(exposes: &[VpcExpose]) -> Option<Fabric> {
    let fabric = Fabric::build(exposes)?;
    fabric.is_probeable().then_some(fabric)
}

fn five_tuple_source(packet: &Packet<TestBuffer>) -> (IpAddr, u16) {
    (
        packet
            .ip_source()
            .unwrap_or_else(|| unreachable!("a probe is always an ip packet")),
        packet.transport_src_port().map_or(0, NonZero::get),
    )
}

fn five_tuple_destination(packet: &Packet<TestBuffer>) -> (IpAddr, u16) {
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
        if seen == 0 {
            return;
        }
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

#[test]
fn a_translated_source_and_port_come_back() {
    drive_round_trip!(Scenario::ports(false));
}

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

#[test]
fn distinct_sources_and_ports_stay_distinct() {
    drive_injectivity!(Scenario::ports(false));
}

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

macro_rules! drive_permission {
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
            });

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
