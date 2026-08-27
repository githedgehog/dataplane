// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![cfg(test)]

use crate::fuzz::oracle_resolved_action;
use crate::fuzz_gen::{OverlaySpec, ProbeSpec};
use crate::{AclFilter, AclFilterContext, AclFilterContextWriter, PacketSummary};
use concurrency::sync::atomic::{AtomicUsize, Ordering};
use config::external::overlay::acl::AclAction;
use net::buffer::TestBuffer;
use net::ip::{NextHeader, UnicastIpAddr};
use net::packet::test_utils::{
    build_test_ipv4_packet_with_transport, build_test_ipv6_packet_with_transport,
};
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use net::tcp::port::TcpPort;
use net::udp::UdpPort;
use pipeline::NetworkFunction;
use std::net::IpAddr;

const MIN_REACHED: usize = 8;

const PROBES: usize = 8;

fn packet_for(summary: &PacketSummary) -> Option<Packet<TestBuffer>> {
    let (sport, dport) = summary.ports?;
    let tcp = match summary.proto {
        NextHeader::TCP => true,
        NextHeader::UDP => false,
        _ => return None,
    };

    let mut packet = match (summary.src_ip, summary.dst_ip) {
        (IpAddr::V4(_), IpAddr::V4(_)) => {
            build_test_ipv4_packet_with_transport(64, Some(summary.proto)).ok()?
        }
        (IpAddr::V6(_), IpAddr::V6(_)) => {
            build_test_ipv6_packet_with_transport(64, Some(summary.proto)).ok()?
        }
        _ => return None,
    };

    packet
        .set_ip_source(UnicastIpAddr::try_from(summary.src_ip).ok()?)
        .ok()?;
    packet.set_ip_destination(summary.dst_ip).ok()?;
    if tcp {
        packet
            .set_tcp_source_port(TcpPort::new_checked(sport.max(1)).ok()?)
            .ok()?;
        packet
            .set_tcp_destination_port(TcpPort::new_checked(dport.max(1)).ok()?)
            .ok()?;
    } else {
        packet
            .set_udp_source_port(UdpPort::new_checked(sport.max(1)).ok()?)
            .ok()?;
        packet
            .set_udp_destination_port(UdpPort::new_checked(dport.max(1)).ok()?)
            .ok()?;
    }

    let meta = packet.meta_mut();
    meta.src_vpcd = Some(VpcDiscriminant::from_vni(summary.src_vni));
    meta.dst_vpcd = Some(VpcDiscriminant::from_vni(summary.dst_vni));
    meta.set_overlay(true);
    meta.set_keep(true);
    Some(packet)
}

fn expected_summary(summary: &PacketSummary) -> PacketSummary {
    let mut expected = summary.clone();
    expected.ports = summary.ports.map(|(s, d)| (s.max(1), d.max(1)));
    expected
}

fn filter(built: &crate::fuzz_gen::BuiltOverlay) -> AclFilter {
    let writer = AclFilterContextWriter::new();
    writer.store(AclFilterContext::for_test(&built.overlay));
    AclFilter::new("nf-fuzz-acl-filter", writer.get_reader())
}

#[derive(Default)]
struct Tally {
    drawn: AtomicUsize,
    reached: AtomicUsize,
    denied: AtomicUsize,
}

impl Tally {
    fn report_arrivals_only(&self, what: &str) {
        let (drawn, reached) = (
            self.drawn.load(Ordering::Relaxed),
            self.reached.load(Ordering::Relaxed),
        );
        if drawn == 0 {
            return;
        }
        println!("{what}: {reached}/{drawn} probes became packets");
        assert!(
            reached >= MIN_REACHED && reached * 4 >= drawn,
            "only {reached} of {drawn} probes became packets, so the {what} assertion is barely \
             running"
        );
    }

    fn report(&self, what: &str) {
        let (drawn, reached, denied) = (
            self.drawn.load(Ordering::Relaxed),
            self.reached.load(Ordering::Relaxed),
            self.denied.load(Ordering::Relaxed),
        );
        if drawn == 0 {
            return;
        }
        println!("{what}: {reached}/{drawn} probes became packets, {denied} of them denied");
        assert!(
            reached >= MIN_REACHED && reached * 4 >= drawn,
            "only {reached} of {drawn} probes became packets, so the {what} assertion is barely \
             running"
        );
        assert!(
            denied * 20 >= reached,
            "only {denied} of {reached} probes were denied, so the drop path is barely exercised \
             and this property is mostly checking that nothing happens"
        );
    }
}

#[test]
fn the_stage_agrees_with_the_configuration() {
    let tally = Tally::default();

    bolero::check!()
        .with_type::<(OverlaySpec, [ProbeSpec; PROBES])>()
        .for_each(|(overlay_spec, probe_specs)| {
            let built = overlay_spec.build();
            let mut acl = filter(&built);

            for probe_spec in probe_specs {
                tally.drawn.fetch_add(1, Ordering::Relaxed);
                let summary = probe_spec.resolve(&built);
                let Some(packet) = packet_for(&summary) else {
                    continue;
                };

                let want = oracle_resolved_action(&built.overlay, &summary);
                let out: Vec<_> = acl.process(std::iter::once(packet)).collect();
                let got = out[0].get_done();

                match want {
                    AclAction::Deny => {
                        assert_eq!(
                            got,
                            Some(DoneReason::AclDropped),
                            "the configuration denies {summary:?} and the stage let it through \
                             with {got:?}\nspec: {overlay_spec:?}"
                        );
                        tally.denied.fetch_add(1, Ordering::Relaxed);
                    }
                    AclAction::Allow => {
                        assert_eq!(
                            got, None,
                            "the configuration allows {summary:?} and the stage dropped it for \
                             {got:?}\nspec: {overlay_spec:?}"
                        );
                    }
                }
                tally.reached.fetch_add(1, Ordering::Relaxed);
            }
        });

    tally.report("stage verdict");
}

#[test]
fn the_summary_survives_the_round_trip_through_a_packet() {
    let tally = Tally::default();

    bolero::check!()
        .with_type::<(OverlaySpec, [ProbeSpec; PROBES])>()
        .for_each(|(overlay_spec, probe_specs)| {
            let built = overlay_spec.build();

            for probe_spec in probe_specs {
                tally.drawn.fetch_add(1, Ordering::Relaxed);
                let summary = probe_spec.resolve(&built);
                let Some(packet) = packet_for(&summary) else {
                    continue;
                };

                let read = PacketSummary::try_from(&packet)
                    .unwrap_or_else(|e| panic!("a built packet did not yield a summary: {e:?}"));
                let expected = expected_summary(&summary);

                assert_eq!(
                    (read.src_vni, read.dst_vni),
                    (expected.src_vni, expected.dst_vni),
                    "discriminants came back swapped or wrong\nspec: {overlay_spec:?}"
                );
                assert_eq!(
                    (read.src_ip, read.dst_ip),
                    (expected.src_ip, expected.dst_ip),
                    "addresses came back swapped or wrong\nspec: {overlay_spec:?}"
                );
                assert_eq!(
                    read.proto, expected.proto,
                    "protocol came back wrong\nspec: {overlay_spec:?}"
                );
                assert_eq!(
                    read.ports, expected.ports,
                    "ports came back swapped or wrong\nspec: {overlay_spec:?}"
                );
                tally.reached.fetch_add(1, Ordering::Relaxed);
            }
        });

    tally.report_arrivals_only("summary round trip");
}

#[test]
fn a_packet_with_no_discriminants_is_dropped() {
    let tally = Tally::default();

    bolero::check!()
        .with_type::<(OverlaySpec, [ProbeSpec; PROBES])>()
        .for_each(|(overlay_spec, probe_specs)| {
            let built = overlay_spec.build();
            let mut acl = filter(&built);

            for probe_spec in probe_specs {
                tally.drawn.fetch_add(1, Ordering::Relaxed);
                let summary = probe_spec.resolve(&built);
                let Some(mut packet) = packet_for(&summary) else {
                    continue;
                };
                packet.meta_mut().dst_vpcd = None;

                let out: Vec<_> = acl.process(std::iter::once(packet)).collect();
                assert_eq!(
                    out[0].get_done(),
                    Some(DoneReason::Unroutable),
                    "a packet with no destination vpc was not refused\nspec: {overlay_spec:?}"
                );
                tally.reached.fetch_add(1, Ordering::Relaxed);
            }
        });

    tally.report_arrivals_only("missing discriminant");
}

#[test]
fn underlay_traffic_is_not_judged() {
    let tally = Tally::default();

    bolero::check!()
        .with_type::<(OverlaySpec, [ProbeSpec; PROBES])>()
        .for_each(|(overlay_spec, probe_specs)| {
            let built = overlay_spec.build();
            let mut acl = filter(&built);

            for probe_spec in probe_specs {
                tally.drawn.fetch_add(1, Ordering::Relaxed);
                let summary = probe_spec.resolve(&built);
                let Some(mut packet) = packet_for(&summary) else {
                    continue;
                };
                packet.meta_mut().set_overlay(false);

                let out: Vec<_> = acl.process(std::iter::once(packet)).collect();
                assert_eq!(
                    out[0].get_done(),
                    None,
                    "a packet that is not overlay traffic was judged by an overlay acl\nspec: \
                     {overlay_spec:?}"
                );
                tally.reached.fetch_add(1, Ordering::Relaxed);
            }
        });

    tally.report_arrivals_only("underlay gate");
}
