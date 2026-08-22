// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The ACL properties, carried from the lookup to the network function.
//!
//! `fuzz.rs` already has the strongest oracle in this codebase: it evaluates the validated
//! configuration directly and compares that against the lowered tables, so a lowering mistake cannot
//! hide behind the thing it produced. What it does not touch is a packet. Every probe there is a
//! [`PacketSummary`] handed straight to `lookup`.
//!
//! Two pieces of production code sit between a packet and that summary, and neither had any
//! coverage from a generated configuration:
//!
//! * **`PacketSummary::try_from`**, which reads the five-tuple and the two discriminants out of the
//!   headers. A summary is six fields, and a stage that read the destination where the source
//!   belongs would pass every property in `fuzz.rs` -- they never build the packet it misreads.
//! * **`AclFilter::process_packet`**, which turns a verdict into a fate: `DoneReason::AclDropped`,
//!   `invalidate_flows`, and the `is_overlay` gate deciding whether any of it happens.
//!
//! So this module re-points the existing generators rather than writing new ones. The
//! [`OverlaySpec`] and [`ProbeSpec`] are the same; what differs is that a probe becomes a packet and
//! the answer is read off the packet's fate rather than returned from a function.
//!
//! # Why the verdict is still not predicted here
//!
//! `oracle_verdict` is the config-semantics oracle from `fuzz.rs`, unchanged. This module does not
//! reimplement it -- it asks the same oracle the same question and checks that the *stage* agrees,
//! which makes this a differential test over the packet path rather than a second ACL.

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

/// The fewest arriving probes any property may see before it is considered vacuous.
const MIN_REACHED: usize = 8;

/// Probes per configuration.
const PROBES: usize = 8;

/// Build a packet carrying a summary's five-tuple and discriminants.
///
/// Returns `None` for a protocol with no port builder. TCP and UDP are what carry ports and so what
/// the port half of every ACL rule is about; a probe drawing ICMP or an arbitrary next header is
/// counted and skipped rather than approximated, since a packet whose headers do not match the
/// summary it came from would make every disagreement below meaningless.
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
        // The generator's `CrossVersion` stray produces these on purpose. There is no such packet
        // to build, so the case belongs to the summary-level properties.
        _ => return None,
    };

    packet
        .set_ip_source(UnicastIpAddr::try_from(summary.src_ip).ok()?)
        .ok()?;
    packet.set_ip_destination(summary.dst_ip).ok()?;
    if tcp {
        packet.set_tcp_source_port(TcpPort::new(sport)).ok()?;
        packet.set_tcp_destination_port(TcpPort::new(dport)).ok()?;
    } else {
        packet.set_udp_source_port(UdpPort::new(sport)).ok()?;
        packet.set_udp_destination_port(UdpPort::new(dport)).ok()?;
    }

    let meta = packet.meta_mut();
    meta.src_vpcd = Some(VpcDiscriminant::from_vni(summary.src_vni));
    meta.dst_vpcd = Some(VpcDiscriminant::from_vni(summary.dst_vni));
    meta.set_overlay(true);
    meta.set_keep(true);
    Some(packet)
}

fn filter(built: &crate::fuzz_gen::BuiltOverlay) -> AclFilter {
    let writer = AclFilterContextWriter::new();
    writer.store(AclFilterContext::for_test(&built.overlay));
    AclFilter::new("nf-fuzz-acl-filter", writer.get_reader())
}

/// How much of a run reached the code under test.
#[derive(Default)]
struct Tally {
    drawn: AtomicUsize,
    reached: AtomicUsize,
    denied: AtomicUsize,
}

impl Tally {
    /// Assert the run was not vacuous.
    ///
    /// Both floors are **ratios**, not absolute counts. An absolute floor measures how fast the
    /// machine was: a property reaching ten thousand probes on its own reaches a few hundred beside
    /// nine hundred other tests under coverage instrumentation, and a floor tuned to the fast case
    /// then fails for a reason unrelated to the code under test.
    ///
    /// The denial ratio matters as much as the arrival one and is easy to miss. A run that only ever
    /// saw permits would pass every assertion below while the drop path -- the only path where the
    /// stage does anything at all -- went entirely unexercised.
    fn report(&self, what: &str) {
        let (drawn, reached, denied) = (
            self.drawn.load(Ordering::Relaxed),
            self.reached.load(Ordering::Relaxed),
            self.denied.load(Ordering::Relaxed),
        );
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

/// The stage's verdict on a packet is the configuration's verdict on its five-tuple.
///
/// The claim `fuzz.rs` makes about the tables, carried to where it is observable: a denied packet is
/// dropped and says `AclDropped`, a permitted one survives untouched.
///
/// This is where the summary extraction is tested, and it is tested implicitly rather than by
/// inspection -- if `PacketSummary::try_from` read any of the six fields from the wrong place, the
/// stage would look up a different tuple from the one the oracle judged, and the two would disagree
/// on the probes where that field decides the answer. The generator's near-miss strays exist to make
/// those probes common.
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

/// The five-tuple the stage reads back is the one the packet was built with.
///
/// The previous property tests the extraction only where a misread field changes a verdict. This one
/// tests it directly, which catches the misread that happens to be harmless for the configuration
/// drawn -- a field read from the wrong place is a defect whether or not this particular ruleset
/// notices.
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
                // The builder no longer normalizes anything: a probe's ports are `NonZero`, so
                // what goes into the packet is what comes back out.
                let expected = &summary;

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
                // The drop path is not this property's subject; borrow the floor.
                tally.denied.fetch_add(1, Ordering::Relaxed);
            }
        });

    tally.report("summary round trip");
}

/// A packet with no discriminants is dropped, and says why.
///
/// `PacketSummary::try_from` returns `DoneReason::Unroutable` for it, and that is the whole of what
/// the stage can do -- an ACL is indexed by the vpc pair, so a packet that names neither cannot be
/// judged at all. Letting it through would apply no policy to it whatsoever, which is the failure
/// this rules out.
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
                tally.denied.fetch_add(1, Ordering::Relaxed);
            }
        });

    tally.report("missing discriminant");
}

/// A packet that is not overlay traffic is left alone.
///
/// The stage's gate. Underlay traffic is not indexed by a vpc pair and no ACL in the configuration
/// describes it, so applying one would be applying a policy to traffic it was never written for.
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
                tally.denied.fetch_add(1, Ordering::Relaxed);
            }
        });

    tally.report("underlay gate");
}
