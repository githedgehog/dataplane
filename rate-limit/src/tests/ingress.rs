// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The ingress policy: drops, police on outer IP packets, and first-match order.

use super::{meter, packet, rate, vni};
use crate::{Classify, IngressRules, RateLimitWriter, RateLimiter, RateLimits, Unit};
use acl::table::Backend;
use concurrency::sync::atomic::{AtomicBool, Ordering};
use config::external::overlay::Overlay;
use config::external::overlay::ValidatedOverlay;
use config::external::overlay::acl::{AclPattern, AclProtoMatch};
use config::external::overlay::ingress::{IngressAction, IngressPolicy, IngressRule};
use config::external::overlay::ratelimit::{ColorActions, Meter, MeterProfile};
use config::external::overlay::vpc::{Vpc, VpcTable};
use config::external::overlay::vpcpeering::VpcPeeringTable;
use lpm::prefix::{PortRange, Prefix, PrefixWithOptionalPorts};
use net::buffer::TestBuffer;
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use policer::Profile;
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;

const FROM: u32 = 3000;
const OTHER: u32 = 3001;

fn overlay(meters: Vec<(&str, Meter)>, rules: Vec<IngressRule>) -> ValidatedOverlay {
    let mut vpcs = VpcTable::new();
    vpcs.add(Vpc::new("vpc-1", "AAAAA", FROM).unwrap()).unwrap();
    vpcs.add(Vpc::new("vpc-2", "BBBBB", OTHER).unwrap())
        .unwrap();
    Overlay::new(vpcs, VpcPeeringTable::new())
        .with_ingress(IngressPolicy {
            meters: meters
                .into_iter()
                .map(|(name, meter)| (name.into(), meter))
                .collect(),
            rules,
        })
        .validate()
        .unwrap()
}

fn writer(config: &ValidatedOverlay) -> RateLimitWriter<IngressRules> {
    let w = RateLimitWriter::<IngressRules>::new(RateLimits::empty(), NonZeroUsize::MIN);
    w.apply(config, Backend::Reference).unwrap();
    w
}

/// An ingress rule from `from` (any VPC if `None`) to `destination`.
fn rule(from: Option<&str>, destination: &str, action: IngressAction) -> IngressRule {
    IngressRule {
        from: from.map(Into::into),
        pattern: AclPattern {
            dst: [PrefixWithOptionalPorts::from(
                destination.parse::<Prefix>().unwrap(),
            )]
            .into(),
            ..AclPattern::default()
        },
        action,
    }
}

/// [`packet`] as it arrives from `from`: no destination VPC yet, and its outer IP length.
fn arriving(from: u32, dst: &str, outer_ip_len: u16) -> Packet<TestBuffer> {
    let mut p = packet(dst, 80);
    p.meta_mut().src_vpcd = Some(VpcDiscriminant::VNI(vni(from)));
    p.meta_mut().dst_vpcd = None;
    p.meta_mut().outer_ip_len = Some(outer_ip_len);
    p
}

fn burst_of(
    stage: &mut RateLimiter<IngressRules>,
    packets: Vec<Packet<TestBuffer>>,
) -> Vec<Packet<TestBuffer>> {
    use pipeline::NetworkFunction;
    stage.process(packets).collect()
}

fn police(name: &str) -> IngressAction {
    IngressAction::Police(name.into())
}

/// A drop rule drops, under its own reason, only traffic from its VPC; an earlier police rule
/// takes what it matches first.
#[test]
fn drops_are_ordered_and_scoped_to_their_vpc() {
    let config = overlay(
        vec![("m", meter(100, 0))],
        vec![
            rule(Some("vpc-1"), "10.1.1.0/24", police("m")),
            rule(Some("vpc-1"), "10.1.0.0/16", IngressAction::Drop),
        ],
    );
    let w = writer(&config);
    let mut stage = RateLimiter::new(w.reader());
    let out = burst_of(
        &mut stage,
        vec![
            arriving(FROM, "10.1.1.1", 100),
            arriving(FROM, "10.1.2.1", 100),
            arriving(OTHER, "10.1.2.1", 100),
        ],
    );
    assert_eq!(
        out.iter().map(Packet::get_done).collect::<Vec<_>>(),
        [None, Some(DoneReason::IngressDropped), None]
    );
    // Drops are counted by source VPC, and the count outlives the policy.
    let counted = |w: &RateLimitWriter<IngressRules>| w.load().dropped().get(&vni(FROM)).copied();
    assert_eq!(counted(&w), Some(1));
    w.apply(&overlay(Vec::new(), Vec::new()), Backend::Reference)
        .unwrap();
    assert_eq!(counted(&w), Some(1));
}

/// Meters count the outer IP packet: a 1000-byte one takes 1000 tokens, whatever the inner
/// packet's size, and a packet not received encapsulated is not charged.
#[test]
fn meters_count_outer_ip_packets() {
    let bytes = Meter {
        bytes: Some(MeterProfile {
            profile: Profile::new(rate(1), 2000, None, 0).unwrap(),
            actions: ColorActions::default(),
        }),
        packets: None,
    };
    let config = overlay(
        vec![("m", bytes)],
        vec![rule(None, "10.1.0.0/16", police("m"))],
    );
    let w = writer(&config);
    let mut stage = RateLimiter::new(w.reader());
    let mut unbilled = arriving(FROM, "10.1.1.1", 1000);
    unbilled.meta_mut().outer_ip_len = None;
    let out = burst_of(
        &mut stage,
        vec![
            arriving(FROM, "10.1.1.1", 1000),
            unbilled,
            arriving(OTHER, "10.1.1.2", 1000),
            arriving(FROM, "10.1.1.3", 1000),
        ],
    );
    assert_eq!(
        out.iter().map(Packet::get_done).collect::<Vec<_>>(),
        [None, None, None, Some(DoneReason::RateLimited)]
    );
    let limits = w.load();
    let component = limits.meters()[0].component(Unit::Bytes).unwrap();
    assert_eq!(component.counted(policer::Color::Green), (2, 2000));
}

/// One generated rule: its VPC (or every VPC), destination, protocol and destination port, and
/// whether it drops.
#[derive(Debug, Clone, Copy, bolero::TypeGenerator)]
struct Generated {
    from: Option<bool>,
    destination: u8,
    proto: u8,
    port: Option<bool>,
    drop: bool,
}

const DESTINATIONS: [(&str, Ipv4Addr, u8); 3] = [
    ("10.0.0.0/8", Ipv4Addr::new(10, 0, 0, 0), 8),
    ("10.1.0.0/16", Ipv4Addr::new(10, 1, 0, 0), 16),
    ("10.1.1.0/24", Ipv4Addr::new(10, 1, 1, 0), 24),
];
const PORTS: [u16; 2] = [53, 80];

impl Generated {
    fn vni(self) -> Option<u32> {
        self.from.map(|other| if other { OTHER } else { FROM })
    }
    fn proto(self) -> AclProtoMatch {
        match (self.proto % 3, self.port) {
            (_, Some(_)) | (1, None) => AclProtoMatch::Udp,
            (2, None) => AclProtoMatch::Tcp(config::external::overlay::acl::AclTcpFlagsMatch::ANY),
            _ => AclProtoMatch::Any,
        }
    }
    fn rule(self) -> IngressRule {
        let (destination, ..) = DESTINATIONS[usize::from(self.destination) % DESTINATIONS.len()];
        let mut r = rule(
            self.vni()
                .map(|v| if v == FROM { "vpc-1" } else { "vpc-2" }),
            destination,
            if self.drop {
                IngressAction::Drop
            } else {
                police("m")
            },
        );
        r.pattern.proto = self.proto();
        if let Some(port) = self.port {
            let port = PORTS[usize::from(port)];
            r.pattern.dst = [PrefixWithOptionalPorts::new(
                destination.parse::<Prefix>().unwrap(),
                Some(PortRange::new(port, port).unwrap()),
            )]
            .into();
        }
        r
    }
    /// Whether it matches a UDP packet from `from` to `dst` port `port`, by the configuration's
    /// meaning alone.
    fn matches(self, from: u32, dst: Ipv4Addr, port: u16) -> bool {
        let (_, net, len) = DESTINATIONS[usize::from(self.destination) % DESTINATIONS.len()];
        let mask = u32::MAX << (32 - u32::from(len));
        self.vni().is_none_or(|v| v == from)
            && u32::from(dst) & mask == u32::from(net)
            && !matches!(self.proto(), AclProtoMatch::Tcp(_))
            && self.port.is_none_or(|p| PORTS[usize::from(p)] == port)
    }
}

/// The classifier picks the first rule the configuration says matches, on both backends.
#[test]
#[dpdk::with_eal]
fn the_first_matching_rule_wins() {
    bolero::check!()
        .with_type::<(Vec<Generated>, bool, u8, u8, bool)>()
        .for_each(|(generated, other, third, fourth, port)| {
            let generated = &generated[..generated.len().min(8)];
            let config = overlay(
                vec![("m", meter(1, 0))],
                generated.iter().map(|g| g.rule()).collect(),
            );
            let build = |backend| {
                RateLimits::<IngressRules>::build(
                    &config,
                    &RateLimits::empty(),
                    NonZeroUsize::MIN,
                    clock::now(),
                    backend,
                )
                .unwrap()
            };
            let (reference, dpdk) = (build(Backend::Reference), build(Backend::Dpdk));
            let from = if *other { OTHER } else { FROM };
            let dst = Ipv4Addr::new(10, 1, *third % 3, *fourth);
            let port = PORTS[usize::from(*port)];
            let mut p = arriving(from, &dst.to_string(), 100);
            if port != 80 {
                p = {
                    let mut q = packet(&dst.to_string(), port);
                    *q.meta_mut() = p.meta().clone();
                    q
                };
            }
            let expected = generated.iter().position(|g| g.matches(from, dst, port));
            // Validation expands a rule per VPC and family: the configured rule is the one asked of.
            let picked = |limits: &RateLimits<IngressRules>| {
                limits
                    .classifier
                    .classify(&p)
                    .map(|i| config.ingress().rules[i].index)
            };
            assert_eq!(
                picked(&reference),
                expected,
                "{generated:?} {from} {dst} {port}"
            );
            assert_eq!(picked(&dpdk), expected);
        });
}

/// An ingress meter and a peering meter of the same name are separate series: meter names are
/// only unique within a policy (a peering named `ingress` has meters named `ingress/...`).
#[test]
fn ingress_and_peering_meters_of_one_name_are_separate_series() {
    let config = overlay(
        vec![("ingress/m", meter(100, 0))],
        vec![rule(None, "10.1.0.0/16", police("ingress/m"))],
    );
    let ingress = writer(&config);
    let peering =
        RateLimitWriter::<crate::PeeringRules>::new(RateLimits::empty(), NonZeroUsize::MIN);
    let peering_config = super::configuration(
        vec![("ingress/m", meter(100, 0))],
        vec![super::rule("10.1.0.0/16", "ingress/m")],
    );
    peering.apply(&peering_config, Backend::Reference).unwrap();
    let mut stage = RateLimiter::new(ingress.reader());
    let _ = burst_of(&mut stage, vec![arriving(FROM, "10.1.1.1", 100)]);
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    metrics::with_local_recorder(&recorder, || {
        ingress.load().publish_metrics();
        peering.load().publish_metrics();
    });
    let scrape = recorder.handle().render();
    let conforming = |policy: &str| {
        scrape
            .lines()
            .find(|l| {
                l.starts_with("rate_limit_packets_total{")
                    && l.contains(&format!("policy=\"{policy}\""))
                    && l.contains("result=\"conforming\"")
            })
            .unwrap_or_else(|| panic!("{scrape}"))
            .to_string()
    };
    assert!(conforming("ingress").ends_with(" 1"), "{scrape}");
    assert!(conforming("peering").ends_with(" 0"), "{scrape}");
}

/// Scrapes that overlap publish drop totals that only grow: none sets an older total after a
/// newer one (which, published as an increment, went below zero).
#[test]
fn overlapping_scrapes_keep_drop_totals_whole() {
    let config = overlay(
        Vec::new(),
        vec![rule(Some("vpc-1"), "10.1.0.0/16", IngressAction::Drop)],
    );
    let w = writer(&config);
    let limits = w.load();
    let done = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let reader = w.reader();
        let done = &done;
        scope.spawn(move || {
            let mut stage = RateLimiter::new(reader);
            for _ in 0..2000 {
                let _ = burst_of(&mut stage, vec![arriving(FROM, "10.1.1.1", 100)]);
            }
            done.store(true, Ordering::Relaxed);
        });
        for _ in 0..4 {
            let limits = &limits;
            scope.spawn(move || {
                while !done.load(Ordering::Relaxed) {
                    limits.publish_metrics();
                }
            });
        }
    });
    assert_eq!(limits.dropped().get(&vni(FROM)).copied(), Some(2000));
}
