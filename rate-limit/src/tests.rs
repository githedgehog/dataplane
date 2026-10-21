// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::{Classify, PeeringRules, RateLimitWriter, RateLimiter, RateLimits, Unit};
use acl::table::Backend;
use config::external::overlay::acl::{AclPattern, AclProtoMatch};
use config::external::overlay::ratelimit::{
    ColorAction, ColorActions, Meter, MeterProfile, RateLimitRule, RateLimitTables,
};
use config::external::overlay::vpc::{Vpc, VpcTable};
use config::external::overlay::vpcpeering::{VpcExpose, VpcManifest, VpcPeering, VpcPeeringTable};
use config::external::overlay::{Overlay, ValidatedOverlay};
use lpm::prefix::with_ports::PrefixPortsSet;
use lpm::prefix::{Prefix, PrefixWithOptionalPorts};
use net::buffer::TestBuffer;
use net::headers::builder::HeaderStack;
use net::headers::{Net, TryIp};
use net::ip::dscp::Dscp;
use net::ipv4::UnicastIpv4Addr;
use net::ipv6::UnicastIpv6Addr;
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use net::parse::DeParse;
use net::udp::UdpPort;
use net::vxlan::Vni;
use pipeline::NetworkFunction;
use policer::{Color, Profile, Rate};
use std::net::{IpAddr, Ipv4Addr};
use std::num::{NonZeroU64, NonZeroUsize};

const VNI1: u32 = 3000;
const VNI2: u32 = 4000;
fn vni(n: u32) -> Vni {
    Vni::new_checked(n).unwrap()
}
fn rate(n: u64) -> Rate {
    Rate::new(NonZeroU64::new(n).unwrap())
}

fn packet(dst: &str, port: u16) -> Packet<TestBuffer> {
    let dst: IpAddr = dst.parse().unwrap();
    let udp = |udp: &mut net::udp::Udp| {
        udp.set_source(UdpPort::try_from(1234).unwrap());
        udp.set_destination(UdpPort::try_from(port).unwrap());
    };
    let stack = HeaderStack::new().eth(|_| {});
    let headers = match dst {
        IpAddr::V4(dst) => stack
            .ipv4(|ip| {
                ip.set_source(UnicastIpv4Addr::new(Ipv4Addr::new(10, 0, 0, 1)).unwrap());
                ip.set_destination(dst);
            })
            .udp(udp)
            .build_headers(),
        IpAddr::V6(dst) => stack
            .ipv6(|ip| {
                ip.set_source(UnicastIpv6Addr::new("fd00::1".parse().unwrap()).unwrap());
                ip.set_destination(dst);
            })
            .udp(udp)
            .build_headers(),
    }
    .unwrap();
    let mut buffer = TestBuffer::new();
    headers.deparse(buffer.as_mut()).unwrap();
    let mut p = Packet::new(buffer).unwrap();
    p.meta_mut().set_overlay(true);
    p.meta_mut().src_vpcd = Some(VpcDiscriminant::VNI(vni(VNI1 + u32::from(dst.is_ipv6()))));
    p.meta_mut().dst_vpcd = Some(VpcDiscriminant::VNI(vni(VNI2 + u32::from(dst.is_ipv6()))));
    p
}

fn component(cbs: u64, ebs: u64) -> MeterProfile {
    MeterProfile {
        profile: Profile::new(rate(1), cbs, None, ebs).unwrap(),
        actions: ColorActions {
            yellow: ColorAction::Remark(Dscp::new(10).unwrap()),
            ..ColorActions::default()
        },
    }
}
fn meter(cbs: u64, ebs: u64) -> Meter {
    Meter {
        bytes: None,
        packets: Some(component(cbs, ebs)),
    }
}
fn rule(destination: &str, meter: &str) -> RateLimitRule {
    let destination: Prefix = destination.parse().unwrap();
    RateLimitRule {
        peering: if destination.is_ipv4() { "p4" } else { "p6" }.into(),
        from: if destination.is_ipv4() {
            "vpc-1"
        } else {
            "vpc-3"
        }
        .into(),
        to: if destination.is_ipv4() {
            "vpc-2"
        } else {
            "vpc-4"
        }
        .into(),
        meter: meter.into(),
        pattern: AclPattern {
            dst: [PrefixWithOptionalPorts::from(destination)].into(),
            ..AclPattern::default()
        },
    }
}
fn configuration(meters: Vec<(&str, Meter)>, rules: Vec<RateLimitRule>) -> ValidatedOverlay {
    let mut vpcs = VpcTable::new();
    vpcs.add(Vpc::new("vpc-1", "AAAAA", VNI1).unwrap()).unwrap();
    vpcs.add(Vpc::new("vpc-2", "BBBBB", VNI2).unwrap()).unwrap();
    vpcs.add(Vpc::new("vpc-3", "CCCCC", VNI1 + 1).unwrap())
        .unwrap();
    vpcs.add(Vpc::new("vpc-4", "DDDDD", VNI2 + 1).unwrap())
        .unwrap();
    let mut peerings = VpcPeeringTable::new();
    for (name, from, to, source, dest) in [
        ("p4", "vpc-1", "vpc-2", "10.0.0.0/24", "10.1.0.0/16"),
        ("p6", "vpc-3", "vpc-4", "fd00::/64", "fd01::/64"),
    ] {
        let mut left = VpcManifest::new(from);
        let mut right = VpcManifest::new(to);
        left.add_expose(VpcExpose::empty().ip(source.parse::<Prefix>().unwrap().into()));
        right.add_expose(VpcExpose::empty().ip(dest.parse::<Prefix>().unwrap().into()));
        peerings
            .add(VpcPeering::new(name, left, right, "default".into()))
            .unwrap();
    }
    Overlay::new(vpcs, peerings)
        .with_rate_limits(RateLimitTables {
            meters: meters
                .into_iter()
                .map(|(name, meter)| (name.into(), meter))
                .collect(),
            rules,
        })
        .validate()
        .unwrap()
}
fn writer(config: &ValidatedOverlay, workers: usize) -> RateLimitWriter<PeeringRules> {
    let w = RateLimitWriter::new(RateLimits::empty(), NonZeroUsize::new(workers).unwrap());
    w.apply(config, Backend::Reference).unwrap();
    w
}
fn burst(
    stage: &mut RateLimiter<PeeringRules>,
    packets: Vec<Packet<TestBuffer>>,
) -> Vec<Packet<TestBuffer>> {
    stage.process(packets).collect()
}
fn dscp(p: &Packet<TestBuffer>) -> u8 {
    match p.try_ip().unwrap() {
        Net::Ipv4(ip) => ip.dscp().value(),
        Net::Ipv6(ip) => ip.dscp().value(),
    }
}
fn counts(limits: &RateLimits<PeeringRules>, name: &str, unit: Unit) -> [u64; 3] {
    let component = limits
        .meters()
        .iter()
        .find(|m| m.name() == name)
        .unwrap()
        .component(unit)
        .unwrap();
    [Color::Green, Color::Yellow, Color::Red].map(|c| component.counted(c).0)
}

#[test]
fn the_first_match_wins_even_when_a_later_prefix_is_longer() {
    let config = configuration(
        vec![("wide", meter(2, 0)), ("narrow", meter(2, 0))],
        vec![rule("10.1.0.0/16", "wide"), rule("10.1.1.0/24", "narrow")],
    );
    let w = writer(&config, 1);
    let limits = w.load();
    let i = limits.classifier.classify(&packet("10.1.1.9", 80)).unwrap();
    assert_eq!(limits.meters()[limits.rules()[i].meter()].name(), "wide");
    assert!(
        limits
            .classifier
            .classify(&packet("10.2.0.1", 80))
            .is_none()
    );
    let mut wrong_vpc = packet("10.1.1.9", 80);
    wrong_vpc.meta_mut().dst_vpcd = Some(VpcDiscriminant::VNI(vni(5000)));
    assert!(limits.classifier.classify(&wrong_vpc).is_none());
}

#[test]
fn rules_share_one_budget_and_counter_set_on_a_worker() {
    let config = configuration(
        vec![("shared", meter(2, 1))],
        vec![rule("10.1.1.0/24", "shared"), rule("10.1.2.0/24", "shared")],
    );
    let w = writer(&config, 1);
    let mut stage = RateLimiter::new(w.reader());
    let out = burst(
        &mut stage,
        ["10.1.1.1", "10.1.2.1", "10.1.1.2", "10.1.2.2"]
            .map(|dst| packet(dst, 80))
            .into(),
    );
    assert_eq!(
        out.iter()
            .map(|p| (p.get_done(), dscp(p)))
            .collect::<Vec<_>>(),
        [
            (None, 0),
            (None, 0),
            (None, 10),
            (Some(DoneReason::RateLimited), 0)
        ]
    );
    assert!(out[2].meta().checksum_refresh());
    assert_eq!(counts(&w.load(), "shared", Unit::Packets), [2, 1, 1]);
}

#[test]
fn workers_share_the_named_meter_budget() {
    let config = configuration(
        vec![("shared", meter(4, 0))],
        vec![rule("10.1.1.0/24", "shared"), rule("10.1.2.0/24", "shared")],
    );
    let w = writer(&config, 2);
    let mut workers = [RateLimiter::new(w.reader()), RateLimiter::new(w.reader())];
    let mut admitted = 0;
    for _ in 0..4 {
        for (i, worker) in workers.iter_mut().enumerate() {
            let out = burst(
                worker,
                vec![packet(if i == 0 { "10.1.1.1" } else { "10.1.2.1" }, 80)],
            );
            admitted += usize::from(out[0].get_done().is_none());
        }
    }
    assert_eq!(admitted, 4);
    assert_eq!(counts(&w.load(), "shared", Unit::Packets), [4, 0, 4]);
}

#[test]
fn a_single_rule_selects_both_components_without_falling_through() {
    let config = configuration(
        vec![
            (
                "bits-only",
                Meter {
                    bytes: Some(component(10000, 0)),
                    packets: None,
                },
            ),
            ("later-pkts", meter(1, 0)),
        ],
        vec![
            rule("10.1.0.0/16", "bits-only"),
            rule("10.1.1.0/24", "later-pkts"),
        ],
    );
    let w = writer(&config, 1);
    let out = burst(
        &mut RateLimiter::new(w.reader()),
        (0..3).map(|_| packet("10.1.1.9", 80)).collect(),
    );
    assert!(out.iter().all(|p| p.get_done().is_none()));
    assert_eq!(counts(&w.load(), "bits-only", Unit::Bytes), [3, 0, 0]);
    assert_eq!(counts(&w.load(), "later-pkts", Unit::Packets), [0, 0, 0]);
}

#[test]
fn packet_meter_preserves_excess_from_the_bandwidth_meter() {
    let cost = u64::from(crate::classify::ip_bytes(
        packet("10.1.1.1", 80).try_ip().unwrap(),
    ));
    let mut pkts = component(10, 2);
    pkts.actions.yellow = ColorAction::Remark(Dscp::new(20).unwrap());
    let config = configuration(
        vec![(
            "both",
            Meter {
                bytes: Some(component(cost, 2 * cost)),
                packets: Some(pkts),
            },
        )],
        vec![rule("10.1.0.0/16", "both")],
    );
    let w = writer(&config, 1);
    let out = burst(
        &mut RateLimiter::new(w.reader()),
        (0..3).map(|_| packet("10.1.1.1", 80)).collect(),
    );
    assert_eq!(out.iter().map(dscp).collect::<Vec<_>>(), [0, 20, 20]);
    assert_eq!(counts(&w.load(), "both", Unit::Bytes), [1, 2, 0]);
    assert_eq!(counts(&w.load(), "both", Unit::Packets), [1, 2, 0]);
}

#[test]
fn bandwidth_drop_stops_packet_accounting() {
    let config = configuration(
        vec![(
            "both",
            Meter {
                bytes: Some(component(1, 0)),
                packets: Some(component(10, 0)),
            },
        )],
        vec![rule("10.1.0.0/16", "both")],
    );
    let w = writer(&config, 1);
    let out = burst(
        &mut RateLimiter::new(w.reader()),
        vec![packet("10.1.1.1", 80)],
    );
    assert_eq!(out[0].get_done(), Some(DoneReason::RateLimited));
    assert_eq!(counts(&w.load(), "both", Unit::Packets), [0, 0, 0]);
}

#[test]
fn changing_rules_keeps_leases_and_changing_profiles_keeps_counters() {
    let config = configuration(vec![("web", meter(2, 1))], vec![rule("10.1.0.0/16", "web")]);
    let w = writer(&config, 1);
    let mut stage = RateLimiter::new(w.reader());
    burst(&mut stage, vec![packet("10.1.1.1", 80)]);
    w.apply(
        &configuration(
            vec![("web", meter(2, 1))],
            vec![rule("10.1.1.0/24", "web"), rule("10.1.2.0/24", "web")],
        ),
        Backend::Reference,
    )
    .unwrap();
    let out = burst(&mut stage, (0..3).map(|_| packet("10.1.1.1", 80)).collect());
    assert_eq!(
        out.iter().map(Packet::get_done).collect::<Vec<_>>(),
        [None, None, Some(DoneReason::RateLimited)]
    );
    assert_eq!(counts(&w.load(), "web", Unit::Packets), [2, 1, 1]);
    w.apply(
        &configuration(vec![("web", meter(5, 0))], vec![rule("10.1.0.0/16", "web")]),
        Backend::Reference,
    )
    .unwrap();
    let out = burst(&mut stage, vec![packet("10.1.1.1", 80)]);
    assert_eq!(out[0].get_done(), None);
    assert_eq!(counts(&w.load(), "web", Unit::Packets), [3, 1, 1]);
}

#[test]
fn unmatched_finished_and_underlay_packets_are_not_charged() {
    let w = writer(
        &configuration(vec![("web", meter(2, 1))], vec![rule("10.1.0.0/16", "web")]),
        1,
    );
    let mut finished = packet("10.1.1.1", 80);
    finished.done(DoneReason::AclDropped);
    let mut underlay = packet("10.1.1.1", 80);
    underlay.meta_mut().set_overlay(false);
    let out = burst(
        &mut RateLimiter::new(w.reader()),
        vec![finished, underlay, packet("10.2.0.1", 80)],
    );
    assert_eq!(
        out.iter().map(Packet::get_done).collect::<Vec<_>>(),
        [Some(DoneReason::AclDropped), None, None]
    );
    assert_eq!(counts(&w.load(), "web", Unit::Packets), [0, 0, 0]);
}

#[test]
fn ipv6_length_remarking_and_counts_use_the_whole_ip_packet() {
    let w = writer(
        &configuration(vec![("v6", meter(1, 1))], vec![rule("fd01::/64", "v6")]),
        1,
    );
    let out = burst(
        &mut RateLimiter::new(w.reader()),
        (0..3).map(|_| packet("fd01::9", 80)).collect(),
    );
    assert_eq!(dscp(&out[1]), 10);
    assert!(out[1].meta().checksum_refresh());
    assert_eq!(out[2].get_done(), Some(DoneReason::RateLimited));
    assert_eq!(
        w.load().meters()[0]
            .component(Unit::Packets)
            .unwrap()
            .counted(Color::Green),
        (1, 48)
    );
}

#[test]
#[dpdk::with_eal]
fn ordered_acl_matches_agree_between_dpdk_and_reference() {
    let mut ports = rule("10.1.0.0/16", "ports");
    ports.pattern.proto = AclProtoMatch::Udp;
    ports.pattern.dst_any_ports = vec![(80..=90).try_into().unwrap()];
    ports.pattern.dst = PrefixPortsSet::default();
    let config = configuration(
        vec![("ports", meter(1, 0)), ("fallback", meter(1, 0))],
        vec![
            ports,
            rule("10.1.0.0/16", "fallback"),
            rule("fd01::/64", "fallback"),
        ],
    );
    let build = |backend| {
        RateLimits::build(
            &config,
            &RateLimits::empty(),
            NonZeroUsize::MIN,
            clock::now(),
            backend,
        )
        .unwrap()
    };
    bolero::check!()
        .with_type::<(bool, u8, u16)>()
        .for_each(|(v6, host, port)| {
            let reference = build(Backend::Reference);
            let dpdk = build(Backend::Dpdk);
            let dst = if *v6 {
                format!("fd01::{host:x}")
            } else {
                format!("10.1.1.{host}")
            };
            let p = packet(&dst, (*port).max(1));
            assert_eq!(
                dpdk.classifier.classify(&p),
                reference.classifier.classify(&p)
            );
            let expected = if *v6 {
                2
            } else {
                usize::from(!(80..=90).contains(port))
            };
            assert_eq!(reference.classifier.classify(&p), Some(expected));
        });
}

#[test]
fn cli_and_prometheus_report_each_shared_meter_once() {
    let w = writer(
        &configuration(
            vec![("shared", meter(2, 1))],
            vec![rule("10.1.1.0/24", "shared"), rule("10.1.2.0/24", "shared")],
        ),
        1,
    );
    burst(
        &mut RateLimiter::new(w.reader()),
        (0..4).map(|_| packet("10.1.1.1", 80)).collect(),
    );
    let limits = w.load();
    let rendered = limits.to_string();
    assert_eq!(rendered.lines().filter(|l| *l == "meter shared").count(), 1);
    assert!(rendered.contains("rule 0:"));
    assert!(rendered.contains("rule 1:"));
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    metrics::with_local_recorder(&recorder, || {
        limits.publish_metrics();
        limits.publish_metrics();
    });
    let scrape = recorder.handle().render();
    for (result, n) in [("conforming", 2), ("excess", 1), ("over_limit", 1)] {
        let line = scrape
            .lines()
            .find(|l| {
                l.starts_with("rate_limit_packets_total{")
                    && l.contains(&format!("result=\"{result}\""))
            })
            .unwrap_or_else(|| panic!("{scrape}"));
        assert!(line.contains("meter=\"shared\""));
        assert!(line.ends_with(&format!(" {n}")), "{line}");
    }
}

#[test]
fn prometheus_counters_survive_profile_changes_and_meter_recreation() {
    let config = |cbs| {
        configuration(
            vec![("shared", meter(cbs, 0))],
            vec![rule("10.1.0.0/16", "shared")],
        )
    };
    let w = writer(&config(1), 1);
    let mut stage = RateLimiter::new(w.reader());
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    metrics::with_local_recorder(&recorder, || {
        burst(&mut stage, vec![packet("10.1.1.1", 80)]);
        w.load().publish_metrics();
        w.apply(&config(2), Backend::Reference).unwrap();
        burst(&mut stage, vec![packet("10.1.1.1", 80)]);
        w.load().publish_metrics();
        w.apply(&configuration(vec![], vec![]), Backend::Reference)
            .unwrap();
        w.apply(&config(1), Backend::Reference).unwrap();
        burst(&mut stage, vec![packet("10.1.1.1", 80)]);
        w.load().publish_metrics();
        w.load().publish_metrics();
    });
    let scrape = recorder.handle().render();
    let line = scrape
        .lines()
        .find(|l| l.starts_with("rate_limit_packets_total{") && l.contains("result=\"conforming\""))
        .unwrap();
    assert!(line.ends_with(" 3"), "{line}");
}
