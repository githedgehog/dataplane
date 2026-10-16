// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::{Classify, RateLimitWriter, RateLimiter, RateLimits, VpcDestination};
use acl::table::Backend;
use config::external::overlay::ratelimit::{
    ColorAction, ColorActions, RateLimit, RateLimitTable, RateLimitTables,
};
use config::external::overlay::vpc::{Vpc, VpcTable};
use config::external::overlay::vpcpeering::VpcPeeringTable;
use config::external::overlay::{Overlay, ValidatedOverlay};
use lpm::prefix::Prefix;
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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::{NonZeroU64, NonZeroUsize};

const VNI1: u32 = 3000;
const VNI2: u32 = 4000;

fn vni(id: u32) -> Vni {
    Vni::new_checked(id).unwrap()
}

/// A UDP packet from VPC `src_vni` to `dst`, as ingress leaves it.
fn packet(src_vni: u32, dst: IpAddr) -> Packet<TestBuffer> {
    let udp = |udp: &mut net::udp::Udp| {
        udp.set_source(UdpPort::try_from(1234).unwrap());
        udp.set_destination(UdpPort::try_from(80).unwrap());
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
    let mut packet = Packet::new(buffer).unwrap();
    packet.meta_mut().set_overlay(true);
    packet.meta_mut().src_vpcd = Some(VpcDiscriminant::VNI(vni(src_vni)));
    packet
}

fn v4(dst: &str) -> IpAddr {
    IpAddr::V4(dst.parse().unwrap())
}

fn rate(per_second: u64) -> Rate {
    Rate::new(NonZeroU64::new(per_second).unwrap())
}

/// Two green, then one yellow, then red, until time passes: of packets in the packet table.
fn two_then_one() -> Profile {
    Profile::new(rate(1), 2, None, 1).unwrap()
}

fn remark_yellow_drop_red() -> ColorActions {
    ColorActions {
        green: ColorAction::Pass,
        yellow: ColorAction::Remark(Dscp::new(10).unwrap()),
        red: ColorAction::Drop,
    }
}

fn rate_limit(name: &str, vpc: &str, destination: &str, profile: Profile) -> RateLimit {
    RateLimit {
        name: name.to_string(),
        vpc: vpc.to_string(),
        destination: destination.parse::<Prefix>().unwrap(),
        profile,
        actions: remark_yellow_drop_red(),
    }
}

fn table(limits: Vec<RateLimit>) -> RateLimitTable {
    let mut table = RateLimitTable::new();
    for limit in limits {
        table.add(limit).unwrap();
    }
    table
}

/// An overlay with `bytes` in the byte table and `packets` in the packet table.
fn tables(bytes: Vec<RateLimit>, packets: Vec<RateLimit>) -> ValidatedOverlay {
    let mut vpcs = VpcTable::new();
    vpcs.add(Vpc::new("vpc-1", "AAAAA", VNI1).unwrap()).unwrap();
    vpcs.add(Vpc::new("vpc-2", "BBBBB", VNI2).unwrap()).unwrap();
    Overlay::new(vpcs, VpcPeeringTable::new())
        .with_rate_limits(RateLimitTables {
            bytes: table(bytes),
            packets: table(packets),
        })
        .validate()
        .unwrap()
}

/// An overlay with `packets` in the packet table, and no byte limits.
fn overlay(packets: Vec<RateLimit>) -> ValidatedOverlay {
    tables(Vec::new(), packets)
}

fn writer(overlay: &ValidatedOverlay) -> RateLimitWriter<VpcDestination> {
    let writer = RateLimitWriter::new(RateLimits::empty(), NonZeroUsize::MIN);
    writer.apply(overlay, Backend::Reference).unwrap();
    writer
}

/// Run `packets` through `stage` as one burst.
fn burst(
    stage: &mut RateLimiter<VpcDestination>,
    packets: Vec<Packet<TestBuffer>>,
) -> Vec<Packet<TestBuffer>> {
    stage.process(packets).collect()
}

fn dscp(packet: &Packet<TestBuffer>) -> u8 {
    match packet.try_ip().unwrap() {
        Net::Ipv4(ip) => ip.dscp().value(),
        Net::Ipv6(ip) => ip.dscp().value(),
    }
}

#[test]
fn the_longest_destination_decides() {
    let limits = RateLimits::build(
        &overlay(vec![
            rate_limit("wide", "vpc-1", "10.1.0.0/16", two_then_one()),
            rate_limit("narrow", "vpc-1", "10.1.1.0/24", two_then_one()),
            rate_limit("v6", "vpc-1", "fd01::/64", two_then_one()),
        ]),
        &RateLimits::empty(),
        NonZeroUsize::MIN,
        clock::now(),
        Backend::Reference,
    )
    .unwrap();
    let named = |packet| {
        let table = limits.packets();
        table
            .classifier
            .classify(&packet)
            .map(|i| table.rules()[i].name())
    };
    assert_eq!(named(packet(VNI1, v4("10.1.1.9"))), Some("narrow"));
    assert_eq!(named(packet(VNI1, v4("10.1.2.9"))), Some("wide"));
    assert_eq!(named(packet(VNI1, v4("10.2.0.1"))), None);
    // Another VPC's traffic to the same destination is not this VPC's.
    assert_eq!(named(packet(VNI2, v4("10.1.1.9"))), None);
    let v6: Ipv6Addr = "fd01::9".parse().unwrap();
    assert_eq!(named(packet(VNI1, IpAddr::V6(v6))), Some("v6"));
}

#[test]
fn each_color_gets_its_action() {
    let writer = writer(&overlay(vec![rate_limit(
        "web",
        "vpc-1",
        "10.1.0.0/16",
        two_then_one(),
    )]));
    let mut stage = RateLimiter::new(writer.reader());
    let out = burst(
        &mut stage,
        (0..4).map(|_| packet(VNI1, v4("10.1.0.1"))).collect(),
    );
    let verdicts: Vec<_> = out
        .iter()
        .map(|packet| (packet.get_done(), dscp(packet)))
        .collect();
    assert_eq!(
        verdicts,
        [
            (None, 0),
            (None, 0),
            (None, 10),
            (Some(DoneReason::RateLimited), 0)
        ]
    );
    assert!(out[2].meta().checksum_refresh());
    let limits = writer.load();
    let rule = &limits.packets().rules()[0];
    let bytes = |n: u64| n * u64::from(crate::classify::ip_bytes(out[0].try_ip().unwrap()));
    assert_eq!(rule.counted(Color::Green), (2, bytes(2)));
    assert_eq!(rule.counted(Color::Yellow), (1, bytes(1)));
    assert_eq!(rule.counted(Color::Red), (1, bytes(1)));
}

#[test]
fn unmatched_finished_and_underlay_packets_pass_untouched() {
    let writer = writer(&overlay(vec![rate_limit(
        "web",
        "vpc-1",
        "10.1.0.0/16",
        two_then_one(),
    )]));
    let mut stage = RateLimiter::new(writer.reader());
    let mut finished = packet(VNI1, v4("10.1.0.1"));
    finished.done(DoneReason::AclDropped);
    let mut underlay = packet(VNI1, v4("10.1.0.1"));
    underlay.meta_mut().set_overlay(false);
    let elsewhere = (0..4).map(|_| packet(VNI1, v4("10.9.0.1")));
    let out = burst(
        &mut stage,
        [finished, underlay].into_iter().chain(elsewhere).collect(),
    );
    let verdicts: Vec<_> = out.iter().map(Packet::get_done).collect();
    assert_eq!(
        verdicts,
        [Some(DoneReason::AclDropped), None, None, None, None, None]
    );
    let limits = writer.load();
    for color in [Color::Green, Color::Yellow, Color::Red] {
        assert_eq!(limits.packets().rules()[0].counted(color), (0, 0));
    }
}

#[test]
fn a_rule_that_survives_a_new_configuration_keeps_its_meter_and_counts() {
    let web = || rate_limit("web", "vpc-1", "10.1.0.0/16", two_then_one());
    let config = overlay(vec![web()]);
    let writer = writer(&config);
    let mut stage = RateLimiter::new(writer.reader());
    burst(&mut stage, vec![packet(VNI1, v4("10.1.0.1"))]);

    // Another rule comes; web stays as it was, and so its bucket does not refill.
    writer
        .apply(
            &overlay(vec![
                web(),
                rate_limit("other", "vpc-2", "10.1.0.0/16", two_then_one()),
            ]),
            Backend::Reference,
        )
        .unwrap();
    let out = burst(
        &mut stage,
        (0..3).map(|_| packet(VNI1, v4("10.1.0.1"))).collect(),
    );
    assert_eq!(
        out.iter().map(Packet::get_done).collect::<Vec<_>>(),
        [None, None, Some(DoneReason::RateLimited)]
    );
    let limits = writer.load();
    let web = limits
        .packets()
        .rules()
        .iter()
        .find(|r| r.name() == "web")
        .unwrap();
    assert_eq!(web.counted(Color::Green).0, 2);
    assert_eq!(web.counted(Color::Yellow).0, 1);

    // Changing web's profile starts it afresh.
    let wider = Profile::new(rate(1), 5, None, 0).unwrap();
    writer
        .apply(
            &overlay(vec![rate_limit("web", "vpc-1", "10.1.0.0/16", wider)]),
            Backend::Reference,
        )
        .unwrap();
    let out = burst(&mut stage, vec![packet(VNI1, v4("10.1.0.1"))]);
    assert_eq!(out[0].get_done(), None);
    assert_eq!(
        writer.load().packets().rules()[0].counted(Color::Green),
        (1, {
            u64::from(crate::classify::ip_bytes(out[0].try_ip().unwrap()))
        })
    );
}

#[test]
fn rate_limits_render_their_rules_and_counts() {
    let writer = writer(&overlay(vec![rate_limit(
        "web",
        "vpc-1",
        "10.1.0.0/16",
        two_then_one(),
    )]));
    let mut stage = RateLimiter::new(writer.reader());
    burst(
        &mut stage,
        (0..4).map(|_| packet(VNI1, v4("10.1.0.1"))).collect(),
    );
    let rendered = writer.load().to_string();
    let lines: Vec<_> = rendered.lines().collect();
    assert_eq!(
        lines[0],
        "rate limit web: from vpc-1 (vni 3000) to 10.1.0.0/16"
    );
    assert_eq!(lines[1], "  packets: cir 1/s cbs 2 ebs 1");
    assert!(lines[2].starts_with("  green:  pass "), "{rendered}");
    assert!(lines[2].contains(" 2 packets"), "{rendered}");
    assert!(
        lines[3].starts_with("  yellow: remark dscp 10 "),
        "{rendered}"
    );
    assert!(lines[4].starts_with("  red:    drop "), "{rendered}");
    assert_eq!(
        RateLimits::empty().to_string(),
        "no rate limits are configured\n"
    );
}

#[test]
#[dpdk::with_eal]
fn rte_acl_classifies_as_the_reference_does() {
    let config = overlay(vec![
        rate_limit("wide", "vpc-1", "10.1.0.0/16", two_then_one()),
        rate_limit("narrow", "vpc-1", "10.1.1.0/24", two_then_one()),
        rate_limit("host", "vpc-1", "10.1.1.1/32", two_then_one()),
        rate_limit("other-vpc", "vpc-2", "10.0.0.0/8", two_then_one()),
        rate_limit("v6", "vpc-1", "fd01::/64", two_then_one()),
    ]);
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
    let (reference, dpdk) = (build(Backend::Reference), build(Backend::Dpdk));
    let destinations = [
        v4("10.1.1.1"),
        v4("10.1.1.2"),
        v4("10.1.2.1"),
        v4("10.2.0.1"),
        v4("11.0.0.1"),
        IpAddr::V6("fd01::1".parse().unwrap()),
        IpAddr::V6("fd02::1".parse().unwrap()),
    ];
    for src in [VNI1, VNI2] {
        for dst in destinations {
            let packet = packet(src, dst);
            assert_eq!(
                dpdk.packets().classifier.classify(&packet),
                reference.packets().classifier.classify(&packet),
                "vni {src} to {dst}"
            );
        }
    }
}

/// A byte limit: `cbs` bytes green and `ebs` yellow, at a byte a second.
fn bytes_limit(
    name: &str,
    destination: &str,
    cbs: u64,
    ebs: u64,
    actions: ColorActions,
) -> RateLimit {
    RateLimit {
        actions,
        ..rate_limit(
            name,
            "vpc-1",
            destination,
            Profile::new(rate(1), cbs, None, ebs).unwrap(),
        )
    }
}

fn pass_all() -> ColorActions {
    ColorActions {
        green: ColorAction::Pass,
        yellow: ColorAction::Pass,
        red: ColorAction::Pass,
    }
}

fn colors_counted(rule: &crate::Rule) -> [u64; 3] {
    [Color::Green, Color::Yellow, Color::Red].map(|color| rule.counted(color).0)
}

/// The byte table and the packet table both meter a packet, each with the rule whose destination is
/// its own longest match.
#[test]
fn a_byte_limit_and_a_packet_limit_both_apply() {
    let probe = packet(VNI1, v4("10.1.1.1"));
    let size = u64::from(crate::classify::ip_bytes(probe.try_ip().unwrap()));
    let writer = writer(&tables(
        vec![bytes_limit(
            "bytes",
            "10.1.0.0/16",
            10 * size,
            0,
            pass_all(),
        )],
        vec![rate_limit(
            "packets",
            "vpc-1",
            "10.1.1.0/24",
            two_then_one(),
        )],
    ));
    let mut stage = RateLimiter::new(writer.reader());
    burst(
        &mut stage,
        (0..3).map(|_| packet(VNI1, v4("10.1.1.1"))).collect(),
    );
    let limits = writer.load();
    assert_eq!(colors_counted(&limits.bytes().rules()[0]), [3, 0, 0]);
    assert_eq!(colors_counted(&limits.packets().rules()[0]), [2, 1, 0]);
}

/// The packet table's meters are color-aware: a packet the byte table colored yellow is at best
/// yellow, and pays the packet meter's excess bucket, not its committed one.
#[test]
fn the_packet_table_never_colors_better_than_the_byte_table() {
    let probe = packet(VNI1, v4("10.1.1.1"));
    let size = u64::from(crate::classify::ip_bytes(probe.try_ip().unwrap()));
    let roomy = Profile::new(rate(1), 100, None, 100).unwrap();
    let writer = writer(&tables(
        // One packet's worth green, the rest yellow.
        vec![bytes_limit(
            "bytes",
            "10.1.0.0/16",
            size,
            100 * size,
            pass_all(),
        )],
        vec![rate_limit("packets", "vpc-1", "10.1.0.0/16", roomy)],
    ));
    let mut stage = RateLimiter::new(writer.reader());
    burst(
        &mut stage,
        (0..3).map(|_| packet(VNI1, v4("10.1.1.1"))).collect(),
    );
    let limits = writer.load();
    assert_eq!(colors_counted(&limits.bytes().rules()[0]), [1, 2, 0]);
    assert_eq!(colors_counted(&limits.packets().rules()[0]), [1, 2, 0]);
}

/// Each table acts on its color in turn: a packet the byte table drops never reaches the packet
/// table, and of two remarks the packet table's stays.
#[test]
fn each_table_acts_in_turn() {
    let probe = packet(VNI1, v4("10.1.1.1"));
    let size = u64::from(crate::classify::ip_bytes(probe.try_ip().unwrap()));
    let remark_yellow_to = |dscp| ColorActions {
        green: ColorAction::Pass,
        yellow: ColorAction::Remark(Dscp::new(dscp).unwrap()),
        red: ColorAction::Drop,
    };
    let roomy = Profile::new(rate(1), 0, None, 100).unwrap();
    let writer = writer(&tables(
        // Yellow for one packet, then red.
        vec![bytes_limit(
            "bytes",
            "10.1.0.0/16",
            0,
            size,
            remark_yellow_to(10),
        )],
        vec![RateLimit {
            actions: remark_yellow_to(20),
            ..rate_limit("packets", "vpc-1", "10.1.0.0/16", roomy)
        }],
    ));
    let mut stage = RateLimiter::new(writer.reader());
    let out = burst(
        &mut stage,
        (0..2).map(|_| packet(VNI1, v4("10.1.1.1"))).collect(),
    );
    assert_eq!(out[0].get_done(), None);
    assert_eq!(dscp(&out[0]), 20);
    assert_eq!(out[1].get_done(), Some(DoneReason::RateLimited));
    let limits = writer.load();
    assert_eq!(colors_counted(&limits.bytes().rules()[0]), [0, 1, 1]);
    assert_eq!(colors_counted(&limits.packets().rules()[0]), [0, 1, 0]);
}

#[test]
fn byte_limits_render_first_and_say_what_they_count() {
    let writer = writer(&tables(
        vec![bytes_limit("b", "10.1.0.0/16", 1500, 0, pass_all())],
        vec![rate_limit("p", "vpc-1", "10.1.0.0/16", two_then_one())],
    ));
    let rendered = writer.load().to_string();
    let lines: Vec<_> = rendered.lines().collect();
    assert_eq!(
        lines[0],
        "rate limit b: from vpc-1 (vni 3000) to 10.1.0.0/16"
    );
    assert_eq!(lines[1], "  bytes: cir 1/s cbs 1500 ebs 0");
    assert_eq!(
        lines[5],
        "rate limit p: from vpc-1 (vni 3000) to 10.1.0.0/16"
    );
    assert_eq!(lines[6], "  packets: cir 1/s cbs 2 ebs 1");
}
