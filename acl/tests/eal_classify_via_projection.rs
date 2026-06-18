// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![cfg(feature = "dpdk")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use core::net::Ipv4Addr;
use core::num::NonZero;

use dataplane_acl::dpdk::install::install_table;
use dataplane_acl::dpdk::rule::{Dpdk, RuleSpec};
use dataplane_acl::dpdk_table_alias;
use dpdk::acl::{CategoryMask, Priority};
use lookup::{Lookup, Projection};
use match_action::{ExactSpec, FixedSize, MatchKey, PrefixSpec, RangeSpec};
use net::eth::Eth;
use net::headers::builder::HeaderStack;
use net::headers::{HeadersView, Look};
use net::ipv4::{Ipv4, UnicastIpv4Addr};
use net::tcp::{Tcp, TcpPort};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct IpProto(u8);

impl FixedSize for IpProto {
    const SIZE: usize = 1;
    fn write_be(&self, out: &mut [u8]) {
        out[0] = self.0;
    }
}

#[derive(MatchKey)]
#[allow(dead_code)]
struct FiveTuple {
    #[exact]
    proto: IpProto,
    #[prefix]
    src_ip: Ipv4Addr,
    #[prefix]
    dst_ip: Ipv4Addr,
    #[range]
    src_port: u16,
    #[range]
    dst_port: u16,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
enum Verdict {
    Allow,
    Drop,
}

dpdk_table_alias!(type FiveTupleTable<A> = FiveTuple);
struct V4TcpSource<'a>(&'a HeadersView<(&'a Eth, &'a Ipv4, &'a Tcp)>);

impl Projection<FiveTuple> for &V4TcpSource<'_> {
    fn project(self) -> FiveTuple {
        let (_eth, ipv4, tcp) = self.0.look();
        FiveTuple {
            proto: IpProto(6),
            src_ip: ipv4.source().inner(),
            dst_ip: ipv4.destination(),
            src_port: u16::from(tcp.source()),
            dst_port: u16::from(tcp.destination()),
        }
    }
}

fn build_packet(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> net::headers::Headers {
    HeaderStack::new()
        .eth(|_| {})
        .ipv4(|ip| {
            ip.set_source(UnicastIpv4Addr::new(src).unwrap());
            ip.set_destination(dst);
        })
        .tcp(|tcp| {
            tcp.set_source(TcpPort::try_from(sport).unwrap());
            tcp.set_destination(TcpPort::try_from(dport).unwrap());
        })
        .build_headers()
        .unwrap()
}

#[dpdk::with_eal]
#[test]
fn classify_real_packet_via_projection() {
    let rule = FiveTupleRule {
        proto: ExactSpec::new(IpProto(6)),
        src_ip: PrefixSpec::new(Ipv4Addr::new(10, 0, 0, 0), 8),
        dst_ip: PrefixSpec::new(Ipv4Addr::UNSPECIFIED, 0),
        src_port: RangeSpec::new(0, u16::MAX),
        dst_port: RangeSpec::exact(22),
    };
    let rule_spec = RuleSpec::<FiveTuple, Verdict>::new(
        Priority::new(100).expect("priority"),
        CategoryMask::new(1).expect("category mask"),
        rule.into_backend_fields::<Dpdk>(),
        Verdict::Drop,
    )
    .expect("RuleSpec");

    let table: FiveTupleTable<Verdict> = install_table(
        "eal_classify_via_projection",
        NonZero::new(16).expect("max rules"),
        vec![rule_spec],
    )
    .expect("install_table");
    let hit = build_packet(
        Ipv4Addr::new(10, 0, 1, 5),
        Ipv4Addr::new(192, 168, 1, 1),
        54321,
        22,
    );
    let view = hit.as_view::<(&Eth, &Ipv4, &Tcp)>().expect("v4 tcp shape");
    let src = V4TcpSource(view);
    assert_eq!(table.classify(&src), Some(&Verdict::Drop));
    let miss = build_packet(
        Ipv4Addr::new(192, 168, 1, 5),
        Ipv4Addr::new(192, 168, 1, 1),
        54321,
        22,
    );
    let miss_view = miss.as_view::<(&Eth, &Ipv4, &Tcp)>().unwrap();
    assert_eq!(table.classify(&V4TcpSource(miss_view)), None);
}

#[test]
fn non_tcp_packet_cannot_be_projected_to_five_tuple() {
    let udp = HeaderStack::new()
        .eth(|_| {})
        .ipv4(|_| {})
        .udp(|_| {})
        .build_headers()
        .unwrap();
    assert!(udp.as_view::<(&Eth, &Ipv4, &Tcp)>().is_none());
}
