// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![cfg(feature = "dpdk")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use core::net::Ipv4Addr;
use core::num::NonZero;

use dataplane_acl::dpdk::install::install_table;
use dataplane_acl::dpdk::rule::{Dpdk, RuleSpec};
use dataplane_acl::dpdk_table_alias;
use dataplane_acl::reference::{Erased, RefRule, ReferenceTable};
use dpdk::acl::{CategoryMask, Priority};
use lookup::Lookup;
use match_action::{ExactSpec, MatchKey, PrefixSpec};
use net::ipv4::UnicastIpv4Addr;
use net::tcp::TcpPort;
use net::vxlan::Vni;
#[derive(MatchKey, Debug, Clone, Copy)]
struct OverlayKey {
    #[exact]
    proto: u8,
    #[prefix]
    src: UnicastIpv4Addr,
    #[exact]
    vni: Vni,
    #[exact]
    dport: TcpPort,
}

dpdk_table_alias!(type OverlayTable<A> = OverlayKey);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Verdict {
    Drop,
}

fn unicast(addr: &str) -> UnicastIpv4Addr {
    UnicastIpv4Addr::new(addr.parse::<Ipv4Addr>().unwrap()).unwrap()
}

fn rule() -> OverlayKeyRule {
    OverlayKeyRule {
        proto: ExactSpec::new(6),
        src: PrefixSpec::new(unicast("10.0.0.0"), 8),
        vni: ExactSpec::new(Vni::new_checked(1000).unwrap()),
        dport: ExactSpec::new(TcpPort::new_checked(443).unwrap()),
    }
}

#[test]
#[dpdk::with_eal]
fn net_newtypes_classify_through_dpdk_and_reference() {
    let spec = RuleSpec::<OverlayKey, Verdict>::new(
        Priority::new(1).unwrap(),
        CategoryMask::new(1).unwrap(),
        rule().into_backend_fields::<Dpdk>(),
        Verdict::Drop,
    )
    .unwrap();
    let dpdk: OverlayTable<Verdict> =
        install_table("net_field_types", NonZero::new(8).unwrap(), vec![spec])
            .expect("install_table");
    let reference = ReferenceTable::<OverlayKey, Verdict>::new(vec![RefRule::new(
        rule().into_backend_fields::<Erased>(),
        Verdict::Drop,
    )]);

    let hit = OverlayKey {
        proto: 6,
        src: unicast("10.9.9.9"),
        vni: Vni::new_checked(1000).unwrap(),
        dport: TcpPort::new_checked(443).unwrap(),
    };
    assert_eq!(dpdk.lookup(&hit), Some(&Verdict::Drop));
    assert_eq!(reference.lookup(&hit), Some(&Verdict::Drop));
    let wrong_vni = OverlayKey {
        vni: Vni::new_checked(2000).unwrap(),
        ..hit
    };
    assert_eq!(dpdk.lookup(&wrong_vni), None);
    assert_eq!(reference.lookup(&wrong_vni), None);
    let off_prefix = OverlayKey {
        src: unicast("11.0.0.1"),
        ..hit
    };
    assert_eq!(dpdk.lookup(&off_prefix), None);
    assert_eq!(reference.lookup(&off_prefix), None);
    let wrong_port = OverlayKey {
        dport: TcpPort::new_checked(80).unwrap(),
        ..hit
    };
    assert_eq!(dpdk.lookup(&wrong_port), None);
    assert_eq!(reference.lookup(&wrong_port), None);
}
