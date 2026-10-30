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
use lookup::{Lookup, Projection};
use match_action::{ExactSpec, MatchKey, PrefixSpec, RangeSpec};
use net::eth::Eth;
use net::headers::builder::HeaderStack;
use net::headers::{HeadersView, Look};
use net::ipv4::{Ipv4, UnicastIpv4Addr};
use net::packet::{PacketMeta, VpcDiscriminant, VrfId};
use net::tcp::{Tcp, TcpPort};
use net::vxlan::Vni;
#[derive(MatchKey, Debug, Clone, Copy)]
struct OverlayFlowKey {
    #[exact]
    proto: u8,
    #[prefix]
    src: Ipv4Addr,
    #[range]
    dport: u16,
    #[exact]
    vrf: VrfId,
    #[exact]
    vni: Vni,
}

dpdk_table_alias!(type OverlayFlowTable<A> = OverlayFlowKey);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Verdict {
    Drop,
}
struct PacketSource<'a> {
    view: &'a HeadersView<(&'a Eth, &'a Ipv4, &'a Tcp)>,
    meta: &'a PacketMeta,
}

impl Projection<Option<OverlayFlowKey>> for &PacketSource<'_> {
    fn project(self) -> Option<OverlayFlowKey> {
        let (_eth, ipv4, tcp) = self.view.look();
        Some(OverlayFlowKey {
            proto: 6,
            src: ipv4.source().inner(),
            dport: tcp.destination().as_u16(),
            vrf: self.meta.vrf?,
            vni: Vni::try_from(self.meta.src_vpcd?).ok()?,
        })
    }
}

fn rule() -> OverlayFlowKeyRule {
    OverlayFlowKeyRule {
        proto: ExactSpec::new(6),
        src: PrefixSpec::new(Ipv4Addr::new(10, 0, 0, 0), 8),
        dport: RangeSpec::exact(443),
        vrf: ExactSpec::new(42),
        vni: ExactSpec::new(Vni::new_checked(1000).unwrap()),
    }
}

fn packet(src: Ipv4Addr, dport: u16) -> net::headers::Headers {
    HeaderStack::new()
        .eth(|_| {})
        .ipv4(|ip| {
            ip.set_source(UnicastIpv4Addr::new(src).unwrap());
            ip.set_destination(Ipv4Addr::new(192, 0, 2, 1));
        })
        .tcp(|tcp| {
            tcp.set_source(TcpPort::try_from(40000u16).unwrap());
            tcp.set_destination(TcpPort::try_from(dport).unwrap());
        })
        .build_headers()
        .unwrap()
}
#[allow(clippy::field_reassign_with_default)]
fn meta_with(vrf: Option<VrfId>, vni: Option<Vni>) -> PacketMeta {
    let mut meta = PacketMeta::default();
    meta.vrf = vrf;
    meta.src_vpcd = vni.map(VpcDiscriminant::from);
    meta
}

#[test]
#[dpdk::with_eal]
fn classify_on_headers_plus_metadata() {
    let dpdk: OverlayFlowTable<Verdict> = install_table(
        "metadata_projection",
        NonZero::new(8).unwrap(),
        vec![
            RuleSpec::<OverlayFlowKey, Verdict>::new(
                Priority::new(1).unwrap(),
                CategoryMask::new(1).unwrap(),
                rule().into_backend_fields::<Dpdk>(),
                Verdict::Drop,
            )
            .unwrap(),
        ],
    )
    .expect("install_table");
    let reference = ReferenceTable::<OverlayFlowKey, Verdict>::new(vec![RefRule::new(
        rule().into_backend_fields::<Erased>(),
        Verdict::Drop,
    )]);

    let headers = packet(Ipv4Addr::new(10, 9, 9, 9), 443);
    let view = headers
        .as_view::<(&Eth, &Ipv4, &Tcp)>()
        .expect("v4 tcp shape");
    let vni = Vni::new_checked(1000).unwrap();
    let full = meta_with(Some(42), Some(vni));
    let src = PacketSource { view, meta: &full };
    assert_eq!(dpdk.classify_opt(&src), Some(&Verdict::Drop));
    assert_eq!(
        reference.classify_opt(&PacketSource { view, meta: &full }),
        Some(&Verdict::Drop)
    );
    let no_vrf = meta_with(None, Some(vni));
    assert_eq!(
        dpdk.classify_opt(&PacketSource {
            view,
            meta: &no_vrf
        }),
        None
    );
    assert_eq!(
        reference.classify_opt(&PacketSource {
            view,
            meta: &no_vrf
        }),
        None
    );
    let wrong_vni = meta_with(Some(42), Some(Vni::new_checked(2000).unwrap()));
    assert_eq!(
        dpdk.classify_opt(&PacketSource {
            view,
            meta: &wrong_vni
        }),
        None
    );
    assert_eq!(
        reference.classify_opt(&PacketSource {
            view,
            meta: &wrong_vni
        }),
        None
    );
}
#[test]
#[dpdk::with_eal]
fn classify_opt_accepts_an_inline_key() {
    let dpdk: OverlayFlowTable<Verdict> = install_table(
        "metadata_projection_by",
        NonZero::new(8).unwrap(),
        vec![
            RuleSpec::<OverlayFlowKey, Verdict>::new(
                Priority::new(1).unwrap(),
                CategoryMask::new(1).unwrap(),
                rule().into_backend_fields::<Dpdk>(),
                Verdict::Drop,
            )
            .unwrap(),
        ],
    )
    .expect("install_table");

    let headers = packet(Ipv4Addr::new(10, 9, 9, 9), 443);
    let view = headers
        .as_view::<(&Eth, &Ipv4, &Tcp)>()
        .expect("v4 tcp shape");
    let key_for = |meta: &PacketMeta| -> Option<OverlayFlowKey> {
        let (_eth, ipv4, tcp) = view.look();
        Some(OverlayFlowKey {
            proto: 6,
            src: ipv4.source().inner(),
            dport: tcp.destination().as_u16(),
            vrf: meta.vrf?,
            vni: Vni::try_from(meta.src_vpcd?).ok()?,
        })
    };

    let full = meta_with(Some(42), Some(Vni::new_checked(1000).unwrap()));
    assert_eq!(dpdk.classify_opt(key_for(&full)), Some(&Verdict::Drop));
    let no_vrf = meta_with(None, Some(Vni::new_checked(1000).unwrap()));
    assert_eq!(dpdk.classify_opt(key_for(&no_vrf)), None);
}
