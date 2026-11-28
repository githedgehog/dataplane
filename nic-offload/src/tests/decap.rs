// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Decapsulation in the NIC: what arrives decapsulated with its VNI in META, and what not; and
//! that everything the switch passes on is stamped (the trap rule).

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use dpdk::flow::template::TemplateAction;
use dpdk::queue::rx::RxQueueIndex;
use net::vxlan::Vni;

use crate::mlx5::{META_VXLAN, Plan, vni_of_meta};
use crate::model::{Outcome, Verdict};
use crate::program::Program;

const VTEP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);

/// IPv4 VXLAN to `vtep` with `vni`, outer TTL `ttl` from `src`, carrying a small inner frame.
fn vxlan(vni: u32, vtep: Ipv4Addr, src: Ipv4Addr, ttl: u8) -> Vec<u8> {
    let mut inner = vec![
        0x02, 0, 0, 0x99, 0, 1, 0x02, 0x99, 0xfa, 0, 0, 1, 0x08, 0x00,
    ];
    inner.extend([
        0x45, 0, 0, 28, 0, 0, 0x40, 0, 64, 17, 0, 0, 10, 0, 1, 5, 10, 0, 2, 2,
    ]);
    inner.extend([0x04, 0x00, 0x00, 0x50, 0, 8, 0, 0]);
    let udp_len = u16::try_from(16 + inner.len()).unwrap_or(u16::MAX);
    let mut f = vec![0x02, 0, 0, 0, 0, 4, 0x02, 0, 0, 0, 0, 3, 0x08, 0x00];
    f.extend([0x45, 0]);
    f.extend((udp_len + 20).to_be_bytes());
    f.extend([0, 0, 0x40, 0, ttl, 17, 0, 0]);
    f.extend(src.octets());
    f.extend(vtep.octets());
    f.extend([0xc0, 0x00, 0x12, 0xb5]);
    f.extend(udp_len.to_be_bytes());
    f.extend([0, 0]);
    let v = vni.to_be_bytes();
    f.extend([0x08, 0, 0, 0, v[1], v[2], v[3], 0]);
    f.extend(inner);
    f
}

fn vni(v: u32) -> Vni {
    Vni::new_checked(v).unwrap_or_else(|_| unreachable!())
}

/// A plan with no NIC rules at all, decapsulating for `vnis` (all at [`VTEP`]).
fn plan(vnis: &[u32]) -> Plan {
    let vteps: BTreeMap<Vni, Ipv4Addr> = vnis.iter().map(|&v| (vni(v), VTEP)).collect();
    Plan::new(
        &Program::default(),
        &vteps,
        &TemplateAction::Queue(RxQueueIndex(0)),
        true,
    )
    .unwrap()
}

fn only(outcomes: &[Outcome]) -> &Outcome {
    assert_eq!(outcomes.len(), 1, "{outcomes:#?}");
    &outcomes[0]
}

const SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

/// Every VNI, the top of the range included (which MARK could not carry: the PMD reserves it).
#[test]
fn a_vpc_without_rules_is_decapsulated_with_its_vni_in_meta_and_stamped() {
    let vnis = [300, 400, 0x00ff_ffef, 0x00ff_fffe, 0x00ff_ffff];
    let plan = plan(&vnis);
    for v in vnis {
        let outcome = plan.outcomes(&vxlan(v, VTEP, SRC, 64)).unwrap();
        let outcome = only(&outcome);
        assert_eq!(outcome.verdict, Verdict::Delivered);
        assert!(outcome.decapped && outcome.stamped, "{v:#x}: {outcome:?}");
        assert_eq!(outcome.meta, Some(META_VXLAN | v));
        assert_eq!(outcome.meta.and_then(vni_of_meta), Some(v));
        assert_eq!(outcome.mark, None, "MARK is the stamp's alone");
    }
}

#[test]
fn what_software_must_judge_arrives_encapsulated_and_stamped() {
    let plan = plan(&[300]);
    let cases = [
        ("outer TTL 0", vxlan(300, VTEP, SRC, 0)),
        (
            "multicast source",
            vxlan(300, VTEP, Ipv4Addr::new(224, 0, 0, 5), 64),
        ),
        ("unknown VNI", vxlan(301, VTEP, SRC, 64)),
        (
            "another VTEP (transit)",
            vxlan(300, Ipv4Addr::new(192, 0, 2, 9), SRC, 64),
        ),
    ];
    for (case, frame) in cases {
        let outcomes = plan.outcomes(&frame).unwrap();
        let outcome = only(&outcomes);
        assert_eq!(outcome.verdict, Verdict::Delivered, "{case}");
        assert!(
            !outcome.decapped && outcome.meta.is_none() && outcome.mark.is_none(),
            "{case}: {outcome:?}"
        );
        // Through the switch, so through the trap: stamped, as everything the switch passes on.
        assert!(outcome.stamped, "{case}: {outcome:?}");
    }
}

/// Without decapsulation, a policy without rules installs nothing, as before.
#[test]
fn without_decapsulation_nothing_changes() {
    let vteps: BTreeMap<Vni, Ipv4Addr> = [(vni(300), VTEP)].into();
    let plan = Plan::new(
        &Program::default(),
        &vteps,
        &TemplateAction::Queue(RxQueueIndex(0)),
        false,
    )
    .unwrap();
    assert!(plan.vpcs.is_empty() && plan.fixed.is_empty());
}

/// Where software resumes: what a VPC's generation delivers decapsulated, at the node the plan is
/// given (past the ingress policy); what the switch delivers raw, at the root.
#[test]
fn decapsulated_deliveries_trap_past_ingress_and_raw_ones_at_the_root() {
    let node = std::num::NonZero::new(1).unwrap();
    let trapping = plan(&[300]).trapping_decapped_at(Some(node));
    let decapped = trapping.outcomes(&vxlan(300, VTEP, SRC, 64)).unwrap();
    let decapped = only(&decapped);
    assert!(decapped.decapped && decapped.stamped);
    assert_eq!(decapped.trap, Some(node));
    for frame in [vxlan(300, VTEP, SRC, 0), vxlan(301, VTEP, SRC, 64)] {
        let raw = trapping.outcomes(&frame).unwrap();
        let raw = only(&raw);
        assert!(!raw.decapped && raw.stamped, "{raw:?}");
        assert_eq!(raw.trap, None, "{raw:?}");
    }
    // By default, every delivery is trapped at the root.
    let root = plan(&[300]).outcomes(&vxlan(300, VTEP, SRC, 64)).unwrap();
    assert_eq!(only(&root).trap, None);
}
