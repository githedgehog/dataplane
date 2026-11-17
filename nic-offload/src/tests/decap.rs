// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Decapsulation in the NIC: what arrives decapsulated and marked with its VNI, and what not.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use dpdk::flow::template::TemplateAction;
use dpdk::queue::rx::RxQueueIndex;
use net::vxlan::Vni;

use crate::mlx5::{MAX_MARKED_VNI, Plan};
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

#[test]
fn a_vpc_without_rules_is_decapsulated_and_marked_with_its_vni() {
    let plan = plan(&[300, 400]);
    for v in [300, 400] {
        let outcome = plan.outcomes(&vxlan(v, VTEP, SRC, 64)).unwrap();
        let outcome = only(&outcome);
        assert_eq!(outcome.verdict, Verdict::Delivered);
        assert!(outcome.decapped);
        assert_eq!(outcome.mark, Some(v));
    }
}

#[test]
fn what_software_must_judge_arrives_encapsulated_and_unmarked() {
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
            !outcome.decapped && outcome.mark.is_none(),
            "{case}: {outcome:?}"
        );
    }
}

/// `0xffffff` arrives as "no mark": that VPC stays in software.
#[test]
fn a_vni_no_mark_carries_stays_in_software() {
    let top = MAX_MARKED_VNI + 1;
    let plan = plan(&[300, top]);
    assert!(!plan.vpcs.contains_key(&vni(top)));
    let outcomes = plan.outcomes(&vxlan(top, VTEP, SRC, 64)).unwrap();
    let outcome = only(&outcomes);
    assert!(!outcome.decapped && outcome.mark.is_none());
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
