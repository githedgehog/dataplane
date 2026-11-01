// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What the program compiler offloads and refuses, from configurations like `rate-limit`'s tests.

use std::num::{NonZeroU64, NonZeroUsize};

use acl::table::Backend;
use config::external::overlay::acl::AclPattern;
use config::external::overlay::ratelimit::{
    ColorAction, ColorActions, Meter, MeterProfile, RateLimitRule, RateLimitTables,
};
use config::external::overlay::vpc::{Vpc, VpcTable};
use config::external::overlay::vpcpeering::{VpcExpose, VpcManifest, VpcPeering, VpcPeeringTable};
use config::external::overlay::{Overlay, ValidatedOverlay};
use lpm::prefix::{Prefix as LpmPrefix, PrefixWithOptionalPorts};
use policer::{Profile, Rate};
use rate_limit::{PeeringRules, RateLimitWriter, RateLimits, Unit};

use crate::program::{Prefix, Program, Refusal};

const VNI1: u32 = 3000;
const VNI2: u32 = 4000;

fn component(red: ColorAction) -> MeterProfile {
    MeterProfile {
        profile: Profile::new(Rate::new(NonZeroU64::new(1000).unwrap()), 1500, None, 0).unwrap(),
        actions: ColorActions {
            red,
            ..ColorActions::default()
        },
    }
}

fn bytes(red: ColorAction) -> Meter {
    Meter {
        bytes: Some(component(red)),
        packets: None,
    }
}

fn rule(destination: &str, meter: &str) -> RateLimitRule {
    RateLimitRule {
        peering: "p".into(),
        from: "vpc-1".into(),
        to: "vpc-2".into(),
        meter: meter.into(),
        pattern: AclPattern {
            dst: [PrefixWithOptionalPorts::from(
                destination.parse::<LpmPrefix>().unwrap(),
            )]
            .into(),
            ..AclPattern::default()
        },
    }
}

fn compile(meters: Vec<(&str, Meter)>, rules: Vec<RateLimitRule>) -> Program {
    let mut vpcs = VpcTable::new();
    vpcs.add(Vpc::new("vpc-1", "AAAAA", VNI1).unwrap()).unwrap();
    vpcs.add(Vpc::new("vpc-2", "BBBBB", VNI2).unwrap()).unwrap();
    let mut left = VpcManifest::new("vpc-1");
    let mut right = VpcManifest::new("vpc-2");
    left.add_expose(VpcExpose::empty().ip("10.0.0.0/24".parse::<LpmPrefix>().unwrap().into()));
    right.add_expose(VpcExpose::empty().ip("10.1.0.0/16".parse::<LpmPrefix>().unwrap().into()));
    let mut peerings = VpcPeeringTable::new();
    peerings
        .add(VpcPeering::new("p", left, right, "default".into()))
        .unwrap();
    let overlay: ValidatedOverlay = Overlay::new(vpcs, peerings)
        .with_rate_limits(RateLimitTables {
            meters: meters
                .into_iter()
                .map(|(name, meter)| (name.into(), meter))
                .collect(),
            rules,
        })
        .validate()
        .unwrap();
    let writer: RateLimitWriter<PeeringRules> =
        RateLimitWriter::new(RateLimits::empty(), NonZeroUsize::MIN);
    writer.apply(&overlay, Backend::Reference).unwrap();
    Program::compile(&writer.load())
}

#[test]
fn disjoint_rules_are_offloaded_with_their_matches() {
    let program = compile(
        vec![
            ("a", bytes(ColorAction::Drop)),
            ("b", bytes(ColorAction::Drop)),
        ],
        vec![rule("10.1.1.0/24", "a"), rule("10.1.2.0/24", "b")],
    );
    assert!(program.refused.is_empty(), "{:?}", program.refused);
    assert_eq!(program.rules.len(), 2);
    assert_eq!(program.meters.len(), 2);
    let first = &program.rules[0];
    assert_eq!(first.src_vni.as_u32(), VNI1);
    assert_eq!(
        first.destination,
        Prefix::V4("10.1.1.0".parse().unwrap(), 24)
    );
    assert_eq!(first.source, Prefix::V4("10.0.0.0".parse().unwrap(), 24));
    assert_eq!(program.meters[first.meter].unit, Unit::Bytes);
}

/// The software takes the first match; hardware tables keep no order, so a later rule another
/// meter could have claimed traffic from stays in software.
#[test]
fn a_rule_overlapping_an_earlier_one_with_another_meter_stays_in_software() {
    let program = compile(
        vec![
            ("wide", bytes(ColorAction::Drop)),
            ("narrow", bytes(ColorAction::Drop)),
        ],
        vec![rule("10.1.0.0/16", "wide"), rule("10.1.1.0/24", "narrow")],
    );
    assert_eq!(program.rules.len(), 1);
    assert_eq!(program.meters[program.rules[0].meter].name, "wide");
    assert_eq!(program.refused, vec![(1, Refusal::Overlap)]);
}

#[test]
fn rules_sharing_a_meter_may_overlap_and_share_one_nic_meter() {
    let program = compile(
        vec![("shared", bytes(ColorAction::Drop))],
        vec![rule("10.1.0.0/16", "shared"), rule("10.1.1.0/24", "shared")],
    );
    assert_eq!(program.refused, vec![]);
    assert_eq!(program.rules.len(), 2);
    assert_eq!(program.meters.len(), 1);
}

#[test]
fn a_meter_that_drops_nothing_is_not_offloaded() {
    let program = compile(
        vec![("pass", bytes(ColorAction::Pass))],
        vec![rule("10.1.0.0/16", "pass")],
    );
    assert!(program.rules.is_empty() && program.meters.is_empty());
    assert_eq!(program.refused, vec![(0, Refusal::NothingToDrop)]);
}
