// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What the program compiler offloads and refuses, from configurations like `rate-limit`'s tests.

mod ingress;

use std::num::{NonZeroU64, NonZeroUsize};

use acl::table::Backend;
use config::external::overlay::acl::{AclPattern, AclProtoMatch};
use config::external::overlay::ratelimit::{
    ColorAction, ColorActions, Meter, MeterProfile, RateLimitRule, RateLimitTables,
};
use config::external::overlay::vpc::{Vpc, VpcTable};
use config::external::overlay::vpcpeering::{VpcExpose, VpcManifest, VpcPeering, VpcPeeringTable};
use config::external::overlay::{Overlay, ValidatedOverlay};
use lpm::prefix::{Prefix as LpmPrefix, PrefixWithOptionalPorts};
use policer::{Profile, Rate};
use rate_limit::{IngressRules, PeeringRules, RateLimitWriter, RateLimits, Unit};

use crate::program::{Exclusions, Origin, Peering, Prefix, Program, Refusal};
use acl_filter::AclFilterContext;

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
    compile_with(meters, rules, true)
}

fn compile_with(meters: Vec<(&str, Meter)>, rules: Vec<RateLimitRule>, offload: bool) -> Program {
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
        .with_offloads_disabled(!offload)
        .validate()
        .unwrap();
    let writer: RateLimitWriter<PeeringRules> =
        RateLimitWriter::new(RateLimits::empty(), NonZeroUsize::MIN);
    writer.apply(&overlay, Backend::Reference).unwrap();
    Program::compile(
        &AclFilterContext::reference(&overlay).unwrap(),
        &writer.load(),
        &RateLimits::<IngressRules>::empty(),
        &flow_filter::FlowFilterContext::reference(&overlay).destinations(),
        &Exclusions::default(),
    )
}

fn peering() -> Peering {
    let vni = |n| net::vxlan::Vni::new_checked(n).unwrap();
    Peering::new(vni(VNI1), vni(VNI2))
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
    assert_eq!(first.matches.src_vni.as_u32(), VNI1);
    assert_eq!(
        first.matches.destination,
        Prefix::V4("10.1.1.0".parse().unwrap(), 24)
    );
    assert_eq!(
        first.matches.source,
        Prefix::V4("10.0.0.0".parse().unwrap(), 24)
    );
    assert_eq!(program.meters[first.meter].unit, Unit::Bytes);
}

/// The software takes the first match; hardware tables keep no order, so a later rule another
/// meter could have claimed traffic from cannot be offloaded, and so neither can the rest of its
/// peering's policy.
#[test]
fn a_rule_overlapping_an_earlier_one_with_another_meter_keeps_its_peering_in_software() {
    let program = compile(
        vec![
            ("wide", bytes(ColorAction::Drop)),
            ("narrow", bytes(ColorAction::Drop)),
        ],
        vec![rule("10.1.0.0/16", "wide"), rule("10.1.1.0/24", "narrow")],
    );
    assert!(program.rules.is_empty() && program.meters.is_empty());
    assert_eq!(
        program.refused,
        vec![(peering(), Origin::RateLimit(1), Refusal::Overlap)]
    );
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
    // Nothing to do in the NIC, and nothing that keeps the peering out of it.
    assert!(program.rules.is_empty() && program.meters.is_empty());
    assert_eq!(program.refused, vec![]);
}

/// Software resolves extension headers to the protocol after them, so a rule for an extension
/// header's protocol number never matches there.
#[test]
fn a_rule_for_an_extension_header_protocol_is_not_offloaded() {
    let mut hop_by_hop = rule("10.1.0.0/16", "a");
    hop_by_hop.pattern.proto = AclProtoMatch::Other(0);
    let mut esp = rule("10.1.0.0/16", "a");
    esp.pattern.proto = AclProtoMatch::Other(50);
    let program = compile(vec![("a", bytes(ColorAction::Drop))], vec![hop_by_hop, esp]);
    assert_eq!(
        program.refused,
        vec![(peering(), Origin::RateLimit(0), Refusal::ExtensionHeader)]
    );
    assert_eq!(program.rules, vec![]);
}

/// `attempt-offloads: "false"` keeps everything in software.
#[test]
fn nothing_is_offloaded_when_offload_is_turned_off() {
    let program = compile_with(
        vec![("a", bytes(ColorAction::Drop))],
        vec![rule("10.1.0.0/16", "a")],
        false,
    );
    assert!(program.rules.is_empty() && program.meters.is_empty() && program.refused.is_empty());
}

/// A rule identical to an earlier one is not offloaded twice: mlx5 takes identical rules into one
/// table, but fails to remove the second.
#[test]
fn identical_rules_are_offloaded_once() {
    let program = compile(
        vec![("a", bytes(ColorAction::Drop))],
        vec![rule("10.1.0.0/16", "a"), rule("10.1.0.0/16", "a")],
    );
    assert_eq!(program.refused, vec![]);
    assert_eq!(program.rules.len(), 1);
}

/// Prefixes are compared as the addresses they match.
#[test]
fn prefixes_are_canonical() {
    let host_bits = Prefix::V4("10.1.2.3".parse().unwrap(), 16).canonical();
    assert_eq!(host_bits, Prefix::V4("10.1.0.0".parse().unwrap(), 16));
    let zero = Prefix::V6("fd00::1".parse().unwrap(), 0).canonical();
    assert_eq!(zero, Prefix::V6(std::net::Ipv6Addr::UNSPECIFIED, 0));
}
