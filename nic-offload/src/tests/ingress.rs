// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What the program compiler makes of the ingress policy: layers, passes, and what a VPC whose
//! ingress rules stay in software keeps there with them.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;

use acl::table::Backend;
use config::external::overlay::acl::{AclPattern, AclProtoMatch};
use config::external::overlay::ingress::{IngressAction, IngressPolicy, IngressRule};
use config::external::overlay::ratelimit::{ColorAction, RateLimitTables};
use config::external::overlay::vpc::{Vpc, VpcTable};
use config::external::overlay::vpcpeering::{VpcExpose, VpcManifest, VpcPeering, VpcPeeringTable};
use config::external::overlay::{Overlay, ValidatedOverlay};
use lpm::prefix::{PortRange, Prefix as LpmPrefix, PrefixWithOptionalPorts};
use rate_limit::{IngressRules, PeeringRules, RateLimitWriter, RateLimits};

use super::{VNI1, bytes, rule};
use crate::mlx5::{Group, Plan, Role};
use crate::program::{Exclusions, IngressVerdict, Program};
use acl_filter::AclFilterContext;

fn ingress(destination: &str, action: IngressAction) -> IngressRule {
    IngressRule {
        from: Some("vpc-1".into()),
        pattern: AclPattern {
            dst: [PrefixWithOptionalPorts::from(
                destination.parse::<LpmPrefix>().unwrap(),
            )]
            .into(),
            ..AclPattern::default()
        },
        action,
    }
}

fn police() -> IngressAction {
    IngressAction::Police("ingress/m".into())
}

/// The program of a peering between VPCs 1 and 2 with `limits` (charging meter `a`), and the
/// ingress policy `rules` (charging meter `ingress/m`, which drops red if `drops`).
fn compile(
    limits: Vec<config::external::overlay::ratelimit::RateLimitRule>,
    rules: Vec<IngressRule>,
    drops: bool,
    excluded: &Exclusions,
) -> Program {
    let red = if drops {
        ColorAction::Drop
    } else {
        ColorAction::Pass
    };
    compile_metered(limits, rules, bytes(red), excluded)
}

/// As [`compile`], with `meter` as `ingress/m`.
fn compile_metered(
    limits: Vec<config::external::overlay::ratelimit::RateLimitRule>,
    rules: Vec<IngressRule>,
    meter: config::external::overlay::ratelimit::Meter,
    excluded: &Exclusions,
) -> Program {
    compile_named(limits, "a", rules, meter, excluded)
}

/// As [`compile_metered`], with the peering meter named `peering_meter`.
fn compile_named(
    limits: Vec<config::external::overlay::ratelimit::RateLimitRule>,
    peering_meter: &str,
    rules: Vec<IngressRule>,
    meter: config::external::overlay::ratelimit::Meter,
    excluded: &Exclusions,
) -> Program {
    let mut vpcs = VpcTable::new();
    vpcs.add(Vpc::new("vpc-1", "AAAAA", VNI1).unwrap()).unwrap();
    vpcs.add(Vpc::new("vpc-2", "BBBBB", super::VNI2).unwrap())
        .unwrap();
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
            meters: [(peering_meter.to_string(), bytes(ColorAction::Drop))].into(),
            rules: limits,
        })
        .with_ingress(IngressPolicy {
            meters: [("ingress/m".to_string(), meter)].into(),
            rules,
        })
        .validate()
        .unwrap();
    let limits: RateLimitWriter<PeeringRules> =
        RateLimitWriter::new(RateLimits::empty(), NonZeroUsize::MIN);
    limits.apply(&overlay, Backend::Reference).unwrap();
    let ingress: RateLimitWriter<IngressRules> =
        RateLimitWriter::new(RateLimits::empty(), NonZeroUsize::MIN);
    ingress.apply(&overlay, Backend::Reference).unwrap();
    Program::compile(
        &AclFilterContext::reference(&overlay).unwrap(),
        &limits.load(),
        &ingress.load(),
        &flow_filter::FlowFilterContext::reference(&overlay).destinations(),
        excluded,
    )
}

/// A rule goes above every earlier rule it overlaps with another verdict, and only those: the
/// lowest layer a packet matches in the NIC then does what its first match does in software.
#[test]
fn overlapping_rules_with_other_verdicts_are_layered() {
    let program = compile(
        Vec::new(),
        vec![
            ingress("10.1.1.0/24", police()),
            ingress("10.1.0.0/16", IngressAction::Drop),
            ingress("10.0.0.0/8", IngressAction::Drop),
            ingress("192.0.2.0/24", IngressAction::Drop),
        ],
        true,
        &Exclusions::default(),
    );
    let layers: Vec<(IngressVerdict, u32)> = program
        .ingress
        .iter()
        .map(|r| (r.verdict, r.layer))
        .collect();
    let police = IngressVerdict::Police(0, None);
    assert_eq!(
        layers,
        [
            (police, 0),
            (IngressVerdict::Drop, 1),
            (IngressVerdict::Drop, 1),
            (IngressVerdict::Drop, 0)
        ]
    );
}

/// A port range is matched as a range; a rule the NIC cannot match exactly (a protocol software
/// resolves past, as an extension header's) passes what it matches, and possibly more, to software;
/// a police whose meter never drops lets the NIC go on with the peering policy.
#[test]
fn what_the_nic_cannot_enforce_passes_to_software() {
    let mut ranged = ingress("10.1.0.0/16", IngressAction::Drop);
    ranged.pattern.proto = AclProtoMatch::Udp;
    ranged.pattern.dst = [PrefixWithOptionalPorts::new(
        "10.1.0.0/16".parse::<LpmPrefix>().unwrap(),
        Some(PortRange::new(80, 90).unwrap()),
    )]
    .into();
    let mut extension = ingress("10.3.0.0/16", IngressAction::Drop);
    extension.pattern.proto = AclProtoMatch::Other(0);
    let program = compile(
        Vec::new(),
        vec![ranged, ingress("10.2.0.0/16", police()), extension],
        false,
        &Exclusions::default(),
    );
    assert_eq!(program.ingress[0].verdict, IngressVerdict::Drop);
    assert_eq!(
        program.ingress[0].matches.dst_port,
        PortRange::new(80, 90).ok()
    );
    assert_eq!(program.ingress[1].verdict, IngressVerdict::Continue);
    assert_eq!(program.ingress[2].verdict, IngressVerdict::Pass);
    assert_eq!(program.ingress[2].matches.proto, None);
    assert_eq!(program.meters, []);
}

/// A VPC whose ingress rules stay in software keeps its peerings there too: a NIC enforcing them
/// without the ingress rules before them could charge meters with what software drops first.
#[test]
fn a_vpc_left_in_software_takes_its_peerings_with_it() {
    let both = |excluded: &Exclusions| {
        compile(
            vec![rule("10.1.0.0/16", "a")],
            vec![ingress("10.1.0.0/16", IngressAction::Drop)],
            true,
            excluded,
        )
    };
    let offloaded = both(&Exclusions::default());
    assert_eq!((offloaded.ingress.len(), offloaded.rules.len()), (1, 1));
    let excluded = Exclusions {
        vpcs: [net::vxlan::Vni::new_checked(VNI1).unwrap()].into(),
        ..Exclusions::default()
    };
    let left = both(&excluded);
    assert!(
        left.ingress.is_empty() && left.rules.is_empty(),
        "{left:#?}"
    );
}

/// A generation with ingress rules starts with them; what they let through goes on to the
/// peering policy, and what they drop goes nowhere.
#[test]
fn ingress_comes_first_in_a_generation() {
    let program = compile(
        vec![rule("10.1.0.0/16", "a")],
        vec![ingress("10.1.1.0/24", IngressAction::Drop)],
        true,
        &Exclusions::default(),
    );
    let vni = net::vxlan::Vni::new_checked(VNI1).unwrap();
    let vteps: BTreeMap<_, _> = [(vni, std::net::Ipv4Addr::new(192, 0, 2, 1))].into();
    let plan = Plan::new(&program, &vteps, &crate::differential::fate()).unwrap();
    let vpc = &plan.vpcs[&vni];
    assert_eq!(vpc.entry, Group::Ingress(vni));
    assert_eq!(
        next(&plan, vni, Group::Ingress(vni)),
        [(
            Role::CatchAll(Group::Ingress(vni)),
            vec![crate::mlx5::Arg::Jump(Group::Police(vni))]
        )]
    );
}

/// What a generation's ingress rules, but those of `group`, do next, by role.
fn next(plan: &Plan, vni: net::vxlan::Vni, group: Group) -> Vec<(Role, Vec<crate::mlx5::Arg>)> {
    plan.vpcs[&vni]
        .tables
        .iter()
        .filter(|t| t.group == group)
        .flat_map(|t| &t.rules)
        .filter(|r| !matches!(r.role, Role::Ingress(_)))
        .map(|r| (r.role, r.args.clone()))
        .collect()
}

/// The NIC's ingress meters pass on some of what software's drop (they are looser): a rate limit
/// after them would be charged for it in the NIC, not in software, and run dry first. The rate
/// limits of traffic from a VPC the NIC polices at ingress stay in software, with their peering;
/// what the ingress rules let through goes to software.
#[test]
fn a_vpc_policed_at_ingress_keeps_its_rate_limits_in_software() {
    let program = compile(
        vec![rule("10.1.0.0/16", "a")],
        vec![
            ingress("10.1.1.0/24", IngressAction::Drop),
            ingress("10.1.0.0/16", police()),
        ],
        true,
        &Exclusions::default(),
    );
    assert!(program.rules.is_empty(), "{:?}", program.rules);
    assert!(
        program
            .refused
            .iter()
            .any(|(_, _, why)| *why == crate::program::Refusal::IngressPoliced),
        "{:?}",
        program.refused
    );
    let vni = net::vxlan::Vni::new_checked(VNI1).unwrap();
    let vteps: BTreeMap<_, _> = [(vni, std::net::Ipv4Addr::new(192, 0, 2, 1))].into();
    let plan = Plan::new(&program, &vteps, &crate::differential::fate()).unwrap();
    assert_eq!(
        next(&plan, vni, Group::Ingress(vni)),
        [(Role::CatchAll(Group::Ingress(vni)), vec![])]
    );
    let colors = next(&plan, vni, Group::IngressColor(vni, 0));
    assert_eq!(colors.len(), 3);
    assert!(colors.iter().all(|(_, args)| args.is_empty()), "{colors:?}");
    // Policing another VPC's traffic leaves this one's rate limits to the NIC.
    let program = compile(
        vec![rule("10.1.0.0/16", "a")],
        vec![IngressRule {
            from: Some("vpc-2".into()),
            ..ingress("10.0.0.0/24", police())
        }],
        true,
        &Exclusions::default(),
    );
    assert_eq!(program.rules.len(), 1);
}

/// A rule naming no protocol takes fragments in the NIC, as in software; but not one an earlier
/// rule with another verdict naming a protocol overlaps, which software may match a first fragment
/// to instead.
#[test]
fn fragments_match_rules_naming_no_protocol() {
    let mut udp = ingress("10.1.1.0/24", police());
    udp.pattern.proto = AclProtoMatch::Udp;
    let program = compile(
        Vec::new(),
        vec![
            udp,
            ingress("10.1.0.0/16", IngressAction::Drop),
            ingress("10.2.0.0/16", IngressAction::Drop),
        ],
        true,
        &Exclusions::default(),
    );
    let fragments: Vec<bool> = program.ingress.iter().map(|r| r.fragments).collect();
    assert_eq!(fragments, [false, false, true]);
}

/// A meter with both components is enforced with both in the NIC: the bytes component first, its
/// green and yellow charged to the packets component, whose own go on.
#[test]
fn both_components_of_a_meter_chain_in_the_nic() {
    let both = config::external::overlay::ratelimit::Meter {
        packets: bytes(ColorAction::Drop).bytes,
        ..bytes(ColorAction::Drop)
    };
    let program = compile_metered(
        Vec::new(),
        vec![ingress("10.1.0.0/16", police())],
        both,
        &Exclusions::default(),
    );
    let IngressVerdict::Police(first, Some(second)) = program.ingress[0].verdict else {
        panic!("{:?}", program.ingress[0].verdict);
    };
    assert_eq!(program.meters[first].unit, rate_limit::Unit::Bytes);
    assert_eq!(program.meters[second].unit, rate_limit::Unit::Packets);
    let vni = net::vxlan::Vni::new_checked(VNI1).unwrap();
    let vteps: BTreeMap<_, _> = [(vni, std::net::Ipv4Addr::new(192, 0, 2, 1))].into();
    let plan = Plan::new(&program, &vteps, &crate::differential::fate()).unwrap();
    let green = |meter| {
        plan.vpcs[&vni]
            .tables
            .iter()
            .filter(|t| t.group == Group::IngressColor(vni, meter))
            .flat_map(|t| &t.rules)
            .find(|r| {
                matches!(
                    r.role,
                    Role::IngressColor(_, _, dpdk::flow::template::Color::Green)
                )
            })
            .map(|r| r.args.clone())
            .unwrap()
    };
    assert_eq!(
        green(first),
        [
            crate::mlx5::Arg::Meter(second),
            crate::mlx5::Arg::Jump(Group::IngressColor(vni, second))
        ]
    );
    // Nothing comes after the ingress rules here: the second meter's green goes to software.
    assert_eq!(green(second), []);
}

/// A meter's components are offloaded only as far as the NIC charges each for nothing software
/// does not: software never charges its packets component for what the bytes one colors red, nor
/// for what the bytes one drops, where the NIC's color-blind packets meter would charge for both.
#[test]
fn a_chain_is_offloaded_only_where_the_nic_charges_what_software_does() {
    use config::external::overlay::ratelimit::{ColorActions, Meter, MeterProfile};
    use rate_limit::Unit;
    let actions = |yellow, red| ColorActions {
        yellow,
        red,
        ..ColorActions::default()
    };
    let profile = |actions| MeterProfile {
        actions,
        ..super::component(ColorAction::Drop)
    };
    let (pass, drop) = (ColorAction::Pass, ColorAction::Drop);
    for (bytes, packets, enforced) in [
        // Police in both: the chain.
        (
            actions(pass, drop),
            actions(pass, drop),
            &[Unit::Bytes, Unit::Packets][..],
        ),
        // Bytes red goes on red to the packets component, which drops it: the NIC's bytes meter
        // drops red (so its packets meter is charged for what software charges, no more).
        (
            actions(pass, pass),
            actions(pass, drop),
            &[Unit::Bytes, Unit::Packets][..],
        ),
        // Software drops bytes yellow before the packets component: the NIC would charge it.
        (actions(drop, drop), actions(pass, drop), &[Unit::Bytes][..]),
        // The packets component drops nothing.
        (actions(pass, drop), actions(pass, pass), &[Unit::Bytes][..]),
        // Neither drops anything.
        (actions(pass, pass), actions(pass, pass), &[][..]),
    ] {
        let meter = Meter {
            bytes: Some(profile(bytes)),
            packets: Some(profile(packets)),
        };
        let program = compile_metered(
            Vec::new(),
            vec![ingress("10.1.0.0/16", police())],
            meter,
            &Exclusions::default(),
        );
        let units: Vec<Unit> = match program.ingress[0].verdict {
            IngressVerdict::Police(first, then) => std::iter::once(first)
                .chain(then)
                .map(|m| program.meters[m].unit)
                .collect(),
            IngressVerdict::Continue => Vec::new(),
            other => panic!("{other:?}"),
        };
        assert_eq!(units, enforced, "bytes {bytes:?}, packets {packets:?}");
    }
}

/// A peering meter and an ingress meter of one name and profile are still two meters: names are
/// unique within a policy only (a peering named `ingress` has meters named `ingress/...`), and
/// sharing one NIC bucket would charge packets that pass both stages twice.
#[test]
fn equal_names_of_two_policies_are_two_meters() {
    // Policing VPC 2's traffic at ingress, as VPC 1's rate limits stay in software otherwise.
    let program = compile_named(
        vec![rule("10.1.0.0/16", "ingress/m")],
        "ingress/m",
        vec![IngressRule {
            from: Some("vpc-2".into()),
            ..ingress("10.0.0.0/24", police())
        }],
        bytes(ColorAction::Drop),
        &Exclusions::default(),
    );
    assert_eq!(program.meters.len(), 2);
    let vni = |n| net::vxlan::Vni::new_checked(n).unwrap();
    let vtep = std::net::Ipv4Addr::new(192, 0, 2, 1);
    let vteps: BTreeMap<_, _> = [(vni(VNI1), vtep), (vni(super::VNI2), vtep)].into();
    let plan = Plan::new(&program, &vteps, &crate::differential::fate()).unwrap();
    assert_eq!(plan.meters[0].key.name, plan.meters[1].key.name);
    assert_ne!(plan.meters[0].key, plan.meters[1].key);
    // Only the peering meter has a color group of its own; the ingress meter's colors are
    // matched in its VPC's ingress color group.
    let colored: Vec<bool> = plan.meters.iter().map(|m| m.colors.is_some()).collect();
    assert_eq!(
        colored,
        plan.meters
            .iter()
            .map(|m| m.key.scope == crate::program::Scope::Peering)
            .collect::<Vec<_>>()
    );
}

/// A rule an identical earlier one shadows makes no meter: a meter no rule charges is one nothing
/// would leave to software if the NIC could not take it (here, faster than mlx5 meters).
#[test]
fn a_shadowed_rule_makes_no_meter() {
    let fast = config::external::overlay::ratelimit::Meter {
        bytes: Some(config::external::overlay::ratelimit::MeterProfile {
            profile: policer::Profile::new(
                policer::Rate::new(std::num::NonZeroU64::new(u64::MAX >> 8).unwrap()),
                1500,
                None,
                0,
            )
            .unwrap(),
            actions: config::external::overlay::ratelimit::ColorActions::default(),
        }),
        packets: None,
    };
    let program = compile_metered(
        Vec::new(),
        vec![
            ingress("10.1.0.0/16", IngressAction::Drop),
            ingress("10.1.0.0/16", police()),
        ],
        fast,
        &Exclusions::default(),
    );
    assert_eq!(program.ingress.len(), 1);
    assert_eq!(program.meters, []);
    let vni = net::vxlan::Vni::new_checked(VNI1).unwrap();
    let vteps: BTreeMap<_, _> = [(vni, std::net::Ipv4Addr::new(192, 0, 2, 1))].into();
    assert!(Plan::new(&program, &vteps, &crate::differential::fate()).is_ok());
}

/// Rules of different source VPCs never overlap, so never layer on each other.
#[test]
fn rules_of_other_vpcs_do_not_layer() {
    let mut other = ingress("10.1.0.0/16", IngressAction::Drop);
    other.from = Some("vpc-2".into());
    let program = compile(
        Vec::new(),
        vec![ingress("10.1.0.0/16", police()), other],
        true,
        &Exclusions::default(),
    );
    let layers: Vec<u32> = program.ingress.iter().map(|r| r.layer).collect();
    assert_eq!(layers, [0, 0]);
}

/// A VPC with ingress rules but no peering is a VPC whose VTEP a NIC needs: flow-filter's
/// destinations do not name it, the ingress policy does.
#[test]
fn ingress_vpcs_name_unpeered_vpcs_too() {
    const VNI3: u32 = 5000;
    let mut vpcs = VpcTable::new();
    vpcs.add(Vpc::new("vpc-1", "AAAAA", VNI1).unwrap()).unwrap();
    vpcs.add(Vpc::new("vpc-2", "BBBBB", super::VNI2).unwrap())
        .unwrap();
    vpcs.add(Vpc::new("vpc-3", "CCCCC", VNI3).unwrap()).unwrap();
    let mut left = VpcManifest::new("vpc-1");
    let mut right = VpcManifest::new("vpc-2");
    left.add_expose(VpcExpose::empty().ip("10.0.0.0/24".parse::<LpmPrefix>().unwrap().into()));
    right.add_expose(VpcExpose::empty().ip("10.1.0.0/16".parse::<LpmPrefix>().unwrap().into()));
    let mut peerings = VpcPeeringTable::new();
    peerings
        .add(VpcPeering::new("p", left, right, "default".into()))
        .unwrap();
    let overlay: ValidatedOverlay = Overlay::new(vpcs, peerings)
        .with_ingress(IngressPolicy {
            meters: BTreeMap::new(),
            rules: vec![IngressRule {
                from: Some("vpc-3".into()),
                ..ingress("10.3.0.0/16", IngressAction::Drop)
            }],
        })
        .validate()
        .unwrap();
    let ingress: RateLimitWriter<IngressRules> =
        RateLimitWriter::new(RateLimits::empty(), NonZeroUsize::MIN);
    ingress.apply(&overlay, Backend::Reference).unwrap();
    let vni3 = net::vxlan::Vni::new_checked(VNI3).unwrap();
    let destinations = flow_filter::FlowFilterContext::reference(&overlay).destinations();
    assert!(
        destinations
            .iter()
            .all(|d| d.src_vni != vni3 && d.dst_vni != vni3)
    );
    assert_eq!(crate::program::ingress_vpcs(&ingress.load()), [vni3].into());
}

/// An ingress rule the NIC refused passes to software; the other rules charging its meter stay.
#[test]
fn a_refused_ingress_rule_passes_alone() {
    let rules = vec![
        ingress("10.1.0.0/24", police()),
        ingress("10.1.1.0/24", police()),
    ];
    let program = compile(
        Vec::new(),
        rules,
        true,
        &Exclusions {
            ingress_rules: [(false, 0)].into(),
            ..Exclusions::default()
        },
    );
    assert_eq!(program.ingress[0].verdict, IngressVerdict::Pass);
    assert!(
        matches!(program.ingress[1].verdict, IngressVerdict::Police(..)),
        "{:?}",
        program.ingress[1].verdict
    );
}

/// mlx5 meters a port range only with at most six words of inner IPv6 address (measured on a
/// BlueField-3 with `install_probe`): an ingress police rule needing more passes to software
/// alone. A drop, an exact port (even written as a range), IPv4, or shorter prefixes stay in the
/// NIC.
#[test]
fn a_metered_ipv6_range_mlx5_cannot_match_passes_to_software() {
    use crate::program::{IngressRule as Rule, Match, Origin, PoliceMeter, Prefix, Scope};
    let vni = net::vxlan::Vni::new_checked(VNI1).unwrap();
    let range = PortRange::new(1000, 2000).ok();
    let exact = PortRange::new(1000, 1000).ok();
    let v6 = |len| Prefix::V6("fd00::".parse().unwrap(), len);
    let v4 = |len| Prefix::V4("10.0.0.0".parse().unwrap(), len);
    let police = IngressVerdict::Police(0, None);
    // Source, destination, source ports, destination ports, verdict; and whether the NIC takes it.
    let shapes = [
        (v6(64), v6(64), None, range, police, true),
        (v6(96), v6(96), None, range, police, true),
        (v6(128), v6(64), None, range, police, true),
        (v6(64), v6(128), range, None, police, true),
        (v6(128), v6(128), None, exact, police, true),
        (v6(128), v6(128), exact, exact, police, true),
        (v6(128), v6(128), None, None, police, true),
        (v4(32), v4(32), range, range, police, true),
        (v6(128), v6(128), None, range, IngressVerdict::Drop, true),
        (v6(96), v6(97), None, range, police, false),
        (v6(65), v6(128), range, None, police, false),
        (v6(128), v6(128), range, range, police, false),
    ];
    let ingress = shapes
        .iter()
        .enumerate()
        .map(
            |(row, &(source, destination, src_port, dst_port, verdict, _))| Rule {
                origin: Origin::Ingress {
                    v6: matches!(source, Prefix::V6(..)),
                    row,
                },
                matches: Match {
                    src_vni: vni,
                    source,
                    destination,
                    proto: Some(6),
                    src_port,
                    dst_port,
                    tcp_flags: None,
                },
                verdict,
                layer: 0,
                fragments: false,
            },
        )
        .collect();
    let rate = policer::Rate::new(std::num::NonZeroU64::new(1_000_000).unwrap());
    let program = Program {
        meters: vec![PoliceMeter {
            name: "ingress/m".into(),
            scope: Scope::Ingress,
            unit: rate_limit::Unit::Bytes,
            billing: rate_limit::Billing::OuterIp,
            profile: policer::Profile::new(rate, 100_000, None, 0).unwrap(),
            lease_slack: [0, 0],
        }],
        ingress,
        ..Program::default()
    };
    let unfit = crate::mlx5::unfit(&program);
    assert!(unfit.ingress_meters.is_empty(), "{unfit:?}");
    for (row, shape) in shapes.iter().enumerate() {
        let v6 = matches!(shape.0, Prefix::V6(..));
        assert_eq!(
            !unfit.ingress_rules.contains(&(v6, row)),
            shape.5,
            "row {row}: {shape:?}"
        );
    }
}
