// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Exercise reconciliation through the DPDK wrappers with queued PMD faults.

#![allow(clippy::unwrap_used)] // Fixture setup failures fail the test.

use super::*;
use crate::program::{DenyRule, Match, PoliceMeter, PoliceRule, Prefix};
use dpdk::flow::FlowError;
use dpdk::flow::template::TemplateAction;
use dpdk::flow::template::testing::{Fixture, Outcome};
use dpdk::queue::rx::RxQueueIndex;

fn vni(value: u32) -> Vni {
    Vni::new_checked(value).unwrap()
}

fn plan(sources: &[u32]) -> Plan {
    let program = Program {
        denies: sources
            .iter()
            .enumerate()
            .map(|(row, &source)| DenyRule {
                origin: Origin::Acl { v6: false, row },
                peering: Peering::new(vni(source), vni(1000)),
                matches: Match {
                    src_vni: vni(source),
                    source: Prefix::V4(Ipv4Addr::UNSPECIFIED, 0),
                    destination: Prefix::V4(Ipv4Addr::new(10, 0, 0, 0), 8),
                    proto: None,
                    src_port: None,
                    dst_port: None,
                    tcp_flags: None,
                },
            })
            .collect(),
        ..Program::default()
    };
    let vteps = sources
        .iter()
        .map(|&v| (vni(v), Ipv4Addr::new(192, 0, 2, 1)))
        .collect();
    Plan::new(&program, &vteps, &TemplateAction::Queue(RxQueueIndex(0))).unwrap()
}

fn any_to(destination: Prefix, source: u32) -> Match {
    Match {
        src_vni: vni(source),
        source: Prefix::V4(Ipv4Addr::UNSPECIFIED, 0),
        destination,
        proto: None,
        src_port: None,
        dst_port: None,
        tcp_flags: None,
    }
}

/// A program with one rate limit from VPC 100, charging a meter named `name` at `rate` bytes/s.
fn policed(name: &str, rate: u64) -> Program {
    Program {
        meters: vec![PoliceMeter {
            name: name.to_string(),
            unit: rate_limit::Unit::Bytes,
            profile: policer::Profile::new(
                policer::Rate::new(std::num::NonZeroU64::new(rate).unwrap()),
                100_000,
                None,
                0,
            )
            .unwrap(),
            lease_slack: [0, 0],
        }],
        rules: vec![PoliceRule {
            rule: 0,
            peering: Peering::new(vni(100), vni(1000)),
            matches: any_to(Prefix::V4(Ipv4Addr::new(10, 0, 0, 0), 8), 100),
            meter: 0,
        }],
        ..Program::default()
    }
}

fn planned(program: &Program) -> Plan {
    let vteps = [(vni(100), Ipv4Addr::new(192, 0, 2, 1))].into();
    Plan::new(program, &vteps, &TemplateAction::Queue(RxQueueIndex(0))).unwrap()
}

/// Meters the next plan does not want are removed before its new ones are made, so a port near
/// its reserved meters can still change every meter.
#[test]
fn unwanted_meters_go_before_new_ones_are_made() {
    let (old, new) = (
        planned(&policed("m", 1_000_000)),
        planned(&policed("m", 2_000_000)),
    );
    // How many removals changing the meter takes, the last of them its old color rules'.
    let removals = {
        let fixture = Fixture::new();
        let flows = fixture.flows();
        let mut port = Port::new(&flows);
        port.reconcile(&old, port.observe()).unwrap();
        let before = fixture.calls("destroy");
        port.reconcile(&new, port.observe()).unwrap();
        fixture.calls("destroy") - before
    };
    let fixture = Fixture::new();
    let flows = fixture.flows();
    let mut port = Port::new(&flows);
    port.reconcile(&old, port.observe()).unwrap();
    let made = fixture.calls("meter_create");
    fixture.fail_after("destroy", removals - 1, Outcome::Reject);
    assert!(matches!(
        port.reconcile(&new, port.observe()),
        Err(Error::Lost { .. })
    ));
    assert_eq!(fixture.calls("meter_create"), made);
}

#[test]
fn completion_errors_require_poisoning_but_clean_refusals_do_not() {
    for error in [
        TemplateError::Timeout("creation"),
        TemplateError::OperationFailed("creation"),
        TemplateError::Completion {
            what: "creation",
            source: FlowError::Unspecified("pull failed".into()),
        },
        TemplateError::Pending,
    ] {
        assert!(unknown_state(&error), "{error}");
    }
    assert!(!unknown_state(&TemplateError::Flow(FlowError::Item(
        "refused".into()
    ))));
}

#[test]
fn failed_switch_insertion_detaches_known_rules_and_tracks_the_unknown_one() {
    for failure in [Outcome::PushError, Outcome::PullError] {
        for root_fails in [false, true] {
            let fixture = Fixture::new();
            let flows = fixture.flows();
            let mut port = Port::new(&flows);
            port.reconcile(&plan(&[100]), port.observe()).unwrap();
            let destroys = fixture.calls("destroy");
            let recycled = port.groups.free.clone();
            // The new generation has a deny and a catch-all, then its switch is inserted.
            fixture.fail_after("create", 2, failure);
            if root_fails {
                fixture.fail("destroy", Outcome::Reject);
            }
            let error = port
                .reconcile(&plan(&[100, 200]), port.observe())
                .unwrap_err();
            assert!(matches!(
                error,
                Error::Lost {
                    source: TemplateError::Completion { .. },
                    ..
                }
            ));
            assert!(port.poisoned());
            assert_eq!(port.stale(), root_fails);
            assert!(port.root.is_none());
            assert_eq!(
                fixture.calls("destroy") - destroys,
                if root_fails { 2 } else { 1 }
            );
            assert_eq!(
                port.switch.as_ref().unwrap().rules.len(),
                usize::from(!root_fails)
            );
            assert!(!port.vpcs.contains_key(&vni(200)));
            assert_eq!(
                port.groups.free, recycled,
                "an uncertain switch may reach its group"
            );
            assert!(matches!(
                port.reconcile(&plan(&[100]), port.observe()),
                Err(Error::Poisoned)
            ));
        }
    }
}

#[test]
fn rejected_switch_insertion_leaves_existing_policy_and_reclaims_the_unused_group() {
    let fixture = Fixture::new();
    let flows = fixture.flows();
    let mut port = Port::new(&flows);
    port.reconcile(&plan(&[100]), port.observe()).unwrap();
    fixture.fail_after("create", 2, Outcome::Reject);
    let result = port.reconcile(&plan(&[100, 200]), port.observe()).unwrap();
    assert!(
        result
            .refused
            .iter()
            .any(|(role, _)| *role == Role::Switch(vni(200)))
    );
    assert!(!port.poisoned());
    assert!(!port.stale());
    assert!(port.root.is_some());
    assert_eq!(
        port.switch
            .as_ref()
            .unwrap()
            .rules
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        [vni(100)]
    );
    assert_eq!(port.groups.free.len(), 1);
}

#[test]
fn failed_switch_removal_is_remembered_when_root_removal_also_fails() {
    let fixture = Fixture::new();
    let flows = fixture.flows();
    let mut port = Port::new(&flows);
    port.reconcile(&plan(&[100, 200]), port.observe()).unwrap();
    let destroys = fixture.calls("destroy");
    fixture.fail("destroy", Outcome::Reject); // The removed switch handle is consumed.
    fixture.fail("destroy", Outcome::Reject); // Root removal fails too.
    assert!(matches!(port.remove(vni(100)), Err(Error::Lost { .. })));
    assert!(port.poisoned() && port.stale());
    assert!(port.switch.as_ref().unwrap().rules.is_empty());
    assert_eq!(fixture.calls("destroy") - destroys, 3); // Still remove the other VPC's switch.
    assert_eq!(port.groups.free, [] as [u32; 0]);
}

#[test]
fn failed_root_removal_can_still_detach_all_known_switches() {
    let fixture = Fixture::new();
    let flows = fixture.flows();
    let mut port = Port::new(&flows);
    port.reconcile(&plan(&[100, 200]), port.observe()).unwrap();
    fixture.fail("destroy", Outcome::Reject);
    assert!(matches!(port.clear(), Err(Error::Lost { .. })));
    assert!(port.poisoned());
    assert!(!port.stale());
    assert!(port.switch.as_ref().unwrap().rules.is_empty());
}

#[test]
fn uncertain_root_creation_is_recorded_before_poisoning() {
    let fixture = Fixture::new();
    let flows = fixture.flows();
    let mut port = Port::new(&flows);
    fixture.fail_after("create", 1, Outcome::PullError); // Catch-all, then root.
    assert!(matches!(
        port.reconcile(&plan(&[100]), port.observe()),
        Err(Error::Lost { .. })
    ));
    assert!(port.poisoned() && port.root_lingers);
    assert!(!port.stale(), "the switch has no VPC rules to reach");
    assert!(port.vpcs.is_empty());
}
