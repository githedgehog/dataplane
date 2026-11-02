// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Exercise the public handles against a thread-local PMD that can fail each operation stage.

#![allow(clippy::unwrap_used)] // A failed setup is a test failure.

use super::*;
use crate::flow::Ingress;
use crate::flow::template::testing::{Fixture, Outcome};
use crate::flow::template::{
    MeterAlgorithm, MeterProfile, MeterProfileId, MeterUnit, SharedArg, SharedMeter, SharedTable,
};
use alloc::rc::Rc;

fn profile() -> MeterProfile {
    MeterProfile {
        algorithm: MeterAlgorithm::Srtcm {
            cir: 100,
            cbs: 100,
            ebs: 0,
        },
        unit: MeterUnit::Packets,
    }
}

fn config() -> TableConfig {
    TableConfig {
        group: FlowGroup(1),
        priority: Priority(0),
        capacity: 8,
    }
}

fn table<'t>(flows: &'t TemplateFlows<'t>) -> SharedTable<'t, Ingress> {
    let pattern = Rc::new(flows.pattern_template(&Pattern::new()).unwrap());
    let actions = Rc::new(flows.actions_template(&[TemplateAction::Meter]).unwrap());
    SharedTable::new(flows, config(), &[pattern], &[actions]).unwrap()
}

#[test]
fn unknown_creation_never_enqueues_destroy_and_retains_dependencies() {
    for outcome in [Outcome::PushError, Outcome::PullError, Outcome::Timeout] {
        let fixture = Fixture::new();
        let flows = fixture.flows();
        let profile = Rc::new(flows.meter_profile(MeterProfileId(1), &profile()).unwrap());
        let meter = SharedMeter::new(&flows, &profile).unwrap();
        let table = table(&flows);
        fixture.fail("create", outcome);
        assert!(
            table
                .insert(0, &Pattern::new(), 0, &[SharedArg::Meter(meter)])
                .is_err()
        );
        assert_eq!(fixture.calls("destroy"), 0);
        assert_eq!(fixture.live_rules(), 1);
        assert!(matches!(table.destroy(), Err(TemplateError::InUse)));
        drop(profile);
        for name in [
            "meter_destroy",
            "table_destroy",
            "pattern_destroy",
            "actions_destroy",
            "profile_delete",
        ] {
            assert_eq!(fixture.calls(name), 0, "{outcome:?}: {name}");
        }
    }
}

#[test]
fn completed_creation_failure_can_destroy_and_release_dependencies() {
    let fixture = Fixture::new();
    let flows = fixture.flows();
    let profile = Rc::new(flows.meter_profile(MeterProfileId(1), &profile()).unwrap());
    let meter = SharedMeter::new(&flows, &profile).unwrap();
    let table = table(&flows);
    fixture.fail("create", Outcome::FailedCompletion);
    assert!(matches!(
        table.insert(0, &Pattern::new(), 0, &[SharedArg::Meter(meter)]),
        Err(TemplateError::OperationFailed(_))
    ));
    table.destroy().unwrap();
    drop(profile);
    assert_eq!(fixture.live_rules(), 0);
    for name in [
        "destroy",
        "meter_destroy",
        "table_destroy",
        "pattern_destroy",
        "actions_destroy",
        "profile_delete",
    ] {
        assert_eq!(fixture.calls(name), 1, "{name}");
    }
}

#[test]
fn failed_rule_removal_retains_dependencies_for_explicit_destroy_and_drop() {
    for explicit in [false, true] {
        for outcome in [
            Outcome::Reject,
            Outcome::PushError,
            Outcome::PullError,
            Outcome::FailedCompletion,
        ] {
            let fixture = Fixture::new();
            let flows = fixture.flows();
            let profile = Rc::new(flows.meter_profile(MeterProfileId(1), &profile()).unwrap());
            let meter = SharedMeter::new(&flows, &profile).unwrap();
            let table = table(&flows);
            let rule = table
                .insert(0, &Pattern::new(), 0, &[SharedArg::Meter(meter)])
                .unwrap();
            drop(table);
            drop(profile);
            fixture.fail("destroy", outcome);
            if explicit {
                assert!(rule.destroy().is_err());
            } else {
                drop(rule);
            }
            assert_eq!(
                fixture.calls("destroy"),
                1,
                "no retry after an uncertain destroy"
            );
            assert_eq!(fixture.live_rules(), 1);
            for name in [
                "meter_destroy",
                "table_destroy",
                "pattern_destroy",
                "actions_destroy",
                "profile_delete",
            ] {
                assert_eq!(fixture.calls(name), 0, "{outcome:?}: {name}");
            }
        }
    }
}

#[test]
fn borrowed_handles_preserve_the_same_native_dependencies_after_failure() {
    let fixture = Fixture::new();
    let flows = fixture.flows();
    let profile = flows.meter_profile(MeterProfileId(1), &profile()).unwrap();
    let meter = flows.meter::<Ingress>(&profile).unwrap();
    let pattern = flows.pattern_template(&Pattern::new()).unwrap();
    let actions = flows.actions_template(&[TemplateAction::Meter]).unwrap();
    let table = flows.table(config(), &[&pattern], &[&actions]).unwrap();
    let rule = table
        .insert(0, &Pattern::new(), 0, &[RuleArg::Meter(&meter)])
        .unwrap();
    fixture.fail("destroy", Outcome::Reject);
    assert!(rule.destroy().is_err());
    drop(table);
    drop(meter);
    drop(profile);
    drop(pattern);
    drop(actions);
    for name in [
        "meter_destroy",
        "table_destroy",
        "pattern_destroy",
        "actions_destroy",
        "profile_delete",
    ] {
        assert_eq!(fixture.calls(name), 0, "{name}");
    }
}

#[test]
fn update_queue_errors_retain_both_meters_and_prevent_handle_reuse() {
    for outcome in [Outcome::PushError, Outcome::PullError] {
        let fixture = Fixture::new();
        let flows = fixture.flows();
        let profile = Rc::new(flows.meter_profile(MeterProfileId(1), &profile()).unwrap());
        let old = SharedMeter::new(&flows, &profile).unwrap();
        let new = SharedMeter::new(&flows, &profile).unwrap();
        let table = table(&flows);
        let mut rule = table
            .insert(0, &Pattern::new(), 0, &[SharedArg::Meter(old)])
            .unwrap();
        fixture.fail("update", outcome);
        assert!(matches!(
            table.update(&mut rule, 0, &[SharedArg::Meter(new)]),
            Err(TemplateError::Completion { .. })
        ));
        assert!(matches!(
            table.update(&mut rule, 0, &[]),
            Err(TemplateError::Pending)
        ));
        assert!(matches!(rule.counts(), Err(TemplateError::Pending)));
        assert_eq!(fixture.calls("update"), 1);
        assert_eq!(fixture.calls("meter_destroy"), 0);
        assert!(matches!(rule.destroy(), Err(TemplateError::Pending)));
        drop(table);
        drop(profile);
        assert_eq!(fixture.calls("destroy"), 0);
        assert_eq!(fixture.calls("meter_destroy"), 0);
        assert_eq!(fixture.calls("profile_delete"), 0);
    }
}

#[test]
fn successful_updates_release_old_meters_and_rejected_updates_release_new_ones() {
    for outcome in [Outcome::Success, Outcome::Reject, Outcome::FailedCompletion] {
        let fixture = Fixture::new();
        let flows = fixture.flows();
        let profile = Rc::new(flows.meter_profile(MeterProfileId(1), &profile()).unwrap());
        let old = SharedMeter::new(&flows, &profile).unwrap();
        let new = SharedMeter::new(&flows, &profile).unwrap();
        let table = table(&flows);
        let mut rule = table
            .insert(0, &Pattern::new(), 0, &[SharedArg::Meter(old)])
            .unwrap();
        fixture.fail("update", outcome);
        assert_eq!(
            table.update(&mut rule, 0, &[SharedArg::Meter(new)]).is_ok(),
            outcome == Outcome::Success
        );
        assert_eq!(
            fixture.calls("meter_destroy"),
            usize::from(outcome != Outcome::FailedCompletion)
        );
        rule.destroy().unwrap();
        assert_eq!(fixture.calls("meter_destroy"), 2);
        table.destroy().unwrap();
        drop(profile);
        assert_eq!(fixture.calls("profile_delete"), 1);
    }
}

/// After a failed update either action set may be installed, so the rule is queried only if both
/// count.
#[test]
fn failed_updates_query_counters_only_if_both_action_sets_count() {
    for (from, to) in [(0, 1), (1, 0), (0, 0)] {
        for outcome in [Outcome::Success, Outcome::FailedCompletion] {
            let fixture = Fixture::new();
            let flows = fixture.flows();
            let pattern = Rc::new(
                flows
                    .pattern_template::<Ingress, _>(&Pattern::new())
                    .unwrap(),
            );
            let counting = Rc::new(flows.actions_template(&[TemplateAction::Count]).unwrap());
            let silent = Rc::new(flows.actions_template(&[TemplateAction::Drop]).unwrap());
            let table =
                SharedTable::new(&flows, config(), &[pattern], &[counting, silent]).unwrap();
            let mut rule = table.insert(0, &Pattern::new(), from, &[]).unwrap();
            fixture.fail("update", outcome);
            assert_eq!(
                table.update(&mut rule, to, &[]).is_ok(),
                outcome == Outcome::Success
            );
            let counted = if outcome == Outcome::Success {
                to == 0
            } else {
                from == 0 && to == 0
            };
            assert_eq!(
                rule.counts().is_ok(),
                counted,
                "{from} -> {to}, {outcome:?}"
            );
            assert_eq!(fixture.calls("query"), usize::from(counted));
        }
    }
}

#[test]
fn explicit_table_destroy_drops_rust_fields_even_on_error() {
    for outcome in [Outcome::Success, Outcome::Reject] {
        let fixture = Fixture::new();
        let flows = fixture.flows();
        let pattern = flows
            .pattern_template::<Ingress, _>(&Pattern::new())
            .unwrap();
        let actions = flows.actions_template(&[TemplateAction::Drop]).unwrap();
        let table = flows.table(config(), &[&pattern], &[&actions]).unwrap();
        let weak = Rc::downgrade(&table.resource.0);
        fixture.fail("table_destroy", outcome);
        assert_eq!(table.destroy().is_ok(), outcome == Outcome::Success);
        assert!(
            weak.upgrade().is_none(),
            "Rust fields must drop with the table"
        );
        assert_eq!(fixture.calls("table_destroy"), 1);
        drop(pattern);
        drop(actions);
        let removed = usize::from(outcome == Outcome::Success);
        assert_eq!(fixture.calls("pattern_destroy"), removed);
        assert_eq!(fixture.calls("actions_destroy"), removed);
    }
}

#[test]
fn failed_meter_operations_preserve_profiles() {
    for outcome in [Outcome::PushError, Outcome::PullError] {
        let fixture = Fixture::new();
        let flows = fixture.flows();
        let profile = Rc::new(flows.meter_profile(MeterProfileId(1), &profile()).unwrap());
        fixture.fail("meter_create", outcome);
        assert!(SharedMeter::<Ingress>::new(&flows, &profile).is_err());
        drop(profile);
        assert_eq!(fixture.calls("meter_destroy"), 0);
        assert_eq!(fixture.calls("profile_delete"), 0);
    }
    for outcome in [
        Outcome::Reject,
        Outcome::PushError,
        Outcome::PullError,
        Outcome::FailedCompletion,
    ] {
        let fixture = Fixture::new();
        let flows = fixture.flows();
        let profile = Rc::new(flows.meter_profile(MeterProfileId(1), &profile()).unwrap());
        let meter = SharedMeter::<Ingress>::new(&flows, &profile).unwrap();
        fixture.fail("meter_destroy", outcome);
        drop(meter);
        drop(profile);
        assert_eq!(fixture.calls("meter_destroy"), 1);
        assert_eq!(fixture.calls("profile_delete"), 0);
    }
}

#[test]
fn late_creation_completion_cannot_complete_a_new_contexts_rule() {
    let fixture = Fixture::new();
    for first in [true, false] {
        let flows = fixture.flows();
        let pattern = Rc::new(
            flows
                .pattern_template::<Ingress, _>(&Pattern::new())
                .unwrap(),
        );
        let actions = Rc::new(flows.actions_template(&[TemplateAction::Drop]).unwrap());
        let table = SharedTable::new(&flows, config(), &[pattern], &[actions]).unwrap();
        if first {
            fixture.fail("create", Outcome::PushError);
            assert!(table.insert(0, &Pattern::new(), 0, &[]).is_err());
            // Deliver the abandoned creation's failure before the next context's success.
            fixture.complete_next(Outcome::FailedCompletion);
        } else {
            let rule = table.insert(0, &Pattern::new(), 0, &[]).unwrap();
            rule.destroy().unwrap();
            table.destroy().unwrap();
        }
    }
    assert_eq!(fixture.calls("create"), 2);
    assert_eq!(fixture.calls("destroy"), 1);
    assert_eq!(fixture.live_rules(), 1);
}
