// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Actions templates and the per-rule arguments they take.

use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr::{from_ref, null};

use dpdk_sys::{
    rte_flow_action, rte_flow_action_handle, rte_flow_action_jump, rte_flow_action_queue,
    rte_flow_action_type as at,
};

use crate::flow::{Domain, FlowGroup};
use crate::queue::rx::RxQueueIndex;

use super::meter::Meter;

/// An action in an [`ActionsTemplate`](super::ActionsTemplate).
///
/// [`Meter`](TemplateAction::Meter) and [`JumpPerRule`](TemplateAction::JumpPerRule) are chosen
/// per rule, with a [`RuleArg`]; the template fixes every other action.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TemplateAction {
    /// Continue in another group.
    Jump(FlowGroup),
    /// Continue in the group each rule names with [`RuleArg::Jump`].
    JumpPerRule,
    /// Deliver to a receive queue of this port.
    Queue(RxQueueIndex),
    /// Count the rule's packets and bytes; see [`TemplateRule::counts`](super::TemplateRule::counts).
    Count,
    /// Drop.
    Drop,
    /// Return the packet to the kernel driver of a bifurcated port, as if no rule had matched.
    SendToKernel,
    /// Color the packet with a per-rule [`Meter`]; match the color in a later group.
    Meter,
}

impl TemplateAction {
    /// Whether a rule supplies this action's configuration.
    pub(crate) fn per_rule(self) -> bool {
        matches!(self, TemplateAction::Meter | TemplateAction::JumpPerRule)
    }
}

/// A rule's configuration for one per-rule action of its template, in template order.
#[derive(Debug, Copy, Clone)]
pub enum RuleArg<'a, D: Domain> {
    /// The meter for a [`TemplateAction::Meter`].
    Meter(&'a Meter<'a, D>),
    /// The group for a [`TemplateAction::JumpPerRule`].
    Jump(FlowGroup),
}

/// The configuration an action points at.
#[derive(Debug, Copy, Clone)]
enum Conf {
    None,
    Jump(rte_flow_action_jump),
    Queue(rte_flow_action_queue),
    Handle(*mut rte_flow_action_handle),
}

/// An action and the configuration it points at, kept in place while the PMD reads them.
#[derive(Debug, Copy, Clone)]
pub(crate) struct OwnedAction {
    type_: at::Type,
    conf: Conf,
}

impl OwnedAction {
    fn new(type_: at::Type, conf: Conf) -> OwnedAction {
        OwnedAction { type_, conf }
    }

    fn ffi(&self) -> rte_flow_action {
        let conf: *const c_void = match &self.conf {
            Conf::None => null(),
            Conf::Jump(jump) => from_ref(jump).cast(),
            Conf::Queue(queue) => from_ref(queue).cast(),
            Conf::Handle(handle) => handle.cast_const().cast(),
        };
        rte_flow_action {
            type_: self.type_,
            conf,
        }
    }
}

/// The END-terminated action array for `actions`, pointing into them: keep `actions` alive and
/// unmoved while the PMD reads the result.
pub(crate) fn lower(actions: &[OwnedAction]) -> Vec<rte_flow_action> {
    let mut lowered: Vec<_> = actions.iter().map(OwnedAction::ffi).collect();
    lowered.push(rte_flow_action {
        type_: at::RTE_FLOW_ACTION_TYPE_END,
        conf: null(),
    });
    lowered
}

/// The fixed part of `action`: what the template and every rule pass for it.
fn fixed(action: TemplateAction) -> OwnedAction {
    match action {
        TemplateAction::Jump(group) => OwnedAction::new(
            at::RTE_FLOW_ACTION_TYPE_JUMP,
            Conf::Jump(rte_flow_action_jump { group: group.0 }),
        ),
        TemplateAction::Queue(queue) => OwnedAction::new(
            at::RTE_FLOW_ACTION_TYPE_QUEUE,
            Conf::Queue(rte_flow_action_queue {
                index: queue.as_u16(),
            }),
        ),
        TemplateAction::Count => OwnedAction::new(at::RTE_FLOW_ACTION_TYPE_COUNT, Conf::None),
        TemplateAction::Drop => OwnedAction::new(at::RTE_FLOW_ACTION_TYPE_DROP, Conf::None),
        TemplateAction::SendToKernel => {
            OwnedAction::new(at::RTE_FLOW_ACTION_TYPE_SEND_TO_KERNEL, Conf::None)
        }
        // The rule names the meter or group: no configuration in the template.
        TemplateAction::Meter => OwnedAction::new(at::RTE_FLOW_ACTION_TYPE_INDIRECT, Conf::None),
        TemplateAction::JumpPerRule => OwnedAction::new(at::RTE_FLOW_ACTION_TYPE_JUMP, Conf::None),
    }
}

/// The template's actions and masks.
///
/// A mask with a configuration fixes the action for every rule; a null one leaves it to the rule.
/// That holds for an indirect action too: mlx5 uses the template's handle for every rule of a
/// template whose mask has a configuration, ignoring the rules' own (`mlx5_flow_hw.c`,
/// `__flow_hw_actions_translate`). So a per-rule meter is an `INDIRECT` action with no
/// configuration, typed by a `METER_MARK` mask with none either.
pub(crate) fn template(actions: &[TemplateAction]) -> (Vec<OwnedAction>, Vec<OwnedAction>) {
    let values = actions.iter().copied().map(fixed).collect();
    let masks = actions
        .iter()
        .map(|&action| match action {
            TemplateAction::Jump(_) => OwnedAction::new(
                at::RTE_FLOW_ACTION_TYPE_JUMP,
                Conf::Jump(rte_flow_action_jump { group: u32::MAX }),
            ),
            TemplateAction::Queue(_) => OwnedAction::new(
                at::RTE_FLOW_ACTION_TYPE_QUEUE,
                Conf::Queue(rte_flow_action_queue { index: u16::MAX }),
            ),
            TemplateAction::Meter => {
                OwnedAction::new(at::RTE_FLOW_ACTION_TYPE_METER_MARK, Conf::None)
            }
            other => fixed(other),
        })
        .collect();
    (values, masks)
}

/// The per-rule arguments do not fit the template.
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArgumentError {
    /// The rule gave more or fewer arguments than the template has per-rule actions.
    #[error(
        "the actions template takes {expected} per-rule argument(s), but the rule gave {given}"
    )]
    Count {
        /// Per-rule actions in the template.
        expected: usize,
        /// Arguments the rule supplied.
        given: usize,
    },
    /// An argument is not for the per-rule action in its position.
    #[error("per-rule argument {index} is not for a {action:?} action")]
    Kind {
        /// The argument's position.
        index: usize,
        /// The per-rule action in that position.
        action: TemplateAction,
    },
}

/// A rule's actions: the template's, with each per-rule action taken from `args` in order.
pub(crate) fn rule<D: Domain>(
    actions: &[TemplateAction],
    args: &[RuleArg<'_, D>],
) -> Result<Vec<OwnedAction>, ArgumentError> {
    let expected = actions.iter().filter(|a| a.per_rule()).count();
    if expected != args.len() {
        return Err(ArgumentError::Count {
            expected,
            given: args.len(),
        });
    }
    let mut args = args.iter().enumerate();
    actions
        .iter()
        .map(|&action| {
            if !action.per_rule() {
                return Ok(fixed(action));
            }
            // The counts were checked above.
            let Some((index, arg)) = args.next() else {
                unreachable!()
            };
            match (action, arg) {
                (TemplateAction::Meter, RuleArg::Meter(meter)) => Ok(OwnedAction::new(
                    at::RTE_FLOW_ACTION_TYPE_INDIRECT,
                    Conf::Handle(meter.raw()),
                )),
                (TemplateAction::JumpPerRule, RuleArg::Jump(group)) => Ok(OwnedAction::new(
                    at::RTE_FLOW_ACTION_TYPE_JUMP,
                    Conf::Jump(rte_flow_action_jump { group: group.0 }),
                )),
                _ => Err(ArgumentError::Kind { index, action }),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn types(actions: &[OwnedAction]) -> Vec<at::Type> {
        actions.iter().map(|a| a.type_).collect()
    }

    #[test]
    fn a_per_rule_meter_leaves_its_handle_to_the_rule() {
        let (values, masks) =
            template(&[TemplateAction::Meter, TemplateAction::Jump(FlowGroup(2))]);
        assert_eq!(
            types(&values),
            [
                at::RTE_FLOW_ACTION_TYPE_INDIRECT,
                at::RTE_FLOW_ACTION_TYPE_JUMP
            ]
        );
        assert_eq!(
            types(&masks),
            [
                at::RTE_FLOW_ACTION_TYPE_METER_MARK,
                at::RTE_FLOW_ACTION_TYPE_JUMP
            ]
        );
        let lowered_values = lower(&values);
        let lowered_masks = lower(&masks);
        assert!(lowered_values[0].conf.is_null());
        assert!(
            lowered_masks[0].conf.is_null(),
            "a masked handle is shared by every rule"
        );
        assert!(!lowered_masks[1].conf.is_null(), "the jump target is fixed");
        assert_eq!(lowered_masks[2].type_, at::RTE_FLOW_ACTION_TYPE_END);
    }

    #[test]
    fn rules_must_supply_exactly_the_per_rule_arguments() {
        let actions = [TemplateAction::Count, TemplateAction::SendToKernel];
        let none: [RuleArg<'_, crate::flow::Ingress>; 0] = [];
        assert_eq!(
            types(&rule(&actions, &none).unwrap_or_default()),
            [
                at::RTE_FLOW_ACTION_TYPE_COUNT,
                at::RTE_FLOW_ACTION_TYPE_SEND_TO_KERNEL
            ]
        );
        assert_eq!(
            rule(&[TemplateAction::Meter], &none).err(),
            Some(ArgumentError::Count {
                expected: 1,
                given: 0
            })
        );
        assert_eq!(
            rule::<crate::flow::Ingress>(&[TemplateAction::Meter], &[RuleArg::Jump(FlowGroup(3))])
                .err(),
            Some(ArgumentError::Kind {
                index: 0,
                action: TemplateAction::Meter
            })
        );
    }

    #[test]
    fn a_per_rule_jump_takes_the_rules_group() {
        let (_, masks) = template(&[TemplateAction::JumpPerRule]);
        assert!(lower(&masks)[0].conf.is_null());
        let actions = rule::<crate::flow::Ingress>(
            &[TemplateAction::Count, TemplateAction::JumpPerRule],
            &[RuleArg::Jump(FlowGroup(7))],
        )
        .unwrap_or_default();
        let lowered = lower(&actions);
        assert_eq!(lowered[1].type_, at::RTE_FLOW_ACTION_TYPE_JUMP);
        // SAFETY: a JUMP action points at an `rte_flow_action_jump`, alive with `actions`.
        assert_eq!(
            unsafe { (*lowered[1].conf.cast::<rte_flow_action_jump>()).group },
            7
        );
    }
}
