// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A software model of a lowered [`Plan`]: what the NIC may do with a frame, without the NIC.
//!
//! Patterns are matched by [`dpdk::flow::model`], on the very structures the PMD reads; this
//! module adds what the tables do: groups, priorities, jumps, meters and their colors. Where the
//! hardware may go more than one way, the model returns every way:
//!
//! - rules of one table (or of tables of equal priority) keep no order among themselves, so every
//!   matching rule is a possible outcome;
//! - a meter may give any color (the model keeps no token state);
//! - the frame may be parsed in more than one way (see [`dpdk::flow::model`]), but for what the
//!   qualification settled for mlx5 ([`mlx5::PARSER`](crate::mlx5::PARSER)).
//!
//! A test then holds every possible outcome to the cascade contract against the software.

use dpdk::flow::Priority;
use dpdk::flow::model::{Frame, Unmodelled, views_by};
use dpdk::flow::template::{Color, TemplateAction};

use crate::mlx5::Group;

use crate::mlx5::{Arg, Plan, PlannedRule, PlannedTable, Role};

/// How far jumps may chain before the model calls it a loop.
const MAX_DEPTH: usize = 16;

/// Where a frame ends up.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Sent on, unchanged, to the driver's fate.
    Delivered,
    /// Dropped.
    Dropped,
    /// Nothing in the root group matched: the port's default handling, as if there were no plan.
    Untouched,
    /// Nothing matched in a group a jump led to: what the NIC does then is not ours to choose.
    Missed(Group),
}

/// One thing the NIC may do with a frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The meters charged, by index into [`Plan::meters`], in order.
    pub meters: Vec<usize>,
    /// The color the last meter gave, if any.
    pub color: Option<Color>,
    /// The rules taken, in order.
    pub path: Vec<Role>,
    /// Where it ended up.
    pub verdict: Verdict,
}

/// The plan cannot be modelled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ModelError {
    /// A pattern constrains something the pattern model does not parse.
    #[error(transparent)]
    Pattern(#[from] Unmodelled),
    /// Jumps chain deeper than the model follows.
    #[error("jumps chain more than {MAX_DEPTH} deep")]
    Loop,
    /// A rule's arguments do not fit its actions template.
    #[error("a rule's arguments do not fit its actions template")]
    Arguments,
}

#[derive(Debug, Clone)]
struct State {
    meters: Vec<usize>,
    color: Option<Color>,
    path: Vec<Role>,
}

impl Plan {
    /// Every outcome the NIC may produce for `frame` (the frame's bytes on the wire).
    ///
    /// # Errors
    ///
    /// Returns [`ModelError`] if the plan uses something the model does not interpret.
    pub fn outcomes(&self, frame: &[u8]) -> Result<Vec<Outcome>, ModelError> {
        self.outcomes_without(frame, &[])
    }

    /// Every outcome the NIC may produce for `frame` with the plan installed but for the rules
    /// in `refused` (see [`Installed::refused`](crate::mlx5::Installed::refused)).
    ///
    /// # Errors
    ///
    /// Returns [`ModelError`] if the plan uses something the model does not interpret.
    pub fn outcomes_without(
        &self,
        frame: &[u8],
        refused: &[Role],
    ) -> Result<Vec<Outcome>, ModelError> {
        let model = Walk {
            plan: self,
            refused,
        };
        let mut outcomes = Vec::new();
        for view in views_by(frame, crate::mlx5::PARSER) {
            let start = State {
                meters: Vec::new(),
                color: None,
                path: Vec::new(),
            };
            for outcome in model.group(&view, Group::Root, start, 0)? {
                if !outcomes.contains(&outcome) {
                    outcomes.push(outcome);
                }
            }
        }
        Ok(outcomes)
    }
}

/// A plan, walked as installed.
struct Walk<'a> {
    plan: &'a Plan,
    refused: &'a [Role],
}

impl Walk<'_> {
    fn group(
        &self,
        frame: &Frame,
        group: Group,
        state: State,
        depth: usize,
    ) -> Result<Vec<Outcome>, ModelError> {
        if depth > MAX_DEPTH {
            return Err(ModelError::Loop);
        }
        let mut tables: Vec<&PlannedTable> =
            self.plan.tables().filter(|t| t.group == group).collect();
        tables.sort_by_key(|t| t.priority);
        let mut levels: Vec<(Priority, Vec<&PlannedTable>)> = Vec::new();
        for table in tables {
            match levels.last_mut() {
                Some((priority, level)) if *priority == table.priority => level.push(table),
                _ => levels.push((table.priority, vec![table])),
            }
        }
        for (_, level) in levels {
            let mut outcomes = Vec::new();
            for table in level {
                for rule in &table.rules {
                    if self.refused.contains(&rule.role) {
                        continue;
                    }
                    if rule.pattern.matches(frame, state.color)? {
                        outcomes.extend(self.actions(frame, table, rule, state.clone(), depth)?);
                    }
                }
            }
            if !outcomes.is_empty() {
                return Ok(outcomes);
            }
        }
        let verdict = if group == Group::Root {
            Verdict::Untouched
        } else {
            Verdict::Missed(group)
        };
        Ok(vec![state.end(verdict)])
    }

    fn actions(
        &self,
        frame: &Frame,
        table: &PlannedTable,
        rule: &PlannedRule,
        mut state: State,
        depth: usize,
    ) -> Result<Vec<Outcome>, ModelError> {
        let actions = table
            .actions
            .get(rule.actions)
            .and_then(|&a| self.plan.actions.get(a))
            .ok_or(ModelError::Arguments)?;
        state.path.push(rule.role);
        let mut args = rule.args.iter();
        // Every way through the actions so far: a meter forks one per color.
        let mut states = vec![state];
        for action in actions {
            match action {
                // A mark is metadata for software; the packet is unchanged.
                TemplateAction::Count | TemplateAction::Mark(_) => {}
                TemplateAction::Meter => {
                    let Some(&Arg::Meter(meter)) = args.next() else {
                        return Err(ModelError::Arguments);
                    };
                    states = states
                        .into_iter()
                        .flat_map(|s| {
                            Color::ALL.into_iter().map(move |color| {
                                let mut s = s.clone();
                                s.meters.push(meter);
                                s.color = Some(color);
                                s
                            })
                        })
                        .collect();
                }
                // The fixed jumps of a plan: to validation, and to the switch.
                TemplateAction::Jump(group) if *group == crate::mlx5::SWITCH => {
                    return self.jump(frame, Group::Switch, states, depth);
                }
                TemplateAction::Jump(group) if *group == crate::mlx5::VALIDATE => {
                    return self.jump(frame, Group::Validate, states, depth);
                }
                TemplateAction::Jump(_) => return Err(ModelError::Arguments),
                TemplateAction::JumpPerRule => {
                    let Some(&Arg::Jump(group)) = args.next() else {
                        return Err(ModelError::Arguments);
                    };
                    return self.jump(frame, group, states, depth);
                }
                TemplateAction::Queue(_)
                | TemplateAction::Rss(_)
                | TemplateAction::SendToKernel => {
                    return Ok(states
                        .into_iter()
                        .map(|s| s.end(Verdict::Delivered))
                        .collect());
                }
                TemplateAction::Drop => {
                    return Ok(states
                        .into_iter()
                        .map(|s| s.end(Verdict::Dropped))
                        .collect());
                }
            }
        }
        // No fate: the NIC's default for the group, which a plan never relies on.
        Ok(states
            .into_iter()
            .map(|s| s.end(Verdict::Missed(table.group)))
            .collect())
    }

    fn jump(
        &self,
        frame: &Frame,
        group: Group,
        states: Vec<State>,
        depth: usize,
    ) -> Result<Vec<Outcome>, ModelError> {
        let mut outcomes = Vec::new();
        for state in states {
            outcomes.extend(self.group(frame, group, state, depth + 1)?);
        }
        Ok(outcomes)
    }
}

impl State {
    fn end(self, verdict: Verdict) -> Outcome {
        Outcome {
            meters: self.meters,
            color: self.color,
            path: self.path,
            verdict,
        }
    }
}
