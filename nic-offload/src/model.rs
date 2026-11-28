// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Model every possible outcome of a lowered [`Plan`].
//!
//! [`dpdk::flow::model`] matches the PMD's pattern structures; this module interprets tables,
//! priorities, jumps and meters. Outcomes include all matching rules at equal priority,
//! all meter colors (no token state), and parser choices allowed by [`mlx5::PARSER`](crate::mlx5::PARSER).
//! Tests compare each outcome with the software cascade contract.

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
    /// The MARK it arrives with, if a rule marked it with a value of its own.
    pub mark: Option<u32>,
    /// Whether a trap rule stamped it with the configuration generation (its MARK).
    pub stamped: bool,
    /// Where that trap rule has software resume (`None`: the root).
    pub trap: Option<std::num::NonZero<u8>>,
    /// The META it arrives with, if any.
    pub meta: Option<u32>,
    /// Whether its outer headers were removed: software receives the inner frame.
    pub decapped: bool,
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
    mark: Option<u32>,
    stamped: bool,
    trap: Option<std::num::NonZero<u8>>,
    meta: Option<u32>,
    decapped: bool,
    /// The TAG registers rules wrote (only the bank's, so far).
    tags: [u32; 1],
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
                mark: None,
                stamped: false,
                trap: None,
                meta: None,
                tags: [0],
                decapped: false,
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
                    if rule
                        .pattern
                        .matches_tagged(frame, state.color, &state.tags)?
                    {
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
                TemplateAction::Count => {}
                // A mark is metadata for software; the packet is unchanged.
                TemplateAction::Mark(id) => {
                    for s in &mut states {
                        s.mark = Some(*id);
                    }
                }
                TemplateAction::MarkPerRule
                | TemplateAction::TagPerRule(_)
                | TemplateAction::MetaPerRule => {
                    let write = self.write(action, args.next())?;
                    for s in &mut states {
                        write(s);
                    }
                }
                // No later pattern of the same rule looks at the frame: only its fate follows.
                TemplateAction::VxlanDecap => {
                    for s in &mut states {
                        s.decapped = true;
                    }
                }
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
                // The fixed jumps of a plan: the root's, to the switch; deliveries', to the trap.
                TemplateAction::Jump(group) if *group == crate::mlx5::SWITCH => {
                    return self.jump(frame, Group::Switch, states, depth);
                }
                TemplateAction::Jump(group) if *group == crate::mlx5::TRAP => {
                    return self.jump(frame, Group::Trap, states, depth);
                }
                TemplateAction::Jump(group) if *group == crate::mlx5::SELECTOR => {
                    return self.jump(frame, Group::Selector, states, depth);
                }
                TemplateAction::Jump(group) if *group == crate::mlx5::TRAP_DECAPPED => {
                    return self.jump(frame, Group::TrapDecapped, states, depth);
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

    /// What a per-rule metadata action writes, given its rule's argument.
    fn write(
        &self,
        action: &TemplateAction,
        arg: Option<&Arg>,
    ) -> Result<impl Fn(&mut State) + use<>, ModelError> {
        // (mark, stamped with a node, META, TAG register and value)
        type Write = (
            Option<u32>,
            Option<Option<std::num::NonZero<u8>>>,
            Option<u32>,
            Option<(usize, u32)>,
        );
        let write: Write = match (action, arg) {
            (TemplateAction::MarkPerRule, Some(&Arg::Mark(id))) => (Some(id), None, None, None),
            (TemplateAction::MarkPerRule, Some(&Arg::Stamp(node))) => {
                (None, Some(node), None, None)
            }
            (TemplateAction::MetaPerRule, Some(&Arg::Meta(value))) => {
                (None, None, Some(value), None)
            }
            (TemplateAction::TagPerRule(index), Some(Arg::Select)) => (
                None,
                None,
                None,
                Some((usize::from(*index), crate::mlx5::bank_tag(self.plan.bank))),
            ),
            _ => return Err(ModelError::Arguments),
        };
        Ok(move |s: &mut State| {
            let (mark, stamp, meta, tag) = write;
            if mark.is_some() {
                s.mark = mark;
            }
            if let Some(node) = stamp {
                s.stamped = true;
                s.trap = node;
            }
            if meta.is_some() {
                s.meta = meta;
            }
            if let Some((index, value)) = tag
                && index < s.tags.len()
            {
                s.tags[index] = value;
            }
        })
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
            mark: self.mark,
            stamped: self.stamped,
            trap: self.trap,
            meta: self.meta,
            decapped: self.decapped,
            verdict,
        }
    }
}
