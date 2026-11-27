// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The plan: what the planner emits, in backend-neutral terms (`PLANNER.md`).
//!
//! A plan is a DAG of **levels**. A level is one exact-match table: its key is a few parts,
//! each either a field's top bits (a prefix of fixed length, so one mask per level) or a
//! **class register** an earlier level wrote. An entry, or the level's miss, writes registers
//! and either goes to another level or ends with an action. Exact entries only: no priorities,
//! no ranges, so a level means the same in any backend that can do exact match.
//!
//! What a backend calls a level (an `rte_flow` group with one template, a hash table, a direct
//! array) and a register (a TAG, a metadata word, a local) is the backend's business.

use crate::rules::{Field, max_of};
use std::collections::HashMap;

/// A level, by index into [`Plan::levels`].
pub type LevelId = usize;

/// A class register, by index.
pub type Reg = u8;

/// A part of a level's key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Part {
    /// The top `len` bits of field `field`.
    Field {
        /// Index into the plan's fields.
        field: usize,
        /// How many top bits.
        len: u8,
    },
    /// A class register.
    Reg(Reg),
}

/// Where a step goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Then<A> {
    /// On to another level.
    Goto(LevelId),
    /// Done: the action.
    Done(A),
}

/// What an entry or a miss does: write registers, then go on or end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step<A> {
    /// Registers to write, and their values.
    pub writes: Vec<(Reg, u32)>,
    /// Then.
    pub then: Then<A>,
}

impl<A> Step<A> {
    /// Write `reg := value`, then go to `level`.
    #[must_use]
    pub fn write_goto(reg: Reg, value: u32, level: LevelId) -> Step<A> {
        Step {
            writes: vec![(reg, value)],
            then: Then::Goto(level),
        }
    }

    /// Go to `level`.
    #[must_use]
    pub fn goto(level: LevelId) -> Step<A> {
        Step {
            writes: Vec::new(),
            then: Then::Goto(level),
        }
    }

    /// End with `action`.
    #[must_use]
    pub fn done(action: A) -> Step<A> {
        Step {
            writes: Vec::new(),
            then: Then::Done(action),
        }
    }
}

/// One exact-match table.
#[derive(Clone, Debug)]
pub struct Level<A> {
    /// For display.
    pub name: String,
    /// The key's parts.
    pub key: Vec<Part>,
    /// Exact entries: one value per key part (a field's value masked to its top bits, as
    /// [`Plan::part_value`] computes it; a register's value).
    pub entries: HashMap<Vec<u128>, Step<A>>,
    /// When no entry matches.
    pub miss: Step<A>,
}

/// A plan.
#[derive(Clone, Debug)]
pub struct Plan<A> {
    /// The key's fields, as in the table the plan was made from.
    pub fields: Vec<Field>,
    /// The levels.
    pub levels: Vec<Level<A>>,
    /// Where a packet starts.
    pub entry: Step<A>,
    /// How many class registers, and their widths in bits.
    pub registers: Vec<u8>,
}

/// What running a plan on a key came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run<A> {
    /// The action.
    pub action: A,
    /// The levels traversed, in order.
    pub path: Vec<LevelId>,
}

impl<A: Clone> Plan<A> {
    /// The value of `part` for `key`, given the registers.
    #[must_use]
    pub fn part_value(&self, part: Part, key: &[u128], regs: &[u32]) -> u128 {
        match part {
            Part::Field { field, len } => {
                let width = self.fields[field].width;
                key[field] & max_of(width) & !max_of(width - len.min(width))
            }
            Part::Reg(r) => u128::from(regs[usize::from(r)]),
        }
    }

    /// Run the plan on `key`, as a backend would: the reference semantics of a plan.
    ///
    /// # Panics
    ///
    /// If the plan loops (longer than its level count).
    #[must_use]
    pub fn run(&self, key: &[u128]) -> Run<A> {
        let mut regs = vec![0u32; self.registers.len()];
        let mut path = Vec::new();
        let mut step = &self.entry;
        loop {
            for &(r, v) in &step.writes {
                regs[usize::from(r)] = v;
            }
            match &step.then {
                Then::Done(action) => {
                    return Run {
                        action: action.clone(),
                        path,
                    };
                }
                Then::Goto(id) => {
                    assert!(path.len() < self.levels.len(), "the plan loops");
                    path.push(*id);
                    let level = &self.levels[*id];
                    let k: Vec<u128> = level
                        .key
                        .iter()
                        .map(|&p| self.part_value(p, key, &regs))
                        .collect();
                    step = level.entries.get(&k).unwrap_or(&level.miss);
                }
            }
        }
    }

    /// The longest path through the levels from the entry, in levels: what a packet may cost,
    /// at worst. `None` if the levels loop.
    #[must_use]
    pub fn worst_path(&self) -> Option<usize> {
        #[derive(Clone, Copy)]
        enum Visit {
            Unseen,
            OnStack,
            Depth(usize),
        }
        // Longest path in a DAG, by depth-first search with memo; a level met again while on
        // the stack is a loop.
        fn depth<A>(plan: &Plan<A>, id: LevelId, memo: &mut [Visit]) -> Option<usize> {
            match memo[id] {
                Visit::Depth(d) => return Some(d),
                Visit::OnStack => return None,
                Visit::Unseen => {}
            }
            memo[id] = Visit::OnStack;
            let level = &plan.levels[id];
            let mut best = 0;
            for step in level.entries.values().chain(std::iter::once(&level.miss)) {
                if let Then::Goto(next) = step.then {
                    best = best.max(depth(plan, next, memo)?);
                }
            }
            memo[id] = Visit::Depth(best + 1);
            Some(best + 1)
        }
        let mut memo = vec![Visit::Unseen; self.levels.len()];
        match self.entry.then {
            Then::Done(_) => Some(0),
            Then::Goto(id) => depth(self, id, &mut memo),
        }
    }

    /// Entries over all levels.
    #[must_use]
    pub fn entries(&self) -> usize {
        self.levels.iter().map(|l| l.entries.len()).sum()
    }
}
