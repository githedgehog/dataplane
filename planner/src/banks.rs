// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Two banks: the plans of two generations in one, sharing what didn't change
//! (`notes/match-action-dag/GENERATIONS.md` §3, the train track, option 2).
//!
//! - **A selector** at the entry reads the packet's bank (hardware: the TAG bit the selector
//!   rule writes) into a bank register, and enters that bank's plan.
//! - **A level equal in both generations is kept once** (I6: unchanged tables keep their rules
//!   and stay hot). Levels are compared by position: plans of the same layout put the same
//!   stage at the same index, and gotos compare by index too.
//! - **A changed level gets a copy per bank.** Where a shared level goes to a changed one, it
//!   goes through a **dispatch** level on the bank register (the "one dispatch hop per versioned
//!   edge"); a bank's own copies go straight to their bank's levels.

use crate::plan::{Entries, Level, LevelId, Part, Plan, Reg, Step, Then};
use crate::rules::Field;
use std::collections::HashMap;
use std::hash::Hash;

/// Two generations' plans in one, and what sharing came to.
#[derive(Clone, Debug)]
pub struct TwoBank<A> {
    /// The plan: its fields are the generations' plus a last one-bit field, the packet's bank
    /// (0: the old generation, 1: the new).
    pub plan: Plan<A>,
    /// Levels kept once.
    pub shared: usize,
    /// Levels with a copy per bank (or in one bank only).
    pub copied: usize,
    /// Dispatch levels.
    pub dispatches: usize,
}

fn same_level<A: PartialEq>(a: &Level<A>, b: &Level<A>) -> bool {
    a.key == b.key && a.miss == b.miss && a.entries.same(&b.entries)
}

/// Where a level of one generation sits in the merged plan.
#[derive(Clone, Copy)]
enum Bank {
    Old,
    New,
    Both,
}

/// Level ids by position and bank, dispatch ids by the changed level they lead to, and the
/// count.
type Numbering = (
    HashMap<(usize, u8), LevelId>,
    HashMap<usize, LevelId>,
    usize,
);

/// Ids in the merged plan: level 0 is the selector, then per position its shared level (keyed
/// `(position, 2)`) or its copies (`(position, bank)`), then a dispatch for every changed level a
/// shared level goes to. Returns those, and the count.
fn number<A>(old: &Plan<A>, new: &Plan<A>, shared: &[bool]) -> Numbering {
    let mut next = 1;
    let mut id_of: HashMap<(usize, u8), LevelId> = HashMap::new();
    for (i, &kept) in shared.iter().enumerate() {
        if kept {
            id_of.insert((i, 2), next);
            next += 1;
        } else {
            for (bank, plan) in [(0u8, old), (1u8, new)] {
                if i < plan.levels.len() {
                    id_of.insert((i, bank), next);
                    next += 1;
                }
            }
        }
    }
    let mut dispatch: HashMap<usize, LevelId> = HashMap::new();
    for (i, _) in shared.iter().enumerate().filter(|(_, kept)| **kept) {
        let level = &old.levels[i];
        for step in level.entries.steps().chain(std::iter::once(&level.miss)) {
            if let Then::Goto(j) = step.then
                && !shared[j]
                && !dispatch.contains_key(&j)
            {
                dispatch.insert(j, next);
                next += 1;
            }
        }
    }
    (id_of, dispatch, next)
}

/// Merge `old` (bank 0) and `new` (bank 1).
///
/// # Panics
///
/// If the two plans are over different fields.
#[must_use]
pub fn merge<A: Clone + Eq + Hash>(old: &Plan<A>, new: &Plan<A>) -> TwoBank<A> {
    assert_eq!(old.fields, new.fields, "two banks of different keys");
    let mut fields = old.fields.clone();
    let bank_field = fields.len();
    fields.push(Field {
        name: "bank",
        width: 1,
    });
    let bank_reg = Reg::try_from(old.registers.len().max(new.registers.len())).unwrap_or(Reg::MAX);
    let n = old.levels.len().max(new.levels.len());
    let shared: Vec<bool> = (0..n)
        .map(|i| match (old.levels.get(i), new.levels.get(i)) {
            (Some(a), Some(b)) => same_level(a, b),
            _ => false,
        })
        .collect();
    // Ids in the merged plan: level 0 is the selector, then per position its shared level or
    // its copies; dispatches after.
    let (id_of, dispatch, next) = number(old, new, &shared);
    let target = |j: usize, from: Bank| -> LevelId {
        if shared[j] {
            return id_of[&(j, 2)];
        }
        match from {
            Bank::Old => id_of[&(j, 0)],
            Bank::New => id_of[&(j, 1)],
            Bank::Both => dispatch[&j],
        }
    };
    let map = |s: &Step<A>, from: Bank| Step {
        writes: s.writes.clone(),
        then: match &s.then {
            Then::Goto(j) => Then::Goto(target(*j, from)),
            Then::Done(a) => Then::Done(a.clone()),
        },
    };
    let mut levels: Vec<Option<Level<A>>> = vec![None; next];
    // The selector.
    let selector_key = vec![Part::Field {
        field: bank_field,
        len: 1,
    }];
    let enter = |plan: &Plan<A>, bank: u8, from: Bank| {
        let mut step = map(&plan.entry, from);
        step.writes.push((bank_reg, u32::from(bank)));
        step
    };
    let mut entries = Entries::for_key(&selector_key, &fields);
    entries.insert(&[0], enter(old, 0, Bank::Old));
    levels[0] = Some(Level {
        name: "selector".to_string(),
        key: selector_key,
        entries,
        miss: enter(new, 1, Bank::New),
    });
    let copy = |level: &Level<A>, from: Bank| Level {
        name: level.name.clone(),
        key: level.key.clone(),
        entries: level.entries.clone().map_steps(|s| map(&s, from)),
        miss: map(&level.miss, from),
    };
    for i in 0..n {
        if shared[i] {
            levels[id_of[&(i, 2)]] = Some(copy(&old.levels[i], Bank::Both));
        } else {
            if let Some(level) = old.levels.get(i) {
                levels[id_of[&(i, 0)]] = Some(copy(level, Bank::Old));
            }
            if let Some(level) = new.levels.get(i) {
                levels[id_of[&(i, 1)]] = Some(copy(level, Bank::New));
            }
        }
    }
    for (&j, &id) in &dispatch {
        let key = vec![Part::Reg(bank_reg)];
        let mut entries = Entries::for_key(&key, &fields);
        entries.insert(&[0], Step::goto(id_of[&(j, 0)]));
        levels[id] = Some(Level {
            name: format!("dispatch {j}"),
            key,
            entries,
            miss: Step::goto(id_of[&(j, 1)]),
        });
    }
    let mut registers = if old.registers.len() >= new.registers.len() {
        old.registers.clone()
    } else {
        new.registers.clone()
    };
    registers.push(1);
    TwoBank {
        plan: Plan {
            fields,
            levels: levels
                .into_iter()
                .map(|l| l.unwrap_or_else(|| unreachable!("every id is a level")))
                .collect(),
            entry: Step::goto(0),
            registers,
        },
        shared: shared.iter().filter(|s| **s).count(),
        copied: shared.iter().filter(|s| !**s).count(),
        dispatches: dispatch.len(),
    }
}
