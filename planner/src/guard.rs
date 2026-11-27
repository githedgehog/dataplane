// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Guarded plans: one plan per tenant, behind a guard level on exact fields (`PLANNER.md`,
//! guarded levels and per-tenant fallback).
//!
//! The guard fields (for an ACL, the VNI pair: the peering) are matched exactly first, and each
//! tenant's rules are planned alone, over the other fields. A tenant whose plan doesn't fit the
//! backend runs in software, alone: a pathological ACL costs its owner, not the other tenants.

use crate::backend::{Backend, Cost, Unfit};
use crate::plan::{Entries, Level, Part, Plan, Step, Then};
use crate::rfc::{self, Options, Refusal};
use crate::rules::{Rule, Table};
use std::collections::BTreeMap;
use std::hash::Hash;

/// Where a guarded plan leaves a packet.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Placed<A> {
    /// Decided here: the table's action.
    Here(A),
    /// Its tenant's rules run in software.
    Software,
}

/// Why a tenant runs in software.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fallback {
    /// No plan could be made.
    Unplanned(Refusal),
    /// The plan doesn't fit the backend.
    Unfit(Unfit),
}

/// One tenant's outcome.
#[derive(Clone, Debug)]
pub struct Tenant {
    /// Its guard fields' values; `None` for packets of no listed tenant.
    pub key: Option<Vec<u128>>,
    /// Its rules.
    pub rules: usize,
    /// What its plan costs, or why it runs in software.
    pub outcome: Result<Cost, Fallback>,
}

/// A guarded plan, and each tenant's outcome.
#[derive(Clone, Debug)]
pub struct Guarded<A> {
    /// The plan.
    pub plan: Plan<Placed<A>>,
    /// Per tenant.
    pub tenants: Vec<Tenant>,
}

/// Plan `table` per tenant, the tenants being the values of the `guard` fields, for `backend`.
///
/// # Errors
///
/// If a rule constrains a guard field to neither one value nor any, or constrains some guard
/// fields but not all.
pub fn plan<A: Clone + Eq + Hash, B: Backend>(
    table: &Table<A>,
    guard: &[usize],
    backend: &B,
    options: &Options,
) -> Result<Guarded<A>, Refusal> {
    let Partition {
        rest,
        tenants: parts,
    } = partition(table, guard)?;
    let guard_key: Vec<Part> = guard
        .iter()
        .map(|&f| Part::Field {
            field: f,
            len: table.fields[f].width,
        })
        .collect();
    let mut levels: Vec<Level<Placed<A>>> = vec![Level {
        name: "guard".to_string(),
        entries: Entries::for_key(&guard_key, &table.fields),
        key: guard_key,
        miss: Step::done(Placed::Software),
    }];
    // Every tenant's plan comes after the guard level.
    let backend = backend.reserving(1);
    let mut registers: BTreeMap<u8, u8> = BTreeMap::new();
    let mut tenants = Vec::new();
    for (key, table) in parts {
        let key = key.as_ref();
        let (step, outcome) = match rfc::plan(&table, options) {
            Err(refusal) => (
                Step::done(Placed::Software),
                Err(Fallback::Unplanned(refusal)),
            ),
            Ok((sub, _)) => match backend.assess(&sub) {
                Err(unfit) => (Step::done(Placed::Software), Err(Fallback::Unfit(unfit))),
                Ok(cost) => {
                    for (r, w) in sub.registers.iter().enumerate() {
                        let e = registers
                            .entry(u8::try_from(r).unwrap_or(u8::MAX))
                            .or_default();
                        *e = (*e).max(*w);
                    }
                    (graft(&mut levels, sub, &rest), Ok(cost))
                }
            },
        };
        match key {
            Some(key) => {
                levels[0].entries.insert(key, step);
            }
            None => levels[0].miss = step,
        }
        tenants.push(Tenant {
            key: key.cloned(),
            rules: table.rules.len(),
            outcome,
        });
    }
    Ok(Guarded {
        plan: Plan {
            fields: table.fields.clone(),
            levels,
            entry: Step::goto(0),
            registers: registers.into_values().collect(),
        },
        tenants,
    })
}

/// A table split by tenant.
pub(crate) struct Partition<A> {
    /// The fields other than the guard's, in order: the sub-tables' fields.
    pub(crate) rest: Vec<usize>,
    /// Each tenant's guard values (`None`: packets of no listed tenant) and rules over `rest`.
    pub(crate) tenants: Vec<(Option<Vec<u128>>, Table<A>)>,
}

/// Split `table` by the values of its `guard` fields. Rules naming no tenant (any on every
/// guard field) are in every tenant's table, in order.
pub(crate) fn partition<A: Clone>(
    table: &Table<A>,
    guard: &[usize],
) -> Result<Partition<A>, Refusal> {
    table.check().map_err(Refusal::Malformed)?;
    let rest: Vec<usize> = (0..table.fields.len())
        .filter(|f| !guard.contains(f))
        .collect();
    let patterns = patterns(table, guard)?;
    let keys: Vec<Vec<u128>> = patterns
        .iter()
        .flatten()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let sub = |key: Option<&Vec<u128>>| Table {
        fields: rest.iter().map(|&f| table.fields[f]).collect(),
        rules: table
            .rules
            .iter()
            .zip(&patterns)
            .filter(|(_, p)| p.is_none() || p.as_ref() == key)
            .map(|(r, _)| Rule {
                matches: rest.iter().map(|&f| r.matches[f].clone()).collect(),
                action: r.action.clone(),
            })
            .collect(),
        default: table.default.clone(),
    };
    let tenants = keys
        .iter()
        .map(Some)
        .chain(std::iter::once(None))
        .map(|key| (key.cloned(), sub(key)))
        .collect();
    Ok(Partition { rest, tenants })
}

/// Each rule's guard values: `Some` if all exact, `None` if all any.
fn patterns<A>(table: &Table<A>, guard: &[usize]) -> Result<Vec<Option<Vec<u128>>>, Refusal> {
    let mut patterns: Vec<Option<Vec<u128>>> = Vec::with_capacity(table.rules.len());
    for (n, rule) in table.rules.iter().enumerate() {
        let exact: Vec<Option<u128>> = guard
            .iter()
            .map(|&f| {
                let ivs = rule.matches[f].intervals();
                (ivs.len() == 1 && ivs[0].lo == ivs[0].hi).then_some(ivs[0].lo)
            })
            .collect();
        let any = guard
            .iter()
            .all(|&f| rule.matches[f].is_any(table.fields[f].width));
        patterns.push(match (exact.iter().all(Option::is_some), any) {
            (true, _) => Some(exact.into_iter().flatten().collect()),
            (false, true) => None,
            (false, false) => {
                return Err(Refusal::Malformed(format!(
                    "rule {n}: guard fields neither all exact nor all any"
                )));
            }
        });
    }
    Ok(patterns)
}

/// Move `sub`'s levels into `levels`, its fields renamed to the table's (`rest`) and its
/// actions placed here; return its entry step.
fn graft<A: Clone>(
    levels: &mut Vec<Level<Placed<A>>>,
    sub: Plan<A>,
    rest: &[usize],
) -> Step<Placed<A>> {
    let offset = levels.len();
    let step = |s: Step<A>| Step {
        writes: s.writes,
        then: match s.then {
            Then::Goto(id) => Then::Goto(id + offset),
            Then::Done(a) => Then::Done(Placed::Here(a)),
        },
    };
    for level in sub.levels {
        levels.push(Level {
            name: level.name,
            key: level
                .key
                .into_iter()
                .map(|p| match p {
                    Part::Field { field, len } => Part::Field {
                        field: rest[field],
                        len,
                    },
                    reg @ Part::Reg(_) => reg,
                })
                .collect(),
            entries: level.entries.map_steps(step),
            miss: step(level.miss),
        });
    }
    step(sub.entry)
}
