// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Shared plans: every tenant in the same levels, so the number of tables (mlx5 groups) does not
//! grow with the tenants (`spike-acl`: the CX-8 slows past about 16 groups).
//!
//! A guard level writes the packet's tenant into a register and dispatches it to one of two
//! **chains** of shared levels, each keyed on the tenant register first. What makes one level
//! serve many tenants is its single miss: so every tenant's classes are numbered with its miss
//! class 0 in every stage ("write 0, go on" is right for all of them), every tenant has every
//! stage (a constant field is an empty stage: its miss writes 0, its only class), the fused pair
//! and each IP field's prefix lengths are chosen once for all tenants, and the last level's miss
//! is the table's default for all.
//!
//! - **The join chain:** phase 0, then one join level ending with the action.
//! - **The pairwise chain**, for tenants whose join is too big: phase 0, then a fixed left fold
//!   of combinations, the last ending with the action. A tenant whose last combination can't
//!   miss to the default, or that no chain fits, runs in software.

use crate::backend::{Backend, Cost, Unfit};
use crate::guard::{Fallback, Placed, Tenant, partition};
use crate::plan::{Entries, Level, LevelId, Part, Plan, Reg, Step};
use crate::rfc::{Bits, Fusion, Group, Options, Planner, Refusal, expansion_targets, pieces};
use crate::rules::{Interval, Table};
use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;

/// A shared plan, and each tenant's outcome.
#[derive(Clone, Debug)]
pub struct Shared<A> {
    /// The plan.
    pub plan: Plan<Placed<A>>,
    /// Per tenant.
    pub tenants: Vec<Tenant>,
    /// Per chain: its tenants and what it costs, or why it couldn't be used.
    pub chains: Vec<(String, usize, Result<Cost, Unfit>)>,
}

/// One phase-0 stage of a tenant, its classes numbered with the miss as 0.
enum StageData {
    /// Two narrow fields at once.
    Fused(Fusion),
    /// One field, by intervals of its values.
    Field(Vec<(Interval, u32)>),
}

/// The layout every tenant follows.
struct Layout {
    /// The stages, in order: `Some((f, g))` fused, `None` for field `f` alone; with its field.
    stages: Vec<(usize, Option<usize>)>,
    /// Per wide field, its prefix-length targets.
    targets: HashMap<usize, Vec<u8>>,
}

/// A tenant's plan in the layout: its stages' data, and its groups.
struct TenantPlan<A> {
    stages: Vec<StageData>,
    groups: Vec<Group>,
    /// The join's entries (class per group, action), or the pairwise chain's per combination
    /// (pairs, miss-normalized; the last one's actions), or neither: software.
    finish: Finish<A>,
}

/// One combination's entries: a pair of classes, and its step.
type Combination<A> = Vec<((u32, u32), Step<A>)>;

enum Finish<A> {
    Join(Vec<(Vec<u32>, A)>),
    Pairwise(Vec<Combination<A>>),
    Software(Fallback),
}

/// Swap class ids `a` and 0, so that `a` (the miss) is 0.
fn to_zero(
    classes: &mut [Bits],
    ids: impl Iterator<Item = u32>,
    a: u32,
) -> impl Iterator<Item = u32> {
    classes.swap(0, a as usize);
    ids.map(move |id| {
        if id == a {
            0
        } else if id == 0 {
            a
        } else {
            id
        }
    })
}

/// Plan `table` with every tenant (the values of the `guard` fields) in shared levels.
///
/// # Errors
///
/// If the table can't be split by tenant (see [`crate::guard::plan`]).
pub fn plan<A: Clone + Eq + Hash, B: Backend>(
    table: &Table<A>,
    guard: &[usize],
    backend: &B,
    options: &Options,
) -> Result<Shared<A>, Refusal> {
    let parts = partition(table, guard)?;
    let rest = parts.rest.clone();
    let tenant_reg = Reg::try_from(rest.len()).unwrap_or(Reg::MAX);
    let mut planners: Vec<Planner<'_, A>> = parts
        .tenants
        .iter()
        .map(|(_, t)| Planner::new(t, options))
        .collect();
    let sub_fields = parts
        .tenants
        .first()
        .map_or_else(Vec::new, |(_, t)| t.fields.clone());
    let layout = layout(&mut planners, &sub_fields, options);
    let mut plans: Vec<TenantPlan<A>> = planners
        .iter_mut()
        .map(|p| tenant_plan(p, &layout, options))
        .collect();
    let mut levels = vec![guard_level(table, guard)];
    let (chains, starts) = chains(
        table,
        &rest,
        &layout,
        &mut plans,
        &mut levels,
        &backend.reserving(1),
        tenant_reg,
    );
    // The guard: tenant -> write its id, go to its chain; or software.
    let mut tenants = Vec::with_capacity(plans.len());
    for (t, ((key, sub), plan)) in parts.tenants.iter().zip(&plans).enumerate() {
        let id = u32::try_from(t).unwrap_or(u32::MAX);
        let step = match starts[t] {
            Some(start) => Step::write_goto(tenant_reg, id, start),
            None => Step::done(Placed::Software),
        };
        match key {
            Some(key) => levels[0].entries.insert(key, step),
            None => levels[0].miss = step,
        }
        tenants.push(Tenant {
            key: key.clone(),
            rules: sub.rules.len(),
            outcome: match &plan.finish {
                Finish::Software(why) => Err(why.clone()),
                _ => Ok(chains
                    .iter()
                    .find(|(n, _, _)| {
                        n == if matches!(plan.finish, Finish::Join(_)) {
                            "join"
                        } else {
                            "pairwise"
                        }
                    })
                    .and_then(|(_, _, c)| c.clone().ok())
                    .unwrap_or_else(|| unreachable!("a planned tenant's chain fits"))),
            },
        });
    }
    Ok(Shared {
        plan: Plan {
            fields: table.fields.clone(),
            levels,
            entry: Step::goto(0),
            registers: vec![24; rest.len() + 1],
        },
        tenants,
        chains,
    })
}

/// Per chain, its outcome; per tenant, where its chain starts (in `levels`), if it fits.
type Chains = (
    Vec<(String, usize, Result<Cost, Unfit>)>,
    Vec<Option<LevelId>>,
);

/// Build the chains into `levels`: join, then pairwise. Each is assessed alone, after the guard
/// (`reserved`); a chain that doesn't fit sends its tenants to software.
fn chains<A: Clone + Eq + Hash, B: Backend>(
    table: &Table<A>,
    rest: &[usize],
    layout: &Layout,
    plans: &mut [TenantPlan<A>],
    levels: &mut Vec<Level<Placed<A>>>,
    reserved: &B,
    tenant_reg: Reg,
) -> Chains {
    let mut chains = Vec::new();
    let mut starts: Vec<Option<LevelId>> = vec![None; plans.len()];
    for join in [true, false] {
        let members: Vec<usize> = plans
            .iter()
            .enumerate()
            .filter(|(_, p)| match p.finish {
                Finish::Join(_) => join,
                Finish::Pairwise(_) => !join,
                Finish::Software(_) => false,
            })
            .map(|(t, _)| t)
            .collect();
        let name = if join { "join" } else { "pairwise" }.to_string();
        if members.is_empty() {
            continue;
        }
        let chain = build_chain(table, rest, layout, plans, &members, tenant_reg);
        let alone = Plan {
            fields: table.fields.clone(),
            levels: chain,
            entry: Step::goto(0),
            registers: vec![24; rest.len() + 1],
        };
        match reserved.assess(&alone) {
            Ok(cost) => {
                let base = levels.len();
                for level in alone.levels {
                    levels.push(offset(level, base));
                }
                for &t in &members {
                    starts[t] = Some(base);
                }
                chains.push((name, members.len(), Ok(cost)));
            }
            Err(unfit) => {
                for &t in &members {
                    plans[t].finish = Finish::Software(Fallback::Unfit(unfit.clone()));
                }
                chains.push((name, members.len(), Err(unfit)));
            }
        }
    }
    (chains, starts)
}

/// The guard level: the guard fields exactly; its entries are filled once tenants are placed.
fn guard_level<A: Clone>(table: &Table<A>, guard: &[usize]) -> Level<Placed<A>> {
    let key: Vec<Part> = guard
        .iter()
        .map(|&f| Part::Field {
            field: f,
            len: table.fields[f].width,
        })
        .collect();
    Level {
        name: "guard".to_string(),
        entries: Entries::for_key(&key, &table.fields),
        key,
        miss: Step::done(Placed::Software),
    }
}

/// The layout: the fused pair and each wide field's prefix lengths, chosen over every tenant.
fn layout<A: Clone + Eq + Hash>(
    planners: &mut [Planner<'_, A>],
    fields: &[crate::rules::Field],
    options: &Options,
) -> Layout {
    let narrow: Vec<usize> = (0..fields.len())
        .filter(|&f| fields[f].width <= options.narrow)
        .collect();
    let fuse = if options.fuse {
        narrow
            .iter()
            .min_by_key(|&&f| fields[f].width)
            .and_then(|&first| {
                narrow
                    .iter()
                    .copied()
                    .filter(|&g| {
                        g != first
                            && u32::from(fields[first].width) + u32::from(fields[g].width) <= 24
                    })
                    .map(|g| {
                        let total: u128 =
                            planners.iter_mut().map(|p| p.fused_entries(first, g)).sum();
                        (total, g)
                    })
                    .filter(|(n, _)| *n <= options.max_entries as u128)
                    .min()
                    .map(|(_, g)| (first.min(g), first.max(g)))
            })
    } else {
        None
    };
    let mut stages = Vec::new();
    for f in 0..fields.len() {
        match fuse {
            Some((a, b)) if f == a => stages.push((a, Some(b))),
            Some((_, b)) if f == b => {}
            _ => stages.push((f, None)),
        }
    }
    let mut targets = HashMap::new();
    for f in (0..fields.len()).filter(|&f| fields[f].width > options.narrow) {
        let mut counts: BTreeMap<u8, usize> = BTreeMap::new();
        for p in planners.iter_mut() {
            let (_, intervals) = p.elementary(f);
            let default = p.field_default(f, &intervals);
            for (iv, _) in intervals.iter().filter(|(_, id)| *id != default) {
                for (_, len) in pieces(iv.lo, iv.hi, fields[f].width) {
                    *counts.entry(len).or_default() += 1;
                }
            }
        }
        let counts: Vec<(u8, usize)> = counts.into_iter().collect();
        let mut t = expansion_targets(&counts, options.expand);
        if t.is_empty() {
            t.push(fields[f].width);
        }
        targets.insert(f, t);
    }
    Layout { stages, targets }
}

/// A tenant's stages in the layout, and its final stage: join if it fits, else pairwise, else
/// software.
fn tenant_plan<A: Clone + Eq + Hash>(
    p: &mut Planner<'_, A>,
    layout: &Layout,
    options: &Options,
) -> TenantPlan<A> {
    let mut stages = Vec::new();
    let mut groups = Vec::new();
    for &(f, g) in &layout.stages {
        let reg = Reg::try_from(f).unwrap_or(Reg::MAX);
        if let Some(g) = g {
            let mut fusion = p.fusion_of(f, g);
            let common = fusion.common;
            let ids: Vec<u32> = to_zero(
                &mut fusion.classes,
                fusion.cross.iter().map(|c| c.2),
                common,
            )
            .collect();
            for (c, id) in fusion.cross.iter_mut().zip(ids) {
                c.2 = id;
            }
            fusion.common = 0;
            groups.push(Group {
                covered: 1 << f | 1 << g,
                classes: fusion.classes.clone(),
                reg: Some(reg),
            });
            stages.push(StageData::Fused(fusion));
        } else {
            let (mut classes, intervals) = p.elementary(f);
            let default = p.field_default(f, &intervals);
            let ids: Vec<u32> =
                to_zero(&mut classes, intervals.iter().map(|(_, id)| *id), default).collect();
            let intervals = intervals
                .iter()
                .zip(ids)
                .map(|((iv, _), id)| (*iv, id))
                .collect();
            groups.push(Group {
                covered: 1 << f,
                classes,
                reg: Some(reg),
            });
            stages.push(StageData::Field(intervals));
        }
    }
    let finish = finish(p, &groups, options);
    TenantPlan {
        stages,
        groups,
        finish,
    }
}

/// The join's entries if within the caps; else the pairwise combinations; else software.
fn finish<A: Clone + Eq + Hash>(
    p: &mut Planner<'_, A>,
    groups: &[Group],
    options: &Options,
) -> Finish<A> {
    if options.join {
        let mut entries = Vec::new();
        let ok = p.join_each(groups, &mut |picked, action| {
            entries.push((picked.to_vec(), action.clone()));
            entries.len() <= options.max_entries
        });
        if ok {
            return Finish::Join(entries);
        }
    }
    // A fixed left fold: (g0 x g1) x g2 x ...
    let default = p.table_default();
    let mut combos = Vec::new();
    let mut acc = Group {
        covered: groups[0].covered,
        classes: groups[0].classes.clone(),
        reg: groups[0].reg,
    };
    for (k, next) in groups.iter().enumerate().skip(1) {
        let last = k + 1 == groups.len();
        let covered = acc.covered | next.covered;
        let dense = acc.classes.len() * next.classes.len() <= options.dense;
        let Ok((mut classes, pairs)) = p.cross(&acc, next, covered, dense, "pairwise") else {
            return Finish::Software(Fallback::Unplanned(Refusal::Product {
                stage: format!("pairwise {k}"),
                product: acc.classes.len() * next.classes.len(),
            }));
        };
        let ra = acc.reg.unwrap_or(0);
        let mut steps = Vec::new();
        if last {
            // Miss to the default: only pairs left out of a sparse enumeration cross to the
            // core (class 0), so the core must act as the default does.
            if !dense && p.action_of(&classes[0]) != default {
                return Finish::Software(Fallback::Unplanned(Refusal::Product {
                    stage: "pairwise: the core's action isn't the default".to_string(),
                    product: pairs.len(),
                }));
            }
            for ((ia, ib), id) in &pairs {
                let action = p.action_of(&classes[*id as usize]);
                if action != default {
                    steps.push(((*ia, *ib), Step::done(action)));
                }
            }
        } else {
            let common = if dense {
                let mut count: HashMap<u32, usize> = HashMap::new();
                for (_, id) in &pairs {
                    *count.entry(*id).or_default() += 1;
                }
                count
                    .into_iter()
                    .max_by_key(|(id, n)| (*n, std::cmp::Reverse(*id)))
                    .map_or(0, |(id, _)| id)
            } else {
                0
            };
            let ids: Vec<u32> =
                to_zero(&mut classes, pairs.iter().map(|(_, id)| *id), common).collect();
            for (((ia, ib), _), id) in pairs.iter().zip(ids) {
                if id != 0 {
                    steps.push(((*ia, *ib), Step::write_goto(ra, id, usize::MAX)));
                }
            }
        }
        if steps.len() > options.max_entries {
            return Finish::Software(Fallback::Unplanned(Refusal::Entries {
                entries: steps.len(),
            }));
        }
        combos.push(steps);
        acc = Group {
            covered,
            classes,
            reg: Some(ra),
        };
    }
    Finish::Pairwise(combos)
}

/// The levels of one chain for `members`, as a plan of its own (level 0 its first).
fn build_chain<A: Clone + Eq + Hash>(
    table: &Table<A>,
    rest: &[usize],
    layout: &Layout,
    plans: &[TenantPlan<A>],
    members: &[usize],
    tenant: Reg,
) -> Vec<Level<Placed<A>>> {
    let tid = |t: usize| u128::try_from(t).unwrap_or(u128::MAX);
    let fields = &table.fields;
    let mut levels: Vec<Level<Placed<A>>> = Vec::new();
    for (s, &(f, g)) in layout.stages.iter().enumerate() {
        let reg = Reg::try_from(f).unwrap_or(Reg::MAX);
        let width = fields[rest[f]].width;
        // How many levels this stage takes: one, or one per prefix-length target.
        let targets: Vec<u8> = match (g, layout.targets.get(&f)) {
            (None, Some(t)) => t.iter().rev().copied().collect(),
            _ => vec![width],
        };
        let base = levels.len();
        let after = base + targets.len();
        let mut stage: Vec<Level<Placed<A>>> = targets
            .iter()
            .enumerate()
            .map(|(k, &len)| {
                let mut key = vec![
                    Part::Reg(tenant),
                    Part::Field {
                        field: rest[f],
                        len,
                    },
                ];
                if let Some(g) = g {
                    key.push(Part::Field {
                        field: rest[g],
                        len: fields[rest[g]].width,
                    });
                }
                let miss = if k + 1 == targets.len() {
                    Step::write_goto(reg, 0, after)
                } else {
                    Step::goto(base + k + 1)
                };
                Level {
                    name: format!("stage {s} /{len}"),
                    entries: Entries::for_key(&key, fields),
                    key,
                    miss,
                }
            })
            .collect();
        for &t in members {
            match &plans[t].stages[s] {
                StageData::Fused(fusion) => {
                    let [vf, vg] = &fusion.values;
                    for (a, b, id, _) in fusion.cross.iter().filter(|c| c.2 != 0) {
                        for x in vf[*a].iter().flat_map(|iv| iv.lo..=iv.hi) {
                            for y in vg[*b].iter().flat_map(|iv| iv.lo..=iv.hi) {
                                stage[0]
                                    .entries
                                    .insert(&[tid(t), x, y], Step::write_goto(reg, *id, after));
                            }
                        }
                    }
                }
                StageData::Field(intervals) => {
                    for (iv, id) in intervals.iter().filter(|(_, id)| *id != 0) {
                        for (lo, len) in pieces(iv.lo, iv.hi, width) {
                            // The shortest target at least the piece's length (targets are
                            // longest first here).
                            let (k, &target) = targets
                                .iter()
                                .enumerate()
                                .rev()
                                .find(|(_, t)| **t >= len)
                                .unwrap_or_else(|| unreachable!("the longest length is a target"));
                            let step = 1u128 << (width - target);
                            for c in 0..1u128 << (target - len) {
                                stage[k].entries.insert(
                                    &[tid(t), lo + c * step],
                                    Step::write_goto(reg, *id, after),
                                );
                            }
                        }
                    }
                }
            }
        }
        levels.extend(stage);
    }
    finish_levels(table, plans, members, tenant, &mut levels);
    levels
}

/// The chain's last levels, after phase 0 (which `levels` holds): the join, or the
/// combinations.
fn finish_levels<A: Clone + Eq + Hash>(
    table: &Table<A>,
    plans: &[TenantPlan<A>],
    members: &[usize],
    tenant: Reg,
    levels: &mut Vec<Level<Placed<A>>>,
) {
    let tid = |t: usize| u128::try_from(t).unwrap_or(u128::MAX);
    let fields = &table.fields;
    let regs: Vec<Reg> = plans[members[0]]
        .groups
        .iter()
        .filter_map(|g| g.reg)
        .collect();
    match &plans[members[0]].finish {
        Finish::Join(_) => {
            let mut key = vec![Part::Reg(tenant)];
            key.extend(regs.iter().map(|&r| Part::Reg(r)));
            let mut entries = Entries::for_key(&key, fields);
            for &t in members {
                if let Finish::Join(rows) = &plans[t].finish {
                    for (picked, action) in rows {
                        let mut values = vec![tid(t)];
                        values.extend(picked.iter().map(|&id| u128::from(id)));
                        entries.insert(&values, Step::done(Placed::Here(action.clone())));
                    }
                }
            }
            levels.push(Level {
                name: "join".to_string(),
                key,
                entries,
                miss: Step::done(Placed::Here(table.default.clone())),
            });
        }
        Finish::Pairwise(combos) => {
            let ra = regs[0];
            for (k, &rb) in regs.iter().enumerate().skip(1) {
                let last = k + 1 == regs.len();
                let key = vec![Part::Reg(tenant), Part::Reg(ra), Part::Reg(rb)];
                let mut entries = Entries::for_key(&key, fields);
                let next = levels.len() + 1;
                for &t in members {
                    if let Finish::Pairwise(combos) = &plans[t].finish {
                        for ((ia, ib), step) in &combos[k - 1] {
                            let step = Step {
                                writes: step.writes.clone(),
                                then: match &step.then {
                                    crate::plan::Then::Done(a) => {
                                        crate::plan::Then::Done(Placed::Here(a.clone()))
                                    }
                                    crate::plan::Then::Goto(_) => crate::plan::Then::Goto(next),
                                },
                            };
                            entries.insert(&[tid(t), u128::from(*ia), u128::from(*ib)], step);
                        }
                    }
                }
                let miss = if last {
                    Step::done(Placed::Here(table.default.clone()))
                } else {
                    Step::write_goto(ra, 0, next)
                };
                levels.push(Level {
                    name: format!("combine {k}"),
                    key,
                    entries,
                    miss,
                });
            }
            let _ = combos;
        }
        Finish::Software(_) => unreachable!("a chain's members are planned"),
    }
}

/// `level`, its gotos shifted by `base`.
fn offset<A: Clone>(level: Level<A>, base: usize) -> Level<A> {
    let shift = |s: Step<A>| Step {
        writes: s.writes,
        then: match s.then {
            crate::plan::Then::Goto(id) => crate::plan::Then::Goto(id + base),
            done @ crate::plan::Then::Done(_) => done,
        },
    };
    Level {
        name: level.name,
        key: level.key,
        entries: level.entries.map_steps(shift),
        miss: shift(level.miss),
    }
}
