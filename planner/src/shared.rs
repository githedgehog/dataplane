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
#[derive(Clone, Debug, PartialEq, Eq)]
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
    let ids: Vec<usize> = (0..parts.tenants.len()).collect();
    let tenants = fill_guard(
        &mut levels[0],
        &parts.tenants,
        &ids,
        &plans,
        &starts,
        &chains,
        tenant_reg,
    );
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

/// Fill `guard` with each tenant's entry (`ids[n]`: the id of `tenants[n]`), and say what came
/// of each.
fn fill_guard<A: Clone + Eq + Hash>(
    guard: &mut Level<Placed<A>>,
    tenants: &[(Option<Vec<u128>>, Table<A>)],
    ids: &[usize],
    plans: &[TenantPlan<A>],
    starts: &[Option<LevelId>],
    chains: &[(String, usize, Result<Cost, Unfit>)],
    tenant_reg: Reg,
) -> Vec<Tenant> {
    let mut out = Vec::with_capacity(tenants.len());
    for ((key, sub), &t) in tenants.iter().zip(ids) {
        let id = u32::try_from(t).unwrap_or(u32::MAX);
        let step = match starts[t] {
            Some(start) => Step::write_goto(tenant_reg, id, start),
            None => Step::done(Placed::Software),
        };
        match key {
            Some(key) => guard.entries.insert(key, step),
            None => guard.miss = step,
        }
        let plan = &plans[t];
        out.push(Tenant {
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
    out
}

/// Two generations in one shared plan, versioned by tenant id.
#[derive(Clone, Debug)]
pub struct Versioned<A> {
    /// The plan: its fields are the table's plus a last one-bit field, the packet's bank (0: the
    /// old generation, 1: the new).
    pub plan: Plan<Placed<A>>,
    /// Per generation, per tenant.
    pub tenants: [Vec<Tenant>; 2],
    /// Tenants new or changed in the new generation: those with entries of their own in it.
    pub fresh: usize,
    /// Per chain: its tenants (ids of both generations) and what it costs.
    pub chains: Vec<(String, usize, Result<Cost, Unfit>)>,
}

/// Plan two generations of `table` in one shared plan, versioned by tenant id (the train
/// track's two banks, GENERATIONS.md §3): a selector on the packet's bank, a guard per
/// generation, and the chains shared. A tenant unchanged between them keeps its id and entries;
/// a new or changed one gets a fresh id, and its entries join the same levels. Only the guard is
/// versioned, so an update costs the changed tenants' entries, not copies of shared levels.
/// Retiring the old generation drops its guard and the ids only it uses.
///
/// The layout is chosen over both generations' tenants, so both fit it.
///
/// # Errors
///
/// If a table can't be split by tenant, or the two are over different fields.
pub fn generations<A: Clone + Eq + Hash, B: Backend>(
    old: &Table<A>,
    new: &Table<A>,
    guard: &[usize],
    backend: &B,
    options: &Options,
) -> Result<Versioned<A>, Refusal> {
    let po = partition(old, guard)?;
    let pn = partition(new, guard)?;
    // Ids: the old generation's tenants, then the new generation's new or changed ones.
    let mut subs: Vec<Option<&Table<A>>> = po.tenants.iter().map(|(_, t)| Some(t)).collect();
    let old_ids: Vec<usize> = (0..subs.len()).collect();
    let mut new_ids = Vec::with_capacity(pn.tenants.len());
    for (key, sub) in &pn.tenants {
        if let Some(i) = po.tenants.iter().position(|(k, t)| k == key && t == sub) {
            new_ids.push(i);
        } else {
            subs.push(Some(sub));
            new_ids.push(subs.len() - 1);
        }
    }
    let banks = Banks {
        old,
        new,
        guard,
        po: &po,
        pn: &pn,
        old_ids: &old_ids,
        new_ids: &new_ids,
        subs: &subs,
    };
    let (versioned, _, _) = two_banks(&banks, backend, options, None)?;
    Ok(versioned)
}

/// Two generations, split by tenant, and the ids their tenants have: what [`two_banks`] plans.
struct Banks<'a, A> {
    old: &'a Table<A>,
    new: &'a Table<A>,
    guard: &'a [usize],
    po: &'a crate::guard::Partition<A>,
    pn: &'a crate::guard::Partition<A>,
    /// The id of each of `po`'s tenants, and of each of `pn`'s.
    old_ids: &'a [usize],
    new_ids: &'a [usize],
    /// Each id's tenant table; `None` for an id no tenant of either generation has.
    subs: &'a [Option<&'a Table<A>>],
}

/// Plan two generations in one shared plan, with the given tenant ids: in `previous`'s layout if
/// every tenant fits it, else in a new one over all of them. Returns the plan, its layout, and
/// whether the layout changed (then every tenant's entries do).
fn two_banks<A: Clone + Eq + Hash, B: Backend>(
    banks: &Banks<'_, A>,
    backend: &B,
    options: &Options,
    previous: Option<&Layout>,
) -> Result<(Versioned<A>, Layout, bool), Refusal> {
    let Banks {
        old,
        new,
        guard,
        po,
        pn,
        old_ids,
        new_ids,
        subs,
    } = *banks;
    if old.fields != new.fields || old.default != new.default {
        // The shared chains' last miss is the default: both generations must agree on it.
        return Err(Refusal::Malformed(
            "two generations of different keys or defaults".to_string(),
        ));
    }
    let rest = po.rest.clone();
    let tenant_reg = Reg::try_from(rest.len()).unwrap_or(Reg::MAX);
    let sub_fields: Vec<crate::rules::Field> = rest.iter().map(|&f| old.fields[f]).collect();
    let mut planners: Vec<Option<Planner<'_, A>>> = subs
        .iter()
        .map(|t| t.map(|t| Planner::new(t, options)))
        .collect();
    let keep = previous.filter(|l| {
        planners
            .iter_mut()
            .flatten()
            .all(|p| fits(l, p, &sub_fields, options))
    });
    let (layout, relayout) = if let Some(l) = keep {
        (l.clone(), false)
    } else {
        let mut live: Vec<Planner<'_, A>> = subs
            .iter()
            .flatten()
            .map(|t| Planner::new(t, options))
            .collect();
        (layout(&mut live, &sub_fields, options), previous.is_some())
    };
    let mut plans: Vec<TenantPlan<A>> = planners
        .iter_mut()
        .map(|p| match p {
            Some(p) => tenant_plan(p, &layout, options),
            None => TenantPlan {
                stages: Vec::new(),
                groups: Vec::new(),
                finish: Finish::Software(Fallback::Unplanned(Refusal::Malformed(
                    "an id no tenant has".to_string(),
                ))),
            },
        })
        .collect();
    let fresh = new_ids.iter().filter(|id| !old_ids.contains(id)).count();
    let (fields, mut levels) = bank_levels(old, new, guard);
    // Every chain comes after the selector and a guard.
    let (chains, starts) = chains(
        old,
        &rest,
        &layout,
        &mut plans,
        &mut levels,
        &backend.reserving(2),
        tenant_reg,
    );
    let old_tenants = fill_guard(
        &mut levels[1],
        &po.tenants,
        old_ids,
        &plans,
        &starts,
        &chains,
        tenant_reg,
    );
    let new_tenants = fill_guard(
        &mut levels[2],
        &pn.tenants,
        new_ids,
        &plans,
        &starts,
        &chains,
        tenant_reg,
    );
    let versioned = Versioned {
        plan: Plan {
            fields,
            levels,
            entry: Step::goto(0),
            registers: vec![24; rest.len() + 1],
        },
        tenants: [old_tenants, new_tenants],
        fresh,
        chains,
    };
    Ok((versioned, layout, relayout))
}

/// The fields of a two-bank plan (the table's, and the bank), and its first levels: the
/// selector on the bank, then a guard per generation.
fn bank_levels<A: Clone + Eq + Hash>(
    old: &Table<A>,
    new: &Table<A>,
    guard: &[usize],
) -> (Vec<crate::rules::Field>, Vec<Level<Placed<A>>>) {
    let mut fields = old.fields.clone();
    let bank = fields.len();
    fields.push(crate::rules::Field {
        name: "bank",
        width: 1,
    });
    let selector_key = vec![Part::Field {
        field: bank,
        len: 1,
    }];
    let mut entries = Entries::for_key(&selector_key, &fields);
    entries.insert(&[0], Step::goto(1));
    let levels = vec![
        Level {
            name: "selector".to_string(),
            key: selector_key,
            entries,
            miss: Step::goto(2),
        },
        Level {
            name: "guard (old)".to_string(),
            ..guard_level(old, guard)
        },
        Level {
            name: "guard (new)".to_string(),
            ..guard_level(new, guard)
        },
    ];
    (fields, levels)
}

/// Whether `planner`'s tenant fits `layout`: every wide field's pieces at most as long as the
/// layout's longest prefix-length target (a piece goes to the shortest target at least its
/// length; with none, the layout would need a new one).
fn fits<A: Clone + Eq + Hash>(
    layout: &Layout,
    planner: &mut Planner<'_, A>,
    fields: &[crate::rules::Field],
    options: &Options,
) -> bool {
    layout.targets.iter().all(|(&f, targets)| {
        let longest = targets.iter().copied().max().unwrap_or(0);
        let (_, intervals) = planner.elementary(f);
        let default = planner.field_default(f, &intervals);
        let _ = options;
        intervals
            .iter()
            .filter(|(_, id)| *id != default)
            .flat_map(|(iv, _)| pieces(iv.lo, iv.hi, fields[f].width))
            .all(|(_, len)| len <= longest)
    })
}

/// Each tenant's guard values (`None`: packets of no listed tenant) and its id.
pub type TenantIds = Vec<(Option<Vec<u128>>, usize)>;

/// Planner state carried from generation to generation: tenant ids that stay put, so an
/// unchanged tenant keeps the same entries, and the layout, kept while every tenant fits it.
pub struct State<A> {
    guard: Vec<usize>,
    /// The live generation: its table, and each of its tenants' guard values and id.
    current: Option<(Table<A>, TenantIds)>,
    layout: Option<Layout>,
}

/// What [`State::next`] made.
#[derive(Clone, Debug)]
pub struct Next<A> {
    /// The two banks: the live generation (0) and the next (1).
    pub versioned: Versioned<A>,
    /// Whether the layout changed: every tenant's entries do, then, not just the fresh ones'.
    pub relayout: bool,
    /// The next generation's tenants' ids.
    pub ids: TenantIds,
}

impl<A: Clone + Eq + Hash> State<A> {
    /// No generation yet, tenants told apart by the `guard` fields.
    #[must_use]
    pub fn new(guard: &[usize]) -> Self {
        State {
            guard: guard.to_vec(),
            current: None,
            layout: None,
        }
    }

    /// Plan `next` as the next generation, in two banks with the live one (the first: in both).
    /// An unchanged tenant keeps its id; a new or changed one takes the lowest id the live
    /// generation doesn't use. Once returned, `next` is the live generation (the old one is
    /// retired before the one after).
    ///
    /// # Errors
    ///
    /// If `next` can't be split by tenant, or differs from the live one in fields or default.
    pub fn next<B: Backend>(
        &mut self,
        next: &Table<A>,
        backend: &B,
        options: &Options,
    ) -> Result<Next<A>, Refusal> {
        let old = self.current.as_ref().map_or(next, |(t, _)| t);
        let po = partition(old, &self.guard)?;
        let pn = partition(next, &self.guard)?;
        let old_ids: Vec<usize> = match &self.current {
            Some((_, ids)) => po
                .tenants
                .iter()
                .map(|(key, _)| {
                    ids.iter()
                        .find(|(k, _)| k == key)
                        .map_or_else(|| unreachable!("the live tenants have ids"), |(_, id)| *id)
                })
                .collect(),
            None => (0..po.tenants.len()).collect(),
        };
        let mut new_ids = Vec::with_capacity(pn.tenants.len());
        let mut used: std::collections::BTreeSet<usize> = old_ids.iter().copied().collect();
        for (key, sub) in &pn.tenants {
            let same = po
                .tenants
                .iter()
                .zip(&old_ids)
                .find(|((k, t), _)| k == key && t == sub)
                .map(|(_, &id)| id);
            let id =
                same.unwrap_or_else(|| (0..=used.len()).find(|i| !used.contains(i)).unwrap_or(0));
            used.insert(id);
            new_ids.push(id);
        }
        let ids = used.iter().max().map_or(0, |m| m + 1);
        let mut subs: Vec<Option<&Table<A>>> = vec![None; ids];
        for ((_, t), &id) in po.tenants.iter().zip(&old_ids) {
            subs[id] = Some(t);
        }
        for ((_, t), &id) in pn.tenants.iter().zip(&new_ids) {
            subs[id] = Some(t);
        }
        let banks = Banks {
            old,
            new: next,
            guard: &self.guard,
            po: &po,
            pn: &pn,
            old_ids: &old_ids,
            new_ids: &new_ids,
            subs: &subs,
        };
        let (versioned, layout, relayout) =
            two_banks(&banks, backend, options, self.layout.as_ref())?;
        let ids: TenantIds = pn
            .tenants
            .iter()
            .map(|(k, _)| k.clone())
            .zip(new_ids)
            .collect();
        self.current = Some((next.clone(), ids.clone()));
        self.layout = Some(layout);
        Ok(Next {
            versioned,
            relayout,
            ids,
        })
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
