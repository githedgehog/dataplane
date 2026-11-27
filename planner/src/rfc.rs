// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A planner by recursive flow classification (RFC), the first strategy: `PLANNER.md`, and the
//! spike that sized it (`notes/match-action-dag/spike-rfc`).
//!
//! - **Phase 0, per field:** cut the field's values into elementary intervals, each carrying the
//!   set of rules whose field holds it, and number the distinct sets: the field's classes. The
//!   largest class is the miss, so its values need no entries. A narrow field becomes one exact
//!   level over its values; a wide one a level per prefix length its pieces use (disjoint, so
//!   in any order).
//! - **Combining:** two fields' (or groups') classes cross into the classes of both, as an
//!   exact level on the two registers; the most common result is the miss. Pairs go smallest
//!   product first. The last combination ends with the action.
//! - **Verdict-aware truncation:** a class's rule set only matters up to its first rule that
//!   holds whatever the fields not yet looked at are: that rule wins over every later one. Cut
//!   there, and classes that differ only in dead rules merge. With every field looked at, a
//!   class is its first rule.
//!
//! Plans are checked against [`Table::first_match`]; see the tests.

use crate::plan::{Level, LevelId, Part, Plan, Reg, Step, Then};
use crate::rules::{Field, Interval, Table, max_of};
use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;

/// A set of rules, by index: bit `i` is rule `i`.
type Bits = Vec<u64>;

/// A pair of classes enumerated by a combination, and the class it crosses to.
type Pair = ((u32, u32), u32);

fn and(a: &Bits, b: &Bits) -> Bits {
    a.iter().zip(b).map(|(x, y)| x & y).collect()
}

fn first(bits: &Bits) -> Option<usize> {
    bits.iter()
        .enumerate()
        .find(|(_, w)| **w != 0)
        .map(|(i, w)| i * 64 + w.trailing_zeros() as usize)
}

/// The most common of `items`.
fn most_common<T: Eq + Hash>(items: impl Iterator<Item = T>) -> Option<T> {
    let mut count: HashMap<T, usize> = HashMap::new();
    for item in items {
        *count.entry(item).or_default() += 1;
    }
    count
        .into_iter()
        .max_by_key(|(_, n)| *n)
        .map(|(item, _)| item)
}

/// The rules in `bits`, in order.
fn ones(bits: &Bits) -> impl Iterator<Item = usize> + '_ {
    bits.iter().enumerate().flat_map(|(i, &w)| {
        let mut w = w;
        std::iter::from_fn(move || {
            (w != 0).then(|| {
                let b = w.trailing_zeros() as usize;
                w &= w - 1;
                i * 64 + b
            })
        })
    })
}

/// Clear every bit after `index`.
fn keep_through(bits: &mut Bits, index: usize) {
    let (word, bit) = (index / 64, index % 64);
    if let Some(w) = bits.get_mut(word) {
        *w &= if bit == 63 {
            u64::MAX
        } else {
            (1 << (bit + 1)) - 1
        };
    }
    for w in bits.iter_mut().skip(word + 1) {
        *w = 0;
    }
}

/// Tuning, and what makes a plan too big to make.
#[derive(Clone, Debug)]
pub struct Options {
    /// Fields at most this wide are classified by one exact level over their values.
    pub narrow: u8,
    /// The largest cross product a combination may enumerate.
    pub max_product: usize,
    /// Up to this product, a combination enumerates every pair and makes the most common result
    /// the miss; beyond it, only pairs sharing a non-core rule, with the core as the miss.
    pub dense: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            narrow: 16,
            max_product: 4_000_000,
            dense: 1_000_000,
        }
    }
}

/// Why no plan was made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A combination's cross product is beyond [`Options::max_product`].
    Product {
        /// Which.
        stage: String,
        /// How big.
        product: usize,
    },
    /// The table is malformed.
    Malformed(String),
}

/// What a stage of the plan came to, for sizing.
#[derive(Clone, Debug)]
pub struct Stage {
    /// Which.
    pub name: String,
    /// Classes out.
    pub classes: usize,
    /// Levels it took.
    pub levels: usize,
    /// Entries over its levels.
    pub entries: usize,
}

/// A group of fields looked at, and its classes.
struct Group {
    /// Fields covered, as a bit mask.
    covered: u32,
    /// Class id -> rule set.
    classes: Vec<Bits>,
    /// The register holding the class id; `None` if there is one class only (nothing to look
    /// up: every packet is in it).
    reg: Option<Reg>,
}

/// Where a stage's levels go next: patched once the next stage exists.
const CONTINUE: LevelId = usize::MAX;

struct Planner<'t, A> {
    table: &'t Table<A>,
    words: usize,
    options: &'t Options,
    levels: Vec<Level<A>>,
    /// Per stage, its first level (if it has any).
    stages: Vec<Option<LevelId>>,
    report: Vec<Stage>,
    universal: HashMap<u32, Bits>,
    /// Whether a level already ends with the action.
    ended: bool,
}

impl<A: Clone + Eq + Hash> Planner<'_, A> {
    fn all_fields(&self) -> u32 {
        (1u32 << self.table.fields.len()) - 1
    }

    /// The rules that hold for every value of every field outside `covered`.
    fn universal_outside(&mut self, covered: u32) -> &Bits {
        let (table, words) = (self.table, self.words);
        self.universal.entry(covered).or_insert_with(|| {
            let mut bits = vec![0; words];
            for (i, rule) in table.rules.iter().enumerate() {
                let any = rule
                    .matches
                    .iter()
                    .zip(&table.fields)
                    .enumerate()
                    .all(|(f, (set, field))| covered & 1 << f != 0 || set.is_any(field.width));
                if any {
                    bits[i / 64] |= 1 << (i % 64);
                }
            }
            bits
        })
    }

    /// Cut `bits` after its first rule that holds whatever the fields outside `covered` are.
    fn truncate(&mut self, mut bits: Bits, covered: u32) -> Bits {
        let universal = self.universal_outside(covered);
        if let Some(winner) = first(&and(&bits, universal)) {
            keep_through(&mut bits, winner);
        }
        bits
    }

    /// The action of a class whose fields are all looked at: its first rule's, or the default.
    fn action_of(&self, bits: &Bits) -> A {
        first(bits).map_or_else(
            || self.table.default.clone(),
            |i| self.table.rules[i].action.clone(),
        )
    }

    fn push_level(&mut self, level: Level<A>) -> LevelId {
        self.levels.push(level);
        self.levels.len() - 1
    }

    /// Field `f`'s elementary intervals, merged where adjacent ones share a class, and its
    /// classes: a sweep over the boundaries of every rule's intervals on `f`.
    fn elementary(&mut self, f: usize) -> (Vec<Bits>, Vec<(Interval, u32)>) {
        let field = self.table.fields[f];
        let covered = 1u32 << f;
        let mut any = vec![0u64; self.words];
        let mut edges: BTreeMap<u128, (Vec<usize>, Vec<usize>)> = BTreeMap::new();
        edges.entry(0).or_default();
        for (i, rule) in self.table.rules.iter().enumerate() {
            let set = &rule.matches[f];
            if set.is_any(field.width) {
                any[i / 64] |= 1 << (i % 64);
                continue;
            }
            for iv in set.intervals() {
                edges.entry(iv.lo).or_default().0.push(i);
                if iv.hi < max_of(field.width) {
                    edges.entry(iv.hi + 1).or_default().1.push(i);
                }
            }
        }
        let points: Vec<u128> = edges.keys().copied().collect();
        let mut current = any;
        let mut ids: HashMap<Bits, u32> = HashMap::new();
        let mut classes: Vec<Bits> = Vec::new();
        let mut intervals: Vec<(Interval, u32)> = Vec::new();
        for (n, at) in points.iter().enumerate() {
            let (starts, ends) = &edges[at];
            for &i in ends {
                current[i / 64] &= !(1 << (i % 64));
            }
            for &i in starts {
                current[i / 64] |= 1 << (i % 64);
            }
            let hi = points
                .get(n + 1)
                .map_or(max_of(field.width), |next| next - 1);
            let bits = self.truncate(current.clone(), covered);
            let id = *ids.entry(bits.clone()).or_insert_with(|| {
                classes.push(bits);
                u32::try_from(classes.len() - 1).unwrap_or(u32::MAX)
            });
            match intervals.last_mut() {
                Some((last, last_id)) if *last_id == id => last.hi = hi,
                _ => intervals.push((Interval { lo: *at, hi }, id)),
            }
        }
        (classes, intervals)
    }

    /// Phase 0 for field `f`: its classes, and the levels that look them up into `reg`.
    fn field(&mut self, f: usize, reg: Reg) -> Group {
        let field = self.table.fields[f];
        let covered = 1u32 << f;
        let (classes, intervals) = self.elementary(f);
        if classes.len() == 1 {
            self.stages.push(None);
            self.report.push(Stage {
                name: field.name.to_string(),
                classes: 1,
                levels: 0,
                entries: 0,
            });
            return Group {
                covered,
                classes,
                reg: None,
            };
        }
        // The miss: the class with the most entries to spare.
        let cost = |iv: &Interval| -> u128 {
            if field.width <= self.options.narrow {
                iv.hi - iv.lo + 1
            } else {
                pieces(iv.lo, iv.hi, field.width).len() as u128
            }
        };
        let mut weight: HashMap<u32, u128> = HashMap::new();
        for (iv, id) in &intervals {
            *weight.entry(*id).or_default() += cost(iv);
        }
        let default = weight
            .iter()
            .max_by_key(|(id, w)| (**w, std::cmp::Reverse(**id)))
            .map_or(0, |(id, _)| *id);
        let first_level = self.levels.len();
        let (levels, entries) = self.field_levels(f, reg, &intervals, default);
        self.report.push(Stage {
            name: field.name.to_string(),
            classes: classes.len(),
            levels,
            entries,
        });
        self.stages.push(Some(first_level));
        Group {
            covered,
            classes,
            reg: Some(reg),
        }
    }

    /// The levels classifying field `f` into `reg`, all but the `default` class's values:
    /// how many levels, and entries.
    fn field_levels(
        &mut self,
        f: usize,
        reg: Reg,
        intervals: &[(Interval, u32)],
        default: u32,
    ) -> (usize, usize) {
        let field = self.table.fields[f];
        let first_level = self.levels.len();
        if field.width <= self.options.narrow {
            let mut entries = HashMap::new();
            for (iv, id) in intervals.iter().filter(|(_, id)| *id != default) {
                for v in iv.lo..=iv.hi {
                    entries.insert(vec![v], Step::write_goto(reg, *id, CONTINUE));
                }
            }
            let n = entries.len();
            self.push_level(Level {
                name: format!("{} (exact)", field.name),
                key: vec![Part::Field {
                    field: f,
                    len: field.width,
                }],
                entries,
                miss: Step::write_goto(reg, default, CONTINUE),
            });
            (1, n)
        } else {
            let mut by_len: BTreeMap<std::cmp::Reverse<u8>, HashMap<Vec<u128>, Step<A>>> =
                BTreeMap::new();
            for (iv, id) in intervals.iter().filter(|(_, id)| *id != default) {
                for (lo, len) in pieces(iv.lo, iv.hi, field.width) {
                    by_len
                        .entry(std::cmp::Reverse(len))
                        .or_default()
                        .insert(vec![lo], Step::write_goto(reg, *id, CONTINUE));
                }
            }
            let count = by_len.len();
            let mut n = 0;
            for (k, (std::cmp::Reverse(len), entries)) in by_len.into_iter().enumerate() {
                n += entries.len();
                let next = first_level + k + 1;
                let miss = if k + 1 == count {
                    Step::write_goto(reg, default, CONTINUE)
                } else {
                    Step::goto(next)
                };
                self.push_level(Level {
                    name: format!("{} /{len}", field.name),
                    key: vec![Part::Field { field: f, len }],
                    entries,
                    miss,
                });
            }
            (count, n)
        }
    }

    /// Cross two groups into one: classes of both, looked up by an exact level on their
    /// registers into `a`'s register. With every field covered, the level ends with the action.
    ///
    /// Sparse: the rules in every class of both sides (the core) are in every crossing, so a
    /// pair sharing no other rule crosses to the core exactly. The core is the miss, and only
    /// pairs sharing a non-core rule are enumerated, through an index from rules to classes.
    fn combine(&mut self, a: &Group, b: &Group) -> Result<Group, Refusal> {
        let covered = a.covered | b.covered;
        let name = format!("{} x {}", self.names(a.covered), self.names(b.covered));
        // With one side constant, nothing to look up: the other side's ids now name the
        // crossed classes.
        let (ra, rb) = match (a.reg, b.reg) {
            (Some(ra), Some(rb)) => (ra, rb),
            (Some(r), None) | (None, Some(r)) => {
                let (other, one) = if a.reg.is_some() { (a, b) } else { (b, a) };
                let relabeled = other
                    .classes
                    .iter()
                    .map(|c| self.truncate(and(c, &one.classes[0]), covered))
                    .collect();
                self.stages.push(None);
                return Ok(Group {
                    covered,
                    classes: relabeled,
                    reg: Some(r),
                });
            }
            (None, None) => {
                let bits = self.truncate(and(&a.classes[0], &b.classes[0]), covered);
                self.stages.push(None);
                return Ok(Group {
                    covered,
                    classes: vec![bits],
                    reg: None,
                });
            }
        };
        let dense = a.classes.len() * b.classes.len() <= self.options.dense;
        let (classes, pairs) = self.cross(a, b, covered, dense, &name)?;
        // The miss: the core, when sparse (the pairs not enumerated cross to it); else the most
        // common result.
        let mut entries = HashMap::new();
        let miss = if covered == self.all_fields() {
            let actions: Vec<A> = classes.iter().map(|c| self.action_of(c)).collect();
            let common = if dense {
                most_common(pairs.iter().map(|(_, id)| &actions[*id as usize]))
                    .unwrap_or(&actions[0])
                    .clone()
            } else {
                actions[0].clone()
            };
            for ((ia, ib), id) in &pairs {
                let action = &actions[*id as usize];
                if *action != common {
                    entries.insert(
                        vec![u128::from(*ia), u128::from(*ib)],
                        Step::done(action.clone()),
                    );
                }
            }
            self.ended = true;
            Step::done(common)
        } else {
            let common = if dense {
                most_common(pairs.iter().map(|(_, id)| id)).map_or(0, |id| *id)
            } else {
                0
            };
            for ((ia, ib), id) in &pairs {
                if *id != common {
                    entries.insert(
                        vec![u128::from(*ia), u128::from(*ib)],
                        Step::write_goto(ra, *id, CONTINUE),
                    );
                }
            }
            Step::write_goto(ra, common, CONTINUE)
        };
        let n = entries.len();
        let id = self.push_level(Level {
            name: name.clone(),
            key: vec![Part::Reg(ra), Part::Reg(rb)],
            entries,
            miss,
        });
        self.stages.push(Some(id));
        self.report.push(Stage {
            name,
            classes: classes.len(),
            levels: 1,
            entries: n,
        });
        Ok(Group {
            covered,
            classes,
            reg: Some(ra),
        })
    }

    /// The classes two groups cross to, and the pairs enumerated: every pair if `dense`, else
    /// those sharing a non-core rule. Class 0 is the core's.
    fn cross(
        &mut self,
        a: &Group,
        b: &Group,
        covered: u32,
        dense: bool,
        name: &str,
    ) -> Result<(Vec<Bits>, Vec<Pair>), Refusal> {
        let core = a
            .classes
            .iter()
            .chain(&b.classes)
            .fold(vec![u64::MAX; self.words], |acc, c| and(&acc, c));
        // Rule -> the classes of `b` holding it, for rules outside the core.
        let mut holders: HashMap<usize, Vec<u32>> = HashMap::new();
        for (ib, bits) in b.classes.iter().enumerate() {
            for rule in ones(bits).filter(|&r| core[r / 64] & 1 << (r % 64) == 0) {
                holders
                    .entry(rule)
                    .or_default()
                    .push(u32::try_from(ib).unwrap_or(u32::MAX));
            }
        }
        let core_bits = self.truncate(core, covered);
        let mut ids: HashMap<Bits, u32> = HashMap::from([(core_bits.clone(), 0)]);
        let mut classes: Vec<Bits> = vec![core_bits];
        let mut pairs: Vec<Pair> = Vec::new();
        let mut seen = vec![u32::MAX; b.classes.len()];
        for (ia, ba) in a.classes.iter().enumerate() {
            let ia32 = u32::try_from(ia).unwrap_or(u32::MAX);
            // Dense: every pair. Sparse: the pairs sharing a non-core rule.
            let candidates: Vec<u32> = if dense {
                (0..u32::try_from(b.classes.len()).unwrap_or(u32::MAX)).collect()
            } else {
                let mut out = Vec::new();
                for rule in ones(ba) {
                    for &ib in holders.get(&rule).map_or(&[][..], Vec::as_slice) {
                        if seen[ib as usize] != ia32 {
                            seen[ib as usize] = ia32;
                            out.push(ib);
                        }
                    }
                }
                out
            };
            for ib in candidates {
                {
                    if pairs.len() >= self.options.max_product {
                        return Err(Refusal::Product {
                            stage: name.to_string(),
                            product: pairs.len(),
                        });
                    }
                    let bits = self.truncate(and(ba, &b.classes[ib as usize]), covered);
                    let id = *ids.entry(bits.clone()).or_insert_with(|| {
                        classes.push(bits);
                        u32::try_from(classes.len() - 1).unwrap_or(u32::MAX)
                    });
                    pairs.push(((ia32, ib), id));
                }
            }
        }
        Ok((classes, pairs))
    }

    /// After the last combination: the action, if it is constant; else, if no level ends with
    /// it yet, a level looking it up from the last group's register.
    fn finish(&mut self, last: Option<Group>) -> Option<A> {
        let all = self.all_fields();
        let group = last?;
        let Some(reg) = group.reg else {
            let bits = self.truncate(group.classes[0].clone(), all);
            return Some(self.action_of(&bits));
        };
        if self.ended {
            return None;
        }
        let actions: Vec<A> = group
            .classes
            .iter()
            .map(|c| {
                let bits = self.truncate(c.clone(), all);
                self.action_of(&bits)
            })
            .collect();
        let common =
            most_common(actions.iter()).map_or_else(|| self.table.default.clone(), Clone::clone);
        let entries = actions
            .iter()
            .enumerate()
            .filter(|(_, a)| **a != common)
            .map(|(id, a)| (vec![id as u128], Step::done(a.clone())))
            .collect();
        let id = self.push_level(Level {
            name: "action".to_string(),
            key: vec![Part::Reg(reg)],
            entries,
            miss: Step::done(common),
        });
        self.stages.push(Some(id));
        None
    }

    fn names(&self, covered: u32) -> String {
        self.table
            .fields
            .iter()
            .enumerate()
            .filter(|(f, _)| covered & 1 << f != 0)
            .map(|(_, field)| field.name)
            .collect::<Vec<_>>()
            .join("+")
    }
}

/// Disjoint aligned prefixes covering `lo..=hi` of a `width`-bit field: `(value, length)`.
#[must_use]
pub fn pieces(mut lo: u128, hi: u128, width: u8) -> Vec<(u128, u8)> {
    let mut out = Vec::new();
    loop {
        // The largest aligned block at `lo` that fits.
        let align = if lo == 0 {
            u32::from(width)
        } else {
            lo.trailing_zeros().min(u32::from(width))
        };
        let mut size_log = align;
        while size_log > 0 && (size_log >= 128 || lo + ((1u128 << size_log) - 1) > hi) {
            size_log -= 1;
        }
        let len = width - u8::try_from(size_log).unwrap_or(width);
        out.push((lo, len));
        let end = if size_log >= 128 {
            u128::MAX
        } else {
            lo + ((1u128 << size_log) - 1)
        };
        if end >= hi {
            return out;
        }
        lo = end + 1;
    }
}

/// Chain the stages: each level's `CONTINUE` goes to the next stage's first level. Returns the
/// first stages' first levels, in order.
fn chain<A>(levels: &mut [Level<A>], stages: &[Option<LevelId>]) -> Vec<LevelId> {
    let firsts: Vec<LevelId> = stages.iter().filter_map(|s| *s).collect();
    let mut owner = vec![0usize; levels.len()];
    for (k, &start) in firsts.iter().enumerate() {
        let end = firsts.get(k + 1).copied().unwrap_or(levels.len());
        for o in &mut owner[start..end] {
            *o = k;
        }
    }
    for (id, level) in levels.iter_mut().enumerate() {
        let next = firsts.get(owner[id] + 1).copied();
        for step in level
            .entries
            .values_mut()
            .chain(std::iter::once(&mut level.miss))
        {
            if matches!(step.then, Then::Goto(CONTINUE)) {
                step.then = next.map_or_else(
                    || unreachable!("the last stage ends with an action"),
                    Then::Goto,
                );
            }
        }
    }
    firsts
}

/// A plan for `table`, and what its stages came to.
///
/// # Errors
///
/// If the table is malformed, or a combination is too big.
pub fn plan<A: Clone + Eq + Hash>(
    table: &Table<A>,
    options: &Options,
) -> Result<(Plan<A>, Vec<Stage>), Refusal> {
    table.check().map_err(Refusal::Malformed)?;
    let fields: Vec<Field> = table.fields.clone();
    let mut planner = Planner {
        table,
        words: table.rules.len().div_ceil(64).max(1),
        options,
        levels: Vec::new(),
        stages: Vec::new(),
        report: Vec::new(),
        universal: HashMap::new(),
        ended: false,
    };
    let mut groups: Vec<Group> = (0..fields.len())
        .map(|f| planner.field(f, u8::try_from(f).unwrap_or(u8::MAX)))
        .collect();
    // Combine, smallest product first.
    while groups.len() > 1 {
        let mut best = (usize::MAX, 0, 1);
        for i in 0..groups.len() {
            for j in i + 1..groups.len() {
                let product = groups[i].classes.len() * groups[j].classes.len();
                if product < best.0 {
                    best = (product, i, j);
                }
            }
        }
        let b = groups.remove(best.2);
        let a = groups.remove(best.1);
        groups.push(planner.combine(&a, &b)?);
    }
    let last = groups.pop();
    let entry_action = planner.finish(last);
    let firsts = chain(&mut planner.levels, &planner.stages);
    let entry = match (entry_action, firsts.first()) {
        (Some(action), _) => Step::done(action),
        (None, Some(&start)) => Step::goto(start),
        (None, None) => Step::done(table.default.clone()),
    };
    let registers = vec![32; fields.len()];
    Ok((
        Plan {
            fields,
            levels: planner.levels,
            entry,
            registers,
        },
        planner.report,
    ))
}
