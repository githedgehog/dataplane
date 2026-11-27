// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Plans mean what their tables mean: every plan is run against the first-match oracle on
//! probe keys at and around rule boundaries.
//!
//! Memory: the suite peaks at about 0.4 GB, the ignored measurements under 2 GB, against CI's
//! 20 GiB for the whole test suite. Plans are bounded by [`crate::rfc::Options::max_entries`].
//! Run measurements as CI would bound them, so a runaway is killed rather than the machine:
//!
//! ```text
//! systemd-run --user --scope -p MemoryMax=20G -p MemorySwapMax=0 -- \
//!     cargo test -p dataplane-planner --release sizes -- --ignored --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::generate::{Family, Lcg, Verdict, acl, probes};
use crate::rfc::{Options, pieces, plan};
use crate::rules::{Field, Rule, Set, Table};

fn check(table: &Table<Verdict>, probes_n: usize) -> usize {
    let (plan, _) = plan(table, &Options::default()).expect("a plan");
    let mut rng = Lcg::new(7);
    let mut bad = 0;
    for key in probes(table, &mut rng, probes_n) {
        let want = *table.first_match(&key);
        let got = plan.run(&key).action;
        if want != got {
            bad += 1;
            if bad < 5 {
                eprintln!("key {key:x?}: want {want:?}, got {got:?}");
            }
        }
    }
    bad
}

#[test]
fn pieces_cover_exactly() {
    for (lo, hi) in [
        (0u128, 65_535u128),
        (1, 1),
        (5, 17),
        (1024, 65_535),
        (0, 0),
        (65_535, 65_535),
    ] {
        let ps = pieces(lo, hi, 16);
        let mut at = lo;
        for (v, len) in &ps {
            assert_eq!(*v, at, "{lo}-{hi}: {ps:?}");
            at = v + (1u128 << (16 - len));
        }
        assert_eq!(at, hi + 1, "{lo}-{hi}: {ps:?}");
    }
}

#[test]
fn small_tables_plan_exactly() {
    let fields = vec![
        Field {
            name: "a",
            width: 8,
        },
        Field {
            name: "b",
            width: 32,
        },
    ];
    let table = Table {
        fields,
        rules: vec![
            Rule {
                matches: vec![Set::range(10, 20), Set::prefix(0x0a00_0000, 8, 32)],
                action: Verdict::Deny,
            },
            Rule {
                matches: vec![Set::any(8), Set::prefix(0x0a01_0000, 16, 32)],
                action: Verdict::Allow,
            },
            Rule {
                matches: vec![Set::exact(15), Set::any(32)],
                action: Verdict::Deny,
            },
        ],
        default: Verdict::Allow,
    };
    assert_eq!(check(&table, 20_000), 0);
}

#[test]
fn spike_families_plan_exactly() {
    for family in [
        Family::Exact,
        Family::Prefixes,
        Family::Ranges,
        Family::Mixed,
    ] {
        for n in [10, 100] {
            let table = acl(family, n, 1);
            assert_eq!(check(&table, 20_000), 0, "{family:?} {n}");
        }
    }
}

/// Sizes of plans for the spike's families, against the spike's Python numbers. Run with
/// `cargo test -p dataplane-planner --release sizes -- --ignored --nocapture`.
#[test]
#[ignore = "a measurement"]
fn sizes() {
    for family in [
        Family::Exact,
        Family::Prefixes,
        Family::Ranges,
        Family::Mixed,
    ] {
        for n in [100, 1000, 10_000] {
            let table = acl(family, n, 1);
            let started = std::time::Instant::now();
            match plan(&table, &Options::default()) {
                Ok((plan, stages)) => {
                    let bad = check(&table, 20_000);
                    eprintln!(
                        "{family:?} {n}: levels={} worst={:?} entries={} in {:?}; mismatches={bad}",
                        plan.levels.len(),
                        plan.worst_path(),
                        plan.entries(),
                        started.elapsed()
                    );
                    for s in stages {
                        eprintln!(
                            "    {:<24} classes={:<7} levels={} entries={}",
                            s.name, s.classes, s.levels, s.entries
                        );
                    }
                }
                Err(e) => eprintln!("{family:?} {n}: refused: {e:?}"),
            }
        }
    }
}

/// Random small tables: any mix of exact values, prefixes, ranges and masks over fields of
/// different widths, rules overlapping with either verdict. Each must plan exactly, dense and
/// sparse alike.
#[test]
fn random_tables_plan_exactly() {
    let widths = [8u8, 16, 32];
    for seed in 0..400u64 {
        let mut rng = Lcg::new(seed);
        let fields: Vec<Field> = widths
            .iter()
            .map(|&width| Field { name: "f", width })
            .collect();
        let set = |rng: &mut Lcg, width: u8| -> Set {
            let max = crate::rules::max_of(width);
            let v =
                |rng: &mut Lcg| u128::from(rng.below(u64::try_from(max).unwrap_or(u64::MAX))) & max;
            match rng.below(5) {
                0 => Set::any(width),
                1 => Set::exact(v(rng)),
                2 => Set::prefix(
                    v(rng),
                    u8::try_from(rng.below(u64::from(width) + 1)).unwrap_or(0),
                    width,
                ),
                3 => {
                    let (a, b) = (v(rng), v(rng));
                    Set::range(a.min(b), a.max(b))
                }
                _ if width <= 16 => Set::masked(v(rng), v(rng), width),
                _ => Set::any(width),
            }
        };
        let n = usize::try_from(rng.between(0, 12)).unwrap_or(0);
        let rules = (0..n)
            .map(|_| Rule {
                matches: widths.iter().map(|&w| set(&mut rng, w)).collect(),
                action: if rng.chance(50) {
                    Verdict::Allow
                } else {
                    Verdict::Deny
                },
            })
            .collect();
        let table = Table {
            fields,
            rules,
            default: if rng.chance(50) {
                Verdict::Allow
            } else {
                Verdict::Deny
            },
        };
        for dense in [usize::MAX, 0] {
            let options = Options {
                dense,
                expand: 1 << 12,
                fuse: true,
                ..Options::default()
            };
            let (plan, _) = plan(&table, &options).expect("a plan");
            let mut probe_rng = Lcg::new(seed + 1);
            for key in probes(&table, &mut probe_rng, 2_000) {
                assert_eq!(
                    plan.run(&key).action,
                    *table.first_match(&key),
                    "seed {seed}, dense {dense}, key {key:x?}"
                );
            }
            assert!(plan.worst_path().is_some(), "seed {seed}: the plan loops");
        }
    }
}

mod guarded {
    use crate::backend::{Backend, Mlx5, Software, closed};
    use crate::generate::{Family, Lcg, Verdict, probes, tenants};
    use crate::guard::{Placed, plan};
    use crate::rfc::Options;

    const GUARD: [usize; 2] = [0, 1];

    /// Every packet of a tenant planned here gets the table's action; every packet of a tenant
    /// that fell back goes to software.
    fn check<B: Backend>(specs: &[(Family, usize)], backend: &B) -> (usize, usize) {
        let table = tenants(specs, 3);
        let guarded = plan(&table, &GUARD, backend, &Options::default()).expect("a plan");
        assert!(closed(&guarded.plan));
        let software: Vec<Vec<u128>> = guarded
            .tenants
            .iter()
            .filter(|t| t.outcome.is_err())
            .filter_map(|t| t.key.clone())
            .collect();
        let listed: Vec<Vec<u128>> = guarded
            .tenants
            .iter()
            .filter_map(|t| t.key.clone())
            .collect();
        let unlisted_software = guarded
            .tenants
            .iter()
            .any(|t| t.key.is_none() && t.outcome.is_err());
        for key in probes(&table, &mut Lcg::new(11), 20_000) {
            let got = guarded.plan.run(&key).action;
            let guard = key[..2].to_vec();
            if software.contains(&guard) || (unlisted_software && !listed.contains(&guard)) {
                assert_eq!(got, Placed::Software, "key {key:x?}");
            } else {
                assert_eq!(got, Placed::Here(*table.first_match(&key)), "key {key:x?}");
            }
        }
        let here = guarded.tenants.iter().filter(|t| t.outcome.is_ok()).count();
        (here, guarded.tenants.len() - here)
    }

    #[test]
    fn tenants_plan_exactly_or_fall_back_alone() {
        let specs = [
            (Family::Exact, 30),
            (Family::Mixed, 60),
            (Family::Ranges, 40),
            (Family::Prefixes, 50),
        ];
        // Software takes every plan.
        let (here, software) = check(&specs, &Software);
        assert_eq!(software, 0);
        assert_eq!(here, specs.len() + 1);
        // A budget of 3 tables: the tenants that need more fall back, and only they.
        let tight = Mlx5 {
            tables_per_packet: 3,
            ..Mlx5::at(44e6)
        };
        let (here, software) = check(&specs, &tight);
        assert!(software > 0 && here > 0, "here={here} software={software}");
    }

    /// Many ordinary tenants and two pathological ones, at two design points. Run with
    /// `cargo test -p dataplane-planner --release guarded_sizes -- --ignored --nocapture`.
    #[test]
    #[ignore = "a measurement"]
    fn guarded_sizes() {
        let mut specs = vec![(Family::Exact, 100); 40];
        specs.extend([(Family::Prefixes, 100); 40]);
        specs.extend([(Family::Mixed, 100); 20]);
        specs.push((Family::Mixed, 10_000));
        specs.push((Family::Ranges, 10_000));
        let table = tenants(&specs, 5);
        for (name, backend) in [("120 Mpps", Mlx5::at(120e6)), ("44 Mpps", Mlx5::at(44e6))] {
            let started = std::time::Instant::now();
            let guarded = plan(&table, &GUARD, &backend, &Options::default()).expect("a plan");
            let here: Vec<_> = guarded
                .tenants
                .iter()
                .filter(|t| t.outcome.is_ok())
                .collect();
            let worst = here
                .iter()
                .filter_map(|t| t.outcome.as_ref().ok().map(|c| c.worst_path))
                .max();
            eprintln!(
                "{name} (budget {} tables): {} tenants, {} in NIC, worst path {:?} (+1 guard), entries {}, in {:?}",
                backend.tables_per_packet,
                guarded.tenants.len(),
                here.len(),
                worst,
                guarded.plan.entries(),
                started.elapsed()
            );
            for t in guarded.tenants.iter().filter(|t| t.outcome.is_err()) {
                eprintln!(
                    "    software: {:?} ({} rules): {:?}",
                    t.key, t.rules, t.outcome
                );
            }
            let mut rng = Lcg::new(1);
            let mismatches = probes(&table, &mut rng, 20_000)
                .iter()
                .filter(|key| match guarded.plan.run(key).action {
                    Placed::Here(a) => a != *table.first_match(key),
                    Placed::Software => false,
                })
                .count();
            eprintln!("    mismatches: {mismatches}");
            let _ = Verdict::Allow;
        }
    }
}

/// How big the join is for the mixed family, uncapped. Run with
/// `cargo test -p dataplane-planner --release mixed_join -- --ignored --nocapture`.
#[test]
#[ignore = "a measurement"]
fn mixed_join() {
    for n in [100, 1000] {
        let table = acl(Family::Mixed, n, 1);
        let options = Options {
            max_product: 400_000_000,
            ..Options::default()
        };
        let started = std::time::Instant::now();
        match plan(&table, &options) {
            Ok((plan, stages)) => {
                eprintln!(
                    "mixed {n}: worst={:?} entries={} in {:?}",
                    plan.worst_path(),
                    plan.entries(),
                    started.elapsed()
                );
                for s in stages {
                    eprintln!(
                        "    {:<24} classes={:<7} entries={}",
                        s.name, s.classes, s.entries
                    );
                }
            }
            Err(e) => eprintln!("mixed {n}: {e:?}"),
        }
    }
}

mod shared {
    use crate::backend::{Backend, Mlx5, Software, closed};
    use crate::generate::{Family, Lcg, probes, tenants};
    use crate::guard::Placed;
    use crate::rfc::Options;
    use crate::shared::plan;

    const GUARD: [usize; 2] = [0, 1];

    fn check<B: Backend>(specs: &[(Family, usize)], backend: &B) -> (usize, usize, usize) {
        let table = tenants(specs, 3);
        let shared = plan(&table, &GUARD, backend, &Options::default()).expect("a plan");
        assert!(closed(&shared.plan));
        let software: Vec<Vec<u128>> = shared
            .tenants
            .iter()
            .filter(|t| t.outcome.is_err())
            .filter_map(|t| t.key.clone())
            .collect();
        let listed: Vec<Vec<u128>> = shared
            .tenants
            .iter()
            .filter_map(|t| t.key.clone())
            .collect();
        // Packets of no listed tenant: whether their partition fell back.
        let unlisted_software = shared
            .tenants
            .iter()
            .any(|t| t.key.is_none() && t.outcome.is_err());
        for key in probes(&table, &mut Lcg::new(11), 30_000) {
            let got = shared.plan.run(&key).action;
            let guard = key[..2].to_vec();
            if software.contains(&guard) || (unlisted_software && !listed.contains(&guard)) {
                assert_eq!(got, Placed::Software, "key {key:x?}");
            } else {
                assert_eq!(got, Placed::Here(*table.first_match(&key)), "key {key:x?}");
            }
        }
        let here = shared.tenants.iter().filter(|t| t.outcome.is_ok()).count();
        (here, shared.tenants.len() - here, shared.plan.levels.len())
    }

    #[test]
    fn tenants_share_levels_and_plan_exactly() {
        let specs = [
            (Family::Exact, 30),
            (Family::Mixed, 60),
            (Family::Ranges, 40),
            (Family::Prefixes, 50),
            (Family::Exact, 20),
        ];
        let (here, software, groups) = check(&specs, &Software);
        assert_eq!(software, 0);
        assert_eq!(here, specs.len() + 1);
        // Twice the tenants, the same levels.
        let doubled: Vec<_> = specs.iter().chain(&specs).copied().collect();
        let (_, _, more) = check(&doubled, &Software);
        assert_eq!(groups, more, "levels grew with tenants");
        // A tight budget sends whole chains to software, and only their tenants.
        let tight = Mlx5 {
            tables_per_packet: 4,
            ..Mlx5::at(44e6)
        };
        let _ = check(&specs, &tight);
    }

    /// The multi-tenant measurement of `guarded_sizes`, shared. Run with
    /// `cargo test -p dataplane-planner --release shared_sizes -- --ignored --nocapture`.
    #[test]
    #[ignore = "a measurement"]
    fn shared_sizes() {
        let mut specs = vec![(Family::Exact, 100); 40];
        specs.extend([(Family::Prefixes, 100); 40]);
        specs.extend([(Family::Mixed, 100); 20]);
        specs.push((Family::Mixed, 10_000));
        specs.push((Family::Ranges, 10_000));
        let table = tenants(&specs, 5);
        for (name, backend) in [("120 Mpps", Mlx5::at(120e6)), ("44 Mpps", Mlx5::at(44e6))] {
            let started = std::time::Instant::now();
            let shared = plan(&table, &GUARD, &backend, &Options::default()).expect("a plan");
            let here = shared.tenants.iter().filter(|t| t.outcome.is_ok()).count();
            eprintln!(
                "{name} (budget {} tables, {} groups): {} tenants, {here} in NIC, {} levels in all, entries {}, in {:?}",
                backend.tables_per_packet,
                backend.groups,
                shared.tenants.len(),
                shared.plan.levels.len(),
                shared.plan.entries(),
                started.elapsed()
            );
            for (chain, n, cost) in &shared.chains {
                eprintln!(
                    "    chain {chain}: {n} tenants: {:?}",
                    cost.as_ref()
                        .map(|c| (c.worst_path, c.groups, c.entries, c.largest_level))
                );
            }
            let mut fallbacks = std::collections::BTreeMap::<String, usize>::new();
            for t in shared.tenants.iter().filter(|t| t.outcome.is_err()) {
                let why = format!("{:?}", t.outcome.as_ref().err());
                *fallbacks.entry(why.chars().take(90).collect()).or_default() += 1;
            }
            for (why, n) in fallbacks {
                eprintln!("    software x{n}: {why}");
            }
            let mut rng = Lcg::new(1);
            let mismatches = probes(&table, &mut rng, 30_000)
                .iter()
                .filter(|key| match shared.plan.run(key).action {
                    Placed::Here(a) => a != *table.first_match(key),
                    Placed::Software => false,
                })
                .count();
            eprintln!("    mismatches: {mismatches}");
        }
    }
}

mod banks {
    use crate::backend::{Backend, Mlx5, Software, closed};
    use crate::banks::merge;
    use crate::generate::{Family, Lcg, probes, tenants};
    use crate::guard::Placed;
    use crate::rfc::Options;
    use crate::rules::Table;
    use crate::shared::plan;

    const GUARD: [usize; 2] = [0, 1];

    /// `old` and `new` merged: bank 0 means what `old` means, bank 1 what `new` means, on probes
    /// of both tables.
    fn check<B: Backend>(
        old: &Table<crate::generate::Verdict>,
        new: &Table<crate::generate::Verdict>,
        backend: &B,
    ) -> crate::banks::TwoBank<Placed<crate::generate::Verdict>> {
        let a = plan(old, &GUARD, backend, &Options::default())
            .expect("a plan")
            .plan;
        let b = plan(new, &GUARD, backend, &Options::default())
            .expect("a plan")
            .plan;
        let two = merge(&a, &b);
        assert!(closed(&two.plan));
        let mut rng = Lcg::new(5);
        let keys = probes(old, &mut rng, 15_000)
            .into_iter()
            .chain(probes(new, &mut rng, 15_000));
        for key in keys {
            for (bank, plan) in [(0, &a), (1, &b)] {
                let mut banked = key.clone();
                banked.push(bank);
                assert_eq!(
                    two.plan.run(&banked).action,
                    plan.run(&key).action,
                    "bank {bank}, key {key:x?}"
                );
            }
        }
        two
    }

    fn specs() -> Vec<(Family, usize)> {
        vec![
            (Family::Exact, 30),
            (Family::Mixed, 60),
            (Family::Ranges, 40),
            (Family::Prefixes, 50),
            (Family::Exact, 20),
        ]
    }

    #[test]
    fn each_bank_means_its_generation() {
        let old = tenants(&specs(), 3);
        // Nothing changed: everything shared, no dispatch.
        let same = check(&old, &old, &Software);
        assert_eq!(same.copied, 0);
        assert_eq!(same.dispatches, 0);
        // One tenant's ACL changed.
        let mut changed = specs();
        changed[3] = (Family::Prefixes, 55);
        let new = tenants(&changed, 3);
        let two = check(&old, &new, &Software);
        assert!(two.copied > 0);
        // A tenant added.
        let mut more = specs();
        more.push((Family::Exact, 25));
        let _ = check(&old, &tenants(&more, 3), &Software);
        // Under a budget, too (tenants falling back in either generation).
        let tight = Mlx5 {
            tables_per_packet: 4,
            ..Mlx5::at(44e6)
        };
        let _ = check(&old, &new, &tight);
    }

    /// What updates copy, on the 103-tenant set at 44 Mpps. Run with
    /// `cargo test -p dataplane-planner --release bank_sizes -- --ignored --nocapture`.
    #[test]
    #[ignore = "a measurement"]
    fn bank_sizes() {
        let mut specs = vec![(Family::Exact, 100); 40];
        specs.extend([(Family::Prefixes, 100); 40]);
        specs.extend([(Family::Mixed, 100); 20]);
        specs.push((Family::Mixed, 10_000));
        specs.push((Family::Ranges, 10_000));
        let backend = Mlx5::at(44e6);
        let old = tenants(&specs, 5);
        let base = plan(&old, &GUARD, &backend, &Options::default())
            .expect("a plan")
            .plan;
        let mut cases: Vec<(&str, Vec<(Family, usize)>)> = Vec::new();
        let mut one = specs.clone();
        one[3] = (Family::Exact, 101);
        cases.push(("one exact tenant edited", one));
        let mut mixed = specs.clone();
        mixed[85] = (Family::Mixed, 101);
        cases.push(("one mixed tenant edited", mixed));
        let mut added = specs.clone();
        added.push((Family::Exact, 100));
        cases.push(("a tenant added", added));
        for (name, changed) in cases {
            let new = tenants(&changed, 5);
            let next = plan(&new, &GUARD, &backend, &Options::default())
                .expect("a plan")
                .plan;
            let two = merge(&base, &next);
            let both: usize = two.plan.entries();
            eprintln!(
                "{name}: levels {} + {} -> {} ({} shared, {} copied, {} dispatches); entries {} + {} -> {}; worst path {:?}",
                base.levels.len(),
                next.levels.len(),
                two.plan.levels.len(),
                two.shared,
                two.copied,
                two.dispatches,
                base.entries(),
                next.entries(),
                both,
                two.plan.worst_path(),
            );
            let fits = backend.assess(&two.plan);
            eprintln!(
                "    as one plan on mlx5: {:?}",
                fits.map(|c| (c.groups, c.worst_path))
            );
        }
    }
}

mod versioned {
    use crate::backend::{Backend, Mlx5, Software, closed};
    use crate::generate::{Family, Lcg, Verdict, probes, tenants};
    use crate::guard::{Placed, Tenant};
    use crate::rfc::Options;
    use crate::rules::Table;
    use crate::shared::{generations, plan};

    const GUARD: [usize; 2] = [0, 1];

    /// What generation `table`'s plan must do with `key`, given its tenants' outcomes.
    fn expect(table: &Table<Verdict>, tenants: &[Tenant], key: &[u128]) -> Placed<Verdict> {
        let guard = key[..2].to_vec();
        let mine = tenants
            .iter()
            .find(|t| t.key.as_ref() == Some(&guard))
            .or_else(|| tenants.iter().find(|t| t.key.is_none()));
        match mine {
            Some(t) if t.outcome.is_err() => Placed::Software,
            _ => Placed::Here(*table.first_match(key)),
        }
    }

    fn check<B: Backend>(old: &Table<Verdict>, new: &Table<Verdict>, backend: &B) -> usize {
        let v = generations(old, new, &GUARD, backend, &Options::default()).expect("a plan");
        assert!(closed(&v.plan));
        let mut rng = Lcg::new(9);
        let keys = probes(old, &mut rng, 15_000)
            .into_iter()
            .chain(probes(new, &mut rng, 15_000));
        for key in keys {
            for (bank, table) in [(0u128, old), (1, new)] {
                let mut banked = key.clone();
                banked.push(bank);
                assert_eq!(
                    v.plan.run(&banked).action,
                    expect(table, &v.tenants[usize::from(bank == 1)], &key),
                    "bank {bank}, key {key:x?}"
                );
            }
        }
        v.fresh
    }

    fn specs() -> Vec<(Family, usize)> {
        vec![
            (Family::Exact, 30),
            (Family::Mixed, 60),
            (Family::Ranges, 40),
            (Family::Prefixes, 50),
            (Family::Exact, 20),
        ]
    }

    #[test]
    fn each_bank_means_its_generation_by_tenant_id() {
        let old = tenants(&specs(), 3);
        assert_eq!(
            check(&old, &old, &Software),
            0,
            "nothing changed, nothing fresh"
        );
        let mut edited = specs();
        edited[3] = (Family::Prefixes, 55);
        assert_eq!(check(&old, &tenants(&edited, 3), &Software), 1);
        let mut added = specs();
        added.push((Family::Exact, 25));
        assert!(check(&old, &tenants(&added, 3), &Software) >= 1);
        let removed: Vec<_> = specs()[..3].to_vec();
        let _ = check(&old, &tenants(&removed, 3), &Software);
        let tight = Mlx5 {
            tables_per_packet: 5,
            ..Mlx5::at(44e6)
        };
        let _ = check(&old, &tenants(&edited, 3), &tight);
    }

    /// Generation after generation through the planner's state: each step's two banks mean
    /// their generations, unchanged tenants keep their ids, and only new or changed ones take
    /// fresh ids (the lowest the live generation doesn't use).
    #[test]
    fn state_keeps_ids_across_generations() {
        // Each step: the tenants, and how many of them are new or changed.
        type Spec = Vec<(usize, Family, usize)>;
        use crate::generate::tenants_at;
        use crate::shared::State;
        let mut state = State::new(&GUARD);
        let mut specs: Vec<(usize, Family, usize)> = specs()
            .into_iter()
            .enumerate()
            .map(|(i, (f, n))| (i, f, n))
            .collect();
        let mut steps: Vec<(Spec, usize)> = vec![(specs.clone(), 0)];
        specs[3].2 = 55;
        steps.push((specs.clone(), 1));
        specs.push((7, Family::Exact, 25));
        steps.push((specs.clone(), 1));
        specs.remove(1);
        specs[0].2 = 31;
        steps.push((specs.clone(), 1));
        steps.push((specs.clone(), 0));
        let mut previous: Option<(Table<Verdict>, crate::shared::TenantIds)> = None;
        for (n, (spec, fresh)) in steps.iter().enumerate() {
            let table = tenants_at(spec, 3);
            let next = state
                .next(&table, &Software, &Options::default())
                .expect("a plan");
            assert!(closed(&next.versioned.plan));
            if n > 0 {
                assert_eq!(next.versioned.fresh, *fresh, "step {n}");
            }
            let old = previous.as_ref().map_or(&table, |(t, _)| t);
            let mut rng = Lcg::new(9 + n as u64);
            let keys = probes(old, &mut rng, 8_000)
                .into_iter()
                .chain(probes(&table, &mut rng, 8_000));
            for key in keys {
                for (bank, t) in [(0u128, old), (1, &table)] {
                    let mut banked = key.clone();
                    banked.push(bank);
                    assert_eq!(
                        next.versioned.plan.run(&banked).action,
                        expect(t, &next.versioned.tenants[usize::from(bank == 1)], &key),
                        "step {n}, bank {bank}, key {key:x?}"
                    );
                }
            }
            // An unchanged tenant (same guard values, same rules) keeps its id.
            if let Some((old_table, old_ids)) = &previous {
                let po = crate::guard::partition(old_table, &GUARD).expect("split");
                let pn = crate::guard::partition(&table, &GUARD).expect("split");
                for ((key, sub), (_, id)) in pn.tenants.iter().zip(&next.ids) {
                    let before = po.tenants.iter().position(|(k, t)| k == key && t == sub);
                    if let Some(i) = before {
                        assert_eq!(old_ids[i].1, *id, "step {n}: tenant {key:?} moved");
                    }
                }
            }
            assert!(!next.relayout, "step {n}: the layout changed");
            previous = Some((table, next.ids.clone()));
        }
    }

    /// What updates cost when versioned by tenant id, on the 103-tenant set at 44 Mpps. Run with
    /// `cargo test -p dataplane-planner --release versioned_sizes -- --ignored --nocapture`.
    #[test]
    #[ignore = "a measurement"]
    fn versioned_sizes() {
        let mut specs = vec![(Family::Exact, 100); 40];
        specs.extend([(Family::Prefixes, 100); 40]);
        specs.extend([(Family::Mixed, 100); 20]);
        specs.push((Family::Mixed, 10_000));
        specs.push((Family::Ranges, 10_000));
        let backend = Mlx5::at(44e6);
        let old = tenants(&specs, 5);
        let alone = plan(&old, &GUARD, &backend, &Options::default())
            .expect("a plan")
            .plan;
        let mut cases: Vec<(&str, Vec<(Family, usize)>)> = Vec::new();
        let mut one = specs.clone();
        one[3] = (Family::Exact, 101);
        cases.push(("one exact tenant edited", one));
        let mut mixed = specs.clone();
        mixed[85] = (Family::Mixed, 101);
        cases.push(("one mixed tenant edited", mixed));
        let mut added = specs.clone();
        added.push((Family::Exact, 100));
        cases.push(("a tenant added", added));
        for (name, changed) in cases {
            let new = tenants(&changed, 5);
            let v = generations(&old, &new, &GUARD, &backend, &Options::default()).expect("a plan");
            let here = |b: usize| v.tenants[b].iter().filter(|t| t.outcome.is_ok()).count();
            eprintln!(
                "{name}: fresh tenants {}; levels {} (alone {}); entries {} (alone {}, +{}); worst path {:?}; in NIC {} -> {}",
                v.fresh,
                v.plan.levels.len(),
                alone.levels.len(),
                v.plan.entries(),
                alone.entries(),
                v.plan.entries().saturating_sub(alone.entries()),
                v.plan.worst_path(),
                here(0),
                here(1),
            );
            eprintln!(
                "    as one plan on mlx5: {:?}",
                backend
                    .assess(&v.plan)
                    .map(|c| (c.groups, c.worst_path, c.largest_level))
            );
        }
    }
}

/// How much of the planning cost is port ranges: the range-bearing families replanned with each
/// port range replaced by its first port (`exact`) or by any port (`any`), everything else kept.
/// The variants mean other things than the originals; each is checked against its own first
/// match. Run with
/// `cargo test -p dataplane-planner --release port_ranges -- --ignored --nocapture`.
#[test]
#[ignore = "a measurement"]
fn port_ranges() {
    use crate::rules::Set;
    #[derive(Clone, Copy, Debug)]
    enum Ports {
        Ranges,
        Exact,
        Any,
    }
    let variant = |table: &Table<Verdict>, ports: Ports| -> Table<Verdict> {
        let mut t = table.clone();
        for rule in &mut t.rules {
            for f in [3, 4] {
                let set = &rule.matches[f];
                if set.is_any(16) || set.intervals().len() != 1 {
                    continue;
                }
                let iv = set.intervals()[0];
                if iv.lo == iv.hi {
                    continue;
                }
                rule.matches[f] = match ports {
                    Ports::Ranges => set.clone(),
                    Ports::Exact => Set::exact(iv.lo),
                    Ports::Any => Set::any(16),
                };
            }
        }
        t
    };
    for family in [Family::Ranges, Family::Mixed] {
        for n in [100, 1000, 10_000] {
            let base = acl(family, n, 1);
            for ports in [Ports::Ranges, Ports::Exact, Ports::Any] {
                let table = variant(&base, ports);
                let started = std::time::Instant::now();
                match plan(&table, &Options::default()) {
                    Ok((p, stages)) => {
                        let joined = stages.iter().any(|s| s.name == "join");
                        let classes: Vec<String> = stages
                            .iter()
                            .filter(|s| s.name != "join")
                            .map(|s| format!("{}={}", s.name, s.classes))
                            .collect();
                        eprintln!(
                            "{family:?} {n} {ports:?}: worst={:?} entries={} join={joined} in {:?}; mismatches={}\n    classes: {}",
                            p.worst_path(),
                            p.entries(),
                            started.elapsed(),
                            check(&table, 10_000),
                            classes.join(" ")
                        );
                    }
                    Err(e) => eprintln!("{family:?} {n} {ports:?}: refused: {e:?}"),
                }
            }
        }
    }
}
