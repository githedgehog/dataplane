// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Plans mean what their tables mean: every plan is run against the first-match oracle on
//! probe keys at and around rule boundaries.

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
        let mut set = |rng: &mut Lcg, width: u8| -> Set {
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
