// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Seeded ACLs, as the hardware spike generated them (`notes/match-action-dag/spike-acl`,
//! `mkacl2.py`), for sizing plans and checking them. Fields: protocol, source and destination
//! IPv4 address, source and destination port.

use crate::rules::{Field, Rule, Set, Table};

/// An ACL verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Verdict {
    /// Let it through.
    Allow,
    /// Drop it.
    Deny,
}

/// The ACL key's fields.
pub const FIELDS: [Field; 5] = [
    Field {
        name: "proto",
        width: 8,
    },
    Field {
        name: "src",
        width: 32,
    },
    Field {
        name: "dst",
        width: 32,
    },
    Field {
        name: "sport",
        width: 16,
    },
    Field {
        name: "dport",
        width: 16,
    },
];

/// The families of the spike.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    /// Distinct /32s and single ports.
    Exact,
    /// The /24s, random overlapping port ranges.
    Ranges,
    /// Random nested prefixes /24-/32, a single destination port.
    Prefixes,
    /// An allow first, then denies with random protocols, nested prefixes and port ranges.
    Mixed,
}

/// A small deterministic generator: the same seed, the same ACL.
#[derive(Clone, Debug)]
pub struct Lcg(u64);

impl Lcg {
    /// Seeded.
    #[must_use]
    pub const fn new(seed: u64) -> Lcg {
        Lcg(seed ^ 0x9e37_79b9_7f4a_7c15)
    }

    /// The next value in `0..bound`.
    pub fn below(&mut self, bound: u64) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 17) % bound.max(1)
    }

    /// The next value in `lo..=hi`.
    pub fn between(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.below(hi - lo + 1)
    }

    /// True with probability `percent`/100.
    pub fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

const UDP: u128 = 17;
const TCP: u128 = 6;
const NET1: u128 = 0x0a00_0100; // 10.0.1.0/24
const NET2: u128 = 0x0a00_0200; // 10.0.2.0/24

fn rule(
    proto: Set,
    src: Set,
    dst: Set,
    sport: Option<Set>,
    dport: Option<Set>,
    action: Verdict,
) -> Rule<Verdict> {
    Rule {
        matches: vec![
            proto,
            src,
            dst,
            sport.unwrap_or_else(|| Set::any(16)),
            dport.unwrap_or_else(|| Set::any(16)),
        ],
        action,
    }
}

/// A random prefix /24-/32 inside `net`/24.
fn prefix(rng: &mut Lcg, net: u128) -> Set {
    let len = u8::try_from(rng.between(24, 32)).unwrap_or(32);
    let host = u128::from(rng.below(256));
    Set::prefix(net | host, len, 32)
}

/// A random port range starting in `lo..=hi`, of exponential-ish width (mean ~2000).
fn ports(rng: &mut Lcg, lo: u64, hi: u64) -> Set {
    let a = rng.between(lo, hi);
    // An exponential width without floats: a geometric sum of halving chances.
    let mut w = 1;
    while w < 16_000 && rng.chance(70) {
        w += rng.between(1, 600);
    }
    let b = (a + w).min(hi);
    Set::range(u128::from(a), u128::from(b))
}

/// An ACL of `n` rules of `family`, seeded by `(family, n, seed)`. The default is allow
/// (`deny-unless-exposed`, with traffic inside the exposes), as in the spike's sizing.
#[must_use]
pub fn acl(family: Family, n: usize, seed: u64) -> Table<Verdict> {
    let mut rng = Lcg::new(seed ^ (n as u64) << 8 ^ family as u64);
    let any_proto = || Set::any(8);
    let allow = rule(
        Set::exact(UDP),
        Set::prefix(NET1, 24, 32),
        Set::prefix(NET2, 24, 32),
        None,
        Some(Set::exact(5000)),
        Verdict::Allow,
    );
    let mut rules = Vec::with_capacity(n);
    for i in 0..n.saturating_sub(1) {
        let i = i as u128;
        rules.push(match family {
            Family::Exact => rule(
                Set::exact(UDP),
                Set::exact(NET1 | (3 + i % 250)),
                Set::exact(NET2 | 2),
                Some(Set::exact(30_000 + i % 30_000)),
                Some(Set::exact(6_000 + i % 50_000)),
                Verdict::Deny,
            ),
            Family::Ranges => rule(
                Set::exact(UDP),
                Set::prefix(NET1, 24, 32),
                Set::prefix(NET2, 24, 32),
                Some(ports(&mut rng, 2000, 65_535)),
                Some(ports(&mut rng, 5001, 65_535)),
                Verdict::Deny,
            ),
            Family::Prefixes => {
                let mut dport = rng.between(1, 65_535);
                if dport == 5000 {
                    dport += 1;
                }
                rule(
                    Set::exact(UDP),
                    prefix(&mut rng, NET1),
                    prefix(&mut rng, NET2),
                    None,
                    Some(Set::exact(u128::from(dport))),
                    Verdict::Deny,
                )
            }
            Family::Mixed => {
                let proto = match rng.below(3) {
                    0 => Some(TCP),
                    1 => Some(UDP),
                    _ => None,
                };
                let sport = (proto.is_some() && rng.chance(70)).then(|| ports(&mut rng, 1, 65_535));
                let dport = (proto.is_some() && rng.chance(70)).then(|| ports(&mut rng, 1, 65_535));
                rule(
                    proto.map_or_else(any_proto, Set::exact),
                    prefix(&mut rng, NET1),
                    prefix(&mut rng, NET2),
                    sport,
                    dport,
                    Verdict::Deny,
                )
            }
        });
    }
    if family == Family::Mixed {
        rules.insert(0, allow);
    } else {
        rules.push(allow);
    }
    Table {
        fields: FIELDS.to_vec(),
        rules,
        default: Verdict::Allow,
    }
}

/// Keys to check a plan with: mostly at or near rule boundaries, where plans go wrong, and some
/// anywhere.
pub fn probes<A>(table: &Table<A>, rng: &mut Lcg, count: usize) -> Vec<Vec<u128>> {
    let pick = |rng: &mut Lcg, set: &Set, width: u8| -> u128 {
        let ivs = set.intervals();
        let iv = ivs[usize::try_from(rng.below(ivs.len() as u64)).unwrap_or(0)];
        let max = crate::rules::max_of(width);
        match rng.below(6) {
            0 => iv.lo,
            1 => iv.hi,
            2 => iv.lo.saturating_sub(1),
            3 => iv.hi.saturating_add(1).min(max),
            4 => {
                let span = u64::try_from(iv.hi - iv.lo).unwrap_or(u64::MAX - 1);
                iv.lo + u128::from(rng.below(span.saturating_add(1)))
            }
            _ => u128::from(rng.below(u64::try_from(max).unwrap_or(u64::MAX))) & max,
        }
    };
    (0..count)
        .map(|_| {
            if table.rules.is_empty() {
                return table.fields.iter().map(|_| 0).collect();
            }
            let r = &table.rules[usize::try_from(rng.below(table.rules.len() as u64)).unwrap_or(0)];
            r.matches
                .iter()
                .zip(&table.fields)
                .map(|(set, field)| pick(rng, set, field.width))
                .collect()
        })
        .collect()
}

/// Several tenants' ACLs in one table, each behind its own VNI pair (two 24-bit exact fields
/// before [`FIELDS`]): tenant `i` is `specs[i]`, from VNI `100 + i` to VNI `200 + i`.
#[must_use]
pub fn tenants(specs: &[(Family, usize)], seed: u64) -> Table<Verdict> {
    let vni = Field {
        name: "vni",
        width: 24,
    };
    let mut fields = vec![
        Field {
            name: "src-vni",
            ..vni
        },
        Field {
            name: "dst-vni",
            ..vni
        },
    ];
    fields.extend(FIELDS);
    let mut rules = Vec::new();
    for (n_th, &(family, n)) in specs.iter().enumerate() {
        let i = n_th as u128;
        for rule in acl(family, n, seed + n_th as u64).rules {
            let mut matches = vec![Set::exact(100 + i), Set::exact(200 + i)];
            matches.extend(rule.matches);
            rules.push(Rule {
                matches,
                action: rule.action,
            });
        }
    }
    Table {
        fields,
        rules,
        default: Verdict::Allow,
    }
}
