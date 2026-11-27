// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What the planner compiles: a first-match table over fixed-width fields.
//!
//! Each field of a rule is a set of values, as sorted disjoint intervals. Exact values, prefixes,
//! port ranges and small masks (protocol, TCP flags) are all such sets, so the planner sees one
//! kind of constraint. The table's meaning is first match: the action of the first rule whose
//! every field holds the packet's value, else the default. Every plan must mean the same
//! ([`Table::first_match`] is the oracle).

use std::fmt;

/// Values `lo..=hi` of a field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Interval {
    /// The first value.
    pub lo: u128,
    /// The last value.
    pub hi: u128,
}

/// A set of values of a field: sorted, disjoint, non-adjacent intervals.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Set(Vec<Interval>);

/// The largest value of a `width`-bit field.
#[must_use]
pub const fn max_of(width: u8) -> u128 {
    if width >= 128 {
        u128::MAX
    } else {
        (1 << width) - 1
    }
}

impl Set {
    /// Every value of a `width`-bit field.
    #[must_use]
    pub fn any(width: u8) -> Set {
        Set(vec![Interval {
            lo: 0,
            hi: max_of(width),
        }])
    }

    /// One value.
    #[must_use]
    pub fn exact(value: u128) -> Set {
        Set(vec![Interval {
            lo: value,
            hi: value,
        }])
    }

    /// `lo..=hi`.
    ///
    /// # Panics
    ///
    /// If `lo > hi`.
    #[must_use]
    pub fn range(lo: u128, hi: u128) -> Set {
        assert!(lo <= hi, "an empty range {lo}..={hi}");
        Set(vec![Interval { lo, hi }])
    }

    /// The values of a `width`-bit field whose top `len` bits are `value`'s.
    #[must_use]
    pub fn prefix(value: u128, len: u8, width: u8) -> Set {
        let host = max_of(width - len.min(width));
        let lo = value & max_of(width) & !host;
        Set(vec![Interval { lo, hi: lo | host }])
    }

    /// The values `v` of a `width`-bit field with `v & mask == value & mask`, enumerated: for
    /// narrow fields (protocol, TCP flags).
    ///
    /// # Panics
    ///
    /// If the field is wider than 16 bits.
    #[must_use]
    pub fn masked(value: u128, mask: u128, width: u8) -> Set {
        assert!(width <= 16, "masks are enumerated, so narrow fields only");
        Set::from_values((0..=max_of(width)).filter(|v| v & mask == value & mask))
    }

    /// The set of sorted `values`.
    fn from_values(values: impl IntoIterator<Item = u128>) -> Set {
        let mut out: Vec<Interval> = Vec::new();
        for v in values {
            match out.last_mut() {
                Some(last) if last.hi.checked_add(1) == Some(v) => last.hi = v,
                _ => out.push(Interval { lo: v, hi: v }),
            }
        }
        Set(out)
    }

    /// Whether `value` is in the set.
    #[must_use]
    pub fn contains(&self, value: u128) -> bool {
        // Sorted and disjoint: the last interval starting at or before `value`.
        let i = self.0.partition_point(|iv| iv.lo <= value);
        i > 0 && self.0[i - 1].hi >= value
    }

    /// Whether the set holds every value of a `width`-bit field.
    #[must_use]
    pub fn is_any(&self, width: u8) -> bool {
        self.0.len() == 1 && self.0[0].lo == 0 && self.0[0].hi == max_of(width)
    }

    /// The intervals.
    #[must_use]
    pub fn intervals(&self) -> &[Interval] {
        &self.0
    }
}

/// A field of the key: its name and width in bits (at most 128).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field {
    /// For display.
    pub name: &'static str,
    /// Width in bits.
    pub width: u8,
}

/// A rule: a set per field, and what to do with a packet that is in all of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule<A> {
    /// One set per field of the table, in order.
    pub matches: Vec<Set>,
    /// The action.
    pub action: A,
}

impl<A> Rule<A> {
    /// Whether the rule holds for `key` (one value per field).
    #[must_use]
    pub fn holds(&self, key: &[u128]) -> bool {
        self.matches
            .iter()
            .zip(key)
            .all(|(set, &v)| set.contains(v))
    }
}

/// A first-match table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table<A> {
    /// The key's fields.
    pub fields: Vec<Field>,
    /// The rules, in priority order.
    pub rules: Vec<Rule<A>>,
    /// The action when no rule holds.
    pub default: A,
}

impl<A> Table<A> {
    /// The oracle: the first rule's action that holds for `key`, else the default.
    #[must_use]
    pub fn first_match(&self, key: &[u128]) -> &A {
        self.rules
            .iter()
            .find(|r| r.holds(key))
            .map_or(&self.default, |r| &r.action)
    }

    /// Check the table is well-formed: one set per field, each within its field's width.
    ///
    /// # Errors
    ///
    /// The first rule that isn't, and why.
    pub fn check(&self) -> Result<(), String> {
        for (n, rule) in self.rules.iter().enumerate() {
            if rule.matches.len() != self.fields.len() {
                return Err(format!(
                    "rule {n}: {} sets for {} fields",
                    rule.matches.len(),
                    self.fields.len()
                ));
            }
            for (set, field) in rule.matches.iter().zip(&self.fields) {
                let too_wide = set.0.iter().any(|iv| iv.hi > max_of(field.width));
                let unsorted = set.0.windows(2).any(|w| w[0].hi >= w[1].lo);
                if set.0.is_empty() || too_wide || unsorted {
                    return Err(format!("rule {n}: field {}: {set}", field.name));
                }
            }
        }
        Ok(())
    }
}

impl fmt::Display for Set {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, iv) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, ",")?;
            }
            if iv.lo == iv.hi {
                write!(f, "{:#x}", iv.lo)?;
            } else {
                write!(f, "{:#x}-{:#x}", iv.lo, iv.hi)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sets() {
        let p = Set::prefix(0x0a00_0100, 24, 32);
        assert!(p.contains(0x0a00_01ff) && !p.contains(0x0a00_0200));
        assert!(Set::any(16).is_any(16));
        assert_eq!(Set::prefix(0xdead, 0, 16), Set::any(16));
        // TCP SYN set, ACK clear, others anything.
        let flags = Set::masked(0x02, 0x12, 8);
        assert!(flags.contains(0x02) && flags.contains(0x03) && !flags.contains(0x12));
        assert_eq!(flags.intervals().len(), 32); // 64 values; bit 0 free pairs them
        assert!(Set::range(5, 9).contains(9) && !Set::range(5, 9).contains(10));
    }
}
