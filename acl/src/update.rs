// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Two-phase update planning for ACL tables.
//!
//! Implements the Reitblatt two-phase update `[reitblatt2012]` in
//! software: diff old vs new table, build a delta classifier for
//! changed rules, compose a two-tier Cascade, and plan background
//! recompilation of the full merged table.
//!
//! The update is per-packet consistent: every packet sees either
//! the complete old rule set or the complete new rule set, never
//! a mix.

use crate::action::ActionSequence;
use crate::classifier::Classifier;
use crate::metadata::Metadata;
use crate::priority::Priority;
use crate::rule::AclRule;
use crate::table::AclTable;

/// The diff between two ACL tables.
///
/// Rules are matched by [`Priority`]  --  priority is the rule's
/// identity from the user's perspective.
#[derive(Debug, Clone)]
pub struct TableDiff<M: Metadata> {
    /// Rules present in the new table but not the old (new priorities).
    pub added: Vec<AclRule<M>>,
    /// Indices (in the old table) of rules removed in the new table.
    pub removed: Vec<usize>,
    /// Rules whose priority exists in both tables but whose match
    /// fields or actions changed.  `(old_index, new_rule)`.
    pub modified: Vec<(usize, AclRule<M>)>,
}

impl<M: Metadata> TableDiff<M> {
    /// Total number of changes.
    #[must_use]
    pub fn change_count(&self) -> usize {
        self.added.len() + self.removed.len() + self.modified.len()
    }

    /// Whether the tables are identical (no changes).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.change_count() == 0
    }
}

/// Diff two ACL tables by priority.
///
/// Rules are matched by [`Priority`].  A rule in the new table with a
/// priority not in the old table is "added."  A rule in the old table
/// with a priority not in the new table is "removed."  A rule with the
/// same priority but different match fields or actions is "modified."
#[must_use]
pub fn diff_tables<M: Metadata + Clone + PartialEq>(
    old: &AclTable<M>,
    new: &AclTable<M>,
) -> TableDiff<M> {
    use std::collections::HashMap;

    // Index old rules by priority.
    let old_by_priority: HashMap<Priority, (usize, &AclRule<M>)> = old
        .rules()
        .iter()
        .enumerate()
        .map(|(i, r)| (r.priority(), (i, r)))
        .collect();

    // Index new rules by priority.
    let new_by_priority: HashMap<Priority, &AclRule<M>> = new
        .rules()
        .iter()
        .map(|r| (r.priority(), r))
        .collect();

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut modified = Vec::new();

    // Find added and modified rules.
    for (priority, new_rule) in &new_by_priority {
        match old_by_priority.get(priority) {
            None => {
                // New priority → added.
                added.push((*new_rule).clone());
            }
            Some((old_idx, old_rule)) => {
                // Same priority  --  check if content changed.
                if **old_rule != **new_rule {
                    modified.push((*old_idx, (*new_rule).clone()));
                }
            }
        }
    }

    // Find removed rules.
    for (priority, (old_idx, _)) in &old_by_priority {
        if !new_by_priority.contains_key(priority) {
            removed.push(*old_idx);
        }
    }

    // Sort removed indices for deterministic output.
    removed.sort_unstable();

    TableDiff {
        added,
        removed,
        modified,
    }
}

/// The result of update planning.
#[derive(Debug, Clone)]
pub struct UpdatePlan<M: Metadata = ()> {
    /// The classifier to publish immediately.
    pub immediate: Classifier<M>,
    /// Whether the immediate classifier is two-tier and needs
    /// background merge to converge to single-tier.
    pub needs_merge: bool,
}

/// Build a two-tier classifier: delta checked first, base as fallback.
#[must_use]
pub fn build_tiered<M: Metadata>(delta: Classifier<M>, base: Classifier<M>) -> Classifier<M> {
    Classifier::cascade(vec![delta, base])
}

/// Plan an update from an old table/classifier to a new table.
///
/// Returns an [`UpdatePlan`] with either:
/// - A fresh single-tier classifier (full rebuild, `needs_merge = false`)
/// - A two-tier Cascade (delta + old base, `needs_merge = true`)
///
/// The caller publishes `plan.immediate` via atomic swap.  If
/// `needs_merge` is true, the caller should also compile the full
/// new table in the background and swap again when done.
#[must_use]
pub fn plan_update<M: Metadata + Clone + PartialEq>(
    old_table: &AclTable<M>,
    old_classifier: &Classifier<M>,
    new_table: &AclTable<M>,
) -> UpdatePlan<M> {
    let diff = diff_tables(old_table, new_table);

    if diff.is_empty() {
        // No changes  --  keep the old classifier.
        return UpdatePlan {
            immediate: old_classifier.clone(),
            needs_merge: false,
        };
    }

    let k = diff.change_count();
    let n = new_table.rules().len();

    // Threshold: use delta strategy if changes are < 10% of total rules
    // and there are at least 10 total rules (below that, full rebuild
    // is trivially fast).
    let use_delta = n >= 10 && k * 10 < n;

    if use_delta {
        // Build a delta table from the changed rules.
        // The delta contains: added rules + new versions of modified rules.
        // Removed rules are handled implicitly: they're absent from the
        // delta, and the base still has them  --  but since the delta is
        // checked first and the base is the OLD table, removed rules in
        // the old base will still match. We need to add explicit "deny"
        // entries in the delta for removed rules... actually no.
        //
        // The two-tier model: delta checked first, base as fallback.
        // For a REMOVED rule: the delta has no entry for that traffic,
        // so it falls through to the base, which has the OLD rule.
        // This means removed rules are NOT reflected in the delta  -- 
        // they still match via the base.  This is WRONG for removes.
        //
        // Fix: for removed rules, add a "shadow" entry in the delta
        // with the same match but the table's default fate.  This
        // overrides the old base rule.
        //
        // For modified rules: the delta has the new version.  The base
        // has the old version.  Delta matches first → correct.
        //
        // For added rules: only in the delta.  Base doesn't have them.
        // Delta matches → correct.
        let mut delta_builder =
            crate::table::AclTableBuilder::new(new_table.default_fate());

        // Added rules go directly into the delta.
        for rule in &diff.added {
            delta_builder.push_rule(rule.clone());
        }

        // Modified rules: new version goes into the delta.
        for (_old_idx, new_rule) in &diff.modified {
            delta_builder.push_rule(new_rule.clone());
        }

        // Removed rules: shadow entry with the default fate.
        // These override the old base rule so removed traffic
        // gets the default instead of the old action.
        for &old_idx in &diff.removed {
            let old_rule = &old_table.rules()[old_idx];
            let shadow = AclRule::new(
                old_rule.packet_match().clone(),
                M::default(),
                ActionSequence::just(new_table.default_fate()),
                old_rule.priority(),
            );
            delta_builder.push_rule(shadow);
        }

        let delta_table = delta_builder.build();
        let delta_classifier = delta_table.compile();

        let tiered = build_tiered(delta_classifier, old_classifier.clone());

        UpdatePlan {
            immediate: tiered,
            needs_merge: true,
        }
    } else {
        // Full rebuild  --  k is too large for delta strategy.
        UpdatePlan {
            immediate: new_table.compile(),
            needs_merge: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::Fate;
    use lpm::prefix::{IpPrefix, Ipv4Prefix};
    use crate::{AclRuleBuilder, AclTableBuilder, FieldMatch};
    use net::headers::builder::HeaderStack;
    use net::tcp::port::TcpPort;
    use std::net::Ipv4Addr;

    fn pri(n: u32) -> Priority {
        Priority::new(n).unwrap()
    }

    fn make_headers(src_ip: Ipv4Addr, dst_port: u16) -> net::headers::Headers {
        HeaderStack::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.set_source(net::ipv4::UnicastIpv4Addr::new(src_ip).unwrap());
            })
            .tcp(|tcp| {
                tcp.set_destination(TcpPort::new_checked(dst_port).unwrap());
            })
            .build_headers()
            .unwrap()
    }

    #[test]
    fn diff_identical_tables() {
        let table = AclTableBuilder::new(Fate::Drop)
            .add_rule(
                AclRuleBuilder::new()
                    .eth(|_| {})
                    .ipv4(|ip| {
                        ip.src = FieldMatch::Select(
                            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
                        );
                    })
                    .permit(pri(100)),
            )
            .build();

        let diff = diff_tables(&table, &table);
        assert!(diff.is_empty());
        assert_eq!(diff.change_count(), 0);
    }

    #[test]
    fn diff_added_rule() {
        let old = AclTableBuilder::new(Fate::Drop)
            .add_rule(
                AclRuleBuilder::new()
                    .eth(|_| {})
                    .ipv4(|ip| {
                        ip.src = FieldMatch::Select(
                            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
                        );
                    })
                    .permit(pri(100)),
            )
            .build();

        let new = AclTableBuilder::new(Fate::Drop)
            .add_rule(
                AclRuleBuilder::new()
                    .eth(|_| {})
                    .ipv4(|ip| {
                        ip.src = FieldMatch::Select(
                            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
                        );
                    })
                    .permit(pri(100)),
            )
            .add_rule(
                AclRuleBuilder::new()
                    .eth(|_| {})
                    .ipv4(|ip| {
                        ip.src = FieldMatch::Select(
                            Ipv4Prefix::new(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap(),
                        );
                    })
                    .deny(pri(200)),
            )
            .build();

        let diff = diff_tables(&old, &new);
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.removed.len(), 0);
        assert_eq!(diff.modified.len(), 0);
    }

    #[test]
    fn diff_removed_rule() {
        let old = AclTableBuilder::new(Fate::Drop)
            .add_rule(AclRuleBuilder::new().eth(|_| {}).permit(pri(100)))
            .add_rule(AclRuleBuilder::new().eth(|_| {}).deny(pri(200)))
            .build();

        let new = AclTableBuilder::new(Fate::Drop)
            .add_rule(AclRuleBuilder::new().eth(|_| {}).permit(pri(100)))
            .build();

        let diff = diff_tables(&old, &new);
        assert_eq!(diff.added.len(), 0);
        assert_eq!(diff.removed.len(), 1);
        assert_eq!(diff.modified.len(), 0);
    }

    #[test]
    fn diff_modified_rule() {
        let old = AclTableBuilder::new(Fate::Drop)
            .add_rule(
                AclRuleBuilder::new()
                    .eth(|_| {})
                    .ipv4(|ip| {
                        ip.src = FieldMatch::Select(
                            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
                        );
                    })
                    .permit(pri(100)),
            )
            .build();

        // Same priority, different action (permit → deny)
        let new = AclTableBuilder::new(Fate::Drop)
            .add_rule(
                AclRuleBuilder::new()
                    .eth(|_| {})
                    .ipv4(|ip| {
                        ip.src = FieldMatch::Select(
                            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
                        );
                    })
                    .deny(pri(100)),
            )
            .build();

        let diff = diff_tables(&old, &new);
        assert_eq!(diff.added.len(), 0);
        assert_eq!(diff.removed.len(), 0);
        assert_eq!(diff.modified.len(), 1);
    }

    #[test]
    fn update_no_change_keeps_old_classifier() {
        let table = AclTableBuilder::new(Fate::Drop)
            .add_rule(AclRuleBuilder::new().eth(|_| {}).permit(pri(100)))
            .build();
        let classifier = table.compile();

        let plan = plan_update(&table, &classifier, &table);
        assert!(!plan.needs_merge);
    }

    #[test]
    fn two_tier_matches_fresh_compile() {
        // Build a large enough table that delta strategy triggers (n >= 10).
        let mut builder = AclTableBuilder::new(Fate::Drop);
        for i in 1..=15u32 {
            builder.push_rule(
                AclRuleBuilder::new()
                    .eth(|_| {})
                    .ipv4(|ip| {
                        ip.src = FieldMatch::Select(
                            Ipv4Prefix::from(Ipv4Addr::new(10, 0, 0, i.try_into().unwrap())),
                        );
                    })
                    .permit(pri(i)),
            );
        }
        let old_table = builder.build();
        let old_classifier = old_table.compile();

        // Add one rule to the new table.
        let mut new_builder = old_table.to_builder();
        new_builder.push_rule(
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(
                        Ipv4Prefix::from(Ipv4Addr::new(192, 168, 1, 1)),
                    );
                })
                .deny(pri(100)),
        );
        let new_table = new_builder.build();

        let plan = plan_update(&old_table, &old_classifier, &new_table);
        assert!(plan.needs_merge, "should use delta strategy for 1 change in 16 rules");

        // The two-tier classifier must match a fresh compile of the new table.
        let fresh = new_table.compile();

        let test_ips = [
            Ipv4Addr::new(10, 0, 0, 1),    // matches old rule → permit
            Ipv4Addr::new(192, 168, 1, 1),  // matches new rule → deny (drop)
            Ipv4Addr::new(172, 16, 0, 1),   // matches nothing → default drop
        ];

        for ip in test_ips {
            let headers = make_headers(ip, 80);
            let tiered_fate = plan.immediate.classify(&headers, &()).fate();
            let fresh_fate = fresh.classify(&headers, &()).fate();
            assert_eq!(
                tiered_fate, fresh_fate,
                "mismatch for {ip}: tiered={tiered_fate:?}, fresh={fresh_fate:?}"
            );
        }
    }

    #[test]
    fn removed_rule_reflected_in_delta() {
        // Large table.
        let mut builder = AclTableBuilder::new(Fate::Drop);
        for i in 1..=15u32 {
            builder.push_rule(
                AclRuleBuilder::new()
                    .eth(|_| {})
                    .ipv4(|ip| {
                        ip.src = FieldMatch::Select(
                            Ipv4Prefix::from(Ipv4Addr::new(10, 0, 0, i.try_into().unwrap())),
                        );
                    })
                    .permit(pri(i)),
            );
        }
        let old_table = builder.build();
        let old_classifier = old_table.compile();

        // Remove rule for 10.0.0.5 (priority 5).
        let mut new_builder = old_table.to_builder();
        new_builder.remove_by_priority(pri(5));
        let new_table = new_builder.build();

        let plan = plan_update(&old_table, &old_classifier, &new_table);
        assert!(plan.needs_merge);

        let fresh = new_table.compile();

        // 10.0.0.5 should now get the default fate (Drop), not permit.
        let headers = make_headers(Ipv4Addr::new(10, 0, 0, 5), 80);
        let tiered_fate = plan.immediate.classify(&headers, &()).fate();
        let fresh_fate = fresh.classify(&headers, &()).fate();
        assert_eq!(tiered_fate, Fate::Drop, "removed rule should not match in delta");
        assert_eq!(tiered_fate, fresh_fate);

        // 10.0.0.3 should still permit (unchanged rule).
        let headers2 = make_headers(Ipv4Addr::new(10, 0, 0, 3), 80);
        let tiered_fate2 = plan.immediate.classify(&headers2, &()).fate();
        let fresh_fate2 = fresh.classify(&headers2, &()).fate();
        assert_eq!(tiered_fate2, Fate::Accept);
        assert_eq!(tiered_fate2, fresh_fate2);
    }
}
