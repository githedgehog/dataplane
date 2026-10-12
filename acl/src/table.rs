// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A first-match classifier table for any [`MatchKey`], with the rules it was built from.

use crate::dpdk::dyn_table::predicate_to_chunks;
use crate::dpdk::install::install_table;
use crate::dpdk::lookup::DpdkAclLookup;
use crate::dpdk::rule::{AclFieldChunks, RuleSpec};
#[cfg(feature = "reference")]
use crate::reference::table::{RefRule, ReferenceTable};
// DPDK's ACL registry survives model-checker executions. Its name counter must also persist to
// avoid reusing a live context's name.
use concurrency::process_global::atomic::{AtomicU64, Ordering};
use dpdk::acl::{CategoryMask, Priority};
use lookup::Lookup;
use match_action::{FieldPredicate, MatchKey};
use std::fmt;
use std::num::NonZero;

/// Which classifier a table is built with.
///
/// `Dpdk` is the production `rte_acl` classifier, which needs the EAL initialized. `Reference` (the
/// `reference` feature) is the linear-scan oracle, for tests that run without the EAL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Dpdk,
    #[cfg(feature = "reference")]
    Reference,
}

/// A classifier and its rules for one IP version.
pub struct Table<K: MatchKey, A> {
    classifier: Classifier<K, A>,
    /// Typed rules in precedence order, retained because `rte_acl` cannot expose installed rules.
    rules: Box<[RuleRow<K, A>]>,
}

/// A typed rule and its action, retained for display.
pub struct RuleRow<K: MatchKey, A> {
    pub rule: K::Rule,
    pub action: A,
}

/// `Empty` avoids building an `rte_acl` context for a zero-rule table.
#[allow(clippy::large_enum_variant)] // backend reprs differ in size; boxing would add an indirection
enum Classifier<K: MatchKey, A> {
    Empty,
    Dpdk(DpdkAclLookup<K, A>),
    #[cfg(feature = "reference")]
    Reference(ReferenceTable<K, A>),
}

impl<K: MatchKey, A> Table<K, A> {
    /// A table that matches nothing.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            classifier: Classifier::Empty,
            rules: Box::new([]),
        }
    }

    /// Look up one key using first-match precedence.
    #[must_use]
    pub fn lookup(&self, key: &K) -> Option<&A> {
        match &self.classifier {
            Classifier::Empty => None,
            Classifier::Dpdk(table) => table.lookup(key),
            #[cfg(feature = "reference")]
            Classifier::Reference(table) => table.lookup(key),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether the table has no rules, and so matches nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The rules this table was built from, in precedence (first-match) order.
    #[must_use]
    pub fn rules(&self) -> &[RuleRow<K, A>] {
        &self.rules
    }
}

impl<K: MatchKey, A> fmt::Debug for Table<K, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.classifier {
            Classifier::Empty => "empty",
            Classifier::Dpdk(_) => "dpdk",
            #[cfg(feature = "reference")]
            Classifier::Reference(_) => "reference",
        };
        write!(f, "Table::{kind}({} rules)", self.len())
    }
}

static TABLE_SEQ: AtomicU64 = AtomicU64::new(0);

fn next_in_sequence() -> u64 {
    TABLE_SEQ.fetch_add(1, Ordering::Relaxed)
}

/// A process-unique `rte_acl` context name. `rte_acl` rejects duplicate names, and a hot-swap briefly
/// keeps the old and new contexts alive at once, so the name must be unique across the process.
fn table_name(base: &str) -> String {
    format!("acl_{base}_{}", next_in_sequence())
}

/// Build one table for the selected backend from rules in precedence (insertion) order.
pub fn build_table<K: MatchKey, A: Clone>(
    backend: Backend,
    base_name: &str,
    rules: Vec<(K::Rule, Vec<FieldPredicate>, A)>,
) -> Result<Table<K, A>, String>
where
    K::Rule: Copy,
{
    let rows: Box<[RuleRow<K, A>]> = rules
        .iter()
        .map(|(rule, _, action)| RuleRow {
            rule: *rule,
            action: action.clone(),
        })
        .collect();

    let classifier = match backend {
        Backend::Dpdk => {
            if rules.is_empty() {
                return Ok(Table::empty());
            }
            let n = rules.len();
            let max = NonZero::new(u32::try_from(n).unwrap_or(u32::MAX))
                .ok_or_else(|| "zero-rule table reached the dpdk builder".to_string())?;
            let specs = K::field_specs();
            let mut rule_specs = Vec::with_capacity(n);
            for (i, (_, fields, action)) in rules.into_iter().enumerate() {
                // Positional first-match: the first matching rule wins. rte_acl returns the
                // highest-priority match, so priority descends with insertion index (rule 0 gets
                // the highest priority). Distinct priorities keep the outcome deterministic.
                let priority_value = i32::try_from(n - i).map_err(|e| e.to_string())?;
                let priority = Priority::new(priority_value).map_err(|e| e.to_string())?;
                let chunks: Vec<AclFieldChunks> = fields
                    .iter()
                    .zip(specs)
                    .map(|(pred, spec)| predicate_to_chunks(pred, spec.size))
                    .collect();
                let spec = RuleSpec::<K, A>::new(
                    priority,
                    CategoryMask::new(1).map_err(|e| e.to_string())?,
                    chunks,
                    action,
                )
                .map_err(|e| e.to_string())?;
                rule_specs.push(spec);
            }
            install_table::<K, A>(&table_name(base_name), max, rule_specs)
                .map(Classifier::Dpdk)
                .map_err(|e| e.to_string())?
        }
        #[cfg(feature = "reference")]
        Backend::Reference => {
            let rules = rules
                .into_iter()
                .map(|(_, fields, action)| RefRule::new(fields, action))
                .collect();
            Classifier::Reference(ReferenceTable::new(rules))
        }
    };
    Ok(Table {
        classifier,
        rules: rows,
    })
}

impl<K: MatchKey, A> Lookup<K, A> for Table<K, A> {
    fn lookup(&self, key: &K) -> Option<&A> {
        Table::lookup(self, key)
    }
}
