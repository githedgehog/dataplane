// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::action::Fate;
use crate::metadata::Metadata;
use crate::priority::Priority;
use crate::rule::AclRule;

/// Builder for an ACL table.
///
/// Accumulates rules and a default fate.  Call [`.build()`](Self::build)
/// to produce an immutable [`AclTable`].
///
/// The builder supports both initial construction and incremental
/// modification.  For updates, create a builder from an existing table
/// via [`AclTable::to_builder()`], modify it, and build a new table.
#[derive(Debug, Clone)]
pub struct AclTableBuilder<M: Metadata = ()> {
    rules: Vec<AclRule<M>>,
    default_fate: Fate,
}

impl<M: Metadata> AclTableBuilder<M> {
    /// Create a new empty builder with the given default fate.
    #[must_use]
    pub fn new(default_fate: Fate) -> Self {
        Self {
            rules: Vec::new(),
            default_fate,
        }
    }

    /// Append a rule.
    #[must_use]
    pub fn add_rule(mut self, rule: AclRule<M>) -> Self {
        self.rules.push(rule);
        self
    }

    /// Append a rule (by mutable reference, for use in loops).
    pub fn push_rule(&mut self, rule: AclRule<M>) {
        self.rules.push(rule);
    }

    /// Remove all rules matching the given priority.
    ///
    /// Returns the number of rules removed.
    pub fn remove_by_priority(&mut self, priority: Priority) -> usize {
        let before = self.rules.len();
        self.rules.retain(|r| r.priority() != priority);
        before - self.rules.len()
    }

    /// Remove the rule at the given index.
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of bounds.
    pub fn remove_at(&mut self, index: usize) -> AclRule<M> {
        self.rules.remove(index)
    }

    /// The current number of rules.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether the builder has no rules.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The current rules (for inspection before building).
    #[must_use]
    pub fn rules(&self) -> &[AclRule<M>] {
        &self.rules
    }

    /// Change the default fate.
    pub fn set_default_fate(&mut self, fate: Fate) {
        self.default_fate = fate;
    }

    /// The current default fate.
    #[must_use]
    pub fn default_fate(&self) -> Fate {
        self.default_fate
    }

    /// Freeze the rule set into an immutable [`AclTable`].
    ///
    /// This does **not** consume the builder  --  you can continue
    /// modifying and rebuilding.
    #[must_use]
    pub fn build(&self) -> AclTable<M>
    where
        M: Clone,
    {
        AclTable {
            rules: self.rules.clone(),
            default_fate: self.default_fate,
        }
    }
}

/// An immutable ACL table: a frozen snapshot of rules with a default fate.
///
/// Rules are evaluated in priority order (lower priority value = higher
/// precedence).  If no rule matches, the default fate applies.
///
/// Construct via [`AclTableBuilder`].  For incremental updates, convert
/// back to a builder via [`to_builder()`](AclTable::to_builder).
///
/// `M` is the metadata match type shared by all rules, defaulting to
/// `()` (no metadata).
#[derive(Debug, Clone)]
pub struct AclTable<M: Metadata = ()> {
    rules: Vec<AclRule<M>>,
    default_fate: Fate,
}

impl<M: Metadata> AclTable<M> {
    /// The rules in this table.
    #[must_use]
    pub fn rules(&self) -> &[AclRule<M>] {
        &self.rules
    }

    /// The default fate when no rule matches.
    #[must_use]
    pub fn default_fate(&self) -> Fate {
        self.default_fate
    }

    /// Convert this table back into a builder for incremental modification.
    ///
    /// The builder starts with a copy of this table's rules and default
    /// fate.  Modify the builder and call `.build()` to produce a new
    /// table.  The original table is unchanged.
    #[must_use]
    pub fn to_builder(&self) -> AclTableBuilder<M>
    where
        M: Clone,
    {
        AclTableBuilder {
            rules: self.rules.clone(),
            default_fate: self.default_fate,
        }
    }
}
