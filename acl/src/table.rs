// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::action::Fate;
use crate::metadata::Metadata;
use crate::rule::AclRule;

/// Builder for an ACL table.
///
/// Accumulates rules and a default fate.  Call [`.build()`](Self::build)
/// to produce an immutable [`AclTable`].
#[derive(Debug, Clone)]
pub struct AclTableBuilder<M: Metadata = ()> {
    rules: Vec<AclRule<M>>,
    default_fate: Fate,
}

impl<M: Metadata> AclTableBuilder<M> {
    /// Create a new builder with the given default fate.
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

    /// Freeze the rule set into an immutable [`AclTable`].
    #[must_use]
    pub fn build(self) -> AclTable<M> {
        AclTable {
            rules: self.rules,
            default_fate: self.default_fate,
        }
    }
}

/// An immutable ACL table: a frozen set of rules with a default fate.
///
/// Rules are evaluated in priority order (lower priority value = higher
/// precedence).  If no rule matches, the default fate applies.
///
/// Construct via [`AclTableBuilder`].
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
}
