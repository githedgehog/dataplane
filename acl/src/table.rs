// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::action::Action;
use crate::metadata::Metadata;
use crate::rule::AclRule;

/// An ordered collection of ACL rules with a default action.
///
/// Rules are evaluated in priority order (lower priority value = higher
/// precedence).  If no rule matches, the default action applies.
///
/// `M` is the metadata match type shared by all rules in this table,
/// defaulting to `()` (no metadata).
#[derive(Debug, Clone)]
pub struct AclTable<M: Metadata = ()> {
    rules: Vec<AclRule<M>>,
    default_action: Action,
}

impl<M: Metadata> AclTable<M> {
    /// Create a new empty table with the given default action.
    #[must_use]
    pub fn new(default_action: Action) -> Self {
        Self {
            rules: Vec::new(),
            default_action,
        }
    }

    /// Append a rule to the table.
    #[must_use]
    pub fn add_rule(mut self, rule: AclRule<M>) -> Self {
        self.rules.push(rule);
        self
    }

    /// The rules in this table, in insertion order.
    #[must_use]
    pub fn rules(&self) -> &[AclRule<M>] {
        &self.rules
    }

    /// The default action when no rule matches.
    #[must_use]
    pub fn default_action(&self) -> Action {
        self.default_action
    }
}
