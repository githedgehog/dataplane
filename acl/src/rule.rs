// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::action::Action;
use crate::builder::AclMatchFields;
use crate::metadata::Metadata;

/// A complete ACL rule: match fields + metadata + action + priority.
///
/// Constructed via [`AclRuleBuilder`](crate::AclRuleBuilder).
/// Lower priority values are evaluated first.
///
/// `M` is the metadata match type, defaulting to `()` (no metadata).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclRule<M: Metadata = ()> {
    match_fields: AclMatchFields,
    metadata: M,
    action: Action,
    priority: u32,
}

impl<M: Metadata> AclRule<M> {
    /// Create a new rule.  Called by the builder's terminal methods.
    pub(super) fn new(
        match_fields: AclMatchFields,
        metadata: M,
        action: Action,
        priority: u32,
    ) -> Self {
        Self {
            match_fields,
            metadata,
            action,
            priority,
        }
    }

    /// The protocol match fields for this rule.
    #[must_use]
    pub fn match_fields(&self) -> &AclMatchFields {
        &self.match_fields
    }

    /// The metadata match criteria.
    #[must_use]
    pub fn metadata(&self) -> &M {
        &self.metadata
    }

    /// The action to take when a packet matches.
    #[must_use]
    pub fn action(&self) -> Action {
        self.action
    }

    /// The rule priority (lower = higher precedence).
    #[must_use]
    pub fn priority(&self) -> u32 {
        self.priority
    }
}
