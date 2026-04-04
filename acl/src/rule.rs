// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::action::Action;
use crate::builder::AclMatchFields;
use crate::metadata::Metadata;
use crate::priority::Priority;

/// A complete ACL rule: packet match + metadata + action + priority.
///
/// Constructed via [`AclRuleBuilder`](crate::AclRuleBuilder).
/// Lower priority values are evaluated first.
///
/// `M` is the metadata match type, defaulting to `()` (no metadata).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclRule<M: Metadata = ()> {
    packet_match: AclMatchFields,
    metadata: M,
    action: Action,
    priority: Priority,
}

impl<M: Metadata> AclRule<M> {
    /// Create a new rule.  Called by the builder's terminal methods.
    pub(super) fn new(
        packet_match: AclMatchFields,
        metadata: M,
        action: Action,
        priority: Priority,
    ) -> Self {
        Self {
            packet_match,
            metadata,
            action,
            priority,
        }
    }

    /// The protocol-layer match criteria for this rule.
    #[must_use]
    pub fn packet_match(&self) -> &AclMatchFields {
        &self.packet_match
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
    pub fn priority(&self) -> Priority {
        self.priority
    }
}
