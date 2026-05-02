// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Backend-agnostic ACL pipeline IR.
//!
//! The reconciler operates on this IR.  Backends materialize values
//! from it (DPDK trie, tc-flower handles, rte_flow rules, ...) but
//! the reconciler itself never sees the materialized form on the
//! ingest path -- it only diffs IRs and submits the result to the
//! build worker.
//!
//! # Diff contract
//!
//! The only requirement on the IR is that two IRs of the same type
//! are diffable.  Container choice per table is free; this v1 uses
//! `BTreeMap<RuleId, AclRule>` for ACL rules because it gets
//! `PartialEq` and `Clone` for free, has deterministic iteration
//! order, and clones are `Arc`-friendly.  Secondary indexes
//! (`multi_index_map`) can swap in later without changing the
//! reconciler protocol.

#![allow(missing_docs)] // shape settling; doc once stable

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::num::NonZero;

// =====================================================================
// Field primitives
// =====================================================================

/// IPv4 prefix.  Length 0 matches everything.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Prefix {
    pub addr: Ipv4Addr,
    pub len: u8,
}

/// Inclusive port range `[lo, hi]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PortRange {
    pub lo: u16,
    pub hi: u16,
}

/// L4 protocol selector.  Backends decide what they can express.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Proto {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AclAction {
    Accept,
    Drop,
}

// =====================================================================
// RuleId + AclRule
// =====================================================================

/// Stable identifier assigned by the IR layer.  The diff is keyed by
/// this.  Backends may carry their own internal indexes (DPDK's u24
/// userdata, tc-flower's chain handle); those never escape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RuleId(NonZero<u64>);

impl RuleId {
    #[must_use]
    pub const fn new(id: NonZero<u64>) -> Self {
        Self(id)
    }

    #[must_use]
    pub const fn get(self) -> NonZero<u64> {
        self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AclRule {
    pub id: RuleId,
    /// Higher numeric value wins on tied matches.  Backends translate
    /// to whatever native priority semantics they have.
    pub priority: u32,
    pub src_ip: Option<Prefix>,
    pub dst_ip: Option<Prefix>,
    pub src_port: Option<PortRange>,
    pub dst_port: Option<PortRange>,
    pub proto: Option<Proto>,
    pub action: AclAction,
}

// =====================================================================
// AclTable + PipelineIR
// =====================================================================

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AclTable {
    pub rules: BTreeMap<RuleId, AclRule>,
}

impl AclTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, rule: AclRule) {
        self.rules.insert(rule.id, rule);
    }

    pub fn remove(&mut self, id: RuleId) -> Option<AclRule> {
        self.rules.remove(&id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &AclRule> {
        self.rules.values()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// Top-level pipeline IR.  Grows one field per logical table as
/// other backends arrive (FIB, NAT, ...).  Generation tagging lives
/// in the [`Submission`](crate::manager::Submission) wrapper, not
/// here -- the IR is structural state, not transient metadata.
///
/// [`Submission`]: crate::manager
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PipelineIR {
    pub acl: AclTable,
}

impl PipelineIR {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn rid(n: u64) -> RuleId {
        RuleId::new(NonZero::new(n).unwrap())
    }

    fn sample_rule(n: u64, action: AclAction) -> AclRule {
        AclRule {
            id: rid(n),
            priority: 100,
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: Some(PortRange { lo: 80, hi: 80 }),
            proto: Some(Proto::Tcp),
            action,
        }
    }

    #[test]
    fn empty_pipelines_are_equal() {
        assert_eq!(PipelineIR::new(), PipelineIR::new());
    }

    #[test]
    fn rule_difference_breaks_equality() {
        let mut a = PipelineIR::new();
        a.acl.insert(sample_rule(1, AclAction::Accept));
        let mut b = PipelineIR::new();
        b.acl.insert(sample_rule(1, AclAction::Drop));
        assert_ne!(a, b);
    }

    #[test]
    fn missing_rule_breaks_equality() {
        let mut a = PipelineIR::new();
        a.acl.insert(sample_rule(1, AclAction::Accept));
        a.acl.insert(sample_rule(2, AclAction::Drop));
        let mut b = PipelineIR::new();
        b.acl.insert(sample_rule(1, AclAction::Accept));
        assert_ne!(a, b);
    }

    #[test]
    fn same_rules_are_equal() {
        let mut a = PipelineIR::new();
        a.acl.insert(sample_rule(1, AclAction::Accept));
        a.acl.insert(sample_rule(2, AclAction::Drop));
        let mut b = PipelineIR::new();
        b.acl.insert(sample_rule(1, AclAction::Accept));
        b.acl.insert(sample_rule(2, AclAction::Drop));
        assert_eq!(a, b);
    }
}
