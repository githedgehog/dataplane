// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Cascade `Layer` / `MutableHead` impls for the ACL classifier.
//!
//! Three concrete types compose the cascade:
//!
//! - [`AclHead`] -- a multi-writer buffer of newly-installed rules,
//!   keyed by priority for per-key dedup on concurrent installs.
//!   `Layer::lookup` returns [`Outcome::Continue`] -- writes are
//!   only visible to readers after the next [`Cascade::rotate`].
//!   This is acceptable because ACL update rates are low and the
//!   one-rotation visibility latency is much smaller than the
//!   control-plane reconciliation interval.  See the cascade docs
//!   on \"head readability under high write rate\" for the rationale.
//!
//! - [`AclFrozen`] -- an immutable rule list sorted ascending by
//!   priority.  `Layer::lookup` walks the list in priority order
//!   and returns the first match.
//!
//! - [`AclTail`] -- structurally identical to [`AclFrozen`] in this
//!   first slice.  Kept as a distinct type so we can later swap in
//!   a richer representation (DPDK ACL context, two-tier compiled
//!   classifier) without touching the cascade composition.
//!
//! Compaction via [`MergeInto<AclTail>`] for [`AclFrozen`] dedups
//! by priority with newer-wins-on-conflict, mirroring the cascade
//! walk's \"newer shadows older\" semantic.
//!
//! [`Cascade::rotate`]: cascade::Cascade::rotate
//! [`Outcome::Continue`]: cascade::Outcome::Continue

use std::collections::BTreeMap;
use std::sync::Mutex;

use cascade::{Layer, MergeInto, MutableHead, Outcome, Upsert};

use crate::types::{AclRule, Headers, Priority};

// ---------------------------------------------------------------------------
// AclRule wears Upsert at the per-key level via last-writer-wins.
// The head decomposes its `Op` into (priority, AclRule) pairs and
// dispatches through this impl on the BTreeMap entry API.
// ---------------------------------------------------------------------------

impl Upsert for AclRule {
    type Op = AclRule;

    fn upsert(&mut self, op: Self::Op) {
        // Last-writer-wins.  Concurrent installs at the same priority
        // converge to whichever arrived last in the head's internal
        // ordering; for ACL workloads this is acceptable because the
        // control plane should not be issuing conflicting installs at
        // the same priority (priority *is* the rule's identity).
        *self = op;
    }

    // TODO: is this method strictly necessary?  If we reframe this as Evolve then
    fn seed(op: Self::Op) -> Self {
        op
    }
}

// ---------------------------------------------------------------------------
// Op type for the head.  Single variant for now; remove will land
// later via shadow-rule synthesis in user code (see the cascade
// design conversation on tombstone semantics for ACL).
// ---------------------------------------------------------------------------

/// Operations that can be applied to an [`AclHead`].
///
/// First slice supports install only.  Removal will be added later
/// via user-code that synthesises shadow rules using
/// [`Cascade::snapshot`](cascade::Cascade::snapshot) and
/// [`Cascade::write`](cascade::Cascade::write).  See the design
/// conversation in the cascade crate's docs on why removal lives
/// in user code rather than the framework.
#[derive(Debug, Clone, Copy)]
pub enum AclOp {
    Install(AclRule),
}

// ---------------------------------------------------------------------------
// AclHead -- multi-writer buffer of pending rule installs.
// ---------------------------------------------------------------------------

/// The cascade's mutable head for an ACL classifier.
///
/// Internally a `Mutex<BTreeMap<Priority, AclRule>>`.  The `BTreeMap`
/// gives priority-sorted iteration for `seal`, and the Mutex serialises
/// concurrent writes (multi-writer scenarios will typically be the
/// control-plane reconciler thread alone, so contention is minimal).
///
/// `Layer::lookup` always returns `Outcome::Continue`; reading a
/// borrow out of a Mutex into the cascade walk would require holding
/// the lock across the entire walk, which we are not willing to do.
/// Writes become visible to readers after the next
/// [`Cascade::rotate`](cascade::Cascade::rotate) seals this head into
/// an [`AclFrozen`] layer.
pub struct AclHead {
    rules: Mutex<BTreeMap<Priority, AclRule>>,
}

impl AclHead {
    /// A fresh, empty head.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            rules: Mutex::new(BTreeMap::new()),
        }
    }
}

impl Default for AclHead {
    fn default() -> Self {
        Self::empty()
    }
}

impl Layer for AclHead {
    type Input = Headers;
    type Output = AclRule;

    fn lookup(&self, _input: &Headers) -> Outcome<&AclRule> {
        Outcome::Continue
    }
}

impl MutableHead for AclHead {
    type Op = AclOp;
    type Frozen = AclFrozen;

    fn write(&self, op: AclOp) {
        let AclOp::Install(rule) = op;
        let mut guard = self
            .rules
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .entry(rule.priority)
            .and_modify(|existing| existing.upsert(rule))
            .or_insert_with(|| AclRule::seed(rule));
    }

    fn freeze(&self) -> AclFrozen {
        let guard = self
            .rules
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        AclFrozen::from_rules(guard.values().copied())
    }

    fn approx_size(&self) -> usize {
        self.rules.lock().map_or(0, |guard| guard.len())
    }
}

// ---------------------------------------------------------------------------
// AclFrozen -- immutable rule list, priority-sorted for linear-scan
// classification.
// ---------------------------------------------------------------------------

/// An immutable, priority-sorted rule list.
///
/// `Layer::lookup` walks the list in ascending priority order and
/// returns the first matching rule.  For very small rule sets this
/// is the right shape; for large ones we will eventually compile
/// the rules into a more efficient structure (DPDK ACL context, a
/// hand-tuned trie, etc.) -- but that lives in a different `Tail`
/// type, not here.
#[derive(Debug, Clone)]
pub struct AclFrozen {
    /// Sorted ascending by priority on construction.
    rules: Vec<AclRule>,
}

impl AclFrozen {
    /// Build a sealed layer from an iterator of rules.  Sorts by
    /// priority once; subsequent lookups are linear scan over the
    /// sorted vec.
    #[must_use]
    pub fn from_rules<I: IntoIterator<Item = AclRule>>(it: I) -> Self {
        let mut rules: Vec<AclRule> = it.into_iter().collect();
        rules.sort_by_key(|r| r.priority);
        Self { rules }
    }

    /// Empty sealed layer.  Useful as the initial tail for an
    /// otherwise-empty classifier.
    #[must_use]
    pub fn empty() -> Self {
        Self { rules: Vec::new() }
    }

    /// Read-only view of the sorted rules.  Diagnostic / iteration.
    #[must_use]
    pub fn rules(&self) -> &[AclRule] {
        &self.rules
    }
}

impl Layer for AclFrozen {
    type Input = Headers;
    type Output = AclRule;

    fn lookup(&self, headers: &Headers) -> Outcome<&AclRule> {
        for rule in &self.rules {
            if rule.matches.matches(headers) {
                return Outcome::Match(rule);
            }
        }
        Outcome::Continue
    }
}

// ---------------------------------------------------------------------------
// AclTail -- structurally identical to AclFrozen in this first slice.
//
// Kept as a distinct nominal type so consumers' generics bind
// against `AclTail` specifically.  When we add a DPDK-backed tail
// for hardware offload, AclTail becomes an enum (or trait object)
// without disturbing the cascade composition.
// ---------------------------------------------------------------------------

/// The ground-truth ACL layer the cascade compacts into.
///
/// Same shape as [`AclFrozen`] in this first slice.  Maintained as
/// a distinct nominal type so that swapping to a hardware-backed
/// tail (`DpdkAclTail` wrapping `dpdk::acl::AclContext`) is a
/// localised change.
#[derive(Debug, Clone)]
pub struct AclTail {
    rules: Vec<AclRule>,
}

impl AclTail {
    #[must_use]
    pub fn empty() -> Self {
        Self { rules: Vec::new() }
    }

    #[must_use]
    pub fn from_rules<I: IntoIterator<Item = AclRule>>(it: I) -> Self {
        let mut rules: Vec<AclRule> = it.into_iter().collect();
        rules.sort_by_key(|r| r.priority);
        Self { rules }
    }

    #[must_use]
    pub fn rules(&self) -> &[AclRule] {
        &self.rules
    }
}

impl Layer for AclTail {
    type Input = Headers;
    type Output = AclRule;

    fn lookup(&self, headers: &Headers) -> Outcome<&AclRule> {
        for rule in &self.rules {
            if rule.matches.matches(headers) {
                return Outcome::Match(rule);
            }
        }
        Outcome::Continue
    }
}

// ---------------------------------------------------------------------------
// MergeInto<AclTail> for AclFrozen -- compaction logic.
//
// Builds a dedup-by-priority BTreeMap seeded from the old tail,
// then overlays self's rules (newer wins on conflict, mirroring
// the cascade walk semantic).  The result becomes the new tail.
// ---------------------------------------------------------------------------

impl MergeInto<AclTail> for AclFrozen {
    fn merge_into(&self, target: &AclTail) -> AclTail {
        let mut by_priority: BTreeMap<Priority, AclRule> = BTreeMap::new();
        // Seed from the existing tail (lower precedence).
        for r in &target.rules {
            by_priority.insert(r.priority, *r);
        }
        // Overlay self's rules; collisions favor self.
        for r in &self.rules {
            by_priority.insert(r.priority, *r);
        }
        AclTail::from_rules(by_priority.into_values())
    }
}
