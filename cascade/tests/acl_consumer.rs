// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! First real-shaped consumer: a minimal ACL classifier built on
//! top of the cascade.
//!
//! Purpose: surface design pressure on the trait surface by
//! exercising it against a use case that is NOT exact-match-keyed.
//! ACL classification looks up packets by header match expressions,
//! not by a single key, and rules carry their own identity
//! (priority) that is separate from the lookup input.  If the
//! cascade trait shape works for ACL it almost certainly works for
//! anything simpler.
//!
//! # Scope
//!
//! - Rules are install-only.  Removal would require a "shadow rule"
//!   mechanism (insert a higher-priority rule with the same match
//!   expression and the default action) that we have not designed
//!   yet; see the comment block at the end of this file for the
//!   open question.
//! - Match expressions are minimal: src/dst IPv4 with optional
//!   single-port match.  Real ACL match expressions are much
//!   richer; that does not change the cascade trait shape.
//! - The head's [`Layer::lookup`] always returns `Continue`.  Writes
//!   become visible only after a rotation seals the head into a
//!   sealed layer.  This works for low-rate ACL updates; high-rate
//!   stateful tables (conntrack) will need a real head-lookup,
//!   which is the GAT/owned-output question we have parked.

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;

use dataplane_cascade::{Cascade, Layer, MergeInto, MutableHead, Outcome};

// ---------------------------------------------------------------------------
// Minimal ACL primitives.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Priority(u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Allow,
    Drop,
}

#[derive(Debug, Clone, Copy)]
struct Match {
    src_ip: Option<Ipv4Addr>,
    dst_ip: Option<Ipv4Addr>,
    dst_port: Option<u16>,
}

impl Match {
    fn matches(&self, headers: &Headers) -> bool {
        self.src_ip.is_none_or(|a| a == headers.src_ip)
            && self.dst_ip.is_none_or(|a| a == headers.dst_ip)
            && self.dst_port.is_none_or(|p| p == headers.dst_port)
    }
}

#[derive(Debug, Clone, Copy)]
struct AclRule {
    priority: Priority,
    matches: Match,
    action: Action,
}

#[derive(Debug, Clone, Copy)]
struct Headers {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    dst_port: u16,
}

// ---------------------------------------------------------------------------
// AclSealed: immutable rule list sorted ascending by priority.
//
// The cascade walks layers head -> sealed[] -> tail looking for the
// first Match.  Within a layer, ACL classification walks rules in
// priority order (lowest priority value = highest precedence in our
// convention).  Same logic applies for tail.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct AclSealed {
    /// Sorted ascending by priority on construction so the lookup
    /// is a linear scan in precedence order.
    rules: Vec<AclRule>,
}

impl AclSealed {
    fn from_rules<I: IntoIterator<Item = AclRule>>(it: I) -> Self {
        let mut rules: Vec<AclRule> = it.into_iter().collect();
        rules.sort_by_key(|r| r.priority);
        Self { rules }
    }
}

impl Layer for AclSealed {
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
// AclHead: a multi-writer buffer of newly-installed rules, keyed by
// priority for de-duplication of concurrent installs at the same
// priority.
//
// The head's lookup always returns Continue for the reason in the file
// docs: returning a borrow out of a Mutex<BTreeMap> is awkward and
// for ACL the head-write -> read latency of "one rotation interval"
// is acceptable.  Higher-rate consumers will need a Slot-published
// head and probably a Layer GAT.
// ---------------------------------------------------------------------------

struct AclHead {
    rules: Mutex<BTreeMap<Priority, AclRule>>,
}

impl AclHead {
    fn empty() -> Self {
        Self {
            rules: Mutex::new(BTreeMap::new()),
        }
    }
}

impl Layer for AclHead {
    type Input = Headers;
    type Output = AclRule;

    fn lookup(&self, _headers: &Headers) -> Outcome<&AclRule> {
        Outcome::Continue
    }
}

#[derive(Debug, Clone, Copy)]
enum AclOp {
    Install(AclRule),
}

impl MutableHead for AclHead {
    type Op = AclOp;
    type Sealed = AclSealed;

    fn write(&self, op: AclOp) {
        let AclOp::Install(rule) = op;
        let mut guard = self.rules.lock().expect("acl head mutex poisoned");
        // Last-writer-wins on collision at the same priority.
        // Realistic ACL would either reject or version-tag here;
        // we keep this minimal for the trait-shape demo.
        guard.insert(rule.priority, rule);
    }

    fn seal(&self) -> AclSealed {
        let guard = self.rules.lock().expect("acl head mutex poisoned");
        AclSealed::from_rules(guard.values().copied())
    }

    fn approx_size(&self) -> usize {
        self.rules.lock().expect("acl head mutex poisoned").len()
    }
}

// ---------------------------------------------------------------------------
// MergeInto: fuse self (a sealed layer) into a copy of target (the tail).
// Per-priority dedupe with self's rules winning -- mirrors the cascade
// walk's "newer wins" semantic, since the cascade folds oldest-first
// and self is always newer than target by the time we're invoked.
// ---------------------------------------------------------------------------

impl MergeInto<AclSealed> for AclSealed {
    fn merge_into(&self, target: &AclSealed) -> AclSealed {
        let mut by_priority: BTreeMap<Priority, AclRule> = BTreeMap::new();
        // Seed from target first.
        for r in &target.rules {
            by_priority.insert(r.priority, *r);
        }
        // Overlay self's rules; collisions favor self.
        for r in &self.rules {
            by_priority.insert(r.priority, *r);
        }
        AclSealed::from_rules(by_priority.into_values())
    }
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

fn ip(s: &str) -> Ipv4Addr {
    s.parse().expect("valid ipv4")
}

fn rule(prio: u32, m: Match, action: Action) -> AclRule {
    AclRule {
        priority: Priority(prio),
        matches: m,
        action,
    }
}

fn allow_any() -> AclRule {
    rule(
        u32::MAX,
        Match {
            src_ip: None,
            dst_ip: None,
            dst_port: None,
        },
        Action::Allow,
    )
}

fn classify(c: &Cascade<AclHead, AclSealed, AclSealed>, headers: &Headers) -> Option<Action> {
    c.snapshot().lookup(headers).map(|r| r.action)
}

fn pkt(src: &str, dst: &str, port: u16) -> Headers {
    Headers {
        src_ip: ip(src),
        dst_ip: ip(dst),
        dst_port: port,
    }
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[test]
fn empty_cascade_returns_no_match() {
    let c = Cascade::new(AclHead::empty(), AclSealed::from_rules([]));
    assert_eq!(classify(&c, &pkt("10.0.0.1", "10.0.0.2", 80)), None);
}

#[test]
fn default_allow_in_tail_matches() {
    let c = Cascade::new(AclHead::empty(), AclSealed::from_rules([allow_any()]));
    assert_eq!(
        classify(&c, &pkt("10.0.0.1", "10.0.0.2", 80)),
        Some(Action::Allow)
    );
}

#[test]
fn install_rule_takes_effect_after_rotation() {
    let c = Cascade::new(AclHead::empty(), AclSealed::from_rules([allow_any()]));
    let pkt_22 = pkt("10.0.0.1", "10.0.0.2", 22);

    // Before rotate: head holds the rule but Layer::lookup on the
    // head always returns Continue.  Classification falls through to
    // the tail (allow_any) and returns Allow.
    c.write(AclOp::Install(rule(
        10,
        Match {
            src_ip: None,
            dst_ip: None,
            dst_port: Some(22),
        },
        Action::Drop,
    )));
    assert_eq!(classify(&c, &pkt_22), Some(Action::Allow));

    // After rotate: the head's contents are in a sealed layer that
    // does walk its rules; the drop rule fires first by priority.
    c.rotate(AclHead::empty);
    assert_eq!(classify(&c, &pkt_22), Some(Action::Drop));
}

#[test]
fn higher_precedence_rule_shadows_lower() {
    let c = Cascade::new(AclHead::empty(), AclSealed::from_rules([allow_any()]));

    // Drop all traffic to port 22 (priority 100).
    c.write(AclOp::Install(rule(
        100,
        Match {
            src_ip: None,
            dst_ip: None,
            dst_port: Some(22),
        },
        Action::Drop,
    )));
    c.rotate(AclHead::empty);
    assert_eq!(
        classify(&c, &pkt("10.0.0.1", "10.0.0.2", 22)),
        Some(Action::Drop)
    );

    // Then allow traffic to port 22 from 10.0.0.1 specifically
    // (priority 50 -- higher precedence).
    c.write(AclOp::Install(rule(
        50,
        Match {
            src_ip: Some(ip("10.0.0.1")),
            dst_ip: None,
            dst_port: Some(22),
        },
        Action::Allow,
    )));
    c.rotate(AclHead::empty);

    // Allowlisted source: hits the higher-precedence Allow.
    assert_eq!(
        classify(&c, &pkt("10.0.0.1", "10.0.0.2", 22)),
        Some(Action::Allow)
    );
    // Non-allowlisted source: still hits the lower-precedence Drop.
    assert_eq!(
        classify(&c, &pkt("10.0.0.5", "10.0.0.2", 22)),
        Some(Action::Drop)
    );
}

#[test]
fn cascade_walk_respects_sealed_order() {
    // Build up a multi-layer cascade and verify the cascade walks
    // newest sealed first.  Same priority value in two layers means
    // the newer wins because the cascade short-circuits on first
    // match.
    let c = Cascade::new(AclHead::empty(), AclSealed::from_rules([allow_any()]));

    // Older rotation: drop port 22 at priority 100.
    c.write(AclOp::Install(rule(
        100,
        Match {
            src_ip: None,
            dst_ip: None,
            dst_port: Some(22),
        },
        Action::Drop,
    )));
    c.rotate(AclHead::empty);

    // Newer rotation: allow port 22 at priority 100 (overrides the
    // older drop rule because newer-sealed comes first in the walk).
    c.write(AclOp::Install(rule(
        100,
        Match {
            src_ip: None,
            dst_ip: None,
            dst_port: Some(22),
        },
        Action::Allow,
    )));
    c.rotate(AclHead::empty);

    assert_eq!(
        classify(&c, &pkt("10.0.0.1", "10.0.0.2", 22)),
        Some(Action::Allow)
    );
}

#[test]
fn compact_collapses_layers_preserving_precedence() {
    let c = Cascade::new(AclHead::empty(), AclSealed::from_rules([allow_any()]));

    // Three rotations, each introducing a rule at decreasing
    // priority value (increasing precedence).
    for (prio, action) in [
        (300, Action::Drop),
        (200, Action::Drop),
        (100, Action::Allow),
    ] {
        c.write(AclOp::Install(rule(
            prio,
            Match {
                src_ip: None,
                dst_ip: None,
                dst_port: Some(22),
            },
            action,
        )));
        c.rotate(AclHead::empty);
    }
    assert_eq!(c.sealed_depth(), 3);

    // The walk before compaction: newest-first -> Allow at 100 wins.
    let pre = pkt("10.0.0.1", "10.0.0.2", 22);
    assert_eq!(classify(&c, &pre), Some(Action::Allow));

    // Compact: keep 1 sealed layer, fold the rest into the tail.
    c.compact(1);
    assert_eq!(c.sealed_depth(), 1);

    // Walk after compaction: Allow at 100 still wins, but now from
    // a fused-into-tail position.
    assert_eq!(classify(&c, &pre), Some(Action::Allow));
}

// ---------------------------------------------------------------------------
// Open design questions surfaced by this slice.
//
// 1. Tombstones for rule removal.
//    The cascade's `Outcome::Forbid` tombstone is keyed by the
//    layer's `Input` type.  For an exact-match map keyed by `K`,
//    tombstoning key `K` is well-defined: "this key is officially
//    absent."  For ACL the lookup `Input` is packet headers and
//    rules are identified by priority -- not by the input.
//    Tombstoning a rule means "this RULE is gone," not "this PACKET
//    is forbidden."
//
//    The acl-stack `update.rs` solution: when removing a rule, the
//    delta layer gets a SHADOW rule with the same match expression
//    and the table's default action, at a precedence that shadows
//    the original.  Lower layers still have the original; the
//    shadow short-circuits the walk before reaching it.
//
//    This is fine but means the head's `Op::Remove` must carry
//    enough information to synthesise a shadow rule -- which means
//    the head needs to know the original rule's match expression,
//    which it does not (the rule lives in a lower layer the head
//    cannot see).  Solutions:
//
//      - `Op::Remove` carries the rule's match expression (caller
//        responsibility to keep that around).
//      - The cascade exposes a `lookup_rule_by_priority(priority)`
//        accessor that the seal step uses to synthesise shadows.
//      - Removes are deferred to a separate compaction step that
//        does have full visibility.
//
//    Worth a follow-on session.
//
// 2. Head readability under high write rate.
//    The head's `Layer::lookup` returning `Continue` here is acceptable
//    for ACL (writes are rare, "becomes visible at next rotation"
//    is fine).  For conntrack-shaped consumers it is NOT
//    acceptable -- new flow entries need to be readable
//    immediately by the same lcore that wrote them.  That probably
//    means the head's lookup needs to return a borrow into the
//    head's internal storage, which means Layer::Output needs to
//    accommodate borrows that are not `&Self::Output`-tied-to-
//    `&self`.  Hello GAT.
//
// 3. The `Op` shape feels right.
//    `Op::Install(AclRule)` is a single-valued enum here because we
//    only support install.  Adding remove/replace turns it into a
//    richer enum, which is fine.  The `MutableHead::Op` and
//    `Absorb::Op` distinction we drew earlier remains useful: the
//    head decomposes its `Op` into per-key absorb-able pieces.
// ---------------------------------------------------------------------------
