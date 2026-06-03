// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(clippy::expect_used)]

use concurrency::sync::Mutex;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use dataplane_cascade::{Cascade, Lookup, MergeInto, MutableHead};

mod common;
use common::GenAlloc;

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

#[derive(Debug, Clone)]
struct AclFrozen {
    rules: Vec<AclRule>,
}

impl AclFrozen {
    fn from_rules<I: IntoIterator<Item = AclRule>>(it: I) -> Self {
        let mut rules: Vec<AclRule> = it.into_iter().collect();
        rules.sort_by_key(|r| r.priority);
        Self { rules }
    }
}

impl Lookup<Headers, AclRule> for AclFrozen {
    fn lookup(&self, headers: &Headers) -> Option<&AclRule> {
        self.rules.iter().find(|r| r.matches.matches(headers))
    }
}

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

impl Lookup<Headers, AclRule> for AclHead {
    fn lookup(&self, _headers: &Headers) -> Option<&AclRule> {
        None
    }
}

#[derive(Debug, Clone, Copy)]
enum AclOp {
    Install(AclRule),
}

impl MutableHead for AclHead {
    type Key = Headers;
    type Action = AclRule;
    type Op = AclOp;
    type Frozen = AclFrozen;

    fn write(&self, op: AclOp) {
        let AclOp::Install(rule) = op;
        let mut guard = self.rules.lock();
        guard.insert(rule.priority, rule);
    }

    fn freeze(&self) -> AclFrozen {
        let guard = self.rules.lock();
        AclFrozen::from_rules(guard.values().copied())
    }

    fn approx_size(&self) -> usize {
        self.rules.lock().len()
    }
}

impl MergeInto<AclFrozen> for AclFrozen {
    fn merge_into(&self, target: &AclFrozen) -> AclFrozen {
        let mut by_priority: BTreeMap<Priority, AclRule> = BTreeMap::new();
        for r in &target.rules {
            by_priority.insert(r.priority, *r);
        }
        for r in &self.rules {
            by_priority.insert(r.priority, *r);
        }
        AclFrozen::from_rules(by_priority.into_values())
    }
}

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

fn classify(c: &Cascade<AclHead, AclFrozen, AclFrozen>, headers: &Headers) -> Option<Action> {
    c.snapshot().lookup(headers).map(|r| r.action)
}

fn pkt(src: &str, dst: &str, port: u16) -> Headers {
    Headers {
        src_ip: ip(src),
        dst_ip: ip(dst),
        dst_port: port,
    }
}

#[test]
fn empty_cascade_returns_no_match() {
    let c = Cascade::new(AclHead::empty(), AclFrozen::from_rules([]));
    assert_eq!(classify(&c, &pkt("10.0.0.1", "10.0.0.2", 80)), None);
}

#[test]
fn default_allow_in_tail_matches() {
    let c = Cascade::new(AclHead::empty(), AclFrozen::from_rules([allow_any()]));
    assert_eq!(
        classify(&c, &pkt("10.0.0.1", "10.0.0.2", 80)),
        Some(Action::Allow)
    );
}

#[test]
fn install_rule_takes_effect_after_rotation() {
    let c = Cascade::new(AclHead::empty(), AclFrozen::from_rules([allow_any()]));
    let mut g_alloc = GenAlloc::new();
    let pkt_22 = pkt("10.0.0.1", "10.0.0.2", 22);
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
    c.rotate(g_alloc.next(), AclHead::empty);
    assert_eq!(classify(&c, &pkt_22), Some(Action::Drop));
}

#[test]
fn higher_precedence_rule_shadows_lower() {
    let c = Cascade::new(AclHead::empty(), AclFrozen::from_rules([allow_any()]));
    let mut g_alloc = GenAlloc::new();
    c.write(AclOp::Install(rule(
        100,
        Match {
            src_ip: None,
            dst_ip: None,
            dst_port: Some(22),
        },
        Action::Drop,
    )));
    c.rotate(g_alloc.next(), AclHead::empty);
    assert_eq!(
        classify(&c, &pkt("10.0.0.1", "10.0.0.2", 22)),
        Some(Action::Drop)
    );
    c.write(AclOp::Install(rule(
        50,
        Match {
            src_ip: Some(ip("10.0.0.1")),
            dst_ip: None,
            dst_port: Some(22),
        },
        Action::Allow,
    )));
    c.rotate(g_alloc.next(), AclHead::empty);
    assert_eq!(
        classify(&c, &pkt("10.0.0.1", "10.0.0.2", 22)),
        Some(Action::Allow)
    );
    assert_eq!(
        classify(&c, &pkt("10.0.0.5", "10.0.0.2", 22)),
        Some(Action::Drop)
    );
}

#[test]
fn cascade_walk_respects_sealed_order() {
    let c = Cascade::new(AclHead::empty(), AclFrozen::from_rules([allow_any()]));
    let mut g_alloc = GenAlloc::new();
    c.write(AclOp::Install(rule(
        100,
        Match {
            src_ip: None,
            dst_ip: None,
            dst_port: Some(22),
        },
        Action::Drop,
    )));
    c.rotate(g_alloc.next(), AclHead::empty);
    c.write(AclOp::Install(rule(
        100,
        Match {
            src_ip: None,
            dst_ip: None,
            dst_port: Some(22),
        },
        Action::Allow,
    )));
    c.rotate(g_alloc.next(), AclHead::empty);

    assert_eq!(
        classify(&c, &pkt("10.0.0.1", "10.0.0.2", 22)),
        Some(Action::Allow)
    );
}

#[test]
fn compact_collapses_layers_preserving_precedence() {
    let c = Cascade::new(AclHead::empty(), AclFrozen::from_rules([allow_any()]));
    let mut g_alloc = GenAlloc::new();
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
        c.rotate(g_alloc.next(), AclHead::empty);
    }
    assert_eq!(c.frozen_depth(), 3);
    let pre = pkt("10.0.0.1", "10.0.0.2", 22);
    assert_eq!(classify(&c, &pre), Some(Action::Allow));
    c.compact(1);
    assert_eq!(c.frozen_depth(), 1);
    assert_eq!(classify(&c, &pre), Some(Action::Allow));
}
