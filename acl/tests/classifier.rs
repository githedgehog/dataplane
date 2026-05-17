// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! End-to-end tests for the `Classifier` API.
//!
//! Exercises the public surface (`classify`, `install`, `rotate`,
//! `compact`, `snapshot`) against scenarios that mirror how a real
//! ACL consumer would drive the classifier: install rules, rotate
//! to make them visible, classify traffic, occasionally compact.
//!
//! These tests do NOT poke into the cascade internals -- they only
//! use the public API.  That is deliberate: it pins the consumer
//! contract that ACL users will program against and surfaces any
//! ergonomics gaps as test friction.

#![allow(clippy::expect_used)]

use core::net::Ipv4Addr;

use dataplane_acl::{AclRule, Action, Classifier, Headers, Match, Priority, Protocol};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ip(s: &str) -> Ipv4Addr {
    s.parse().expect("valid ipv4")
}

fn pkt(src: &str, dst: &str, proto: Protocol, src_port: u16, dst_port: u16) -> Headers {
    Headers {
        src_ip: ip(src),
        dst_ip: ip(dst),
        protocol: proto,
        src_port,
        dst_port,
    }
}

fn rule(prio: u32, m: Match, action: Action) -> AclRule {
    AclRule::new(Priority(prio), m, action)
}

fn match_dst_port(port: u16) -> Match {
    Match {
        dst_port: Some(port),
        ..Match::any()
    }
}

// ---------------------------------------------------------------------------
// Classify with no rules returns the default action
// ---------------------------------------------------------------------------

#[test]
fn empty_classifier_returns_default_action() {
    let c = Classifier::new(Action::Drop);
    assert_eq!(
        c.classify(&pkt("10.0.0.1", "10.0.0.2", Protocol::Tcp, 12345, 80)),
        Action::Drop
    );

    let c_allow = Classifier::new(Action::Allow);
    assert_eq!(
        c_allow.classify(&pkt("10.0.0.1", "10.0.0.2", Protocol::Tcp, 12345, 80)),
        Action::Allow
    );
}

// ---------------------------------------------------------------------------
// Install + rotate makes the rule visible
// ---------------------------------------------------------------------------

#[test]
fn install_alone_is_not_yet_visible() {
    let c = Classifier::new(Action::Allow);
    let target = pkt("10.0.0.1", "10.0.0.2", Protocol::Tcp, 12345, 22);

    // Install a rule that would drop SSH traffic, but DO NOT rotate.
    c.install(rule(100, match_dst_port(22), Action::Drop));

    // The head's lookup returns Continue, so the rule is invisible
    // to classify until the next rotate.  Default action wins.
    assert_eq!(c.classify(&target), Action::Allow);
}

#[test]
fn install_then_rotate_makes_rule_visible() {
    let c = Classifier::new(Action::Allow);
    let target = pkt("10.0.0.1", "10.0.0.2", Protocol::Tcp, 12345, 22);

    c.install(rule(100, match_dst_port(22), Action::Drop));
    c.rotate();

    assert_eq!(c.classify(&target), Action::Drop);
    assert_eq!(c.frozen_depth(), 1);
}

// ---------------------------------------------------------------------------
// Priority precedence: lower number wins
// ---------------------------------------------------------------------------

#[test]
fn lower_priority_value_shadows_higher_value() {
    let c = Classifier::new(Action::Drop);
    let target = pkt("10.0.0.1", "10.0.0.2", Protocol::Tcp, 12345, 22);

    // High-priority value (lower precedence) Drop rule.
    c.install(rule(200, match_dst_port(22), Action::Drop));
    c.rotate();
    assert_eq!(c.classify(&target), Action::Drop);

    // Low-priority value (higher precedence) Allow rule for the
    // same traffic.
    c.install(rule(50, match_dst_port(22), Action::Allow));
    c.rotate();
    assert_eq!(c.classify(&target), Action::Allow);
}

// ---------------------------------------------------------------------------
// Multi-field matching: src IP narrowing
// ---------------------------------------------------------------------------

#[test]
fn src_ip_narrows_rule_to_allowlist() {
    let c = Classifier::new(Action::Drop);

    // Allow SSH from 10.0.0.1 only.
    c.install(rule(
        50,
        Match {
            src_ip: Some(ip("10.0.0.1")),
            dst_port: Some(22),
            ..Match::any()
        },
        Action::Allow,
    ));
    c.rotate();

    // Matches the allowlist source.
    assert_eq!(
        c.classify(&pkt("10.0.0.1", "10.0.0.2", Protocol::Tcp, 12345, 22)),
        Action::Allow
    );

    // Different source: falls through to default Drop.
    assert_eq!(
        c.classify(&pkt("10.0.0.5", "10.0.0.2", Protocol::Tcp, 12345, 22)),
        Action::Drop
    );
}

// ---------------------------------------------------------------------------
// Multi-rule cascade: head + multiple sealed layers + tail
// ---------------------------------------------------------------------------

#[test]
fn rules_from_multiple_rotations_compose_correctly() {
    let c = Classifier::new(Action::Drop);

    // Rotation 1: allow SSH.
    c.install(rule(100, match_dst_port(22), Action::Allow));
    c.rotate();

    // Rotation 2: allow HTTP.
    c.install(rule(100, match_dst_port(80), Action::Allow));
    c.rotate();

    // Rotation 3: drop telnet (would have been default-dropped anyway,
    // but this rule documents intent).
    c.install(rule(100, match_dst_port(23), Action::Drop));
    c.rotate();

    assert_eq!(c.frozen_depth(), 3);

    let ssh = pkt("10.0.0.1", "10.0.0.2", Protocol::Tcp, 12345, 22);
    let http = pkt("10.0.0.1", "10.0.0.2", Protocol::Tcp, 12345, 80);
    let telnet = pkt("10.0.0.1", "10.0.0.2", Protocol::Tcp, 12345, 23);
    let dns = pkt("10.0.0.1", "10.0.0.2", Protocol::Udp, 12345, 53);

    assert_eq!(c.classify(&ssh), Action::Allow);
    assert_eq!(c.classify(&http), Action::Allow);
    assert_eq!(c.classify(&telnet), Action::Drop);
    assert_eq!(c.classify(&dns), Action::Drop); // default
}

// ---------------------------------------------------------------------------
// Compaction preserves classification semantics
// ---------------------------------------------------------------------------

#[test]
fn compact_preserves_classification_results() {
    let c = Classifier::new(Action::Drop);

    // Install three distinct rules across three rotations.
    for (prio, port, action) in [
        (300, 22, Action::Allow),
        (200, 80, Action::Allow),
        (100, 443, Action::Allow),
    ] {
        c.install(rule(prio, match_dst_port(port), action));
        c.rotate();
    }
    assert_eq!(c.frozen_depth(), 3);

    // Sample classifications BEFORE compaction.
    let before = [
        c.classify(&pkt("a", 22)),
        c.classify(&pkt("a", 80)),
        c.classify(&pkt("a", 443)),
        c.classify(&pkt("a", 25)),
    ];

    // Compact down to one sealed layer; the others fold into tail.
    c.compact(1);
    assert_eq!(c.frozen_depth(), 1);

    // Same classifications AFTER compaction.
    let after = [
        c.classify(&pkt("a", 22)),
        c.classify(&pkt("a", 80)),
        c.classify(&pkt("a", 443)),
        c.classify(&pkt("a", 25)),
    ];

    assert_eq!(before, after);
    assert_eq!(
        after,
        [Action::Allow, Action::Allow, Action::Allow, Action::Drop]
    );

    // Local helper so this test doesn't have to spell out every field.
    fn pkt(_src: &str, port: u16) -> Headers {
        Headers {
            src_ip: ip("10.0.0.1"),
            dst_ip: ip("10.0.0.2"),
            protocol: Protocol::Tcp,
            src_port: 12345,
            dst_port: port,
        }
    }
}

// ---------------------------------------------------------------------------
// Snapshot held across rotation pins the old composition
// ---------------------------------------------------------------------------

#[test]
fn snapshot_held_across_rotation_pins_old_state() {
    let c = Classifier::new(Action::Drop);
    let target = pkt("10.0.0.1", "10.0.0.2", Protocol::Tcp, 12345, 22);

    // Install and rotate an Allow rule.
    c.install(rule(100, match_dst_port(22), Action::Allow));
    c.rotate();
    let snap = c.snapshot();
    assert_eq!(snap.lookup(&target).map(|r| r.action), Some(Action::Allow),);

    // Now install and rotate a higher-precedence Drop rule.
    c.install(rule(50, match_dst_port(22), Action::Drop));
    c.rotate();

    // The held snapshot continues to see the pre-second-rotate
    // state (Allow wins because there is no higher-priority Drop
    // in its sealed-vec Arc).  Fresh snapshot sees the new Drop.
    assert_eq!(snap.lookup(&target).map(|r| r.action), Some(Action::Allow),);
    assert_eq!(c.classify(&target), Action::Drop);
}
