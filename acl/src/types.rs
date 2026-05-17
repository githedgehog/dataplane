// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Core ACL types: priority, action, match expression, rule, headers.
//!
//! This module is deliberately self-contained -- it does not depend
//! on `net::headers::Headers`.  The intent is to land the
//! cascade-based ACL machinery with a minimal, locally-owned packet
//! representation, then graduate to the workspace's
//! `net::headers::Headers` in a follow-on commit once the cascade
//! integration is settled.  The local `Headers` type below is a
//! placeholder shaped to match `net::headers::Headers`' usage
//! pattern (matchable fields per layer); the swap should be
//! contained to the [`Match::matches`] body.

use core::cmp::Ordering;
use core::net::Ipv4Addr;

/// Priority ordering for ACL rules.
///
/// Lower numerical value means **higher** precedence -- this matches
/// the convention used by the workspace's existing ACL work (acl-stack)
/// and most network-rule systems (e.g. iptables `--rule-num`).  The
/// cascade walks rules in priority order and returns on the first
/// match; the lowest-numbered matching rule wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Priority(pub u32);

impl PartialOrd for Priority {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Priority {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

/// What the ACL says to do with a packet that matches a rule.
///
/// This first slice supports the two minimal terminal actions.
/// Real-world ACLs need many more (Redirect, Count, Log, Trap, ...);
/// each of those becomes a new variant.  The cascade does not care
/// about action semantics -- it just returns the matched rule's
/// `Action` to the consumer to interpret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Forward the packet onward through the pipeline.
    Allow,
    /// Drop the packet.
    Drop,
}

/// IP protocol numbers we support matching on.
///
/// Closed enum so the match-expression code can stay exhaustive.
/// Will grow to a richer set (covering `ICMPv6`, SCTP, etc.) when a
/// real consumer demands it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

/// A minimal packet-header view that the ACL classifier matches against.
///
/// Placeholder for `net::headers::Headers`.  See the module-level
/// docstring -- this exists so the ACL crate can land with a clean
/// internal API and graduate to the workspace's full headers
/// representation in a follow-on commit.  The field set is
/// deliberately small: enough to exercise multi-field matching but
/// not enough to drag in the full workspace dependency tree on the
/// first pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Headers {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub protocol: Protocol,
    /// Set to `0` for ICMP (which has no port concept); ignored by
    /// rules that do not match on port.
    pub src_port: u16,
    pub dst_port: u16,
}

/// Match expression: a conjunction of field predicates.
///
/// Each field is independently `None` (wildcard, always matches) or
/// `Some(predicate)` (must match the value).  Empty matches (all
/// fields `None`) match every packet.  This shape matches the
/// "exact match or wildcard" pattern most ACL frameworks expose; richer
/// patterns (ranges, prefixes, masked addresses) become richer field
/// types when needed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Match {
    pub src_ip: Option<Ipv4Addr>,
    pub dst_ip: Option<Ipv4Addr>,
    pub protocol: Option<Protocol>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

impl Match {
    /// Empty match -- wildcards every field.  Matches any packet.
    #[must_use]
    pub fn any() -> Self {
        Self::default()
    }

    /// Test the match expression against a packet's headers.
    ///
    /// Each field is checked independently; if any non-wildcard
    /// field disagrees with the packet, the match fails.  All
    /// non-wildcard fields must agree for the match to succeed.
    ///
    /// This is the per-rule cost of a classify call; for a linear
    /// classifier it dominates the cascade walk's runtime.  Future
    /// optimisations (DPDK ACL, two-tier compilation) move this work
    /// into specialised data structures while preserving the same
    /// semantics.
    #[must_use]
    pub fn matches(&self, headers: &Headers) -> bool {
        self.src_ip.is_none_or(|ip| ip == headers.src_ip)
            && self.dst_ip.is_none_or(|ip| ip == headers.dst_ip)
            && self.protocol.is_none_or(|p| p == headers.protocol)
            && self.src_port.is_none_or(|p| p == headers.src_port)
            && self.dst_port.is_none_or(|p| p == headers.dst_port)
    }
}

/// A single rule: priority, match expression, action.
///
/// `Clone` and `Copy` because rules are small and the cascade
/// machinery copies them freely during seal / compact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AclRule {
    pub priority: Priority,
    pub matches: Match,
    pub action: Action,
}

impl AclRule {
    /// Convenience constructor.
    #[must_use]
    pub fn new(priority: Priority, matches: Match, action: Action) -> Self {
        Self {
            priority,
            matches,
            action,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().expect("valid ipv4 literal")
    }

    fn pkt() -> Headers {
        Headers {
            src_ip: ip("10.0.0.1"),
            dst_ip: ip("10.0.0.2"),
            protocol: Protocol::Tcp,
            src_port: 12345,
            dst_port: 80,
        }
    }

    #[test]
    fn any_matches_everything() {
        assert!(Match::any().matches(&pkt()));
    }

    #[test]
    fn single_field_match() {
        let m = Match {
            dst_port: Some(80),
            ..Match::any()
        };
        assert!(m.matches(&pkt()));
    }

    #[test]
    fn single_field_mismatch_rejects() {
        let m = Match {
            dst_port: Some(22),
            ..Match::any()
        };
        assert!(!m.matches(&pkt()));
    }

    #[test]
    fn conjunction_requires_all_fields() {
        let m = Match {
            src_ip: Some(ip("10.0.0.1")),
            dst_port: Some(80),
            ..Match::any()
        };
        assert!(m.matches(&pkt()));

        let m_mismatch = Match {
            src_ip: Some(ip("10.0.0.1")),
            dst_port: Some(22), // does not agree
            ..Match::any()
        };
        assert!(!m_mismatch.matches(&pkt()));
    }

    #[test]
    fn priority_lower_is_higher_precedence() {
        // Sanity: Ord on Priority sorts ascending, which means the
        // lowest-value Priority comes first in iteration order.
        // That is "highest precedence" by the convention documented
        // on Priority.
        let mut priorities = vec![Priority(300), Priority(100), Priority(200)];
        priorities.sort();
        assert_eq!(
            priorities,
            vec![Priority(100), Priority(200), Priority(300)]
        );
    }
}
