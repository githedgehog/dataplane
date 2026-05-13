// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Rule overlap detection.
//!
//! Two ACL rules **overlap** if there exists a packet that matches both.
//! Overlap detection is a compiler pass that runs before backend
//! compilation  --  backends that don't tolerate overlapping rules need
//! this analysis to partition or reject the rule set.
//!
//! # Algorithm
//!
//! Per-dimension decomposition: two rules overlap iff ALL their
//! individual field dimensions overlap.  Each dimension has a simple
//! overlap test:
//!
//! - **Ignore × anything**: always overlaps (wildcard)
//! - **Exact × exact**: overlaps iff values are equal
//! - **Prefix × prefix**: overlaps iff the prefixes share any address
//! - **Range × range**: overlaps iff the ranges intersect
//!
//! Two rules with disjoint match layer types (one is IPv4, the other
//! IPv6) never overlap  --  they can't both match the same packet.

use crate::match_expr::FieldMatch;
use crate::match_fields::{EthMatch, Icmp4Match, Ipv4Match, Ipv6Match, TcpMatch, UdpMatch};
use crate::metadata::Metadata;
use lpm::prefix::ip::IpPrefixColliding;
use lpm::prefix::{Ipv4Prefix, Ipv6Prefix};
use crate::rule::AclRule;
use std::ops::RangeInclusive;

/// A pair of overlapping rule indices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OverlapPair {
    /// Index of the first rule (lower index).
    pub a: usize,
    /// Index of the second rule (higher index).
    pub b: usize,
}

/// Result of overlap analysis on a rule set.
#[derive(Debug, Clone)]
pub struct OverlapAnalysis {
    /// All pairs of rules whose match fields overlap.
    overlapping_pairs: Vec<OverlapPair>,
}

impl OverlapAnalysis {
    /// The overlapping rule pairs.
    #[must_use]
    pub fn pairs(&self) -> &[OverlapPair] {
        &self.overlapping_pairs
    }

    /// Whether any rules overlap.
    #[must_use]
    pub fn has_overlaps(&self) -> bool {
        !self.overlapping_pairs.is_empty()
    }

    /// Number of overlapping pairs.
    #[must_use]
    pub fn count(&self) -> usize {
        self.overlapping_pairs.len()
    }
}

/// Analyze a set of rules for pairwise overlap.
///
/// Returns all pairs `(i, j)` where `i < j` and rules `i` and `j`
/// have overlapping match fields (there exists a packet that matches
/// both).
///
/// This is O(n²) in the worst case.  For large rule sets, the
/// per-dimension decomposition keeps the constant factor low.
#[must_use]
pub fn analyze_overlaps<M: Metadata>(rules: &[AclRule<M>]) -> OverlapAnalysis {
    let mut pairs = Vec::new();

    for i in 0..rules.len() {
        for j in (i + 1)..rules.len() {
            if rules_overlap(&rules[i], &rules[j]) {
                pairs.push(OverlapPair { a: i, b: j });
            }
        }
    }

    OverlapAnalysis {
        overlapping_pairs: pairs,
    }
}

/// Check whether two rules overlap (could both match the same packet).
fn rules_overlap<M: Metadata>(a: &AclRule<M>, b: &AclRule<M>) -> bool {
    let pa = a.packet_match();
    let pb = b.packet_match();

    // Layer presence: if one rule has an IPv4 match and the other has
    // an IPv6 match, they can never match the same packet.
    if pa.ipv4().is_some() && pb.ipv6().is_some() {
        return false;
    }
    if pa.ipv6().is_some() && pb.ipv4().is_some() {
        return false;
    }

    // TCP vs UDP vs ICMP: if both have transport matches of different
    // types, they can't match the same packet.
    if !transport_compatible(pa.tcp(), pa.udp(), pa.icmp4(), pb.tcp(), pb.udp(), pb.icmp4()) {
        return false;
    }

    // Per-dimension overlap checks.  ALL dimensions must overlap for
    // the rules to overlap.  If any dimension is disjoint, return false.
    eth_overlaps(pa.eth(), pb.eth())
        && ipv4_overlaps(pa.ipv4(), pb.ipv4())
        && ipv6_overlaps(pa.ipv6(), pb.ipv6())
        && tcp_overlaps(pa.tcp(), pb.tcp())
        && udp_overlaps(pa.udp(), pb.udp())
        && icmp4_overlaps(pa.icmp4(), pb.icmp4())
}

/// Check if two transport layer combinations are compatible
/// (could match the same packet).
fn transport_compatible(
    a_tcp: Option<&TcpMatch>,
    a_udp: Option<&UdpMatch>,
    a_icmp: Option<&Icmp4Match>,
    b_tcp: Option<&TcpMatch>,
    b_udp: Option<&UdpMatch>,
    b_icmp: Option<&Icmp4Match>,
) -> bool {
    let a_type = transport_type(a_tcp.is_some(), a_udp.is_some(), a_icmp.is_some());
    let b_type = transport_type(b_tcp.is_some(), b_udp.is_some(), b_icmp.is_some());

    // None = no transport constraint → compatible with anything.
    // Same type → compatible (individual fields checked later).
    // Different types → incompatible.
    match (a_type, b_type) {
        (None, _) | (_, None) => true,
        (Some(a), Some(b)) => a == b,
    }
}

#[derive(PartialEq, Eq)]
enum TransportKind {
    Tcp,
    Udp,
    Icmp4,
}

fn transport_type(tcp: bool, udp: bool, icmp: bool) -> Option<TransportKind> {
    if tcp {
        Some(TransportKind::Tcp)
    } else if udp {
        Some(TransportKind::Udp)
    } else if icmp {
        Some(TransportKind::Icmp4)
    } else {
        None
    }
}

// ---- Per-dimension overlap checks ----
//
// Each function checks whether two match layers overlap in their
// respective dimensions.  If either layer is absent (None), the
// dimension is unconstrained → overlaps with anything.

fn eth_overlaps(a: Option<&EthMatch>, b: Option<&EthMatch>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => field_match_overlaps_exact(&a.ether_type, &b.ether_type),
        _ => true, // one or both absent → unconstrained
    }
}

fn ipv4_overlaps(a: Option<&Ipv4Match>, b: Option<&Ipv4Match>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => {
            field_match_overlaps_exact(&a.protocol, &b.protocol)
                && field_match_overlaps_prefix_v4(a.src, b.src)
                && field_match_overlaps_prefix_v4(a.dst, b.dst)
        }
        _ => true,
    }
}

fn ipv6_overlaps(a: Option<&Ipv6Match>, b: Option<&Ipv6Match>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => {
            field_match_overlaps_exact(&a.protocol, &b.protocol)
                && field_match_overlaps_prefix_v6(&a.src, &b.src)
                && field_match_overlaps_prefix_v6(&a.dst, &b.dst)
        }
        _ => true,
    }
}

fn tcp_overlaps(a: Option<&TcpMatch>, b: Option<&TcpMatch>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => {
            field_match_overlaps_range(&a.src, &b.src) && field_match_overlaps_range(&a.dst, &b.dst)
        }
        _ => true,
    }
}

fn udp_overlaps(a: Option<&UdpMatch>, b: Option<&UdpMatch>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => {
            field_match_overlaps_range(&a.src, &b.src) && field_match_overlaps_range(&a.dst, &b.dst)
        }
        _ => true,
    }
}

fn icmp4_overlaps(a: Option<&Icmp4Match>, b: Option<&Icmp4Match>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => {
            field_match_overlaps_exact(&a.icmp_type, &b.icmp_type)
                && field_match_overlaps_exact(&a.icmp_code, &b.icmp_code)
        }
        _ => true,
    }
}

// ---- Generic field overlap helpers ----

/// Exact-match fields overlap iff both are Ignore, or at least one is
/// Ignore, or their values are equal.
fn field_match_overlaps_exact<T: PartialEq>(a: &FieldMatch<T>, b: &FieldMatch<T>) -> bool {
    match (a.as_option(), b.as_option()) {
        (None, _) | (_, None) => true, // Ignore → overlaps with anything
        (Some(va), Some(vb)) => va == vb,
    }
}

/// IPv4 prefix fields overlap iff the prefixes share any address.
fn field_match_overlaps_prefix_v4(
    a: FieldMatch<Ipv4Prefix>,
    b: FieldMatch<Ipv4Prefix>,
) -> bool {
    match (a.as_option(), b.as_option()) {
        (None, _) | (_, None) => true,
        (Some(pa), Some(pb)) => prefixes_overlap_v4(pa, pb),
    }
}

/// IPv6 prefix fields overlap iff the prefixes share any address.
fn field_match_overlaps_prefix_v6(
    a: &FieldMatch<Ipv6Prefix>,
    b: &FieldMatch<Ipv6Prefix>,
) -> bool {
    match (a.as_option(), b.as_option()) {
        (None, _) | (_, None) => true,
        (Some(pa), Some(pb)) => prefixes_overlap_v6(pa, pb),
    }
}

/// Range fields overlap iff the ranges intersect.
fn field_match_overlaps_range<T: Ord>(a: &FieldMatch<RangeInclusive<T>>, b: &FieldMatch<RangeInclusive<T>>) -> bool {
    match (a.as_option(), b.as_option()) {
        (None, _) | (_, None) => true,
        (Some(ra), Some(rb)) => ra.start() <= rb.end() && rb.start() <= ra.end(),
    }
}

// ---- Prefix overlap helpers ----

/// Two IPv4 prefixes overlap iff one contains the other (or they're
/// identical).  More precisely: the longer prefix's network address
/// must fall within the shorter prefix.
fn prefixes_overlap_v4(a: &Ipv4Prefix, b: &Ipv4Prefix) -> bool {
    a.collides_with(b)
}

/// Two IPv6 prefixes overlap (same logic as IPv4).
fn prefixes_overlap_v6(a: &Ipv6Prefix, b: &Ipv6Prefix) -> bool {
    a.collides_with(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AclRuleBuilder, FieldMatch, Priority};
    use lpm::prefix::IpPrefix;
    use std::net::Ipv4Addr;

    fn pri(n: u32) -> Priority {
        Priority::new(n).unwrap()
    }

    #[test]
    fn identical_rules_overlap() {
        let r = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.src =
                    FieldMatch::Select(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
            })
            .tcp(|tcp| {
                tcp.dst = FieldMatch::Select(80u16..=80u16);
            })
            .permit(pri(100));

        let r2 = r.clone();
        let analysis = analyze_overlaps(&[r, r2]);
        assert!(analysis.has_overlaps());
        assert_eq!(analysis.count(), 1);
        assert_eq!(analysis.pairs()[0], OverlapPair { a: 0, b: 1 });
    }

    #[test]
    fn disjoint_prefixes_do_not_overlap() {
        let r1 = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.src =
                    FieldMatch::Select(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
            })
            .permit(pri(100));

        let r2 = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.src = FieldMatch::Select(
                    Ipv4Prefix::new(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap(),
                );
            })
            .deny(pri(200));

        let analysis = analyze_overlaps(&[r1, r2]);
        assert!(!analysis.has_overlaps());
    }

    #[test]
    fn nested_prefixes_overlap() {
        // 10.0.0.0/8 contains 10.1.0.0/16
        let r1 = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.src =
                    FieldMatch::Select(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
            })
            .permit(pri(100));

        let r2 = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.src =
                    FieldMatch::Select(Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 16).unwrap());
            })
            .deny(pri(200));

        let analysis = analyze_overlaps(&[r1, r2]);
        assert!(analysis.has_overlaps());
    }

    #[test]
    fn ipv4_vs_ipv6_never_overlap() {
        let r1 = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .permit(pri(100));

        let r2 = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv6(|_| {})
            .deny(pri(200));

        let analysis = analyze_overlaps(&[r1, r2]);
        assert!(!analysis.has_overlaps());
    }

    #[test]
    fn tcp_vs_udp_never_overlap() {
        let r1 = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .tcp(|_| {})
            .permit(pri(100));

        let r2 = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .udp(|_| {})
            .deny(pri(200));

        let analysis = analyze_overlaps(&[r1, r2]);
        assert!(!analysis.has_overlaps());
    }

    #[test]
    fn disjoint_port_ranges_do_not_overlap() {
        let r1 = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .tcp(|tcp| {
                tcp.dst = FieldMatch::Select(80u16..=89u16);
            })
            .permit(pri(100));

        let r2 = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .tcp(|tcp| {
                tcp.dst = FieldMatch::Select(443u16..=449u16);
            })
            .deny(pri(200));

        let analysis = analyze_overlaps(&[r1, r2]);
        assert!(!analysis.has_overlaps());
    }

    #[test]
    fn overlapping_port_ranges() {
        let r1 = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .tcp(|tcp| {
                tcp.dst = FieldMatch::Select(80u16..=443u16);
            })
            .permit(pri(100));

        let r2 = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .tcp(|tcp| {
                tcp.dst = FieldMatch::Select(200u16..=500u16);
            })
            .deny(pri(200));

        let analysis = analyze_overlaps(&[r1, r2]);
        assert!(analysis.has_overlaps());
    }

    #[test]
    fn wildcard_rule_overlaps_with_everything() {
        let wildcard = AclRuleBuilder::new().permit(pri(1));

        let specific = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.src =
                    FieldMatch::Select(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
            })
            .tcp(|tcp| {
                tcp.dst = FieldMatch::Select(80u16..=80u16);
            })
            .deny(pri(100));

        let analysis = analyze_overlaps(&[wildcard, specific]);
        assert!(analysis.has_overlaps());
    }

    #[test]
    fn three_rules_pairwise_analysis() {
        // r0 and r1 overlap (both 10.0.0.0/8)
        // r0 and r2 don't overlap (10.x vs 192.168.x)
        // r1 and r2 don't overlap (10.x vs 192.168.x)
        let r0 = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.src =
                    FieldMatch::Select(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
            })
            .permit(pri(100));

        let r1 = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.src =
                    FieldMatch::Select(Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 16).unwrap());
            })
            .deny(pri(200));

        let r2 = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.src = FieldMatch::Select(
                    Ipv4Prefix::new(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap(),
                );
            })
            .permit(pri(300));

        let analysis = analyze_overlaps(&[r0, r1, r2]);
        assert_eq!(analysis.count(), 1);
        assert_eq!(analysis.pairs()[0], OverlapPair { a: 0, b: 1 });
    }
}
