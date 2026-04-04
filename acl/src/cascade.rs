// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Cascade compiler: assigns rules to backends with trap insertion.
//!
//! The cascade compiler walks rules in priority order and decides
//! which backend handles each rule.  When a higher-priority rule
//! must run in software but a lower-priority rule with overlapping
//! match is offloaded to hardware, the compiler inserts a **synthetic
//! trap rule** in hardware to punt matching packets to software.
//! This preserves the linear-scan priority semantics.
//!
//! # Algorithm
//!
//! Greedy per-rule assignment (same approach as tc-flower/OvS):
//!
//! 1. Sort rules by priority (lower value = higher precedence).
//! 2. For each rule, try the preferred backend first.
//! 3. Check: can the backend express the match fields?
//! 4. Check: can the backend handle the action?
//! 5. Check: does the backend tolerate overlap with already-assigned rules?
//! 6. If all checks pass → assign to preferred backend.
//! 7. If any check fails → assign to software fallback.
//! 8. If a software rule overlaps with any already-offloaded hardware
//!    rule of lower priority → insert a trap rule in hardware.
//!
//! # Mental model
//!
//! The user sees a linear scan of rules in priority order.  The
//! cascade compiler preserves this semantics across backends.  The
//! user never needs to think about which backend handles which rule.

use crate::action::ActionSequence;
use crate::builder::AclMatchFields;
use crate::metadata::Metadata;
use crate::overlap::OverlapPair;
use crate::rule::AclRule;
use crate::signature::FieldSignature;

/// Describes what a backend can handle.
///
/// Implement this trait for each backend (DPDK ACL, `rte_flow`, mock NIC,
/// etc.) to tell the cascade compiler what it can accept.
pub trait BackendCapabilities {
    /// Can this backend express the given match field signature?
    ///
    /// Returns `false` if the backend lacks support for any of the
    /// field types in the signature (e.g., a NIC that doesn't support
    /// port range matching).
    fn can_express_match(&self, signature: FieldSignature) -> bool;

    /// Can this backend execute the given action sequence?
    ///
    /// Returns `false` if the backend doesn't support any step or
    /// fate in the sequence (e.g., hardware that can't do NAT
    /// rewrites, or a NIC that doesn't support `Jump`).
    fn can_execute_actions(&self, actions: &ActionSequence) -> bool;

    /// Does this backend tolerate overlapping rules?
    ///
    /// If `false`, the cascade compiler will not assign overlapping
    /// rules to this backend.  One of the overlapping pair will be
    /// moved to the software fallback (with a trap rule if needed).
    fn overlap_tolerant(&self) -> bool;

    /// Maximum number of rules this backend can hold.
    ///
    /// Returns `None` for unlimited (e.g., software).
    fn max_rules(&self) -> Option<usize>;
}

/// Where a rule is assigned in the compilation plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Assignment {
    /// Offloaded to the preferred (hardware) backend.
    Hardware,
    /// Assigned to the software fallback.
    Software,
}

/// A synthetic trap rule injected into hardware.
///
/// When a software rule has higher priority than an overlapping
/// hardware rule, a trap is inserted in hardware with the same
/// match but action = punt-to-software.  This ensures the software
/// rule gets a chance to evaluate the packet first.
#[derive(Debug, Clone)]
pub struct TrapRule {
    /// The match fields for the trap (same as the software rule
    /// that triggered it).
    pub match_fields: AclMatchFields,
    /// The priority of the trap rule.  Must be higher than the
    /// hardware rule it's protecting against.
    pub priority: crate::priority::Priority,
    /// Index of the software rule that caused this trap.
    pub triggered_by: usize,
    /// Index of the hardware rule this trap preempts.
    pub preempts: usize,
}

/// The output of the cascade compiler.
///
/// Describes which rules go to which backend and where trap rules
/// are needed.
#[derive(Debug, Clone)]
pub struct CompilationPlan {
    /// Per-rule assignment (indexed by rule position in the table).
    assignments: Vec<Assignment>,
    /// Synthetic trap rules to insert in hardware.
    traps: Vec<TrapRule>,
    /// Number of rules assigned to hardware.
    hardware_count: usize,
    /// Number of rules assigned to software.
    software_count: usize,
}

impl CompilationPlan {
    /// Per-rule assignments.
    #[must_use]
    pub fn assignments(&self) -> &[Assignment] {
        &self.assignments
    }

    /// Synthetic trap rules for hardware.
    #[must_use]
    pub fn traps(&self) -> &[TrapRule] {
        &self.traps
    }

    /// Number of rules assigned to hardware.
    #[must_use]
    pub fn hardware_count(&self) -> usize {
        self.hardware_count
    }

    /// Number of rules assigned to software.
    #[must_use]
    pub fn software_count(&self) -> usize {
        self.software_count
    }

    /// Whether any trap rules were needed.
    #[must_use]
    pub fn has_traps(&self) -> bool {
        !self.traps.is_empty()
    }
}

/// Run the greedy cascade compiler.
///
/// Assigns each rule to either `Hardware` or `Software` based on the
/// backend's capabilities, then inserts trap rules where needed to
/// preserve priority semantics.
///
/// Rules must be sorted by priority (lower value = higher precedence)
/// before calling this function.
#[must_use]
pub fn compile_cascade<M: Metadata>(
    rules: &[AclRule<M>],
    overlaps: &[OverlapPair],
    backend: &impl BackendCapabilities,
) -> CompilationPlan {
    let n = rules.len();
    let mut assignments = vec![Assignment::Software; n];
    let mut hardware_count = 0usize;
    let hw_limit = backend.max_rules();

    // Phase 1: Greedy assignment.
    // Walk rules in priority order (caller sorted them).
    for (i, rule) in rules.iter().enumerate() {
        // Check capacity.
        if hw_limit.is_some_and(|max| hardware_count >= max) {
            continue; // hardware full, stays Software
        }

        let sig = FieldSignature::from_match_fields(rule.packet_match());

        // Check expressibility.
        if !backend.can_express_match(sig) {
            continue;
        }

        // Check action.
        if !backend.can_execute_actions(rule.actions()) {
            continue;
        }

        // Check overlap tolerance.
        if !backend.overlap_tolerant() {
            // Would this rule overlap with any already-assigned hardware rule?
            let would_conflict = overlaps.iter().any(|pair| {
                let other = if pair.a == i {
                    pair.b
                } else if pair.b == i {
                    pair.a
                } else {
                    return false;
                };
                assignments[other] == Assignment::Hardware
            });
            if would_conflict {
                continue;
            }
        }

        // All checks pass → offload.
        assignments[i] = Assignment::Hardware;
        hardware_count += 1;
    }

    let software_count = n - hardware_count;

    // Phase 2: Trap insertion.
    // For each software rule, check if it overlaps with any
    // lower-priority hardware rule.  If so, inject a trap.
    let mut traps = Vec::new();

    for (i, assignment) in assignments.iter().enumerate() {
        if *assignment != Assignment::Software {
            continue;
        }

        // Find hardware rules that this software rule overlaps with
        // AND that have lower priority (higher priority number).
        for pair in overlaps {
            let (sw_idx, hw_idx) = if pair.a == i && assignments[pair.b] == Assignment::Hardware {
                (pair.a, pair.b)
            } else if pair.b == i && assignments[pair.a] == Assignment::Hardware {
                (pair.b, pair.a)
            } else {
                continue;
            };

            // Only need a trap if the software rule has higher precedence
            // (lower priority value) than the hardware rule.
            if rules[sw_idx].priority() < rules[hw_idx].priority() {
                traps.push(TrapRule {
                    match_fields: rules[sw_idx].packet_match().clone(),
                    priority: rules[sw_idx].priority(),
                    triggered_by: sw_idx,
                    preempts: hw_idx,
                });
            }
        }
    }

    CompilationPlan {
        assignments,
        traps,
        hardware_count,
        software_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::overlap::analyze_overlaps;
    use crate::range::{Ipv4Prefix, PortRange};
    use crate::{AclRuleBuilder, FieldMatch, Priority};
    use net::tcp::port::TcpPort;
    use std::net::Ipv4Addr;

    fn pri(n: u32) -> Priority {
        Priority::new(n).unwrap()
    }

    /// A mock NIC that accepts everything.
    struct FullNic;
    impl BackendCapabilities for FullNic {
        fn can_express_match(&self, _sig: FieldSignature) -> bool {
            true
        }
        fn can_execute_actions(&self, _actions: &ActionSequence) -> bool {
            true
        }
        fn overlap_tolerant(&self) -> bool {
            true
        }
        fn max_rules(&self) -> Option<usize> {
            None
        }
    }

    /// A mock NIC with limited capacity.
    struct TinyNic;
    impl BackendCapabilities for TinyNic {
        fn can_express_match(&self, _sig: FieldSignature) -> bool {
            true
        }
        fn can_execute_actions(&self, _actions: &ActionSequence) -> bool {
            true
        }
        fn overlap_tolerant(&self) -> bool {
            true
        }
        fn max_rules(&self) -> Option<usize> {
            Some(1)
        }
    }

    /// A mock NIC that can't handle port ranges.
    struct NoRangeNic;
    impl BackendCapabilities for NoRangeNic {
        fn can_express_match(&self, sig: FieldSignature) -> bool {
            // Reject signatures that include port fields
            !sig.has_tcp_src()
                && !sig.has_tcp_dst()
                && !sig.has_udp_src()
                && !sig.has_udp_dst()
        }
        fn can_execute_actions(&self, _actions: &ActionSequence) -> bool {
            true
        }
        fn overlap_tolerant(&self) -> bool {
            true
        }
        fn max_rules(&self) -> Option<usize> {
            None
        }
    }

    /// A mock NIC that doesn't tolerate overlap.
    struct NoOverlapNic;
    impl BackendCapabilities for NoOverlapNic {
        fn can_express_match(&self, _sig: FieldSignature) -> bool {
            true
        }
        fn can_execute_actions(&self, _actions: &ActionSequence) -> bool {
            true
        }
        fn overlap_tolerant(&self) -> bool {
            false
        }
        fn max_rules(&self) -> Option<usize> {
            None
        }
    }

    fn sorted_rules() -> Vec<AclRule> {
        let mut rules = vec![
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(
                        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
                    );
                })
                .tcp(|tcp| {
                    tcp.dst =
                        FieldMatch::Select(PortRange::exact(TcpPort::new_checked(80).unwrap()));
                })
                .permit(pri(100)),
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(
                        Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 16).unwrap(),
                    );
                })
                .tcp(|tcp| {
                    tcp.dst =
                        FieldMatch::Select(PortRange::exact(TcpPort::new_checked(80).unwrap()));
                })
                .deny(pri(200)),
        ];
        rules.sort_by_key(AclRule::priority);
        rules
    }

    #[test]
    fn full_nic_offloads_everything() {
        let rules = sorted_rules();
        let analysis = analyze_overlaps(&rules);
        let plan = compile_cascade(&rules, analysis.pairs(), &FullNic);

        assert_eq!(plan.hardware_count(), 2);
        assert_eq!(plan.software_count(), 0);
        assert!(!plan.has_traps());
    }

    #[test]
    fn capacity_limit_causes_fallback() {
        let rules = sorted_rules();
        let analysis = analyze_overlaps(&rules);
        let plan = compile_cascade(&rules, analysis.pairs(), &TinyNic);

        assert_eq!(plan.hardware_count(), 1);
        assert_eq!(plan.software_count(), 1);
        // First rule (highest priority) gets hardware.
        assert_eq!(plan.assignments()[0], Assignment::Hardware);
        assert_eq!(plan.assignments()[1], Assignment::Software);
    }

    #[test]
    fn unsupported_match_causes_fallback() {
        let rules = sorted_rules(); // both have TCP port ranges
        let analysis = analyze_overlaps(&rules);
        let plan = compile_cascade(&rules, analysis.pairs(), &NoRangeNic);

        // NoRangeNic rejects port ranges → all software
        assert_eq!(plan.hardware_count(), 0);
        assert_eq!(plan.software_count(), 2);
    }

    #[test]
    fn overlap_intolerant_nic_splits_rules() {
        let rules = sorted_rules(); // these two overlap (10.1/16 ⊂ 10/8)
        let analysis = analyze_overlaps(&rules);
        assert!(analysis.has_overlaps());

        let plan = compile_cascade(&rules, analysis.pairs(), &NoOverlapNic);

        // First rule gets hardware, second can't (would overlap) → software
        assert_eq!(plan.hardware_count(), 1);
        assert_eq!(plan.software_count(), 1);
        assert_eq!(plan.assignments()[0], Assignment::Hardware);
        assert_eq!(plan.assignments()[1], Assignment::Software);
    }

    #[test]
    fn trap_inserted_for_priority_inversion() {
        // Rule 0 (pri 100): software-only (unsupported match)
        // Rule 1 (pri 200): offloadable, overlaps with rule 0
        // → trap needed: rule 0's match installed in HW as trap
        //   so it preempts rule 1 and punts to software
        let rules = vec![
            // High priority, but has ports → NoRangeNic rejects
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(
                        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
                    );
                })
                .tcp(|tcp| {
                    tcp.dst =
                        FieldMatch::Select(PortRange::exact(TcpPort::new_checked(80).unwrap()));
                })
                .permit(pri(100)),
            // Lower priority, no ports → NoRangeNic accepts
            // But overlaps in ipv4_src dimension with rule 0
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(
                        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
                    );
                })
                .deny(pri(200)),
        ];

        let analysis = analyze_overlaps(&rules);
        assert!(analysis.has_overlaps());

        let plan = compile_cascade(&rules, analysis.pairs(), &NoRangeNic);

        // Rule 0 → software (ports unsupported)
        // Rule 1 → hardware (accepted)
        assert_eq!(plan.assignments()[0], Assignment::Software);
        assert_eq!(plan.assignments()[1], Assignment::Hardware);

        // Trap needed: rule 0 (software, pri 100) preempts rule 1 (hw, pri 200)
        assert!(plan.has_traps());
        assert_eq!(plan.traps().len(), 1);
        assert_eq!(plan.traps()[0].triggered_by, 0);
        assert_eq!(plan.traps()[0].preempts, 1);
    }
}
