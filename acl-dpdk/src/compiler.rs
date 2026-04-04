// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK ACL compiler: translates an [`AclTable`] into compilation
//! artifacts that can be fed to DPDK's `AclContext`.
//!
//! # Design
//!
//! The compiler does NOT create `AclContext` directly.  Instead it
//! produces [`CompiledGroup`]s — one per unique [`FieldSignature`] —
//! each containing:
//!
//! - The `FieldDef` array (table schema)
//! - The translated `AclField` arrays (rule data)
//! - The `RuleData` for each rule (priority, category, userdata)
//!
//! The caller assembles these into `Rule<N>` and `AclContext<N>` at
//! the point where `N` is known.  This avoids the const-generic `N`
//! problem: the compiler works with runtime-sized field lists, and
//! the caller picks the right `N` at the FFI boundary.
//!
//! ## Why not produce `AclContext` directly?
//!
//! `AclContext<N>` requires `N` as a const generic, but the field count
//! is determined at runtime by the rule set's field signatures.  Rather
//! than enumerate all possible `N` values or use unsafe casts, we
//! produce the compilation artifacts and let the caller (who knows `N`
//! statically for their use case) assemble the DPDK objects.
//!
//! This is a pragmatic choice documented for future reconsideration.
//! If a runtime-`N` `AclContext` proves necessary, the compiler's
//! output (`CompiledGroup`) contains all the information needed to
//! build one via raw FFI calls.

use std::num::NonZero;

use acl::{AclRule, AclTable, Action, FieldSignature, Metadata};
use dpdk::acl::field::FieldDef;
use dpdk::acl::rule::{AclField, RuleData};

use crate::field_map::{self, OffsetProvider};
use crate::rule_translate;

/// A group of compiled rules sharing the same field signature.
///
/// Each `CompiledGroup` corresponds to one DPDK `AclContext`.
#[derive(Debug, Clone)]
pub struct CompiledGroup {
    /// The field signature shared by all rules in this group.
    signature: FieldSignature,
    /// DPDK field definitions (the table schema).
    field_defs: Vec<FieldDef>,
    /// Compiled rules: each entry is `(RuleData, Vec<AclField>)`.
    rules: Vec<CompiledRule>,
}

/// A single compiled rule ready for DPDK.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    /// DPDK rule metadata.
    pub data: RuleData,
    /// Field values in the same order as the group's `field_defs`.
    pub fields: Vec<AclField>,
}

impl CompiledGroup {
    /// The field signature for this group.
    #[must_use]
    pub fn signature(&self) -> FieldSignature {
        self.signature
    }

    /// The DPDK field definitions (column schema).
    #[must_use]
    pub fn field_defs(&self) -> &[FieldDef] {
        &self.field_defs
    }

    /// The compiled rules.
    #[must_use]
    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }

    /// The number of fields per rule (determines `N` for `Rule<N>`).
    #[must_use]
    pub fn field_count(&self) -> usize {
        self.field_defs.len()
    }
}

/// Compile an [`AclTable`] into groups of DPDK-ready rules.
///
/// Returns one [`CompiledGroup`] per unique [`FieldSignature`] in the
/// table.  Each group can be used to create one DPDK `AclContext`.
///
/// Rules are assigned `userdata` values starting from 1 (since DPDK
/// reserves 0 for "no match").  The `userdata` encodes the original
/// rule index so the caller can map results back to actions.
///
/// All rules get `category_mask = 1` (single category) for now.
/// Multi-category support can be added when the category system is
/// wired up.
#[must_use]
pub fn compile<M: Metadata>(
    table: &AclTable<M>,
    offsets: &impl OffsetProvider,
) -> Vec<CompiledGroup> {
    let rules = table.rules();
    if rules.is_empty() {
        return Vec::new();
    }

    // Extract match fields for signature computation.
    let match_fields: Vec<acl::AclMatchFields> = rules
        .iter()
        .map(|r| r.packet_match().clone())
        .collect();
    let groups = acl::group_rules_by_signature(&match_fields);

    groups
        .into_iter()
        .filter_map(|group| {
            let sig = group.signature();
            if sig == FieldSignature::EMPTY {
                // Rules with no selected fields can't produce a DPDK context.
                // They match everything — handled by the default action.
                return None;
            }

            let field_defs = field_map::build_field_defs(sig, offsets);

            let compiled_rules: Vec<CompiledRule> = group
                .rule_indices()
                .iter()
                .map(|&idx| {
                    let rule = &rules[idx];

                    // userdata = rule index + 1 (0 is reserved for "no match")
                    #[allow(clippy::unwrap_used)] // idx + 1 is always > 0
                    let userdata = NonZero::new(u32::try_from(idx + 1).unwrap_or(u32::MAX))
                        .unwrap();

                    // Convert our Priority (NonZero<u32>) to DPDK's i32 priority.
                    // DPDK: higher numeric value = higher priority.
                    // Our Priority: lower value = higher precedence.
                    // We invert so that our priority 1 becomes a high DPDK priority.
                    let dpdk_priority = i32::MAX - i32::try_from(rule.priority().get())
                        .unwrap_or(i32::MAX);

                    let data = RuleData {
                        category_mask: 1, // single category for now
                        priority: dpdk_priority,
                        userdata,
                    };

                    let fields = rule_translate::translate_rule(sig, rule);

                    CompiledRule { data, fields }
                })
                .collect();

            Some(CompiledGroup {
                signature: sig,
                field_defs,
                rules: compiled_rules,
            })
        })
        .collect()
}

/// Map a DPDK classification result back to an [`Action`].
///
/// `userdata` is the value returned by `rte_acl_classify`.  If 0
/// (no match), returns the table's default action.  Otherwise,
/// decodes the rule index and returns that rule's action.
#[must_use]
pub fn resolve_action<M: Metadata>(
    table: &AclTable<M>,
    userdata: u32,
    default_action: Action,
) -> Action {
    if userdata == 0 {
        return default_action;
    }
    let idx = (userdata - 1) as usize;
    table
        .rules()
        .get(idx)
        .map_or(default_action, acl::AclRule::action)
}

#[cfg(test)]
mod tests {
    use super::*;
    use acl::{AclRuleBuilder, AclTableBuilder, FieldMatch, Ipv4Prefix, PortRange, Priority};
    use net::tcp::port::TcpPort;
    use std::net::Ipv4Addr;

    use crate::field_map::StandardEthernetOffsets;

    fn pri(n: u32) -> Priority {
        Priority::new(n).unwrap()
    }

    #[test]
    fn compile_single_signature_group() {
        let table = AclTableBuilder::new(Action::Deny)
            .add_rule(
                AclRuleBuilder::new()
                    .eth(|_| {})
                    .ipv4(|ip| {
                        ip.src = FieldMatch::Select(
                            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
                        );
                    })
                    .tcp(|tcp| {
                        tcp.dst = FieldMatch::Select(PortRange::exact(
                            TcpPort::new_checked(80).unwrap(),
                        ));
                    })
                    .permit(pri(100)),
            )
            .add_rule(
                AclRuleBuilder::new()
                    .eth(|_| {})
                    .ipv4(|ip| {
                        ip.src = FieldMatch::Select(
                            Ipv4Prefix::new(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap(),
                        );
                    })
                    .tcp(|tcp| {
                        tcp.dst = FieldMatch::Select(PortRange::exact(
                            TcpPort::new_checked(443).unwrap(),
                        ));
                    })
                    .deny(pri(200)),
            )
            .build();

        let groups = compile(&table, &StandardEthernetOffsets);

        // Both rules have the same signature → one group
        assert_eq!(groups.len(), 1);

        let group = &groups[0];
        assert_eq!(group.rules().len(), 2);
        assert_eq!(group.field_count(), 4); // proto, eth_type, ipv4_src, tcp_dst

        // userdata is rule_index + 1
        assert_eq!(group.rules()[0].data.userdata.get(), 1);
        assert_eq!(group.rules()[1].data.userdata.get(), 2);
    }

    #[test]
    fn compile_splits_different_signatures() {
        let table = AclTableBuilder::new(Action::Deny)
            .add_rule(
                // IPv4 + TCP with ports
                AclRuleBuilder::new()
                    .eth(|_| {})
                    .ipv4(|ip| {
                        ip.src = FieldMatch::Select(
                            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
                        );
                    })
                    .tcp(|tcp| {
                        tcp.dst = FieldMatch::Select(PortRange::exact(
                            TcpPort::new_checked(80).unwrap(),
                        ));
                    })
                    .permit(pri(100)),
            )
            .add_rule(
                // IPv4 only (no ports) → different signature
                AclRuleBuilder::new()
                    .eth(|_| {})
                    .ipv4(|ip| {
                        ip.src = FieldMatch::Select(
                            Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 12).unwrap(),
                        );
                    })
                    .permit(pri(200)),
            )
            .build();

        let groups = compile(&table, &StandardEthernetOffsets);

        // Different signatures → two groups
        assert_eq!(groups.len(), 2);

        // One group has tcp_dst, the other doesn't
        let has_ports = groups.iter().any(|g| g.field_count() == 4);
        let no_ports = groups.iter().any(|g| g.field_count() < 4);
        assert!(has_ports);
        assert!(no_ports);
    }

    #[test]
    fn resolve_action_maps_userdata() {
        let table = AclTableBuilder::new(Action::Deny)
            .add_rule(AclRuleBuilder::new().eth(|_| {}).permit(pri(100)))
            .add_rule(AclRuleBuilder::new().eth(|_| {}).deny(pri(200)))
            .build();

        // userdata 0 → default (Deny)
        assert_eq!(resolve_action(&table, 0, Action::Deny), Action::Deny);

        // userdata 1 → rule 0 (Permit)
        assert_eq!(resolve_action(&table, 1, Action::Deny), Action::Permit);

        // userdata 2 → rule 1 (Deny)
        assert_eq!(resolve_action(&table, 2, Action::Deny), Action::Deny);

        // userdata 99 → out of bounds → default
        assert_eq!(resolve_action(&table, 99, Action::Deny), Action::Deny);
    }

    #[test]
    fn priority_inversion() {
        // Our priority 1 (highest precedence) should get a higher DPDK priority
        // than our priority 1000 (lower precedence).
        let table = AclTableBuilder::new(Action::Deny)
            .add_rule(
                AclRuleBuilder::new()
                    .eth(|_| {})
                    .ipv4(|_| {})
                    .tcp(|_| {})
                    .permit(pri(1)),
            )
            .add_rule(
                AclRuleBuilder::new()
                    .eth(|_| {})
                    .ipv4(|_| {})
                    .tcp(|_| {})
                    .deny(pri(1000)),
            )
            .build();

        let groups = compile(&table, &StandardEthernetOffsets);
        assert_eq!(groups.len(), 1);

        let rules = groups[0].rules();
        // Priority 1 should have higher DPDK priority (larger number)
        assert!(rules[0].data.priority > rules[1].data.priority);
    }
}
