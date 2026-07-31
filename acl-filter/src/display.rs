// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Display implementations for the ACL filter context.
//!
//! Every table retains the (typed) rules it was built from, so production renders exactly what the
//! reference backend renders -- the rte_acl classifier is opaque, but it is not what is being
//! rendered. Each field formats itself through its own type, so unlike decoding erased predicates
//! by position, the output cannot silently mislabel itself when `AclKey`'s field order changes.

use common::cliprovider::{CliSource, Heading};

use std::fmt::{self, Display, Write};

use crate::AclFilterContext;
use crate::PacketSummary;
use crate::context::{AclTables, AnyTable, RuleRow};
use match_action::MatchKey;

impl CliSource for AclFilterContext {}

impl Display for AclFilterContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Heading("ACL filter").fmt(f)?;
        write!(f, "{}", self.acls)
    }
}

/// Dump the peering default actions, sorted for a deterministic rendering. Shared by both the
/// production (count-only) and test (full) table renderings.
fn fmt_default_actions<W: Write>(w: &mut W, tables: &AclTables) -> fmt::Result {
    writeln!(w, "default actions:")?;
    let mut w = indenter::indented(w).with_str("  ");
    if tables.default_actions.is_empty() {
        return writeln!(w, "(none)");
    }
    let mut defaults: Vec<_> = tables.default_actions.iter().collect();
    defaults.sort_by_key(|((src, dst), _)| (src.as_u32(), dst.as_u32()));
    for ((src, dst), action) in defaults {
        writeln!(w, "VPC {src} -> VPC {dst}: {action:?}")?;
    }
    Ok(())
}

// -------------------------------------------------------------------------------------------------
// Rendering: one section per IP version, each rule on a line, in precedence (first-match) order.

impl Display for AclTables {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use indenter::indented;
        writeln!(f, "IPv4:")?;
        fmt_table(&mut indented(f).with_str("  "), &self.v4)?;
        writeln!(f, "IPv6:")?;
        fmt_table(&mut indented(f).with_str("  "), &self.v6)?;
        fmt_default_actions(f, self)
    }
}

/// Format a single table as a numbered list of rules. The index is the rule's precedence: the
/// first match wins, so `[0]` is consulted first.
fn fmt_table<W: Write, K: MatchKey>(
    w: &mut W,
    table: &AnyTable<K, crate::context::LookupResult>,
) -> fmt::Result
where
    K::Rule: Display,
{
    if table.len() == 0 {
        return writeln!(w, "(none)");
    }
    for (idx, RuleRow { rule, action }) in table.rules().iter().enumerate() {
        let log = if action.log { ", log" } else { "" };
        writeln!(
            w,
            "[{idx}] {rule} -> {:?} ({:?}{log})",
            action.action, action.scope
        )?;
    }
    Ok(())
}

impl Display for PacketSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let (Some(sport), Some(dport)) = self.ports.unzip() {
            write!(
                f,
                "vni:{} -> vni:{}, {}:{} -> {}:{} ({})",
                self.src_vni, self.dst_vni, self.src_ip, sport, self.dst_ip, dport, self.proto
            )
        } else {
            write!(
                f,
                "vni:{} -> vni:{}, {} -> {} ({})",
                self.src_vni, self.dst_vni, self.src_ip, self.dst_ip, self.proto
            )
        }
    }
}
