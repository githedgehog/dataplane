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
use match_action::{Field, MatchKey, RuleFields, write_grid};

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

/// Format a single table as a grid of rules, in precedence (first-match) order.
///
/// The rank column is the rule's position: the first match wins, so `[0]` is consulted first. Key
/// columns come from the rule's own fields, with a `|` before the action columns so it is obvious
/// which half is matched on and which half is the result.
fn fmt_table<W: Write, K: MatchKey>(
    w: &mut W,
    table: &AnyTable<K, crate::context::LookupResult>,
) -> fmt::Result
where
    K::Rule: RuleFields,
{
    if table.len() == 0 {
        return writeln!(w, "(none)");
    }

    let key_fields = <K::Rule as RuleFields>::FIELD_NAMES;
    let mut headings: Vec<&str> = Vec::with_capacity(key_fields.len() + 5);
    headings.push("rank");
    headings.extend_from_slice(key_fields);
    headings.extend_from_slice(&["|", "action", "scope", "log"]);

    let mut rows: Vec<Vec<String>> = Vec::with_capacity(table.len());
    for (rank, RuleRow { rule, action }) in table.rules().iter().enumerate() {
        let mut row = Vec::with_capacity(headings.len());
        row.push(format!("[{rank}]"));
        for index in 0..key_fields.len() {
            row.push(Field::of(rule, index).to_string());
        }
        row.push("|".to_string());
        row.push(format!("{:?}", action.action));
        row.push(format!("{:?}", action.scope));
        row.push(if action.log { "log" } else { "-" }.to_string());
        rows.push(row);
    }
    write_grid(w, &headings, &rows)
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
