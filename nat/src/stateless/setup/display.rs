// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Display implementations for the stateless NAT table objects

use crate::stateless::setup::tables::{
    AddrTranslationValue, NatRuleTable, NatTableValue, NatTables, PerVniTable,
    PortAddrTranslationValue,
};
use indenter::indented;
use std::collections::BTreeMap;
use std::fmt::{Display, Write};

fn fmt_static_nat_table_heading(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(
        f,
        " ──────────────────────────────────────── Static NAT table ─────────────────────────────────────────"
    )
}

impl Display for NatTables {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt_static_nat_table_heading(f)?;
        if self.is_empty() {
            return writeln!(f, " (empty)");
        }
        let sorted_table = self.iter().collect::<BTreeMap<_, _>>();
        for (vni, table) in &sorted_table {
            writeln!(f, "source VNI {vni}:")?;
            writeln!(indented(f).with_str("  "), "{table}")?;
        }
        Ok(())
    }
}

impl Display for PerVniTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "destination NAT:")?;
        write!(indented(f).with_str("  "), "{}", self.dst_nat)?;
        writeln!(f, "source NAT:")?;
        let sorted_src_nat = self.src_nat.iter().collect::<BTreeMap<_, _>>();
        for (vni, table) in &sorted_src_nat {
            writeln!(f, "  destination VNI {vni}:")?;
            write!(indented(f).with_str("    "), "{table}")?;
        }
        Ok(())
    }
}

impl Display for NatRuleTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (prefix, value) in self.iter() {
            if let NatTableValue::Nat(nat_value) = value
                && nat_value.len() == 1
            {
                // No need to print a prefix for a single port range (two representations of the
                // same IP range)
                let (range, (target_range, offset)) =
                    nat_value.iter().next().unwrap_or_else(|| unreachable!());
                // Should match Display implementation for AddrTranslationValue
                writeln!(f, "{range} -> {target_range} (offset: {offset})")?;
            } else if let NatTableValue::Pat(_) = value {
                write!(f, "{prefix}, ")?;
                write!(f, "{value}")?;
            } else {
                writeln!(f, "{prefix}:")?;
                write!(indented(f).with_str("  "), "{value}")?;
            }
        }
        Ok(())
    }
}

impl Display for NatTableValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatTableValue::Nat(value) => write!(f, "{value}"),
            NatTableValue::Pat(value) => write!(f, "{value}"),
        }
    }
}

impl Display for AddrTranslationValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (range, (target_range, offset)) in self.iter() {
            writeln!(f, "{range} -> {target_range} (offset: {offset})")?;
        }
        Ok(())
    }
}

impl Display for PortAddrTranslationValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "port ranges [ ")?;
        let mut first = true;
        for port_range in self.iter_prefixes() {
            if !first {
                write!(f, ", ")?;
            }
            first = false;
            write!(f, "{port_range}")?;
        }
        writeln!(f, " ]:")?;

        for (bounds, (range, offset)) in self.iter_tree() {
            writeln!(
                indented(f).with_str("  "),
                "{bounds} -> {range}  (offset: {offset})"
            )?;
        }
        Ok(())
    }
}
