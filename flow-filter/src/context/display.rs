// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Display implementations for the routing context tables.
//!
//! Tables retain typed rules for backend-independent display. Each field's type controls its
//! formatting, keeping values coupled to their key fields.

use super::tables::{FlowFilterContext, GateVni, SourceGate};

impl crate::NatRequirement {
    fn label(self) -> &'static str {
        match self {
            crate::NatRequirement::Static => "static",
            crate::NatRequirement::Masquerade => "masquerade",
            crate::NatRequirement::PortForwarding => "port-forwarding",
        }
    }
}

impl std::fmt::Display for crate::NatRequirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

impl std::fmt::Display for GateVni {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(vni) => write!(f, "{vni}"),
            None => f.write_str("-"),
        }
    }
}

impl std::fmt::Display for SourceGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceGate::Ungated => f.write_str("-"),
            SourceGate::PortFwdReply => f.write_str("pfwd"),
        }
    }
}

// -------------------------------------------------------------------------------------------------
// Rendering: one section per table, each rule on a line, in match order.

mod render {
    use super::super::tables::{AnyTable, RuleRow, Verdict};
    use super::FlowFilterContext;
    use crate::NatRequirement;
    use common::cliprovider::{CliSource, Heading};
    use indenter::indented;
    use match_action::{Field, MatchKey, RuleFields, write_grid};
    use std::fmt::{self, Display, Formatter, Write};

    impl CliSource for FlowFilterContext {}

    impl Display for FlowFilterContext {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            Heading("Routing context (flow filter)").fmt(f)?;
            writeln!(f, "Remote v4 (destination -> dst VPC + dst NAT):")?;
            write!(indented(f).with_str("  "), "{}", Table(&self.remote_v4))?;
            writeln!(f, "Local v4 (source -> src NAT):")?;
            write!(indented(f).with_str("  "), "{}", Table(&self.local_v4))?;
            writeln!(f, "Remote v6 (destination -> dst VPC + dst NAT):")?;
            write!(indented(f).with_str("  "), "{}", Table(&self.remote_v6))?;
            writeln!(f, "Local v6 (source -> src NAT):")?;
            write!(indented(f).with_str("  "), "{}", Table(&self.local_v6))
        }
    }

    struct Table<'a, K: MatchKey, A>(&'a AnyTable<K, A>);

    /// Rules as a table in match order: `[0]` is consulted first.
    ///
    /// The rank column is the rule's position, not its internal priority value. A priority is a
    /// computed encoding of (prefix length, port-forwarding bit) that means nothing outside the
    /// table builder and is not stable across releases -- printing it invites an operator to read
    /// precedence out of an opaque number, or to compare two numbers whose scale may have changed
    /// underneath them. The rank answers the question they actually have: which rule wins.
    ///
    /// Key columns come from the rule's own fields, action columns from [`ActionColumns`], with a
    /// `|` between the two so it is obvious which half is matched on and which half is the result.
    impl<K: MatchKey, A: ActionColumns> Display for Table<'_, K, A>
    where
        K::Rule: RuleFields,
    {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            if self.0.len() == 0 {
                return writeln!(f, "(no rules)");
            }

            let key_fields = <K::Rule as RuleFields>::FIELD_NAMES;
            let mut headings: Vec<&str> =
                Vec::with_capacity(key_fields.len() + A::HEADINGS.len() + 2);
            headings.push("rank");
            headings.extend_from_slice(key_fields);
            headings.push("|");
            headings.extend_from_slice(A::HEADINGS);

            let mut rows: Vec<Vec<String>> = Vec::with_capacity(self.0.len());
            for (rank, RuleRow { rule, action }) in self.0.rules().iter().enumerate() {
                let mut row = Vec::with_capacity(headings.len());
                row.push(format!("[{rank}]"));
                for index in 0..key_fields.len() {
                    row.push(Field::of(rule, index).to_string());
                }
                row.push("|".to_string());
                action.columns(&mut row);
                rows.push(row);
            }
            write_grid(f, &headings, &rows)
        }
    }

    /// An action, as the columns it occupies.
    ///
    /// A trait rather than `Display` because one action type is the alias
    /// `Option<NatRequirement>`, which this crate cannot implement `Display` for -- and because a
    /// columnar layout needs the cells separately anyway.
    trait ActionColumns {
        const HEADINGS: &'static [&'static str];
        fn columns(&self, row: &mut Vec<String>);
    }

    impl ActionColumns for Verdict {
        const HEADINGS: &'static [&'static str] = &["to", "NAT"];

        fn columns(&self, row: &mut Vec<String>) {
            row.push(self.dst_vpcd.to_string());
            row.push(nat_mode(&self.nat_mode));
        }
    }

    impl ActionColumns for Option<NatRequirement> {
        const HEADINGS: &'static [&'static str] = &["NAT"];

        fn columns(&self, row: &mut Vec<String>) {
            row.push(nat_mode(self));
        }
    }

    fn nat_mode(nat: &Option<NatRequirement>) -> String {
        nat.map_or_else(|| "-".to_string(), |nat| nat.to_string())
    }
}
