// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Display implementations for the routing context tables.
//!
//! Every table retains the (typed) rules it was built from, so the same full rendering is produced
//! in production as in tests -- the rte_acl classifier itself is opaque, but it is not the thing
//! being rendered. Each field formats itself through its own type, so the output cannot drift from
//! the key layout the way position- or width-based decoding of erased predicates can.

use super::tables::FlowFilterContext;

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

// -------------------------------------------------------------------------------------------------
// Rendering: one section per table, each rule on a line, in match order.

mod render {
    use super::super::tables::{AnyTable, RuleRow, Verdict};
    use super::FlowFilterContext;
    use crate::NatRequirement;
    use common::cliprovider::{CliSource, Heading};
    use indenter::indented;
    use match_action::MatchKey;
    use std::fmt::{self, Display, Formatter, Write};

    impl CliSource for FlowFilterContext {}

    impl Display for FlowFilterContext {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            Heading("Routing context (flow filter)").fmt(f)?;
            writeln!(f, "remote v4 (destination -> dst VPC + dst NAT):")?;
            write!(indented(f).with_str("  "), "{}", Table(&self.remote_v4))?;
            writeln!(f, "local v4 (source -> src NAT):")?;
            write!(indented(f).with_str("  "), "{}", Table(&self.local_v4))?;
            writeln!(f, "remote v6 (destination -> dst VPC + dst NAT):")?;
            write!(indented(f).with_str("  "), "{}", Table(&self.remote_v6))?;
            writeln!(f, "local v6 (source -> src NAT):")?;
            write!(indented(f).with_str("  "), "{}", Table(&self.local_v6))
        }
    }

    struct Table<'a, K: MatchKey, A>(&'a AnyTable<K, A>);

    impl<K: MatchKey, A: ActionDisplay> Display for Table<'_, K, A>
    where
        K::Rule: Display,
    {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            if self.0.len() == 0 {
                return writeln!(f, "(no rules)");
            }
            for RuleRow {
                priority,
                rule,
                action,
            } in self.0.rules()
            {
                write!(f, "[{priority}] {rule} -> ")?;
                action.fmt_action(f)?;
                writeln!(f)?;
            }
            Ok(())
        }
    }

    // Dedicated trait (rather than `Display`) because one action type is the alias
    // `Option<NatRequirement>`, for which we cannot implement `Display`.
    trait ActionDisplay {
        fn fmt_action(&self, f: &mut Formatter<'_>) -> fmt::Result;
    }

    impl ActionDisplay for Verdict {
        fn fmt_action(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "{}, NAT: ", self.dst_vpcd)?;
            fmt_nat_mode(f, &self.nat_mode)
        }
    }

    impl ActionDisplay for Option<NatRequirement> {
        fn fmt_action(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "NAT: ")?;
            fmt_nat_mode(f, self)
        }
    }

    fn fmt_nat_mode(f: &mut Formatter<'_>, nat: &Option<NatRequirement>) -> fmt::Result {
        match nat {
            Some(nat) => write!(f, "{nat}"),
            None => write!(f, "-"),
        }
    }
}
