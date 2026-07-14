// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Display implementations for the routing context tables.
//!
//! In production (rte_acl backend) the rules are baked into an opaque classifier, so only a rule
//! count is shown per table. In test / `reference`-feature builds the reference backend keeps the
//! rules, so the field predicates + action are rendered in full.

use super::tables::PeeringTables;
use common::cliprovider::CliSource;

impl CliSource for PeeringTables {}

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
// Production (rte_acl / opaque): a one-line summary per table.

#[cfg(not(test))]
mod render {
    use super::PeeringTables;
    use common::cliprovider::Heading;
    use std::fmt::{self, Display, Formatter};

    impl Display for PeeringTables {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            Heading("Routing context (flow filter)").fmt(f)?;
            writeln!(f, "remote v4: {} rules", self.remote_v4.len())?;
            writeln!(f, "local  v4: {} rules", self.local_v4.len())?;
            writeln!(f, "remote v6: {} rules", self.remote_v6.len())?;
            writeln!(f, "local  v6: {} rules", self.local_v6.len())
        }
    }
}

// -------------------------------------------------------------------------------------------------
// Test / `reference` builds: full per-rule rendering when the reference backend holds the rules.

#[cfg(test)]
mod render {
    use super::super::tables::{AnyTable, Verdict};
    use super::PeeringTables;
    use crate::NatRequirement;
    use common::cliprovider::Heading;
    use indenter::indented;
    use match_action::{FieldPredicate, MatchKey};
    use std::fmt::{self, Display, Formatter, Write};
    use std::net::{Ipv4Addr, Ipv6Addr};

    impl Display for PeeringTables {
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

    impl<K: MatchKey, A: ActionDisplay> Display for Table<'_, K, A> {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            let Some(rules) = self.0.reference_rules() else {
                return writeln!(f, "({} rules)", self.0.len());
            };
            if rules.is_empty() {
                return writeln!(f, "(no rules)");
            }
            for rule in rules {
                for (i, pred) in rule.fields().iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    fmt_predicate(f, pred)?;
                }
                write!(f, " -> ")?;
                rule.action().fmt_action(f)?;
                writeln!(f)?;
            }
            Ok(())
        }
    }

    fn fmt_predicate(f: &mut Formatter<'_>, pred: &FieldPredicate) -> fmt::Result {
        if let Some((bytes, len)) = pred.as_prefix() {
            match bytes.len() {
                4 => write!(
                    f,
                    "{}/{len}",
                    Ipv4Addr::from(<[u8; 4]>::try_from(bytes).unwrap())
                ),
                16 => write!(
                    f,
                    "{}/{len}",
                    Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap())
                ),
                _ => write!(f, "{bytes:02x?}/{len}"),
            }
        } else if let Some((min, max)) = pred.as_range() {
            let (Some(lo), Some(hi)) = (read_u16(min), read_u16(max)) else {
                return write!(f, "range {min:02x?}..={max:02x?}");
            };
            if lo == 0 && hi == u16::MAX {
                write!(f, "ports *")
            } else if lo == hi {
                write!(f, "port {lo}")
            } else {
                write!(f, "ports {lo}..={hi}")
            }
        } else if let Some(bytes) = pred.as_exact() {
            write!(f, "{bytes:02x?}")
        } else if let Some((value, mask)) = pred.as_mask() {
            if mask.iter().all(|&b| b == 0) {
                write!(f, "*")
            } else {
                write!(f, "{value:02x?}/{mask:02x?}")
            }
        } else {
            Ok(())
        }
    }

    fn read_u16(bytes: &[u8]) -> Option<u16> {
        if let [hi, lo] = bytes {
            Some(u16::from_be_bytes([*hi, *lo]))
        } else {
            None
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
