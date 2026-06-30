// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Display implementations for context tables.

use super::tables::{PeeringEndsTables, PeeringTables, Verdict, VpcTable};
use crate::NatRequirement;
use acl::reference::table::ReferenceTable;
use common::cliprovider::{CliSource, Heading};
use indenter::indented;
use match_action::{FieldPredicate, MatchKey};
use net::packet::VpcDiscriminant;
use std::collections::{BTreeMap, HashMap};
use std::fmt::{self, Display, Formatter, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

impl CliSource for PeeringTables {}

impl Display for PeeringTables {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Heading("Routing context").fmt(f)?;

        writeln!(f, "IPv4 peering tables:")?;
        fmt_vpc_tables(f, &self.v4)?;

        writeln!(f, "IPv6 peering tables:")?;
        fmt_vpc_tables(f, &self.v6)?;
        Ok(())
    }
}

// Collect into a `BTreeMap` to get a deterministic order when dumping the
// entries, as the underlying `HashMap` has no stable iteration order
fn fmt_vpc_tables<T: MatchKey, U: MatchKey>(
    f: &mut Formatter<'_>,
    tables: &HashMap<VpcDiscriminant, VpcTable<T, U>>,
) -> fmt::Result {
    if tables.is_empty() {
        return writeln!(f, "  (none)");
    }
    for (src_vpcd, table) in tables.iter().collect::<BTreeMap<_, _>>() {
        writeln!(f, "  source VPC {src_vpcd}:")?;
        write!(indented(f).with_str("    "), "{table}")?;
        writeln!(f)?;
    }
    Ok(())
}

impl<T: MatchKey, U: MatchKey> Display for VpcTable<T, U> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "local ends:")?;
        if self.local_ends.is_empty() {
            writeln!(f, "  (none)")?;
        } else {
            for (remote_vpcd, ends) in self.local_ends.iter().collect::<BTreeMap<_, _>>() {
                writeln!(f, "  for remote VPC {remote_vpcd}:")?;
                write!(indented(f).with_str("    "), "{ends}")?;
            }
        }
        writeln!(f, "remote ends:")?;
        write!(indented(f).with_str("  "), "{}", self.remote_ends)?;
        match &self.default_remote_vpcd {
            Some(vpcd) => writeln!(f, "default remote VPC: {vpcd}"),
            None => writeln!(f, "default remote VPC: -"),
        }
    }
}

impl<T: MatchKey, U: MatchKey, V: ActionDisplay> Display for PeeringEndsTables<T, U, V> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "TCP:")?;
        write!(indented(f).with_str("  "), "{}", Rules(&self.tcp))?;
        writeln!(f, "UDP:")?;
        write!(indented(f).with_str("  "), "{}", Rules(&self.udp))?;
        writeln!(f, "other:")?;
        write!(indented(f).with_str("  "), "{}", Rules(&self.other))?;
        writeln!(f, "has default expose: {}", self.has_default)
    }
}

// Display wrapper around a reference table. The table itself lives in the `acl` crate, so we cannot
// implement `Display` for it directly.
struct Rules<'a, K, A>(&'a ReferenceTable<K, A>);

impl<K: MatchKey, A: ActionDisplay> Display for Rules<'_, K, A> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let table = self.0;
        if table.is_empty() {
            return writeln!(f, "(no rules)");
        }
        for rule in table.rules() {
            let mut first = true;
            for pred in rule.fields() {
                if first {
                    first = false;
                } else {
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

// Render a single ACL field predicate
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
        write!(f, "{value:02x?}/{mask:02x?}")
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

// The action carried by a reference table rule. Use a dedicated trait
// (rather than `Display`) because one of the action types is the bare alias
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

impl Display for NatRequirement {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let label = match self {
            NatRequirement::Static => "static",
            NatRequirement::Masquerade => "masquerade",
            NatRequirement::PortForwarding => "port-forwarding",
        };
        f.write_str(label)
    }
}
