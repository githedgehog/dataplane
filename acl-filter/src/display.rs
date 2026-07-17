// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Display implementations for the ACL filter context.
//!
//! The ACL rules are stored in the context after being lowered into positional field predicates
//! (see [`crate::context`]), so the human-readable field values are reconstructed here from the raw
//! bytes of each predicate. This relies on the field layout of the `AclKey` match key defined in
//! `context.rs`:
//!
//!    - `AclKey`: proto, src_vni, dst_vni, src_ip, dst_ip, src_port, dst_port
//!
//! If that layout changes, the decoding below must be updated accordingly.

use common::cliprovider::{CliSource, Heading};
use indenter::indented;

use std::fmt::{self, Display, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

use acl::reference::table::ReferenceTable;
use match_action::{FieldPredicate, MatchKey};

use crate::AclFilterContext;
use crate::context::{AclTables, LookupResult};

impl CliSource for AclFilterContext {}

impl Display for AclFilterContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Heading("ACL filter").fmt(f)?;
        write!(f, "{}", self.acls)
    }
}

impl Display for AclTables {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "IPv4:")?;
        {
            let mut w = indented(f).with_str("  ");
            fmt_ref_table(&mut w, &self.v4)?;
        }

        writeln!(f, "IPv6:")?;
        {
            let mut w = indented(f).with_str("  ");
            fmt_ref_table(&mut w, &self.v6)?;
        }

        writeln!(f, "default actions:")?;
        let mut w = indented(f).with_str("  ");
        if self.default_actions.is_empty() {
            writeln!(w, "(none)")?;
        } else {
            // Sort for a deterministic dump.
            let mut defaults: Vec<_> = self.default_actions.iter().collect();
            defaults.sort_by_key(|((src, dst), _)| (src.as_u32(), dst.as_u32()));
            for ((src, dst), action) in defaults {
                writeln!(w, "VPC {src} -> VPC {dst}: {action:?}")?;
            }
        }
        Ok(())
    }
}

/// Format a single reference table as a numbered list of rules. The decoding reads each rule's
/// predicates by position, following the `AclKey` layout in `context.rs`:
/// proto, src_vni, dst_vni, src_ip, dst_ip, src_port, dst_port.
fn fmt_ref_table<W: Write, K: MatchKey>(
    w: &mut W,
    table: &ReferenceTable<K, LookupResult>,
) -> fmt::Result {
    if table.is_empty() {
        return writeln!(w, "(none)");
    }
    for (idx, rule) in table.rules().iter().enumerate() {
        let fields = rule.fields();
        let result = rule.action();
        let proto = decode_proto(fields.first());
        let src_vni = decode_vni(fields.get(1));
        let dst_vni = decode_vni(fields.get(2));
        let src_ip = decode_prefix(fields.get(3));
        let dst_ip = decode_prefix(fields.get(4));
        let src_ports = decode_ports(fields.get(5));
        let dst_ports = decode_ports(fields.get(6));
        let log = if result.log { ", log" } else { "" };
        writeln!(
            w,
            "[{idx}] VPC {src_vni} -> VPC {dst_vni} | proto {proto} | src {src_ip}:{src_ports} | dst {dst_ip}:{dst_ports} | {:?} ({:?}{log})",
            result.action, result.scope
        )?;
    }
    Ok(())
}

/// Decode a VNI stored as a 4-byte big-endian exact-match predicate.
fn decode_vni(predicate: Option<&FieldPredicate>) -> String {
    match predicate.and_then(FieldPredicate::as_exact) {
        Some([a, b, c, d]) => u32::from_be_bytes([*a, *b, *c, *d]).to_string(),
        _ => "?".to_string(),
    }
}

/// Decode an IP prefix stored as a prefix-match predicate (4 bytes for IPv4, 16 bytes for IPv6,
/// plus a prefix length).
fn decode_prefix(predicate: Option<&FieldPredicate>) -> String {
    match predicate.and_then(FieldPredicate::as_prefix) {
        Some(([a, b, c, d], len)) => format!("{}/{len}", Ipv4Addr::new(*a, *b, *c, *d)),
        Some((bytes, len)) if bytes.len() == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(bytes);
            format!("{}/{len}", Ipv6Addr::from(octets))
        }
        _ => "?".to_string(),
    }
}

/// Decode an IP protocol stored as a 1-byte bitmask predicate. A zero mask (wildcard) renders as
/// `any`, a full mask as the single protocol number.
fn decode_proto(predicate: Option<&FieldPredicate>) -> String {
    match predicate.and_then(FieldPredicate::as_mask) {
        Some(([value], [mask])) => {
            if *mask == 0 {
                "any".to_string()
            } else if *mask == u8::MAX {
                value.to_string()
            } else {
                format!("{value}&{mask:#04x}")
            }
        }
        _ => "?".to_string(),
    }
}

/// Decode a port range stored as a pair of 2-byte big-endian range bounds. A full range renders as
/// `*`, an exact match as the single port.
fn decode_ports(predicate: Option<&FieldPredicate>) -> String {
    match predicate.and_then(FieldPredicate::as_range) {
        Some(([lo_hi, lo_lo], [hi_hi, hi_lo])) => {
            let lo = u16::from_be_bytes([*lo_hi, *lo_lo]);
            let hi = u16::from_be_bytes([*hi_hi, *hi_lo]);
            if lo == 0 && hi == u16::MAX {
                "*".to_string()
            } else if lo == hi {
                lo.to_string()
            } else {
                format!("{lo}-{hi}")
            }
        }
        _ => "?".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_ports, decode_prefix, decode_proto, decode_vni};
    use match_action::{Erased, ExactSpec, IntoBackendField, MaskSpec, PrefixSpec, RangeSpec};
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn decode_vni_reads_u32() {
        let p = IntoBackendField::<Erased>::into_backend_field(ExactSpec::new(4242u32));
        assert_eq!(decode_vni(Some(&p)), "4242");
        assert_eq!(decode_vni(None), "?");
    }

    #[test]
    fn decode_prefix_reads_v4_and_v6() {
        let v4 = IntoBackendField::<Erased>::into_backend_field(PrefixSpec::new(
            Ipv4Addr::new(10, 0, 0, 0),
            8,
        ));
        assert_eq!(decode_prefix(Some(&v4)), "10.0.0.0/8");

        let v6 = IntoBackendField::<Erased>::into_backend_field(PrefixSpec::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            32,
        ));
        assert_eq!(decode_prefix(Some(&v6)), "2001:db8::/32");
    }

    #[test]
    fn decode_ports_handles_wildcard_exact_and_range() {
        let wildcard =
            IntoBackendField::<Erased>::into_backend_field(RangeSpec::new(0u16, u16::MAX));
        assert_eq!(decode_ports(Some(&wildcard)), "*");

        let exact = IntoBackendField::<Erased>::into_backend_field(RangeSpec::new(80u16, 80u16));
        assert_eq!(decode_ports(Some(&exact)), "80");

        let range = IntoBackendField::<Erased>::into_backend_field(RangeSpec::new(80u16, 8080u16));
        assert_eq!(decode_ports(Some(&range)), "80-8080");
    }

    #[test]
    fn decode_proto_handles_any_and_exact() {
        let any = IntoBackendField::<Erased>::into_backend_field(MaskSpec::new(0u8, 0u8));
        assert_eq!(decode_proto(Some(&any)), "any");

        let tcp = IntoBackendField::<Erased>::into_backend_field(MaskSpec::new(6u8, u8::MAX));
        assert_eq!(decode_proto(Some(&tcp)), "6");

        let udp = IntoBackendField::<Erased>::into_backend_field(MaskSpec::new(17u8, u8::MAX));
        assert_eq!(decode_proto(Some(&udp)), "17");
    }
}
