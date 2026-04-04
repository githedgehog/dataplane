// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Field signature for DPDK ACL context grouping.
//!
//! A [`FieldSignature`] captures which individual match fields are
//! `Select` (present in the table) vs `Ignore` (absent).  Rules with
//! the same signature share a DPDK ACL context (same `FieldDef` array).
//!
//! The signature is a compact bitset — each bit corresponds to one
//! matchable field across all protocol layers.

use crate::builder::AclMatchFields;

/// Bit positions for each matchable field.
///
/// These are stable identifiers used in the signature bitset.
/// The ordering doesn't matter for correctness, only consistency.
mod bits {
    pub const ETH_SRC_MAC: u32 = 0;
    pub const ETH_DST_MAC: u32 = 1;
    pub const ETH_TYPE: u32 = 2;
    pub const VLAN_VID: u32 = 3;
    pub const VLAN_PCP: u32 = 4;
    pub const VLAN_INNER_TYPE: u32 = 5;
    pub const IPV4_SRC: u32 = 6;
    pub const IPV4_DST: u32 = 7;
    pub const IPV4_PROTO: u32 = 8;
    pub const IPV6_SRC: u32 = 9;
    pub const IPV6_DST: u32 = 10;
    pub const IPV6_PROTO: u32 = 11;
    pub const TCP_SRC: u32 = 12;
    pub const TCP_DST: u32 = 13;
    pub const UDP_SRC: u32 = 14;
    pub const UDP_DST: u32 = 15;
    pub const ICMP4_TYPE: u32 = 16;
    pub const ICMP4_CODE: u32 = 17;
}

/// A compact representation of which match fields are active in a rule.
///
/// Two rules with the same `FieldSignature` can share a DPDK ACL context
/// because they use the same set of `FieldDef` entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FieldSignature(u32); // AGENT: is this better suited to a u64 or u128?

impl FieldSignature {
    /// The empty signature (no fields selected).
    pub const EMPTY: Self = Self(0);

    /// Extract the field signature from a set of match fields.
    #[must_use]
    pub fn from_match_fields(fields: &AclMatchFields) -> Self {
        /// Set bit `bit` in `sig` if `field` is `Select`.
        fn set_if_select<T>(sig: &mut u32, bit: u32, field: &crate::match_expr::FieldMatch<T>) {
            if field.is_select() {
                *sig |= 1 << bit;
            }
        }

        let mut sig = 0u32;

        if let Some(eth) = fields.eth() {
            set_if_select(&mut sig, bits::ETH_SRC_MAC, &eth.src_mac);
            set_if_select(&mut sig, bits::ETH_DST_MAC, &eth.dst_mac);
            set_if_select(&mut sig, bits::ETH_TYPE, &eth.ether_type);
        }
        if let Some(vlan) = fields.vlan() {
            set_if_select(&mut sig, bits::VLAN_VID, &vlan.vid);
            set_if_select(&mut sig, bits::VLAN_PCP, &vlan.pcp);
            set_if_select(&mut sig, bits::VLAN_INNER_TYPE, &vlan.inner_ether_type);
        }
        if let Some(ipv4) = fields.ipv4() {
            set_if_select(&mut sig, bits::IPV4_SRC, &ipv4.src);
            set_if_select(&mut sig, bits::IPV4_DST, &ipv4.dst);
            set_if_select(&mut sig, bits::IPV4_PROTO, &ipv4.protocol);
        }
        if let Some(ipv6) = fields.ipv6() {
            set_if_select(&mut sig, bits::IPV6_SRC, &ipv6.src);
            set_if_select(&mut sig, bits::IPV6_DST, &ipv6.dst);
            set_if_select(&mut sig, bits::IPV6_PROTO, &ipv6.protocol);
        }
        if let Some(tcp) = fields.tcp() {
            set_if_select(&mut sig, bits::TCP_SRC, &tcp.src);
            set_if_select(&mut sig, bits::TCP_DST, &tcp.dst);
        }
        if let Some(udp) = fields.udp() {
            set_if_select(&mut sig, bits::UDP_SRC, &udp.src);
            set_if_select(&mut sig, bits::UDP_DST, &udp.dst);
        }
        if let Some(icmp4) = fields.icmp4() {
            set_if_select(&mut sig, bits::ICMP4_TYPE, &icmp4.icmp_type);
            set_if_select(&mut sig, bits::ICMP4_CODE, &icmp4.icmp_code);
        }

        Self(sig)
    }

    /// The number of selected fields.
    #[must_use]
    pub fn field_count(&self) -> u32 {
        self.0.count_ones()
    }

    /// The raw bitset value.
    #[must_use]
    pub fn bits(&self) -> u32 {
        self.0
    }

    /// Whether a specific field bit is set.
    #[must_use]
    pub fn has_field(&self, bit: u32) -> bool {
        self.0 & (1 << bit) != 0
    }

    /// Whether this signature includes Ethernet source MAC.
    #[must_use]
    pub fn has_eth_src_mac(&self) -> bool {
        self.has_field(bits::ETH_SRC_MAC)
    }

    /// Whether this signature includes Ethernet destination MAC.
    #[must_use]
    pub fn has_eth_dst_mac(&self) -> bool {
        self.has_field(bits::ETH_DST_MAC)
    }

    /// Whether this signature includes `ether_type`.
    #[must_use]
    pub fn has_eth_type(&self) -> bool {
        self.has_field(bits::ETH_TYPE)
    }

    /// Whether this signature includes VLAN VID.
    #[must_use]
    pub fn has_vlan_vid(&self) -> bool {
        self.has_field(bits::VLAN_VID)
    }

    /// Whether this signature includes VLAN PCP.
    #[must_use]
    pub fn has_vlan_pcp(&self) -> bool {
        self.has_field(bits::VLAN_PCP)
    }

    /// Whether this signature includes VLAN inner `ether_type`.
    #[must_use]
    pub fn has_vlan_inner_type(&self) -> bool {
        self.has_field(bits::VLAN_INNER_TYPE)
    }

    /// Whether this signature includes IPv4 source.
    #[must_use]
    pub fn has_ipv4_src(&self) -> bool {
        self.has_field(bits::IPV4_SRC)
    }

    /// Whether this signature includes IPv4 destination.
    #[must_use]
    pub fn has_ipv4_dst(&self) -> bool {
        self.has_field(bits::IPV4_DST)
    }

    /// Whether this signature includes IPv4 protocol.
    #[must_use]
    pub fn has_ipv4_proto(&self) -> bool {
        self.has_field(bits::IPV4_PROTO)
    }

    /// Whether this signature includes IPv6 source.
    #[must_use]
    pub fn has_ipv6_src(&self) -> bool {
        self.has_field(bits::IPV6_SRC)
    }

    /// Whether this signature includes IPv6 destination.
    #[must_use]
    pub fn has_ipv6_dst(&self) -> bool {
        self.has_field(bits::IPV6_DST)
    }

    /// Whether this signature includes IPv6 protocol.
    #[must_use]
    pub fn has_ipv6_proto(&self) -> bool {
        self.has_field(bits::IPV6_PROTO)
    }

    /// Whether this signature includes TCP source port.
    #[must_use]
    pub fn has_tcp_src(&self) -> bool {
        self.has_field(bits::TCP_SRC)
    }

    /// Whether this signature includes TCP destination port.
    #[must_use]
    pub fn has_tcp_dst(&self) -> bool {
        self.has_field(bits::TCP_DST)
    }

    /// Whether this signature includes UDP source port.
    #[must_use]
    pub fn has_udp_src(&self) -> bool {
        self.has_field(bits::UDP_SRC)
    }

    /// Whether this signature includes UDP destination port.
    #[must_use]
    pub fn has_udp_dst(&self) -> bool {
        self.has_field(bits::UDP_DST)
    }

    /// Whether this signature includes `ICMPv4` type.
    #[must_use]
    pub fn has_icmp4_type(&self) -> bool {
        self.has_field(bits::ICMP4_TYPE)
    }

    /// Whether this signature includes `ICMPv4` code.
    #[must_use]
    pub fn has_icmp4_code(&self) -> bool {
        self.has_field(bits::ICMP4_CODE)
    }
}

/// A group of rule indices that share the same [`FieldSignature`].
///
/// Each group will become one DPDK ACL context with a `FieldDef` array
/// matching the signature's selected fields.
#[derive(Debug, Clone)]
pub struct SignatureGroup {
    /// The shared field signature.
    signature: FieldSignature,
    /// Indices into the original rule list.
    rule_indices: Vec<usize>,
}

impl SignatureGroup {
    /// The shared field signature for this group.
    #[must_use]
    pub fn signature(&self) -> FieldSignature {
        self.signature
    }

    /// Indices of rules in this group (into the original table's rule list).
    #[must_use]
    pub fn rule_indices(&self) -> &[usize] {
        &self.rule_indices
    }
}

/// Partition a slice of match field sets by their field signature.
///
/// Returns one [`SignatureGroup`] per unique signature.  Groups are
/// sorted by signature for deterministic ordering.
#[must_use]
pub fn group_rules_by_signature(rules: &[AclMatchFields]) -> Vec<SignatureGroup> {
    use std::collections::BTreeMap;

    let mut groups: BTreeMap<FieldSignature, Vec<usize>> = BTreeMap::new();
    for (i, fields) in rules.iter().enumerate() {
        let sig = FieldSignature::from_match_fields(fields);
        groups.entry(sig).or_default().push(i);
    }

    groups
        .into_iter()
        .map(|(signature, rule_indices)| SignatureGroup {
            signature,
            rule_indices,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::match_expr::FieldMatch;
    use crate::priority::Priority;
    use crate::range::{Ipv4Prefix, PortRange};
    use crate::AclRuleBuilder;
    use std::net::Ipv4Addr;

    fn pri(n: u32) -> Priority {
        Priority::new(n).unwrap()
    }

    #[test]
    fn empty_rule_has_empty_signature() {
        let rule = AclRuleBuilder::new().permit(pri(1));
        let sig = FieldSignature::from_match_fields(rule.packet_match());
        assert_eq!(sig, FieldSignature::EMPTY);
        assert_eq!(sig.field_count(), 0);
    }

    #[test]
    fn eth_ipv4_tcp_signature() {
        let rule = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.src =
                    FieldMatch::Select(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
            })
            .tcp(|tcp| {
                tcp.dst = FieldMatch::Select(PortRange::exact(80u16));
            })
            .permit(pri(100));

        let sig = FieldSignature::from_match_fields(rule.packet_match());

        // conform sets ether_type and protocol
        assert!(sig.has_eth_type());
        assert!(sig.has_ipv4_src());
        assert!(!sig.has_ipv4_dst()); // not set in the rule
        assert!(sig.has_ipv4_proto()); // set by conform
        assert!(sig.has_tcp_dst());
        assert!(!sig.has_tcp_src()); // not set
        assert!(!sig.has_ipv6_src()); // not an IPv6 rule

        // eth_type + ipv4_src + ipv4_proto + tcp_dst = 4 fields
        assert_eq!(sig.field_count(), 4);
    }

    #[test]
    fn same_shape_rules_get_same_signature() {
        let r1 = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.src =
                    FieldMatch::Select(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
            })
            .tcp(|tcp| {
                tcp.dst = FieldMatch::Select(PortRange::exact(80u16));
            })
            .permit(pri(100));

        let r2 = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.src = FieldMatch::Select(
                    Ipv4Prefix::new(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap(),
                );
            })
            .tcp(|tcp| {
                tcp.dst =
                    FieldMatch::Select(PortRange::exact(443u16));
            })
            .deny(pri(200));

        let sig1 = FieldSignature::from_match_fields(r1.packet_match());
        let sig2 = FieldSignature::from_match_fields(r2.packet_match());

        assert_eq!(sig1, sig2);
    }

    #[test]
    fn wildcard_transport_shares_signature() {
        // IPv4+TCP and IPv4+UDP with no port constraints share a
        // signature: both have just eth_type + ipv4_proto.  The
        // protocol *value* differs (TCP vs UDP) but the set of
        // *selected fields* is the same.  They belong in the same
        // DPDK context.
        let r1 = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .tcp(|_| {})
            .permit(pri(100));

        let r2 = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .udp(|_| {})
            .deny(pri(100));

        let sig1 = FieldSignature::from_match_fields(r1.packet_match());
        let sig2 = FieldSignature::from_match_fields(r2.packet_match());

        assert_eq!(sig1, sig2);
    }

    #[test]
    fn port_fields_change_signature() {
        // Rule with TCP dst port selected
        let r1 = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .tcp(|tcp| {
                tcp.dst = FieldMatch::Select(PortRange::exact(80u16));
            })
            .permit(pri(100));

        // Rule with no port fields
        let r2 = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .tcp(|_| {})
            .deny(pri(100));

        let sig1 = FieldSignature::from_match_fields(r1.packet_match());
        let sig2 = FieldSignature::from_match_fields(r2.packet_match());

        assert_ne!(sig1, sig2);
        assert!(sig1.has_tcp_dst());
        assert!(!sig2.has_tcp_dst());
    }

    #[test]
    fn wildcard_layers_dont_add_fields() {
        // .eth(|_| {}) with no field modifications → ether_type is Ignore
        let rule = AclRuleBuilder::new().eth(|_| {}).permit(pri(1));
        let sig = FieldSignature::from_match_fields(rule.packet_match());

        // eth layer is present but ether_type is Ignore → not in signature
        assert!(!sig.has_eth_type());
        assert_eq!(sig.field_count(), 0);
    }

    #[test]
    fn group_rules_by_signature_partitions_correctly() {
        // Two IPv4+TCP rules with ports → same signature
        let r0 = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.src =
                    FieldMatch::Select(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
            })
            .tcp(|tcp| {
                tcp.dst = FieldMatch::Select(PortRange::exact(80u16));
            })
            .permit(pri(100));

        let r1 = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.src = FieldMatch::Select(
                    Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 12).unwrap(),
                );
            })
            .tcp(|tcp| {
                tcp.dst =
                    FieldMatch::Select(PortRange::exact(443u16));
            })
            .deny(pri(200));

        // One IPv4-only rule (no ports) → different signature
        let r2 = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.src =
                    FieldMatch::Select(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
            })
            .permit(pri(300));

        let match_fields: Vec<AclMatchFields> = [&r0, &r1, &r2]
            .iter()
            .map(|r| r.packet_match().clone())
            .collect();

        let groups = group_rules_by_signature(&match_fields);

        // Should produce 2 groups
        assert_eq!(groups.len(), 2);

        // Find the group with 2 rules (the TCP port rules)
        let tcp_group = groups.iter().find(|g| g.rule_indices().len() == 2).unwrap();
        assert_eq!(tcp_group.rule_indices(), &[0, 1]);
        assert!(tcp_group.signature().has_tcp_dst());

        // Find the group with 1 rule (the IPv4-only rule)
        let ip_group = groups.iter().find(|g| g.rule_indices().len() == 1).unwrap();
        assert_eq!(ip_group.rule_indices(), &[2]);
        assert!(!ip_group.signature().has_tcp_dst());
    }
}
