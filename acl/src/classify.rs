// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Linear-scan reference classifier.
//!
//! This is the simplest possible ACL classifier: it walks the rules in
//! priority order and returns the action of the first match, or the
//! default action if no rule matches.
//!
//! It exists for two purposes:
//!
//! 1. **Reference semantics** — it defines what "correct" means.  Every
//!    other backend (DPDK ACL, `rte_flow`, `tc-flower`) must produce the
//!    same result as this linear scan.
//! 2. **Property testing oracle** — bolero/proptest can generate
//!    arbitrary rule sets and packets, classify with both this and a
//!    "smart" backend, and assert identical results.
//!
//! Performance is explicitly not a goal.  Clarity and correctness are.

use std::net::{Ipv4Addr, Ipv6Addr};

use net::headers::{Headers, Net, Transport};

use crate::action::{ActionSequence, Fate};
use crate::builder::AclMatchFields;
use crate::match_fields::{
    EthMatch, Icmp4Match, Ipv4Match, Ipv6Match, TcpMatch, UdpMatch, VlanMatch,
};
use crate::metadata::Metadata;
use crate::range::{Ipv4Prefix, Ipv6Prefix, PortRange};
use crate::rule::AclRule;
use crate::table::AclTable;

/// The result of classifying a packet.
///
/// Either the matched rule's full [`ActionSequence`], or the table's
/// default [`Fate`] if no rule matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassifyOutcome<'a> {
    /// A rule matched — execute this action sequence.
    Matched(&'a ActionSequence),
    /// No rule matched — apply the default fate.
    Default(Fate),
}

impl ClassifyOutcome<'_> {
    /// The terminal fate, regardless of whether a rule matched.
    #[must_use]
    pub fn fate(&self) -> Fate {
        match self {
            Self::Matched(seq) => seq.fate(),
            Self::Default(fate) => *fate,
        }
    }
}

/// A compiled linear-scan classifier.
///
/// Rules are sorted by priority (lower value = higher precedence).
/// Classification walks the sorted list and returns the first match.
#[derive(Debug, Clone)]
pub struct LinearClassifier<M: Metadata = ()> {
    rules: Vec<AclRule<M>>,
    default_fate: Fate,
}

impl<M: Metadata> LinearClassifier<M> {
    /// Classify a packet's headers against the rule set.
    ///
    /// Returns the full [`ClassifyOutcome`]: either the matched rule's
    /// [`ActionSequence`] or the table's default [`Fate`].
    #[must_use]
    pub fn classify(&self, headers: &Headers) -> ClassifyOutcome<'_> {
        for rule in &self.rules {
            if rule_matches_headers(rule.packet_match(), headers) {
                return ClassifyOutcome::Matched(rule.actions());
            }
        }
        ClassifyOutcome::Default(self.default_fate)
    }

    /// The default fate when no rule matches.
    #[must_use]
    pub fn default_fate(&self) -> Fate {
        self.default_fate
    }

    /// The rules, in priority order.
    #[must_use]
    pub fn rules(&self) -> &[AclRule<M>] {
        &self.rules
    }
}

impl<M: Metadata + Clone> AclTable<M> {
    /// Compile the table into a linear-scan classifier.
    ///
    /// Rules are sorted by priority (lower value = higher precedence).
    /// This is the reference implementation — correct but not fast.
    #[must_use]
    pub fn compile_linear(&self) -> LinearClassifier<M> {
        let mut rules: Vec<AclRule<M>> = self.rules().to_vec();
        rules.sort_by_key(AclRule::priority);
        LinearClassifier {
            rules,
            default_fate: self.default_fate(),
        }
    }
}

// ---- Matching logic ----
//
// Each function below checks whether a single match layer is satisfied
// by the packet.  `None` fields in the match are wildcards (always match).
// A rule matches if ALL of its match layers match.

/// Check if a rule's match fields are satisfied by the given headers.
/// Check if a rule's match fields are satisfied by the given headers.
///
/// Exposed as `pub(crate)` for use by the [`Classifier`](crate::Classifier)
/// wrapper. Not part of the public API.
pub(crate) fn rule_matches_headers(fields: &AclMatchFields, headers: &Headers) -> bool {
    fields.eth().is_none_or(|m| eth_matches(m, headers))
        && fields.vlan().is_none_or(|m| vlan_matches(m, headers))
        && fields.ipv4().is_none_or(|m| ipv4_matches(m, headers))
        && fields.ipv6().is_none_or(|m| ipv6_matches(m, headers))
        && fields.tcp().is_none_or(|m| tcp_matches(m, headers))
        && fields.udp().is_none_or(|m| udp_matches(m, headers))
        && fields.icmp4().is_none_or(|m| icmp4_matches(m, headers))
}

/// Ethernet layer matching.
fn eth_matches(m: &EthMatch, headers: &Headers) -> bool {
    let eth = headers.eth();
    m.src_mac
        .matches(|mac| eth.is_some_and(|e| e.source().inner() == *mac))
        && m.dst_mac
            .matches(|mac| eth.is_some_and(|e| e.destination().inner() == *mac))
        && m.ether_type
            .matches(|et| eth.is_some_and(|e| e.ether_type() == *et))
}

/// VLAN layer matching.
fn vlan_matches(m: &VlanMatch, headers: &Headers) -> bool {
    let vlans = headers.vlan();
    if vlans.is_empty() {
        // Rule requires VLAN but packet has none.
        return false;
    }
    // Match against the first (outermost) VLAN tag.
    let vlan = &vlans[0];
    m.vid.matches(|v| vlan.vid() == *v)
        && m.pcp.matches(|p| vlan.pcp() == *p)
        && m.inner_ether_type
            .matches(|et| vlan.inner_ethtype() == *et)
}

/// IPv4 layer matching.
fn ipv4_matches(m: &Ipv4Match, headers: &Headers) -> bool {
    let Some(Net::Ipv4(ip)) = headers.net() else {
        return false;
    };

    m.src.matches(|pfx| ipv4_in_prefix(*pfx, ip.source().into()))
        && m.dst.matches(|pfx| ipv4_in_prefix(*pfx, ip.destination()))
        && m.protocol.matches(|p| ip.next_header() == *p)
}

/// IPv6 layer matching.
fn ipv6_matches(m: &Ipv6Match, headers: &Headers) -> bool {
    let Some(Net::Ipv6(ip)) = headers.net() else {
        return false;
    };

    m.src.matches(|pfx| ipv6_in_prefix(*pfx, ip.source().into()))
        && m.dst.matches(|pfx| ipv6_in_prefix(*pfx, ip.destination()))
        && m.protocol.matches(|p| ip.next_header() == *p)
}

/// TCP layer matching.
fn tcp_matches(m: &TcpMatch, headers: &Headers) -> bool {
    let Some(Transport::Tcp(tcp)) = headers.transport() else {
        return false;
    };

    m.src
        .matches(|r| port_in_range(*r, tcp.source().as_u16()))
        && m.dst
            .matches(|r| port_in_range(*r, tcp.destination().as_u16()))
}

/// UDP layer matching.
fn udp_matches(m: &UdpMatch, headers: &Headers) -> bool {
    let Some(Transport::Udp(udp)) = headers.transport() else {
        return false;
    };

    m.src
        .matches(|r| port_in_range(*r, udp.source().as_u16()))
        && m.dst
            .matches(|r| port_in_range(*r, udp.destination().as_u16()))
}

/// `ICMPv4` layer matching.
///
/// Note: ICMP type/code matching requires access to raw type/code u8
/// values from the `Icmp4` header.  Currently `Icmp4` only exposes the
/// rich `Icmpv4Type` enum.  Full type/code matching will require
/// adding `type_u8()` and `code_u8()` accessors to `Icmp4`.
fn icmp4_matches(m: &Icmp4Match, headers: &Headers) -> bool {
    let Some(Transport::Icmp4(_icmp)) = headers.transport() else {
        return false;
    };

    // TODO: implement type/code matching once Icmp4 exposes raw u8 accessors.
    // For now, if the rule specifies type or code constraints, we
    // conservatively fail the match since we cannot verify them.
    m.icmp_type.is_ignore() && m.icmp_code.is_ignore()
}

// ---- Helper functions ----

/// Check if an IPv4 address falls within a prefix.
fn ipv4_in_prefix(prefix: Ipv4Prefix, addr: Ipv4Addr) -> bool {
    let mask = prefix.mask();
    (u32::from(addr) & mask) == u32::from(prefix.addr())
}

/// Check if an IPv6 address falls within a prefix.
fn ipv6_in_prefix(prefix: Ipv6Prefix, addr: Ipv6Addr) -> bool {
    let mask = prefix.mask();
    (u128::from(addr) & mask) == u128::from(prefix.addr())
}

/// Check if a u16 port value falls within a range.
fn port_in_range(range: PortRange<u16>, port: u16) -> bool {
    port >= range.min && port <= range.max
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::Fate;
    use crate::match_expr::FieldMatch;
    use crate::priority::Priority;
    use crate::{AclRuleBuilder, AclTableBuilder};
    use net::headers::builder::HeaderStack;
    use net::tcp::port::TcpPort;
    use net::vlan::{Pcp, Vid};

    /// Shorthand for creating a Priority in tests.
    fn pri(n: u32) -> Priority {
        Priority::new(n).unwrap()
    }

    #[test]
    fn empty_table_returns_default() {
        let table: AclTable = AclTableBuilder::new(Fate::Drop).build();
        let classifier = table.compile_linear();

        let headers = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .tcp(|_| {})
            .build_headers()
            .unwrap();

        assert_eq!(classifier.classify(&headers).fate(), Fate::Drop);
    }

    #[test]
    fn permit_all_rule() {
        let table = AclTableBuilder::new(Fate::Drop)
            .add_rule(AclRuleBuilder::new().permit(pri(100)))
            .build();

        let classifier = table.compile_linear();

        let headers = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .tcp(|_| {})
            .build_headers()
            .unwrap();

        assert_eq!(classifier.classify(&headers).fate(), Fate::Forward);
    }

    #[test]
    fn ipv4_prefix_match() {
        use std::net::Ipv4Addr;

        let table_builder = AclTableBuilder::new(Fate::Drop);

        let example_rule1 = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.src = FieldMatch::Select(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
            })
            .tcp(|tcp| {
                tcp.dst = FieldMatch::Select(PortRange {
                    min: 1u16,
                    max: 1024u16,
                });
            })
            .permit(pri(100));

        let example_rule2 = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv6(|ip| {
                ip.dst = FieldMatch::Select(
                    Ipv6Prefix::new(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 64).unwrap(),
                );
            })
            .permit(pri(50));

        let table = table_builder
            .add_rule(example_rule1)
            .add_rule(example_rule2)
            .build();
        let classifier = table.compile_linear();

        let matching_headers = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.set_source(net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(10, 1, 2, 3)).unwrap());
            })
            .tcp(|tcp| {
                tcp.set_destination(TcpPort::new_checked(80).unwrap());
            })
            .build_headers()
            .unwrap();
        assert_eq!(classifier.classify(&matching_headers).fate(), Fate::Forward);

        let non_matching_headers = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.set_source(
                    net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(192, 168, 1, 1)).unwrap(),
                );
            })
            .tcp(|_| {})
            .build_headers()
            .unwrap();
        assert_eq!(classifier.classify(&non_matching_headers).fate(), Fate::Drop);

        let leading_vlan_protocol = HeaderStack::new()
            .eth(|_| {})
            .vlan(|v| {
                v.set_vid(Vid::new(3).unwrap());
            })
            .ipv4(|ip| {
                ip.set_source(net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(10, 1, 2, 3)).unwrap());
            })
            .tcp(|tcp| {
                tcp.set_destination(TcpPort::new_checked(80).unwrap());
            })
            .build_headers()
            .unwrap();
        assert_eq!(classifier.classify(&leading_vlan_protocol).fate(), Fate::Drop);

        let priority_tagged = HeaderStack::new()
            .eth(|_| {})
            .vlan(|v| {
                v.set_pcp(Pcp::new(2).unwrap());
            })
            .ipv4(|ip| {
                ip.set_source(net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(10, 1, 2, 3)).unwrap());
            })
            .tcp(|tcp| {
                tcp.set_destination(TcpPort::new_checked(80).unwrap());
            })
            .build_headers()
            .unwrap();
        assert_eq!(classifier.classify(&priority_tagged).fate(), Fate::Drop);
    }

    #[test]
    fn priority_ordering() {
        use std::net::Ipv4Addr;

        let broad = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.src = FieldMatch::Select(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
            })
            .permit(pri(200));

        let narrow = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.src = FieldMatch::Select(Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 16).unwrap());
            })
            .deny(pri(100));

        let table = AclTableBuilder::new(Fate::Drop)
            .add_rule(broad)
            .add_rule(narrow)
            .build();
        let classifier = table.compile_linear();

        let pkt = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.set_source(net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(10, 1, 2, 3)).unwrap());
            })
            .tcp(|_| {})
            .build_headers()
            .unwrap();
        assert_eq!(classifier.classify(&pkt).fate(), Fate::Drop);

        let pkt2 = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.set_source(net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(10, 2, 0, 1)).unwrap());
            })
            .tcp(|_| {})
            .build_headers()
            .unwrap();
        assert_eq!(classifier.classify(&pkt2).fate(), Fate::Forward);
    }

    #[test]
    fn tcp_port_range_match() {
        let rule = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .tcp(|tcp| {
                tcp.dst = FieldMatch::Select(PortRange::new(80u16, 443u16).unwrap());
            })
            .permit(pri(100));

        let table = AclTableBuilder::new(Fate::Drop).add_rule(rule).build();
        let classifier = table.compile_linear();

        let pkt80 = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .tcp(|tcp| {
                tcp.set_destination(TcpPort::new_checked(80).unwrap());
            })
            .build_headers()
            .unwrap();
        assert_eq!(classifier.classify(&pkt80).fate(), Fate::Forward);

        let pkt443 = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .tcp(|tcp| {
                tcp.set_destination(TcpPort::new_checked(443).unwrap());
            })
            .build_headers()
            .unwrap();
        assert_eq!(classifier.classify(&pkt443).fate(), Fate::Forward);

        let pkt8080 = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .tcp(|tcp| {
                tcp.set_destination(TcpPort::new_checked(8080).unwrap());
            })
            .build_headers()
            .unwrap();
        assert_eq!(classifier.classify(&pkt8080).fate(), Fate::Drop);
    }

    #[test]
    fn ipv4_rule_does_not_match_ipv6_packet() {
        let rule = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| ip.src = FieldMatch::Select(Ipv4Prefix::any()))
            .permit(pri(100));

        let table = AclTableBuilder::new(Fate::Drop).add_rule(rule).build();
        let classifier = table.compile_linear();

        let ipv6_pkt = HeaderStack::new()
            .eth(|_| {})
            .ipv6(|_| {})
            .tcp(|_| {})
            .build_headers()
            .unwrap();
        assert_eq!(classifier.classify(&ipv6_pkt).fate(), Fate::Drop);
    }

    #[test]
    fn ether_type_match() {
        use net::eth::ethtype::EthType;

        let rule = AclRuleBuilder::new()
            .eth(|e| e.ether_type = FieldMatch::Select(EthType::IPV4))
            .permit(pri(100));

        let table = AclTableBuilder::new(Fate::Drop).add_rule(rule).build();
        let classifier = table.compile_linear();

        let ipv4_pkt = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .tcp(|_| {})
            .build_headers()
            .unwrap();
        assert_eq!(classifier.classify(&ipv4_pkt).fate(), Fate::Forward);

        let ipv6_pkt = HeaderStack::new()
            .eth(|_| {})
            .ipv6(|_| {})
            .tcp(|_| {})
            .build_headers()
            .unwrap();
        assert_eq!(classifier.classify(&ipv6_pkt).fate(), Fate::Drop);
    }

    #[test]
    fn conform_sets_protocol_for_matching() {
        let rule = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .tcp(|_| {})
            .permit(pri(100));

        let table = AclTableBuilder::new(Fate::Drop).add_rule(rule).build();
        let classifier = table.compile_linear();

        let tcp_pkt = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .tcp(|_| {})
            .build_headers()
            .unwrap();
        assert_eq!(classifier.classify(&tcp_pkt).fate(), Fate::Forward);

        let udp_pkt = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .udp(|_| {})
            .build_headers()
            .unwrap();
        assert_eq!(classifier.classify(&udp_pkt).fate(), Fate::Drop);
    }
}
