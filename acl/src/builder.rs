// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Typestate ACL rule builder.
//!
//! Follows the same trait-driven pattern as the header builder in `dataplane-net`:
//! [`Within<T>`] enforces valid match field ordering at compile time,
//! [`Blank`] provides wildcard defaults, and [`AclRuleBuilder<T, M>`]
//! is the state carrier.
//!
//! Match layers are stored as an ordered sequence in [`AclMatchFields`].
//! The sequence invariant (valid layer ordering, no duplicates) is
//! enforced by construction — [`MatchLayer`] and the inner `Vec` are
//! private, so the only way to build an [`AclMatchFields`] is through
//! the builder.
//!
//! Metadata matches (VRF, VNI, etc.) are orthogonal to protocol layer
//! ordering.  They're carried via the `M` type parameter, which
//! defaults to `()` (no metadata).  Call `.metadata(|m| { ... })` to
//! attach metadata, where the closure's argument type drives inference.

use net::eth::ethtype::EthType;
use net::ip::NextHeader;

use crate::action::ActionSequence;
use crate::match_expr::FieldMatch;
use crate::match_fields::{EthMatch, Icmp4Match, Ipv4Match, Ipv6Match, TcpMatch, UdpMatch};
use crate::metadata::Metadata;
use crate::priority::Priority;
use crate::rule::AclRule;

/// A single match layer in the ordered sequence.
///
/// Private — can only be constructed through the builder, which
/// enforces valid ordering via [`Within<T>`] bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
enum MatchLayer {
    Eth(EthMatch),
    Ipv4(Ipv4Match),
    Ipv6(Ipv6Match),
    Tcp(TcpMatch),
    Udp(UdpMatch),
    Icmp4(Icmp4Match),
}

/// An ordered sequence of match layers accumulated by the builder.
///
/// The sequence is guaranteed to be in valid protocol order (e.g.,
/// Ethernet before IP, IP before transport) because the inner
/// [`MatchLayer`] enum and `Vec` are private.  The only way to
/// construct an `AclMatchFields` is through [`AclRuleBuilder`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AclMatchFields(Vec<MatchLayer>);

impl AclMatchFields {
    /// The number of match layers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the match is empty (no layers constrained).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The Ethernet match layer, if present.
    #[must_use]
    pub fn eth(&self) -> Option<&EthMatch> {
        self.0.iter().find_map(|l| match l {
            MatchLayer::Eth(m) => Some(m),
            _ => None,
        })
    }

    /// The IPv4 match layer, if present.
    #[must_use]
    pub fn ipv4(&self) -> Option<&Ipv4Match> {
        self.0.iter().find_map(|l| match l {
            MatchLayer::Ipv4(m) => Some(m),
            _ => None,
        })
    }

    /// The IPv6 match layer, if present.
    #[must_use]
    pub fn ipv6(&self) -> Option<&Ipv6Match> {
        self.0.iter().find_map(|l| match l {
            MatchLayer::Ipv6(m) => Some(m),
            _ => None,
        })
    }

    /// The TCP match layer, if present.
    #[must_use]
    pub fn tcp(&self) -> Option<&TcpMatch> {
        self.0.iter().find_map(|l| match l {
            MatchLayer::Tcp(m) => Some(m),
            _ => None,
        })
    }

    /// The UDP match layer, if present.
    #[must_use]
    pub fn udp(&self) -> Option<&UdpMatch> {
        self.0.iter().find_map(|l| match l {
            MatchLayer::Udp(m) => Some(m),
            _ => None,
        })
    }

    /// The `ICMPv4` match layer, if present.
    #[must_use]
    pub fn icmp4(&self) -> Option<&Icmp4Match> {
        self.0.iter().find_map(|l| match l {
            MatchLayer::Icmp4(m) => Some(m),
            _ => None,
        })
    }
}

// ---- Traits ----

/// Declares that `Self` is a valid child of match layer `T`.
///
/// When `Self` is stacked on a parent `T`, [`conform`](Within::conform)
/// adjusts the parent's fields to be consistent with the child.
/// For example, `Within<Ipv4Match> for TcpMatch` sets
/// `protocol = Some(NextHeader::TCP)` on the IPv4 match.
pub trait Within<T> {
    /// Adjust `parent` to be consistent with `Self` being stacked on it.
    fn conform(parent: &mut T);
}

/// Declares that [`AclMatchFields`] can absorb a value of type `T`.
pub trait Install<T> {
    /// Append `value` to the match layer sequence.
    fn install(&mut self, value: T);
}

/// Produce an all-wildcard instance of a match type.
///
/// ACL `Blank` produces an all-`None` (don't-care) match layer —
/// the most permissive possible.
pub trait Blank {
    /// Return an all-wildcard match layer.
    fn blank() -> Self;
}

// ---- Builder ----

/// Typestate ACL rule builder.
///
/// `T` is the protocol match layer currently being held.  `M` is the
/// metadata match type (defaults to `()` for no metadata).
///
/// Start with [`AclRuleBuilder::new()`], optionally call
/// `.metadata(|m| { ... })`, chain protocol match methods, then
/// finalize with `.permit(priority)` or `.deny(priority)`.
pub struct AclRuleBuilder<T, M: Metadata = ()> {
    fields: AclMatchFields,
    metadata: M,
    working: T,
}

impl AclRuleBuilder<()> {
    /// Create a new rule builder with no metadata.
    #[must_use]
    pub fn new() -> Self {
        AclRuleBuilder {
            fields: AclMatchFields::default(),
            metadata: (),
            working: (),
        }
    }
}

impl Default for AclRuleBuilder<()> {
    fn default() -> Self {
        Self::new()
    }
}

// Metadata transition: only available when M = () (not yet set).
impl<T> AclRuleBuilder<T, ()>
where
    AclMatchFields: Install<T>,
{
    /// Attach metadata match criteria.
    ///
    /// The metadata type `M` is inferred from the closure argument.
    /// A default (all-wildcard) `M` is created, then `f` runs to
    /// constrain it.
    ///
    /// Can be called at any point in the layer chain, but only once
    /// (calling it transitions `M` from `()` to the user's type).
    pub fn metadata<M: Metadata>(self, f: impl FnOnce(&mut M)) -> AclRuleBuilder<T, M> {
        let mut meta = M::default();
        f(&mut meta);
        AclRuleBuilder {
            fields: self.fields,
            metadata: meta,
            working: self.working,
        }
    }
}

/// Helper macro to generate named match-layer methods.
macro_rules! match_method {
    ($(#[$meta:meta])* $method:ident, $field:ty) => {
        $(#[$meta])*
        pub fn $method(self, f: impl FnOnce(&mut $field)) -> AclRuleBuilder<$field, M>
        where
            $field: Blank + Within<T>,
            AclMatchFields: Install<$field>,
        {
            self.stack(f)
        }
    };
}

impl<T, M: Metadata> AclRuleBuilder<T, M>
where
    AclMatchFields: Install<T>,
{
    /// Push a new match layer onto the builder.
    ///
    /// The new layer is created via [`Blank::blank`] (all-wildcard),
    /// then the closure `f` runs to constrain it.  The previous layer
    /// is conformed and installed before the new layer is created.
    pub fn stack<U>(mut self, f: impl FnOnce(&mut U)) -> AclRuleBuilder<U, M>
    where
        U: Blank + Within<T>,
        AclMatchFields: Install<U>,
    {
        U::conform(&mut self.working);
        self.fields.install(self.working);

        let mut m = U::blank();
        f(&mut m);
        AclRuleBuilder {
            fields: self.fields,
            metadata: self.metadata,
            working: m,
        }
    }

    /// Finalize the rule with a [`Forward`](crate::Fate::Forward) fate (permit).
    #[must_use]
    pub fn permit(mut self, priority: Priority) -> AclRule<M> {
        self.fields.install(self.working);
        AclRule::new(self.fields, self.metadata, ActionSequence::forward(), priority)
    }

    /// Finalize the rule with a [`Drop`](crate::Fate::Drop) fate (deny).
    #[must_use]
    pub fn deny(mut self, priority: Priority) -> AclRule<M> {
        self.fields.install(self.working);
        AclRule::new(self.fields, self.metadata, ActionSequence::drop_packet(), priority)
    }

    /// Finalize the rule with a custom [`ActionSequence`].
    #[must_use]
    pub fn action(mut self, actions: ActionSequence, priority: Priority) -> AclRule<M> {
        self.fields.install(self.working);
        AclRule::new(self.fields, self.metadata, actions, priority)
    }

    match_method!(
        /// Add an Ethernet match layer.
        eth, EthMatch
    );
    match_method!(
        /// Add an IPv4 match layer.
        ipv4, Ipv4Match
    );
    match_method!(
        /// Add an IPv6 match layer.
        ipv6, Ipv6Match
    );
    match_method!(
        /// Add a TCP match layer.
        tcp, TcpMatch
    );
    match_method!(
        /// Add a UDP match layer.
        udp, UdpMatch
    );
    match_method!(
        /// Add an `ICMPv4` match layer.
        icmp4, Icmp4Match
    );
}

// ---- Within impls ----

impl Within<()> for EthMatch {
    fn conform(_parent: &mut ()) {}
}

impl Within<EthMatch> for Ipv4Match {
    fn conform(parent: &mut EthMatch) {
        parent.ether_type = FieldMatch::Select(EthType::IPV4);
    }
}

impl Within<EthMatch> for Ipv6Match {
    fn conform(parent: &mut EthMatch) {
        parent.ether_type = FieldMatch::Select(EthType::IPV6);
    }
}

impl Within<Ipv4Match> for TcpMatch {
    fn conform(parent: &mut Ipv4Match) {
        parent.protocol = FieldMatch::Select(NextHeader::TCP);
    }
}

impl Within<Ipv6Match> for TcpMatch {
    fn conform(parent: &mut Ipv6Match) {
        parent.protocol = FieldMatch::Select(NextHeader::TCP);
    }
}

impl Within<Ipv4Match> for UdpMatch {
    fn conform(parent: &mut Ipv4Match) {
        parent.protocol = FieldMatch::Select(NextHeader::UDP);
    }
}

impl Within<Ipv6Match> for UdpMatch {
    fn conform(parent: &mut Ipv6Match) {
        parent.protocol = FieldMatch::Select(NextHeader::UDP);
    }
}

impl Within<Ipv4Match> for Icmp4Match {
    fn conform(parent: &mut Ipv4Match) {
        parent.protocol = FieldMatch::Select(NextHeader::ICMP);
    }
}

// ---- Install impls ----

impl Install<()> for AclMatchFields {
    fn install(&mut self, (): ()) {}
}

impl Install<EthMatch> for AclMatchFields {
    fn install(&mut self, eth: EthMatch) {
        self.0.push(MatchLayer::Eth(eth));
    }
}

impl Install<Ipv4Match> for AclMatchFields {
    fn install(&mut self, ipv4: Ipv4Match) {
        self.0.push(MatchLayer::Ipv4(ipv4));
    }
}

impl Install<Ipv6Match> for AclMatchFields {
    fn install(&mut self, ipv6: Ipv6Match) {
        self.0.push(MatchLayer::Ipv6(ipv6));
    }
}

impl Install<TcpMatch> for AclMatchFields {
    fn install(&mut self, tcp: TcpMatch) {
        self.0.push(MatchLayer::Tcp(tcp));
    }
}

impl Install<UdpMatch> for AclMatchFields {
    fn install(&mut self, udp: UdpMatch) {
        self.0.push(MatchLayer::Udp(udp));
    }
}

impl Install<Icmp4Match> for AclMatchFields {
    fn install(&mut self, icmp4: Icmp4Match) {
        self.0.push(MatchLayer::Icmp4(icmp4));
    }
}

// ---- Blank impls ----

impl Blank for () {
    fn blank() -> Self {}
}

impl Blank for EthMatch {
    fn blank() -> Self {
        Self::default()
    }
}

impl Blank for Ipv4Match {
    fn blank() -> Self {
        Self::default()
    }
}

impl Blank for Ipv6Match {
    fn blank() -> Self {
        Self::default()
    }
}

impl Blank for TcpMatch {
    fn blank() -> Self {
        Self::default()
    }
}

impl Blank for UdpMatch {
    fn blank() -> Self {
        Self::default()
    }
}

impl Blank for Icmp4Match {
    fn blank() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::Fate;
    use crate::match_expr::ExactMatch;
    use crate::priority::Priority;
    use crate::range::{Ipv4Prefix, Ipv6Prefix, PortRange};
    use net::eth::ethtype::EthType;
    use net::ip::NextHeader;
    use net::tcp::port::TcpPort;
    use net::udp::port::UdpPort;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn pri(n: u32) -> Priority {
        Priority::new(n).unwrap()
    }

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    struct TestMeta {
        vrf: Option<ExactMatch<u32>>,
        vni: Option<ExactMatch<u32>>,
    }

    impl Metadata for TestMeta {}

    #[test]
    fn ipv4_tcp_rule() {
        let rule = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.src = FieldMatch::Select(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
            })
            .tcp(|tcp| {
                tcp.dst = FieldMatch::Select(PortRange::exact(TcpPort::new_checked(80).unwrap()));
            })
            .permit(pri(100));

        assert_eq!(rule.actions().fate(), Fate::Forward);
        assert_eq!(rule.priority(), pri(100));

        let eth = rule.packet_match().eth().unwrap();
        assert_eq!(eth.ether_type, FieldMatch::Select(EthType::IPV4));

        let ipv4 = rule.packet_match().ipv4().unwrap();
        assert_eq!(ipv4.protocol, FieldMatch::Select(NextHeader::TCP));
        assert!(ipv4.src.is_select());
        assert!(ipv4.dst.is_ignore());
    }

    #[test]
    fn ipv6_udp_rule() {
        let rule = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv6(|ip| {
                ip.dst = FieldMatch::Select(Ipv6Prefix::host(Ipv6Addr::LOCALHOST));
            })
            .udp(|udp| {
                udp.dst = FieldMatch::Select(PortRange::exact(UdpPort::new_checked(53).unwrap()));
            })
            .deny(pri(200));

        assert_eq!(rule.actions().fate(), Fate::Drop);

        let eth = rule.packet_match().eth().unwrap();
        assert_eq!(eth.ether_type, FieldMatch::Select(EthType::IPV6));

        let ipv6 = rule.packet_match().ipv6().unwrap();
        assert_eq!(ipv6.protocol, FieldMatch::Select(NextHeader::UDP));
    }

    #[test]
    fn icmp4_rule() {
        let rule = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .icmp4(|icmp| {
                icmp.icmp_type = FieldMatch::Select(8);
            })
            .permit(pri(300));

        let ipv4 = rule.packet_match().ipv4().unwrap();
        assert_eq!(ipv4.protocol, FieldMatch::Select(NextHeader::ICMP));

        let icmp = rule.packet_match().icmp4().unwrap();
        assert_eq!(icmp.icmp_type, FieldMatch::Select(8));
        assert_eq!(icmp.icmp_code, FieldMatch::Ignore);
    }

    #[test]
    fn wildcard_eth_only() {
        let rule = AclRuleBuilder::new().eth(|_| {}).deny(pri(999));

        let eth = rule.packet_match().eth().unwrap();
        assert_eq!(eth.ether_type, FieldMatch::Ignore);
        assert!(rule.packet_match().ipv4().is_none());
        assert!(rule.packet_match().tcp().is_none());
    }

    #[test]
    fn table_collects_rules() {
        let r1 = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .permit(pri(100));

        let r2 = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv6(|_| {})
            .deny(pri(999));

        let table = crate::AclTableBuilder::new(Fate::Drop)
            .add_rule(r1)
            .add_rule(r2)
            .build();

        assert_eq!(table.rules().len(), 2);
        assert_eq!(table.default_fate(), Fate::Drop);
    }

    #[test]
    fn permit_without_match_layers() {
        let rule = AclRuleBuilder::new().permit(pri(1));
        assert_eq!(rule.actions().fate(), Fate::Forward);
        assert!(rule.packet_match().is_empty());
    }

    #[test]
    fn layer_ordering_preserved() {
        let rule = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .tcp(|_| {})
            .permit(pri(1));

        assert_eq!(rule.packet_match().len(), 3);
        assert!(rule.packet_match().eth().is_some());
        assert!(rule.packet_match().ipv4().is_some());
        assert!(rule.packet_match().tcp().is_some());
    }

    #[test]
    fn metadata_before_layers() {
        let rule = AclRuleBuilder::new()
            .metadata(|m: &mut TestMeta| {
                m.vrf = Some(ExactMatch(42));
            })
            .eth(|_| {})
            .ipv4(|_| {})
            .permit(pri(100));

        assert_eq!(rule.metadata().vrf, Some(ExactMatch(42)));
        assert_eq!(rule.metadata().vni, None);
    }

    #[test]
    fn metadata_between_layers() {
        let rule = AclRuleBuilder::new()
            .eth(|_| {})
            .metadata(|m: &mut TestMeta| {
                m.vni = Some(ExactMatch(1000));
            })
            .ipv4(|_| {})
            .tcp(|_| {})
            .deny(pri(50));

        assert_eq!(rule.metadata().vni, Some(ExactMatch(1000)));
        let ipv4 = rule.packet_match().ipv4().unwrap();
        assert_eq!(ipv4.protocol, FieldMatch::Select(NextHeader::TCP));
    }

    #[test]
    fn no_metadata_uses_unit() {
        let rule = AclRuleBuilder::new()
            .eth(|_| {})
            .permit(pri(1));

        assert_eq!(rule.metadata(), &());
    }
}
