#![allow(unsafe_code)] // scratch harness uses #[unsafe(no_mangle)]

// ---- scratch 5 -----
//
// NF pipeline topology sketch (scratch 5 / 6 notes kept in git history;
// this file now carries only a minimal harness to eyeball the Window
// abstraction's emitted asm from a consumer crate).
//
// Expected digraph evolution (first-stage compile -> synthesized
// passthrough edges):
//
// ```dot
// digraph G {
//     ingress -> nf_0_0;
//     ingress -> nf_0_1;
//     nf_0_0 -> nf_1_0;
//     nf_0_0 -> nf_1_1;
//     nf_0_0 -> nf_1_2;
//     nf_0_1 -> nf_1_0;
//     nf_0_1 -> nf_1_2;
//     nf_0_1 -> nf_2_0;
//     nf_1_0 -> nf_2_0;
//     nf_1_1 -> nf_2_0;
//     nf_2_0 -> egress;
// }
// ```
//
// ```dot
// digraph G {
//     ingress -> nf_0_0;
//     ingress -> nf_0_1;
//     nf_0_0 -> nf_1_0;
//     nf_0_0 -> nf_1_1;
//     nf_0_0 -> nf_1_2;
//     nf_0_1 -> nf_1_0;
//     nf_0_1 -> nf_1_2;
//     // synthetic passthrough induced by type system / compiler
//     nf_0_1 -> nf_1_3;
//     nf_1_0 -> nf_2_0;
//     nf_1_1 -> nf_2_0;
//     nf_1_3 -> nf_2_0;
//     nf_2_0 -> egress;
// }
// ```

use std::net::{Ipv4Addr, Ipv6Addr};

use net::{
    eth::Eth,
    headers::{Headers, Look, Window},
    ipv4::Ipv4,
    ipv6::Ipv6,
    tcp::Tcp,
    udp::Udp,
};

// ===========================================================================
// Action / identity / outcome
// ===========================================================================

/// Decision produced by classifying a packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Accept,
    Drop,
}

/// Runtime identity of a logical table.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
#[repr(transparent)]
pub struct TableId(pub u32);

/// Identity of a specific rule within a table.  `local == u32::MAX`
/// is reserved for the implicit default-rule match.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct MatchId {
    pub table: TableId,
    pub local: u32,
}

impl MatchId {
    pub const DEFAULT_LOCAL: u32 = u32::MAX;

    pub const fn default_for(table: TableId) -> Self {
        Self {
            table,
            local: Self::DEFAULT_LOCAL,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Outcome {
    pub rule: MatchId,
    pub action: Action,
}

// ===========================================================================
// The Select trait and the generic RuleBody / Linear machinery
// ===========================================================================

pub trait Select<Shape> {
    fn select(&self, key: &Window<Shape>) -> Outcome;
}

/// A rule body that matches against the refs tuple of Window<Shape>.
///
/// Rules author themselves per-shape by implementing this trait with
/// the appropriate Shape type parameter.  Linear<Shape, R> consumes
/// any R that implements RuleBody<Shape>.
pub trait RuleBody<Shape>
where
    Window<Shape>: Look<Shape>,
{
    fn matches<'a>(&self, refs: <Window<Shape> as Look<Shape>>::Refs<'a>) -> bool;
    fn action(&self) -> Action;
}

/// Generic linear classifier.  One type, parameterized by Shape + Rule.
/// First-match wins; falls through to `default_action` on exhaustion.
pub struct Linear<Shape, R> {
    id: TableId,
    rules: Vec<R>,
    default_action: Action,
    // Variance trick: fn() -> Shape gives us contravariant behavior,
    // which means Shape lifetimes inside the tuple don't force
    // `Self: 'shape`.  Since we never actually store anything of type
    // Shape, this is sound.
    _shape: core::marker::PhantomData<fn() -> Shape>,
}

impl<Shape, R> Linear<Shape, R> {
    pub fn new(id: TableId, default_action: Action) -> Self {
        Self {
            id,
            rules: Vec::new(),
            default_action,
            _shape: core::marker::PhantomData,
        }
    }

    pub fn push(&mut self, rule: R) {
        self.rules.push(rule);
    }
}

impl<Shape, R> Select<Shape> for Linear<Shape, R>
where
    R: RuleBody<Shape>,
    Window<Shape>: Look<Shape>,
    // Refs tuple is Copy for all lifetimes (tuple of & is always Copy);
    // needed so the select loop can reuse `refs` across iterations.
    for<'a> <Window<Shape> as Look<Shape>>::Refs<'a>: Copy,
{
    fn select(&self, key: &Window<Shape>) -> Outcome {
        let refs = key.look();
        for (idx, rule) in self.rules.iter().enumerate() {
            if rule.matches(refs) {
                return Outcome {
                    rule: MatchId {
                        table: self.id,
                        local: idx as u32,
                    },
                    action: rule.action(),
                };
            }
        }
        Outcome {
            rule: MatchId::default_for(self.id),
            action: self.default_action,
        }
    }
}

// ===========================================================================
// Match predicates
// ===========================================================================

/// IPv4 prefix match expressed as (network, mask).
#[derive(Clone, Copy, Debug)]
pub struct V4Prefix {
    addr: u32, // already masked
    mask: u32,
}

impl V4Prefix {
    pub fn new(addr: Ipv4Addr, prefix_len: u8) -> Self {
        let bits = u32::from(addr);
        let mask = if prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - prefix_len)
        };
        Self {
            addr: bits & mask,
            mask,
        }
    }

    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        (u32::from(addr) & self.mask) == self.addr
    }
}

/// IPv6 prefix match.
#[derive(Clone, Copy, Debug)]
pub struct V6Prefix {
    addr: u128,
    mask: u128,
}

impl V6Prefix {
    pub fn new(addr: Ipv6Addr, prefix_len: u8) -> Self {
        let bits = u128::from(addr);
        let mask = if prefix_len == 0 {
            0
        } else {
            u128::MAX << (128 - prefix_len)
        };
        Self {
            addr: bits & mask,
            mask,
        }
    }

    pub fn contains(&self, addr: Ipv6Addr) -> bool {
        (u128::from(addr) & self.mask) == self.addr
    }
}

// ---- rules: None field = wildcard ----------------------------------------
//
// Each rule type impls RuleBody<Shape> for its shape.  The Linear<Shape, R>
// generic below dispatches via that trait.

pub struct V4TcpRule {
    pub src: Option<V4Prefix>,
    pub dport: Option<u16>,
    pub action: Action,
}

impl<'x> RuleBody<(&'x Eth, &'x Ipv4, &'x Tcp)> for V4TcpRule {
    fn matches<'a>(&self, (_eth, ip, tcp): (&'a Eth, &'a Ipv4, &'a Tcp)) -> bool {
        if let Some(p) = self.src
            && !p.contains(ip.source().into())
        {
            return false;
        }
        if let Some(dp) = self.dport
            && tcp.destination().as_u16() != dp
        {
            return false;
        }
        true
    }

    fn action(&self) -> Action {
        self.action
    }
}

pub struct V4UdpRule {
    pub src: Option<V4Prefix>,
    pub dport: Option<u16>,
    pub action: Action,
}

impl<'x> RuleBody<(&'x Eth, &'x Ipv4, &'x Udp)> for V4UdpRule {
    fn matches<'a>(&self, (_eth, ip, udp): (&'a Eth, &'a Ipv4, &'a Udp)) -> bool {
        if let Some(p) = self.src
            && !p.contains(ip.source().into())
        {
            return false;
        }
        if let Some(dp) = self.dport
            && udp.destination().as_u16() != dp
        {
            return false;
        }
        true
    }

    fn action(&self) -> Action {
        self.action
    }
}

pub struct V6TcpRule {
    pub src: Option<V6Prefix>,
    pub dport: Option<u16>,
    pub action: Action,
}

impl<'x> RuleBody<(&'x Eth, &'x Ipv6, &'x Tcp)> for V6TcpRule {
    fn matches<'a>(&self, (_eth, ip, tcp): (&'a Eth, &'a Ipv6, &'a Tcp)) -> bool {
        if let Some(p) = self.src
            && !p.contains(ip.source().into())
        {
            return false;
        }
        if let Some(dp) = self.dport
            && tcp.destination().as_u16() != dp
        {
            return false;
        }
        true
    }

    fn action(&self) -> Action {
        self.action
    }
}

pub struct V6UdpRule {
    pub src: Option<V6Prefix>,
    pub dport: Option<u16>,
    pub action: Action,
}

impl<'x> RuleBody<(&'x Eth, &'x Ipv6, &'x Udp)> for V6UdpRule {
    fn matches<'a>(&self, (_eth, ip, udp): (&'a Eth, &'a Ipv6, &'a Udp)) -> bool {
        if let Some(p) = self.src
            && !p.contains(ip.source().into())
        {
            return false;
        }
        if let Some(dp) = self.dport
            && udp.destination().as_u16() != dp
        {
            return false;
        }
        true
    }

    fn action(&self) -> Action {
        self.action
    }
}

// ===========================================================================
// Type aliases for common shapes (convenience; Linear itself is generic)
// ===========================================================================
//
// The 'static lifetime on the Shape tuple is a phantom-only choice --
// Linear<Shape, R> uses PhantomData<fn() -> Shape>, so no references
// are actually stored.  The alias is just a readability win at the
// Pipeline struct declaration and other storage sites.

pub type LinearV4Tcp = Linear<(&'static Eth, &'static Ipv4, &'static Tcp), V4TcpRule>;
pub type LinearV4Udp = Linear<(&'static Eth, &'static Ipv4, &'static Udp), V4UdpRule>;
pub type LinearV6Tcp = Linear<(&'static Eth, &'static Ipv6, &'static Tcp), V6TcpRule>;
pub type LinearV6Udp = Linear<(&'static Eth, &'static Ipv6, &'static Udp), V6UdpRule>;

// ===========================================================================
// Pipeline: shape dispatch across the four sub-classifiers
// ===========================================================================

pub struct Pipeline {
    pub v4_tcp: LinearV4Tcp,
    pub v4_udp: LinearV4Udp,
    pub v6_tcp: LinearV6Tcp,
    pub v6_udp: LinearV6Udp,
    /// Fate for packets whose shape isn't covered by any sub-classifier.
    pub unknown_shape_action: Action,
}

impl Pipeline {
    /// Classify a single packet by dispatching on shape.  Non-consuming:
    /// `Headers` stays where it lives (owned by caller), each sub-table
    /// takes a borrowed shape-typed view.
    pub fn classify(&self, headers: &Headers) -> Outcome {
        if let Some(w) = headers.as_window::<(&Eth, &Ipv4, &Tcp)>() {
            return self.v4_tcp.select(w);
        }
        if let Some(w) = headers.as_window::<(&Eth, &Ipv4, &Udp)>() {
            return self.v4_udp.select(w);
        }
        if let Some(w) = headers.as_window::<(&Eth, &Ipv6, &Tcp)>() {
            return self.v6_tcp.select(w);
        }
        if let Some(w) = headers.as_window::<(&Eth, &Ipv6, &Udp)>() {
            return self.v6_udp.select(w);
        }
        Outcome {
            rule: MatchId {
                table: TableId(u32::MAX),
                local: MatchId::DEFAULT_LOCAL,
            },
            action: self.unknown_shape_action,
        }
    }

    /// Batch classification: iterate over packets in wire order.
    pub fn classify_batch<'a, I>(&self, batch: I) -> Vec<Outcome>
    where
        I: IntoIterator<Item = &'a Headers>,
    {
        batch.into_iter().map(|h| self.classify(h)).collect()
    }
}

// ===========================================================================
// Smoke test
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    use net::headers::builder::HeaderStack;
    use net::ipv4::UnicastIpv4Addr;
    use net::tcp::TcpPort;
    use net::udp::UdpPort;

    fn make_v4_tcp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Headers {
        HeaderStack::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.set_source(UnicastIpv4Addr::new(src).unwrap());
                ip.set_destination(dst);
            })
            .tcp(|tcp| {
                tcp.set_source(TcpPort::new_checked(sport).unwrap());
                tcp.set_destination(TcpPort::new_checked(dport).unwrap());
            })
            .build_headers()
            .unwrap()
    }

    fn make_v4_udp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Headers {
        HeaderStack::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.set_source(UnicastIpv4Addr::new(src).unwrap());
                ip.set_destination(dst);
            })
            .udp(|udp| {
                udp.set_source(UdpPort::new_checked(sport).unwrap());
                udp.set_destination(UdpPort::new_checked(dport).unwrap());
            })
            .build_headers()
            .unwrap()
    }

    fn build_pipeline() -> Pipeline {
        let mut v4_tcp = LinearV4Tcp::new(TableId(1), Action::Drop);
        // Rule 0: accept TCP traffic from 10.0.0.0/8 to port 80.
        v4_tcp.push(V4TcpRule {
            src: Some(V4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8)),
            dport: Some(80),
            action: Action::Accept,
        });
        // Rule 1: drop everything else from 10.0.0.0/8 (regardless of port).
        v4_tcp.push(V4TcpRule {
            src: Some(V4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8)),
            dport: None,
            action: Action::Drop,
        });

        let mut v4_udp = LinearV4Udp::new(TableId(2), Action::Accept);
        // Rule 0: drop UDP to port 53.
        v4_udp.push(V4UdpRule {
            src: None,
            dport: Some(53),
            action: Action::Drop,
        });

        Pipeline {
            v4_tcp,
            v4_udp,
            v6_tcp: LinearV6Tcp::new(TableId(3), Action::Drop),
            v6_udp: LinearV6Udp::new(TableId(4), Action::Drop),
            unknown_shape_action: Action::Drop,
        }
    }

    #[test]
    fn v4_tcp_hits_rule_0() {
        let p = build_pipeline();
        let h = make_v4_tcp(Ipv4Addr::new(10, 1, 2, 3), Ipv4Addr::new(8, 8, 8, 8), 1111, 80);
        let out = p.classify(&h);
        assert_eq!(out.rule, MatchId { table: TableId(1), local: 0 });
        assert_eq!(out.action, Action::Accept);
    }

    #[test]
    fn v4_tcp_hits_rule_1_wrong_port() {
        let p = build_pipeline();
        let h = make_v4_tcp(Ipv4Addr::new(10, 1, 2, 3), Ipv4Addr::new(8, 8, 8, 8), 1111, 443);
        let out = p.classify(&h);
        assert_eq!(out.rule, MatchId { table: TableId(1), local: 1 });
        assert_eq!(out.action, Action::Drop);
    }

    #[test]
    fn v4_tcp_no_match_uses_default() {
        let p = build_pipeline();
        let h = make_v4_tcp(Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(10, 0, 0, 1), 1111, 443);
        let out = p.classify(&h);
        assert_eq!(out.rule, MatchId::default_for(TableId(1)));
        assert_eq!(out.action, Action::Drop);
    }

    #[test]
    fn v4_udp_dispatches_to_udp_table() {
        let p = build_pipeline();
        let h = make_v4_udp(Ipv4Addr::new(10, 1, 2, 3), Ipv4Addr::new(8, 8, 8, 8), 1111, 53);
        let out = p.classify(&h);
        assert_eq!(out.rule, MatchId { table: TableId(2), local: 0 });
        assert_eq!(out.action, Action::Drop);
    }

    // ShapePrefix / AsRef downgrade: a wide Window can be viewed as a
    // narrow Window without runtime cost.  Verifies the type-level
    // lattice is wired correctly and the AsRef blanket impl fires.
    #[test]
    fn wide_window_downgrades_via_as_ref() {
        let h = make_v4_tcp(Ipv4Addr::new(10, 1, 2, 3), Ipv4Addr::new(8, 8, 8, 8), 1111, 80);

        let wide: &Window<(&Eth, &Ipv4, &Tcp)> = h.as_window().expect("shape matches");

        // Narrow via AsRef: (&Eth, &Ipv4, &Tcp) -> (&Eth, &Ipv4)
        let narrow_v4: &Window<(&Eth, &Ipv4)> = wide.as_ref();
        let (eth, ip) = narrow_v4.look();
        let src: Ipv4Addr = ip.source().into();
        assert_eq!(src, Ipv4Addr::new(10, 1, 2, 3));
        let _ = eth; // quiet unused

        // Narrow all the way: (&Eth, &Ipv4, &Tcp) -> (&Eth,)
        let eth_only: &Window<(&Eth,)> = wide.as_ref();
        let (_eth,) = eth_only.look();
    }
}
