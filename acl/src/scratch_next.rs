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
// The Select trait
// ===========================================================================

pub trait Select<Shape> {
    fn select(&self, key: &Window<Shape>) -> Outcome;
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

pub struct V4TcpRule {
    pub src: Option<V4Prefix>,
    pub dport: Option<u16>,
    pub action: Action,
}

impl V4TcpRule {
    fn matches(&self, _eth: &Eth, ip: &Ipv4, tcp: &Tcp) -> bool {
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
}

pub struct V4UdpRule {
    pub src: Option<V4Prefix>,
    pub dport: Option<u16>,
    pub action: Action,
}

impl V4UdpRule {
    fn matches(&self, _eth: &Eth, ip: &Ipv4, udp: &Udp) -> bool {
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
}

pub struct V6TcpRule {
    pub src: Option<V6Prefix>,
    pub dport: Option<u16>,
    pub action: Action,
}

impl V6TcpRule {
    fn matches(&self, _eth: &Eth, ip: &Ipv6, tcp: &Tcp) -> bool {
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
}

pub struct V6UdpRule {
    pub src: Option<V6Prefix>,
    pub dport: Option<u16>,
    pub action: Action,
}

impl V6UdpRule {
    fn matches(&self, _eth: &Eth, ip: &Ipv6, udp: &Udp) -> bool {
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
}

// ===========================================================================
// Linear classifiers: one per shape
// ===========================================================================

pub struct LinearV4Tcp {
    id: TableId,
    rules: Vec<V4TcpRule>,
    default_action: Action,
}

impl LinearV4Tcp {
    pub fn new(id: TableId, default_action: Action) -> Self {
        Self {
            id,
            rules: Vec::new(),
            default_action,
        }
    }

    pub fn push(&mut self, rule: V4TcpRule) {
        self.rules.push(rule);
    }
}

impl<'x> Select<(&'x Eth, &'x Ipv4, &'x Tcp)> for LinearV4Tcp
where
    Self: 'x,
{
    fn select(&self, key: &Window<(&'x Eth, &'x Ipv4, &'x Tcp)>) -> Outcome {
        let (eth, ip, tcp) = key.look();
        for (idx, rule) in self.rules.iter().enumerate() {
            if rule.matches(eth, ip, tcp) {
                return Outcome {
                    rule: MatchId {
                        table: self.id,
                        local: idx as u32,
                    },
                    action: rule.action,
                };
            }
        }
        Outcome {
            rule: MatchId::default_for(self.id),
            action: self.default_action,
        }
    }
}

pub struct LinearV4Udp {
    id: TableId,
    rules: Vec<V4UdpRule>,
    default_action: Action,
}

impl LinearV4Udp {
    pub fn new(id: TableId, default_action: Action) -> Self {
        Self {
            id,
            rules: Vec::new(),
            default_action,
        }
    }

    pub fn push(&mut self, rule: V4UdpRule) {
        self.rules.push(rule);
    }
}

impl<'x> Select<(&'x Eth, &'x Ipv4, &'x Udp)> for LinearV4Udp
where
    Self: 'x,
{
    fn select(&self, key: &Window<(&'x Eth, &'x Ipv4, &'x Udp)>) -> Outcome {
        let (eth, ip, udp) = key.look();
        for (idx, rule) in self.rules.iter().enumerate() {
            if rule.matches(eth, ip, udp) {
                return Outcome {
                    rule: MatchId {
                        table: self.id,
                        local: idx as u32,
                    },
                    action: rule.action,
                };
            }
        }
        Outcome {
            rule: MatchId::default_for(self.id),
            action: self.default_action,
        }
    }
}

pub struct LinearV6Tcp {
    id: TableId,
    rules: Vec<V6TcpRule>,
    default_action: Action,
}

impl LinearV6Tcp {
    pub fn new(id: TableId, default_action: Action) -> Self {
        Self {
            id,
            rules: Vec::new(),
            default_action,
        }
    }

    pub fn push(&mut self, rule: V6TcpRule) {
        self.rules.push(rule);
    }
}

impl<'x> Select<(&'x Eth, &'x Ipv6, &'x Tcp)> for LinearV6Tcp
where
    Self: 'x,
{
    fn select(&self, key: &Window<(&'x Eth, &'x Ipv6, &'x Tcp)>) -> Outcome {
        let (eth, ip, tcp) = key.look();
        for (idx, rule) in self.rules.iter().enumerate() {
            if rule.matches(eth, ip, tcp) {
                return Outcome {
                    rule: MatchId {
                        table: self.id,
                        local: idx as u32,
                    },
                    action: rule.action,
                };
            }
        }
        Outcome {
            rule: MatchId::default_for(self.id),
            action: self.default_action,
        }
    }
}

pub struct LinearV6Udp {
    id: TableId,
    rules: Vec<V6UdpRule>,
    default_action: Action,
}

impl LinearV6Udp {
    pub fn new(id: TableId, default_action: Action) -> Self {
        Self {
            id,
            rules: Vec::new(),
            default_action,
        }
    }

    pub fn push(&mut self, rule: V6UdpRule) {
        self.rules.push(rule);
    }
}

impl<'x> Select<(&'x Eth, &'x Ipv6, &'x Udp)> for LinearV6Udp
where
    Self: 'x,
{
    fn select(&self, key: &Window<(&'x Eth, &'x Ipv6, &'x Udp)>) -> Outcome {
        let (eth, ip, udp) = key.look();
        for (idx, rule) in self.rules.iter().enumerate() {
            if rule.matches(eth, ip, udp) {
                return Outcome {
                    rule: MatchId {
                        table: self.id,
                        local: idx as u32,
                    },
                    action: rule.action,
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
    /// Classify a single `Headers` by shape, dispatching to the right
    /// sub-classifier.  Cascades through Window::new attempts -- ugly
    /// but honest; an `as_window` non-consuming view on Headers would
    /// be the obvious follow-up.
    pub fn classify(&self, headers: Headers) -> Outcome {
        let headers = match Window::<(&Eth, &Ipv4, &Tcp)>::new(headers) {
            Ok(w) => return self.v4_tcp.select(&w),
            Err(h) => h,
        };
        let headers = match Window::<(&Eth, &Ipv4, &Udp)>::new(headers) {
            Ok(w) => return self.v4_udp.select(&w),
            Err(h) => h,
        };
        let headers = match Window::<(&Eth, &Ipv6, &Tcp)>::new(headers) {
            Ok(w) => return self.v6_tcp.select(&w),
            Err(h) => h,
        };
        let _headers = match Window::<(&Eth, &Ipv6, &Udp)>::new(headers) {
            Ok(w) => return self.v6_udp.select(&w),
            Err(h) => h,
        };
        Outcome {
            rule: MatchId {
                table: TableId(u32::MAX),
                local: MatchId::DEFAULT_LOCAL,
            },
            action: self.unknown_shape_action,
        }
    }

    /// Batch classification: accept a batch of headers, return outcomes
    /// in wire order.
    pub fn classify_batch(&self, batch: Vec<Headers>) -> Vec<Outcome> {
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
        let out = p.classify(h);
        assert_eq!(out.rule, MatchId { table: TableId(1), local: 0 });
        assert_eq!(out.action, Action::Accept);
    }

    #[test]
    fn v4_tcp_hits_rule_1_wrong_port() {
        let p = build_pipeline();
        let h = make_v4_tcp(Ipv4Addr::new(10, 1, 2, 3), Ipv4Addr::new(8, 8, 8, 8), 1111, 443);
        let out = p.classify(h);
        assert_eq!(out.rule, MatchId { table: TableId(1), local: 1 });
        assert_eq!(out.action, Action::Drop);
    }

    #[test]
    fn v4_tcp_no_match_uses_default() {
        let p = build_pipeline();
        let h = make_v4_tcp(Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(10, 0, 0, 1), 1111, 443);
        let out = p.classify(h);
        assert_eq!(out.rule, MatchId::default_for(TableId(1)));
        assert_eq!(out.action, Action::Drop);
    }

    #[test]
    fn v4_udp_dispatches_to_udp_table() {
        let p = build_pipeline();
        let h = make_v4_udp(Ipv4Addr::new(10, 1, 2, 3), Ipv4Addr::new(8, 8, 8, 8), 1111, 53);
        let out = p.classify(h);
        assert_eq!(out.rule, MatchId { table: TableId(2), local: 0 });
        assert_eq!(out.action, Action::Drop);
    }
}
