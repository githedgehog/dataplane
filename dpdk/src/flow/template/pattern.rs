// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Patterns for templates and their rules.

use alloc::vec::Vec;
use core::marker::PhantomData;

use dpdk_sys::{rte_color, rte_flow_item_meter_color};
use net::eth::Eth;
use net::headers::Within;
use net::ipv4::Ipv4;
use net::ipv6::Ipv6;
use net::tcp::Tcp;
use net::udp::Udp;
use net::vlan::Vlan;
use net::vxlan::Vxlan;

use crate::flow::item::MatchItem;
use crate::flow::pattern::{
    EthMatch, Ipv4Match, Ipv6Match, ItemShape, TcpMatch, UdpMatch, VlanMatch, VxlanMatch,
};

/// The Ethernet header inside a VXLAN tunnel, as a pattern position.
///
/// Matching inner headers does not decapsulate: the packet keeps its outer headers.
#[derive(Debug)]
pub struct InnerEth;

impl Within<InnerEth> for Vlan {
    fn conform(_: &mut InnerEth) {}
}

impl Within<InnerEth> for Ipv4 {
    fn conform(_: &mut InnerEth) {}
}

impl Within<InnerEth> for Ipv6 {
    fn conform(_: &mut InnerEth) {}
}

/// The position after a [`Pattern::meter_color`] item, which nothing follows.
#[derive(Debug)]
pub struct Colored;

/// The position of a [`Pattern::complete`]d pattern, which nothing follows.
///
/// Templates and rules accept patterns at any position, so completing one only lets patterns that
/// end in different headers share a type.
#[derive(Debug)]
pub struct Complete;

/// The color a meter gave a packet earlier in the pipeline.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Color {
    /// Within the committed rate.
    Green,
    /// Over the committed rate, within the excess rate or burst.
    Yellow,
    /// Over every rate.
    Red,
}

impl Color {
    /// Every color, in order.
    pub const ALL: [Color; 3] = [Color::Green, Color::Yellow, Color::Red];

    fn raw(self) -> rte_color::Type {
        match self {
            Color::Green => rte_color::RTE_COLOR_GREEN,
            Color::Yellow => rte_color::RTE_COLOR_YELLOW,
            Color::Red => rte_color::RTE_COLOR_RED,
        }
    }
}

/// A match pattern for a [`PatternTemplate`](super::PatternTemplate) or one of its rules.
///
/// `Pos` is the last header matched; [`Within`] decides what may follow, as for
/// [`FlowBuilder`](crate::flow::FlowBuilder).
/// In a template the masks are what count; in a rule, the values.
/// A rule's masks must equal its template's (see [`ItemShape`]).
pub struct Pattern<Pos> {
    pub(crate) items: Vec<MatchItem>,
    pub(crate) shapes: Vec<ItemShape>,
    position: PhantomData<Pos>,
}

impl<Pos> core::fmt::Debug for Pattern<Pos> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pattern")
            .field("shapes", &self.shapes)
            .finish_non_exhaustive()
    }
}

impl Default for Pattern<()> {
    fn default() -> Self {
        Pattern::new()
    }
}

impl Pattern<()> {
    /// An empty pattern, which matches every packet.
    #[must_use]
    pub fn new() -> Pattern<()> {
        Pattern {
            items: Vec::new(),
            shapes: Vec::new(),
            position: PhantomData,
        }
    }

    /// Match the color an earlier meter gave the packet.
    #[must_use]
    pub fn meter_color(color: Color) -> Pattern<Colored> {
        // SAFETY: zero is valid for this C struct.
        let mut spec: rte_flow_item_meter_color = unsafe { core::mem::zeroed() };
        let mut mask: rte_flow_item_meter_color = unsafe { core::mem::zeroed() };
        spec.color = color.raw();
        // Every color bit: a partial mask makes rules for different colors overlap.
        mask.color = 0x3;
        Pattern::new().push(MatchItem::MeterColor(spec, mask), ItemShape::MeterColor)
    }
}

impl<Pos> Pattern<Pos> {
    fn push<Next>(mut self, item: MatchItem, shape: ItemShape) -> Pattern<Next> {
        self.items.push(item);
        self.shapes.push(shape);
        Pattern {
            items: self.items,
            shapes: self.shapes,
            position: PhantomData,
        }
    }

    /// End the pattern, forgetting its position.
    #[must_use]
    pub fn complete(self) -> Pattern<Complete> {
        Pattern {
            items: self.items,
            shapes: self.shapes,
            position: PhantomData,
        }
    }

    /// Match an Ethernet header; only at the start of a pattern.
    #[must_use]
    pub fn eth(self, criteria: EthMatch) -> Pattern<Eth>
    where
        Eth: Within<Pos>,
    {
        let (spec, mask) = criteria.lower();
        self.push(MatchItem::Eth(spec, mask), criteria.shape())
    }

    /// Match a VLAN tag.
    #[must_use]
    pub fn vlan(self, criteria: VlanMatch) -> Pattern<Vlan>
    where
        Vlan: Within<Pos>,
    {
        let (spec, mask) = criteria.lower();
        self.push(MatchItem::Vlan(spec, mask), criteria.shape())
    }

    /// Match an IPv4 header.
    #[must_use]
    pub fn ipv4(self, criteria: Ipv4Match) -> Pattern<Ipv4>
    where
        Ipv4: Within<Pos>,
    {
        let (spec, mask) = criteria.lower();
        self.push(MatchItem::Ipv4(spec, mask), criteria.shape())
    }

    /// Match an IPv6 header.
    #[must_use]
    pub fn ipv6(self, criteria: Ipv6Match) -> Pattern<Ipv6>
    where
        Ipv6: Within<Pos>,
    {
        let (spec, mask) = criteria.lower();
        self.push(MatchItem::Ipv6(spec, mask), criteria.shape())
    }

    /// Match a UDP header.
    #[must_use]
    pub fn udp(self, criteria: UdpMatch) -> Pattern<Udp>
    where
        Udp: Within<Pos>,
    {
        let (spec, mask) = criteria.lower();
        self.push(MatchItem::Udp(spec, mask), criteria.shape())
    }

    /// Match a TCP header.
    #[must_use]
    pub fn tcp(self, criteria: TcpMatch) -> Pattern<Tcp>
    where
        Tcp: Within<Pos>,
    {
        let (spec, mask) = criteria.lower();
        self.push(MatchItem::Tcp(spec, mask), criteria.shape())
    }

    /// Match a VXLAN header.
    #[must_use]
    pub fn vxlan(self, criteria: VxlanMatch) -> Pattern<Vxlan>
    where
        Vxlan: Within<Pos>,
    {
        let (spec, mask) = criteria.lower();
        self.push(MatchItem::Vxlan(spec, mask), criteria.shape())
    }
}

impl Pattern<Vxlan> {
    /// Continue into the tunnel: match the inner Ethernet header.
    #[must_use]
    pub fn inner_eth(self, criteria: EthMatch) -> Pattern<InnerEth> {
        let (spec, mask) = criteria.lower();
        self.push(MatchItem::Eth(spec, mask), criteria.shape())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::pattern::Ipv4Prefix;
    use core::net::Ipv4Addr;
    use dpdk_sys::rte_flow_item_type as it;

    fn vni_and_inner_dst(addr: Ipv4Addr, len: u8) -> Pattern<Ipv4> {
        Pattern::new()
            .eth(EthMatch::default())
            .ipv4(Ipv4Match::default())
            .udp(UdpMatch::default().dst(4789))
            .vxlan(VxlanMatch::default())
            .inner_eth(EthMatch::default())
            .ipv4(Ipv4Match::default().dst(Ipv4Prefix::prefix(addr, len)))
    }

    #[test]
    fn inner_headers_follow_the_tunnel_in_order() {
        let pattern = vni_and_inner_dst(Ipv4Addr::new(10, 0, 0, 0), 24);
        let types: Vec<_> = pattern.items.iter().map(MatchItem::type_).collect();
        assert_eq!(
            types,
            [
                it::RTE_FLOW_ITEM_TYPE_ETH,
                it::RTE_FLOW_ITEM_TYPE_IPV4,
                it::RTE_FLOW_ITEM_TYPE_UDP,
                it::RTE_FLOW_ITEM_TYPE_VXLAN,
                it::RTE_FLOW_ITEM_TYPE_ETH,
                it::RTE_FLOW_ITEM_TYPE_IPV4,
            ]
        );
    }

    /// Shapes compare masks, not values: one template serves every prefix of its length.
    #[test]
    fn shapes_ignore_values_but_not_prefix_lengths() {
        bolero::check!()
            .with_type::<(u32, u32, u8, u8)>()
            .for_each(|&(a, b, len_a, len_b)| {
                let (len_a, len_b) = (len_a % 33, len_b % 33);
                let x = vni_and_inner_dst(Ipv4Addr::from(a), len_a);
                let y = vni_and_inner_dst(Ipv4Addr::from(b), len_b);
                assert_eq!(x.shapes == y.shapes, len_a == len_b);
            });
    }

    #[test]
    fn every_color_has_its_own_value_under_a_full_mask() {
        let lowered: Vec<_> = Color::ALL
            .iter()
            .map(|&c| match Pattern::meter_color(c).items.as_slice() {
                [MatchItem::MeterColor(spec, mask)] => (spec.color, mask.color),
                _ => unreachable!("one meter color item"),
            })
            .collect();
        assert_eq!(
            lowered,
            [
                (rte_color::RTE_COLOR_GREEN, 3),
                (rte_color::RTE_COLOR_YELLOW, 3),
                (rte_color::RTE_COLOR_RED, 3),
            ]
        );
    }
}
