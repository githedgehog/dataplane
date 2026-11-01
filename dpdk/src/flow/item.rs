// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Owned pattern items, shared by synchronous rules and templates.

use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr::{from_ref, null};

use dpdk_sys::{
    rte_flow_item, rte_flow_item_eth, rte_flow_item_ipv4, rte_flow_item_ipv6,
    rte_flow_item_meter_color, rte_flow_item_tcp, rte_flow_item_type as it, rte_flow_item_udp,
    rte_flow_item_vlan, rte_flow_item_vxlan,
};

/// Owned match criteria, kept in place while the PMD reads their pointers.
pub(crate) enum MatchItem {
    Eth(rte_flow_item_eth, rte_flow_item_eth),
    Vlan(rte_flow_item_vlan, rte_flow_item_vlan),
    Ipv4(rte_flow_item_ipv4, rte_flow_item_ipv4),
    Ipv6(rte_flow_item_ipv6, rte_flow_item_ipv6),
    Udp(rte_flow_item_udp, rte_flow_item_udp),
    Tcp(rte_flow_item_tcp, rte_flow_item_tcp),
    Vxlan(rte_flow_item_vxlan, rte_flow_item_vxlan),
    MeterColor(rte_flow_item_meter_color, rte_flow_item_meter_color),
}

impl MatchItem {
    pub(crate) fn type_(&self) -> it::Type {
        match self {
            MatchItem::Eth(..) => it::RTE_FLOW_ITEM_TYPE_ETH,
            MatchItem::Vlan(..) => it::RTE_FLOW_ITEM_TYPE_VLAN,
            MatchItem::Ipv4(..) => it::RTE_FLOW_ITEM_TYPE_IPV4,
            MatchItem::Ipv6(..) => it::RTE_FLOW_ITEM_TYPE_IPV6,
            MatchItem::Udp(..) => it::RTE_FLOW_ITEM_TYPE_UDP,
            MatchItem::Tcp(..) => it::RTE_FLOW_ITEM_TYPE_TCP,
            MatchItem::Vxlan(..) => it::RTE_FLOW_ITEM_TYPE_VXLAN,
            MatchItem::MeterColor(..) => it::RTE_FLOW_ITEM_TYPE_METER_COLOR,
        }
    }

    /// Pointer to the spec struct. Valid while `self` is alive.
    pub(crate) fn spec(&self) -> *const c_void {
        match self {
            MatchItem::Eth(spec, _) => from_ref(spec).cast(),
            MatchItem::Vlan(spec, _) => from_ref(spec).cast(),
            MatchItem::Ipv4(spec, _) => from_ref(spec).cast(),
            MatchItem::Ipv6(spec, _) => from_ref(spec).cast(),
            MatchItem::Udp(spec, _) => from_ref(spec).cast(),
            MatchItem::Tcp(spec, _) => from_ref(spec).cast(),
            MatchItem::Vxlan(spec, _) => from_ref(spec).cast(),
            MatchItem::MeterColor(spec, _) => from_ref(spec).cast(),
        }
    }

    /// Pointer to the mask struct. Valid while `self` is alive.
    pub(crate) fn mask(&self) -> *const c_void {
        match self {
            MatchItem::Eth(_, mask) => from_ref(mask).cast(),
            MatchItem::Vlan(_, mask) => from_ref(mask).cast(),
            MatchItem::Ipv4(_, mask) => from_ref(mask).cast(),
            MatchItem::Ipv6(_, mask) => from_ref(mask).cast(),
            MatchItem::Udp(_, mask) => from_ref(mask).cast(),
            MatchItem::Tcp(_, mask) => from_ref(mask).cast(),
            MatchItem::Vxlan(_, mask) => from_ref(mask).cast(),
            MatchItem::MeterColor(_, mask) => from_ref(mask).cast(),
        }
    }
}

/// The END-terminated item array for `items`, pointing into them: keep `items` alive and unmoved
/// while the PMD reads the result.
pub(crate) fn lower(items: &[MatchItem]) -> Vec<rte_flow_item> {
    let mut lowered: Vec<rte_flow_item> = Vec::with_capacity(items.len() + 1);
    for item in items {
        lowered.push(rte_flow_item {
            type_: item.type_(),
            spec: item.spec(),
            last: null(),
            mask: item.mask(),
        });
    }
    lowered.push(rte_flow_item {
        type_: it::RTE_FLOW_ITEM_TYPE_END,
        spec: null(),
        last: null(),
        mask: null(),
    });
    lowered
}
