// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Flow construction and FFI conversion.
//! The builder owns all spec, mask, and action data until the PMD copies it.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::marker::PhantomData;
use core::net::{Ipv4Addr, Ipv6Addr};
use core::ptr::{NonNull, from_ref, null};

use dpdk_sys::{
    rte_flow_action, rte_flow_action_jump, rte_flow_action_mark, rte_flow_action_modify_field,
    rte_flow_action_of_push_vlan, rte_flow_action_of_set_vlan_pcp, rte_flow_action_of_set_vlan_vid,
    rte_flow_action_queue, rte_flow_action_set_ipv4, rte_flow_action_set_tp,
    rte_flow_action_type as at, rte_flow_action_vxlan_encap, rte_flow_attr, rte_flow_create,
    rte_flow_error, rte_flow_field_id, rte_flow_item, rte_flow_item_eth, rte_flow_item_ipv4,
    rte_flow_item_ipv6, rte_flow_item_tcp, rte_flow_item_type as it, rte_flow_item_udp,
    rte_flow_item_vlan, rte_flow_item_vxlan, rte_flow_modify_op, rte_flow_validate,
};

use net::eth::Eth;
use net::eth::ethtype::EthType;
use net::eth::mac::Mac;
use net::headers::Within;
use net::ipv4::Ipv4;
use net::ipv6::Ipv6;
use net::tcp::Tcp;
use net::udp::Udp;
use net::vlan::{Pcp, Vid, Vlan};
use net::vxlan::{Vni, Vxlan};

use crate::dev::{Dev, DevIndex, Started};
use crate::flow::error::FlowError;
use crate::flow::pattern::{Ipv4Match, Ipv6Match, TcpMatch, UdpMatch, VlanMatch, VxlanMatch};
use crate::flow::rule::FlowRule;
use crate::flow::{Direction, Domain, FlowGroup, Mark, Priority};
use crate::queue::rx::RxQueueIndex;
use concurrency::sync::atomic::AtomicUsize;

/// Owned match criteria, kept in place while the PMD reads their pointers.
enum MatchItem {
    Eth,
    Vlan(rte_flow_item_vlan, rte_flow_item_vlan),
    Ipv4(rte_flow_item_ipv4, rte_flow_item_ipv4),
    Ipv6(rte_flow_item_ipv6, rte_flow_item_ipv6),
    Udp(rte_flow_item_udp, rte_flow_item_udp),
    Tcp(rte_flow_item_tcp, rte_flow_item_tcp),
    Vxlan(rte_flow_item_vxlan, rte_flow_item_vxlan),
}

impl MatchItem {
    fn type_(&self) -> it::Type {
        match self {
            MatchItem::Eth => it::RTE_FLOW_ITEM_TYPE_ETH,
            MatchItem::Vlan(..) => it::RTE_FLOW_ITEM_TYPE_VLAN,
            MatchItem::Ipv4(..) => it::RTE_FLOW_ITEM_TYPE_IPV4,
            MatchItem::Ipv6(..) => it::RTE_FLOW_ITEM_TYPE_IPV6,
            MatchItem::Udp(..) => it::RTE_FLOW_ITEM_TYPE_UDP,
            MatchItem::Tcp(..) => it::RTE_FLOW_ITEM_TYPE_TCP,
            MatchItem::Vxlan(..) => it::RTE_FLOW_ITEM_TYPE_VXLAN,
        }
    }

    /// Pointer to the spec struct (null for a presence-only item). Valid while `self` is alive.
    fn spec(&self) -> *const c_void {
        match self {
            MatchItem::Eth => null(),
            MatchItem::Vlan(spec, _) => from_ref(spec).cast(),
            MatchItem::Ipv4(spec, _) => from_ref(spec).cast(),
            MatchItem::Ipv6(spec, _) => from_ref(spec).cast(),
            MatchItem::Udp(spec, _) => from_ref(spec).cast(),
            MatchItem::Tcp(spec, _) => from_ref(spec).cast(),
            MatchItem::Vxlan(spec, _) => from_ref(spec).cast(),
        }
    }

    /// Pointer to the mask struct (null for a presence-only item). Valid while `self` is alive.
    fn mask(&self) -> *const c_void {
        match self {
            MatchItem::Eth => null(),
            MatchItem::Vlan(_, mask) => from_ref(mask).cast(),
            MatchItem::Ipv4(_, mask) => from_ref(mask).cast(),
            MatchItem::Ipv6(_, mask) => from_ref(mask).cast(),
            MatchItem::Udp(_, mask) => from_ref(mask).cast(),
            MatchItem::Tcp(_, mask) => from_ref(mask).cast(),
            MatchItem::Vxlan(_, mask) => from_ref(mask).cast(),
        }
    }
}

/// An action plus the owned configuration struct the PMD reads through a pointer.
enum Action {
    Jump(rte_flow_action_jump),
    Mark(rte_flow_action_mark),
    Queue(rte_flow_action_queue),
    Drop,
    SetIpv4Src(rte_flow_action_set_ipv4),
    SetIpv4Dst(rte_flow_action_set_ipv4),
    SetTpSrc(rte_flow_action_set_tp),
    SetTpDst(rte_flow_action_set_tp),
    OfPushVlan(rte_flow_action_of_push_vlan),
    OfPopVlan,
    OfSetVlanVid(rte_flow_action_of_set_vlan_vid),
    OfSetVlanPcp(rte_flow_action_of_set_vlan_pcp),
    ModifyField(rte_flow_action_modify_field),
    VxlanDecap,
    VxlanEncap(Box<EncapDef>),
}

impl Action {
    fn type_(&self) -> at::Type {
        match self {
            Action::Jump(_) => at::RTE_FLOW_ACTION_TYPE_JUMP,
            Action::Mark(_) => at::RTE_FLOW_ACTION_TYPE_MARK,
            Action::Queue(_) => at::RTE_FLOW_ACTION_TYPE_QUEUE,
            Action::Drop => at::RTE_FLOW_ACTION_TYPE_DROP,
            Action::SetIpv4Src(_) => at::RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC,
            Action::SetIpv4Dst(_) => at::RTE_FLOW_ACTION_TYPE_SET_IPV4_DST,
            Action::SetTpSrc(_) => at::RTE_FLOW_ACTION_TYPE_SET_TP_SRC,
            Action::SetTpDst(_) => at::RTE_FLOW_ACTION_TYPE_SET_TP_DST,
            Action::OfPushVlan(_) => at::RTE_FLOW_ACTION_TYPE_OF_PUSH_VLAN,
            Action::OfPopVlan => at::RTE_FLOW_ACTION_TYPE_OF_POP_VLAN,
            Action::OfSetVlanVid(_) => at::RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID,
            Action::OfSetVlanPcp(_) => at::RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_PCP,
            Action::ModifyField(_) => at::RTE_FLOW_ACTION_TYPE_MODIFY_FIELD,
            Action::VxlanDecap => at::RTE_FLOW_ACTION_TYPE_VXLAN_DECAP,
            Action::VxlanEncap(_) => at::RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP,
        }
    }

    /// mlx5 action order: remove headers, mark, rewrite, push headers, forward.
    /// Actions of equal rank retain their insertion order.
    fn rank(&self) -> u8 {
        match self {
            Action::OfPopVlan | Action::VxlanDecap => 0,
            Action::Mark(_) => 1,
            Action::SetIpv4Src(_)
            | Action::SetIpv4Dst(_)
            | Action::SetTpSrc(_)
            | Action::SetTpDst(_)
            | Action::OfSetVlanVid(_)
            | Action::OfSetVlanPcp(_)
            | Action::ModifyField(_) => 2,
            Action::OfPushVlan(_) | Action::VxlanEncap(_) => 3,
            Action::Jump(_) | Action::Queue(_) | Action::Drop => 4,
        }
    }

    fn view(&self) -> ActionView<'_> {
        let conf = match self {
            Action::Jump(j) => from_ref(j).cast(),
            Action::Mark(m) => from_ref(m).cast(),
            Action::Queue(q) => from_ref(q).cast(),
            Action::Drop => null(),
            Action::SetIpv4Src(a) | Action::SetIpv4Dst(a) => from_ref(a).cast(),
            Action::SetTpSrc(a) | Action::SetTpDst(a) => from_ref(a).cast(),
            Action::OfPushVlan(a) => from_ref(a).cast(),
            Action::OfPopVlan => null(),
            Action::OfSetVlanVid(a) => from_ref(a).cast(),
            Action::OfSetVlanPcp(a) => from_ref(a).cast(),
            Action::ModifyField(m) => from_ref(m).cast(),
            Action::VxlanDecap => null(),
            Action::VxlanEncap(headers) => {
                let item = |type_, spec| rte_flow_item {
                    type_,
                    spec,
                    last: null(),
                    mask: null(),
                };
                return ActionView::VxlanEncap {
                    _headers: headers,
                    items: [
                        item(it::RTE_FLOW_ITEM_TYPE_ETH, from_ref(&headers.eth).cast()),
                        item(it::RTE_FLOW_ITEM_TYPE_IPV4, from_ref(&headers.ipv4).cast()),
                        item(it::RTE_FLOW_ITEM_TYPE_UDP, from_ref(&headers.udp).cast()),
                        item(
                            it::RTE_FLOW_ITEM_TYPE_VXLAN,
                            from_ref(&headers.vxlan).cast(),
                        ),
                        item(it::RTE_FLOW_ITEM_TYPE_END, null()),
                    ],
                };
            }
        };
        ActionView::Direct { action: self, conf }
    }
}

/// Borrows action data; encapsulation item arrays contain no pointers into themselves.
enum ActionView<'a> {
    Direct {
        action: &'a Action,
        conf: *const c_void,
    },
    VxlanEncap {
        _headers: &'a EncapDef,
        items: [rte_flow_item; 5],
    },
}

impl ActionView<'_> {
    fn config(&self) -> ActionConfig<'_> {
        match self {
            Self::Direct { action, conf } => ActionConfig::Direct {
                action,
                conf: *conf,
            },
            Self::VxlanEncap { items, .. } => ActionConfig::VxlanEncap {
                _view: self,
                config: rte_flow_action_vxlan_encap {
                    definition: items.as_ptr().cast_mut(),
                },
            },
        }
    }
}

/// Keeps the borrowed data alive until the synchronous FFI call completes.
enum ActionConfig<'a> {
    Direct {
        action: &'a Action,
        conf: *const c_void,
    },
    VxlanEncap {
        _view: &'a ActionView<'a>,
        config: rte_flow_action_vxlan_encap,
    },
}

impl ActionConfig<'_> {
    fn as_ffi(&self) -> rte_flow_action {
        let (type_, conf) = match self {
            Self::Direct { action, conf } => (action.type_(), *conf),
            Self::VxlanEncap { config, .. } => (
                at::RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP,
                from_ref(config).cast(),
            ),
        };
        rte_flow_action { type_, conf }
    }
}

fn set_ipv4(addr: Ipv4Addr) -> rte_flow_action_set_ipv4 {
    rte_flow_action_set_ipv4 {
        ipv4_addr: u32::from(addr).to_be(),
    }
}

fn set_tp(port: u16) -> rte_flow_action_set_tp {
    rte_flow_action_set_tp { port: port.to_be() }
}

/// Set `dst` from bytes in the corresponding `rte_flow_item_*` field's order and size.
/// The immediate source inherits the destination's bit offset.
fn modify_set(
    dst: rte_flow_field_id::Type,
    width: u32,
    value: &[u8],
) -> rte_flow_action_modify_field {
    // SAFETY: zero is valid for every field in this C configuration struct.
    let mut mf: rte_flow_action_modify_field = unsafe { core::mem::zeroed() };
    mf.operation = rte_flow_modify_op::RTE_FLOW_MODIFY_SET;
    mf.dst.field = dst;
    mf.src.field = rte_flow_field_id::RTE_FLOW_FIELD_VALUE;
    let mut buf = [0u8; 16];
    buf[..value.len()].copy_from_slice(value);
    mf.src.annon1.value = buf;
    mf.width = width;
    mf
}

/// The outer headers prepended by a [`vxlan_encap`](FlowBuilder::vxlan_encap) action. Byte orders are
/// handled internally; the outer UDP destination is fixed at the VXLAN port (4789).
#[derive(Debug, Copy, Clone)]
pub struct VxlanEncap {
    /// Outer Ethernet source MAC.
    pub eth_src: Mac,
    /// Outer Ethernet destination MAC.
    pub eth_dst: Mac,
    /// Outer IPv4 source address.
    pub ip_src: Ipv4Addr,
    /// Outer IPv4 destination address.
    pub ip_dst: Ipv4Addr,
    /// Outer UDP source port (the entropy/hash port).
    pub udp_src: u16,
    /// The tunnel VNI to encapsulate with.
    pub vni: Vni,
}

/// Owned VXLAN headers. FFI pointers are formed only while borrowing these headers.
struct EncapDef {
    eth: rte_flow_item_eth,
    ipv4: rte_flow_item_ipv4,
    udp: rte_flow_item_udp,
    vxlan: rte_flow_item_vxlan,
}

fn build_encap(e: &VxlanEncap) -> Box<EncapDef> {
    // SAFETY: zero is valid for every field in these C header structs.
    let mut eth: rte_flow_item_eth = unsafe { core::mem::zeroed() };
    eth.annon1.hdr.dst_addr.addr_bytes = e.eth_dst.0;
    eth.annon1.hdr.src_addr.addr_bytes = e.eth_src.0;
    eth.annon1.hdr.ether_type = 0x0800u16.to_be(); // outer is IPv4
    let mut ipv4: rte_flow_item_ipv4 = unsafe { core::mem::zeroed() };
    ipv4.hdr.annon1.version_ihl = 0x45; // IPv4, 20-byte header
    ipv4.hdr.time_to_live = 64;
    ipv4.hdr.next_proto_id = 17; // UDP
    ipv4.hdr.src_addr = u32::from(e.ip_src).to_be();
    ipv4.hdr.dst_addr = u32::from(e.ip_dst).to_be();
    let mut udp: rte_flow_item_udp = unsafe { core::mem::zeroed() };
    udp.hdr.src_port = e.udp_src.to_be();
    udp.hdr.dst_port = 4789u16.to_be();
    let mut vxlan: rte_flow_item_vxlan = unsafe { core::mem::zeroed() };
    vxlan.annon1.annon1.flags = 0x08; // I flag: VNI present
    let v = e.vni.as_u32();
    vxlan.annon1.annon1.vni = [(v >> 16) as u8, (v >> 8) as u8, v as u8];

    Box::new(EncapDef {
        eth,
        ipv4,
        udp,
        vxlan,
    })
}

/// Build, validate, or install a flow rule in domain `D`.
/// `Pos` tracks the last matched header; [`Within`] constrains the next layer.
#[must_use = "a FlowBuilder does nothing until create() or validate() is called"]
pub struct FlowBuilder<'dev, D: Domain, Pos> {
    port: DevIndex,
    /// The device's live-rule count; borrowing it ties the builder and its rule to the device.
    live_rules: &'dev AtomicUsize,
    group: u32,
    priority: u32,
    items: Vec<MatchItem>,
    actions: Vec<Action>,
    domain: PhantomData<D>,
    position: PhantomData<Pos>,
}

impl<'dev, D: Domain> FlowBuilder<'dev, D, ()> {
    pub(crate) fn start(dev: &'dev Dev<'_, Started>) -> FlowBuilder<'dev, D, ()> {
        FlowBuilder {
            port: dev.info().index(),
            live_rules: dev.live_rules(),
            group: 0,
            priority: 0,
            items: Vec::new(),
            actions: Vec::new(),
            domain: PhantomData,
            position: PhantomData,
        }
    }
}

impl<'dev, D: Domain, Pos> FlowBuilder<'dev, D, Pos> {
    /// Change the pattern position while retaining the accumulated rule.
    fn retype<NewPos>(self) -> FlowBuilder<'dev, D, NewPos> {
        FlowBuilder {
            port: self.port,
            live_rules: self.live_rules,
            group: self.group,
            priority: self.priority,
            items: self.items,
            actions: self.actions,
            domain: PhantomData,
            position: PhantomData,
        }
    }

    /// Set the group (table) this rule lives in. Group 0 is the root; reach other groups via a
    /// [`jump`](Self::jump). Defaults to 0.
    pub fn group(mut self, group: FlowGroup) -> Self {
        self.group = group.0;
        self
    }

    /// Set the rule priority within its group (lower value is higher priority). Defaults to 0.
    pub fn priority(mut self, priority: Priority) -> Self {
        self.priority = priority.0;
        self
    }

    /// Match the presence of an Ethernet header.
    ///
    /// Only available at the start of a pattern (`Eth` is the sole layer `Within<()>`).
    pub fn match_eth(mut self) -> FlowBuilder<'dev, D, Eth>
    where
        Eth: Within<Pos>,
    {
        self.items.push(MatchItem::Eth);
        self.retype()
    }

    /// Match a VLAN (802.1Q) tag against `criteria` ([`VlanMatch::default`] matches any VLAN tag).
    ///
    /// Available after Ethernet (or after another VLAN, for QinQ).
    pub fn match_vlan(mut self, criteria: VlanMatch) -> FlowBuilder<'dev, D, Vlan>
    where
        Vlan: Within<Pos>,
    {
        let (spec, mask) = criteria.lower();
        self.items.push(MatchItem::Vlan(spec, mask));
        self.retype()
    }

    /// Match an IPv4 header against `criteria` ([`Ipv4Match::default`] matches any IPv4 packet).
    ///
    /// Available only after a layer IPv4 may follow (Ethernet, or a VLAN).
    pub fn match_ipv4(mut self, criteria: Ipv4Match) -> FlowBuilder<'dev, D, Ipv4>
    where
        Ipv4: Within<Pos>,
    {
        let (spec, mask) = criteria.lower();
        self.items.push(MatchItem::Ipv4(spec, mask));
        self.retype()
    }

    /// Match an IPv6 header against `criteria` ([`Ipv6Match::default`] matches any IPv6 packet).
    ///
    /// Available only after a layer IPv6 may follow (Ethernet, or a VLAN).
    pub fn match_ipv6(mut self, criteria: Ipv6Match) -> FlowBuilder<'dev, D, Ipv6>
    where
        Ipv6: Within<Pos>,
    {
        let (spec, mask) = criteria.lower();
        self.items.push(MatchItem::Ipv6(spec, mask));
        self.retype()
    }

    /// Match a UDP header against `criteria` ([`UdpMatch::default`] matches any UDP packet).
    ///
    /// Available only after a network layer (an IP header).
    pub fn match_udp(mut self, criteria: UdpMatch) -> FlowBuilder<'dev, D, Udp>
    where
        Udp: Within<Pos>,
    {
        let (spec, mask) = criteria.lower();
        self.items.push(MatchItem::Udp(spec, mask));
        self.retype()
    }

    /// Match a TCP header against `criteria` ([`TcpMatch::default`] matches any TCP packet).
    ///
    /// Available only after a network layer (an IP header).
    pub fn match_tcp(mut self, criteria: TcpMatch) -> FlowBuilder<'dev, D, Tcp>
    where
        Tcp: Within<Pos>,
    {
        let (spec, mask) = criteria.lower();
        self.items.push(MatchItem::Tcp(spec, mask));
        self.retype()
    }

    /// Match a VXLAN header against `criteria` ([`VxlanMatch::default`] matches any VXLAN packet).
    ///
    /// Available only after UDP (VXLAN is UDP-encapsulated). Inner (decapsulated) headers can then be
    /// matched as the pattern continues, since the `net` lattice resumes at the tunnel's inner start.
    pub fn match_vxlan(mut self, criteria: VxlanMatch) -> FlowBuilder<'dev, D, Vxlan>
    where
        Vxlan: Within<Pos>,
    {
        let (spec, mask) = criteria.lower();
        self.items.push(MatchItem::Vxlan(spec, mask));
        self.retype()
    }

    /// Redirect matching packets to another group (a JUMP action).
    pub fn jump(mut self, group: FlowGroup) -> Self {
        self.actions
            .push(Action::Jump(rte_flow_action_jump { group: group.0 }));
        self
    }

    /// Attach a MARK to matching packets, delivered to software in the mbuf
    /// ([`Mbuf::rx_mark`](crate::mem::Mbuf::rx_mark)).
    pub fn mark(mut self, mark: Mark) -> Self {
        self.actions
            .push(Action::Mark(rte_flow_action_mark { id: mark.0 }));
        self
    }

    /// Steer matching packets to a receive queue.
    pub fn queue(mut self, queue: RxQueueIndex) -> Self {
        self.actions.push(Action::Queue(rte_flow_action_queue {
            index: queue.as_u16(),
        }));
        self
    }

    /// Drop matching packets.
    pub fn drop(mut self) -> Self {
        self.actions.push(Action::Drop);
        self
    }

    /// Rewrite the IPv4 source address. The NIC fixes the affected checksums.
    pub fn set_ipv4_src(mut self, addr: Ipv4Addr) -> Self {
        self.actions.push(Action::SetIpv4Src(set_ipv4(addr)));
        self
    }

    /// Rewrite the IPv4 destination address. The NIC fixes the affected checksums.
    pub fn set_ipv4_dst(mut self, addr: Ipv4Addr) -> Self {
        self.actions.push(Action::SetIpv4Dst(set_ipv4(addr)));
        self
    }

    /// Rewrite the L4 (TCP/UDP) source port. The NIC fixes the affected checksum.
    pub fn set_tp_src(mut self, port: u16) -> Self {
        self.actions.push(Action::SetTpSrc(set_tp(port)));
        self
    }

    /// Rewrite the L4 (TCP/UDP) destination port. The NIC fixes the affected checksum.
    pub fn set_tp_dst(mut self, port: u16) -> Self {
        self.actions.push(Action::SetTpDst(set_tp(port)));
        self
    }

    /// Rewrite the IPv6 source address (`MODIFY_FIELD` on `IPV6_SRC`).
    pub fn set_ipv6_src(mut self, addr: Ipv6Addr) -> Self {
        self.actions.push(Action::ModifyField(modify_set(
            rte_flow_field_id::RTE_FLOW_FIELD_IPV6_SRC,
            128,
            &addr.octets(),
        )));
        self
    }

    /// Rewrite the IPv6 destination address (`MODIFY_FIELD` on `IPV6_DST`).
    pub fn set_ipv6_dst(mut self, addr: Ipv6Addr) -> Self {
        self.actions.push(Action::ModifyField(modify_set(
            rte_flow_field_id::RTE_FLOW_FIELD_IPV6_DST,
            128,
            &addr.octets(),
        )));
        self
    }

    /// Rewrite the IPv4 TTL (`MODIFY_FIELD` on `IPV4_TTL`). The NIC fixes the IPv4 checksum.
    pub fn set_ipv4_ttl(mut self, ttl: u8) -> Self {
        self.actions.push(Action::ModifyField(modify_set(
            rte_flow_field_id::RTE_FLOW_FIELD_IPV4_TTL,
            8,
            &[ttl],
        )));
        self
    }

    /// Rewrite the IPv6 hop limit (`MODIFY_FIELD` on `IPV6_HOPLIMIT`).
    pub fn set_ipv6_hop_limit(mut self, hop_limit: u8) -> Self {
        self.actions.push(Action::ModifyField(modify_set(
            rte_flow_field_id::RTE_FLOW_FIELD_IPV6_HOPLIMIT,
            8,
            &[hop_limit],
        )));
        self
    }

    /// Set the value read by [`Mbuf::rx_meta`](crate::mem::Mbuf::rx_meta).
    /// mlx5 cannot copy `VXLAN_VNI` directly; use an immediate value per VNI rule.
    pub fn set_meta(mut self, value: u32) -> Self {
        self.actions.push(Action::ModifyField(modify_set(
            rte_flow_field_id::RTE_FLOW_FIELD_META,
            32,
            &value.to_le_bytes(),
        )));
        self
    }

    /// Strip the outer Ethernet/IP/UDP/VXLAN headers.
    /// The pattern must include [`match_vxlan`](Self::match_vxlan).
    pub fn vxlan_decap(mut self) -> Self {
        self.actions.push(Action::VxlanDecap);
        self
    }

    /// Prepend a VXLAN tunnel. Combined with [`vxlan_decap`](Self::vxlan_decap),
    /// which runs first, this can replace a VNI that mlx5 cannot rewrite in place.
    pub fn vxlan_encap(mut self, outer: VxlanEncap) -> Self {
        self.actions.push(Action::VxlanEncap(build_encap(&outer)));
        self
    }

    /// Push a VLAN tag with the given TPID and zero VID/PCP.
    /// On BlueField-3, set VID/PCP in a later group reached via [`jump`](Self::jump),
    /// after the new tag exists.
    pub fn of_push_vlan(mut self, tpid: EthType) -> Self {
        self.actions
            .push(Action::OfPushVlan(rte_flow_action_of_push_vlan {
                ethertype: tpid.as_u16().to_be(),
            }));
        self
    }

    /// Pop the outer VLAN tag (`OF_POP_VLAN`). The rule's pattern must match the VLAN being stripped
    /// (i.e. include a VLAN item).
    pub fn of_pop_vlan(mut self) -> Self {
        self.actions.push(Action::OfPopVlan);
        self
    }

    /// Set the VID of the packet's existing outer VLAN tag (`OF_SET_VLAN_VID`). The tag must already
    /// be present -- either matched in the pattern or pushed in an earlier group (see
    /// [`of_push_vlan`](Self::of_push_vlan)).
    pub fn of_set_vlan_vid(mut self, vid: Vid) -> Self {
        self.actions
            .push(Action::OfSetVlanVid(rte_flow_action_of_set_vlan_vid {
                vlan_vid: vid.as_u16().to_be(),
            }));
        self
    }

    /// Set the PCP of the packet's existing outer VLAN tag (`OF_SET_VLAN_PCP`). Same tag-presence
    /// requirement as [`of_set_vlan_vid`](Self::of_set_vlan_vid).
    pub fn of_set_vlan_pcp(mut self, pcp: Pcp) -> Self {
        self.actions
            .push(Action::OfSetVlanPcp(rte_flow_action_of_set_vlan_pcp {
                vlan_pcp: pcp.to_u8(),
            }));
        self
    }

    /// Use the C arrays while their borrowed data and intermediate descriptors are alive.
    fn with_lowered<R>(
        &self,
        use_rule: impl FnOnce(&rte_flow_attr, &[rte_flow_item], &[rte_flow_action]) -> R,
    ) -> R {
        // SAFETY: `rte_flow_attr` is plain old data; an all-zero value is a valid empty attribute.
        let mut attr: rte_flow_attr = unsafe { core::mem::zeroed() };
        attr.group = self.group;
        attr.priority = self.priority;
        match D::DIRECTION {
            Direction::Ingress => attr.set_ingress(1),
            Direction::Egress => attr.set_egress(1),
            Direction::Transfer => attr.set_transfer(1),
        }

        let mut items: Vec<rte_flow_item> = Vec::with_capacity(self.items.len() + 1);
        for item in &self.items {
            items.push(rte_flow_item {
                type_: item.type_(),
                spec: item.spec(),
                last: null(),
                mask: item.mask(),
            });
        }
        items.push(rte_flow_item {
            type_: it::RTE_FLOW_ITEM_TYPE_END,
            spec: null(),
            last: null(),
            mask: null(),
        });

        // Preserve insertion order within each action rank.
        let mut ordered: Vec<&Action> = self.actions.iter().collect();
        ordered.sort_by_key(|a| a.rank());
        // Finish each descriptor array before borrowing it for the next pointer layer.
        let views: Vec<_> = ordered.iter().map(|action| action.view()).collect();
        let configs: Vec<_> = views.iter().map(ActionView::config).collect();
        let mut actions: Vec<_> = configs.iter().map(ActionConfig::as_ffi).collect();
        actions.push(rte_flow_action {
            type_: at::RTE_FLOW_ACTION_TYPE_END,
            conf: null(),
        });

        use_rule(&attr, &items, &actions)
    }

    /// Validate without installing. Creation may still fail, for example if
    /// hardware resources are exhausted.
    pub fn validate(&self) -> Result<(), FlowError> {
        let mut error: rte_flow_error = unsafe { core::mem::zeroed() };
        // SAFETY: the END-terminated arrays and their backing data outlive this call.
        let ret = self.with_lowered(|attr, items, actions| unsafe {
            rte_flow_validate(
                self.port(),
                attr,
                items.as_ptr(),
                actions.as_ptr(),
                &mut error,
            )
        });
        if ret == 0 {
            Ok(())
        } else {
            Err(FlowError::from_raw(&error))
        }
    }

    /// Install the rule, returning an RAII [`FlowRule`] handle bound to the device.
    pub fn create(self) -> Result<FlowRule<'dev>, FlowError> {
        let port = self.port;
        let live_rules = self.live_rules;
        let mut error: rte_flow_error = unsafe { core::mem::zeroed() };
        // SAFETY: the END-terminated arrays and their backing data outlive this call;
        // the PMD copies the configuration before returning.
        let flow = self.with_lowered(|attr, items, actions| unsafe {
            rte_flow_create(
                port.as_u16(),
                attr,
                items.as_ptr(),
                actions.as_ptr(),
                &mut error,
            )
        });
        match NonNull::new(flow) {
            Some(flow) => Ok(FlowRule::new(port, flow, live_rules)),
            None => Err(FlowError::from_raw(&error)),
        }
    }

    fn port(&self) -> u16 {
        self.port.as_u16()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_encapsulation<D: Domain, Pos>(
        builder: &FlowBuilder<'_, D, Pos>,
        expected: &[VxlanEncap],
    ) {
        builder.with_lowered(|_, _, actions| {
            let encaps: Vec<_> = actions
                .iter()
                .filter(|a| a.type_ == at::RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP)
                .collect();
            assert_eq!(encaps.len(), expected.len());
            for (action, expected) in encaps.into_iter().zip(expected) {
                // SAFETY: the lowered descriptors and headers are borrowed for this callback.
                let config = unsafe { &*action.conf.cast::<rte_flow_action_vxlan_encap>() };
                let items = unsafe { core::slice::from_raw_parts(config.definition, 5) };
                assert_eq!(
                    items.iter().map(|item| item.type_).collect::<Vec<_>>(),
                    [
                        it::RTE_FLOW_ITEM_TYPE_ETH,
                        it::RTE_FLOW_ITEM_TYPE_IPV4,
                        it::RTE_FLOW_ITEM_TYPE_UDP,
                        it::RTE_FLOW_ITEM_TYPE_VXLAN,
                        it::RTE_FLOW_ITEM_TYPE_END,
                    ]
                );
                assert!(items[4].spec.is_null());
                assert!(
                    items
                        .iter()
                        .all(|item| item.mask.is_null() && item.last.is_null())
                );
                let eth = unsafe { &*items[0].spec.cast::<rte_flow_item_eth>() };
                let ipv4 = unsafe { &*items[1].spec.cast::<rte_flow_item_ipv4>() };
                let udp = unsafe { &*items[2].spec.cast::<rte_flow_item_udp>() };
                let vxlan = unsafe { &*items[3].spec.cast::<rte_flow_item_vxlan>() };
                assert_eq!(
                    unsafe { eth.annon1.hdr.src_addr.addr_bytes },
                    expected.eth_src.0
                );
                assert_eq!(
                    unsafe { eth.annon1.hdr.dst_addr.addr_bytes },
                    expected.eth_dst.0
                );
                assert_eq!(u16::from_be(unsafe { eth.annon1.hdr.ether_type }), 0x0800);
                assert_eq!(u32::from_be(ipv4.hdr.src_addr), u32::from(expected.ip_src));
                assert_eq!(u32::from_be(ipv4.hdr.dst_addr), u32::from(expected.ip_dst));
                assert_eq!(u16::from_be(udp.hdr.src_port), expected.udp_src);
                assert_eq!(u16::from_be(udp.hdr.dst_port), 4789);
                let vni = unsafe { vxlan.annon1.annon1.vni };
                assert_eq!(
                    u32::from_be_bytes([0, vni[0], vni[1], vni[2]]),
                    expected.vni.as_u32()
                );
            }
        });
    }

    #[test]
    fn vxlan_encap_pointers_survive_builder_moves() -> Result<(), net::vxlan::InvalidVni> {
        let live = AtomicUsize::new(0);
        let builder: FlowBuilder<'_, crate::flow::Ingress, ()> = FlowBuilder {
            port: DevIndex(0),
            live_rules: &live,
            group: 0,
            priority: 0,
            items: Vec::new(),
            actions: Vec::new(),
            domain: PhantomData,
            position: PhantomData,
        };
        let first = VxlanEncap {
            eth_src: Mac([2, 0, 0, 0, 0, 1]),
            eth_dst: Mac([2, 0, 0, 0, 0, 2]),
            ip_src: Ipv4Addr::new(192, 0, 2, 1),
            ip_dst: Ipv4Addr::new(192, 0, 2, 2),
            udp_src: 12345,
            vni: Vni::new_checked(0x123456)?,
        };
        let second = VxlanEncap {
            ip_src: Ipv4Addr::new(198, 51, 100, 1),
            udp_src: 54321,
            vni: Vni::new_checked(0xabcdef)?,
            ..first
        };
        let mut builder = builder.vxlan_encap(first).mark(Mark(7));
        check_encapsulation(&builder, &[first]);
        builder.actions.reserve(128);
        let builder = builder.match_eth().vxlan_encap(second).drop();
        check_encapsulation(&builder, &[first, second]);
        check_encapsulation(&builder, &[first, second]);
        assert_eq!(live.load(concurrency::sync::atomic::Ordering::Relaxed), 0);
        Ok(())
    }

    /// The validated mlx5 pipeline order: pop -> MARK -> MODIFY_HDR -> push -> terminal.
    #[test]
    fn action_rank_orders_pipeline() {
        let pop = Action::OfPopVlan;
        let mark = Action::Mark(rte_flow_action_mark { id: 0 });
        let modify = Action::SetIpv4Dst(set_ipv4(Ipv4Addr::UNSPECIFIED));
        let push = Action::OfPushVlan(rte_flow_action_of_push_vlan { ethertype: 0 });
        let queue = Action::Queue(rte_flow_action_queue { index: 0 });
        assert!(pop.rank() < mark.rank());
        assert!(
            mark.rank() < modify.rank(),
            "MARK must precede MODIFY_HDR (hardware-validated)"
        );
        assert!(modify.rank() < push.rank());
        assert!(push.rank() < queue.rank());
    }

    /// Actions added in a HW-invalid order are canonicalized by the lowering sort.
    #[test]
    fn scrambled_actions_canonicalize() {
        let scrambled = [
            Action::SetIpv4Dst(set_ipv4(Ipv4Addr::UNSPECIFIED)), // MODIFY_HDR added first...
            Action::Mark(rte_flow_action_mark { id: 7 }), // ...MARK after (would be rejected)
            Action::Queue(rte_flow_action_queue { index: 0 }),
        ];
        let mut ordered: Vec<&Action> = scrambled.iter().collect();
        ordered.sort_by_key(|a| a.rank());
        let types: Vec<at::Type> = ordered.iter().map(|a| a.type_()).collect();
        assert_eq!(
            types,
            [
                at::RTE_FLOW_ACTION_TYPE_MARK,
                at::RTE_FLOW_ACTION_TYPE_SET_IPV4_DST,
                at::RTE_FLOW_ACTION_TYPE_QUEUE,
            ]
        );
    }
}
