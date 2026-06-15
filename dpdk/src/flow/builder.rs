// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Building and installing flow rules.
//!
//! This is the one place that touches the `rte_flow` FFI and the pattern/action arrays. The builder
//! owns the per-item match spec/mask structs and the per-action config structs, so the pointers
//! handed to `rte_flow_create`/`validate` stay valid for the duration of the call (the PMD copies
//! them before returning).

use alloc::vec::Vec;
use core::ffi::c_void;
use core::marker::PhantomData;
use core::net::{Ipv4Addr, Ipv6Addr};
use core::ptr::{NonNull, from_ref, null};

use dpdk_sys::{
    rte_flow_action, rte_flow_action_jump, rte_flow_action_mark, rte_flow_action_modify_field,
    rte_flow_action_of_push_vlan, rte_flow_action_of_set_vlan_pcp, rte_flow_action_of_set_vlan_vid,
    rte_flow_action_queue, rte_flow_action_set_ipv4, rte_flow_action_set_tp,
    rte_flow_action_type as at, rte_flow_attr, rte_flow_create, rte_flow_error, rte_flow_field_id,
    rte_flow_item, rte_flow_item_ipv4, rte_flow_item_ipv6, rte_flow_item_tcp,
    rte_flow_item_type as it, rte_flow_item_udp, rte_flow_item_vlan, rte_flow_item_vxlan,
    rte_flow_modify_op, rte_flow_validate,
};

use net::eth::Eth;
use net::eth::ethtype::EthType;
use net::headers::Within;
use net::ipv4::Ipv4;
use net::ipv6::Ipv6;
use net::tcp::Tcp;
use net::udp::Udp;
use net::vlan::{Pcp, Vid, Vlan};
use net::vxlan::Vxlan;

use crate::dev::{Dev, Started};
use crate::flow::error::FlowError;
use crate::flow::pattern::{Ipv4Match, Ipv6Match, TcpMatch, UdpMatch, VlanMatch, VxlanMatch};
use crate::flow::rule::FlowRule;
use crate::flow::{Direction, Domain, FlowGroup, Mark, Priority};
use crate::queue::rx::RxQueueIndex;

/// A pattern item plus the owned spec/mask structs the PMD reads through pointers.
///
/// Keeping the spec/mask inline here is what keeps the pointers passed to `rte_flow_create` valid
/// for the duration of the call. `Eth` matches presence only (per-field Ethernet matching is
/// deferred -- `rte_flow_item_eth` carries the fields behind an anonymous union).
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
        }
    }

    /// Position in the mlx5 fixed action pipeline. The hardware steering engine processes actions in
    /// a fixed order and rejects an out-of-order actions list (mlx5 HWS: "Invalid action_type
    /// sequence: MODIFY_HDR, TAG, TIR"). Validated on a BlueField-3 (`hws_combo_probe`): `MARK` before
    /// a `SET_*` rewrite is accepted, the reverse is rejected; the full `MARK -> SET_* -> QUEUE` chain
    /// is accepted. Distinct action types are semantically order-independent, so [`lower`] sorts by
    /// this rank (stably) regardless of the order the caller added them -- the builder produces a
    /// HW-valid ordering rather than rejecting or trusting the call order.
    ///
    /// Order: header removal (pop/decap) -> `TAG`/`MARK` -> `MODIFY_HDR` (field rewrites) -> header
    /// push (encap) -> terminal forward (queue/drop/jump).
    fn rank(&self) -> u8 {
        match self {
            Action::OfPopVlan => 0,
            Action::Mark(_) => 1,
            Action::SetIpv4Src(_)
            | Action::SetIpv4Dst(_)
            | Action::SetTpSrc(_)
            | Action::SetTpDst(_)
            | Action::OfSetVlanVid(_)
            | Action::OfSetVlanPcp(_)
            | Action::ModifyField(_) => 2,
            Action::OfPushVlan(_) => 3,
            Action::Jump(_) | Action::Queue(_) | Action::Drop => 4,
        }
    }

    /// Pointer to the configuration struct (null for actions that take none). Valid while `self`
    /// is alive and not moved.
    fn conf(&self) -> *const c_void {
        match self {
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
        }
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

/// A `MODIFY_FIELD` that sets `dst` to an immediate value. `value` holds the low `width` bits in the
/// same byte order and length as the corresponding `rte_flow_item_*` field (e.g. network-order for
/// header fields), left-aligned; per the `rte_flow` contract the destination's bit offset is
/// inherited by the immediate source.
fn modify_set(
    dst: rte_flow_field_id::Type,
    width: u32,
    value: &[u8],
) -> rte_flow_action_modify_field {
    // SAFETY: `rte_flow_action_modify_field` is plain data; all-zero is a valid empty value
    // (operation SET, level/offset 0, empty immediate).
    let mut mf: rte_flow_action_modify_field = unsafe { core::mem::zeroed() };
    mf.operation = rte_flow_modify_op::RTE_FLOW_MODIFY_SET;
    mf.dst.field = dst;
    mf.src.field = rte_flow_field_id::RTE_FLOW_FIELD_VALUE;
    let mut buf = [0u8; 16];
    buf[..value.len()].copy_from_slice(value);
    mf.src.annon1.value = buf; // union write (safe)
    mf.width = width;
    mf
}

/// Builds one flow rule and installs (or validates) it.
///
/// Construct via [`Flow::ingress`](crate::flow::Flow::ingress) /
/// [`egress`](crate::flow::Flow::egress) / [`transfer`](crate::flow::Flow::transfer). Two typestates
/// constrain construction:
///
/// - `D` fixes the `ingress`/`egress`/`transfer` attribute (which are mutually exclusive in the
///   API).
/// - `Pos` is the type-level "current layer" of the match pattern, exactly as in
///   [`Headers::pat`](net::headers::Headers::pat). Each `match_*` method requires the next layer to
///   satisfy [`Within<Pos>`], reusing `net`'s header-adjacency graph -- so an out-of-order pattern
///   (`match_udp` with no preceding IP layer, a second `match_eth`, an L3 match before `match_eth`)
///   is a compile error rather than a runtime rejection from the PMD. A fresh builder starts at
///   `Pos = ()`, where only [`match_eth`](Self::match_eth) (the sole `Within<()>` layer) is
///   available.
#[must_use = "a FlowBuilder does nothing until create() or validate() is called"]
pub struct FlowBuilder<'dev, D: Domain, Pos> {
    dev: &'dev Dev<Started>,
    group: u32,
    priority: u32,
    items: Vec<MatchItem>,
    actions: Vec<Action>,
    domain: PhantomData<D>,
    position: PhantomData<Pos>,
}

impl<'dev, D: Domain> FlowBuilder<'dev, D, ()> {
    pub(crate) fn start(dev: &'dev Dev<Started>) -> FlowBuilder<'dev, D, ()> {
        FlowBuilder {
            dev,
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
    /// Move the accumulated builder to a new pattern position, preserving everything else.
    ///
    /// The owned `items`/`actions` carry over by move; only the type-level `Pos` changes.
    fn retype<NewPos>(self) -> FlowBuilder<'dev, D, NewPos> {
        FlowBuilder {
            dev: self.dev,
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

    /// Set the 32-bit `META` channel to an immediate value, delivered to software in the mbuf
    /// ([`Mbuf::rx_meta`](crate::mem::Mbuf::rx_meta)).
    ///
    /// In a per-VNI match rule this is how the matched VNI reaches software: mlx5 rejects a generic
    /// `MODIFY_FIELD` that reads or writes `VXLAN_VNI` ("modifications of the VXLAN Network Identifier
    /// is not supported"), so there is no single global "copy any VNI to META" rule -- instead each
    /// per-VNI rule carries that VNI as an immediate.
    pub fn set_meta(mut self, value: u32) -> Self {
        self.actions.push(Action::ModifyField(modify_set(
            rte_flow_field_id::RTE_FLOW_FIELD_META,
            32,
            &value.to_le_bytes(),
        )));
        self
    }

    /// Push a new VLAN tag (`OF_PUSH_VLAN`) with the given TPID (typically
    /// [`EthType::VLAN`](net::eth::ethtype::EthType::VLAN) for 802.1Q). The pushed tag's VID/PCP are
    /// zero until set.
    ///
    /// Setting the VID/PCP of a freshly pushed tag cannot be done in the same rule: the VLAN field
    /// does not exist until the push takes effect, so the set must happen in a later group reached
    /// via [`jump`](Self::jump) (push in group N, [`of_set_vlan_vid`](Self::of_set_vlan_vid) /
    /// [`of_set_vlan_pcp`](Self::of_set_vlan_pcp) in group N+1). Validated on a BlueField-3.
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

    /// Lower the accumulated attributes, pattern, and actions into the `rte_flow` C arrays.
    ///
    /// The returned `items`/`actions` `Vec`s carry pointers into `self`, so `self` must outlive
    /// their use (it does in [`create`](Self::create)/[`validate`](Self::validate)).
    fn lower(&self) -> (rte_flow_attr, Vec<rte_flow_item>, Vec<rte_flow_action>) {
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

        // Emit actions in the mlx5 fixed pipeline order (see `Action::rank`), not call order. A stable
        // sort keeps the relative order of same-rank actions (e.g. two field rewrites).
        let mut ordered: Vec<&Action> = self.actions.iter().collect();
        ordered.sort_by_key(|a| a.rank());
        let mut actions: Vec<rte_flow_action> = Vec::with_capacity(ordered.len() + 1);
        for action in ordered {
            actions.push(rte_flow_action {
                type_: action.type_(),
                conf: action.conf(),
            });
        }
        actions.push(rte_flow_action {
            type_: at::RTE_FLOW_ACTION_TYPE_END,
            conf: null(),
        });

        (attr, items, actions)
    }

    /// Ask the PMD whether this rule *could* be created, without installing it.
    ///
    /// Validation is a hint, not a guarantee: a NIC may pass validate yet fail create (resource
    /// exhaustion), and behavior is only truly confirmed by observing packets. Use it as a cheap
    /// capability probe, not as proof.
    pub fn validate(&self) -> Result<(), FlowError> {
        let (attr, items, actions) = self.lower();
        let mut error: rte_flow_error = unsafe { core::mem::zeroed() };
        // SAFETY: `attr`, `items`, `actions`, and the spec/mask/config structs owned by `self` all
        // outlive this call; the arrays are END-terminated and the pointers are non-dangling.
        let ret = unsafe {
            rte_flow_validate(
                self.port(),
                &attr,
                items.as_ptr(),
                actions.as_ptr(),
                &mut error,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(FlowError::from_raw(&error))
        }
    }

    /// Install the rule, returning an RAII [`FlowRule`] handle bound to the device.
    pub fn create(self) -> Result<FlowRule<'dev>, FlowError> {
        let port = self.dev.info.index();
        let (attr, items, actions) = self.lower();
        let mut error: rte_flow_error = unsafe { core::mem::zeroed() };
        // SAFETY: `attr`, `items`, `actions`, and the spec/mask/config structs owned by `self` all
        // outlive this call; the arrays are END-terminated and the pointers are non-dangling. The
        // PMD copies what it needs before returning.
        let flow = unsafe {
            rte_flow_create(
                port.as_u16(),
                &attr,
                items.as_ptr(),
                actions.as_ptr(),
                &mut error,
            )
        };
        match NonNull::new(flow) {
            Some(flow) => Ok(FlowRule::new(port, flow)),
            None => Err(FlowError::from_raw(&error)),
        }
    }

    fn port(&self) -> u16 {
        self.dev.info.index().as_u16()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Actions added in a HW-invalid order are canonicalized by the same stable sort `lower` uses.
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
