// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(missing_docs)] // TODO

use crate::FlowKey;
use crate::flows::conn_tracking::SynProxyState;
use crate::flows::{FlowInfo, FlowInfoFlags};
use crate::interface::InterfaceIndex;
use crate::ip::dscp::Dscp;
use crate::ip::ecn::Ecn;
use crate::tcp::TcpFlags;
use crate::vxlan::Vni;

use bitflags::bitflags;
use concurrency::sync::Arc;
use serde::Serialize;
use std::fmt::Display;
use std::net::IpAddr;
use std::num::NonZero;
use strum_macros::{EnumCount, EnumIter, FromRepr, IntoStaticStr};
use tracing::error;

/// Every VRF is univocally identified with a numerical VRF id
pub type VrfId = u32;

/// A bridge domain identifier.
#[derive(Copy, Clone, Debug, Default)]
pub struct BridgeDomain(u32);
#[allow(unused)]
impl BridgeDomain {
    #[must_use]
    pub fn get_id(&self) -> u32 {
        self.0
    }
    #[must_use]
    pub fn with_id(id: u32) -> Self {
        Self(id)
    }
}

/// A dataplane-level discriminant to identify (traffic pertaining to) a Vpc
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Ord, PartialOrd, Serialize)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub enum VpcDiscriminant {
    VNI(Vni),
}

impl VpcDiscriminant {
    #[must_use]
    pub fn from_vni(vni: Vni) -> Self {
        Self::VNI(vni)
    }
}
impl AsRef<VpcDiscriminant> for VpcDiscriminant {
    fn as_ref(&self) -> &VpcDiscriminant {
        self
    }
}

impl From<Vni> for VpcDiscriminant {
    fn from(vni: Vni) -> Self {
        Self::VNI(vni)
    }
}

impl TryFrom<VpcDiscriminant> for Vni {
    type Error = ();

    fn try_from(value: VpcDiscriminant) -> Result<Self, Self::Error> {
        match value {
            VpcDiscriminant::VNI(vni) => Ok(vni),
        }
    }
}

impl Display for VpcDiscriminant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VpcDiscriminant::VNI(vni) => write!(f, "VNI({vni})"),
        }
    }
}

#[repr(u8)]
#[allow(unused)]
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, EnumCount, EnumIter, FromRepr, IntoStaticStr)]
pub enum DoneReason {
    InternalFailure,      /* catch-all for internal issues */
    InterfaceUnknown,     /* the interface cannot be found */
    InterfaceDetached,    /* interface has not been attached to any VRF */
    InterfaceAdmDown,     /* interface is admin down */
    InterfaceOperDown,    /* interface is oper down : no link */
    InterfaceUnsupported, /* the operation is not supported on the interface */
    NotEthernet,          /* could not get eth header */
    Unhandled,            /* there exists no support to handle this type of packet */
    MacNotForUs,          /* frame is not broadcast nor for us */
    InvalidDstMac,        /* dropped the packet since it had to have an invalid destination mac */
    MissingEtherType,     /* couldn't determine ethertype to use */
    NotIp,                /* could not get IP header or packet is not IP */
    ArpOutOfResources,    /* required ARP/ND resolution but had no resources to admit packet */
    ArpDaemonDrop,        /* the packet reached the ARP/ND daemon, which dropped it */
    RouteFailure,         /* missing routing information */
    RouteDrop,            /* routing explicitly requests pkts to be dropped */
    HopLimitExceeded,     /* TTL / Hop count was exceeded */
    MissL2resolution,     /* adjacency failure: we don't know mac of some ip next-hop */
    VxlanDecapFailure,    /* Failed to decap a Vxlan packet */
    VxlanEncapFailure,    /* Failed to encap a packet in vxlan */
    VxlanNotForUs,        /* Got vxlan packet not for us */
    Filtered,             /* The packet was administratively filtered */
    AclDropped,           /* The packet was dropped by an ACL rule */
    RateLimited,          /* Dropped by a rate-limit rule */
    IngressDropped,       /* Dropped by a drop rule of the gateway's ingress policy */
    NatOutOfResources,    /* can't do NAT due to lack of resources */
    FlowCapacityExceeded, /* could not create flow state: flow table capacity exceeded */
    NatUnsupportedProto,  /* unsupported transport protocol for NATing */
    NatFailure,           /* It was not possible to NAT the packet */
    NatNotPortForwarded,  /* Packet was sent to port forwarder and it rejected it */
    Malformed,            /* the packet does not conform / is malformed */
    Unroutable,           /* we don't have state to forward the packet */
    InvalidChecksum,      /* the validation of a checksum for this packet failed */
    IcmpErrorIncomplete,  /* the packet is an ICMP error but it does not contain data it should */
    InternalDrop,         /* the packet was dropped internally due to a queue being full */
    Local,                /* the packet has to be locally consumed by kernel */
    Delivered,            /* the packet buffer was delivered by the pipeline for xmit */
    DeparseError, /* the packet was delivered to driver, but not sent due to serialization issue */
    NoBuffRoomXmit, /* the packet was delivered to driver, but not serialized due to lack of buffer headroom */
    NoBuffRoom, /* the packet had to be dropped due to lack of buffer room (e.g. when rebuffering) */
    StaleGeneration, /* stamped with a configuration generation no longer live */
    TrapUnknownNode, /* trapped by hardware at a node that is not a trap target here: a lowering bug */
    TrapDecode,      /* trapped by hardware with metadata its node cannot decode: a lowering bug */
    TrapShape,       /* trapped by hardware, but not the packet its node takes: a lowering bug */
}

bitflags! {
    /// Each flag is a bit of its own, given by its position. A bit shared by two flags is a
    /// compile-time error (see the assertion below).
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    struct MetaFlags: u32 {
        const NATTED_SRC          = 1 << 0; /* set to true if source address of a packet has been NATed */
        const NATTED_DST          = 1 << 1; /* set to true if destination address of a packet has been NATed */
        const REFR_CHKSUM         = 1 << 2; /* if true, an indication that packet checksums need to be refreshed */
        const IS_OVERLAY          = 1 << 3; /* Packet was obtained by decapsulation and belongs to a VPC */
        const REQ_MASQUERADE      = 1 << 4; /* Packet requires masquerade (source and/or destination) */
        const REQ_PORT_FORWARDING = 1 << 5; /* Packet requires port forwarding */
        const REQ_STATIC_NAT_SRC  = 1 << 6; /* Packet requires static NAT (source) */
        const REQ_STATIC_NAT_DST  = 1 << 7; /* Packet requires static NAT (destination) */
        const FORCE_FLOW_TRACKING = 1 << 8; /* We need to track this flow, e.g. to apply stateful user ACLs */
        const NEED_ARPND          = 1 << 9; /* Need ARP/ND resolution */
        const NIC_DECAP           = 1 << 10; /* The NIC decapsulated it; `src_vpcd` is its VNI, until the first IP forwarder takes it */
    }
}

// No two flags of [`MetaFlags`] share a bit: their union has a bit per flag
const _: () = assert!(
    MetaFlags::all().bits().count_ones() as usize == <MetaFlags as bitflags::Flags>::FLAGS.len(),
    "two MetaFlags flags share a bit"
);

/// One of the two banks a configuration generation can occupy, in hardware and software alike
/// (`notes/match-action-dag/GENERATIONS.md`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Bank {
    /// Bank A.
    A,
    /// Bank B.
    B,
}

impl Bank {
    /// The other bank.
    #[must_use]
    pub const fn other(self) -> Bank {
        match self {
            Bank::A => Bank::B,
            Bank::B => Bank::A,
        }
    }
}

/// The generation a packet was classified under, as hardware stamps it: the bank, and the low
/// bits of the generation, which catch a straggler stamped before its bank was reused.
///
/// One byte, never zero, so that `Option<Stamp>` is one byte too: the bank in the top bit, a
/// marker bit, and the generation's low three bits. Three because that is what the trap MARK
/// carries (four bits with the bank, `notes/match-action-dag/TRAP-RESUME.md` §3): a straggler
/// aliases a live generation only if it is a multiple of eight generations old.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Stamp(NonZero<u8>);

impl Stamp {
    const BANK: u8 = 0x80;
    const MARKER: u8 = 0x40;
    const LOW: u8 = 0x07;

    /// The stamp of `generation` in `bank`.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // the low bits are the point
    pub const fn new(bank: Bank, generation: u64) -> Stamp {
        let low = (generation as u8) & Self::LOW;
        let bits = match bank {
            Bank::A => low | Self::MARKER,
            Bank::B => low | Self::MARKER | Self::BANK,
        };
        match NonZero::new(bits) {
            Some(bits) => Stamp(bits),
            None => unreachable!(),
        }
    }

    /// As one byte, never zero.
    #[must_use]
    pub const fn to_bits(self) -> u8 {
        self.0.get()
    }

    /// From [`Stamp::to_bits`]: `None` for a byte no stamp encodes to.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Stamp> {
        if bits & Self::MARKER == 0 {
            return None;
        }
        match NonZero::new(bits) {
            Some(bits) => Some(Stamp(bits)),
            None => None,
        }
    }

    /// The bank.
    #[must_use]
    pub const fn bank(self) -> Bank {
        if self.0.get() & Self::BANK == 0 {
            Bank::A
        } else {
            Bank::B
        }
    }

    /// As the four bits hardware writes: the bank, then the generation's low bits.
    #[must_use]
    pub const fn to_nibble(self) -> u8 {
        let bits = self.0.get();
        ((bits & Self::BANK) >> 4) | (bits & Self::LOW)
    }

    /// From [`Stamp::to_nibble`]'s four bits (higher bits are ignored).
    #[must_use]
    pub const fn from_nibble(nibble: u8) -> Stamp {
        let bits = ((nibble & 0x08) << 4) | (nibble & Self::LOW) | Self::MARKER;
        match NonZero::new(bits) {
            Some(bits) => Stamp(bits),
            None => unreachable!(),
        }
    }
}

/// Where hardware left a packet to software: the node it enters at, which has not executed
/// (everything before it has, once), and its trap edge's metadata, as that node declares it
/// (`notes/match-action-dag/TRAP-RESUME.md` T1, T2). The generation is the [`Stamp`] beside it,
/// in the packet's [`Mark`]. No trap: the packet enters at the root.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Trap {
    node: NonZero<u8>,
    payload: u16,
}

impl Trap {
    /// A trap at `node` (never the root, 0) with its edge's `payload`.
    #[must_use]
    pub const fn new(node: NonZero<u8>, payload: u16) -> Trap {
        Trap { node, payload }
    }

    /// The node it enters at.
    #[must_use]
    pub const fn node(self) -> NonZero<u8> {
        self.node
    }

    /// Its edge's metadata, encoded as its node declares.
    #[must_use]
    pub const fn payload(self) -> u16 {
        self.payload
    }
}

/// What hardware wrote in a packet's MARK: the generation it classified the packet under, and,
/// past the root, where it trapped it. The trap rule writes MARK as one immediate
/// (`notes/match-action-dag/TRAP-RESUME.md` §3), laid out as:
///
/// | MARK bits | Content |
/// | --- | --- |
/// | 23:19 | the node, 5 bits; 0 is the root, 31 reserved (it keeps MARK below the PMD's reserved values above `0xffffef`) |
/// | 18:15 | the stamp: bank, and the generation's low 3 bits ([`Stamp::to_nibble`]) |
/// | 14:0 | the node's edge payload, 15 bits; none at the root |
///
/// Kept as received, in 3 bytes (`Packet<Mbuf>`'s size budget,
/// `dataplane/src/drivers/dpdk/worker.rs`): the reserved node stands for no MARK, so the field
/// needs no `Option`.
///
/// Revised from §3's draft (8 node bits, 12 payload bits): slice 1's edges past the flow filter
/// carry its verdict, an interned destination VPC and five flags, which 12 bits would hold only
/// for 127 VPCs. 31 node ids is far more than slice 1's handful of trap targets (§4: static ids).
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Mark([u8; 3]);

/// Why a MARK is not one [`Mark`] encodes: a counted drop, and a lowering bug if ever seen (T7).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MarkError {
    /// Bits above the layout, or the reserved node.
    Reserved,
    /// The root with a payload: the root takes none.
    RootPayload,
}

impl Mark {
    /// Payload bits.
    pub const PAYLOAD_BITS: u32 = 15;
    /// The largest payload.
    pub const PAYLOAD_MAX: u16 = (1 << Self::PAYLOAD_BITS) - 1;
    /// The reserved node id.
    pub const RESERVED_NODE: u8 = 31;
    const NODE_SHIFT: u32 = 19;
    const STAMP_SHIFT: u32 = 15;
    /// No MARK: the reserved node.
    const NONE: Mark = Mark([0xff; 3]);

    /// What the trap rule for `trap` (`None`: the root) writes on packets classified under
    /// `stamp`.
    ///
    /// # Panics
    ///
    /// If the trap's node is the reserved id or wider, or its payload exceeds
    /// [`Mark::PAYLOAD_MAX`]: the lowering refuses both at load time.
    #[must_use]
    pub const fn new(stamp: Stamp, trap: Option<Trap>) -> Mark {
        let (node, payload) = match trap {
            Some(trap) => (trap.node.get(), trap.payload),
            None => (0, 0),
        };
        assert!(
            node < Self::RESERVED_NODE,
            "a reserved or too wide trap node"
        );
        assert!(payload <= Self::PAYLOAD_MAX, "a too wide trap payload");
        let bits = ((node as u32) << Self::NODE_SHIFT)
            | ((stamp.to_nibble() as u32) << Self::STAMP_SHIFT)
            | payload as u32;
        let [lo, mid, hi, _] = bits.to_le_bytes();
        Mark([lo, mid, hi])
    }

    /// From the 32 bits the NIC delivers.
    ///
    /// # Errors
    ///
    /// If the MARK is outside the layout ([`MarkError`]).
    pub const fn from_bits(bits: u32) -> Result<Mark, MarkError> {
        let node = bits >> Self::NODE_SHIFT;
        if node >= Self::RESERVED_NODE as u32 {
            return Err(MarkError::Reserved);
        }
        if node == 0 && bits & Self::PAYLOAD_MAX as u32 != 0 {
            return Err(MarkError::RootPayload);
        }
        let [lo, mid, hi, _] = bits.to_le_bytes();
        Ok(Mark([lo, mid, hi]))
    }

    /// The 32 bits the trap rule writes.
    #[must_use]
    pub const fn to_bits(self) -> u32 {
        let [lo, mid, hi] = self.0;
        u32::from_le_bytes([lo, mid, hi, 0])
    }

    /// The generation the packet was classified under.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // masked
    pub const fn stamp(self) -> Stamp {
        Stamp::from_nibble((self.to_bits() >> Self::STAMP_SHIFT) as u8 & 0xf)
    }

    /// Where the packet was trapped, if past the root.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // masked, and below the reserved node
    pub const fn trap(self) -> Option<Trap> {
        let bits = self.to_bits();
        match NonZero::new((bits >> Self::NODE_SHIFT) as u8) {
            Some(node) => Some(Trap::new(node, (bits & Self::PAYLOAD_MAX as u32) as u16)),
            None => None,
        }
    }

    const fn is_none(self) -> bool {
        self.to_bits() >> Self::NODE_SHIFT >= Self::RESERVED_NODE as u32
    }
}

impl Default for Mark {
    fn default() -> Self {
        Mark::NONE
    }
}

impl std::fmt::Debug for Mark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_none() {
            f.pad("no mark")
        } else {
            f.debug_struct("Mark")
                .field("stamp", &self.stamp())
                .field("trap", &self.trap())
                .finish()
        }
    }
}

#[allow(unused)]
#[derive(Debug, Default, Clone)]
pub struct PacketMeta {
    flags: MetaFlags,
    pub iif: Option<InterfaceIndex>, /* incoming interface: set by ingress stage */
    pub oif: Option<InterfaceIndex>, /* outgoing interface - set by IO manager for outgoing traffic or forwarding functions */
    pub nh_addr: Option<IpAddr>,     /* IP address of next-hop */
    pub vrf: Option<VrfId>,          /* for IP packet, the VRF to use to route it */
    pub done: Option<DoneReason>, /* if Some, the reason why a packet was marked as done, including delivery to NF */
    pub src_vpcd: Option<VpcDiscriminant>, /* the vpc discriminant of a received encapsulated packet */
    pub outer_ip_len: Option<NonZero<u16>>, /* length of a decapsulated packet's outer IP packet, as received */
    pub dst_vpcd: Option<VpcDiscriminant>, /* the vpc discriminant of a packet to be (or already) re-encapsulated by the gateway */
    pub flow_info: Option<Arc<FlowInfo>>, /* flow specific information that can be looked up in the flow table */
    pub dscp: Option<Dscp>,               /* Dscp to preserve for egress traffic */
    pub ecn: Option<Ecn>,                 /* Ecn to preserve for egress traffic */
    pub flow_key: Option<Box<FlowKey>>,   /* the flow key to use for NAT flow creation */
    pub tcp_flags: Option<TcpFlags>,      /* TCP flags seen by the ACL stage, for new flows */
    pub syn_proxy: Option<Arc<SynProxyState>>, /* state for new flows set up by the SYN proxy */
    mark: Mark, /* what hardware wrote in MARK, if anything: its stamp and trap */
    #[cfg(feature = "test_meta")]
    pub test: Option<Box<TestMeta>>,
}

#[cfg(feature = "test_meta")]
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TestMeta {
    pub id: u64,
}
impl PacketMeta {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn set_flag(&mut self, flag: MetaFlags, value: bool) {
        if value {
            self.flags.insert(flag);
        } else {
            self.flags.remove(flag);
        }
    }

    /// Tell if the packet has been marked as done (see [`Self::done`]).
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.done.is_some()
    }

    /// What hardware wrote in MARK, if anything.
    #[must_use]
    pub fn mark(&self) -> Option<Mark> {
        (!self.mark.is_none()).then_some(self.mark)
    }

    /// Set what hardware wrote in MARK (the driver, or emulated hardware).
    pub fn set_mark(&mut self, mark: Option<Mark>) {
        self.mark = mark.unwrap_or(Mark::NONE);
    }

    /// The configuration generation hardware classified it under, if any.
    #[must_use]
    pub fn stamp(&self) -> Option<Stamp> {
        self.mark().map(Mark::stamp)
    }

    /// Stamp it as classified under `stamp` (`None`: unstamped), keeping its trap.
    pub fn set_stamp(&mut self, stamp: Option<Stamp>) {
        let trap = self.trap();
        self.set_mark(stamp.map(|stamp| Mark::new(stamp, trap)));
    }

    /// Where hardware left it to software, if past the root.
    #[must_use]
    pub fn trap(&self) -> Option<Trap> {
        self.mark().and_then(Mark::trap)
    }

    #[must_use]
    pub fn is_src_natted(&self) -> bool {
        self.flags.contains(MetaFlags::NATTED_SRC)
    }
    pub fn src_natted(&mut self, value: bool) {
        self.set_flag(MetaFlags::NATTED_SRC, value);
    }
    #[must_use]
    pub fn is_dst_natted(&self) -> bool {
        self.flags.contains(MetaFlags::NATTED_DST)
    }
    pub fn dst_natted(&mut self, value: bool) {
        self.set_flag(MetaFlags::NATTED_DST, value);
    }
    #[must_use]
    pub fn is_natted(&self) -> bool {
        self.is_src_natted() || self.is_dst_natted()
    }

    #[must_use]
    pub fn requires_masquerade(&self) -> bool {
        self.flags.contains(MetaFlags::REQ_MASQUERADE)
    }
    pub fn set_masquerade(&mut self, value: bool) {
        self.set_flag(MetaFlags::REQ_MASQUERADE, value);
    }
    #[must_use]
    pub fn requires_port_forwarding(&self) -> bool {
        self.flags.contains(MetaFlags::REQ_PORT_FORWARDING)
    }
    pub fn set_port_forwarding(&mut self, value: bool) {
        self.set_flag(MetaFlags::REQ_PORT_FORWARDING, value);
    }
    #[must_use]
    pub fn requires_static_nat_src(&self) -> bool {
        self.flags.contains(MetaFlags::REQ_STATIC_NAT_SRC)
    }
    pub fn set_static_nat_src(&mut self, value: bool) {
        self.set_flag(MetaFlags::REQ_STATIC_NAT_SRC, value);
    }
    #[must_use]
    pub fn requires_static_nat_dst(&self) -> bool {
        self.flags.contains(MetaFlags::REQ_STATIC_NAT_DST)
    }
    pub fn set_static_nat_dst(&mut self, value: bool) {
        self.set_flag(MetaFlags::REQ_STATIC_NAT_DST, value);
    }
    #[must_use]
    pub fn requires_static_nat(&self) -> bool {
        self.requires_static_nat_src() || self.requires_static_nat_dst()
    }

    /// Forget the flows of the packet and what NAT and flow tracking it requires, for a packet
    /// that a stage turns into a reply to its sender, before NAT.
    pub fn clear_flow_state(&mut self) {
        self.flow_info = None;
        self.flow_key = None;
        self.tcp_flags = None;
        self.syn_proxy = None;
        self.flags.remove(
            MetaFlags::REQ_MASQUERADE
                | MetaFlags::REQ_PORT_FORWARDING
                | MetaFlags::REQ_STATIC_NAT_SRC
                | MetaFlags::REQ_STATIC_NAT_DST
                | MetaFlags::FORCE_FLOW_TRACKING,
        );
    }

    /// Tell if the NAT or flow-tracking stages will create flows for the connection of the
    /// packet: if it requires masquerade or port forwarding, or if flow tracking is forced.
    #[must_use]
    pub fn gets_flows(&self) -> bool {
        self.requires_masquerade()
            || self.requires_port_forwarding()
            || self.has_forced_flow_tracking()
    }

    #[must_use]
    pub fn has_forced_flow_tracking(&self) -> bool {
        self.flags.contains(MetaFlags::FORCE_FLOW_TRACKING)
    }
    pub fn set_forced_flow_tracking(&mut self, value: bool) {
        self.set_flag(MetaFlags::FORCE_FLOW_TRACKING, value);
    }

    /// Mark the packet as one the NIC decapsulated from VXLAN of `vni`: the frame is the inner one.
    /// The VNI is its `src_vpcd`, as for a packet decapsulated in software; the mark costs a flag,
    /// not a field (`Packet<Mbuf>` is kept within what the compiler copies inline).
    pub fn set_nic_decap(&mut self, vni: Vni) {
        self.src_vpcd = Some(VpcDiscriminant::VNI(vni));
        self.set_flag(MetaFlags::NIC_DECAP, true);
    }

    /// The VNI of the VXLAN the NIC decapsulated, until [`Self::take_nic_decap`].
    #[must_use]
    pub fn nic_decap(&self) -> Option<Vni> {
        if !self.flags.contains(MetaFlags::NIC_DECAP) {
            return None;
        }
        self.src_vpcd.map(|VpcDiscriminant::VNI(vni)| vni)
    }

    /// [`Self::nic_decap`], and forget that the NIC decapsulated it (its `src_vpcd` stays).
    pub fn take_nic_decap(&mut self) -> Option<Vni> {
        let vni = self.nic_decap();
        self.set_flag(MetaFlags::NIC_DECAP, false);
        vni
    }

    #[must_use]
    pub fn is_overlay(&self) -> bool {
        self.flags.contains(MetaFlags::IS_OVERLAY)
    }

    pub fn set_overlay(&mut self, value: bool) {
        self.set_flag(MetaFlags::IS_OVERLAY, value);
    }

    #[must_use]
    pub fn checksum_refresh(&self) -> bool {
        self.flags.contains(MetaFlags::REFR_CHKSUM)
    }
    pub fn set_checksum_refresh(&mut self, value: bool) {
        self.set_flag(MetaFlags::REFR_CHKSUM, value);
    }

    #[must_use]
    pub fn compute_flow_flags_forward(&self) -> FlowInfoFlags {
        let mut flags = FlowInfoFlags::default();
        flags.insert(FlowInfoFlags::INITIATOR);

        if self.requires_static_nat_src() {
            flags |= FlowInfoFlags::REQ_STATIC_NAT_SRC;
        }
        if self.requires_static_nat_dst() {
            flags |= FlowInfoFlags::REQ_STATIC_NAT_DST;
        }
        flags
    }

    #[must_use]
    pub fn compute_flow_flags_reverse(&self) -> FlowInfoFlags {
        let mut flags = FlowInfoFlags::default();
        if self.requires_static_nat_src() {
            flags |= FlowInfoFlags::REQ_STATIC_NAT_DST;
        }
        if self.requires_static_nat_dst() {
            flags |= FlowInfoFlags::REQ_STATIC_NAT_SRC;
        }
        flags
    }

    #[must_use]
    pub fn need_arp_nd(&self) -> bool {
        self.flags.contains(MetaFlags::NEED_ARPND)
    }
    pub fn set_need_arp_nd(&mut self, value: bool) {
        self.set_flag(MetaFlags::NEED_ARPND, value);
    }
}
impl Drop for PacketMeta {
    fn drop(&mut self) {
        if self.done.is_none() {
            error!("Attempted to drop packet with unspecified verdict!");
        }
    }
}
