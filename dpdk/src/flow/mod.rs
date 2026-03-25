// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(clippy::all)]

//! Flow rules for DPDK
//!
//! Basically everything that starts with `rte_flow_` in DPDK.

use crate::dev::DevIndex;
use crate::queue::tx::TxQueueIndex;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::any::Any;
use core::ffi::c_void;
use core::fmt::Debug;
use core::marker::PhantomData;
use core::ptr::{self, NonNull};
use net::eth::ethtype::EthType;
use net::eth::mac::Mac;
use net::ip::dscp::Dscp;
use net::ip::ecn::Ecn;
use net::vlan::Vid;
use tracing::error;

/// Flow manager
///
/// This is a zero-sized type that is used for lifetime management and to ensure that the Eal is
/// properly initialized and cleaned up.
#[derive(Debug)]
pub struct Manager {
    phantom: PhantomData<()>,
}

impl Manager {
    /// Initialize the flow manager.
    ///
    /// <div class="warning">
    ///
    /// * This method should only be called once per [`Eal`][crate::eal::Eal] lifetime.
    ///
    /// * The return value should only _ever_ be stored in the
    ///   [`Eal`][crate::eal::Eal] singleton.
    ///
    /// </div>
    pub(crate) fn init() -> Manager {
        Manager {
            phantom: PhantomData,
        }
    }

    /// Create a flow rule on a device.
    ///
    /// # Errors
    ///
    /// Returns a [`FlowError`] if the rule could not be created.
    pub fn create(
        &self,
        port: DevIndex,
        attr: &FlowAttr,
        pattern: &[FlowMatch],
        actions: &[FlowAction],
    ) -> Result<FlowRule, FlowError> {
        FlowRule::create(port, attr, pattern, actions)
    }

    /// Validate a flow rule without installing it.
    ///
    /// # Errors
    ///
    /// Returns a [`FlowError`] if the rule is invalid.
    pub fn validate(
        &self,
        port: DevIndex,
        attr: &FlowAttr,
        pattern: &[FlowMatch],
        actions: &[FlowAction],
    ) -> Result<(), FlowError> {
        FlowRule::validate(port, attr, pattern, actions)
    }

    /// Flush (destroy) all flow rules on a device.
    ///
    /// # Errors
    ///
    /// Returns a [`FlowError`] if the flush operation failed.
    pub fn flush(&self, port: DevIndex) -> Result<(), FlowError> {
        FlowRule::flush(port)
    }
}

/// A flow rule installed in a network device (i.e., a hardware offload).
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowRule {
    port: DevIndex, // TODO: this should be a ref for safety
    flow: NonNull<dpdk_sys::rte_flow>,
    _phantom: PhantomData<dpdk_sys::rte_flow>,
}

pub const MAX_PATTERN_NUM: usize = 16;
pub const MAX_ACTION_NUM: usize = 16;

/// Flow rule attributes: priority, group, and traffic direction.
///
/// Wraps `rte_flow_attr` with a safe, Rust-idiomatic interface.
#[derive(Debug, Clone, Copy, Default)]
pub struct FlowAttr {
    /// Flow rule group (0 = root).
    pub group: u32,
    /// Rule priority within the group (lower = higher priority).
    pub priority: u32,
    /// Apply to ingress traffic.
    pub ingress: bool,
    /// Apply to egress traffic.
    pub egress: bool,
    /// Apply as a transfer rule (e.g., eswitch offload).
    pub transfer: bool,
}

impl FlowAttr {
    /// Convert to the C-level `rte_flow_attr`.
    fn as_c_attr(self) -> dpdk_sys::rte_flow_attr {
        let mut attr = dpdk_sys::rte_flow_attr {
            group: self.group,
            priority: self.priority,
            ..Default::default()
        };
        attr.set_ingress(u32::from(self.ingress));
        attr.set_egress(u32::from(self.egress));
        attr.set_transfer(u32::from(self.transfer));
        attr
    }
}

/// Errors that can occur during flow rule operations.
#[derive(Debug, thiserror::Error)]
pub enum FlowError {
    /// The DPDK flow operation returned an error.
    #[error("flow error (type {error_type}): {message}")]
    OperationFailed {
        /// The `rte_flow_error_type` value from DPDK.
        error_type: u32,
        /// Human-readable error message from DPDK.
        message: String,
    },
    /// A flow match type in the pattern is not yet supported by this wrapper.
    #[error("unsupported flow match type in pattern")]
    UnsupportedMatchType,
    /// A flow action type is not yet supported by this wrapper.
    #[error("unsupported flow action type")]
    UnsupportedActionType,
}

/// TODO: convert numbers to constant references to `rte_flow_item_type`
#[derive(Debug)]
#[repr(u32)]
pub enum MatchType {
    /// \[META\]
    ///
    /// End marker for item lists.
    /// Prevents further processing of items, thereby ending the pattern.
    /// No associated specification structure.
    End = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_END,
    /// \[META\]
    ///
    /// Used as a placeholder for convenience.
    /// It is ignored and simply discarded by PMDs.
    /// No associated specification structure.
    Void = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_VOID,
    /// \[META\]
    ///
    /// Inverted matching, i.e., process packets that do not match the pattern.
    /// No associated specification structure.
    Invert = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_INVERT,
    /// Matches any protocol in place of the current layer, a single ANY may also stand for several
    /// protocol layers.
    ///
    /// See struct `rte_flow_item_any`.
    Any = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_ANY,
    /// > **Deprecated** [`dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_PORT_REPRESENTOR`]
    ///
    /// [`dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_REPRESENTED_PORT`]
    ///
    /// \[META\]
    ///
    /// Matches traffic originating from (ingress) or going to (egress) a
    /// given DPDK port ID.
    ///
    /// See struct rte_flow_item_port_id.
    PortId = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_PORT_ID,
    /// Matches a byte string of a given length at a given offset.
    ///
    /// See struct `rte_flow_item_raw`
    Raw = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_RAW,
    /// Matches an Ethernet header.
    ///
    /// See struct `rte_flow_item_eth`.
    Eth = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_ETH,
    /// Matches an 802.1Q/ad VLAN tag.
    ///
    /// See struct `rte_flow_item_vlan`.
    Vlan = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_VLAN,
    /// Matches an IPv4 header.
    ///
    /// See struct `rte_flow_item_ipv4`.
    Ipv4 = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_IPV4,
    /// Matches an IPv6 header.
    ///
    /// See struct `rte_flow_item_ipv6`.
    Ipv6 = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_IPV6,
    /// Matches an ICMP header.
    ///
    /// See struct `rte_flow_item_icmp`.
    Icmp = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_ICMP,
    /// Matches a UDP header.
    ///
    /// See struct `rte_flow_item_udp`.
    Udp = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_UDP,
    /// Matches a TCP header.
    ///
    /// See struct `rte_flow_item_tcp`.
    Tcp = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_TCP,
    /// Matches a SCTP header.
    ///
    /// See struct `rte_flow_item_sctp`.
    Sctp = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_SCTP,
    /// Matches a VXLAN header.
    ///
    /// See struct `rte_flow_item_vxlan`.
    Vxlan = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_VXLAN,
    /// Matches a `E_TAG` header.
    ///
    /// See struct `rte_flow_item_e_tag`.
    Etag = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_E_TAG,
    /// Matches a NVGRE header.
    ///
    /// See struct `rte_flow_item_nvgre`.
    Nvgre = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_NVGRE,
    /// Matches a MPLS header.
    ///
    /// See struct `rte_flow_item_mpls`.
    Mpls = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_MPLS,
    /// Matches a GRE header.
    ///
    /// See struct `rte_flow_item_gre`.
    Gre = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_GRE,
    /// \[META\]
    ///
    /// Fuzzy pattern match, expect faster than default.
    ///
    /// This is for device that support fuzzy matching option.
    /// Usually a fuzzy matching is fast, but the cost is accuracy.
    ///
    /// See struct `rte_flow_item_fuzzy`.
    Fuzzy = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_FUZZY,
    /// Matches a GTP header.
    ///
    /// Configure flow for GTP packets.
    ///
    /// See struct `rte_flow_item_gtp`.
    Gtp = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_GTP,
    /// Matches a GTP header.
    ///
    /// Configure flow for GTP-C packets.
    ///
    /// See struct `rte_flow_item_gtp`.
    Gtpc = 21,
    /// Matches a GTP header.
    ///
    /// Configure flow for GTP-U packets.
    ///
    /// See struct `rte_flow_item_gtp`.
    Gtpu = 22,
    /// Matches a ESP header.
    ///
    /// See struct `rte_flow_item_esp`.
    Esp = 23,
    /// Matches a GENEVE header.
    ///
    /// See struct `rte_flow_item_geneve`.
    Geneve = 24,
    /// > **Deprecated** [`dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_VXLAN`]
    ///
    /// Matches a VXLAN-GPE header.
    ///
    /// See struct rte_flow_item_vxlan_gpe.
    VxlanGpe = 25,
    /// Matches an ARP header for Ethernet/IPv4.
    ///
    /// See struct `rte_flow_item_arp_eth_ipv4`.
    ArpEthIpv4 = 26,
    /// Matches the presence of any IPv6 extension header.
    ///
    /// See struct `rte_flow_item_ipv6_ext`.
    Ipv6Ext = 27,
    /// Matches any `ICMPv6` header.
    ///
    /// See struct `rte_flow_item_icmp6`.
    Icmp6 = 28,
    /// Matches an `ICMPv6` neighbor discovery solicitation.
    ///
    /// See struct `rte_flow_item_icmp6_nd_ns`.
    Icmp6NdNs = 29,
    /// Matches an `ICMPv6` neighbor discovery advertisement.
    ///
    /// See struct `rte_flow_item_icmp6_nd_na`.
    Icmp6NdNa = 30,
    /// Matches the presence of any `ICMPv6` neighbor discovery option.
    ///
    /// See struct `rte_flow_item_icmp6_nd_opt`.
    Icmp6NdOpt = 31,
    /// Matches an `ICMPv6` neighbor discovery source Ethernet link-layer
    /// address option.
    ///
    /// See struct `rte_flow_item_icmp6_nd_opt_sla_eth`.
    Icmp6NdOptSlaEth = 32,
    /// Matches an `ICMPv6` neighbor discovery target Ethernet link-layer
    /// address option.
    ///
    /// See struct `rte_flow_item_icmp6_nd_opt_tla_eth`.
    Icmp6NdOptTlaEth = 33,
    /// Matches specified mark field.
    ///
    /// See struct `rte_flow_item_mark`.
    Mark = 34,
    /// \[META\]
    ///
    /// Matches a metadata value.
    ///
    /// See struct `rte_flow_item_meta`.
    Meta = 35,
    /// Matches a GRE optional key field.
    ///
    /// The value should a big-endian 32bit integer.
    ///
    /// When this item present the K bit is implicitly matched as \"1\"
    /// in the default mask.
    ///
    /// `spec/mask` type:
    /// `rte_be32_t` *
    GreKey = 36,
    /// Matches a GTP extension header: PDU session container.
    ///
    /// Configure flow for GTP packets with extension header type 0x85.
    ///
    /// See struct `rte_flow_item_gtp_psc`.
    GtpPsc = 37,
    /// Matches a `PPPoE` header.
    ///
    /// Configure flow for `PPPoE` session packets.
    ///
    /// See struct `rte_flow_item_pppoe`.
    PppoeS = 38,
    /// Matches a `PPPoE` header.
    ///
    /// Configure flow for `PPPoE` discovery packets.
    ///
    /// See struct `rte_flow_item_pppoe`.
    PppoeD = 39,
    /// Matches a `PPPoE` optional `proto_id` field.
    ///
    /// It only applies to `PPPoE` session packets.
    ///
    /// See struct `rte_flow_item_pppoe_proto_id`.
    PppoeProtoId = 40,
    /// Matches Network service header (NSH).
    /// See struct `rte_flow_item_nsh.
    ///`
    Nsh = 41,
    /// Matches Internet Group Management Protocol (IGMP).
    /// See struct `rte_flow_item_igmp.
    ///`
    Igmp = 42,
    /// Matches IP Authentication Header (AH).
    /// See struct `rte_flow_item_ah.
    ///`
    Ah = 43,
    /// Matches a HIGIG header.
    /// see struct `rte_flow_item_higig2_hdr`.
    Higig2 = 44,
    /// \[META\]
    ///
    /// Matches a tag value.
    ///
    /// See struct `rte_flow_item_tag`.
    Tag = 45,
    /// Matches an ` L2TPv3 ` over IP header.
    ///
    /// Configure flow for `L2TPv3` over IP packets.
    ///
    /// See struct `rte_flow_item_l2tpv3oip`.
    L2tpv3oIp = 46,
    /// Matches PFCP Header.
    /// See struct `rte_flow_item_pfcp.
    ///`
    Pfcp = 47,
    /// Matches eCPRI Header.
    ///
    /// Configure flow for eCPRI over ETH or UDP packets.
    ///
    /// See struct `rte_flow_item_ecpri`.
    Ecpri = 48,
    /// Matches the presence of IPv6 fragment extension header.
    ///
    /// See struct `rte_flow_item_ipv6_frag_ext`.
    Ipv6FragExt = 49,
    /// Matches Geneve Variable Length Option
    ///
    /// See struct `rte_flow_item_geneve_opt`
    GeneveOpt = 50,
    /// \[META\]
    ///
    /// Matches on packet integrity.
    /// For some devices the application needs to enable integration checks in HW
    /// before using this item.
    ///
    /// `struct rte_flow_item_integrity`.
    Integrity = 51,
    /// \[META\]
    ///
    /// Matches conntrack state.
    ///
    /// `struct rte_flow_item_conntrack`.
    Conntrack = 52,
    /// \[META\]
    ///
    /// Matches traffic entering the embedded switch from the given ethdev.
    ///
    /// `struct rte_flow_item_ethdev`
    PortRepresentor = 53,
    /// \[META\]
    ///
    /// Matches traffic entering the embedded switch from
    /// the entity represented by the given ethdev.
    ///
    /// `struct rte_flow_item_ethdev`
    RepresentedPort = 54,
    /// Matches a configured set of fields at runtime calculated offsets
    /// over the generic network header with variable length and
    /// flexible pattern
    ///
    /// `struct rte_flow_item_flex`.
    Flex = 55,
    /// Matches `L2TPv2` Header.
    ///
    /// See struct `rte_flow_item_l2tpv2`.
    L2tpv2 = 56,
    /// Matches PPP Header.
    ///
    /// See struct `rte_flow_item_ppp`.
    Ppp = 57,
    /// Matches GRE optional fields.
    ///
    /// See struct `rte_flow_item_gre_opt`.
    GreOption = 58,
    /// Matches `MACsec` Ethernet Header.
    ///
    /// See struct `rte_flow_item_macsec`.
    MacSec = 59,
    /// Matches Meter Color Marker.
    ///
    /// See struct `rte_flow_item_meter_color`.
    MeterColor = 60,
    /// Matches the presence of IPv6 routing extension header.
    ///
    /// `struct rte_flow_item_ipv6_routing_ext`.
    Ipv6RoutingExt = 61,
    /// Matches an `ICMPv6` echo request.
    ///
    /// `struct rte_flow_item_icmp6_echo`.
    Icmp6EchoRequest = 62,
    /// Matches an `ICMPv6` echo reply.
    ///
    /// `struct rte_flow_item_icmp6_echo`.
    Icmp6EchoReply = 63,
    /// Match Quota state
    ///
    /// `struct rte_flow_item_quota`
    Quota = 64,
    /// Matches on the aggregated port of the received packet.
    /// Used in case multiple ports are aggregated to a DPDK port.
    /// First port is number 1.
    ///
    /// `struct rte_flow_item_aggr_affinity`.
    AggrAffinity = 65,
    /// Match Tx queue number.
    /// This is valid only for egress rules.
    ///
    /// `struct rte_flow_item_tx_queue`
    TxQueue = 66,
    /// Matches an `InfiniBand` base transport header in `RoCE` packet.
    ///
    /// `struct rte_flow_item_ib_bth`.
    IbBth = 67,
    /// Matches the packet type as defined in `rte_mbuf_ptype`.
    ///
    /// See struct `rte_flow_item_ptype`.
    Ptype = 68,
    /// \[META\]
    ///
    /// Matches a random value.
    ///
    /// This value is not based on the packet data/headers.
    /// The application shouldn't assume that this value is kept
    /// during the lifetime of the packet.
    ///
    /// `struct rte_flow_item_random`.
    Random = 69,
    /// Match packet with various comparison types.
    ///
    /// See struct `rte_flow_item_compare`.
    Compare = 70,
}

/// This is a wrapper around `struct rte_flow_item`.
pub enum FlowMatch {
    /// The end of a match
    End,
    /// A placeholder for convenience
    Void,
    // /// Inverted matching
    // Invert,
    /// Matches any protocol in place of the current layer
    Any,
    // /// Matches traffic originating from or going to a given DPDK port ID
    // PortId {
    //     port_id: DevIndex,
    // },
    // Raw(FlowSpec<Vec<u8>>),
    /// Matches an Ethernet header
    Eth(FlowSpec<EthHeader>),
    Vlan(FlowSpec<VlanHeader>),
    Ipv4(FlowSpec<Ipv4Header>),
    Ipv6(FlowSpec<Ipv6Header>),
    // Icmp(FlowSpec<IcmpHeader>),
    Udp(FlowSpec<UdpHeader>),
    Tcp(FlowSpec<TcpHeader>),
    // Sctp(FlowSpec<SctpHeader>),
    Vxlan(FlowSpec<VxlanHeader>),
    // Etag(FlowSpec<EtagHeader>),
    // Nvgre(FlowSpec<NvgreHeader>),
    // Mpls(FlowSpec<MplsHeader>),
    // Gre(FlowSpec<GreHeader>),
    // Fuzzy(FlowSpec<FuzzyHeader>),
    // Gtp(FlowSpec<GtpHeader>),
    // Gtpc(FlowSpec<GtpcHeader>),
    // Gtpu(FlowSpec<GtpuHeader>),
    // Esp(FlowSpec<EspHeader>),
    // Geneve(FlowSpec<GeneveHeader>),
    // VxlanGpe(FlowSpec<VxlanGpeHeader>),
    // ArpEthIpv4(FlowSpec<ArpEthIpv4Header>),
    //...
    Meta(MatchMeta),
    Tag(MatchTag),
    TxQueue(TxQueueIndex),
    // ...
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct U24(u32);

// TODO: validator for Tag bounds
/// A tag value.
///
/// This maxes out at <var>2<sup>24</sup> - 1</var>.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct MatchTag {
    pub data: U24,
}

/// A metadata value to match on.
///
/// see `struct rte_flow_item_meta`
#[derive(Debug, Clone, Copy)]
pub struct MatchMeta {
    /// The meta-data to match on
    pub data: u32,
}

#[derive(Debug)]
pub struct Vni(pub u32);

// TODO: expose remaining fields
pub struct VxlanHeader {
    pub vni: Vni,
}

pub struct UdpPort(pub u16);
pub struct TcpPort(pub u16);

// TODO: expose remaining fields
pub struct TcpHeader {
    pub src_port: TcpPort,
    pub dst_port: TcpPort,
}

// TODO: expose remaining fields
pub struct UdpHeader {
    pub src_port: UdpPort,
    pub dst_port: UdpPort,
}

// TODO: expose remaining fields
pub struct Ipv6Header {
    pub src: core::net::Ipv6Addr,
    pub dst: core::net::Ipv6Addr,
}

// TODO: expose remaining fields
pub struct Ipv4Header {
    pub src: core::net::Ipv4Addr,
    pub dst: core::net::Ipv4Addr,
}

pub struct FlowSpec<T> {
    spec: T,
    mask: Option<T>,
}

impl<T> FlowSpec<T> {
    /// Create a new flow spec with no mask
    pub fn new(spec: T) -> Self {
        Self { spec, mask: None }
    }

    /// Create a new flow spec with a mask
    pub fn new_with_mask(spec: T, mask: T) -> Self {
        Self {
            spec,
            mask: Some(mask),
        }
    }

    /// Get the spec
    pub fn spec(&self) -> &T {
        &self.spec
    }

    /// Get the mask
    pub fn mask(&self) -> Option<&T> {
        self.mask.as_ref()
    }
}

pub struct EthHeader {
    src: Mac,
    dst: Mac,
    ether_type: EthType,
}

impl EthHeader {
    /// Create a new Ethernet header specification.
    #[must_use]
    pub fn new(src: Mac, dst: Mac, ether_type: EthType) -> Self {
        Self {
            src,
            dst,
            ether_type,
        }
    }

    /// Source MAC address.
    #[must_use]
    pub fn src(&self) -> Mac {
        self.src
    }

    /// Destination MAC address.
    #[must_use]
    pub fn dst(&self) -> Mac {
        self.dst
    }

    /// Ethernet type field.
    #[must_use]
    pub fn ether_type(&self) -> EthType {
        self.ether_type
    }
}

/// TODO: forbid multicast mac src
impl From<EthHeader> for dpdk_sys::rte_flow_item_eth {
    fn from(header: EthHeader) -> Self {
        let mut eth = dpdk_sys::rte_flow_item_eth::default();
        eth.annon1.hdr = dpdk_sys::rte_ether_hdr {
            dst_addr: dpdk_sys::rte_ether_addr {
                addr_bytes: header.dst.0,
            },
            src_addr: dpdk_sys::rte_ether_addr {
                addr_bytes: header.src.0,
            },
            ether_type: hton_16(header.ether_type.as_u16()),
        };
        if header.ether_type == EthType::VLAN
            || header.ether_type == EthType::VLAN_QINQ
            || header.ether_type == EthType::VLAN_DOUBLE_TAGGED
        {
            eth.set_has_vlan(1);
        }
        eth
    }
}

pub struct VlanTci(pub u16);

pub struct VlanHeader {
    pub ether_type: EthType,
    pub tci: VlanTci,
    pub inner_ether_type: EthType,
    // TODO: figure out why DPDK lets you spec TCI twice
}

#[tracing::instrument(level = "trace")]
fn hton_16<T: Debug + Into<u16>>(x: T) -> u16 {
    u16::to_be(x.into())
}

#[repr(u32)]
pub enum FlowActionType {
    /// End marker for action lists.
    ///
    /// Prevents further processing of actions, thereby ending the list.n No associated configuration structure.
    End = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_END,
    /// Used as a placeholder for convenience.
    ///
    /// It is ignored and simply discarded by PMDs.
    /// No associated configuration structure.
    Void = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_VOID,
    /// Leaves traffic up for additional processing by subsequent flow rules;
    ///
    /// This makes a flow rule non-terminating.
    /// No associated configuration structure.
    PassThrough = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_PASSTHRU,
    /// Redirects packets to a group on the current device.
    ///
    /// See struct `struct rte_flow_action_jump`
    Jump = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_JUMP,
    /// Attaches an integer value to packets and sets `RTE_MBUF_F_RX_FDIR` and
    /// `RTE_MBUF_F_RX_FDIR_ID` mbuf flags.
    ///
    /// See struct `rte_flow_action_mark`.
    ///
    /// One should negotiate mark delivery from the NIC to the PMD.
    ///
    /// `rte_eth_rx_metadata_negotiate()`
    /// `RTE_ETH_RX_METADATA_USER_MARK`
    Mark = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_MARK,
    /// Flags packets. Similar to MARK without a specific value; only sets the `RTE_MBUF_F_RX_FDIR`
    /// mbuf flag. No associated configuration structure. One should negotiate flag delivery from
    /// the NIC to the PMD.
    ///
    /// `rte_eth_rx_metadata_negotiate()`
    /// `RTE_ETH_RX_METADATA_USER_FLAG`
    Flag = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_FLAG,
    /// Assigns packets to a given queue index. See struct `rte_flow_action_queue`.
    Queue = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_QUEUE,
    /// Drops packets.
    ///
    /// [`FlowActionType::PassThrough`] overrides this action if both are specified.
    /// No associated configuration structure.
    Drop = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_DROP,
    /// Enables counters for this flow rule. These counters can be retrieved and reset through `rte_flow_query()` or `rte_flow_action_handle_query()` if the action provided via handle, see struct `rte_flow_query_count`. See struct `rte_flow_action_count`.
    Count = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_COUNT,
    /// Similar to QUEUE, except RSS is additionally performed on packets to spread them among several queues according to the provided parameters. See struct `rte_flow_action_rss`.
    Rss = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_RSS,
    /// Traffic metering and policing (MTR). See struct `rte_flow_action_meter`. See file `rte_mtr.h` for MTR object configuration.
    Meter = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_METER,
    /// Redirects packets to security engine of current device for security processing as specified by security session. See struct `rte_flow_action_security`.
    Security = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_SECURITY,
    /// Implements `OFPAT_POP_VLAN` (\"pop the outer VLAN tag\") as defined by the `OpenFlow` Switch Specification. No associated configuration structure.
    PopVlan = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_OF_POP_VLAN,
    /// Implements `OFPAT_PUSH_VLAN` (\"push a new VLAN tag\") as defined by the `OpenFlow` Switch Specification. See struct `rte_flow_action_of_push_vlan`.
    PushVlan = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_OF_PUSH_VLAN,
    /// Implements `OFPAT_SET_VLAN_VID` (\"set the 802.1q VLAN ID\") as defined by the `OpenFlow` Switch Specification. See struct `rte_flow_action_of_set_vlan_vid`.
    SetVlanVid = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID,
    /// Implements `OFPAT_SET_LAN_PCP` (\"set the 802.1q priority\") as defined by the `OpenFlow` Switch Specification. See struct `rte_flow_action_of_set_vlan_pcp`.
    SetVlanPcp = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_PCP,
    /// Implements `OFPAT_POP_MPLS` (\"pop the outer MPLS tag\") as defined by the `OpenFlow` Switch Specification. See struct `rte_flow_action_of_pop_mpls`.
    PopMpls = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_OF_POP_MPLS,
    /// Implements `OFPAT_PUSH_MPLS` (\"push a new MPLS tag\") as defined by the `OpenFlow` Switch Specification. See struct `rte_flow_action_of_push_mpls`.
    PushMpls = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_OF_PUSH_MPLS,
    /// Encapsulate flow in VXLAN tunnel as defined in `rte_flow_action_vxlan_encap` action structure. See struct `rte_flow_action_vxlan_encap`.
    VxlanEncap = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP,
    /// Decapsulate outer most VXLAN tunnel from matched flow. If flow pattern does not define a valid VXLAN tunnel (as specified by RFC7348) then the PMD should return a `RTE_FLOW_ERROR_TYPE_ACTION` error.
    VxlanDecap = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_VXLAN_DECAP,
    /// Encapsulate flow in NVGRE tunnel defined in the `rte_flow_action_nvgre_encap` action structure. See struct `rte_flow_action_nvgre_encap`.
    NvgreEncap = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_NVGRE_ENCAP,
    /// Decapsulate outer most NVGRE tunnel from matched flow. If flow pattern does not define a valid NVGRE tunnel (as specified by RFC7637) then the PMD should return a `RTE_FLOW_ERROR_TYPE_ACTION` error.
    NvgreDecap = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_NVGRE_DECAP,
    /// Add outer header whose template is provided in its data buffer See struct `rte_flow_action_raw_encap`.
    RawEncap = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
    /// Remove outer header whose template is provided in its data buffer. See struct `rte_flow_action_raw_decap`
    RawDecap = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_RAW_DECAP,
    /// Swap the source and destination MAC addresses in the outermost Ethernet header. If flow pattern does not define a valid `RTE_FLOW_ITEM_TYPE_ETH`, then the PMD should return a `RTE_FLOW_ERROR_TYPE_ACTION` error. No associated configuration structure.
    MacSwap = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_MAC_SWAP,
    /// Report as aged flow if timeout passed without any matching on the flow. See struct `rte_flow_action_age`. See function `rte_flow_get_q_aged_flows` See function `rte_flow_get_aged_flows` see enum `RTE_ETH_EVENT_FLOW_AGED` See struct `rte_flow_query_age` See struct `rte_flow_update_age`
    Age = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_AGE,
    /// The matching packets will be duplicated with specified ratio and applied with own set of actions with a fate action. See struct `rte_flow_action_sample`.
    Sample = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_SAMPLE,
    /// Modify a packet header field, tag, mark or metadata. Allow the modification of an arbitrary header field via set, add and sub operations or copying its content into tag, meta or mark for future processing. See struct `rte_flow_action_modify_field`.
    ModifyField = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_MODIFY_FIELD,
    /// An action handle is referenced in a rule through an indirect action. The same action handle may be used in multiple rules for the same or different ethdev ports.
    Indirect = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_INDIRECT,
    /// Color the packet to reflect the meter color result. Set the meter color in the mbuf to the selected color. See struct `rte_flow_action_meter_color`.
    MeterColor = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_METER_COLOR,
    /// At embedded switch level, sends matching traffic to the given ethdev.
    ///
    /// `struct rte_flow_action_ethdev`
    PortRepresentor = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_PORT_REPRESENTOR,
    /// At embedded switch level, send matching traffic to the entity represented by the given ethdev.
    ///
    /// `struct rte_flow_action_ethdev`
    RepresentedPort = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT,
    /// Traffic metering and marking (MTR).
    ///
    /// `struct rte_flow_action_meter_mark`
    ///
    /// See file `rte_mtr.h` for MTR profile object configuration.
    MeterMark = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_METER_MARK,
    /// Send packets to the kernel, without going to userspace at all. The packets will be received by the kernel driver sharing the same device as the DPDK port on which this action is configured. This action mostly suits bifurcated driver model. No associated configuration structure.
    SendToKernel = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_SEND_TO_KERNEL,
    /// Apply the quota verdict (PASS or BLOCK) to a flow.
    ///
    /// `struct rte_flow_action_quota`
    /// `struct rte_flow_query_quota`
    /// `struct rte_flow_update_quota`
    Quota = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_QUOTA,
    /// Action handle to reference flow actions list.
    ///
    /// `struct rte_flow_action_indirect_list`
    IndirectList = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_INDIRECT_LIST,
    /// NAT64 translation of IPv4/IPv6 headers.
    ///
    /// `struct rte_flow_action_nat64`
    Nat64 = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_NAT64,
    // /// > **Deprecated** [`RTE_FLOW_ACTION_TYPE_PORT_REPRESENTOR`] [`RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT`] Directs matching traffic to the physical function (PF) of the current device. No associated configuration structure.
    // RTE_FLOW_ACTION_TYPE_PF,
    // /// > **Deprecated** [`RTE_FLOW_ACTION_TYPE_PORT_REPRESENTOR`] [`RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT`] Directs matching traffic to a given virtual function of the current device. See struct rte_flow_action_vf.
    // RTE_FLOW_ACTION_TYPE_VF,
    // /// > **Deprecated** [`RTE_FLOW_ACTION_TYPE_PORT_REPRESENTOR`] [`RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT`] Directs matching traffic to a given DPDK port ID. See struct rte_flow_action_port_id.
    // RTE_FLOW_ACTION_TYPE_PORT_ID,
    // /// This is a legacy action. [`RTE_FLOW_ACTION_TYPE_MODIFY_FIELD`] Implements OFPAT_DEC_NW_TTL (\"decrement IP TTL\") as defined by the OpenFlow Switch Specification. No associated configuration structure.
    // DecNwTtl = rte_flow_action_type::RTE_FLOW_ACTION_TYPE_OF_DEC_NW_TTL,
    // /// This is a legacy action. [`RTE_FLOW_ACTION_TYPE_MODIFY_FIELD`] Modify IPv4 source address in the outermost IPv4 header. If flow pattern does not define a valid RTE_FLOW_ITEM_TYPE_IPV4, then the PMD should return a RTE_FLOW_ERROR_TYPE_ACTION error. See struct rte_flow_action_set_ipv4.
    // SetIpv4Src = rte_flow_action_type::RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC,
    // /// This is a legacy action. [`RTE_FLOW_ACTION_TYPE_MODIFY_FIELD`] Modify IPv4 destination address in the outermost IPv4 header. If flow pattern does not define a valid RTE_FLOW_ITEM_TYPE_IPV4, then the PMD should return a RTE_FLOW_ERROR_TYPE_ACTION error. See struct rte_flow_action_set_ipv4.
    // SetIpv4Dst = rte_flow_action_type::RTE_FLOW_ACTION_TYPE_SET_IPV4_DST,
    // /// This is a legacy action. [`RTE_FLOW_ACTION_TYPE_MODIFY_FIELD`] Modify IPv6 source address in the outermost IPv6 header. If flow pattern does not define a valid RTE_FLOW_ITEM_TYPE_IPV6, then the PMD should return a RTE_FLOW_ERROR_TYPE_ACTION error. See struct rte_flow_action_set_ipv6.
    // SetIpv6Src = rte_flow_action_type::RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC,
    // /// This is a legacy action. [`RTE_FLOW_ACTION_TYPE_MODIFY_FIELD`] Modify IPv6 destination address in the outermost IPv6 header. If flow pattern does not define a valid RTE_FLOW_ITEM_TYPE_IPV6, then the PMD should return a RTE_FLOW_ERROR_TYPE_ACTION error. See struct rte_flow_action_set_ipv6.
    // SetIpv6Dst = rte_flow_action_type::RTE_FLOW_ACTION_TYPE_SET_IPV6_DST,
    // /// This is a legacy action. [`RTE_FLOW_ACTION_TYPE_MODIFY_FIELD`] Modify source port number in the outermost TCP/UDP header. If flow pattern does not define a valid RTE_FLOW_ITEM_TYPE_TCP or RTE_FLOW_ITEM_TYPE_UDP, then the PMD should return a RTE_FLOW_ERROR_TYPE_ACTION error. See struct rte_flow_action_set_tp.
    // SetL4Src = rte_flow_action_type::RTE_FLOW_ACTION_TYPE_SET_TP_SRC,
    // /// This is a legacy action. [`RTE_FLOW_ACTION_TYPE_MODIFY_FIELD`] Modify destination port number in the outermost TCP/UDP header. If flow pattern does not define a valid RTE_FLOW_ITEM_TYPE_TCP or RTE_FLOW_ITEM_TYPE_UDP, then the PMD should return a RTE_FLOW_ERROR_TYPE_ACTION error. See struct rte_flow_action_set_tp.
    // SetL4Dst = rte_flow_action_type::RTE_FLOW_ACTION_TYPE_SET_TP_DST,
    // /// This is a legacy action. [`RTE_FLOW_ACTION_TYPE_MODIFY_FIELD`] Decrease TTL value directly No associated configuration structure.
    // DecTtl = rte_flow_action_type::RTE_FLOW_ACTION_TYPE_DEC_TTL,
    // /// This is a legacy action. [`RTE_FLOW_ACTION_TYPE_MODIFY_FIELD`] Set TTL value See struct rte_flow_action_set_ttl
    // RTE_FLOW_ACTION_TYPE_SET_TTL,
    // /// This is a legacy action. [`RTE_FLOW_ACTION_TYPE_MODIFY_FIELD`] Set source MAC address from matched flow. If flow pattern does not define a valid RTE_FLOW_ITEM_TYPE_ETH, the PMD should return a RTE_FLOW_ERROR_TYPE_ACTION error. See struct rte_flow_action_set_mac.
    // RTE_FLOW_ACTION_TYPE_SET_MAC_SRC,
    // /// This is a legacy action. [`RTE_FLOW_ACTION_TYPE_MODIFY_FIELD`] Set destination MAC address from matched flow. If flow pattern does not define a valid RTE_FLOW_ITEM_TYPE_ETH, the PMD should return a RTE_FLOW_ERROR_TYPE_ACTION error. See struct rte_flow_action_set_mac.
    // RTE_FLOW_ACTION_TYPE_SET_MAC_DST,
    // /// This is a legacy action. [`RTE_FLOW_ACTION_TYPE_MODIFY_FIELD`] Increase sequence number in the outermost TCP header. Action configuration specifies the value to increase TCP sequence number as a big-endian 32 bit integer. `conf` type: rte_be32_t * Using this action on non-matching traffic will result in undefined behavior.
    // RTE_FLOW_ACTION_TYPE_INC_TCP_SEQ,
    // /// This is a legacy action. [`RTE_FLOW_ACTION_TYPE_MODIFY_FIELD`] Decrease sequence number in the outermost TCP header. Action configuration specifies the value to decrease TCP sequence number as a big-endian 32 bit integer. `conf` type: rte_be32_t * Using this action on non-matching traffic will result in undefined behavior.
    // RTE_FLOW_ACTION_TYPE_DEC_TCP_SEQ,
    // /// This is a legacy action. [`RTE_FLOW_ACTION_TYPE_MODIFY_FIELD`] Increase acknowledgment number in the outermost TCP header. Action configuration specifies the value to increase TCP acknowledgment number as a big-endian 32 bit integer. `conf` type: rte_be32_t * Using this action on non-matching traffic will result in undefined behavior.
    // RTE_FLOW_ACTION_TYPE_INC_TCP_ACK,
    // /// This is a legacy action. [`RTE_FLOW_ACTION_TYPE_MODIFY_FIELD`] Decrease acknowledgment number in the outermost TCP header. Action configuration specifies the value to decrease TCP acknowledgment number as a big-endian 32 bit integer. `conf` type: rte_be32_t * Using this action on non-matching traffic will result in undefined behavior.
    // RTE_FLOW_ACTION_TYPE_DEC_TCP_ACK,
    // /// This is a legacy action. [`RTE_FLOW_ACTION_TYPE_MODIFY_FIELD`] Set Tag. Tag is for internal flow usage only and is not delivered to the application. See struct rte_flow_action_set_tag.
    // RTE_FLOW_ACTION_TYPE_SET_TAG,
    // /// This is a legacy action. [`RTE_FLOW_ACTION_TYPE_MODIFY_FIELD`] Set metadata on ingress or egress path. See struct rte_flow_action_set_meta.
    // RTE_FLOW_ACTION_TYPE_SET_META,
    // /// This is a legacy action. [`RTE_FLOW_ACTION_TYPE_MODIFY_FIELD`] Modify IPv4 DSCP in the outermost IP header. If flow pattern does not define a valid RTE_FLOW_ITEM_TYPE_IPV4, then the PMD should return a RTE_FLOW_ERROR_TYPE_ACTION error. See struct rte_flow_action_set_dscp.
    // RTE_FLOW_ACTION_TYPE_SET_IPV4_DSCP,
    // /// This is a legacy action. [`RTE_FLOW_ACTION_TYPE_MODIFY_FIELD`] Modify IPv6 DSCP in the outermost IP header. If flow pattern does not define a valid RTE_FLOW_ITEM_TYPE_IPV6, then the PMD should return a RTE_FLOW_ERROR_TYPE_ACTION error. See struct rte_flow_action_set_dscp.
    // RTE_FLOW_ACTION_TYPE_SET_IPV6_DSCP,
    // /// > **Deprecated** [`RTE_FLOW_ACTION_TYPE_INDIRECT`] Describe action shared across multiple flow rules. Allow multiple rules reference the same action by handle (see struct rte_flow_shared_action).
    // Shared = rte_flow_action_type::RTE_FLOW_ACTION_TYPE_SHARED,
    // /// [META] Enable tracking a TCP connection state. [`struct`] rte_flow_action_conntrack.
    // Conntrack = rte_flow_action_type::RTE_FLOW_ACTION_TYPE_CONNTRACK,
    // /// Skip congestion management configuration. Using rte_eth_cman_config_set(), the application can configure ethdev Rx queue's congestion mechanism. This flow action allows to skip the congestion configuration applied to the given ethdev Rx queue.
    // RTE_FLOW_ACTION_TYPE_SKIP_CMAN,
    // /// RTE_FLOW_ACTION_TYPE_IPV6_EXT_PUSH Push IPv6 extension into IPv6 packet. [`struct`] rte_flow_action_ipv6_ext_push.
    // RTE_FLOW_ACTION_TYPE_IPV6_EXT_PUSH,
    // /// RTE_FLOW_ACTION_TYPE_IPV6_EXT_REMOVE Remove IPv6 extension from IPv6 packet whose type is provided in its configuration buffer. [`struct`] rte_flow_action_ipv6_ext_remove.
    // RTE_FLOW_ACTION_TYPE_IPV6_EXT_REMOVE,
    // /// Program action. These actions are defined by the program currently loaded on the device. For example, these actions are applicable to devices that can be programmed through the P4 language. [`struct`] rte_flow_action_prog.
    // RTE_FLOW_ACTION_TYPE_PROG,
}

pub struct FlowGroup(pub u32);
pub struct FlowMark(pub u32);
pub struct CounterId(pub u32);
pub struct MeterId(pub u32);

pub enum FlowAction {
    End,
    Void,
    PassThrough,
    Jump(FlowGroup),
    Mark(FlowMark),
    Flag,
    Queue(TxQueueIndex),
    Drop,
    Count(CounterId),
    // Rss  // TODO: expose RSS as an action
    Meter {
        id: MeterId,
    },
    // Security  // TODO: expose security as an action
    PopVlan,
    PushVlan {
        ethertype: EthType,
    },
    SetVlanVid {
        vlan_id: Vid,
    },
    // SetVlanPcp { // TODO: expose PCP as an action
    //     pcp: net::vlan::Pcp, // TODO: import Pcp when exposed
    // },
    // PopMpls // TODO: expose MPLS as an action
    // PushMpls // TODO: expose MPLS as an action
    // VxlanEncap  // TODO: expose VXLAN as an action
    // VxlanDecap  // TODO: expose VXLAN as an action
    RawEncap {
        data: Vec<u8>,
        mask: Option<Vec<u8>>,
    },
    RawDecap {
        data: Vec<u8>,
    },
    MacSwap,
    Age {
        timeout: u32,
        // TODO: what is "context"?
    },
    // Sample, // TODO: expose sampling as an action
    // TODO: this is much more powerful than described here
    ModifyField(SetFlowField),
    // Indirect {
    //     handle: FlowActionHandle,
    // },
    // MeterColor,
    // PortRepresentor,
    // RepresentedPort,
    // MeterMark,
    // SendToKernel,
    // Quota,
    // IndirectList,
    // Nat64,
}

/// Modify a field
#[repr(u32)]
pub enum FieldModificationOperation {
    /// Set a field
    Set = dpdk_sys::rte_flow_modify_op::RTE_FLOW_MODIFY_SET,
    /// Add to a field
    Add = dpdk_sys::rte_flow_modify_op::RTE_FLOW_MODIFY_ADD,
    /// Subtract from a field
    Subtract = dpdk_sys::rte_flow_modify_op::RTE_FLOW_MODIFY_SUB,
}

/// A wrapper around a `rte_flow_action_modify_field` that specifies the
/// field to modify and its new value.
#[repr(u32)]
pub enum FlowFieldId {
    /// Start with a packet.
    Start = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_START,
    /// Destination MAC Address.
    MacDst = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_MAC_DST,
    /// Source MAC Address.
    MacSrc = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_MAC_SRC,
    /// VLAN Tag Identifier.
    VlanType = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_VLAN_TYPE,
    /// VLAN Identifier.
    VlanVid = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_VLAN_ID,
    /// EtherType.
    EtherType = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_MAC_TYPE,
    /// IPv4 DSCP.
    Ipv4Dscp = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_IPV4_DSCP,
    /// IPv4 Time To Live.
    Ipv4Ttl = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_IPV4_TTL,
    /// IPv4 Source Address.
    Ipv4Src = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_IPV4_SRC,
    /// IPv4 Destination Address.
    Ipv4Dst = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_IPV4_DST,
    /// IPv6 DSCP.
    Ipv6Dscp = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_IPV6_DSCP,
    /// IPv6 Hop Limit.
    Ipv6HopLimit = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_IPV6_HOPLIMIT,
    /// IPv6 Source Address.
    Ipv6Src = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_IPV6_SRC,
    /// IPv6 Destination Address.
    Ipv6Dst = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_IPV6_DST,
    /// TCP Source Port Number.
    TcpPortSrc = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_TCP_PORT_SRC,
    /// TCP Destination Port Number.
    TcpPortDst = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_TCP_PORT_DST,
    /// TCP Sequence Number.
    TcpSeqNum = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_TCP_SEQ_NUM,
    /// TCP Acknowledgment Number.
    TcpAckNum = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_TCP_ACK_NUM,
    /// TCP Flags.
    TcpFlags = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_TCP_FLAGS,
    /// UDP Source Port Number.
    UdpPortSrc = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_UDP_PORT_SRC,
    /// UDP Destination Port Number.
    UdpPortDst = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_UDP_PORT_DST,
    /// VXLAN Network Identifier.
    VxlanVni = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_VXLAN_VNI,
    /// GENEVE Network Identifier.
    GeneveVni = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_GENEVE_VNI,
    /// GTP Tunnel Endpoint Identifier.
    GtpTeid = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_GTP_TEID,
    /// Tag value.
    Tag = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_TAG,
    /// Mark value.
    Mark = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_MARK,
    /// Metadata value.
    Meta = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_META,
    /// Memory pointer.
    Pointer = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_POINTER,
    /// Immediate value.
    Value = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_VALUE,
    /// IPv4 ECN.
    Ipv4Ecn = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_IPV4_ECN,
    /// IPv6 ECN.
    Ipv6Ecn = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_IPV6_ECN,
    /// GTP QFI.
    GtpQfi = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_GTP_PSC_QFI,
    /// Meter color marker.
    MeterColor = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_METER_COLOR,
    /// IPv6 next header.
    Ipv6NextHeader = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_IPV6_PROTO,
    /// Flex item.
    FlexItem = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_FLEX_ITEM,
    /// Hash result.
    HashResult = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_HASH_RESULT,
    /// GENEVE option type.
    GeneveOptType = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_GENEVE_OPT_TYPE,
    /// GENEVE option class.
    GeneveOptClass = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_GENEVE_OPT_CLASS,
    /// GENEVE option data.
    GeneveOptData = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_GENEVE_OPT_DATA,
    /// MPLS header.
    MplsHeader = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_MPLS,
    /// TCP data offset.
    TcpDataOffset = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_TCP_DATA_OFFSET,
    /// IPv4 IHL.
    Ipv4Ihl = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_IPV4_IHL,
    /// IPv4 total length.
    Ipv4TotalLength = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_IPV4_TOTAL_LEN,
    /// IPv6 payload length.
    Ipv6PayloadLength = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_IPV6_PAYLOAD_LEN,
    /// IPv4 next protocol.
    Ipv4NextProtocol = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_IPV4_PROTO,
    /// IPv6 flow label.
    Ipv6FlowLabel = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_IPV6_FLOW_LABEL,
    /// IPv6 traffic class.
    Ipv6TrafficClass = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_IPV6_TRAFFIC_CLASS,
    /// ESP SPI.
    EspSpi = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_ESP_SPI,
    /// ESP Sequence Number.
    EspSeqNum = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_ESP_SEQ_NUM,
    /// ESP next protocol value.
    EspProto = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_ESP_PROTO,
    /// Random value.
    Random = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_RANDOM,
    /// VXLAN last reserved byte.
    VxlanLastReserved = dpdk_sys::rte_flow_field_id::RTE_FLOW_FIELD_VXLAN_LAST_RSVD,
}

/// A wrapper around a `rte_flow_action_modify_field` that specifies the
/// field to modify and its new value.
#[derive(Debug, Clone, Copy)]
pub enum SetFlowField {
    /// Dest mac
    MacDst(Mac),
    /// Source mac
    MacSrc(Mac),
    /// Vlan ethertype
    VlanType(EthType),
    /// Vlan VID
    VlanVid(Vid),
    /// Ethertype
    EtherType(EthType),
    /// IPv4 DSCP
    Ipv4Dscp(Dscp),
    /// IPv4 TTL
    Ipv4Ttl(u8),
    /// Ipv4 source
    Ipv4Src(core::net::Ipv4Addr),
    /// Ipv4 dest
    Ipv4Dst(core::net::Ipv4Addr),
    /// Ipv6 DSCP
    Ipv6Dscp(Dscp),
    /// Ipv6 hop limit (ttl)
    Ipv6HopLimit(u8),
    /// Ipv6 source
    Ipv6Src(core::net::Ipv6Addr),
    /// Ipv6 dest
    Ipv6Dst(core::net::Ipv6Addr),
    /// TCP source port
    TcpPortSrc(u16),
    /// TCP dest port
    TcpPortDst(u16),
    /// TCP seq number
    TcpSeqNum(u32),
    /// TCP ack num
    TcpAckNum(u32),
    /// TCP flags
    TcpFlags(u16),
    /// UDP source port
    UdpPortSrc(u16),
    /// UDP dest port
    UdpPortDst(u16),
    /// VXLAN vni
    VxlanVni(net::vxlan::Vni),
    /// Tag
    Tag(MatchTag),
    /// Metadata
    Meta(MatchMeta),
    /// Ipv4 ECN
    IpV4Ecn(Ecn),
    /// IPv6 ECN
    IpV6Ecn(Ecn),
}

/// A wrapper around a `rte_flow_action_modify_field` that specifies the
/// field to modify and its new value.
pub struct SetFieldAction {
    pub rule: SetFlowField,
    pub conf: dpdk_sys::rte_flow_action_modify_field,
}

impl SetFlowField {
    /// Converts the `SetFlowField` into a `SetFieldAction`.
    ///
    /// Each variant packs its value into a 16-byte immediate-value buffer
    /// and pairs it with the corresponding [`FlowFieldId`] destination.
    #[must_use]
    pub fn to_flow_rule(&self) -> SetFieldAction {
        /// Construct a [`dpdk_sys::rte_flow_action_modify_field`] that sets
        /// `dst_field` to the immediate value stored in `value`.
        ///
        /// `width` is the field width in bytes, following the convention
        /// established by the original `MacDst` implementation.
        fn set_field(
            dst_field: FlowFieldId,
            value: [u8; 16],
            width: u32,
        ) -> dpdk_sys::rte_flow_action_modify_field {
            dpdk_sys::rte_flow_action_modify_field {
                operation: FieldModificationOperation::Set as u32,
                src: dpdk_sys::rte_flow_field_data {
                    field: FlowFieldId::Value as u32,
                    annon1: dpdk_sys::rte_flow_field_data__bindgen_ty_1 { value },
                },
                dst: dpdk_sys::rte_flow_field_data {
                    field: dst_field as u32,
                    annon1: dpdk_sys::rte_flow_field_data__bindgen_ty_1::default(),
                },
                width,
            }
        }

        /// Pack a byte slice into the leading positions of a `[u8; 16]`
        /// buffer, zero-filling the remainder.
        fn pack(bytes: &[u8]) -> [u8; 16] {
            let mut buf = [0u8; 16];
            buf[..bytes.len()].copy_from_slice(bytes);
            buf
        }

        let conf = match self {
            SetFlowField::MacDst(mac) => {
                set_field(FlowFieldId::MacDst, pack(&mac.0), size_of::<Mac>() as u32)
            }
            SetFlowField::MacSrc(mac) => {
                set_field(FlowFieldId::MacSrc, pack(&mac.0), size_of::<Mac>() as u32)
            }
            SetFlowField::VlanType(et) => {
                set_field(FlowFieldId::VlanType, pack(&et.as_u16().to_be_bytes()), size_of::<u16>() as u32)
            }
            SetFlowField::VlanVid(vid) => {
                let raw: u16 = (*vid).into();
                set_field(FlowFieldId::VlanVid, pack(&raw.to_be_bytes()), size_of::<u16>() as u32)
            }
            SetFlowField::EtherType(et) => {
                set_field(FlowFieldId::EtherType, pack(&et.as_u16().to_be_bytes()), size_of::<u16>() as u32)
            }
            SetFlowField::Ipv4Dscp(dscp) => {
                set_field(FlowFieldId::Ipv4Dscp, pack(&[dscp.value()]), size_of::<u8>() as u32)
            }
            SetFlowField::Ipv4Ttl(ttl) => {
                set_field(FlowFieldId::Ipv4Ttl, pack(&[*ttl]), size_of::<u8>() as u32)
            }
            SetFlowField::Ipv4Src(addr) => {
                set_field(FlowFieldId::Ipv4Src, pack(&addr.octets()), 4)
            }
            SetFlowField::Ipv4Dst(addr) => {
                set_field(FlowFieldId::Ipv4Dst, pack(&addr.octets()), 4)
            }
            SetFlowField::Ipv6Dscp(dscp) => {
                set_field(FlowFieldId::Ipv6Dscp, pack(&[dscp.value()]), size_of::<u8>() as u32)
            }
            SetFlowField::Ipv6HopLimit(hl) => {
                set_field(FlowFieldId::Ipv6HopLimit, pack(&[*hl]), size_of::<u8>() as u32)
            }
            SetFlowField::Ipv6Src(addr) => {
                // IPv6 address is exactly 16 bytes — fills the entire value buffer.
                set_field(FlowFieldId::Ipv6Src, addr.octets(), 16)
            }
            SetFlowField::Ipv6Dst(addr) => {
                set_field(FlowFieldId::Ipv6Dst, addr.octets(), 16)
            }
            SetFlowField::TcpPortSrc(port) => {
                set_field(FlowFieldId::TcpPortSrc, pack(&port.to_be_bytes()), size_of::<u16>() as u32)
            }
            SetFlowField::TcpPortDst(port) => {
                set_field(FlowFieldId::TcpPortDst, pack(&port.to_be_bytes()), size_of::<u16>() as u32)
            }
            SetFlowField::TcpSeqNum(seq) => {
                set_field(FlowFieldId::TcpSeqNum, pack(&seq.to_be_bytes()), size_of::<u32>() as u32)
            }
            SetFlowField::TcpAckNum(ack) => {
                set_field(FlowFieldId::TcpAckNum, pack(&ack.to_be_bytes()), size_of::<u32>() as u32)
            }
            SetFlowField::TcpFlags(flags) => {
                set_field(FlowFieldId::TcpFlags, pack(&flags.to_be_bytes()), size_of::<u16>() as u32)
            }
            SetFlowField::UdpPortSrc(port) => {
                set_field(FlowFieldId::UdpPortSrc, pack(&port.to_be_bytes()), size_of::<u16>() as u32)
            }
            SetFlowField::UdpPortDst(port) => {
                set_field(FlowFieldId::UdpPortDst, pack(&port.to_be_bytes()), size_of::<u16>() as u32)
            }
            SetFlowField::VxlanVni(vni) => {
                // VNI is a 24-bit field.  Extract the lower 3 bytes from the
                // big-endian representation of the underlying u32.
                let raw: u32 = (*vni).into();
                let be = raw.to_be_bytes();
                set_field(FlowFieldId::VxlanVni, pack(&be[1..]), 3)
            }
            SetFlowField::Tag(tag) => {
                set_field(FlowFieldId::Tag, pack(&tag.data.0.to_be_bytes()), size_of::<u32>() as u32)
            }
            SetFlowField::Meta(meta) => {
                set_field(FlowFieldId::Meta, pack(&meta.data.to_be_bytes()), size_of::<u32>() as u32)
            }
            SetFlowField::IpV4Ecn(ecn) => {
                set_field(FlowFieldId::Ipv4Ecn, pack(&[ecn.value()]), size_of::<u8>() as u32)
            }
            SetFlowField::IpV6Ecn(ecn) => {
                set_field(FlowFieldId::Ipv6Ecn, pack(&[ecn.value()]), size_of::<u8>() as u32)
            }
        };
        SetFieldAction { rule: *self, conf }
    }
}

/// should remain private
trait Sealed {}
impl Sealed for u8 {}
impl Sealed for u16 {}
impl Sealed for u32 {}
impl Sealed for u64 {}
impl Sealed for u128 {}

/// A wrapper around unsigned numbers that specifies they are in big endian order.
#[repr(transparent)]
pub struct BigEndian<T>(T)
where
    T: UnsignedNum;

/// An unsigned number (e.g. u8 or u32)
#[allow(private_bounds)]
pub trait UnsignedNum: Sealed {}

impl<T> UnsignedNum for T where T: Sealed {}

impl<T> BigEndian<T>
where
    T: UnsignedNum,
{
    /// Get the raw value in `BigEndian` form
    pub fn to_raw(self) -> T {
        self.0
    }
}

impl From<u8> for BigEndian<u8> {
    fn from(x: u8) -> Self {
        BigEndian(x.to_be()) // no-op
    }
}

impl From<u16> for BigEndian<u16> {
    fn from(x: u16) -> Self {
        BigEndian(x.to_be())
    }
}

impl From<u32> for BigEndian<u32> {
    fn from(x: u32) -> Self {
        BigEndian(x.to_be())
    }
}

impl From<u64> for BigEndian<u64> {
    fn from(x: u64) -> Self {
        BigEndian(x.to_be())
    }
}

impl From<u128> for BigEndian<u128> {
    fn from(x: u128) -> Self {
        BigEndian(x.to_be())
    }
}

// ============================================================
// Flow Rule Operations
// ============================================================

/// Extract a [`FlowError`] from a DPDK `rte_flow_error` struct.
fn extract_flow_error(error: &dpdk_sys::rte_flow_error) -> FlowError {
    let message = if error.message.is_null() {
        String::from("unknown flow error")
    } else {
        // SAFETY: DPDK guarantees `message` is a valid C string when non-null.
        unsafe { core::ffi::CStr::from_ptr(error.message) }
            .to_string_lossy()
            .into_owned()
    };
    FlowError::OperationFailed {
        error_type: error.type_,
        message,
    }
}

// -- Backing-storage helpers --

/// Allocate `val` on the heap, returning a raw `*const c_void` pointer
/// alongside an owning [`Box`] erased to `dyn Any` for heterogeneous
/// storage.
///
/// The caller **must** keep the returned `Box` alive for as long as the
/// pointer is in use.
fn heap_ptr<T: 'static>(val: T) -> (*const c_void, Box<dyn Any>) {
    let b = Box::new(val);
    let ptr = &*b as *const T as *const c_void;
    (ptr, b)
}

/// Backing storage for a C-level flow pattern item array.
///
/// The `items` array contains `rte_flow_item` structs whose `spec` and
/// `mask` pointers borrow from the heap allocations held in `_storage`.
/// This struct **must** outlive any use of [`Self::as_ptr`].
struct CFlowPattern {
    items: Vec<dpdk_sys::rte_flow_item>,
    _storage: Vec<Box<dyn Any>>,
}

impl CFlowPattern {
    /// Pointer to the first element, suitable for passing to DPDK.
    fn as_ptr(&self) -> *const dpdk_sys::rte_flow_item {
        self.items.as_ptr()
    }
}

/// Backing storage for a C-level flow action array.
///
/// See [`CFlowPattern`] for the ownership / lifetime contract.
struct CFlowActions {
    actions: Vec<dpdk_sys::rte_flow_action>,
    _storage: Vec<Box<dyn Any>>,
}

impl CFlowActions {
    /// Pointer to the first element, suitable for passing to DPDK.
    fn as_ptr(&self) -> *const dpdk_sys::rte_flow_action {
        self.actions.as_ptr()
    }
}

// -- Header conversion helpers --

/// Convert an [`EthHeader`] reference to a C `rte_flow_item_eth`.
///
/// This duplicates the logic in `From<EthHeader> for rte_flow_item_eth`
/// but operates on a borrow (the `From` impl consumes by value).
fn eth_to_c(header: &EthHeader) -> dpdk_sys::rte_flow_item_eth {
    let mut eth = dpdk_sys::rte_flow_item_eth::default();
    eth.annon1.hdr = dpdk_sys::rte_ether_hdr {
        dst_addr: dpdk_sys::rte_ether_addr {
            addr_bytes: header.dst.0,
        },
        src_addr: dpdk_sys::rte_ether_addr {
            addr_bytes: header.src.0,
        },
        ether_type: hton_16(header.ether_type.as_u16()),
    };
    if header.ether_type == EthType::VLAN
        || header.ether_type == EthType::VLAN_QINQ
        || header.ether_type == EthType::VLAN_DOUBLE_TAGGED
    {
        eth.set_has_vlan(1);
    }
    eth
}

// -- Pattern builder --

/// Build a C-level flow pattern from a slice of [`FlowMatch`] items.
///
/// # Errors
///
/// Returns [`FlowError::UnsupportedMatchType`] if a match variant lacks
/// a C-level conversion.
fn build_c_pattern(pattern: &[FlowMatch]) -> Result<CFlowPattern, FlowError> {
    use dpdk_sys::rte_flow_item_type::*;

    let mut items: Vec<dpdk_sys::rte_flow_item> = Vec::with_capacity(pattern.len() + 1);
    let mut storage: Vec<Box<dyn Any>> = Vec::with_capacity(pattern.len() * 2);

    /// Push a spec (and optional mask) into `storage`, returning their
    /// raw pointers for embedding into an `rte_flow_item`.
    fn push_spec_mask<T: 'static + Default>(
        storage: &mut Vec<Box<dyn Any>>,
        spec: T,
        mask: Option<T>,
    ) -> (*const c_void, *const c_void) {
        let (spec_ptr, spec_box) = heap_ptr(spec);
        storage.push(spec_box);
        let mask_ptr = match mask {
            Some(m) => {
                let (p, b) = heap_ptr(m);
                storage.push(b);
                p
            }
            None => ptr::null(),
        };
        (spec_ptr, mask_ptr)
    }

    for m in pattern {
        match m {
            FlowMatch::End => {
                items.push(dpdk_sys::rte_flow_item {
                    type_: RTE_FLOW_ITEM_TYPE_END,
                    spec: ptr::null(),
                    last: ptr::null(),
                    mask: ptr::null(),
                });
            }
            FlowMatch::Void => {
                items.push(dpdk_sys::rte_flow_item {
                    type_: RTE_FLOW_ITEM_TYPE_VOID,
                    spec: ptr::null(),
                    last: ptr::null(),
                    mask: ptr::null(),
                });
            }
            FlowMatch::Any => {
                items.push(dpdk_sys::rte_flow_item {
                    type_: RTE_FLOW_ITEM_TYPE_ANY,
                    spec: ptr::null(),
                    last: ptr::null(),
                    mask: ptr::null(),
                });
            }
            FlowMatch::Eth(fs) => {
                let spec_c = eth_to_c(fs.spec());
                let mask_c = fs.mask().map(eth_to_c);
                let (spec_ptr, mask_ptr) = push_spec_mask(&mut storage, spec_c, mask_c);
                items.push(dpdk_sys::rte_flow_item {
                    type_: RTE_FLOW_ITEM_TYPE_ETH,
                    spec: spec_ptr,
                    last: ptr::null(),
                    mask: mask_ptr,
                });
            }
            FlowMatch::Ipv4(fs) => {
                let spec = dpdk_sys::rte_flow_item_ipv4 {
                    hdr: dpdk_sys::rte_ipv4_hdr {
                        src_addr: u32::from(fs.spec().src).to_be(),
                        dst_addr: u32::from(fs.spec().dst).to_be(),
                        ..Default::default()
                    },
                };
                let mask_c = fs.mask().map(|m| {
                    dpdk_sys::rte_flow_item_ipv4 {
                        hdr: dpdk_sys::rte_ipv4_hdr {
                            src_addr: u32::from(m.src).to_be(),
                            dst_addr: u32::from(m.dst).to_be(),
                            ..Default::default()
                        },
                    }
                });
                let (spec_ptr, mask_ptr) = push_spec_mask(&mut storage, spec, mask_c);
                items.push(dpdk_sys::rte_flow_item {
                    type_: RTE_FLOW_ITEM_TYPE_IPV4,
                    spec: spec_ptr,
                    last: ptr::null(),
                    mask: mask_ptr,
                });
            }
            FlowMatch::Ipv6(fs) => {
                // TODO: Set src/dst addresses.  The rte_ipv6_addr layout
                // varies across DPDK versions; for now the spec matches
                // any IPv6 traffic and the addresses are ignored.
                let _ = fs;
                let spec = dpdk_sys::rte_flow_item_ipv6::default();
                let (spec_ptr, spec_box) = heap_ptr(spec);
                storage.push(spec_box);
                items.push(dpdk_sys::rte_flow_item {
                    type_: RTE_FLOW_ITEM_TYPE_IPV6,
                    spec: spec_ptr,
                    last: ptr::null(),
                    mask: ptr::null(),
                });
            }
            FlowMatch::Udp(fs) => {
                let spec = dpdk_sys::rte_flow_item_udp {
                    hdr: dpdk_sys::rte_udp_hdr {
                        src_port: fs.spec().src_port.0.to_be(),
                        dst_port: fs.spec().dst_port.0.to_be(),
                        ..Default::default()
                    },
                };
                let mask_c = fs.mask().map(|m| {
                    dpdk_sys::rte_flow_item_udp {
                        hdr: dpdk_sys::rte_udp_hdr {
                            src_port: m.src_port.0.to_be(),
                            dst_port: m.dst_port.0.to_be(),
                            ..Default::default()
                        },
                    }
                });
                let (spec_ptr, mask_ptr) = push_spec_mask(&mut storage, spec, mask_c);
                items.push(dpdk_sys::rte_flow_item {
                    type_: RTE_FLOW_ITEM_TYPE_UDP,
                    spec: spec_ptr,
                    last: ptr::null(),
                    mask: mask_ptr,
                });
            }
            FlowMatch::Tcp(fs) => {
                let spec = dpdk_sys::rte_flow_item_tcp {
                    hdr: dpdk_sys::rte_tcp_hdr {
                        src_port: fs.spec().src_port.0.to_be(),
                        dst_port: fs.spec().dst_port.0.to_be(),
                        ..Default::default()
                    },
                };
                let mask_c = fs.mask().map(|m| {
                    dpdk_sys::rte_flow_item_tcp {
                        hdr: dpdk_sys::rte_tcp_hdr {
                            src_port: m.src_port.0.to_be(),
                            dst_port: m.dst_port.0.to_be(),
                            ..Default::default()
                        },
                    }
                });
                let (spec_ptr, mask_ptr) = push_spec_mask(&mut storage, spec, mask_c);
                items.push(dpdk_sys::rte_flow_item {
                    type_: RTE_FLOW_ITEM_TYPE_TCP,
                    spec: spec_ptr,
                    last: ptr::null(),
                    mask: mask_ptr,
                });
            }
            FlowMatch::Vlan(_) | FlowMatch::Vxlan(_) => {
                // TODO: Implement VLAN and VXLAN pattern conversion.
                // The bindgen field layout for rte_flow_item_vlan / _vxlan
                // uses anonymous unions that vary across DPDK versions.
                return Err(FlowError::UnsupportedMatchType);
            }
            FlowMatch::Meta(meta) => {
                let spec = dpdk_sys::rte_flow_item_meta { data: meta.data };
                let (spec_ptr, spec_box) = heap_ptr(spec);
                storage.push(spec_box);
                items.push(dpdk_sys::rte_flow_item {
                    type_: RTE_FLOW_ITEM_TYPE_META,
                    spec: spec_ptr,
                    last: ptr::null(),
                    mask: ptr::null(),
                });
            }
            FlowMatch::Tag(tag) => {
                // TODO: expose tag index (defaults to register 0)
                let spec = dpdk_sys::rte_flow_item_tag {
                    data: tag.data.0,
                    ..Default::default()
                };
                let (spec_ptr, spec_box) = heap_ptr(spec);
                storage.push(spec_box);
                items.push(dpdk_sys::rte_flow_item {
                    type_: RTE_FLOW_ITEM_TYPE_TAG,
                    spec: spec_ptr,
                    last: ptr::null(),
                    mask: ptr::null(),
                });
            }
            FlowMatch::TxQueue(_) => {
                // TODO: Implement TxQueue pattern item.
                return Err(FlowError::UnsupportedMatchType);
            }
        }
    }

    // Terminate the pattern with an END sentinel.
    items.push(dpdk_sys::rte_flow_item {
        type_: RTE_FLOW_ITEM_TYPE_END,
        spec: ptr::null(),
        last: ptr::null(),
        mask: ptr::null(),
    });

    Ok(CFlowPattern {
        items,
        _storage: storage,
    })
}

// -- Action builder --

/// Build a C-level action array from a slice of [`FlowAction`] items.
///
/// # Errors
///
/// Returns [`FlowError::UnsupportedActionType`] if an action variant lacks
/// a C-level conversion.
fn build_c_actions(actions: &[FlowAction]) -> Result<CFlowActions, FlowError> {
    use dpdk_sys::rte_flow_action_type::*;

    let mut c_actions: Vec<dpdk_sys::rte_flow_action> = Vec::with_capacity(actions.len() + 1);
    let mut storage: Vec<Box<dyn Any>> = Vec::with_capacity(actions.len());

    for a in actions {
        match a {
            FlowAction::End => {
                c_actions.push(dpdk_sys::rte_flow_action {
                    type_: RTE_FLOW_ACTION_TYPE_END,
                    conf: ptr::null(),
                });
            }
            FlowAction::Void => {
                c_actions.push(dpdk_sys::rte_flow_action {
                    type_: RTE_FLOW_ACTION_TYPE_VOID,
                    conf: ptr::null(),
                });
            }
            FlowAction::PassThrough => {
                c_actions.push(dpdk_sys::rte_flow_action {
                    type_: RTE_FLOW_ACTION_TYPE_PASSTHRU,
                    conf: ptr::null(),
                });
            }
            FlowAction::Flag => {
                c_actions.push(dpdk_sys::rte_flow_action {
                    type_: RTE_FLOW_ACTION_TYPE_FLAG,
                    conf: ptr::null(),
                });
            }
            FlowAction::Drop => {
                c_actions.push(dpdk_sys::rte_flow_action {
                    type_: RTE_FLOW_ACTION_TYPE_DROP,
                    conf: ptr::null(),
                });
            }
            FlowAction::PopVlan => {
                c_actions.push(dpdk_sys::rte_flow_action {
                    type_: RTE_FLOW_ACTION_TYPE_OF_POP_VLAN,
                    conf: ptr::null(),
                });
            }
            FlowAction::MacSwap => {
                c_actions.push(dpdk_sys::rte_flow_action {
                    type_: RTE_FLOW_ACTION_TYPE_MAC_SWAP,
                    conf: ptr::null(),
                });
            }
            FlowAction::Jump(group) => {
                let conf = dpdk_sys::rte_flow_action_jump { group: group.0 };
                let (conf_ptr, conf_box) = heap_ptr(conf);
                storage.push(conf_box);
                c_actions.push(dpdk_sys::rte_flow_action {
                    type_: RTE_FLOW_ACTION_TYPE_JUMP,
                    conf: conf_ptr,
                });
            }
            FlowAction::Mark(mark) => {
                let conf = dpdk_sys::rte_flow_action_mark { id: mark.0 };
                let (conf_ptr, conf_box) = heap_ptr(conf);
                storage.push(conf_box);
                c_actions.push(dpdk_sys::rte_flow_action {
                    type_: RTE_FLOW_ACTION_TYPE_MARK,
                    conf: conf_ptr,
                });
            }
            FlowAction::Queue(queue_idx) => {
                let conf = dpdk_sys::rte_flow_action_queue {
                    index: queue_idx.as_u16(),
                };
                let (conf_ptr, conf_box) = heap_ptr(conf);
                storage.push(conf_box);
                c_actions.push(dpdk_sys::rte_flow_action {
                    type_: RTE_FLOW_ACTION_TYPE_QUEUE,
                    conf: conf_ptr,
                });
            }
            FlowAction::Count(counter_id) => {
                let conf = dpdk_sys::rte_flow_action_count { id: counter_id.0 };
                let (conf_ptr, conf_box) = heap_ptr(conf);
                storage.push(conf_box);
                c_actions.push(dpdk_sys::rte_flow_action {
                    type_: RTE_FLOW_ACTION_TYPE_COUNT,
                    conf: conf_ptr,
                });
            }
            FlowAction::Meter { id } => {
                let conf = dpdk_sys::rte_flow_action_meter { mtr_id: id.0 };
                let (conf_ptr, conf_box) = heap_ptr(conf);
                storage.push(conf_box);
                c_actions.push(dpdk_sys::rte_flow_action {
                    type_: RTE_FLOW_ACTION_TYPE_METER,
                    conf: conf_ptr,
                });
            }
            FlowAction::PushVlan { ethertype } => {
                let conf = dpdk_sys::rte_flow_action_of_push_vlan {
                    ethertype: ethertype.as_u16().to_be(),
                };
                let (conf_ptr, conf_box) = heap_ptr(conf);
                storage.push(conf_box);
                c_actions.push(dpdk_sys::rte_flow_action {
                    type_: RTE_FLOW_ACTION_TYPE_OF_PUSH_VLAN,
                    conf: conf_ptr,
                });
            }
            FlowAction::SetVlanVid { vlan_id } => {
                let raw: u16 = (*vlan_id).into();
                let conf = dpdk_sys::rte_flow_action_of_set_vlan_vid {
                    vlan_vid: raw.to_be(),
                };
                let (conf_ptr, conf_box) = heap_ptr(conf);
                storage.push(conf_box);
                c_actions.push(dpdk_sys::rte_flow_action {
                    type_: RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID,
                    conf: conf_ptr,
                });
            }
            FlowAction::Age { timeout } => {
                let mut conf = dpdk_sys::rte_flow_action_age::default();
                conf.set_timeout(*timeout);
                let (conf_ptr, conf_box) = heap_ptr(conf);
                storage.push(conf_box);
                c_actions.push(dpdk_sys::rte_flow_action {
                    type_: RTE_FLOW_ACTION_TYPE_AGE,
                    conf: conf_ptr,
                });
            }
            FlowAction::ModifyField(set_flow_field) => {
                let action = set_flow_field.to_flow_rule();
                let (conf_ptr, conf_box) = heap_ptr(action.conf);
                storage.push(conf_box);
                c_actions.push(dpdk_sys::rte_flow_action {
                    type_: RTE_FLOW_ACTION_TYPE_MODIFY_FIELD,
                    conf: conf_ptr,
                });
            }
            FlowAction::RawEncap { data, mask } => {
                // Keep the data/mask buffers alive via cloned Vecs in storage.
                let data_clone = data.clone();
                let data_ptr = data_clone.as_ptr();
                let data_len = data_clone.len();
                storage.push(Box::new(data_clone));

                let preserve_ptr = match mask {
                    Some(m) => {
                        let mask_clone = m.clone();
                        let p = mask_clone.as_ptr();
                        storage.push(Box::new(mask_clone));
                        p
                    }
                    None => ptr::null(),
                };

                let conf = dpdk_sys::rte_flow_action_raw_encap {
                    data: data_ptr.cast_mut(),
                    preserve: preserve_ptr.cast_mut(),
                    size: data_len,
                };
                let (conf_ptr, conf_box) = heap_ptr(conf);
                storage.push(conf_box);
                c_actions.push(dpdk_sys::rte_flow_action {
                    type_: RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
                    conf: conf_ptr,
                });
            }
            FlowAction::RawDecap { data } => {
                let data_clone = data.clone();
                let data_ptr = data_clone.as_ptr();
                let data_len = data_clone.len();
                storage.push(Box::new(data_clone));

                let conf = dpdk_sys::rte_flow_action_raw_decap {
                    data: data_ptr.cast_mut(),
                    size: data_len,
                };
                let (conf_ptr, conf_box) = heap_ptr(conf);
                storage.push(conf_box);
                c_actions.push(dpdk_sys::rte_flow_action {
                    type_: RTE_FLOW_ACTION_TYPE_RAW_DECAP,
                    conf: conf_ptr,
                });
            }
        }
    }

    // Terminate the action list with an END sentinel.
    c_actions.push(dpdk_sys::rte_flow_action {
        type_: RTE_FLOW_ACTION_TYPE_END,
        conf: ptr::null(),
    });

    Ok(CFlowActions {
        actions: c_actions,
        _storage: storage,
    })
}

// -- FlowRule Send / Sync --

/// # Safety
///
/// `FlowRule` wraps a `NonNull<rte_flow>` pointer obtained from
/// [`dpdk_sys::rte_flow_create`].  DPDK flow rule operations
/// (`rte_flow_destroy`, `rte_flow_query`) serialise access per-port
/// internally, so transferring a `FlowRule` to another thread is safe.
/// The `FlowRule` owns the underlying hardware flow resource uniquely
/// (no aliasing is possible through this API).
unsafe impl Send for FlowRule {}

/// # Safety
///
/// See the [`Send`] impl.  Read-only operations on a flow rule (e.g.,
/// `rte_flow_query`) are safe to call concurrently.  Destruction requires
/// either ownership ([`FlowRule::destroy`]) or `&mut self` ([`Drop`]).
unsafe impl Sync for FlowRule {}

// -- FlowRule methods --

impl FlowRule {
    /// Create a flow rule on the specified device.
    ///
    /// The backing storage for the C-level pattern/action arrays is
    /// allocated on the heap and kept alive for the duration of the
    /// `rte_flow_create` call.  Once the call returns, only the
    /// resulting `rte_flow *` handle is retained.
    ///
    /// # Errors
    ///
    /// Returns a [`FlowError`] if the DPDK driver rejects the rule.
    pub fn create(
        port: DevIndex,
        attr: &FlowAttr,
        pattern: &[FlowMatch],
        actions: &[FlowAction],
    ) -> Result<FlowRule, FlowError> {
        let c_attr = attr.as_c_attr();
        let c_pattern = build_c_pattern(pattern)?;
        let c_actions = build_c_actions(actions)?;

        let mut flow_err = dpdk_sys::rte_flow_error::default();

        // SAFETY: `c_pattern` and `c_actions` are alive for the duration
        // of this call, so every raw pointer embedded in their item / action
        // arrays remains valid.
        let flow_ptr = unsafe {
            dpdk_sys::rte_flow_create(
                port.as_u16(),
                &c_attr,
                c_pattern.as_ptr(),
                c_actions.as_ptr(),
                &mut flow_err,
            )
        };

        match NonNull::new(flow_ptr) {
            Some(flow) => Ok(FlowRule {
                port,
                flow,
                _phantom: PhantomData,
            }),
            None => Err(extract_flow_error(&flow_err)),
        }
    }

    /// Validate a flow rule without installing it.
    ///
    /// Useful for checking whether the device supports a particular
    /// pattern / action combination before committing to creation.
    ///
    /// # Errors
    ///
    /// Returns a [`FlowError`] if the rule is invalid or unsupported.
    pub fn validate(
        port: DevIndex,
        attr: &FlowAttr,
        pattern: &[FlowMatch],
        actions: &[FlowAction],
    ) -> Result<(), FlowError> {
        let c_attr = attr.as_c_attr();
        let c_pattern = build_c_pattern(pattern)?;
        let c_actions = build_c_actions(actions)?;

        let mut flow_err = dpdk_sys::rte_flow_error::default();

        // SAFETY: same lifetime guarantees as `create`.
        let ret = unsafe {
            dpdk_sys::rte_flow_validate(
                port.as_u16(),
                &c_attr,
                c_pattern.as_ptr(),
                c_actions.as_ptr(),
                &mut flow_err,
            )
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(extract_flow_error(&flow_err))
        }
    }

    /// Destroy this flow rule, releasing the associated hardware resources.
    ///
    /// This consumes the `FlowRule`.  On failure the underlying DPDK
    /// resource *may* still be allocated (DPDK provides no recovery
    /// mechanism), so the rule is forgotten regardless of the outcome.
    ///
    /// Prefer this method over relying on [`Drop`] when you need to
    /// inspect destroy errors.
    ///
    /// # Errors
    ///
    /// Returns a [`FlowError`] if the DPDK driver reports a failure.
    pub fn destroy(self) -> Result<(), FlowError> {
        let mut flow_err = dpdk_sys::rte_flow_error::default();

        // SAFETY: We own the flow rule and the pointer was obtained from
        // a successful rte_flow_create.
        let ret = unsafe {
            dpdk_sys::rte_flow_destroy(
                self.port.as_u16(),
                self.flow.as_ptr(),
                &mut flow_err,
            )
        };

        // Prevent Drop from running — we already attempted destruction.
        core::mem::forget(self);

        if ret == 0 {
            Ok(())
        } else {
            Err(extract_flow_error(&flow_err))
        }
    }

    /// Flush (destroy) **all** flow rules on the specified device.
    ///
    /// # Errors
    ///
    /// Returns a [`FlowError`] if the flush operation fails.
    pub fn flush(port: DevIndex) -> Result<(), FlowError> {
        let mut flow_err = dpdk_sys::rte_flow_error::default();

        // SAFETY: port.as_u16() is a valid DPDK port ID.
        let ret = unsafe {
            dpdk_sys::rte_flow_flush(port.as_u16(), &mut flow_err)
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(extract_flow_error(&flow_err))
        }
    }

    /// Returns the port index this flow rule is installed on.
    #[must_use]
    pub fn port(&self) -> DevIndex {
        self.port
    }
}

impl Drop for FlowRule {
    fn drop(&mut self) {
        let mut flow_err = dpdk_sys::rte_flow_error::default();

        // SAFETY: self.flow is a valid pointer obtained from a successful
        // rte_flow_create.  We own it exclusively.
        let ret = unsafe {
            dpdk_sys::rte_flow_destroy(
                self.port.as_u16(),
                self.flow.as_ptr(),
                &mut flow_err,
            )
        };

        if ret != 0 {
            error!(
                "Failed to destroy flow rule on port {port}: error {ret}",
                port = self.port,
            );
        }
    }
}
