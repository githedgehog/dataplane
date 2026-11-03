// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Flow match criteria. Defaults match header presence; setters constrain fields.
//! Values may include addresses and ports that parsed-packet types reject.

use core::net::{Ipv4Addr, Ipv6Addr};

use dpdk_sys::{
    rte_flow_item_eth, rte_flow_item_ipv4, rte_flow_item_ipv6, rte_flow_item_tcp,
    rte_flow_item_udp, rte_flow_item_vlan, rte_flow_item_vxlan,
};
use net::eth::ethtype::EthType;
use net::eth::mac::Mac;
use net::vlan::{Pcp, Vid};
use net::vxlan::Vni;

use crate::flow::item::MatchItem;

/// `rte_be32_t` (network byte order) for an IPv4 address.
fn be32(addr: Ipv4Addr) -> u32 {
    u32::from(addr).to_be()
}

/// Match criteria for an Ethernet header. `default()` matches any Ethernet frame (presence only).
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct EthMatch {
    dst: Option<Mac>,
    src: Option<Mac>,
    ether_type: Option<EthType>,
    tagged: Option<bool>,
}

impl EthMatch {
    /// Constrain the destination MAC address, e.g. LLDP's nearest-bridge group address.
    #[must_use]
    pub fn dst(mut self, dst: Mac) -> EthMatch {
        self.dst = Some(dst);
        self
    }

    /// Constrain the source MAC address.
    #[must_use]
    pub fn src(mut self, src: Mac) -> EthMatch {
        self.src = Some(src);
        self
    }

    /// Constrain the EtherType, e.g. [`EthType::ARP`] or [`EthType::LLDP`].
    ///
    /// This is the EtherType of the Ethernet header itself: on a VLAN-tagged frame that is the tag's
    /// TPID, and the payload's type is the VLAN item's to match.
    #[must_use]
    pub fn ether_type(mut self, ether_type: EthType) -> EthMatch {
        self.ether_type = Some(ether_type);
        self
    }

    /// Constrain whether at least one VLAN tag follows the header (`has_vlan`).
    ///
    /// Without it, whether a pattern of an Ethernet header and an IP header matches a tagged frame
    /// is the PMD's choice.
    #[must_use]
    pub fn tagged(mut self, tagged: bool) -> EthMatch {
        self.tagged = Some(tagged);
        self
    }

    /// Lower to the `(spec, mask)` pair the PMD reads. Unconstrained fields stay zero in `mask`,
    /// which `rte_flow` reads as "don't care".
    pub(crate) fn lower(&self) -> (rte_flow_item_eth, rte_flow_item_eth) {
        // SAFETY: zeroed fields are valid; a zero mask leaves fields unconstrained.
        let mut spec: rte_flow_item_eth = unsafe { core::mem::zeroed() };
        let mut mask: rte_flow_item_eth = unsafe { core::mem::zeroed() };
        if let Some(dst) = self.dst {
            spec.annon1.hdr.dst_addr.addr_bytes = dst.0;
            mask.annon1.hdr.dst_addr.addr_bytes = [u8::MAX; 6];
        }
        if let Some(src) = self.src {
            spec.annon1.hdr.src_addr.addr_bytes = src.0;
            mask.annon1.hdr.src_addr.addr_bytes = [u8::MAX; 6];
        }
        if let Some(ether_type) = self.ether_type {
            spec.annon1.hdr.ether_type = ether_type.as_u16().to_be();
            mask.annon1.hdr.ether_type = u16::MAX;
        }
        if let Some(tagged) = self.tagged {
            spec.set_has_vlan(u32::from(tagged));
            mask.set_has_vlan(1);
        }
        (spec, mask)
    }
}

/// An IPv4 address and mask, supporting host, subnet and arbitrary masked matches.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Ipv4Prefix {
    addr: Ipv4Addr,
    mask: Ipv4Addr,
}

impl Ipv4Prefix {
    /// Match a single address exactly (`/32`).
    #[must_use]
    pub fn host(addr: Ipv4Addr) -> Ipv4Prefix {
        Ipv4Prefix {
            addr,
            mask: Ipv4Addr::from(u32::MAX),
        }
    }

    /// Match a CIDR prefix of `len` bits (`len` is clamped to `0..=32`).
    #[must_use]
    pub fn prefix(addr: Ipv4Addr, len: u8) -> Ipv4Prefix {
        let mask = match len {
            0 => 0,
            len if len >= 32 => u32::MAX,
            len => u32::MAX << (32 - len),
        };
        Ipv4Prefix {
            addr,
            mask: Ipv4Addr::from(mask),
        }
    }

    /// Match with an arbitrary bit-mask.
    #[must_use]
    pub fn masked(addr: Ipv4Addr, mask: Ipv4Addr) -> Ipv4Prefix {
        Ipv4Prefix { addr, mask }
    }
}

/// Match criteria for an IPv4 header. `default()` matches any IPv4 packet (presence only).
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct Ipv4Match {
    src: Option<Ipv4Prefix>,
    dst: Option<Ipv4Prefix>,
    proto: Option<u8>,
    unfragmented: bool,
}

impl Ipv4Match {
    /// Constrain the source address.
    #[must_use]
    pub fn src(mut self, src: Ipv4Prefix) -> Ipv4Match {
        self.src = Some(src);
        self
    }

    /// Constrain the destination address.
    #[must_use]
    pub fn dst(mut self, dst: Ipv4Prefix) -> Ipv4Match {
        self.dst = Some(dst);
        self
    }

    /// Constrain the L4 protocol (`next_proto_id`), e.g. 6 (TCP) or 17 (UDP).
    #[must_use]
    pub fn proto(mut self, proto: u8) -> Ipv4Match {
        self.proto = Some(proto);
        self
    }

    /// Match only packets that are not fragments.
    ///
    /// Constrains the whole fragment field but the don't-fragment bit (more fragments and offset)
    /// to zero, which mlx5 serves as its own "fragmented" bit.
    #[must_use]
    pub fn unfragmented(mut self) -> Ipv4Match {
        self.unfragmented = true;
        self
    }

    /// Lower to the `(spec, mask)` pair the PMD reads. Unconstrained fields stay zero in `mask`,
    /// which `rte_flow` reads as "don't care".
    pub(crate) fn lower(&self) -> (rte_flow_item_ipv4, rte_flow_item_ipv4) {
        // SAFETY: zeroed fields are valid; a zero mask leaves fields unconstrained.
        let mut spec: rte_flow_item_ipv4 = unsafe { core::mem::zeroed() };
        let mut mask: rte_flow_item_ipv4 = unsafe { core::mem::zeroed() };
        if let Some(src) = self.src {
            spec.hdr.src_addr = be32(src.addr);
            mask.hdr.src_addr = be32(src.mask);
        }
        if let Some(dst) = self.dst {
            spec.hdr.dst_addr = be32(dst.addr);
            mask.hdr.dst_addr = be32(dst.mask);
        }
        if let Some(proto) = self.proto {
            spec.hdr.next_proto_id = proto;
            mask.hdr.next_proto_id = u8::MAX;
        }
        if self.unfragmented {
            // More fragments and the offset; not don't-fragment.
            mask.hdr.fragment_offset = 0x3fffu16.to_be();
        }
        (spec, mask)
    }
}

/// An IPv6 address and mask, supporting host, subnet and arbitrary masked matches.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Ipv6Prefix {
    addr: Ipv6Addr,
    mask: Ipv6Addr,
}

impl Ipv6Prefix {
    /// Match a single address exactly (`/128`).
    #[must_use]
    pub fn host(addr: Ipv6Addr) -> Ipv6Prefix {
        Ipv6Prefix {
            addr,
            mask: Ipv6Addr::from(u128::MAX),
        }
    }

    /// Match a CIDR prefix of `len` bits (`len` is clamped to `0..=128`).
    #[must_use]
    pub fn prefix(addr: Ipv6Addr, len: u8) -> Ipv6Prefix {
        let mask = match len {
            0 => 0,
            len if len >= 128 => u128::MAX,
            len => u128::MAX << (128 - len),
        };
        Ipv6Prefix {
            addr,
            mask: Ipv6Addr::from(mask),
        }
    }

    /// Match with an arbitrary bit-mask.
    #[must_use]
    pub fn masked(addr: Ipv6Addr, mask: Ipv6Addr) -> Ipv6Prefix {
        Ipv6Prefix { addr, mask }
    }
}

/// Match criteria for an IPv6 header. `default()` matches any IPv6 packet (presence only).
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct Ipv6Match {
    src: Option<Ipv6Prefix>,
    dst: Option<Ipv6Prefix>,
    proto: Option<u8>,
    unfragmented: bool,
}

impl Ipv6Match {
    /// Constrain the source address.
    #[must_use]
    pub fn src(mut self, src: Ipv6Prefix) -> Ipv6Match {
        self.src = Some(src);
        self
    }

    /// Constrain the destination address.
    #[must_use]
    pub fn dst(mut self, dst: Ipv6Prefix) -> Ipv6Match {
        self.dst = Some(dst);
        self
    }

    /// Constrain the next-header / L4 protocol (`proto`), e.g. 6 (TCP), 17 (UDP), 58 (ICMPv6).
    #[must_use]
    pub fn proto(mut self, proto: u8) -> Ipv6Match {
        self.proto = Some(proto);
        self
    }

    /// Match only packets without a fragment extension header (`has_frag_ext`).
    #[must_use]
    pub fn unfragmented(mut self) -> Ipv6Match {
        self.unfragmented = true;
        self
    }

    /// Lower to the `(spec, mask)` pair the PMD reads. IPv6 addresses are stored network-order
    /// (`Ipv6Addr::octets`); unconstrained fields stay zero in `mask` ("don't care").
    pub(crate) fn lower(&self) -> (rte_flow_item_ipv6, rte_flow_item_ipv6) {
        // SAFETY: zeroed fields are valid; a zero mask leaves fields unconstrained.
        let mut spec: rte_flow_item_ipv6 = unsafe { core::mem::zeroed() };
        let mut mask: rte_flow_item_ipv6 = unsafe { core::mem::zeroed() };
        if let Some(src) = self.src {
            spec.hdr.src_addr.a = src.addr.octets();
            mask.hdr.src_addr.a = src.mask.octets();
        }
        if let Some(dst) = self.dst {
            spec.hdr.dst_addr.a = dst.addr.octets();
            mask.hdr.dst_addr.a = dst.mask.octets();
        }
        if let Some(proto) = self.proto {
            spec.hdr.proto = proto;
            mask.hdr.proto = u8::MAX;
        }
        if self.unfragmented {
            mask.set_has_frag_ext(1);
        }
        (spec, mask)
    }
}

/// Match criteria for a VLAN (802.1Q) tag. `default()` matches any VLAN tag (presence only).
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct VlanMatch {
    vid: Option<Vid>,
    pcp: Option<Pcp>,
}

impl VlanMatch {
    /// Constrain the VLAN id (VID, 12 bits).
    #[must_use]
    pub fn vid(mut self, vid: Vid) -> VlanMatch {
        self.vid = Some(vid);
        self
    }

    /// Constrain the priority code point (PCP, 3 bits).
    #[must_use]
    pub fn pcp(mut self, pcp: Pcp) -> VlanMatch {
        self.pcp = Some(pcp);
        self
    }

    /// Lower to the `(spec, mask)` pair. The tag-control-information (TCI) packs PCP (bits 15..13),
    /// DEI (bit 12), and VID (bits 11..0); only the constrained sub-fields are set in `mask`.
    pub(crate) fn lower(&self) -> (rte_flow_item_vlan, rte_flow_item_vlan) {
        // SAFETY: zeroed fields are valid; a zero mask leaves fields unconstrained.
        let mut spec: rte_flow_item_vlan = unsafe { core::mem::zeroed() };
        let mut mask: rte_flow_item_vlan = unsafe { core::mem::zeroed() };
        let mut spec_tci: u16 = 0;
        let mut mask_tci: u16 = 0;
        if let Some(vid) = self.vid {
            spec_tci |= vid.as_u16() & 0x0fff;
            mask_tci |= 0x0fff;
        }
        if let Some(pcp) = self.pcp {
            spec_tci |= (u16::from(pcp.to_u8()) & 0x7) << 13;
            mask_tci |= 0xe000;
        }
        spec.annon1.hdr.vlan_tci = spec_tci.to_be();
        mask.annon1.hdr.vlan_tci = mask_tci.to_be();
        (spec, mask)
    }
}

/// Match criteria for a VXLAN header. `default()` matches any VXLAN packet (presence only).
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct VxlanMatch {
    vni: Option<Vni>,
}

impl VxlanMatch {
    /// Constrain the VXLAN network identifier (VNI, 24 bits).
    #[must_use]
    pub fn vni(mut self, vni: Vni) -> VxlanMatch {
        self.vni = Some(vni);
        self
    }

    /// Lower to the `(spec, mask)` pair. The 24-bit VNI is stored big-endian in a 3-byte field.
    pub(crate) fn lower(&self) -> (rte_flow_item_vxlan, rte_flow_item_vxlan) {
        // SAFETY: zeroed fields are valid; a zero mask leaves fields unconstrained.
        let mut spec: rte_flow_item_vxlan = unsafe { core::mem::zeroed() };
        let mut mask: rte_flow_item_vxlan = unsafe { core::mem::zeroed() };
        if let Some(vni) = self.vni {
            let v = vni.as_u32();
            let bytes = [(v >> 16) as u8, (v >> 8) as u8, v as u8];
            spec.annon1.annon1.vni = bytes;
            mask.annon1.annon1.vni = [0xff; 3];
        }
        (spec, mask)
    }
}

/// Ports from a first to a last, both included: never empty.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PortRange {
    lo: u16,
    hi: u16,
}

impl PortRange {
    /// `lo..=hi`, if `lo` is at most `hi`.
    #[must_use]
    pub fn new(lo: u16, hi: u16) -> Option<PortRange> {
        (lo <= hi).then_some(PortRange { lo, hi })
    }

    /// The ports between `a` and `b`, both included, whichever is the larger.
    #[must_use]
    pub fn between(a: u16, b: u16) -> PortRange {
        PortRange {
            lo: a.min(b),
            hi: a.max(b),
        }
    }
}

/// A port to match: one, or every port of a range.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Ports {
    Exact(u16),
    /// From the first to the second, both included; the second is above the first.
    Range(u16, u16),
}

impl Ports {
    /// The ports of `range`: one port if it holds one.
    fn range(range: PortRange) -> Ports {
        if range.lo == range.hi {
            Ports::Exact(range.lo)
        } else {
            Ports::Range(range.lo, range.hi)
        }
    }

    /// The spec, mask and `last` of a port field: `last` only for a range, and zero (no range)
    /// otherwise.
    fn lower(ports: Option<Ports>) -> (u16, u16, u16) {
        match ports {
            None => (0, 0, 0),
            Some(Ports::Exact(port)) => (port.to_be(), u16::MAX, 0),
            Some(Ports::Range(lo, hi)) => (lo.to_be(), u16::MAX, hi.to_be()),
        }
    }
}

/// Match criteria for a UDP header. `default()` matches any UDP packet.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct UdpMatch {
    src: Option<Ports>,
    dst: Option<Ports>,
}

impl UdpMatch {
    /// Constrain the source port.
    #[must_use]
    pub fn src(mut self, src: u16) -> UdpMatch {
        self.src = Some(Ports::Exact(src));
        self
    }

    /// Constrain the destination port.
    #[must_use]
    pub fn dst(mut self, dst: u16) -> UdpMatch {
        self.dst = Some(Ports::Exact(dst));
        self
    }

    /// Constrain the source port to `range` (one port, if it holds one).
    ///
    /// A range is a `last` bound, which a template table matches only if its pattern template
    /// has a range there too: shapes tell them apart.
    #[must_use]
    pub fn src_range(mut self, range: PortRange) -> UdpMatch {
        self.src = Some(Ports::range(range));
        self
    }

    /// Constrain the destination port to `range`; see [`UdpMatch::src_range`].
    #[must_use]
    pub fn dst_range(mut self, range: PortRange) -> UdpMatch {
        self.dst = Some(Ports::range(range));
        self
    }

    pub(crate) fn lower(
        &self,
    ) -> (
        rte_flow_item_udp,
        rte_flow_item_udp,
        Option<rte_flow_item_udp>,
    ) {
        // SAFETY: zeroed fields are valid; a zero mask leaves fields unconstrained.
        let mut spec: rte_flow_item_udp = unsafe { core::mem::zeroed() };
        let mut mask: rte_flow_item_udp = unsafe { core::mem::zeroed() };
        let mut last: rte_flow_item_udp = unsafe { core::mem::zeroed() };
        (spec.hdr.src_port, mask.hdr.src_port, last.hdr.src_port) = Ports::lower(self.src);
        (spec.hdr.dst_port, mask.hdr.dst_port, last.hdr.dst_port) = Ports::lower(self.dst);
        let ranged = last.hdr.src_port != 0 || last.hdr.dst_port != 0;
        (spec, mask, ranged.then_some(last))
    }
}

/// Match criteria for a TCP header. `default()` matches any TCP packet.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct TcpMatch {
    src: Option<Ports>,
    dst: Option<Ports>,
    /// Flag values and the mask of flags constrained.
    flags: Option<(u8, u8)>,
}

impl TcpMatch {
    /// Constrain the source port.
    #[must_use]
    pub fn src(mut self, src: u16) -> TcpMatch {
        self.src = Some(Ports::Exact(src));
        self
    }

    /// Constrain the destination port.
    #[must_use]
    pub fn dst(mut self, dst: u16) -> TcpMatch {
        self.dst = Some(Ports::Exact(dst));
        self
    }

    /// Constrain the source port to `range`; see [`UdpMatch::src_range`].
    #[must_use]
    pub fn src_range(mut self, range: PortRange) -> TcpMatch {
        self.src = Some(Ports::range(range));
        self
    }

    /// Constrain the destination port to `range`; see [`UdpMatch::src_range`].
    #[must_use]
    pub fn dst_range(mut self, range: PortRange) -> TcpMatch {
        self.dst = Some(Ports::range(range));
        self
    }

    /// Constrain the flags in `mask` (the TCP header's flags byte, FIN = `0x01` to CWR = `0x80`)
    /// to their values in `value`.
    #[must_use]
    pub fn flags(mut self, value: u8, mask: u8) -> TcpMatch {
        self.flags = Some((value & mask, mask));
        self
    }

    pub(crate) fn lower(
        &self,
    ) -> (
        rte_flow_item_tcp,
        rte_flow_item_tcp,
        Option<rte_flow_item_tcp>,
    ) {
        // SAFETY: zeroed fields are valid; a zero mask leaves fields unconstrained.
        let mut spec: rte_flow_item_tcp = unsafe { core::mem::zeroed() };
        let mut mask: rte_flow_item_tcp = unsafe { core::mem::zeroed() };
        let mut last: rte_flow_item_tcp = unsafe { core::mem::zeroed() };
        (spec.hdr.src_port, mask.hdr.src_port, last.hdr.src_port) = Ports::lower(self.src);
        (spec.hdr.dst_port, mask.hdr.dst_port, last.hdr.dst_port) = Ports::lower(self.dst);
        if let Some((value, flags)) = self.flags {
            spec.hdr.tcp_flags = value;
            mask.hdr.tcp_flags = flags;
        }
        let ranged = last.hdr.src_port != 0 || last.hdr.dst_port != 0;
        (spec, mask, ranged.then_some(last))
    }
}

/// The masks an item lowers to, ignoring the values matched.
///
/// A template table matches every rule with its pattern template's masks, so a rule whose masks
/// differ would silently match something other than what it says; templates compare shapes to
/// refuse such rules. Shapes are read back from the lowered masks, so they agree with what the PMD
/// sees: an unconstrained field and a zero-length prefix have the same shape. Only the fields
/// lowering sets are read.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ItemShape {
    /// An Ethernet header.
    Eth {
        /// Destination MAC mask.
        dst: [u8; 6],
        /// Source MAC mask.
        src: [u8; 6],
        /// EtherType mask.
        ether_type: u16,
        /// VLAN presence constrained.
        tagged: bool,
    },
    /// A VLAN tag.
    Vlan {
        /// Tag control information (PCP, DEI, VID) mask.
        tci: u16,
    },
    /// An IPv4 header.
    Ipv4 {
        /// Source address mask.
        src: Ipv4Addr,
        /// Destination address mask.
        dst: Ipv4Addr,
        /// Protocol mask.
        proto: u8,
        /// Flags and fragment offset mask; set to exclude fragments.
        fragment_offset: u16,
    },
    /// An IPv6 header.
    Ipv6 {
        /// Source address mask.
        src: Ipv6Addr,
        /// Destination address mask.
        dst: Ipv6Addr,
        /// Next header mask.
        proto: u8,
        /// Fragments excluded.
        unfragmented: bool,
    },
    /// A UDP header.
    Udp {
        /// Source port mask.
        src: u16,
        /// Destination port mask.
        dst: u16,
        /// Which ports are ranges, source then destination.
        ranges: (bool, bool),
    },
    /// A TCP header.
    Tcp {
        /// Source port mask.
        src: u16,
        /// Destination port mask.
        dst: u16,
        /// Which ports are ranges, source then destination.
        ranges: (bool, bool),
        /// Flags mask.
        flags: u8,
    },
    /// A VXLAN header.
    Vxlan {
        /// VNI mask.
        vni: [u8; 3],
    },
    /// A meter color.
    MeterColor {
        /// Color mask.
        color: u32,
    },
}

impl MatchItem {
    /// The masks this item lowered to.
    pub(crate) fn shape(&self) -> ItemShape {
        match self {
            MatchItem::Eth(_, mask) => {
                // SAFETY: lowering writes the `hdr` view of the anonymous union.
                let hdr = unsafe { &mask.annon1.hdr };
                ItemShape::Eth {
                    dst: hdr.dst_addr.addr_bytes,
                    src: hdr.src_addr.addr_bytes,
                    ether_type: u16::from_be(hdr.ether_type),
                    tagged: mask.has_vlan() != 0,
                }
            }
            MatchItem::Vlan(_, mask) => ItemShape::Vlan {
                // SAFETY: lowering writes the `hdr` view of the anonymous union.
                tci: u16::from_be(unsafe { mask.annon1.hdr.vlan_tci }),
            },
            MatchItem::Ipv4(_, mask) => ItemShape::Ipv4 {
                src: Ipv4Addr::from(u32::from_be(mask.hdr.src_addr)),
                dst: Ipv4Addr::from(u32::from_be(mask.hdr.dst_addr)),
                proto: mask.hdr.next_proto_id,
                fragment_offset: u16::from_be(mask.hdr.fragment_offset),
            },
            MatchItem::Ipv6(_, mask) => ItemShape::Ipv6 {
                src: Ipv6Addr::from(mask.hdr.src_addr.a),
                dst: Ipv6Addr::from(mask.hdr.dst_addr.a),
                proto: mask.hdr.proto,
                unfragmented: mask.has_frag_ext() != 0,
            },
            MatchItem::Udp(_, mask, last) => ItemShape::Udp {
                src: u16::from_be(mask.hdr.src_port),
                dst: u16::from_be(mask.hdr.dst_port),
                ranges: last.map_or((false, false), |l| {
                    (l.hdr.src_port != 0, l.hdr.dst_port != 0)
                }),
            },
            MatchItem::Tcp(_, mask, last) => ItemShape::Tcp {
                src: u16::from_be(mask.hdr.src_port),
                dst: u16::from_be(mask.hdr.dst_port),
                ranges: last.map_or((false, false), |l| {
                    (l.hdr.src_port != 0, l.hdr.dst_port != 0)
                }),
                flags: mask.hdr.tcp_flags,
            },
            MatchItem::Vxlan(_, mask) => ItemShape::Vxlan {
                // SAFETY: lowering writes the `vni` view of the anonymous unions.
                vni: unsafe { mask.annon1.annon1.vni },
            },
            MatchItem::MeterColor(_, mask) => ItemShape::MeterColor { color: mask.color },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether `rte_flow` would say `(spec, mask)` matches a header of these fields: every masked bit
    /// of the header equals the spec's.
    fn eth_matches(
        lowered: &(rte_flow_item_eth, rte_flow_item_eth),
        dst: Mac,
        src: Mac,
        ty: u16,
    ) -> bool {
        let (spec, mask) = lowered;
        let bytes = |a: [u8; 6], s: [u8; 6], m: [u8; 6]| (0..6).all(|i| a[i] & m[i] == s[i] & m[i]);
        // SAFETY: reading the `hdr` view of the anonymous union, which is how `lower` wrote it.
        let (spec, mask) = unsafe { (&spec.annon1.hdr, &mask.annon1.hdr) };
        bytes(dst.0, spec.dst_addr.addr_bytes, mask.dst_addr.addr_bytes)
            && bytes(src.0, spec.src_addr.addr_bytes, mask.src_addr.addr_bytes)
            && ty.to_be() & mask.ether_type == spec.ether_type & mask.ether_type
    }

    #[test]
    fn an_eth_match_lowers_to_exactly_its_criteria() {
        bolero::check!()
            .with_type::<(
                Option<[u8; 6]>,
                Option<[u8; 6]>,
                Option<u16>,
                [u8; 6],
                [u8; 6],
                u16,
            )>()
            .for_each(|&(want_dst, want_src, want_type, dst, src, ty)| {
                let mut criteria = EthMatch::default();
                if let Some(d) = want_dst {
                    criteria = criteria.dst(Mac(d));
                }
                if let Some(s) = want_src {
                    criteria = criteria.src(Mac(s));
                }
                if let Some(t) = want_type {
                    criteria = criteria.ether_type(EthType::new(t));
                }
                let expected = want_dst.is_none_or(|d| d == dst)
                    && want_src.is_none_or(|s| s == src)
                    && want_type.is_none_or(|t| t == ty);
                assert_eq!(
                    eth_matches(&criteria.lower(), Mac(dst), Mac(src), ty),
                    expected
                );
                // And the header the criteria describe always matches.
                let own = (
                    want_dst.unwrap_or(dst),
                    want_src.unwrap_or(src),
                    want_type.unwrap_or(ty),
                );
                assert!(eth_matches(
                    &criteria.lower(),
                    Mac(own.0),
                    Mac(own.1),
                    own.2
                ));
            });
    }
}
