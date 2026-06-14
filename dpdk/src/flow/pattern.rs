// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Per-field match criteria for flow patterns.
//!
//! Each header has a `*Match` struct whose `Default` matches the header's mere presence; builder
//! methods add per-field constraints. Match *values* use permissive types (`Ipv4Addr`, `u16`,
//! `u8`) rather than the strict `net` newtypes (`UnicastIpv4Addr`, `UdpPort`, ...): a rule may
//! legitimately match values those newtypes forbid (a multicast destination, port 0, ...), and a
//! match is a pattern, not a parsed packet.

use core::net::Ipv4Addr;

use dpdk_sys::{rte_flow_item_ipv4, rte_flow_item_tcp, rte_flow_item_udp};

/// `rte_be32_t` (network byte order) for an IPv4 address.
fn be32(addr: Ipv4Addr) -> u32 {
    u32::from(addr).to_be()
}

/// An IPv4 address match: an address with a bit-mask. A host (`/32`) match is the common case; a
/// shorter prefix matches a subnet.
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

    /// Lower to the `(spec, mask)` pair the PMD reads. Unconstrained fields stay zero in `mask`,
    /// which `rte_flow` reads as "don't care".
    pub(crate) fn lower(&self) -> (rte_flow_item_ipv4, rte_flow_item_ipv4) {
        // SAFETY: `rte_flow_item_ipv4` is plain data; all-zero is the valid "match nothing" value.
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
        (spec, mask)
    }
}

/// Match criteria for a UDP header. `default()` matches any UDP packet.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct UdpMatch {
    src: Option<u16>,
    dst: Option<u16>,
}

impl UdpMatch {
    /// Constrain the source port.
    #[must_use]
    pub fn src(mut self, src: u16) -> UdpMatch {
        self.src = Some(src);
        self
    }

    /// Constrain the destination port.
    #[must_use]
    pub fn dst(mut self, dst: u16) -> UdpMatch {
        self.dst = Some(dst);
        self
    }

    pub(crate) fn lower(&self) -> (rte_flow_item_udp, rte_flow_item_udp) {
        // SAFETY: `rte_flow_item_udp` is plain data; all-zero is the valid "match nothing" value.
        let mut spec: rte_flow_item_udp = unsafe { core::mem::zeroed() };
        let mut mask: rte_flow_item_udp = unsafe { core::mem::zeroed() };
        if let Some(src) = self.src {
            spec.hdr.src_port = src.to_be();
            mask.hdr.src_port = u16::MAX;
        }
        if let Some(dst) = self.dst {
            spec.hdr.dst_port = dst.to_be();
            mask.hdr.dst_port = u16::MAX;
        }
        (spec, mask)
    }
}

/// Match criteria for a TCP header. `default()` matches any TCP packet.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct TcpMatch {
    src: Option<u16>,
    dst: Option<u16>,
}

impl TcpMatch {
    /// Constrain the source port.
    #[must_use]
    pub fn src(mut self, src: u16) -> TcpMatch {
        self.src = Some(src);
        self
    }

    /// Constrain the destination port.
    #[must_use]
    pub fn dst(mut self, dst: u16) -> TcpMatch {
        self.dst = Some(dst);
        self
    }

    pub(crate) fn lower(&self) -> (rte_flow_item_tcp, rte_flow_item_tcp) {
        // SAFETY: `rte_flow_item_tcp` is plain data; all-zero is the valid "match nothing" value.
        let mut spec: rte_flow_item_tcp = unsafe { core::mem::zeroed() };
        let mut mask: rte_flow_item_tcp = unsafe { core::mem::zeroed() };
        if let Some(src) = self.src {
            spec.hdr.src_port = src.to_be();
            mask.hdr.src_port = u16::MAX;
        }
        if let Some(dst) = self.dst {
            spec.hdr.dst_port = dst.to_be();
            mask.hdr.dst_port = u16::MAX;
        }
        (spec, mask)
    }
}
