// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A software model of how a NIC matches `rte_flow` patterns, to test what is lowered into a NIC
//! without one.
//!
//! The model interprets the very spec and mask structures a PMD reads, against a frame's bytes, so
//! it checks what the NIC is told rather than a second rendering of the intent.
//!
//! Where the hardware's parser may reasonably go either way, the model does not guess: [`views`]
//! returns every way a NIC might see a frame, and a pattern *may* match if it matches any of them.
//! Each such choice is an assumption a hardware qualification run can settle:
//!
//! - VLAN tags: a pattern without a VLAN item may or may not match a tagged frame, and its
//!   Ethernet item may see the EtherType before or after the tags, at each Ethernet header (outer
//!   and inner) independently. `has_vlan` is exact, and is about the first tag, as mlx5 hardware
//!   steering classifies it: none, 802.1Q (customer) or 802.1ad (service). `has_vlan` set matches
//!   a customer tag only, unset no tag only, so a frame whose first tag is a service tag matches
//!   neither. A service tag matches no VLAN item.
//! - IPv4 fragments after the first: the NIC may or may not parse their payload as a transport
//!   header.
//! - IPv6 extension headers (hop-by-hop, routing, destination options, fragment): the NIC may or
//!   may not walk them to the transport header, and may match the IPv6 item's `proto` on the fixed
//!   header's next header or on the protocol at the end of the chain. `has_frag_ext` is exact.
//!
//! Integrity verdicts ([`IntegrityMatch`](crate::flow::IntegrityMatch)) are computed as mlx5
//! computes them on a BlueField-3 (see [`verdicts`]).
//!
//! Only UDP to port 4789 is parsed as VXLAN. A [`Parser`] narrows the choices a qualification
//! settled for a NIC ([`views_by`]).

use alloc::vec;
use alloc::vec::Vec;
use core::mem::{size_of, size_of_val};

use dpdk_sys::{
    rte_ether_hdr, rte_flow_item_eth, rte_flow_item_vlan, rte_ipv4_hdr, rte_ipv6_hdr, rte_tcp_hdr,
    rte_udp_hdr, rte_vlan_hdr, rte_vxlan_hdr,
};

use super::item::MatchItem;
use super::template::{Color, Pattern};

// The headers are compared as the bytes on the wire: their C structures must have no padding.
const _: () = {
    assert!(size_of::<rte_ether_hdr>() == 14);
    assert!(size_of::<rte_vlan_hdr>() == 4);
    assert!(size_of::<rte_ipv4_hdr>() == 20);
    assert!(size_of::<rte_ipv6_hdr>() == 40);
    assert!(size_of::<rte_udp_hdr>() == 8);
    assert!(size_of::<rte_tcp_hdr>() == 20);
    assert!(size_of::<rte_vxlan_hdr>() == 8);
};

const VXLAN_PORT: u16 = 4789;
const ETH_P_IPV4: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const ETH_P_CVLAN: u16 = 0x8100;
const ETH_P_SVLAN: u16 = 0x88a8;
const UDP: u8 = 17;
const TCP: u8 = 6;
const HOP_BY_HOP: u8 = 0;
const ROUTING: u8 = 43;
const FRAGMENT: u8 = 44;
const DESTINATION_OPTIONS: u8 = 60;
/// The mobility header, which mlx5's integrity check walks like an extension header.
const MOBILITY: u8 = 135;

/// One header as a NIC parsed it: its kind and its bytes on the wire (options excluded).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Header {
    /// An Ethernet header, and the kind of tag that follows it first.
    Eth([u8; 14], FirstTag),
    /// An 802.1Q (customer) tag.
    Vlan([u8; 4]),
    /// An 802.1ad (service) tag, which no item matches.
    ServiceTag([u8; 4]),
    Ipv4([u8; 20]),
    /// An IPv6 header, and whether a fragment extension header follows it.
    Ipv6([u8; 40], bool),
    Udp([u8; 8]),
    Tcp([u8; 20]),
    Vxlan([u8; 8]),
}

/// A frame as one possible NIC parser saw it: its headers, outermost first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    headers: Vec<Header>,
    /// The NIC's integrity verdicts on the outer and the inner headers.
    verdicts: [u64; 2],
}

/// A pattern the model cannot judge: it constrains something the model does not parse.
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the model does not interpret this pattern item's {0}")]
pub struct Unmodelled(pub &'static str);

/// What a NIC's parser is known to do, where NICs may differ: each choice settled narrows the
/// model to that NIC.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Parser {
    /// How the NIC treats IPv6 extension headers.
    pub ipv6_extensions: Ipv6Extensions,
}

impl Parser {
    /// Nothing settled: every choice the module documentation lists stays open.
    pub const ANY: Parser = Parser {
        ipv6_extensions: Ipv6Extensions::Any,
    };
}

/// How a NIC treats IPv6 extension headers.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Ipv6Extensions {
    /// It may walk them or not, and match `proto` on the fixed header's next header or the last.
    Any,
    /// It walks them to the transport header, and matches `proto` on the last next header.
    WalkedToLast,
}

/// Every way a NIC might parse `bytes`; see the [module documentation](self).
#[must_use]
pub fn views(bytes: &[u8]) -> Vec<Frame> {
    views_by(bytes, Parser::ANY)
}

/// Every way a NIC with `parser` might parse `bytes`.
#[must_use]
pub fn views_by(bytes: &[u8], parser: Parser) -> Vec<Frame> {
    let mut frames: Vec<Frame> = Vec::new();
    for headers in eth(bytes, true, parser) {
        let frame = Frame {
            headers,
            verdicts: verdicts(bytes),
        };
        if !frames.contains(&frame) {
            frames.push(frame);
        }
    }
    frames
}

/// Integrity verdict bits; see [`IntegrityMatch`](crate::flow::IntegrityMatch).
const L3_OK: u64 = 1 << 2;
const L4_OK: u64 = 1 << 3;
const IPV4_CSUM_OK: u64 = 1 << 5;
const L4_CSUM_OK: u64 = 1 << 6;

/// The ones' complement sum of `bytes`, from `acc`.
fn ones(bytes: &[u8], mut acc: u32) -> u32 {
    for w in bytes.chunks(2) {
        acc += u32::from(u16::from_be_bytes([w[0], *w.get(1).unwrap_or(&0)]));
        acc = (acc & 0xffff) + (acc >> 16);
    }
    acc
}

/// Whether a ones' complement sum (header or pseudo-header and payload) checks out.
fn sums_to_zero(acc: u32) -> bool {
    let mut acc = acc;
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    acc == 0xffff
}

/// The verdicts on one IP packet: `wire` from its header to the end of the frame, of which the
/// enclosing headers vouch for `limit` bytes; and, for an outer VXLAN packet, the same for its
/// inner frame.
fn level(wire: &[u8], limit: usize) -> (u64, Option<(&[u8], usize)>) {
    let Some(&first) = wire.first() else {
        return (0, None);
    };
    let mut verdict = 0;
    // How much of `wire` the packet's own header vouches for (what encloses it, if layer 3
    // fails), the protocol, whether a fragment and a later one, the pseudo-header's sum without
    // the length, where the transport header is, and what a UDP length is held to.
    let (bounded, proto, fragment, later, pseudo, header, udp_room) = match first >> 4 {
        4 => {
            let ihl = usize::from(first & 0xf) * 4;
            if ihl < 20 || wire.len() < ihl {
                return (0, None);
            }
            if sums_to_zero(ones(&wire[..ihl], 0)) {
                verdict |= IPV4_CSUM_OK;
            }
            let total = usize::from(be16(wire, 2));
            let bounded = if total >= ihl && total <= limit {
                verdict |= L3_OK;
                total
            } else {
                limit
            };
            let frag = be16(wire, 6);
            let pseudo = ones(&wire[12..20], u32::from(wire[9]));
            let (fragment, later) = (frag & 0x3fff != 0, frag & 0x1fff != 0);
            (
                bounded,
                wire[9],
                fragment,
                later,
                pseudo,
                ihl,
                bounded.saturating_sub(ihl),
            )
        }
        6 => {
            if wire.len() < 40 {
                return (0, None);
            }
            let total = 40 + usize::from(be16(wire, 4));
            let bounded = if total <= limit {
                verdict |= L3_OK;
                total
            } else {
                limit
            };
            // mlx5 walks the extension headers, in any order and number, up to a fragment
            // header. One running past the packet fails every verdict.
            let (mut next, mut at, mut fragment, mut later) = (wire[6], 40, false, false);
            while !fragment
                && matches!(
                    next,
                    HOP_BY_HOP | ROUTING | DESTINATION_OPTIONS | MOBILITY | FRAGMENT
                )
            {
                let Some(ext) = wire.get(at..at + 8).filter(|_| at + 8 <= bounded) else {
                    return (0, None);
                };
                if next == FRAGMENT {
                    fragment = true;
                    later |= be16(ext, 2) & 0xfff8 != 0;
                    at += 8;
                } else {
                    at += 8 + usize::from(ext[1]) * 8;
                }
                if at > bounded {
                    return (0, None);
                }
                next = ext[0];
            }
            let pseudo = ones(&wire[8..40], u32::from(next));
            // mlx5 holds a UDP length to the IPv6 payload length as if there were no extension
            // headers: up to their length too long passes.
            (bounded, next, fragment, later, pseudo, at, bounded - 40)
        }
        _ => return (0, None),
    };
    let (Some(l4), Some(vouched)) = (wire.get(header..), bounded.checked_sub(header)) else {
        return (verdict, None);
    };
    // The checksum covers what the transport header says it does, of what is on the wire.
    let sum_ok = |length: usize| {
        let length32 = u32::try_from(length).unwrap_or(u32::MAX);
        sums_to_zero(ones(&l4[..length.min(l4.len())], pseudo + length32))
    };
    match proto {
        _ if later => {}
        // A first fragment's transport checksum covers the whole datagram: mlx5 says it holds,
        // and never that the transport header is consistent.
        _ if fragment => verdict |= L4_CSUM_OK,
        UDP if l4.len() >= 8 => {
            let length = usize::from(be16(l4, 4));
            let csum_ok = be16(l4, 6) == 0 || (length >= 8 && sum_ok(length));
            if csum_ok {
                verdict |= L4_CSUM_OK;
            }
            // mlx5's "consistent" includes the checksum, and the datagram must be within what
            // the IP header vouches for (bytes after it are fine, as for Linux).
            if csum_ok && (8..=udp_room).contains(&length) {
                verdict |= L4_OK;
            }
            if be16(l4, 2) == VXLAN_PORT && l4.len() >= 16 {
                return (verdict, Some((&l4[16..], vouched.saturating_sub(16))));
            }
        }
        TCP if l4.len() >= 20 => {
            let offset = usize::from(l4[12] >> 4) * 4;
            if sum_ok(vouched) {
                verdict |= L4_CSUM_OK;
                if (20..=vouched).contains(&offset) {
                    verdict |= L4_OK;
                }
            }
        }
        _ => {}
    }
    (verdict, None)
}

/// The integrity verdicts a NIC gives a frame, outer then inner, as measured on a BlueField-3
/// (`nic-offload`'s `integrity_truth_table`):
///
/// - layer 3: a sane IPv4 header length, and a total length (or IPv6 payload length) within
///   what the enclosing headers vouch for (the frame, at the outer level), a shorter one being
///   padding; IPv6 extension headers (hop-by-hop, routing, destination options, mobility, in
///   any order, up to a fragment header) within it too, or no verdict holds; the IPv4 header
///   checksum is a verdict of its own, and never holds for IPv6;
/// - layer 4, for TCP and UDP only: the checksum, over the bytes the UDP length says (a zero
///   UDP checksum holds, IPv4 or IPv6); and "consistent", which also needs the checksum and a
///   UDP datagram within what the IP header vouches for (for IPv6, its payload length, the
///   extension headers not subtracted), or a TCP header within that. A first
///   fragment's checksum is said to hold, and no fragment is consistent;
/// - the inner level is the frame inside an outer VXLAN packet, vouched for by the outer IP
///   header; when the outer layer 3 fails, only the inner checksum is judged;
/// - VLAN tags are skipped at either level.
#[must_use]
pub fn verdicts(bytes: &[u8]) -> [u64; 2] {
    let ip = |frame: &[u8]| -> Option<usize> {
        let mut at = 12;
        loop {
            let ether_type = u16::from_be_bytes([*frame.get(at)?, *frame.get(at + 1)?]);
            if matches!(ether_type, ETH_P_CVLAN | ETH_P_SVLAN) {
                at += 4;
                continue;
            }
            return matches!(ether_type, ETH_P_IPV4 | ETH_P_IPV6).then_some(at + 2);
        }
    };
    let Some(at) = ip(bytes) else {
        return [0, 0];
    };
    let wire = &bytes[at..];
    let (outer, inner) = level(wire, wire.len());
    let inner = inner
        .and_then(|(frame, limit)| {
            let at = ip(frame)?;
            let (verdict, _) = level(&frame[at..], limit.saturating_sub(at));
            Some(if outer & L3_OK == 0 {
                verdict & L4_CSUM_OK
            } else {
                verdict
            })
        })
        .unwrap_or(0);
    [outer, inner]
}

fn take<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    bytes.get(..N)?.try_into().ok()
}

fn be16(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

/// Prefix `header` to every continuation.
fn then(header: Header, rest: Vec<Vec<Header>>) -> Vec<Vec<Header>> {
    rest.into_iter()
        .map(|mut tail| {
            tail.insert(0, header.clone());
            tail
        })
        .collect()
}

/// The first tag after an Ethernet header, as mlx5 hardware steering classifies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirstTag {
    None,
    /// 802.1Q.
    Customer,
    /// 802.1ad.
    Service,
}

/// An Ethernet header and what follows; `outer` is whether a VXLAN header may follow.
fn eth(bytes: &[u8], outer: bool, parser: Parser) -> Vec<Vec<Header>> {
    let Some(header) = take::<14>(bytes) else {
        return vec![Vec::new()];
    };
    let mut at = 14;
    let mut ether_type = be16(&header, 12);
    let mut tags = Vec::new();
    while matches!(ether_type, ETH_P_CVLAN | ETH_P_SVLAN) {
        let Some(tag) = take::<4>(&bytes[at..]) else {
            break;
        };
        tags.push(if ether_type == ETH_P_CVLAN {
            Header::Vlan(tag)
        } else {
            Header::ServiceTag(tag)
        });
        ether_type = be16(&tag, 2);
        at += 4;
    }
    let rest = &bytes[at..];
    let tails = match ether_type {
        ETH_P_IPV4 => ipv4(rest, outer, parser),
        ETH_P_IPV6 => ipv6(rest, outer, parser),
        _ => vec![Vec::new()],
    };
    let tagged = match tags.first() {
        None => FirstTag::None,
        Some(Header::Vlan(_)) => FirstTag::Customer,
        Some(_) => FirstTag::Service,
    };
    // Seen with its tags.
    let mut with_tags = tails.clone();
    for tag in tags.iter().rev() {
        with_tags = then(tag.clone(), with_tags);
    }
    let mut views = then(Header::Eth(header, tagged), with_tags);
    if !tags.is_empty() {
        // Seen past its tags, a frame's EtherType is the one after them.
        let mut past = header;
        past[12..14].copy_from_slice(&ether_type.to_be_bytes());
        views.extend(then(Header::Eth(past, tagged), tails));
    }
    views
}

fn ipv4(bytes: &[u8], outer: bool, parser: Parser) -> Vec<Vec<Header>> {
    let Some(header) = take::<20>(bytes) else {
        return vec![Vec::new()];
    };
    let ihl = usize::from(header[0] & 0xf) * 4;
    if header[0] >> 4 != 4 || ihl < 20 || bytes.len() < ihl {
        return vec![vec![Header::Ipv4(header)]];
    }
    let later_fragment = be16(&header, 6) & 0x1fff != 0;
    let tails = transport(&bytes[ihl..], header[9], outer, parser);
    let tails = if later_fragment {
        // A NIC may or may not parse a later fragment's payload as a transport header.
        let mut both = vec![Vec::new()];
        both.extend(tails);
        both
    } else {
        tails
    };
    then(Header::Ipv4(header), tails)
}

fn ipv6(bytes: &[u8], outer: bool, parser: Parser) -> Vec<Vec<Header>> {
    let Some(header) = take::<40>(bytes) else {
        return vec![Vec::new()];
    };
    if header[0] >> 4 != 6 {
        return vec![vec![Header::Ipv6(header, false)]];
    }
    // The extension headers, as far as they parse.
    let (mut next, mut at) = (header[6], 40);
    let (mut fragment, mut later_fragment, mut walked) = (false, false, true);
    while matches!(next, HOP_BY_HOP | ROUTING | DESTINATION_OPTIONS | FRAGMENT) {
        let Some(ext) = bytes.get(at..).and_then(take::<8>) else {
            walked = false;
            break;
        };
        if next == FRAGMENT {
            fragment = true;
            later_fragment |= be16(&ext, 2) & 0xfff8 != 0;
            at += 8;
        } else {
            at += 8 + usize::from(ext[1]) * 8;
        }
        next = ext[0];
        // A later fragment's payload is data, not more headers.
        if later_fragment {
            break;
        }
    }
    walked &= at <= bytes.len();
    // A NIC that does not walk the extension headers sees the transport header only right after
    // the fixed header.
    let unwalked = || {
        then(
            Header::Ipv6(header, fragment),
            transport(&bytes[40..], header[6], outer, parser),
        )
    };
    if !walked || at == 40 {
        return unwalked();
    }
    let mut views = match parser.ipv6_extensions {
        Ipv6Extensions::Any => unwalked(),
        Ipv6Extensions::WalkedToLast => Vec::new(),
    };
    // One that walks them may also match `proto` on the last next header.
    let mut tails = transport(&bytes[at..], next, outer, parser);
    if later_fragment {
        tails.push(Vec::new());
    }
    let mut last = header;
    last[6] = next;
    let protos: &[[u8; 40]] = match parser.ipv6_extensions {
        Ipv6Extensions::Any => &[header, last],
        Ipv6Extensions::WalkedToLast => &[last],
    };
    for &header in protos {
        for view in then(Header::Ipv6(header, fragment), tails.clone()) {
            if !views.contains(&view) {
                views.push(view);
            }
        }
    }
    views
}

fn transport(bytes: &[u8], proto: u8, outer: bool, parser: Parser) -> Vec<Vec<Header>> {
    match proto {
        UDP => {
            let Some(header) = take::<8>(bytes) else {
                return vec![Vec::new()];
            };
            let tails = match take::<8>(&bytes[8..]) {
                Some(vxlan) if outer && be16(&header, 2) == VXLAN_PORT => {
                    then(Header::Vxlan(vxlan), eth(&bytes[16..], false, parser))
                }
                _ => vec![Vec::new()],
            };
            then(Header::Udp(header), tails)
        }
        TCP => match take::<20>(bytes) {
            Some(header) => vec![vec![Header::Tcp(header)]],
            None => vec![Vec::new()],
        },
        _ => vec![Vec::new()],
    }
}

/// The bytes of a header structure. Only for the padding-free headers asserted above.
fn raw<T>(header: &T) -> &[u8] {
    // SAFETY: `T` is a packed wire header with no padding, so every byte is initialized.
    unsafe { core::slice::from_raw_parts(core::ptr::from_ref(header).cast(), size_of::<T>()) }
}

fn masked_eq(spec: &[u8], mask: &[u8], value: &[u8]) -> bool {
    spec.iter()
        .zip(mask)
        .zip(value)
        .all(|((s, m), v)| s & m == v & m)
}

fn bitfields_unset(bits: &[u8], what: &'static str) -> Result<(), Unmodelled> {
    if bits.iter().all(|&b| b == 0) {
        Ok(())
    } else {
        Err(Unmodelled(what))
    }
}

fn eth_hdr(item: &rte_flow_item_eth) -> &rte_ether_hdr {
    // SAFETY: both members of the union are plain bytes of the same header.
    unsafe { &item.annon1.hdr }
}

fn vlan_hdr(item: &rte_flow_item_vlan) -> &rte_vlan_hdr {
    // SAFETY: both members of the union are plain bytes of the same header.
    unsafe { &item.annon1.hdr }
}

/// The flag bits after a header (VLAN and extension header presence): a byte array.
fn bitfields<T>(unit: &dpdk_sys::__BindgenBitfieldUnit<T>) -> &[u8] {
    // SAFETY: a bitfield unit is `repr(C)` over a byte array.
    unsafe { core::slice::from_raw_parts(core::ptr::from_ref(unit).cast(), size_of_val(unit)) }
}

impl MatchItem {
    /// Whether this item matches `header`, at the same position.
    fn matches(&self, header: &Header) -> Result<bool, Unmodelled> {
        Ok(match (self, header) {
            (MatchItem::Eth(spec, mask), Header::Eth(value, tagged)) => {
                if mask.reserved() != 0 {
                    return Err(Unmodelled("reserved bits"));
                }
                let has_vlan = match tagged {
                    FirstTag::None => Some(0),
                    FirstTag::Customer => Some(1),
                    FirstTag::Service => None,
                };
                (mask.has_vlan() == 0 || has_vlan == Some(spec.has_vlan()))
                    && masked_eq(raw(eth_hdr(spec)), raw(eth_hdr(mask)), value)
            }
            (MatchItem::Vlan(spec, mask), Header::Vlan(value)) => {
                bitfields_unset(bitfields(&mask._bitfield_1), "inner VLAN presence")?;
                masked_eq(raw(vlan_hdr(spec)), raw(vlan_hdr(mask)), value)
            }
            (MatchItem::Ipv4(spec, mask), Header::Ipv4(value)) => {
                masked_eq(raw(&spec.hdr), raw(&mask.hdr), value)
            }
            (MatchItem::Ipv6(spec, mask), Header::Ipv6(value, fragment)) => {
                let mut others = *mask;
                others.set_has_frag_ext(0);
                bitfields_unset(bitfields(&others._bitfield_1), "extension header presence")?;
                (mask.has_frag_ext() == 0 || spec.has_frag_ext() == u32::from(*fragment))
                    && masked_eq(raw(&spec.hdr), raw(&mask.hdr), value)
            }
            (MatchItem::Udp(spec, mask), Header::Udp(value)) => {
                masked_eq(raw(&spec.hdr), raw(&mask.hdr), value)
            }
            (MatchItem::Tcp(spec, mask), Header::Tcp(value)) => {
                masked_eq(raw(&spec.hdr), raw(&mask.hdr), value)
            }
            (MatchItem::Vxlan(spec, mask), Header::Vxlan(value)) => {
                // SAFETY: both members of the union are plain bytes of the same header.
                let (spec, mask) = unsafe { (&spec.annon1.hdr, &mask.annon1.hdr) };
                masked_eq(raw(spec), raw(mask), value)
            }
            _ => false,
        })
    }
}

impl<Pos> Pattern<Pos> {
    /// Whether this pattern matches `frame` as one NIC parser saw it, with `color` the color an
    /// earlier meter gave the packet, if any.
    ///
    /// Items match the frame's headers position by position, outermost first; a pattern may stop
    /// before the frame does. A meter color item matches the color, not a header.
    ///
    /// # Errors
    ///
    /// Returns [`Unmodelled`] if the pattern constrains something the model does not parse.
    pub fn matches(&self, frame: &Frame, color: Option<Color>) -> Result<bool, Unmodelled> {
        let mut headers = frame.headers.iter();
        for item in &self.items {
            if let MatchItem::Integrity(spec, mask) = item {
                // SAFETY: both members of the union are the same 64 bits.
                let (spec, mask_bits) = unsafe { (spec.annon1.value, mask.annon1.value) };
                let level = usize::from(mask.level != 0);
                let required = spec & mask_bits;
                if frame.verdicts[level] & required != required {
                    return Ok(false);
                }
                continue;
            }
            if let MatchItem::MeterColor(spec, mask) = item {
                let Some(color) = color else {
                    return Ok(false);
                };
                if (color.raw() ^ spec.color) & mask.color != 0 {
                    return Ok(false);
                }
                continue;
            }
            match headers.next() {
                Some(header) if item.matches(header)? => {}
                _ => return Ok(false),
            }
        }
        Ok(true)
    }

    /// Whether this pattern may match `bytes`: whether it matches some way a NIC might parse them.
    ///
    /// # Errors
    ///
    /// Returns [`Unmodelled`] if the pattern constrains something the model does not parse.
    pub fn may_match(&self, bytes: &[u8], color: Option<Color>) -> Result<bool, Unmodelled> {
        for frame in views(bytes) {
            if self.matches(&frame, color)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::template::Complete;
    use crate::flow::{EthMatch, Ipv4Match, Ipv4Prefix, UdpMatch, VxlanMatch};
    use core::net::Ipv4Addr;
    use net::vxlan::Vni;

    /// An inner IPv4 frame to `dst`, with `proto` and a transport header carrying `dst_port`,
    /// fragment offset `offset` (in 8-byte units).
    fn inner(dst: [u8; 4], proto: u8, dst_port: u16, offset: u16) -> Vec<u8> {
        let mut f = vec![0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00];
        let frag = offset.to_be_bytes();
        f.extend([0x45, 0, 0, 36, 0, 1, frag[0], frag[1], 64, proto, 0, 0]);
        f.extend([10, 0, 0, 1]);
        f.extend(dst);
        let port = dst_port.to_be_bytes();
        f.extend([0x30, 0x39, port[0], port[1], 0, 16, 0, 0]);
        f.extend([0; 8]);
        f
    }

    fn vxlan(vni: u32, inner: &[u8]) -> Vec<u8> {
        let mut f = vec![0x02, 0, 0, 0, 0, 4, 0x02, 0, 0, 0, 0, 3, 0x08, 0x00];
        f.extend([
            0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2,
        ]);
        f.extend([0xc0, 0x00, 0x12, 0xb5, 0, 0, 0, 0]);
        let v = vni.to_be_bytes();
        f.extend([0x08, 0, 0, 0, v[1], v[2], v[3], 0]);
        f.extend(inner);
        f
    }

    fn tunnel(vni: u32) -> Pattern<crate::flow::template::InnerEth> {
        Pattern::new()
            .eth(EthMatch::default())
            .ipv4(Ipv4Match::default())
            .udp(UdpMatch::default().dst(VXLAN_PORT))
            .vxlan(VxlanMatch::default().vni(Vni::new_checked(vni).unwrap()))
            .inner_eth(EthMatch::default())
    }

    fn rule(vni: u32, dst: [u8; 4], len: u8, port: Option<u16>) -> Pattern<Complete> {
        let ip = tunnel(vni).ipv4(
            Ipv4Match::default()
                .dst(Ipv4Prefix::prefix(Ipv4Addr::from(dst), len))
                .proto(17),
        );
        match port {
            Some(port) => ip.udp(UdpMatch::default().dst(port)).complete(),
            None => ip.complete(),
        }
    }

    #[test]
    fn vni_prefix_proto_and_port_all_count() {
        let frame = vxlan(100, &inner([10, 1, 2, 3], 17, 80, 0));
        let may = |p: &Pattern<Complete>| p.may_match(&frame, None).unwrap();
        assert!(may(&rule(100, [10, 1, 0, 0], 16, Some(80))));
        assert!(may(&rule(100, [10, 1, 2, 3], 32, None)));
        assert!(!may(&rule(101, [10, 1, 0, 0], 16, Some(80))));
        assert!(!may(&rule(100, [10, 2, 0, 0], 16, Some(80))));
        assert!(!may(&rule(100, [10, 1, 0, 0], 16, Some(81))));
        let tcp = vxlan(100, &inner([10, 1, 2, 3], 6, 80, 0));
        assert!(
            !rule(100, [10, 1, 0, 0], 16, None)
                .may_match(&tcp, None)
                .unwrap()
        );
    }

    /// A later fragment carries the protocol in its IP header but no transport header: the
    /// protocol still matches, and ports may or may not, depending on the NIC.
    #[test]
    fn later_fragments_match_the_protocol_and_maybe_ports() {
        let frame = vxlan(100, &inner([10, 1, 2, 3], 17, 80, 100));
        let frames = views(&frame);
        let port = rule(100, [10, 1, 0, 0], 16, Some(80));
        let matches: Vec<bool> = frames
            .iter()
            .map(|f| port.matches(f, None).unwrap())
            .collect();
        assert!(matches.contains(&true) && matches.contains(&false));
        assert!(
            rule(100, [10, 1, 0, 0], 16, None)
                .may_match(&frame, None)
                .unwrap()
        );
    }

    #[test]
    fn only_the_tunnel_port_is_parsed_as_vxlan() {
        let mut frame = vxlan(100, &inner([10, 1, 2, 3], 17, 80, 0));
        frame[36..38].copy_from_slice(&4790u16.to_be_bytes());
        let deeper = Pattern::new()
            .eth(EthMatch::default())
            .ipv4(Ipv4Match::default())
            .udp(UdpMatch::default())
            .vxlan(VxlanMatch::default())
            .complete();
        assert!(!deeper.may_match(&frame, None).unwrap());
    }

    /// Without `has_vlan` a tagged inner frame may match; with it, never.
    #[test]
    fn has_vlan_decides_what_vlan_items_leave_open() {
        let mut tagged = inner([10, 1, 2, 3], 17, 80, 0);
        tagged.splice(12..12, [0x81, 0x00, 0x00, 0x05]);
        let frame = vxlan(100, &tagged);
        let open = Pattern::new()
            .eth(EthMatch::default())
            .ipv4(Ipv4Match::default())
            .udp(UdpMatch::default().dst(VXLAN_PORT))
            .vxlan(VxlanMatch::default())
            .inner_eth(EthMatch::default())
            .ipv4(Ipv4Match::default())
            .complete();
        let untagged = Pattern::new()
            .eth(EthMatch::default())
            .ipv4(Ipv4Match::default())
            .udp(UdpMatch::default().dst(VXLAN_PORT))
            .vxlan(VxlanMatch::default())
            .inner_eth(EthMatch::default().tagged(false))
            .ipv4(Ipv4Match::default())
            .complete();
        assert!(open.may_match(&frame, None).unwrap());
        assert!(!untagged.may_match(&frame, None).unwrap());
        let plain = vxlan(100, &inner([10, 1, 2, 3], 17, 80, 0));
        assert!(untagged.may_match(&plain, None).unwrap());
    }

    #[test]
    fn meter_colors_match_only_their_own_color() {
        let frame = views(&[]).pop().unwrap();
        for c in Color::ALL {
            for d in Color::ALL {
                assert_eq!(
                    Pattern::meter_color(c).matches(&frame, Some(d)).unwrap(),
                    c == d
                );
            }
            assert!(!Pattern::meter_color(c).matches(&frame, None).unwrap());
        }
    }

    /// Garbage never panics, and the empty pattern matches every frame.
    #[test]
    fn any_bytes_parse() {
        bolero::check!().with_type::<Vec<u8>>().for_each(|bytes| {
            let frames = views(bytes);
            assert!(!frames.is_empty());
            for frame in &frames {
                assert!(Pattern::new().matches(frame, None).unwrap());
            }
        });
    }

    /// An 802.1ad tag is no VLAN to a NIC, nor is it no tag: `has_vlan` set or unset never matches
    /// a frame whose first tag is one, and no VLAN item matches it.
    #[test]
    fn a_service_tag_is_not_a_vlan() {
        let mut stagged = inner([10, 1, 2, 3], 17, 80, 0);
        stagged.splice(12..12, [0x88, 0xa8, 0x00, 0x05]);
        let frame = vxlan(100, &stagged);
        let tunnel = || {
            Pattern::new()
                .eth(EthMatch::default())
                .ipv4(Ipv4Match::default())
                .udp(UdpMatch::default().dst(VXLAN_PORT))
                .vxlan(VxlanMatch::default())
        };
        let untagged = tunnel()
            .inner_eth(EthMatch::default().tagged(false))
            .ipv4(Ipv4Match::default())
            .complete();
        let tagged = tunnel()
            .inner_eth(EthMatch::default().tagged(true))
            .complete();
        assert!(!untagged.may_match(&frame, None).unwrap());
        assert!(!tagged.may_match(&frame, None).unwrap());
    }

    /// On legal frames, one of the model's views has the headers the `net` parser finds, at the
    /// same offsets: the model parses where software does. (It does not walk the authentication
    /// header, so frames with one are left out.)
    #[test]
    fn a_view_agrees_with_the_net_parser() {
        use net::headers::{Net, NetExt, ShapedHeaders, Transport};
        use net::parse::{DeParse, Parse};
        bolero::check!()
            .with_generator(ShapedHeaders)
            .for_each(|headers| {
                let size = usize::from(headers.size().get());
                let mut bytes = vec![0u8; size + 64];
                if headers.deparse(&mut bytes).is_err() {
                    return;
                }
                // What `net` finds in the bytes, rather than what was generated.
                let Ok((parsed, _)) = net::headers::Headers::parse(&bytes) else {
                    return;
                };
                if parsed
                    .net_ext()
                    .iter()
                    .any(|e| matches!(e, NetExt::Ipv4Auth(_) | NetExt::Ipv6Auth(_)))
                {
                    return;
                }
                let mut expected = Vec::new();
                let mut at = 0;
                let Some(eth) = parsed.eth() else { return };
                let first_tag = be16(&bytes, 12);
                expected.push(Header::Eth(
                    take::<14>(&bytes).unwrap_or_else(|| unreachable!()),
                    match (parsed.vlan().is_empty(), first_tag) {
                        (true, _) => FirstTag::None,
                        (false, ETH_P_CVLAN) => FirstTag::Customer,
                        (false, _) => FirstTag::Service,
                    },
                ));
                at += usize::from(eth.size().get());
                let mut tpid = first_tag;
                for vlan in parsed.vlan() {
                    let tag = take::<4>(&bytes[at..]).unwrap_or_else(|| unreachable!());
                    expected.push(if tpid == ETH_P_CVLAN {
                        Header::Vlan(tag)
                    } else {
                        Header::ServiceTag(tag)
                    });
                    tpid = be16(&tag, 2);
                    at += usize::from(vlan.size().get());
                }
                let fragment = parsed
                    .net_ext()
                    .iter()
                    .any(|e| matches!(e, NetExt::Fragment(_)));
                // Whether the chain reached a later fragment, past which a NIC does not parse
                // (where `net` may still take the payload for a transport header).
                let mut later = false;
                match parsed.net() {
                    Some(Net::Ipv4(ip)) => {
                        expected.push(Header::Ipv4(
                            take::<20>(&bytes[at..]).unwrap_or_else(|| unreachable!()),
                        ));
                        at += usize::from(ip.size().get());
                    }
                    Some(Net::Ipv6(ip)) => {
                        let mut header = take::<40>(&bytes[at..]).unwrap_or_else(|| unreachable!());
                        at += usize::from(ip.size().get());
                        let mut next = header[6];
                        for ext in parsed.net_ext() {
                            next = bytes[at];
                            // A NIC stops at a later fragment: what follows is the fragment's data.
                            if matches!(ext, NetExt::Fragment(_))
                                && be16(&bytes, at + 2) & 0xfff8 != 0
                            {
                                later = true;
                                break;
                            }
                            at += usize::from(ext.size().get());
                        }
                        // Where `net` stops walking with another extension header next (it bounds the
                        // chain), the model walks on: no common ground.
                        if !later
                            && matches!(next, HOP_BY_HOP | ROUTING | DESTINATION_OPTIONS | FRAGMENT)
                        {
                            return;
                        }
                        // A NIC that walks the chain may match `proto` on the last next header.
                        if !parsed.net_ext().is_empty() {
                            header[6] = next;
                        }
                        expected.push(Header::Ipv6(header, fragment));
                    }
                    None => {}
                }
                match parsed.transport().filter(|_| !later) {
                    Some(Transport::Udp(_)) => expected.push(Header::Udp(
                        take::<8>(&bytes[at..]).unwrap_or_else(|| unreachable!()),
                    )),
                    Some(Transport::Tcp(_)) => expected.push(Header::Tcp(
                        take::<20>(&bytes[at..]).unwrap_or_else(|| unreachable!()),
                    )),
                    _ => {}
                }
                let views = views(&bytes);
                assert!(
                    views.iter().any(|view| view.headers.starts_with(&expected)),
                    "no view starts with {expected:02x?}\nviews: {views:02x?}\nbytes: {bytes:02x?}"
                );
            });
    }
}
