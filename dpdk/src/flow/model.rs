// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Match frame bytes against the spec and mask structures passed to a PMD.
//!
//! [`views`] includes each supported parser interpretation; a pattern may match if any view matches.
//! Hardware qualification can narrow these choices through [`Parser`] and [`views_by`]:
//!
//! - VLAN parsing may skip tags, independently for outer and inner Ethernet headers.
//!   `has_vlan` set matches a leading 802.1Q tag; unset matches no tag.
//!   A leading 802.1ad tag matches neither, and service tags match no VLAN item.
//! - Later IPv4 fragments may be parsed as transport headers.
//! - IPv6 extension headers may be walked or left unparsed; `proto` may match the fixed header
//!   or the final protocol. `has_frag_ext` is exact.
//!
//! Only UDP port 4789 is parsed as VXLAN.

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
        let frame = Frame { headers };
        if !frames.contains(&frame) {
            frames.push(frame);
        }
    }
    frames
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

/// Whether `value` matches `spec` and `mask`, and the ranges `last` bounds: each 16-bit field at
/// one of `fields` (offsets into the header) where `last` is not zero matches if its masked value
/// is within the masked `spec..=last`; every other bit as [`masked_eq`].
fn ranged_eq(
    spec: &[u8],
    mask: &[u8],
    last: Option<&[u8]>,
    fields: &[usize],
    value: &[u8],
) -> bool {
    let Some(last) = last else {
        return masked_eq(spec, mask, value);
    };
    let ranged: Vec<usize> = fields
        .iter()
        .copied()
        .filter(|&at| be16(last, at) != 0)
        .collect();
    let mut exact = mask.to_vec();
    for &at in &ranged {
        exact[at..at + 2].fill(0);
    }
    masked_eq(spec, &exact, value)
        && ranged.iter().all(|&at| {
            let m = be16(mask, at);
            let v = be16(value, at) & m;
            be16(spec, at) & m <= v && v <= be16(last, at) & m
        })
}

/// Where the fields that may be ranges are, in their headers: the ports.
const PORT_RANGES: &[usize] = &[0, 2];

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
            (MatchItem::Udp(spec, mask, last), Header::Udp(value)) => ranged_eq(
                raw(&spec.hdr),
                raw(&mask.hdr),
                last.as_ref().map(|l| raw(&l.hdr)),
                PORT_RANGES,
                value,
            ),
            (MatchItem::Tcp(spec, mask, last), Header::Tcp(value)) => ranged_eq(
                raw(&spec.hdr),
                raw(&mask.hdr),
                last.as_ref().map(|l| raw(&l.hdr)),
                PORT_RANGES,
                value,
            ),
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
    /// Match one parsed view of `frame`, using `color` from an earlier meter, if any.
    /// Header items match in order, outermost first; the pattern may stop before the frame ends.
    /// Meter color items match metadata.
    ///
    /// # Errors
    ///
    /// Returns [`Unmodelled`] for constraints the model does not parse.
    pub fn matches(&self, frame: &Frame, color: Option<Color>) -> Result<bool, Unmodelled> {
        let mut headers = frame.headers.iter();
        for item in &self.items {
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
    use crate::flow::{EthMatch, Ipv4Match, Ipv4Prefix, PortRange, UdpMatch, VxlanMatch};
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

    /// A port range matches exactly the ports within it, whatever the port; the shape tells a range
    /// from an exact port, so a template takes rules of its own kind only.
    #[test]
    fn port_ranges_match_the_ports_within_them() {
        bolero::check!()
            .with_type::<(u16, u16, u16)>()
            .for_each(|&(a, b, port)| {
                let (lo, hi) = (a.min(b), a.max(b));
                let frame = vxlan(100, &inner([10, 1, 2, 3], 17, port, 0));
                let ranged = tunnel(100)
                    .ipv4(Ipv4Match::default())
                    .udp(UdpMatch::default().dst_range(PortRange::between(b, a)))
                    .complete();
                assert_eq!(
                    ranged.may_match(&frame, None).unwrap(),
                    (lo..=hi).contains(&port),
                    "{lo}..={hi} vs {port}"
                );
                let shape = |m: UdpMatch| {
                    let (spec, mask, last) = m.lower();
                    MatchItem::Udp(spec, mask, last).shape()
                };
                assert_eq!(
                    shape(UdpMatch::default().dst_range(PortRange::between(lo, hi)))
                        == shape(UdpMatch::default().dst(lo)),
                    lo == hi
                );
                // A reversed range is no range: it never stands for every port.
                assert_eq!(PortRange::new(hi, lo).is_some(), lo == hi);
            });
    }

    /// The unfragmented match takes whole packets, and no first, later or last fragment.
    #[test]
    fn unfragmented_takes_no_fragment() {
        // (more fragments, offset): whole, first, later, last.
        for (more, offset) in [(false, 0u16), (true, 0), (true, 100), (false, 100)] {
            let field = offset | if more { 0x2000 } else { 0 };
            let frame = vxlan(100, &inner([10, 1, 2, 3], 17, 80, field));
            let fragment = more || offset != 0;
            let pattern = tunnel(100)
                .ipv4(Ipv4Match::default().unfragmented())
                .complete();
            assert_eq!(
                pattern.may_match(&frame, None).unwrap(),
                !fragment,
                "more fragments {more}, offset {offset}"
            );
        }
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
