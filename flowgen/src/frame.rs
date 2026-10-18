// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Building the frames a stream sends, and reading the ones that come back.
//!
//! Each flow's frame is built once, as a [`Template`]; sending a packet stamps the template with
//! its sequence number and send time and updates the one checksum that covers them, which is
//! cheap enough to do at line rate. Frames are Ethernet, IPv4 and UDP, optionally inside VXLAN.
//!
//! Both directions are written here, byte by byte, rather than with the dataplane's own header
//! code: a generator that shared the dataplane's parser would share its bugs, and agree with it.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::checksum;
use crate::signature::{self, Signature};
use crate::space::{self, Tuple};

const ETH_LEN: usize = 14;
const IPV4_LEN: usize = 20;
const UDP_LEN: usize = 8;
const VXLAN_LEN: usize = 8;
const ETHERTYPE_IPV4: u16 = 0x0800;
const PROTO_UDP: u8 = 17;

/// The UDP port VXLAN is sent to ([RFC 7348]).
///
/// [RFC 7348]: https://www.rfc-editor.org/rfc/rfc7348
pub const VXLAN_PORT: u16 = 4789;

/// A MAC address.
pub type Mac = [u8; 6];

/// The tunnel a stream's frames travel in, as the VTEP sending them would build it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vxlan {
    /// The VNI.
    pub vni: u32,
    /// The sending VTEP's MAC.
    pub src_mac: Mac,
    /// The next hop's MAC: the gateway's.
    pub dst_mac: Mac,
    /// The sending VTEP.
    pub src: Ipv4Addr,
    /// The receiving VTEP: the gateway.
    pub dst: Ipv4Addr,
}

/// Everything about a stream's frames but the flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameSpec {
    /// The inner frame's source MAC.
    pub src_mac: Mac,
    /// The inner frame's destination MAC.
    pub dst_mac: Mac,
    /// The tunnel, if the frames travel in one.
    pub vxlan: Option<Vxlan>,
    /// The inner UDP payload's length, signature included; at least [`signature::LEN`].
    pub payload_len: u16,
    /// The inner packet's TTL.
    pub ttl: u8,
}

/// One flow's frame, ready to stamp and send.
#[derive(Debug, Clone)]
pub struct Template {
    bytes: Vec<u8>,
    /// Where the signature starts.
    signature: usize,
    /// Where the inner UDP checksum is.
    udp_checksum: usize,
}

impl Template {
    /// The frame for `flow`, the `number`th flow of its stream in run `run`, built to `spec`.
    #[must_use]
    pub fn new(spec: &FrameSpec, run: u32, number: u64, flow: &Tuple) -> Template {
        let payload_len = usize::from(spec.payload_len).max(signature::LEN);
        let inner_len = ETH_LEN + IPV4_LEN + UDP_LEN + payload_len;
        let outer_len = spec
            .vxlan
            .map_or(0, |_| ETH_LEN + IPV4_LEN + UDP_LEN + VXLAN_LEN);
        let mut bytes = vec![0u8; outer_len + inner_len];

        if let Some(vxlan) = spec.vxlan {
            let (outer, _) = bytes.split_at_mut(outer_len);
            ethernet(&mut outer[..ETH_LEN], vxlan.dst_mac, vxlan.src_mac);
            ipv4(
                &mut outer[ETH_LEN..ETH_LEN + IPV4_LEN],
                vxlan.src,
                vxlan.dst,
                64,
                UDP_LEN + VXLAN_LEN + inner_len,
            );
            // Entropy in the source port, as VTEPs do, so that the underlay spreads flows.
            let sport = 0xc000 | (space::hash(flow) & 0x3fff) as u16;
            let udp = &mut outer[ETH_LEN + IPV4_LEN..ETH_LEN + IPV4_LEN + UDP_LEN];
            udp_header(udp, sport, VXLAN_PORT, UDP_LEN + VXLAN_LEN + inner_len);
            // A zero checksum: VXLAN's UDP checksum SHOULD be zero (RFC 7348 section 5).
            let vx = &mut outer[ETH_LEN + IPV4_LEN + UDP_LEN..];
            vx[0] = 0x08; // the VNI is valid
            vx[4..7].copy_from_slice(&vxlan.vni.to_be_bytes()[1..]);
        }

        let inner = &mut bytes[outer_len..];
        ethernet(&mut inner[..ETH_LEN], spec.dst_mac, spec.src_mac);
        ipv4(
            &mut inner[ETH_LEN..ETH_LEN + IPV4_LEN],
            flow.src,
            flow.dst,
            spec.ttl,
            UDP_LEN + payload_len,
        );
        let udp_at = ETH_LEN + IPV4_LEN;
        udp_header(
            &mut inner[udp_at..udp_at + UDP_LEN],
            flow.sport,
            flow.dport,
            UDP_LEN + payload_len,
        );
        let payload = &mut inner[udp_at + UDP_LEN..];
        Signature {
            run,
            flow: number,
            seq: 0,
            tx_ns: 0,
        }
        .write(payload);
        fill(payload);
        let checksum = checksum::udp_ipv4(flow.src, flow.dst, &inner[udp_at..]);
        inner[udp_at + 6..udp_at + 8].copy_from_slice(&checksum.to_be_bytes());

        Template {
            bytes,
            signature: outer_len + udp_at + UDP_LEN,
            udp_checksum: outer_len + udp_at + 6,
        }
    }

    /// Stamp the frame as packet `seq` of its flow, sent at `tx_ns`.
    pub fn stamp(&mut self, seq: u64, tx_ns: u64) {
        // The sequence number and time are the signature's last 16 bytes, at an even offset into
        // the datagram, so the checksum can be updated for them alone.
        let at = self.signature + 16;
        let mut old = [0u8; 16];
        old.copy_from_slice(&self.bytes[at..at + 16]);
        let mut new = [0u8; 16];
        new[..8].copy_from_slice(&seq.to_be_bytes());
        new[8..].copy_from_slice(&tx_ns.to_be_bytes());
        self.bytes[at..at + 16].copy_from_slice(&new);
        let c = self.udp_checksum;
        let checksum = u16::from_be_bytes([self.bytes[c], self.bytes[c + 1]]);
        let checksum = checksum::adjust(checksum, &old, &new);
        self.bytes[c..c + 2].copy_from_slice(&checksum.to_be_bytes());
    }

    /// The frame as last stamped.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

fn ethernet(out: &mut [u8], dst: Mac, src: Mac) {
    out[0..6].copy_from_slice(&dst);
    out[6..12].copy_from_slice(&src);
    out[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
}

/// An IPv4 header without options, carrying `payload_len` bytes of UDP.
fn ipv4(out: &mut [u8], src: Ipv4Addr, dst: Ipv4Addr, ttl: u8, payload_len: usize) {
    let total = u16::try_from(IPV4_LEN + payload_len).unwrap_or(u16::MAX);
    out[0] = 0x45; // version 4, five words
    out[2..4].copy_from_slice(&total.to_be_bytes());
    out[8] = ttl;
    out[9] = PROTO_UDP;
    out[12..16].copy_from_slice(&src.octets());
    out[16..20].copy_from_slice(&dst.octets());
    let checksum = checksum::ipv4_header(out);
    out[10..12].copy_from_slice(&checksum.to_be_bytes());
}

/// A UDP header with a zero checksum.
fn udp_header(out: &mut [u8], sport: u16, dport: u16, len: usize) {
    out[0..2].copy_from_slice(&sport.to_be_bytes());
    out[2..4].copy_from_slice(&dport.to_be_bytes());
    let len = u16::try_from(len).unwrap_or(u16::MAX);
    out[4..6].copy_from_slice(&len.to_be_bytes());
}

/// Fill a payload past its signature with a pattern a reader can check: byte `i` is `i % 256`.
#[allow(clippy::cast_possible_truncation)] // the pattern is the offset's low byte
fn fill(payload: &mut [u8]) {
    for (i, byte) in payload.iter_mut().enumerate().skip(signature::LEN) {
        *byte = (i % 256) as u8;
    }
}

/// Whether a payload past its signature still holds the pattern [`fill`] put there.
#[allow(clippy::cast_possible_truncation)] // the pattern is the offset's low byte
fn filled(payload: &[u8]) -> bool {
    payload
        .iter()
        .enumerate()
        .skip(signature::LEN)
        .all(|(i, &byte)| byte == (i % 256) as u8)
}

/// How a checksum in a received frame came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumState {
    /// Correct.
    Valid,
    /// Wrong.
    Invalid,
    /// Not there: a zero UDP checksum, which means none.
    Absent,
}

/// The tunnel a received frame came in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tunnel {
    /// Its source MAC.
    pub src_mac: Mac,
    /// Its destination MAC.
    pub dst_mac: Mac,
    /// The VTEP that sent it.
    pub src: Ipv4Addr,
    /// The VTEP it was sent to.
    pub dst: Ipv4Addr,
    /// The VNI.
    pub vni: u32,
}

/// What a received frame turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Received {
    /// The tunnel it came in, if any.
    pub tunnel: Option<Tunnel>,
    /// The inner frame's source MAC.
    pub src_mac: Mac,
    /// The inner frame's destination MAC.
    pub dst_mac: Mac,
    /// The inner packet's addresses and ports, as they arrived.
    pub tuple: Tuple,
    /// The inner packet's TTL, as it arrived.
    pub ttl: u8,
    /// The inner IPv4 header checksum.
    pub ip_checksum: ChecksumState,
    /// The inner UDP checksum.
    pub udp_checksum: ChecksumState,
    /// The signature, if the payload carries one.
    pub signature: Option<Signature>,
    /// Whether the payload past the signature is as it was sent.
    pub payload_intact: bool,
}

/// Why a received frame is not one of ours to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// It ends before a header it needs.
    #[error("the frame is too short for its {0} header")]
    Short(&'static str),
    /// It is not IPv4.
    #[error("not IPv4 (ethertype {0:#06x})")]
    NotIpv4(u16),
    /// Its IP header is not version 4, or is shorter than its minimum.
    #[error("a malformed IPv4 header")]
    BadIpv4,
    /// It is not UDP.
    #[error("not UDP (protocol {0})")]
    NotUdp(u8),
    /// It is a fragment, which a stream never sends.
    #[error("an IPv4 fragment")]
    Fragment,
}

/// Read a received frame.
///
/// # Errors
///
/// If the frame is not Ethernet, IPv4 and UDP (optionally inside VXLAN), unfragmented.
pub fn parse(frame: &[u8]) -> Result<Received, ParseError> {
    let outer = Layers::parse(frame)?;
    let (tunnel, inner) = if outer.dport == VXLAN_PORT {
        let vx = outer
            .payload
            .get(..VXLAN_LEN)
            .ok_or(ParseError::Short("VXLAN"))?;
        let vni = u32::from_be_bytes([0, vx[4], vx[5], vx[6]]);
        let inner = Layers::parse(&outer.payload[VXLAN_LEN..])?;
        let tunnel = Tunnel {
            src_mac: outer.src_mac,
            dst_mac: outer.dst_mac,
            src: outer.tuple.src,
            dst: outer.tuple.dst,
            vni,
        };
        (Some(tunnel), inner)
    } else {
        (None, outer)
    };
    Ok(Received {
        tunnel,
        src_mac: inner.src_mac,
        dst_mac: inner.dst_mac,
        tuple: inner.tuple,
        ttl: inner.ttl,
        ip_checksum: inner.ip_checksum,
        udp_checksum: inner.udp_checksum,
        signature: Signature::read(inner.payload),
        payload_intact: filled(inner.payload),
    })
}

/// One Ethernet, IPv4 and UDP header stack.
struct Layers<'f> {
    src_mac: Mac,
    dst_mac: Mac,
    tuple: Tuple,
    dport: u16,
    ttl: u8,
    ip_checksum: ChecksumState,
    udp_checksum: ChecksumState,
    payload: &'f [u8],
}

impl<'f> Layers<'f> {
    fn parse(frame: &'f [u8]) -> Result<Layers<'f>, ParseError> {
        let eth = frame.get(..ETH_LEN).ok_or(ParseError::Short("Ethernet"))?;
        let mac = |at: usize| {
            let mut m = [0; 6];
            m.copy_from_slice(&eth[at..at + 6]);
            m
        };
        let ethertype = u16::from_be_bytes([eth[12], eth[13]]);
        if ethertype != ETHERTYPE_IPV4 {
            return Err(ParseError::NotIpv4(ethertype));
        }
        let ip = &frame[ETH_LEN..];
        let first = *ip.first().ok_or(ParseError::Short("IPv4"))?;
        let ihl = usize::from(first & 0x0f) * 4;
        if first >> 4 != 4 || ihl < IPV4_LEN {
            return Err(ParseError::BadIpv4);
        }
        let header = ip.get(..ihl).ok_or(ParseError::Short("IPv4"))?;
        let total = usize::from(u16::from_be_bytes([header[2], header[3]]));
        if total < ihl {
            return Err(ParseError::BadIpv4);
        }
        if u16::from_be_bytes([header[6], header[7]]) & 0x3fff != 0 {
            return Err(ParseError::Fragment);
        }
        if header[9] != PROTO_UDP {
            return Err(ParseError::NotUdp(header[9]));
        }
        let ip_checksum = if checksum::finish(checksum::sum(0, header)) == 0 {
            ChecksumState::Valid
        } else {
            ChecksumState::Invalid
        };
        let addr =
            |at: usize| Ipv4Addr::new(header[at], header[at + 1], header[at + 2], header[at + 3]);
        let (src, dst) = (addr(12), addr(16));
        // Ethernet pads short frames; the IP length says where the packet really ends.
        let datagram = ip.get(ihl..total).ok_or(ParseError::Short("UDP"))?;
        let udp = datagram.get(..UDP_LEN).ok_or(ParseError::Short("UDP"))?;
        let sport = u16::from_be_bytes([udp[0], udp[1]]);
        let dport = u16::from_be_bytes([udp[2], udp[3]]);
        let carried = u16::from_be_bytes([udp[6], udp[7]]);
        let udp_checksum = if carried == 0 {
            ChecksumState::Absent
        } else if checksum::udp_ipv4_verifies(src, dst, datagram) {
            ChecksumState::Valid
        } else {
            ChecksumState::Invalid
        };
        Ok(Layers {
            src_mac: mac(6),
            dst_mac: mac(0),
            tuple: Tuple {
                src,
                dst,
                sport,
                dport,
            },
            dport,
            ttl: header[8],
            ip_checksum,
            udp_checksum,
            payload: &datagram[UDP_LEN..],
        })
    }
}
