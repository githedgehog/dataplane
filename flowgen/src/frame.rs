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
use crate::mutate::{self, Mutation};
use crate::signature::{self, Signature};
use crate::space::{self, Tuple};

const ETH_LEN: usize = 14;
const IPV4_LEN: usize = 20;
const UDP_LEN: usize = 8;
const TCP_LEN: usize = 20;
const VXLAN_LEN: usize = 8;
const ETHERTYPE_IPV4: u16 = 0x0800;
const PROTO_UDP: u8 = 17;
const PROTO_TCP: u8 = 6;

/// TCP flags, as the header's flag byte carries them.
pub mod tcp {
    /// No more data from the sender.
    pub const FIN: u8 = 0x01;
    /// Synchronise sequence numbers: open a connection.
    pub const SYN: u8 = 0x02;
    /// Reset the connection.
    pub const RST: u8 = 0x04;
    /// Push the data to the application.
    pub const PSH: u8 = 0x08;
    /// The acknowledgement number is valid.
    pub const ACK: u8 = 0x10;
}

/// What a stream's packets carry over IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// UDP.
    #[default]
    Udp,
    /// TCP segments with these flags, and nothing else of a connection: no handshake, no
    /// acknowledgements, sequence numbers counting packets.
    Tcp {
        /// The flags every segment carries; see [`tcp`].
        flags: u8,
    },
}

impl Transport {
    fn protocol(self) -> u8 {
        match self {
            Transport::Udp => PROTO_UDP,
            Transport::Tcp { .. } => PROTO_TCP,
        }
    }

    fn header_len(self) -> usize {
        match self {
            Transport::Udp => UDP_LEN,
            Transport::Tcp { .. } => TCP_LEN,
        }
    }
}

/// The UDP port VXLAN is sent to ([RFC 7348]).
///
/// [RFC 7348]: https://www.rfc-editor.org/rfc/rfc7348
pub const VXLAN_PORT: u16 = 4789;

/// A MAC address.
pub type Mac = [u8; 6];

/// MAC addresses as people write them, `02:00:00:00:00:01`, for `#[serde(with = "mac_text")]`.
pub mod mac_text {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    use super::Mac;

    /// Write `mac` as six colon-separated hex octets.
    ///
    /// # Errors
    ///
    /// If `serializer` fails.
    pub fn serialize<S: Serializer>(mac: &Mac, serializer: S) -> Result<S::Ok, S::Error> {
        let text = mac.map(|octet| format!("{octet:02x}")).join(":");
        serializer.serialize_str(&text)
    }

    /// Read six colon-separated hex octets.
    ///
    /// # Errors
    ///
    /// If the text is not a MAC address.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Mac, D::Error> {
        let text = String::deserialize(deserializer)?;
        parse(&text).ok_or_else(|| D::Error::custom(format!("{text:?} is not a MAC address")))
    }

    /// `text` as a MAC address, if it is one.
    #[must_use]
    pub fn parse(text: &str) -> Option<Mac> {
        let mut mac = [0u8; 6];
        let mut octets = text.split(':');
        for octet in &mut mac {
            let part = octets.next()?;
            if part.len() != 2 {
                return None;
            }
            *octet = u8::from_str_radix(part, 16).ok()?;
        }
        octets.next().is_none().then_some(mac)
    }
}

/// The tunnel a stream's frames travel in, as the VTEP sending them would build it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vxlan {
    /// The VNI.
    pub vni: u32,
    /// The sending VTEP's MAC.
    #[serde(with = "mac_text")]
    pub src_mac: Mac,
    /// The next hop's MAC: the gateway's.
    #[serde(with = "mac_text")]
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
    #[serde(with = "mac_text")]
    pub src_mac: Mac,
    /// The inner frame's destination MAC.
    #[serde(with = "mac_text")]
    pub dst_mac: Mac,
    /// The tunnel, if the frames travel in one.
    pub vxlan: Option<Vxlan>,
    /// What the inner packet carries.
    #[serde(default)]
    pub transport: Transport,
    /// The inner payload's length, signature included; at least [`signature::LEN`].
    pub payload_len: u16,
    /// The inner packet's TTL.
    pub ttl: u8,
    /// One change to make to every frame, to make it one a gateway should refuse; see
    /// [`mutate`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutation: Option<Mutation>,
}

/// One flow's frame, ready to stamp and send.
#[derive(Debug, Clone)]
pub struct Template {
    bytes: Vec<u8>,
    /// Where the signature starts, if the frame still has all of it and its checksum.
    signature: Option<usize>,
    /// Where the inner transport checksum is.
    l4_checksum: usize,
    /// The inner transport protocol.
    protocol: u8,
}

impl Template {
    /// The frame for `flow`, the `number`th flow of its stream in run `run`, built to `spec`.
    #[must_use]
    pub fn new(spec: &FrameSpec, run: u32, number: u64, flow: &Tuple) -> Template {
        let payload_len = usize::from(spec.payload_len).max(signature::LEN);
        let inner_len = ETH_LEN + IPV4_LEN + spec.transport.header_len() + payload_len;
        let outer_len = spec
            .vxlan
            .map_or(0, |_| ETH_LEN + IPV4_LEN + UDP_LEN + VXLAN_LEN);
        let mut bytes = vec![0u8; outer_len + inner_len];

        if let Some(vxlan) = spec.vxlan {
            let (outer, _) = bytes.split_at_mut(outer_len);
            ethernet(&mut outer[..ETH_LEN], vxlan.dst_mac, vxlan.src_mac);
            ipv4(
                &mut outer[ETH_LEN..ETH_LEN + IPV4_LEN],
                PROTO_UDP,
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
        let l4_len = spec.transport.header_len();
        let protocol = spec.transport.protocol();
        ipv4(
            &mut inner[ETH_LEN..ETH_LEN + IPV4_LEN],
            protocol,
            flow.src,
            flow.dst,
            spec.ttl,
            l4_len + payload_len,
        );
        let l4_at = ETH_LEN + IPV4_LEN;
        let checksum_at = match spec.transport {
            Transport::Udp => {
                udp_header(
                    &mut inner[l4_at..l4_at + UDP_LEN],
                    flow.sport,
                    flow.dport,
                    UDP_LEN + payload_len,
                );
                6
            }
            Transport::Tcp { flags } => {
                tcp_header(
                    &mut inner[l4_at..l4_at + TCP_LEN],
                    flow.sport,
                    flow.dport,
                    flags,
                );
                16
            }
        };
        let payload = &mut inner[l4_at + l4_len..];
        Signature {
            run,
            flow: number,
            seq: 0,
            tx_ns: 0,
        }
        .write(payload);
        fill(payload);
        let checksum = checksum::l4_ipv4(protocol, flow.src, flow.dst, &inner[l4_at..]);
        inner[l4_at + checksum_at..l4_at + checksum_at + 2]
            .copy_from_slice(&checksum.to_be_bytes());

        let mut signature = outer_len + l4_at + l4_len;
        let mut l4_checksum = outer_len + l4_at + checksum_at;
        if let Some(mutation) = spec.mutation {
            let (outer, inner) = mutate::layouts(spec.vxlan.is_some(), protocol, inner_len);
            if let Some(resize) = mutate::apply(&mut bytes, outer, inner, mutation) {
                let moved = |at: usize| {
                    if at >= resize.at {
                        at.saturating_add_signed(resize.by)
                    } else {
                        at
                    }
                };
                signature = moved(signature);
                l4_checksum = moved(l4_checksum);
            }
        }
        // A frame cut short of its signature, or of the checksum over it, is sent as it is.
        let whole = signature + signature::LEN <= bytes.len() && l4_checksum + 2 <= bytes.len();

        Template {
            bytes,
            signature: whole.then_some(signature),
            l4_checksum,
            protocol,
        }
    }

    /// Stamp the frame as packet `seq` of its flow, sent at `tx_ns`.
    pub fn stamp(&mut self, seq: u64, tx_ns: u64) {
        let Some(signature) = self.signature else {
            return;
        };
        // The sequence number and time are the signature's last 16 bytes, at an even offset into
        // the datagram, so the checksum can be updated for them alone.
        let at = signature + 16;
        let mut old = [0u8; 16];
        old.copy_from_slice(&self.bytes[at..at + 16]);
        let mut new = [0u8; 16];
        new[..8].copy_from_slice(&seq.to_be_bytes());
        new[8..].copy_from_slice(&tx_ns.to_be_bytes());
        self.bytes[at..at + 16].copy_from_slice(&new);
        let c = self.l4_checksum;
        let checksum = u16::from_be_bytes([self.bytes[c], self.bytes[c + 1]]);
        if checksum == 0 && self.protocol == PROTO_UDP {
            // No checksum: there is nothing to update.
            return;
        }
        let checksum = checksum::adjust(self.protocol, checksum, &old, &new);
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

/// An IPv4 header without options, carrying `payload_len` bytes of `protocol`.
fn ipv4(out: &mut [u8], protocol: u8, src: Ipv4Addr, dst: Ipv4Addr, ttl: u8, payload_len: usize) {
    let total = u16::try_from(IPV4_LEN + payload_len).unwrap_or(u16::MAX);
    out[0] = 0x45; // version 4, five words
    out[2..4].copy_from_slice(&total.to_be_bytes());
    out[8] = ttl;
    out[9] = protocol;
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

/// A TCP header without options and with a zero checksum, carrying `flags`.
fn tcp_header(out: &mut [u8], sport: u16, dport: u16, flags: u8) {
    out[0..2].copy_from_slice(&sport.to_be_bytes());
    out[2..4].copy_from_slice(&dport.to_be_bytes());
    out[12] = 0x50; // five words
    out[13] = flags;
    out[14..16].copy_from_slice(&u16::MAX.to_be_bytes()); // window
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
    /// The inner UDP or TCP checksum.
    pub l4_checksum: ChecksumState,
    /// The inner TCP segment's flags, if it is TCP.
    pub tcp_flags: Option<u8>,
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
    /// It is neither UDP nor TCP.
    #[error("neither UDP nor TCP (protocol {0})")]
    NotUdpOrTcp(u8),
    /// It is a fragment, which a stream never sends.
    #[error("an IPv4 fragment")]
    Fragment,
}

/// Read a received frame.
///
/// # Errors
///
/// If the frame is not Ethernet, IPv4 and UDP or TCP (optionally inside VXLAN), unfragmented.
pub fn parse(frame: &[u8]) -> Result<Received, ParseError> {
    let outer = Layers::parse(frame)?;
    let (tunnel, inner) = if outer.tcp_flags.is_none() && outer.tuple.dport == VXLAN_PORT {
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
        l4_checksum: inner.l4_checksum,
        tcp_flags: inner.tcp_flags,
        signature: Signature::read(inner.payload),
        payload_intact: filled(inner.payload),
    })
}

/// A UDP datagram's endpoints, as a protocol speaker addresses one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoints {
    /// The sender's MAC.
    #[serde(with = "mac_text")]
    pub src_mac: Mac,
    /// The next hop's MAC.
    #[serde(with = "mac_text")]
    pub dst_mac: Mac,
    /// The sender's address and port.
    pub src: (Ipv4Addr, u16),
    /// The receiver's address and port.
    pub dst: (Ipv4Addr, u16),
}

/// An Ethernet frame carrying `payload` in UDP between `endpoints`, with `ttl`: for a protocol
/// speaker, whose payload is the protocol's rather than a signature.
#[must_use]
pub fn udp(endpoints: &Endpoints, ttl: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; ETH_LEN + IPV4_LEN + UDP_LEN + payload.len()];
    ethernet(&mut bytes[..ETH_LEN], endpoints.dst_mac, endpoints.src_mac);
    let (src, sport) = endpoints.src;
    let (dst, dport) = endpoints.dst;
    ipv4(
        &mut bytes[ETH_LEN..ETH_LEN + IPV4_LEN],
        PROTO_UDP,
        src,
        dst,
        ttl,
        UDP_LEN + payload.len(),
    );
    let at = ETH_LEN + IPV4_LEN;
    udp_header(
        &mut bytes[at..at + UDP_LEN],
        sport,
        dport,
        UDP_LEN + payload.len(),
    );
    bytes[at + UDP_LEN..].copy_from_slice(payload);
    let checksum = checksum::l4_ipv4(PROTO_UDP, src, dst, &bytes[at..]);
    bytes[at + 6..at + 8].copy_from_slice(&checksum.to_be_bytes());
    bytes
}

/// An Ethernet frame from `src` to `dst` carrying the IPv4 packet `packet`.
#[must_use]
pub fn ethernet_ipv4(dst: Mac, src: Mac, packet: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; ETH_LEN + packet.len()];
    ethernet(&mut bytes[..ETH_LEN], dst, src);
    bytes[ETH_LEN..].copy_from_slice(packet);
    bytes
}

/// The Ethernet frame `inner`, in VXLAN through `tunnel`, with `entropy` as the outer source port's
/// low bits.
#[must_use]
pub fn vxlan(tunnel: &Vxlan, entropy: u16, inner: &[u8]) -> Vec<u8> {
    let outer_len = ETH_LEN + IPV4_LEN + UDP_LEN + VXLAN_LEN;
    let mut bytes = vec![0u8; outer_len + inner.len()];
    ethernet(&mut bytes[..ETH_LEN], tunnel.dst_mac, tunnel.src_mac);
    ipv4(
        &mut bytes[ETH_LEN..ETH_LEN + IPV4_LEN],
        PROTO_UDP,
        tunnel.src,
        tunnel.dst,
        64,
        UDP_LEN + VXLAN_LEN + inner.len(),
    );
    let at = ETH_LEN + IPV4_LEN;
    udp_header(
        &mut bytes[at..at + UDP_LEN],
        0xc000 | (entropy & 0x3fff),
        VXLAN_PORT,
        UDP_LEN + VXLAN_LEN + inner.len(),
    );
    let vx = &mut bytes[at + UDP_LEN..outer_len];
    vx[0] = 0x08;
    vx[4..7].copy_from_slice(&tunnel.vni.to_be_bytes()[1..]);
    bytes[outer_len..].copy_from_slice(inner);
    bytes
}

/// The VNI and inner Ethernet frame of a VXLAN frame, if `frame` is one.
#[must_use]
pub fn decapsulate(frame: &[u8]) -> Option<(u32, &[u8])> {
    let outer = Layers::parse(frame).ok()?;
    if outer.tcp_flags.is_some() || outer.tuple.dport != VXLAN_PORT {
        return None;
    }
    let vx = outer.payload.get(..VXLAN_LEN)?;
    let vni = u32::from_be_bytes([0, vx[4], vx[5], vx[6]]);
    Some((vni, &outer.payload[VXLAN_LEN..]))
}

/// The destination MAC and IPv4 packet of an Ethernet frame carrying one, trimmed of padding.
#[must_use]
pub fn ipv4_packet(frame: &[u8]) -> Option<(Mac, &[u8])> {
    let eth = frame.get(..ETH_LEN)?;
    if u16::from_be_bytes([eth[12], eth[13]]) != ETHERTYPE_IPV4 {
        return None;
    }
    let mut dst = [0; 6];
    dst.copy_from_slice(&eth[..6]);
    let ip = &frame[ETH_LEN..];
    let total = usize::from(u16::from_be_bytes([*ip.get(2)?, *ip.get(3)?]));
    Some((dst, ip.get(..total)?))
}

/// A received UDP datagram, not tunnelled, as a protocol speaker reads one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Datagram<'f> {
    /// Its addresses and ports.
    pub tuple: Tuple,
    /// The TTL it arrived with.
    pub ttl: u8,
    /// Its payload.
    pub payload: &'f [u8],
}

/// `frame` as a plain UDP datagram, if it is one with a correct or absent checksum.
#[must_use]
pub fn datagram(frame: &[u8]) -> Option<Datagram<'_>> {
    let layers = Layers::parse(frame).ok()?;
    if layers.tcp_flags.is_some() || layers.l4_checksum == ChecksumState::Invalid {
        return None;
    }
    Some(Datagram {
        tuple: layers.tuple,
        ttl: layers.ttl,
        payload: layers.payload,
    })
}

/// One Ethernet, IPv4 and UDP or TCP header stack.
struct Layers<'f> {
    src_mac: Mac,
    dst_mac: Mac,
    tuple: Tuple,
    ttl: u8,
    ip_checksum: ChecksumState,
    l4_checksum: ChecksumState,
    tcp_flags: Option<u8>,
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
        let protocol = header[9];
        if protocol != PROTO_UDP && protocol != PROTO_TCP {
            return Err(ParseError::NotUdpOrTcp(protocol));
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
        let segment = ip.get(ihl..total).ok_or(ParseError::Short("transport"))?;
        let ports = segment.get(..4).ok_or(ParseError::Short("transport"))?;
        let sport = u16::from_be_bytes([ports[0], ports[1]]);
        let dport = u16::from_be_bytes([ports[2], ports[3]]);
        let (l4_checksum, tcp_flags, payload) = if protocol == PROTO_UDP {
            let udp = segment.get(..UDP_LEN).ok_or(ParseError::Short("UDP"))?;
            let state = if u16::from_be_bytes([udp[6], udp[7]]) == 0 {
                ChecksumState::Absent
            } else if checksum::l4_ipv4_verifies(protocol, src, dst, segment) {
                ChecksumState::Valid
            } else {
                ChecksumState::Invalid
            };
            (state, None, &segment[UDP_LEN..])
        } else {
            let tcp = segment.get(..TCP_LEN).ok_or(ParseError::Short("TCP"))?;
            let offset = usize::from(tcp[12] >> 4) * 4;
            let payload = segment
                .get(offset.max(TCP_LEN)..)
                .ok_or(ParseError::Short("TCP"))?;
            let state = if checksum::l4_ipv4_verifies(protocol, src, dst, segment) {
                ChecksumState::Valid
            } else {
                ChecksumState::Invalid
            };
            (state, Some(tcp[13]), payload)
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
            ttl: header[8],
            ip_checksum,
            l4_checksum,
            tcp_flags,
            payload,
        })
    }
}
