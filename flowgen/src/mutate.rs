// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Frames a gateway should refuse, or think twice about: a stream's frame, built as usual, then
//! changed in one place.
//!
//! The change is made to the bytes, after the frame is built, so it can be anything at all: an
//! address no host may send from, a header length shorter than the header, a fragment of nothing.
//! The dataplane's own header types would refuse to build most of these, which is the point of
//! building frames here rather than with them.
//!
//! Every other field stays as it was built, and every checksum the change does not concern is made
//! right again, so that a frame is wrong in the one way it is meant to be: a frame with a TTL of
//! zero has a correct header checksum, and one with a bad header checksum is otherwise sound. When
//! the change makes the stream's packet longer or shorter inside a tunnel, the tunnel's lengths are
//! made to agree with it, so the tunnel stays sound around it.
//!
//! The signature survives every change but [`Change::Truncate`] that cuts into it, so a mutated
//! frame that comes back is still counted against its flow.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::checksum;
use crate::frame::{FrameSpec, Mac, mac_text};

/// Which of a frame's headers a [`Mutation`] changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    /// The tunnel's: outer Ethernet, IPv4, UDP and VXLAN. Only a tunnelled stream has one.
    Outer,
    /// The stream's own frame, inside the tunnel if there is one.
    #[default]
    Inner,
}

/// One change to every frame of a stream. See the [module documentation](self).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mutation {
    /// The headers it changes.
    #[serde(default)]
    pub layer: Layer,
    /// What it changes.
    pub change: Change,
}

/// What a [`Mutation`] changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Change {
    /// The Ethernet source address.
    SourceMac {
        /// The address.
        #[serde(with = "mac_text")]
        mac: Mac,
    },
    /// The Ethernet destination address.
    DestinationMac {
        /// The address.
        #[serde(with = "mac_text")]
        mac: Mac,
    },
    /// The Ethernet type.
    EtherType {
        /// The type.
        ethertype: u16,
    },
    /// An IEEE 802.1Q tag, inserted after the source address.
    VlanTag {
        /// Its VLAN id; 0 tags a frame with a priority only.
        vid: u16,
    },
    /// The frame cut short, `len` bytes after the start of the layer's Ethernet header.
    Truncate {
        /// The bytes kept from the layer's Ethernet header on.
        len: u16,
    },
    /// Bytes after the IPv4 packet's end, before the frame's: Ethernet padding, or junk.
    Padding {
        /// How many zero bytes.
        bytes: u16,
    },
    /// The IP version.
    IpVersion {
        /// The version.
        version: u8,
    },
    /// The IPv4 header length field, in 32-bit words, without changing the header.
    HeaderLength {
        /// The length, in words.
        words: u8,
    },
    /// The IPv4 total length field, moved from the truth by `delta`, without changing the packet.
    TotalLength {
        /// How far from the truth.
        delta: i16,
    },
    /// IPv4 options: `words` 32-bit words of No Operation, lengthening the header and the packet.
    IpOptions {
        /// How many words, at most 10.
        words: u8,
    },
    /// The IPv4 header checksum, made wrong.
    IpChecksum,
    /// The IPv4 time to live.
    Ttl {
        /// The TTL.
        ttl: u8,
    },
    /// The IPv4 protocol, without changing what the packet carries.
    Protocol {
        /// The protocol number.
        protocol: u8,
    },
    /// The IPv4 source address.
    SourceIp {
        /// The address.
        addr: Ipv4Addr,
    },
    /// The IPv4 destination address.
    DestinationIp {
        /// The address.
        addr: Ipv4Addr,
    },
    /// The IPv4 fragment fields: a fragment, though the packet is whole.
    Fragment {
        /// The More Fragments flag.
        more: bool,
        /// The fragment offset, in 8-byte units.
        offset: u16,
    },
    /// The UDP or TCP checksum, made wrong.
    L4Checksum,
    /// The UDP checksum, zero: no checksum, which IPv4 allows.
    UdpChecksumZero,
    /// The UDP length field, moved from the truth by `delta`, without changing the datagram.
    UdpLength {
        /// How far from the truth.
        delta: i16,
    },
    /// The TCP data offset, in 32-bit words, without changing the segment.
    TcpDataOffset {
        /// The offset, in words.
        words: u8,
    },
    /// The TCP flags.
    TcpFlags {
        /// The flags; see [`frame::tcp`](crate::frame::tcp).
        flags: u8,
    },
    /// The UDP or TCP source port.
    SourcePort {
        /// The port.
        port: u16,
    },
    /// The UDP or TCP destination port.
    DestinationPort {
        /// The port.
        port: u16,
    },
    /// The VXLAN flags byte. Outer layer only.
    VxlanFlags {
        /// The flags; `0x08` is the I flag, saying the VNI is valid.
        flags: u8,
    },
    /// The VXLAN header's reserved fields, every bit set. Outer layer only.
    VxlanReserved,
    /// The VNI. Outer layer only.
    Vni {
        /// The VNI.
        vni: u32,
    },
}

/// Why a mutation cannot be made to a stream's frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MutationError {
    /// It changes the tunnel, and the stream's frames are not tunnelled.
    #[error("the frames have no tunnel to change")]
    NoTunnel,
    /// It changes VXLAN, which only the outer layer has.
    #[error("only the outer layer has a VXLAN header")]
    NotVxlan,
    /// It changes UDP, and the layer is TCP, or the other way about.
    #[error("the layer does not carry that transport")]
    WrongTransport,
    /// It asks for more options than an IPv4 header has room for.
    #[error("an IPv4 header has room for at most 10 words of options")]
    TooManyOptions,
}

impl Mutation {
    /// Whether the mutation can be made to frames built to `spec`.
    ///
    /// # Errors
    ///
    /// If it changes a header the frames do not have.
    pub fn check(&self, spec: &FrameSpec) -> Result<(), MutationError> {
        if self.layer == Layer::Outer && spec.vxlan.is_none() {
            return Err(MutationError::NoTunnel);
        }
        let udp = match self.layer {
            Layer::Outer => true,
            Layer::Inner => spec.transport == crate::frame::Transport::Udp,
        };
        match self.change {
            Change::VxlanFlags { .. } | Change::VxlanReserved | Change::Vni { .. }
                if self.layer != Layer::Outer =>
            {
                Err(MutationError::NotVxlan)
            }
            Change::UdpChecksumZero | Change::UdpLength { .. } if !udp => {
                Err(MutationError::WrongTransport)
            }
            Change::TcpDataOffset { .. } | Change::TcpFlags { .. } if udp => {
                Err(MutationError::WrongTransport)
            }
            Change::IpOptions { words } if words > 10 => Err(MutationError::TooManyOptions),
            _ => Ok(()),
        }
    }
}

impl Mutation {
    /// The mutation `bits` picks: its layer, its change, and the change's values, all from the 64
    /// bits, so that a seeded sequence -- [`Mutations`] -- or a fuzzer can range over every mutation
    /// there is. It may not suit a given stream's frames; see [`Mutation::check`].
    #[must_use]
    pub fn from_bits(bits: u64) -> Mutation {
        let [kind, layer, a0, a1, b0, b1, b2, b3] = bits.to_le_bytes();
        let a = u16::from_le_bytes([a0, a1]);
        let b = u32::from_le_bytes([b0, b1, b2, b3]);
        let mac = [b0, b1, b2, b3, a0, a1];
        let delta = i16::from_le_bytes([a0, a1]);
        let change = match kind % 26 {
            0 => Change::SourceMac { mac },
            1 => Change::DestinationMac { mac },
            2 => Change::EtherType { ethertype: a },
            3 => Change::VlanTag { vid: a },
            4 => Change::Truncate { len: a % 200 },
            5 => Change::Padding { bytes: a % 64 },
            6 => Change::IpVersion { version: a0 },
            7 => Change::HeaderLength { words: a0 },
            8 => Change::TotalLength { delta },
            9 => Change::IpOptions { words: a0 % 11 },
            10 => Change::IpChecksum,
            11 => Change::Ttl { ttl: a0 },
            12 => Change::Protocol { protocol: a0 },
            13 => Change::SourceIp {
                addr: Ipv4Addr::from(b),
            },
            14 => Change::DestinationIp {
                addr: Ipv4Addr::from(b),
            },
            15 => Change::Fragment {
                more: a & 1 == 1,
                offset: a >> 1,
            },
            16 => Change::L4Checksum,
            17 => Change::UdpChecksumZero,
            18 => Change::UdpLength { delta },
            19 => Change::TcpDataOffset { words: a0 },
            20 => Change::TcpFlags { flags: a0 },
            21 => Change::SourcePort { port: a },
            22 => Change::DestinationPort { port: a },
            23 => Change::VxlanFlags { flags: a0 },
            24 => Change::VxlanReserved,
            _ => Change::Vni { vni: b },
        };
        let layer = if layer & 1 == 0 {
            Layer::Inner
        } else {
            Layer::Outer
        };
        Mutation { layer, change }
    }
}

/// An endless, reproducible sequence of arbitrary mutations: [`Mutation::from_bits`] of each value
/// of a `SplitMix64` generator seeded with the seed.
#[derive(Debug, Clone)]
pub struct Mutations {
    state: u64,
}

impl Mutations {
    /// The sequence seeded with `seed`.
    #[must_use]
    pub fn seeded(seed: u64) -> Mutations {
        Mutations { state: seed }
    }
}

impl Iterator for Mutations {
    type Item = Mutation;

    fn next(&mut self) -> Option<Mutation> {
        // SplitMix64 (Steele, Lea and Flood, 2014): every 64-bit value once per period, well mixed.
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        Some(Mutation::from_bits(z ^ (z >> 31)))
    }
}

const ETH_LEN: usize = 14;
const IPV4_LEN: usize = 20;
const UDP_LEN: usize = 8;
const PROTO_UDP: u8 = 17;
const PROTO_TCP: u8 = 6;

/// Where one layer's headers are in a frame, as it was built.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Layout {
    /// The Ethernet header.
    pub(crate) eth: usize,
    /// The IPv4 header.
    pub(crate) ip: usize,
    /// The UDP or TCP header.
    pub(crate) l4: usize,
    /// The end of the IPv4 packet.
    pub(crate) end: usize,
    /// UDP or TCP.
    pub(crate) protocol: u8,
}

impl Layout {
    fn checksum_at(&self) -> usize {
        self.l4 + if self.protocol == PROTO_UDP { 6 } else { 16 }
    }

    /// Everything after `at` moved on by `by`.
    fn shifted(self, at: usize, by: isize) -> Layout {
        let shift = |n: usize| {
            if n >= at {
                n.saturating_add_signed(by)
            } else {
                n
            }
        };
        Layout {
            eth: shift(self.eth),
            ip: shift(self.ip),
            l4: shift(self.l4),
            end: shift(self.end),
            protocol: self.protocol,
        }
    }
}

/// How a mutation changed the frame's length: by `by` bytes, at `at`. Whatever was at or after
/// `at` has moved by `by`, unless it was cut off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Resize {
    pub(crate) at: usize,
    pub(crate) by: isize,
}

/// Make `mutation` to `bytes`, a frame whose headers are where `outer` and `inner` say, as built.
/// Returns how the frame's length changed, if it did.
///
/// A mutation [`Mutation::check`] refuses for the frame is not made.
pub(crate) fn apply(
    bytes: &mut Vec<u8>,
    outer: Option<Layout>,
    inner: Layout,
    mutation: Mutation,
) -> Option<Resize> {
    let target = match mutation.layer {
        Layer::Outer => outer?,
        Layer::Inner => inner,
    };
    let effect = rewrite(bytes, target, mutation)?;
    let layout = match effect.resize {
        Some(resize) => target.shifted(resize.at, resize.by),
        None => target,
    };
    checksums(bytes, layout, &effect);
    // The stream's packet grew or shrank inside a tunnel: the tunnel's lengths follow.
    if let (Layer::Inner, Some(outer), Some(resize)) = (mutation.layer, outer, effect.resize) {
        follow(bytes, outer, resize.by);
    }
    effect.resize
}

/// What becomes of one of a layer's checksums after a change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sum {
    /// Made right again for the change.
    Fix,
    /// Left as it was.
    Leave,
    /// Made wrong.
    Break,
}

/// What a change did, beyond the bytes it changed: how the frame's length changed, and what
/// becomes of the layer's checksums.
struct Effect {
    resize: Option<Resize>,
    ip: Sum,
    l4: Sum,
}

impl Effect {
    const FIX: Effect = Effect {
        resize: None,
        ip: Sum::Fix,
        l4: Sum::Fix,
    };

    fn resized(at: usize, by: isize) -> Effect {
        Effect {
            resize: Some(Resize { at, by }),
            ..Effect::FIX
        }
    }
}

/// Make `mutation`'s change to the layer of `bytes` at `target`, and say what else it needs.
fn rewrite(bytes: &mut Vec<u8>, target: Layout, mutation: Mutation) -> Option<Effect> {
    match mutation.change {
        Change::VlanTag { vid } => {
            let at = target.eth + 12;
            let tci = (vid & 0x0fff).to_be_bytes();
            bytes.splice(at..at, [0x81, 0x00, tci[0], tci[1]]);
            Some(Effect::resized(at, 4))
        }
        Change::Truncate { len } => {
            let at = target.eth + usize::from(len);
            let resize = (at < bytes.len()).then(|| {
                let by = -isize::try_from(bytes.len() - at).unwrap_or(isize::MAX);
                bytes.truncate(at);
                Resize { at, by }
            });
            // What is left of the headers is as it was; there may be no checksum left to fix.
            Some(Effect {
                resize,
                ip: Sum::Leave,
                l4: Sum::Leave,
            })
        }
        Change::Padding { bytes: n } => {
            // After the packet's end, which stays where it is.
            let at = target.end;
            bytes.splice(at..at, std::iter::repeat_n(0, usize::from(n)));
            Some(Effect::resized(
                at + 1,
                isize::try_from(n).unwrap_or(isize::MAX),
            ))
        }
        Change::IpOptions { words } => {
            let ip = target.ip;
            let words = words.min(10);
            let at = ip + IPV4_LEN;
            // No Operation, option type 1, as padding between options would be.
            bytes.splice(at..at, std::iter::repeat_n(1, usize::from(words) * 4));
            bytes[ip] = (bytes[ip] & 0xf0) | (5 + words);
            let total = u16::from_be_bytes([bytes[ip + 2], bytes[ip + 3]]);
            let total = total.saturating_add(u16::from(words) * 4);
            put(bytes, ip + 2, &total.to_be_bytes());
            Some(Effect::resized(at, isize::from(words) * 4))
        }
        change => field(bytes, target, mutation.layer, change),
    }
}

/// Make a change that rewrites a header field in place, leaving the frame's length alone.
fn field(bytes: &mut [u8], target: Layout, layer: Layer, change: Change) -> Option<Effect> {
    let udp = target.protocol == PROTO_UDP;
    let tcp = target.protocol == PROTO_TCP;
    let outer = layer == Layer::Outer;
    let (eth, ip, l4) = (target.eth, target.ip, target.l4);
    let mut effect = Effect::FIX;
    match change {
        Change::SourceMac { mac } => put(bytes, eth + 6, &mac),
        Change::DestinationMac { mac } => put(bytes, eth, &mac),
        Change::EtherType { ethertype } => put(bytes, eth + 12, &ethertype.to_be_bytes()),
        Change::IpVersion { version } => bytes[ip] = (version << 4) | (bytes[ip] & 0x0f),
        Change::HeaderLength { words } => bytes[ip] = (bytes[ip] & 0xf0) | (words & 0x0f),
        Change::TotalLength { delta } => {
            let total = u16::from_be_bytes([bytes[ip + 2], bytes[ip + 3]]);
            put(
                bytes,
                ip + 2,
                &total.wrapping_add_signed(delta).to_be_bytes(),
            );
        }
        Change::IpChecksum => effect.ip = Sum::Break,
        Change::Ttl { ttl } => bytes[ip + 8] = ttl,
        Change::Protocol { protocol } => {
            bytes[ip + 9] = protocol;
            // What the packet carries is no longer what its header says; leave it as it was.
            effect.l4 = Sum::Leave;
        }
        Change::SourceIp { addr } => put(bytes, ip + 12, &addr.octets()),
        Change::DestinationIp { addr } => put(bytes, ip + 16, &addr.octets()),
        Change::Fragment { more, offset } => {
            let field = (u16::from(more) << 13) | (offset & 0x1fff);
            put(bytes, ip + 6, &field.to_be_bytes());
        }
        Change::L4Checksum => effect.l4 = Sum::Break,
        Change::UdpChecksumZero if udp => {
            put(bytes, l4 + 6, &[0, 0]);
            effect.l4 = Sum::Leave;
        }
        Change::UdpLength { delta } if udp => {
            let len = u16::from_be_bytes([bytes[l4 + 4], bytes[l4 + 5]]);
            put(bytes, l4 + 4, &len.wrapping_add_signed(delta).to_be_bytes());
        }
        Change::TcpDataOffset { words } if tcp => {
            bytes[l4 + 12] = (words << 4) | (bytes[l4 + 12] & 0x0f);
        }
        Change::TcpFlags { flags } if tcp => bytes[l4 + 13] = flags,
        Change::SourcePort { port } => put(bytes, l4, &port.to_be_bytes()),
        Change::DestinationPort { port } => put(bytes, l4 + 2, &port.to_be_bytes()),
        Change::VxlanFlags { flags } if outer => bytes[l4 + UDP_LEN] = flags,
        Change::VxlanReserved if outer => {
            let vx = l4 + UDP_LEN;
            put(bytes, vx + 1, &[0xff; 3]);
            bytes[vx + 7] = 0xff;
        }
        Change::Vni { vni } if outer => put(bytes, l4 + UDP_LEN + 4, &vni.to_be_bytes()[1..]),
        // Refused by `Mutation::check`, a header the layer does not have; or made by `rewrite`,
        // since they change the frame's length.
        Change::UdpChecksumZero
        | Change::UdpLength { .. }
        | Change::TcpDataOffset { .. }
        | Change::TcpFlags { .. }
        | Change::VxlanFlags { .. }
        | Change::VxlanReserved
        | Change::Vni { .. }
        | Change::VlanTag { .. }
        | Change::Truncate { .. }
        | Change::Padding { .. }
        | Change::IpOptions { .. } => return None,
    }
    Some(effect)
}

/// Make the layer at `layout` in `bytes` right again where `effect` says, and wrong where it says.
fn checksums(bytes: &mut [u8], layout: Layout, effect: &Effect) {
    let udp = layout.protocol == PROTO_UDP;
    let tcp = layout.protocol == PROTO_TCP;
    // An absent UDP checksum -- the tunnel's, say -- stays absent: it covers nothing to fix.
    let checksum_at = layout.checksum_at();
    let absent = udp && bytes.get(checksum_at..checksum_at + 2) == Some(&[0, 0]);
    match effect.l4 {
        Sum::Fix if !absent && (udp || tcp) && layout.end <= bytes.len() => {
            put(bytes, checksum_at, &[0, 0]);
            let src = address(bytes, layout.ip + 12);
            let dst = address(bytes, layout.ip + 16);
            let sum = checksum::l4_ipv4(layout.protocol, src, dst, &bytes[layout.l4..layout.end]);
            put(bytes, checksum_at, &sum.to_be_bytes());
        }
        Sum::Break => bytes[checksum_at + 1] ^= 1,
        Sum::Fix | Sum::Leave => {}
    }
    match effect.ip {
        Sum::Fix => {
            put(bytes, layout.ip + 10, &[0, 0]);
            let sum = checksum::ipv4_header(&bytes[layout.ip..layout.l4]);
            put(bytes, layout.ip + 10, &sum.to_be_bytes());
        }
        // Off by one: never the other representation of the same sum, as flipping every bit of
        // a zero checksum would be.
        Sum::Break => bytes[layout.ip + 11] ^= 1,
        Sum::Leave => {}
    }
}

/// Lengthen the tunnel at `outer` by `by` bytes, as what it carries was, and make its header
/// checksum right again.
fn follow(bytes: &mut [u8], outer: Layout, by: isize) {
    let grow = |bytes: &mut [u8], at: usize| {
        let len = u16::from_be_bytes([bytes[at], bytes[at + 1]]);
        let len = i64::from(len) + i64::try_from(by).unwrap_or(0);
        let len = u16::try_from(len.max(0)).unwrap_or(u16::MAX);
        put(bytes, at, &len.to_be_bytes());
    };
    grow(bytes, outer.ip + 2);
    grow(bytes, outer.l4 + 4);
    put(bytes, outer.ip + 10, &[0, 0]);
    let sum = checksum::ipv4_header(&bytes[outer.ip..outer.l4]);
    put(bytes, outer.ip + 10, &sum.to_be_bytes());
}

/// Write `new` into `bytes` at `at`.
fn put(bytes: &mut [u8], at: usize, new: &[u8]) {
    bytes[at..at + new.len()].copy_from_slice(new);
}

fn address(bytes: &[u8], at: usize) -> Ipv4Addr {
    Ipv4Addr::new(bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3])
}

/// Where a tunnelled frame's or a bare frame's layers are, as [`Template`](crate::frame::Template)
/// builds them: the tunnel, if any, then the stream's own frame, `inner_len` bytes of it.
pub(crate) fn layouts(tunnelled: bool, protocol: u8, inner_len: usize) -> (Option<Layout>, Layout) {
    let outer_len = if tunnelled {
        ETH_LEN + IPV4_LEN + UDP_LEN + 8
    } else {
        0
    };
    let outer = tunnelled.then_some(Layout {
        eth: 0,
        ip: ETH_LEN,
        l4: ETH_LEN + IPV4_LEN,
        end: outer_len + inner_len,
        protocol: PROTO_UDP,
    });
    let inner = Layout {
        eth: outer_len,
        ip: outer_len + ETH_LEN,
        l4: outer_len + ETH_LEN + IPV4_LEN,
        end: outer_len + inner_len,
        protocol,
    };
    (outer, inner)
}
