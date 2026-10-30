// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Checksums for a forwarded packet, adjusted for exactly what changed in its headers.
//!
//! Parsing consumes a packet's headers from the front of its buffer but leaves their bytes in place.
//! Until something writes there, those bytes are a log of the headers as they arrived, checksums
//! included. When the headers are written back over them, [`adjust_checksums`] changes each checksum
//! by the 16-bit words that differ between the log and what was written (RFC 1624), and by nothing
//! else. So stages need not keep checksums current, a checksum that arrived wrong leaves exactly as
//! wrong, and bytes the parser does not reproduce count as changes like any other.

use crate::checksum::incremental_update;
use crate::headers::{EmbeddedHeaders, EmbeddedTransport, Net, Transport};
use crate::parse::DeParse;

/// What a checksummed header is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Ipv4,
    Ipv6,
    Tcp,
    Udp,
    Icmp4,
    Icmp6,
}

impl Kind {
    /// Where the header keeps its checksum, if it has one.
    fn checksum_at(self) -> Option<u16> {
        match self {
            Kind::Ipv4 => Some(10),
            Kind::Ipv6 => None,
            Kind::Tcp => Some(16),
            Kind::Udp => Some(6),
            Kind::Icmp4 | Kind::Icmp6 => Some(2),
        }
    }
}

/// One checksummed header's place in a run of deparsed headers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Layer {
    offset: u16,
    len: u16,
    kind: Kind,
}

/// Where the checksummed headers sit in the bytes [`Headers::deparse`] writes.
///
/// Two runs with the same layout put the same kinds of header in the same places, so the checksums
/// of one can be adjusted word for word against the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Layout {
    len: u16,
    net: Option<Layer>,
    transport: Option<Layer>,
    quoted_net: Option<Layer>,
    quoted_transport: Option<Layer>,
}

impl Layout {
    /// A layout with nothing recorded yet.
    pub(super) const EMPTY: Layout = Layout {
        len: 0,
        net: None,
        transport: None,
        quoted_net: None,
        quoted_transport: None,
    };

    /// The length of the whole run of headers.
    pub(crate) fn len(&self) -> u16 {
        self.len
    }

    /// Record a network header of `len` octets at `offset`.
    pub(super) fn net(&mut self, net: &Net, offset: u16, len: u16) {
        let kind = match net {
            Net::Ipv4(_) => Kind::Ipv4,
            Net::Ipv6(_) => Kind::Ipv6,
        };
        self.net = Some(Layer { offset, len, kind });
    }

    /// Record a transport header of `len` octets at `offset`.
    pub(super) fn transport(&mut self, transport: &Transport, offset: u16, len: u16) {
        let kind = match transport {
            Transport::Tcp(_) => Kind::Tcp,
            Transport::Udp(_) => Kind::Udp,
            Transport::Icmp4(_) => Kind::Icmp4,
            Transport::Icmp6(_) => Kind::Icmp6,
        };
        self.transport = Some(Layer { offset, len, kind });
    }

    /// Record the headers an ICMP error quotes, starting at `offset`.
    pub(super) fn quoted(&mut self, quoted: &EmbeddedHeaders, offset: u16) {
        let mut at = offset;
        self.quoted_net = quoted.net.as_ref().map(|net| {
            let layer = Layer {
                offset: at,
                len: net.size().get(),
                kind: match net {
                    Net::Ipv4(_) => Kind::Ipv4,
                    Net::Ipv6(_) => Kind::Ipv6,
                },
            };
            at += layer.len + quoted.net_ext_headers_len();
            layer
        });
        self.quoted_transport = quoted.transport.as_ref().map(|transport| Layer {
            offset: at,
            len: transport.size().get(),
            kind: match transport {
                EmbeddedTransport::Tcp(_) => Kind::Tcp,
                EmbeddedTransport::Udp(_) => Kind::Udp,
                EmbeddedTransport::Icmp4(_) => Kind::Icmp4,
                EmbeddedTransport::Icmp6(_) => Kind::Icmp6,
            },
        });
    }

    /// Record the length of the whole run.
    pub(super) fn finish(&mut self, len: u16) {
        self.len = len;
    }
}

/// The 16-bit word at `at`, or the last byte padded with zero if only one is left.
fn word(bytes: &[u8], at: usize) -> u16 {
    match bytes.get(at..at + 2) {
        Some(&[high, low]) => u16::from_be_bytes([high, low]),
        _ => u16::from(bytes[at]) << 8,
    }
}

/// Fold each word of `old[range]` that `new[range]` changed into `checksum`, skipping the word at
/// `skip`.
///
/// Usually little or nothing changed, so this compares eight octets at a time and looks at words
/// only where those differ.
fn fold(
    mut checksum: u16,
    old: &[u8],
    new: &[u8],
    range: std::ops::Range<usize>,
    skip: Option<usize>,
) -> u16 {
    let base = range.start;
    let (old, new) = (&old[range.clone()], &new[range]);
    let (old_chunks, _) = old.as_chunks::<8>();
    let (new_chunks, _) = new.as_chunks::<8>();
    for (chunk, (before, after)) in old_chunks.iter().zip(new_chunks).enumerate() {
        if u64::from_ne_bytes(*before) == u64::from_ne_bytes(*after) {
            continue;
        }
        for (pair, (before, after)) in before
            .as_chunks::<2>()
            .0
            .iter()
            .zip(after.as_chunks::<2>().0)
            .enumerate()
        {
            if before != after && Some(base + chunk * 8 + pair * 2) != skip {
                checksum = incremental_update(
                    checksum,
                    u16::from_be_bytes(*before),
                    u16::from_be_bytes(*after),
                );
            }
        }
    }
    for at in (old_chunks.len() * 8..old.len()).step_by(2) {
        let (before, after) = (word(old, at), word(new, at));
        if before != after && Some(base + at) != skip {
            checksum = incremental_update(checksum, before, after);
        }
    }
    checksum
}

/// The pseudo-header words a transport checksum takes from `net`: its addresses, and its length,
/// whose change is the change in the transport length when the header lengths stay put.
fn fold_pseudo_header(checksum: u16, net: Layer, old: &[u8], new: &[u8]) -> u16 {
    let base = usize::from(net.offset);
    match net.kind {
        Kind::Ipv4 => {
            let checksum = fold(checksum, old, new, base + 2..base + 4, None);
            fold(checksum, old, new, base + 12..base + 20, None)
        }
        Kind::Ipv6 => {
            let checksum = fold(checksum, old, new, base + 4..base + 6, None);
            fold(checksum, old, new, base + 8..base + 40, None)
        }
        _ => unreachable!("a network layer is IPv4 or IPv6"),
    }
}

fn read(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

fn write(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_be_bytes());
}

/// Adjust an IPv4 header's checksum; other network headers have none.
fn adjust_net(net: Layer, old: &[u8], new: &mut [u8]) {
    let Some(checksum_at) = net.kind.checksum_at() else {
        return;
    };
    let start = usize::from(net.offset);
    let at = start + usize::from(checksum_at);
    let checksum = fold(
        read(old, at),
        old,
        new,
        start..start + usize::from(net.len),
        Some(at),
    );
    write(new, at, checksum);
}

/// Adjust a transport checksum, which covers its pseudo-header, its own header, and everything up to
/// `end` after it: quoted headers, or a VXLAN header.
///
/// Returns where an `ICMPv4` checksum came out zero over headers that are all zero: whether it
/// should be `0xffff` instead depends on the payload too.
fn adjust_transport(
    net: Option<Layer>,
    transport: Layer,
    end: u16,
    old: &[u8],
    new: &mut [u8],
) -> Option<usize> {
    let checksum_at = transport.kind.checksum_at()?;
    let start = usize::from(transport.offset);
    let at = start + usize::from(checksum_at);
    if at + 2 > usize::from(end) {
        // A quoted header cut off before its checksum.
        return None;
    }
    let before = read(old, at);
    if transport.kind == Kind::Udp && before == 0 {
        // UDP without a checksum stays without one.
        write(new, at, 0);
        return None;
    }
    let mut checksum = before;
    if let (Some(net), Kind::Tcp | Kind::Udp | Kind::Icmp6) = (net, transport.kind) {
        checksum = fold_pseudo_header(checksum, net, old, new);
    }
    checksum = fold(checksum, old, new, start..usize::from(end), Some(at));
    let mut ambiguous = None;
    if checksum == 0 {
        match transport.kind {
            // Zero means "no checksum" in UDP.
            Kind::Udp => checksum = 0xffff,
            // ICMPv4 has no pseudo-header, so its data can be all zero, which needs 0xffff.
            Kind::Icmp4
                if new[start..usize::from(end)]
                    .iter()
                    .enumerate()
                    .all(|(i, b)| *b == 0 || start + i == at || start + i == at + 1) =>
            {
                ambiguous = Some(at);
            }
            _ => {}
        }
    }
    write(new, at, checksum);
    ambiguous
}

/// Adjust every checksum in `new`, a run of headers with `layout` just written over `old`, by the
/// words that differ between the two.
///
/// Returns where the outermost checksum is an `ICMPv4` zero that must become `0xffff` if the payload
/// is all zero as well.
pub(crate) fn adjust_checksums(layout: &Layout, old: &[u8], new: &mut [u8]) -> Option<usize> {
    // Innermost first: a quoted header's checksums are data to the ICMP checksum around them.
    if let Some(quoted_transport) = layout.quoted_transport {
        adjust_transport(
            layout.quoted_net,
            quoted_transport,
            quoted_transport.offset + quoted_transport.len,
            old,
            new,
        );
    }
    if let Some(quoted_net) = layout.quoted_net {
        adjust_net(quoted_net, old, new);
    }
    let ambiguous = layout
        .transport
        .and_then(|transport| adjust_transport(layout.net, transport, layout.len, old, new));
    if let Some(net) = layout.net {
        adjust_net(net, old, new);
    }
    ambiguous
}
