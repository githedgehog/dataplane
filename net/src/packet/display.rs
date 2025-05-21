// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Display of Packets

use crate::eth::Eth;
use crate::headers::{Headers, Net, Transport};
use crate::icmp4::Icmp4;
use crate::icmp6::Icmp6;
use crate::ipv4::Ipv4;
use crate::ipv6::Ipv6;
use crate::tcp::Tcp;
use crate::udp::{Udp, UdpEncap};

use crate::buffer::PacketBufferMut;
use crate::packet::{BridgeDomain, DoneReason, InterfaceId, InvalidPacket, Packet, PacketMeta};
use std::fmt::{Display, Formatter};

impl Display for Eth {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "  Eth : {} -> {} ({:?})",
            self.source(),
            self.destination(),
            self.ether_type(),
        )
    }
}
impl Display for Ipv4 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "  IPv4: {} -> {} proto: {:?}",
            self.source(),
            self.destination(),
            self.protocol()
        )?;
        writeln!(
            f,
            "        header-length: {} total-length: {} identification: {} frag-offset: {}",
            self.header_len(),
            self.total_len(),
            self.identification(),
            self.fragment_offset()
        )?;
        writeln!(
            f,
            "        DF: {} MF: {} DSCP: {:?} ECN: {:?} TTL: {:?}",
            self.dont_fragment(),
            self.more_fragments(),
            self.dscp(),
            self.ecn(),
            self.ttl()
        )
    }
}
impl Display for Ipv6 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "  IPv6:")?;
        writeln!(f, "    src ip: {:?}", self.source())?;
        writeln!(f, "    dst ip: {:?}", self.destination())?;
        /* Todo: complete */
        Ok(())
    }
}
impl Display for Net {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Net::Ipv4(v4) => v4.fmt(f),
            Net::Ipv6(v6) => v6.fmt(f),
        }
    }
}
impl Display for Icmp4 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "  ICMP:")?;
        writeln!(f, "        icmp-type: {:?}", self.icmp_type())?;
        writeln!(f, "        checksum: {}", self.checksum())?;
        Ok(())
    }
}
impl Display for Icmp6 {
    fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
        /* Todo */
        Ok(())
    }
}
impl Display for Udp {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "  UDP : {} -> {} length: {} checksum: {}",
            self.source().as_u16(),
            self.destination().as_u16(),
            self.length(),
            self.checksum()
        )
    }
}
impl Tcp {
    fn flags_as_string(&self) -> String {
        let mut flags = String::with_capacity(8 * 3);
        if self.syn() {
            flags += "|SYN";
        }
        if self.ack() {
            flags += "|ACK";
        }
        if self.fin() {
            flags += "|FIN";
        }
        if self.rst() {
            flags += "|RST";
        }
        if self.psh() {
            flags += "|RST";
        }
        if self.urg() {
            flags += "|URG";
        }
        if self.ece() {
            flags += "|CWR";
        }
        if self.ns() {
            flags += "|NS";
        }
        flags += "|";
        flags
    }
}
impl Display for Tcp {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "  TCP : {} -> {} flags: {} seq: {} ack: {} window-size: {}",
            self.source().as_u16(),
            self.destination().as_u16(),
            self.flags_as_string(),
            self.sequence_number(),
            self.ack_number(),
            self.window_size()
        )?;
        writeln!(
            f,
            "        header-len: {} data-offset: {} checksum: {} urg-pointer: {}",
            self.header_len(),
            self.data_offset(),
            self.checksum(),
            self.urgent_pointer(),
        )
    }
}
impl Display for Transport {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Transport::Icmp4(x) => x.fmt(f),
            Transport::Icmp6(x) => x.fmt(f),
            Transport::Udp(x) => x.fmt(f),
            Transport::Tcp(x) => x.fmt(f),
        }
    }
}
impl Display for UdpEncap {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "  ENCAP:")?;
        match self {
            UdpEncap::Vxlan(vxlan) => writeln!(f, "  vxlan, vni={}", vxlan.vni()),
        }
    }
}

/* ============= All headers ============ */
impl Display for Headers {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        if let Some(eth) = &self.eth {
            write!(f, "{eth}")?;
        }
        if let Some(net) = &self.net {
            write!(f, "{net}")?;
        }
        if let Some(transport) = &self.transport {
            write!(f, "{transport}")?;
        }
        if let Some(udp_encap) = &self.udp_encap {
            write!(f, "{udp_encap}")?;
        }
        Ok(())
    }
}

/* ============= METADATA =============== */
impl Display for DoneReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // using Debug at the moment since the enum may soon change
        write!(f, "{self:?}")
    }
}

fn fmt_opt<T: Display>(
    f: &mut Formatter<'_>,
    name: &str,
    optval: Option<T>,
    nl: bool,
) -> std::fmt::Result {
    if nl {
        match optval {
            Some(x) => writeln!(f, "{name}: {x}"),
            None => writeln!(f, "{name}: --"),
        }
    } else {
        match optval {
            Some(x) => write!(f, "{name}: {x}"),
            None => write!(f, "{name}: --"),
        }
    }
}
impl Display for InterfaceId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.get_id())
    }
}
impl Display for BridgeDomain {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.get_id())
    }
}
impl Display for PacketMeta {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "  metadata:")?;
        write!(f, "    iif: {}", self.iif.get_id())?;
        fmt_opt(f, " oif", self.oif, true)?;

        writeln!(
            f,
            "    bcast: {} iplocal: {}",
            self.is_l2bcast, self.is_iplocal
        )?;
        fmt_opt(f, "    vrf", self.vrf, false)?;
        fmt_opt(f, "    bd", self.bridge, true)?;
        fmt_opt(f, "    next-hop", self.nh_addr, true)?;
        fmt_opt(f, "    done", self.done, true)
    }
}

/* ============= HEXDUMP ================ */

#[inline]
fn min(a: usize, b: usize) -> usize {
    if a < b { a } else { b }
}
static HEX_CHARS: &[u8] = b"0123456789abcdef";
fn dump_hex(raw: &[u8], chunk_size: usize) -> String {
    let mut out = Vec::with_capacity(raw.len() * 3);
    let mut count = 0;
    let chunks = raw.chunks(chunk_size);
    for chunk in chunks {
        let range = format!(
            "[{:04}-{:04}]",
            count,
            count + min(chunk_size, chunk.len()) - 1
        );
        for &byte in range.as_bytes() {
            out.push(byte);
        }
        out.push(b' ');
        count += chunk_size;

        for &byte in chunk {
            out.push(HEX_CHARS[(byte >> 4) as usize]);
            out.push(HEX_CHARS[(byte & 0xf) as usize]);
            out.push(b' ');
        }
        out.push(b'\n');
    }
    String::from_utf8_lossy(&out[..]).into_owned()
}

fn fmt_packet_buf<Buf: PacketBufferMut>(f: &mut Formatter<'_>, payload: &Buf) -> std::fmt::Result {
    let raw = payload.as_ref();
    writeln!(f, "{:─<width$}", "─", width = 100)?;
    write!(f, "{}", dump_hex(raw, 32))?;
    writeln!(f, "{:─<width$}", "─", width = 100)?;
    writeln!(
        f,
        "buffer: {} data octets (headroom: {} tailroom: {}))",
        raw.len(),
        payload.headroom(),
        payload.tailroom()
    )
}

/* ============= Packet ================ */
impl<Buf: PacketBufferMut> Display for Packet<Buf> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        fmt_packet_buf(f, self.payload())?;
        write!(f, "headers: {}", self.get_headers())?;
        write!(f, "{}", self.get_meta())?;
        Ok(())
    }
}
impl<Buf: PacketBufferMut> Display for InvalidPacket<Buf> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Invalid packet")?;
        fmt_packet_buf(f, &self.mbuf)?;
        writeln!(f, "error: {}", self.error)?;
        Ok(())
    }
}
