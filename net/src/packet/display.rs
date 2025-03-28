// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Display of Packets

use crate::eth::Eth;
use crate::headers::Net;
use crate::headers::Transport;
use crate::icmp4::Icmp4;
use crate::icmp6::Icmp6;
use crate::ipv4::Ipv4;
use crate::ipv6::Ipv6;
use crate::packet::PacketMeta;
use crate::tcp::Tcp;
use crate::udp::Udp;

use crate::buffer::PacketBufferMut;
use crate::headers::Headers;
use crate::packet::Packet;
use nom::HexDisplay;
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
        Ok(())
    }
}

impl Display for PacketMeta {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "  metadata:")?;
        writeln!(f, "    iif: {:?} oif: {:?}", self.iif, self.oif)?;
        writeln!(
            f,
            "    broadcast: {:?} iplocal: {:?}",
            self.is_l2bcast, self.is_iplocal
        )?;
        writeln!(f, "    vrf: {:?} bd: {:?}", self.vrf, self.bridge)?;
        writeln!(f, "    next-hop: {:?}", self.nh_addr)?;
        writeln!(f, "    done: {:?}", self.done)
    }
}

fn fmt_packet_buf<Buf: PacketBufferMut>(
    f: &mut Formatter<'_>,
    packet: &Packet<Buf>,
) -> std::fmt::Result {
    if let Some(buf) = packet.get_buf() {
        let raw = buf.as_ref();
        writeln!(f, "{:─<width$}", "─", width = 100)?;
        write!(f, "{}", raw.to_hex(16))?;
        writeln!(f, "{:─<width$}", "─", width = 100)?;
        writeln!(
            f,
            "buffer: {} data octets (headroom: {} tailroom: {}))",
            raw.len(),
            buf.headroom(),
            buf.tailroom()
        )?;
    } else {
        writeln!(f, "buffer: None")?;
    }
    Ok(())
}

impl<Buf: PacketBufferMut> Display for Packet<Buf> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        fmt_packet_buf(f, self)?;
        writeln!(f, "consumed: {} octets", self.get_consumed())?;
        write!(f, "headers: {}", self.get_headers())?;
        write!(f, "{}", self.get_meta())?;
        Ok(())
    }
}
