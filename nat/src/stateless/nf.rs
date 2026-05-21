// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Stateless NAT implementation

use super::setup::tables::{NatTables, PerVniTable};
use crate::NatPort;
use crate::icmp_handler::icmp_error_msg::{
    IcmpErrorMsgError, nat_translate_icmp_inner_dst, nat_translate_icmp_inner_src,
    validate_checksums_icmp,
};
pub use crate::stateless::natrw::{NatTablesReader, NatTablesWriter}; // re-export
use net::buffer::PacketBufferMut;
use net::headers::{
    Net, NetError, TryEmbeddedHeaders, TryEmbeddedTransport, TryHeadersMut, TryIcmpAny, TryInnerIp,
    TryIp,
};
use net::ip::UnicastIpAddr;
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use net::tcp_udp::TcpUdpMut;
use net::vxlan::Vni;
use pipeline::NetworkFunction;
use std::net::IpAddr;
use std::num::NonZero;
use thiserror::Error;
use tracing::{debug, error, warn};

#[derive(Error, Debug, PartialEq)]
enum StatelessNatError {
    #[error("No IP header")]
    NoIpHeader,
    #[error("Failed to set source IP: {0}")]
    FailedToSetSourceIp(NetError),
    #[error("Failed to set destination IP: {0}")]
    FailedToSetDestIp(NetError),
    #[error("Can't find NAT tables for VNI {0}")]
    MissingTable(Vni),
    #[error("Failed to translate ICMP inner packet: {0}")]
    IcmpErrorMsg(IcmpErrorMsgError),
    #[error("No mapping found")]
    NoMappingFound,
}

/// A NAT processor, implementing the [`NetworkFunction`] trait. [`StatelessNat`] processes packets
/// to run source or destination Network Address Translation (NAT) on their IP addresses.
#[derive(Debug)]
pub struct StatelessNat {
    name: String,
    tablesr: NatTablesReader,
}

impl StatelessNat {
    /// Creates a new [`StatelessNat`] processor, providing a writer to its internal `NatTables`.
    #[must_use]
    pub fn new(name: &str) -> (Self, NatTablesWriter) {
        let writer = NatTablesWriter::new();
        let reader = writer.get_reader();
        (
            Self {
                name: name.to_string(),
                tablesr: reader,
            },
            writer,
        )
    }
    /// Creates a new [`StatelessNat`] processor as `new()`, but uses the provided `NatTablesReader`.
    #[must_use]
    pub fn with_reader(name: &str, tablesr: NatTablesReader) -> Self {
        Self {
            name: name.to_string(),
            tablesr,
        }
    }

    /// Get the name of this instance
    #[must_use]
    pub fn name(&self) -> &String {
        &self.name
    }

    fn translate_src(
        &self,
        net: &mut Net,
        target_src: UnicastIpAddr,
    ) -> Result<(), StatelessNatError> {
        let nfi = self.name();
        debug!("{nfi}: Changing IP src: {} -> {target_src}", net.src_addr());
        net.try_set_source(target_src)
            .map_err(StatelessNatError::FailedToSetSourceIp)
    }

    fn translate_dst(&self, net: &mut Net, target_dst: IpAddr) -> Result<(), StatelessNatError> {
        let nfi = self.name();
        debug!("{nfi}: Changing IP dst: {} -> {target_dst}", net.dst_addr());
        net.try_set_destination(target_dst)
            .map_err(StatelessNatError::FailedToSetDestIp)
    }

    fn translate_src_port(&self, transport: &mut TcpUdpMut<'_>, new_port: NonZero<u16>) {
        debug!(
            "{}: Changing L4 source port: {:?} -> {new_port}",
            self.name(),
            transport.src_port()
        );
        transport.set_src_port(new_port);
    }

    fn translate_dst_port(&self, transport: &mut TcpUdpMut<'_>, new_port: NonZero<u16>) {
        debug!(
            "{}: Changing L4 destination port: {:?} -> {new_port}",
            self.name(),
            transport.dst_port()
        );
        transport.set_dst_port(new_port);
    }

    // Is this an ICMP error packet that contains an embedded IP packet?
    fn is_icmp_inner_translation_candidate<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> bool {
        // If no network layer, no translation needed
        packet.try_ip().is_some()
        // If not ICMPv4 or ICMPv6, no translation needed
        && packet.try_icmp_any().is_some_and(|icmp| {
            // If not an ICMP error message, no translation needed
            icmp.is_error_message()
        })
        // If no embedded IP packet, no translation needed
        && packet.embedded_headers().is_some()
    }

    fn translate_icmp_inner_packet_src_if_any<Buf: PacketBufferMut>(
        table: &PerVniTable,
        packet: &mut Packet<Buf>,
    ) -> Result<bool, StatelessNatError> {
        let addr = packet
            .try_inner_ip()
            .ok_or(StatelessNatError::NoIpHeader)?
            .src_addr();
        let port = packet
            .try_embedded_transport()
            .and_then(|t| t.source().map(NonZero::get));
        // Note: we assign the _destination_ mapping to the target _source_ address.
        // We're sending the inner packet back without swapping source and destination in the
        // header, so we need to swap the ranges we get from the tables lookup.
        let Some((src_addr, src_port)) = table.find_dst_mapping(&addr, port) else {
            return Err(StatelessNatError::NoMappingFound);
        };
        let src_port = src_port.map(NatPort::new_port);
        nat_translate_icmp_inner_src::<Buf>(packet, src_addr, src_port)
            .map_err(StatelessNatError::IcmpErrorMsg)?;
        Ok(true)
    }

    fn translate_icmp_inner_packet_dst_if_any<Buf: PacketBufferMut>(
        table: &PerVniTable,
        packet: &mut Packet<Buf>,
        dst_vni: Vni,
    ) -> Result<bool, StatelessNatError> {
        let addr = packet
            .try_inner_ip()
            .ok_or(StatelessNatError::NoIpHeader)?
            .dst_addr();
        let port = packet
            .try_embedded_transport()
            .and_then(|t| t.destination().map(NonZero::get));
        // Note: we assign the _source_ mapping to the target _destination_ address.
        // We're sending the inner packet back without swapping source and destination in the
        // header, so we need to swap the ranges we get from the tables lookup.
        let Some((dst_addr, dst_port)) = table.find_src_mapping(&addr, port, dst_vni) else {
            return Err(StatelessNatError::NoMappingFound);
        };
        let dst_port = dst_port.map(NatPort::new_port);
        nat_translate_icmp_inner_dst::<Buf>(packet, dst_addr.inner(), dst_port)
            .map_err(StatelessNatError::IcmpErrorMsg)?;
        Ok(true)
    }

    fn source_nat<Buf: PacketBufferMut>(
        &self,
        table: &PerVniTable,
        packet: &mut Packet<Buf>,
        dst_vni: Vni,
    ) -> Result<bool, StatelessNatError> {
        let nfi = self.name();
        let mut modified = false;

        // Walk the header stack once: eth / net / (optional) transport. The
        // structural shape lets us read addresses/ports and (later) mutate
        // them through the same chain, without re-borrowing the packet.
        let Some((_, ip, tp_opt)) = packet
            .headers_mut()
            .pat_mut()
            .eth()
            .net()
            .opt_transport()
            .done()
        else {
            error!("{nfi}: Failed to get source IP address");
            return Err(StatelessNatError::NoIpHeader);
        };
        let mut tcp_udp = tp_opt.and_then(|t| TcpUdpMut::try_from(t).ok());

        let src_addr = ip.src_addr();
        let src_port_opt = tcp_udp.as_ref().map(|t| t.src_port().get());

        if let Some((new_src_addr, new_src_port_opt)) =
            table.find_src_mapping(&src_addr, src_port_opt, dst_vni)
        {
            if new_src_addr.inner() != src_addr {
                self.translate_src(ip, new_src_addr)?;
                modified = true;
            }
            if let (Some(transport), Some(new_src_port)) = (&mut tcp_udp, new_src_port_opt)
                && new_src_port != transport.src_port()
            {
                self.translate_src_port(transport, new_src_port);
                modified = true;
            }
        }

        // ICMP Error messages
        if Self::is_icmp_inner_translation_candidate(packet) {
            validate_checksums_icmp(packet).map_err(StatelessNatError::IcmpErrorMsg)?;
            modified |= Self::translate_icmp_inner_packet_dst_if_any(table, packet, dst_vni)?;
        }

        if modified {
            packet.meta_mut().src_natted(true);
        }
        Ok(modified)
    }

    fn destination_nat<Buf: PacketBufferMut>(
        &self,
        table: &PerVniTable,
        packet: &mut Packet<Buf>,
    ) -> Result<bool, StatelessNatError> {
        let nfi = self.name();
        let mut modified = false;

        let Some((_, ip, tp_opt)) = packet
            .headers_mut()
            .pat_mut()
            .eth()
            .net()
            .opt_transport()
            .done()
        else {
            error!("{nfi}: Failed to get destination IP address");
            return Err(StatelessNatError::NoIpHeader);
        };
        let mut tcp_udp = tp_opt.and_then(|t| TcpUdpMut::try_from(t).ok());

        let dst_addr = ip.dst_addr();
        let dst_port_opt = tcp_udp.as_ref().map(|t| t.dst_port().get());

        if let Some((new_dst_addr, new_dst_port_opt)) =
            table.find_dst_mapping(&dst_addr, dst_port_opt)
        {
            if new_dst_addr != dst_addr {
                self.translate_dst(ip, new_dst_addr)?;
                modified = true;
            }
            if let (Some(transport), Some(new_dst_port)) = (&mut tcp_udp, new_dst_port_opt)
                && new_dst_port != transport.dst_port()
            {
                self.translate_dst_port(transport, new_dst_port);
                modified = true;
            }
        }

        // ICMP Error messages
        if Self::is_icmp_inner_translation_candidate(packet) {
            modified |= Self::translate_icmp_inner_packet_src_if_any(table, packet)?;
        }

        if modified {
            packet.meta_mut().dst_natted(true);
        }
        Ok(modified)
    }

    /// Applies network address translation to a packet, knowing the current and target ranges.
    /// # Errors
    /// This method may fail if `translate_src` or `translate_dst` fail, which can happen if
    /// addresses are invalid or an unsupported translation is required (e.g. IPv4 -> IPv6).
    fn translate<Buf: PacketBufferMut>(
        &self,
        nat_tables: &NatTables,
        packet: &mut Packet<Buf>,
        src_vni: Vni,
        dst_vni: Vni,
    ) -> Result<bool, StatelessNatError> {
        let nfi = self.name();
        let mut modified = false;

        let Some(table) = nat_tables.get_table(src_vni) else {
            error!("{nfi}: Can't find NAT tables for VNI {src_vni}");
            return Err(StatelessNatError::MissingTable(src_vni));
        };

        if packet.meta().requires_static_nat_src() && !packet.meta().is_src_natted() {
            modified |= self.source_nat(table, packet, dst_vni)?;
        }
        if packet.meta().requires_static_nat_dst() && !packet.meta().is_dst_natted() {
            modified |= self.destination_nat(table, packet)?;
        }
        Ok(modified)
    }

    /// Processes one packet. This is the main entry point for processing a packet. This is also the
    /// function that we pass to [`StatelessNat::process`] to iterate over packets.
    fn process_packet<Buf: PacketBufferMut>(
        &self,
        nat_tables: &NatTables,
        packet: &mut Packet<Buf>,
    ) {
        let nfi = self.name();

        /* get source VNI annotation */
        let Some(VpcDiscriminant::VNI(src_vni)) = packet.meta().src_vpcd() else {
            warn!("{nfi}: Packet has no source VNI annotation!. Will drop...");
            packet.done(DoneReason::Unroutable);
            return;
        };

        /* get destination VNI annotation */
        let Some(VpcDiscriminant::VNI(dst_vni)) = packet.meta().dst_vpcd else {
            warn!("{nfi}: Packet has no destination VNI annotation!. Will drop...");
            packet.done(DoneReason::Unroutable);
            return;
        };

        /* do the translations needed according to the NAT tables */
        match self.translate(nat_tables, packet, src_vni, dst_vni) {
            Err(error) => {
                debug!("{nfi}: Translation failed: {error}");
                packet.done(translate_error(&error));
            }
            Ok(modified) => {
                if modified {
                    packet.meta_mut().set_checksum_refresh(true);
                    debug!("{nfi}: Packet was NAT'ed");
                } else {
                    debug!("{nfi}: No NAT translation needed");
                }
            }
        }
    }
}

fn translate_error(error: &StatelessNatError) -> DoneReason {
    match error {
        StatelessNatError::NoIpHeader
        | StatelessNatError::IcmpErrorMsg(IcmpErrorMsgError::NoIpHeader) => DoneReason::NotIp,

        StatelessNatError::MissingTable(_) => DoneReason::Unroutable,

        StatelessNatError::IcmpErrorMsg(IcmpErrorMsgError::InvalidPort(_)) => DoneReason::Malformed,

        StatelessNatError::IcmpErrorMsg(IcmpErrorMsgError::NotUnicast(_)) => DoneReason::NatFailure,

        StatelessNatError::FailedToSetDestIp(_)
        | StatelessNatError::FailedToSetSourceIp(_)
        | StatelessNatError::IcmpErrorMsg(
            IcmpErrorMsgError::InvalidIpVersion | IcmpErrorMsgError::NoTranslationPossible,
        ) => DoneReason::InternalFailure,

        StatelessNatError::NoMappingFound
        | StatelessNatError::IcmpErrorMsg(
            IcmpErrorMsgError::BadChecksumIcmp(_) | IcmpErrorMsgError::BadChecksumInnerIpv4(_),
        ) => DoneReason::InvalidChecksum,

        StatelessNatError::IcmpErrorMsg(
            IcmpErrorMsgError::NoEmbeddedHeaders | IcmpErrorMsgError::NoInnerIpHeader,
        ) => DoneReason::Filtered,
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for StatelessNat {
    #[allow(clippy::if_not_else)]
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.filter_map(|mut packet| {
            if !packet.is_done()
                && packet.meta().requires_static_nat()
                && !packet.meta().is_natted()
            {
                // Packet should never be marked for NAT and reach this point if it is not overlay
                debug_assert!(packet.meta().is_overlay());

                // FIXME: Ideally, we'd `enter` once for the whole batch. However, this requires
                // boxing the closures, which may be worse than calling `enter` per packet? ... if
                // not uglier (same thing for StatefulNat)
                if let Some(tablesr) = &self.tablesr.enter() {
                    self.process_packet(tablesr, &mut packet);
                } else {
                    error!("{}: failed to read nat tables", self.name);
                    packet.done(DoneReason::InternalFailure);
                }
            }
            packet.enforce()
        })
    }
}
