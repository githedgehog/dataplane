// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Stateless NAT implementation

pub mod natrw;
pub mod setup;
pub(crate) mod test;

use crate::NatPort;
use crate::icmp_handler::icmp_error_msg::{
    IcmpErrorMsgError, nat_translate_icmp_inner_dst, nat_translate_icmp_inner_src,
    validate_checksums_icmp,
};
pub use crate::stateless::natrw::{NatTablesReader, NatTablesWriter}; // re-export
use net::buffer::PacketBufferMut;
use net::headers::{
    Net, NetError, Transport, TryEmbeddedHeaders, TryEmbeddedTransport, TryIcmpAny, TryInnerIp,
    TryIp, TryIpMut, TryTransportMut,
};
use net::ip::UnicastIpAddr;
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use net::vxlan::Vni;
use pipeline::NetworkFunction;
use setup::tables::{NatTableValue, NatTables, PerVniTable};
use std::net::IpAddr;
use std::num::NonZero;
use thiserror::Error;
use tracing::{debug, error, warn};

use tracectl::trace_target;
trace_target!("stateless-nat", LevelFilter::INFO, &["nat", "pipeline"]);

#[derive(Error, Debug, PartialEq)]
enum StatelessNatError {
    #[error("No IP header")]
    NoIpHeader,
    #[error("Invalid address {0}")]
    // this should not happen if the nat tables contained sanitized data
    InvalidAddress(IpAddr),
    #[error("Failed to set source IP: {0}")]
    FailedToSetSourceIp(NetError),
    #[error("Failed to set destination IP: {0}")]
    FailedToSetDestIp(NetError),
    #[error("No transport header")]
    NoTransportHeader,
    #[error("TCP or UDP port cannot be zero")]
    ZeroPort,
    #[error("Failed to set source port")]
    FailedToSetSourcePort,
    #[error("Failed to set destination port")]
    FailedToSetDestPort,
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

    fn translate_src(&self, net: &mut Net, target_src: IpAddr) -> Result<(), StatelessNatError> {
        let new_src = UnicastIpAddr::try_from(target_src)
            .map_err(|_| StatelessNatError::InvalidAddress(target_src))?;
        let nfi = self.name();
        debug!("{nfi}: Changing IP src: {} -> {new_src}", net.src_addr());
        net.try_set_source(new_src)
            .map_err(StatelessNatError::FailedToSetSourceIp)
    }

    fn translate_dst(&self, net: &mut Net, target_dst: IpAddr) -> Result<(), StatelessNatError> {
        let nfi = self.name();
        debug!("{nfi}: Changing IP dst: {} -> {target_dst}", net.dst_addr());
        net.try_set_destination(target_dst)
            .map_err(StatelessNatError::FailedToSetDestIp)
    }

    fn translate_src_port<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        new_port: u16,
    ) -> Result<(), StatelessNatError> {
        let nfi = self.name();
        let transport = packet
            .try_transport_mut()
            .ok_or(StatelessNatError::NoTransportHeader)?;
        match transport {
            Transport::Tcp(_) | Transport::Udp(_) => {
                debug!(
                    "{nfi}: Changing L4 source port: {:?} -> {new_port}",
                    transport.src_port()
                );
                packet
                    .set_source_port(
                        NonZero::try_from(new_port).map_err(|_| StatelessNatError::ZeroPort)?,
                    )
                    .map_err(|_| StatelessNatError::FailedToSetSourcePort)?;
            }
            Transport::Icmp4(_) | Transport::Icmp6(_) => {
                todo!()
            }
        }
        Ok(())
    }

    fn translate_dst_port<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        new_port: u16,
    ) -> Result<(), StatelessNatError> {
        let nfi = self.name();
        let transport = packet
            .try_transport_mut()
            .ok_or(StatelessNatError::NoTransportHeader)?;
        match transport {
            Transport::Tcp(_) | Transport::Udp(_) => {
                debug!(
                    "{nfi}: Changing L4 destination port: {:?} -> {new_port}",
                    transport.dst_port()
                );
                packet
                    .set_destination_port(
                        NonZero::try_from(new_port).map_err(|_| StatelessNatError::ZeroPort)?,
                    )
                    .map_err(|_| StatelessNatError::FailedToSetDestPort)?;
            }
            Transport::Icmp4(_) | Transport::Icmp6(_) => {
                todo!()
            }
        }
        Ok(())
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
        let src_port = src_port.and_then(|p| NatPort::new_port_checked(p).ok());
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
        let dst_port = dst_port.and_then(|p| NatPort::new_port_checked(p).ok());
        nat_translate_icmp_inner_dst::<Buf>(packet, dst_addr, dst_port)
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

        // Get source IP address, port
        let Some(src_addr) = packet.ip_source() else {
            error!("{nfi}: Failed to get source IP address");
            return Err(StatelessNatError::NoIpHeader);
        };
        let src_port_opt = packet.transport_src_port().map(NonZero::get);

        // Source NAT
        if let Some((new_src_addr, new_src_port_opt)) =
            table.find_src_mapping(&src_addr, src_port_opt, dst_vni)
        {
            let net = packet.try_ip_mut().ok_or(StatelessNatError::NoIpHeader)?;
            if new_src_addr != src_addr {
                self.translate_src(net, new_src_addr)?;
                modified = true;
            }
            if let (Some(src_port), Some(new_src_port)) = (src_port_opt, new_src_port_opt)
                && new_src_port != src_port
            {
                self.translate_src_port(packet, new_src_port)?;
                modified = true;
            }
        }

        // ICMP Error messages
        if Self::is_icmp_inner_translation_candidate(packet) {
            validate_checksums_icmp(packet).map_err(StatelessNatError::IcmpErrorMsg)?;
            modified |= Self::translate_icmp_inner_packet_dst_if_any(table, packet, dst_vni)?;
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

        // Get destination IP address, port
        let Some(dst_addr) = packet.ip_destination() else {
            error!("{nfi}: Failed to get destination IP address");
            return Err(StatelessNatError::NoIpHeader);
        };
        let dst_port_opt = packet.transport_dst_port().map(NonZero::get);

        // Destination NAT
        if let Some((new_dst_addr, new_dst_port_opt)) =
            table.find_dst_mapping(&dst_addr, dst_port_opt)
        {
            let net = packet.try_ip_mut().ok_or(StatelessNatError::NoIpHeader)?;
            if new_dst_addr != dst_addr {
                self.translate_dst(net, new_dst_addr)?;
                modified = true;
            }
            if let (Some(dst_port), Some(new_dst_port)) = (dst_port_opt, new_dst_port_opt)
                && new_dst_port != dst_port
            {
                self.translate_dst_port(packet, new_dst_port)?;
                modified = true;
            }
        }

        // ICMP Error messages
        if Self::is_icmp_inner_translation_candidate(packet) {
            modified |= Self::translate_icmp_inner_packet_src_if_any(table, packet)?;
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

        modified |= self.source_nat(table, packet, dst_vni)?;
        modified |= self.destination_nat(table, packet)?;
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
        let Some(VpcDiscriminant::VNI(src_vni)) = packet.meta().src_vpcd else {
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
                    packet.meta_mut().natted(true);
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
        | StatelessNatError::IcmpErrorMsg(IcmpErrorMsgError::BadIpHeader) => DoneReason::NotIp,

        StatelessNatError::FailedToSetSourcePort
        | StatelessNatError::FailedToSetDestPort
        | StatelessNatError::ZeroPort
        | StatelessNatError::NoTransportHeader => DoneReason::NatUnsupportedProto,

        StatelessNatError::MissingTable(_) => DoneReason::Unroutable,

        StatelessNatError::IcmpErrorMsg(IcmpErrorMsgError::InvalidPort(_)) => DoneReason::Malformed,

        StatelessNatError::InvalidAddress(_)
        | StatelessNatError::IcmpErrorMsg(IcmpErrorMsgError::NotUnicast(_)) => {
            DoneReason::NatFailure
        }

        StatelessNatError::FailedToSetDestIp(_)
        | StatelessNatError::FailedToSetSourceIp(_)
        | StatelessNatError::IcmpErrorMsg(
            IcmpErrorMsgError::InvalidIpVersion | IcmpErrorMsgError::NoTranslationPossible,
        ) => DoneReason::InternalFailure,

        StatelessNatError::NoMappingFound
        | StatelessNatError::IcmpErrorMsg(
            IcmpErrorMsgError::BadChecksumIcmp(_) | IcmpErrorMsgError::BadChecksumInnerIpv4(_),
        ) => DoneReason::InvalidChecksum,
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
                && packet.meta().requires_stateless_nat()
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
