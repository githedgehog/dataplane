// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Stateless NAT implementation

pub mod natrw;
pub mod setup;
mod test;

use crate::icmp_error_msg::{
    IcmpErrorMsgError, stateful_translate_icmp_inner, validate_checksums_icmp,
};
pub use crate::stateless::natrw::{NatTablesReader, NatTablesWriter}; // re-export
use crate::{NatPort, NatTranslationData};
use net::buffer::PacketBufferMut;
use net::headers::{
    Net, Transport, TryEmbeddedTransport, TryInnerIp, TryIpMut, TryTransport, TryTransportMut,
};
use net::ip::UnicastIpAddr;
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use net::tcp::TcpPort;
use net::udp::UdpPort;
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
    #[error("Unsupported NAT translation")]
    UnsupportedTranslation,
    #[error("Invalid address {0}")]
    // this should not happen if the nat tables contained sanitized data
    InvalidAddress(IpAddr),
    #[error("Can't find NAT tables for VNI {0}")]
    MissingTable(Vni),
    #[error("Failed to translate ICMP inner packet: {0}")]
    IcmpErrorMsg(IcmpErrorMsgError),
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
            .map_err(|_| StatelessNatError::UnsupportedTranslation)
    }

    fn translate_dst(&self, net: &mut Net, target_dst: IpAddr) -> Result<(), StatelessNatError> {
        let nfi = self.name();
        debug!("{nfi}: Changing IP dst: {} -> {target_dst}", net.dst_addr());
        net.try_set_destination(target_dst)
            .map_err(|_| StatelessNatError::UnsupportedTranslation)
    }

    fn get_ports<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> (Option<u16>, Option<u16>) {
        let Some(transport) = packet.try_transport() else {
            return (None, None);
        };
        match transport {
            Transport::Tcp(tcp) => (
                Some(tcp.source().as_u16()),
                Some(tcp.destination().as_u16()),
            ),
            Transport::Udp(udp) => (
                Some(udp.source().as_u16()),
                Some(udp.destination().as_u16()),
            ),
            Transport::Icmp4(_icmp4) => (None, None),
            Transport::Icmp6(_icmp6) => (None, None),
        }
    }

    fn translate_src_port<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        new_port: u16,
    ) -> Result<(), StatelessNatError> {
        let nfi = self.name();
        let transport = packet
            .try_transport_mut()
            .ok_or(StatelessNatError::UnsupportedTranslation)?;
        match transport {
            Transport::Tcp(tcp) => {
                debug!(
                    "{nfi}: Changing L4 source port: {:?} -> {new_port}",
                    tcp.source()
                );
                tcp.set_source(
                    TcpPort::try_from(new_port)
                        .map_err(|_| StatelessNatError::UnsupportedTranslation)?,
                );
            }
            Transport::Udp(udp) => {
                debug!(
                    "{nfi}: Changing L4 source port: {:?} -> {new_port}",
                    udp.source()
                );
                udp.set_source(
                    UdpPort::try_from(new_port)
                        .map_err(|_| StatelessNatError::UnsupportedTranslation)?,
                );
            }
            Transport::Icmp4(_icmp4) => {
                todo!()
            }
            Transport::Icmp6(_icmp6) => {
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
            .ok_or(StatelessNatError::UnsupportedTranslation)?;
        match transport {
            Transport::Tcp(tcp) => {
                debug!(
                    "{nfi}: Changing L4 destination port: {:?} -> {new_port}",
                    tcp.destination()
                );
                tcp.set_destination(
                    TcpPort::try_from(new_port)
                        .map_err(|_| StatelessNatError::UnsupportedTranslation)?,
                );
            }
            Transport::Udp(udp) => {
                debug!(
                    "{nfi}: Changing L4 destination port: {:?} -> {new_port}",
                    udp.destination()
                );
                udp.set_destination(
                    UdpPort::try_from(new_port)
                        .map_err(|_| StatelessNatError::UnsupportedTranslation)?,
                );
            }
            Transport::Icmp4(_icmp4) => {
                todo!()
            }
            Transport::Icmp6(_icmp6) => {
                todo!()
            }
        }
        Ok(())
    }

    fn find_translation_icmp_inner<Buf: PacketBufferMut>(
        table: &PerVniTable,
        packet: &Packet<Buf>,
        dst_vni: Vni,
    ) -> Option<NatTranslationData> {
        let net = packet.try_inner_ip()?;
        let transport = packet.try_embedded_transport();
        // Note how we swap addresses to find NAT ranges: we're sending the inner packet back
        // without swapping source and destination in the header, so we need to swap the ranges we
        // get from the tables lookup.
        let src_mapping = table.find_dst_mapping(
            &net.src_addr(),
            transport.and_then(|t| t.destination().map(NonZero::get)),
        );
        let dst_mapping = table.find_src_mapping(
            &net.dst_addr(),
            transport.and_then(|t| t.destination().map(NonZero::get)),
            dst_vni,
        );

        Some(NatTranslationData {
            src_addr: src_mapping.map(|(addr, _)| addr),
            dst_addr: dst_mapping.map(|(addr, _)| addr),
            src_port: src_mapping.and_then(|(_, port)| {
                port.and_then(|port| NatPort::new_port_checked(port).ok()) // TODO: FIXME ICMP
            }),
            dst_port: dst_mapping.and_then(|(_, port)| {
                port.and_then(|port| NatPort::new_port_checked(port).ok()) // TODO: FIXME ICMP
            }),
        })
    }

    fn translate_icmp_inner_packet_if_any<Buf: PacketBufferMut>(
        table: &PerVniTable,
        packet: &mut Packet<Buf>,
        dst_vni: Vni,
    ) -> Result<(), StatelessNatError> {
        match validate_checksums_icmp(packet) {
            Err(e) => return Err(StatelessNatError::IcmpErrorMsg(e)), // Error, drop packet
            Ok(false) => return Ok(()),                               // No translation needed
            Ok(true) => {} // Translation needed, carry on
        }

        let Some(state) = Self::find_translation_icmp_inner(table, packet, dst_vni) else {
            return Err(StatelessNatError::UnsupportedTranslation);
        };
        stateful_translate_icmp_inner::<Buf>(packet, &state)
            .map_err(StatelessNatError::IcmpErrorMsg)
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

        // Get source and destination IP addresses
        let Some((src_addr, dst_addr)) = packet
            .ip_source()
            .and_then(|src| packet.ip_destination().map(|dst| (src, dst)))
        else {
            error!("{nfi}: Failed to get IP addresses!");
            return Err(StatelessNatError::NoIpHeader);
        };

        // Get NAT tables
        let Some(table) = nat_tables.get_table(src_vni) else {
            error!("{nfi}: Can't find NAT tables for VNI {src_vni}");
            return Err(StatelessNatError::MissingTable(src_vni));
        };

        let (src_port_opt, dst_port_opt) = Self::get_ports(packet);
        let mut modified = false;

        // Run NAT
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

        // If we modified the outer header of the packet, check whether this is an ICMP Error
        // message that requires additional processing
        if !modified {
            return Ok(false);
        }
        Self::translate_icmp_inner_packet_if_any(table, packet, dst_vni)?;

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

        StatelessNatError::UnsupportedTranslation => DoneReason::UnsupportedTransport,

        StatelessNatError::MissingTable(_) => DoneReason::Unroutable,

        StatelessNatError::IcmpErrorMsg(IcmpErrorMsgError::InvalidPort(_)) => DoneReason::Malformed,

        StatelessNatError::InvalidAddress(_)
        | StatelessNatError::IcmpErrorMsg(IcmpErrorMsgError::NotUnicast(_)) => {
            DoneReason::NatFailure
        }

        StatelessNatError::IcmpErrorMsg(
            IcmpErrorMsgError::InvalidIpVersion | IcmpErrorMsgError::NoIdentifier,
        ) => DoneReason::InternalFailure,

        StatelessNatError::IcmpErrorMsg(
            IcmpErrorMsgError::BadChecksumIcmp(_) | IcmpErrorMsgError::BadChecksumInnerIpv4(_),
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
                && packet.meta().requires_stateless_nat()
                && !packet.meta().is_natted()
            {
                // fixme: ideally, we'd `enter` once for the whole batch. However,
                // this requires boxing the closures, which may be worse than
                // calling `enter` per packet? ... if not uglier
                // (same thing for StatefulNat)
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
