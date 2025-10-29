// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Stateless NAT implementation

pub mod natrw;
pub mod setup;
mod test;

use crate::NatTranslationData;
use crate::icmp_error_msg::{
    IcmpErrorMsgError, stateful_translate_icmp_inner, validate_checksums_icmp,
};
pub use crate::stateless::natrw::{NatTablesReader, NatTablesWriter}; // re-export
use net::buffer::PacketBufferMut;
use net::headers::{Net, TryHeadersMut, TryInnerIp, TryIpMut};
use net::ipv4::UnicastIpv4Addr;
use net::ipv6::UnicastIpv6Addr;
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use net::vxlan::Vni;
use pipeline::NetworkFunction;
use setup::tables::{NatTableValue, NatTables, PerVniTable};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;

#[allow(unused)]
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
    #[error("Failed to map IP address: {0}")]
    MappingError(IpAddr),
    #[error("Failed to map IP address offset: {0}")]
    MappingOffsetError(u128),
    #[error("Can't find NAT tables for VNI {0}")]
    MissingTable(Vni),
    #[error("Failed to translate ICMP inner packet: {0}")]
    IcmpErrorMsg(IcmpErrorMsgError),
}

fn addr_offset_in_range(range_start: &IpAddr, addr: &IpAddr) -> Result<u128, StatelessNatError> {
    match (range_start, addr) {
        (IpAddr::V4(range_start), IpAddr::V4(addr)) => {
            let addr_bits = addr.to_bits();
            if addr_bits < range_start.to_bits() {
                return Err(StatelessNatError::MappingError(IpAddr::V4(*addr)));
            }
            Ok(u128::from(addr_bits - range_start.to_bits()))
        }
        (IpAddr::V6(range_start), IpAddr::V6(addr)) => {
            let addr_bits = addr.to_bits();
            if addr_bits < range_start.to_bits() {
                return Err(StatelessNatError::MappingError(IpAddr::V6(*addr)));
            }
            Ok(addr_bits - range_start.to_bits())
        }
        _ => Err(StatelessNatError::MappingError(*addr)),
    }
}

fn addr_from_offset(range_start: &IpAddr, offset: u128) -> Result<IpAddr, StatelessNatError> {
    match range_start {
        IpAddr::V4(range_start) => {
            let bits = range_start.to_bits()
                + u32::try_from(offset)
                    .map_err(|_| StatelessNatError::MappingOffsetError(offset))?;
            Ok(IpAddr::V4(Ipv4Addr::from(bits)))
        }
        IpAddr::V6(range_start) => {
            let bits = range_start.to_bits() + offset;
            Ok(IpAddr::V6(Ipv6Addr::from(bits)))
        }
    }
}

fn map_ip_nat(
    stage_name: &str,
    ranges: &NatTableValue,
    current_ip: &IpAddr,
) -> Result<IpAddr, StatelessNatError> {
    let offset = addr_offset_in_range(&ranges.orig_range_start, current_ip)?;
    debug!(
        "{stage_name}: Mapping {current_ip} from range {}-{} to range {}: found offset {offset}",
        ranges.orig_range_start, ranges.orig_range_end, ranges.target_range_start
    );
    addr_from_offset(&ranges.target_range_start, offset)
}

/// A NAT processor, implementing the [`NetworkFunction`] trait. [`StatelessNat`] processes packets
/// to run source or destination Network Address Translation (NAT) on their IP addresses.
#[derive(Debug)]
pub struct StatelessNat {
    name: String,
    tablesr: NatTablesReader,
}

#[allow(clippy::new_without_default)]
impl StatelessNat {
    /// Creates a new [`StatelessNat`] processor, providing a writer to its internal `NatTables`.
    #[must_use]
    pub fn new(name: &str) -> (Self, NatTablesWriter) {
        #![allow(clippy::similar_names)]
        let tablesw = NatTablesWriter::new();
        let tablesr = tablesw.get_reader();
        (
            Self {
                name: name.to_string(),
                tablesr,
            },
            tablesw,
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

    /// Translate packet source ip address.
    /// # Errors
    /// Returns `NatError::UnsupportedTranslation` if the translation is unsupported. On success, returns `Ok` indicating
    /// if the address did actually change or not, since the NAT module may map it to the same address.
    fn translate_src(
        &self,
        net: &mut Net,
        ranges_src_nat: &NatTableValue,
    ) -> Result<bool, StatelessNatError> {
        let nfi = self.name();
        let current_src = net.src_addr();
        let target_src = map_ip_nat(nfi, ranges_src_nat, &current_src)
            .map_err(|_| StatelessNatError::MappingError(current_src))?;
        if target_src == current_src {
            return Ok(false);
        }
        match (net, target_src) {
            (Net::Ipv4(hdr), IpAddr::V4(src)) => {
                debug!("{nfi}: Changing ipv4 src: {current_src} -> {src}");
                hdr.set_source(
                    UnicastIpv4Addr::new(src)
                        .map_err(|_| StatelessNatError::InvalidAddress(target_src))?,
                );
                Ok(true)
            }
            (Net::Ipv6(hdr), IpAddr::V6(src)) => {
                debug!("{nfi}: Changing ipv6 src: {current_src} -> {src}");
                hdr.set_source(
                    UnicastIpv6Addr::new(src)
                        .map_err(|_| StatelessNatError::InvalidAddress(target_src))?,
                );
                Ok(true)
            }
            _ => Err(StatelessNatError::UnsupportedTranslation),
        }
    }

    /// Translate packet destination ip address.
    /// # Errors
    /// Returns `NatError::UnsupportedTranslation` if the translation is unsupported. On success, returns `Ok` indicating
    /// if the address did actually change or not, since the NAT module may map it to the same address.
    fn translate_dst(
        &self,
        net: &mut Net,
        ranges_dst_nat: &NatTableValue,
    ) -> Result<bool, StatelessNatError> {
        let nfi = self.name();
        let current_dst = net.dst_addr();
        let target_dst = map_ip_nat(nfi, ranges_dst_nat, &current_dst)
            .map_err(|_| StatelessNatError::MappingError(current_dst))?;
        if target_dst == current_dst {
            return Ok(false);
        }
        match (net, target_dst) {
            (Net::Ipv4(hdr), IpAddr::V4(dst)) => {
                debug!("{nfi}: Changing ipv4 dst: {current_dst} -> {dst}");
                hdr.set_destination(dst);
                Ok(true)
            }
            (Net::Ipv6(hdr), IpAddr::V6(dst)) => {
                debug!("{nfi}: Changing ipv6 dst: {current_dst} -> {dst}");
                hdr.set_destination(dst);
                Ok(true)
            }
            _ => Err(StatelessNatError::UnsupportedTranslation),
        }
    }

    fn find_translation_icmp_inner<Buf: PacketBufferMut>(
        &self,
        table: &PerVniTable,
        packet: &Packet<Buf>,
        dst_vni: Vni,
    ) -> Option<NatTranslationData> {
        let net = packet.try_inner_ip()?;
        // Note how we swap addresses to find NAT ranges: we're sending the inner packet back
        // without swapping source and destination in the header, so we need to swap the ranges we
        // get from the tables lookup.
        let (dst_ranges, src_ranges) =
            table.find_nat_ranges(net.dst_addr(), net.src_addr(), dst_vni);

        let src_addr = src_ranges.and_then(|r| map_ip_nat(self.name(), &r, &net.src_addr()).ok());
        let dst_addr = dst_ranges.and_then(|r| map_ip_nat(self.name(), &r, &net.dst_addr()).ok());
        Some(NatTranslationData {
            src_addr,
            dst_addr,
            ..Default::default()
        })
    }

    fn translate_icmp_inner_packet_if_any<Buf: PacketBufferMut>(
        &self,
        table: &PerVniTable,
        packet: &mut Packet<Buf>,
        dst_vni: Vni,
    ) -> Result<(), StatelessNatError> {
        match validate_checksums_icmp(packet) {
            Err(e) => return Err(StatelessNatError::IcmpErrorMsg(e)), // Error, drop packet
            Ok(false) => return Ok(()),                               // No translation needed
            Ok(true) => {} // Translation needed, carry on
        }

        let Some(state) = self.find_translation_icmp_inner(table, packet, dst_vni) else {
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

        // Get IP header
        let Some(net) = packet.headers_mut().try_ip_mut() else {
            error!("{nfi}: Failed to get IP headers!");
            return Err(StatelessNatError::NoIpHeader);
        };

        // Get NAT tables
        let Some(table) = nat_tables.get_table(src_vni) else {
            error!("{nfi}: Can't find NAT tables for VNI {src_vni}");
            return Err(StatelessNatError::MissingTable(src_vni));
        };

        let (src_ranges, dst_ranges) =
            table.find_nat_ranges(net.src_addr(), net.dst_addr(), dst_vni);

        // will set to true if packet is modified
        let mut modified = false;
        if let Some(ranges_src) = src_ranges {
            modified |= self.translate_src(net, &ranges_src)?;
        }

        if let Some(ranges_dst) = dst_ranges {
            modified |= self.translate_dst(net, &ranges_dst)?;
        }

        // If we modified the outer header of the packet, check whether this is an ICMP Error
        // message that requires additional processing
        if !modified {
            return Ok(false);
        }
        self.translate_icmp_inner_packet_if_any(table, packet, dst_vni)?;

        Ok(modified)
    }

    /// Processes one packet. This is the main entry point for processing a packet. This is also the
    /// function that we pass to [`StatelessNat::process`] to iterate over packets.
    #[allow(clippy::unused_self)]
    fn process_packet<Buf: PacketBufferMut>(
        &self,
        nat_tables: &NatTables,
        packet: &mut Packet<Buf>,
    ) {
        let nfi = self.name();

        /* get source VNI annotation */
        let Some(VpcDiscriminant::VNI(src_vni)) = packet.get_meta().src_vpcd else {
            warn!("{nfi}: Packet has no source VNI annotation!. Will drop...");
            packet.done(DoneReason::Unroutable);
            return;
        };

        /* get destination VNI annotation */
        let Some(VpcDiscriminant::VNI(dst_vni)) = packet.get_meta().dst_vpcd else {
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
                // we have already natted the packet. Prevent stateful from doing so.
                // This is a temporary hack.
                packet.get_meta_mut().set_nat(false);
                if modified {
                    packet.get_meta_mut().set_checksum_refresh(true);
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
        | StatelessNatError::IcmpErrorMsg(IcmpErrorMsgError::BadIpHeader) => DoneReason::NotIp,

        StatelessNatError::UnsupportedTranslation => DoneReason::UnsupportedTransport,

        StatelessNatError::MissingTable(_) => DoneReason::Unroutable,

        StatelessNatError::IcmpErrorMsg(IcmpErrorMsgError::InvalidPort(_)) => DoneReason::Malformed,

        StatelessNatError::InvalidAddress(_)
        | StatelessNatError::MappingError(_)
        | StatelessNatError::MappingOffsetError(_)
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
            if !packet.is_done() && packet.get_meta().nat() {
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
