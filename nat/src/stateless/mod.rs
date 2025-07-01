// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Stateless NAT implementation

pub mod config;
mod iplist;
pub mod natrw;

pub use crate::stateless::natrw::{NatTablesReader, NatTablesWriter}; // re-export
use config::tables::{NatTables, PerVniTable, TrieValue};
use iplist::{IpList, IpListSubset};
use net::buffer::PacketBufferMut;
use net::headers::{Net, TryHeadersMut, TryIpMut};
use net::ipv4::UnicastIpv4Addr;
use net::ipv6::UnicastIpv6Addr;
use net::packet::{DoneReason, Packet};
use net::vxlan::Vni;
use pipeline::NetworkFunction;
use std::net::IpAddr;
use thiserror::Error;

#[allow(unused)]
use tracing::{debug, error, warn};

#[derive(Error, Debug, PartialEq)]
enum NatError {
    #[error("Unsupported NAT translation")]
    UnsupportedTranslation,
    #[error("Invalid address {0}")]
    // this should not happen if the nat tables contained sanitized data
    InvalidAddress(IpAddr),
}

#[must_use]
fn map_ip_nat(ranges: &TrieValue, current_ip: &IpAddr) -> IpAddr {
    let current_range = IpListSubset::new(ranges.orig_prefix_offset(), *ranges.orig_prefix());
    let target_range = IpList::new(ranges.target_prefixes());
    let offset = current_range.addr_offset_in_prefix(current_ip);
    target_range.addr_from_prefix_offset(&offset)
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
    pub fn name(&self) -> &String {
        &self.name
    }

    /// Translate packet source ip address.
    /// # Errors
    /// Returns `NatError::UnsupportedTranslation` if the translation is unsupported. On success, returns `Ok` indicating
    /// if the address did actually change or not, since the NAT module may map it to the same address.
    fn translate_src(&self, net: &mut Net, ranges_src_nat: &TrieValue) -> Result<bool, NatError> {
        let nfi = self.name();
        let current_src = net.src_addr();
        let target_src = map_ip_nat(ranges_src_nat, &current_src);
        if target_src == current_src {
            return Ok(false);
        }
        match (net, target_src) {
            (Net::Ipv4(hdr), IpAddr::V4(src)) => {
                debug!("{nfi}: Changing ipv4 src: {current_src} -> {src}");
                hdr.set_source(
                    UnicastIpv4Addr::new(src).map_err(|_| NatError::InvalidAddress(target_src))?,
                );
                Ok(true)
            }
            (Net::Ipv6(hdr), IpAddr::V6(src)) => {
                debug!("{nfi}: Changing ipv6 src: {current_src} -> {src}");
                hdr.set_source(
                    UnicastIpv6Addr::new(src).map_err(|_| NatError::InvalidAddress(target_src))?,
                );
                Ok(true)
            }
            _ => Err(NatError::UnsupportedTranslation),
        }
    }

    /// Translate packet destination ip address.
    /// # Errors
    /// Returns `NatError::UnsupportedTranslation` if the translation is unsupported. On success, returns `Ok` indicating
    /// if the address did actually change or not, since the NAT module may map it to the same address.
    fn translate_dst(&self, net: &mut Net, ranges_dst_nat: &TrieValue) -> Result<bool, NatError> {
        let nfi = self.name();
        let current_dst = net.dst_addr();
        let target_dst = map_ip_nat(ranges_dst_nat, &current_dst);
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
            _ => Err(NatError::UnsupportedTranslation),
        }
    }

    /// Applies network address translation to a packet, knowing the current and target ranges.
    /// # Errors
    /// This method may fail if `translate_src` or `translate_dst` fail, which can happen if
    /// addresses are invalid or an unsupported translation is required (e.g. IPv4 -> IPv6).
    fn translate(
        &self,
        net: &mut Net,
        per_vni_table: &PerVniTable,
    ) -> Result<(bool, Option<Vni>), NatError> {
        let (src_ranges, dst_ranges) =
            per_vni_table.find_nat_ranges(net.src_addr(), net.dst_addr());

        // will set to true if packet is modified
        let mut modified = false;
        if let Some(ranges_src) = src_ranges {
            modified |= self.translate_src(net, ranges_src)?;
        }
        let mut dst_vni = None;
        if let Some(ranges_dst) = dst_ranges {
            modified |= self.translate_dst(net, ranges_dst)?;
            dst_vni = ranges_dst.get_vni();
        }
        /* Note: if dst_ranges is not Some(), we will not learn the dst_vni from this module.
        If routing is fine, it may learn it itself. However, if the packet is not to be routed,
        then dst_vni will remain unset and the drop statistics for vpc peerings not be updated. */
        Ok((modified, dst_vni))
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

        /* get vni annotation */
        let Some(vni) = packet.get_meta().src_vni else {
            warn!("{nfi}: Packet has no vni annotation!. Will drop...");
            packet.done(DoneReason::Unroutable);
            return;
        };

        /* get per vni table */
        let Some(table) = nat_tables.get_table(vni) else {
            error!("{nfi}: Can't find nat tables for vni {vni}");
            packet.done(DoneReason::Unroutable);
            return;
        };

        /* get ip header */
        let Some(net) = packet.headers_mut().try_ip_mut() else {
            error!("{nfi}: Failed to get ip headers!");
            packet.done(DoneReason::InternalFailure);
            return;
        };

        /* do the translations needed according to the `PerVniTable` */
        match self.translate(net, table) {
            Err(e) => {
                error!("{nfi}: {e}");
                packet.done(DoneReason::NatFailure);
            }
            Ok((modified, opt_vni)) => {
                if let Some(vni) = opt_vni {
                    packet.get_meta_mut().dst_vni = Some(vni);
                }
                if modified {
                    packet.get_meta_mut().refresh_chksums = true;
                    debug!("{nfi}: Packet was NAT'ed:\n{packet}");
                } else {
                    debug!("{nfi}: No NAT translation needed");
                }
            }
        }
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for StatelessNat {
    #[allow(clippy::if_not_else)]
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.filter_map(|mut packet| {
            if !packet.is_done() && packet.get_meta().nat {
                // fixme: ideally, we'd `enter` once for the whole batch. However,
                // this requires boxing the closures, which may be worse than
                // calling `enter` per packet? ... if not uglier
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
