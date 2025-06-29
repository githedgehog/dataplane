// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Stateless NAT implementation

pub mod config;
mod iplist;
pub mod natrw;

pub use crate::stateless::natrw::{NatTablesReader, NatTablesWriter}; // re-export

use config::tables::{NatTables, TrieValue};
use iplist::IpList;
use net::buffer::PacketBufferMut;
use net::headers::{Net, TryHeadersMut, TryIpMut};
use net::ipv4::UnicastIpv4Addr;
use net::ipv6::UnicastIpv6Addr;
use net::packet::{DoneReason, Packet};
use net::vxlan::Vni;
use pipeline::NetworkFunction;
use std::net::IpAddr;

#[allow(unused)]
use tracing::{debug, error, warn};

#[must_use]
fn map_ip_src_nat(ranges: &TrieValue, current_ip: &IpAddr) -> IpAddr {
    let current_range = IpList::new(ranges.orig_prefixes());
    let target_range = IpList::new(ranges.target_prefixes());
    let offset = current_range.addr_offset_in_prefix(current_ip);
    target_range.addr_from_prefix_offset(&offset)
}

#[must_use]
fn map_ip_dst_nat(ranges: &TrieValue, current_ip: &IpAddr) -> IpAddr {
    let current_range = IpList::new(ranges.target_prefixes());
    let target_range = IpList::new(ranges.orig_prefixes());
    let offset = current_range.addr_offset_in_prefix(current_ip);
    target_range.addr_from_prefix_offset(&offset)
}

/// A NAT processor, implementing the [`NetworkFunction`] trait. [`StatelessNat`] processes packets
/// to run source or destination Network Address Translation (NAT) on their IP addresses.
#[derive(Debug)]
pub struct StatelessNat {
    tablesr: NatTablesReader,
}

impl NatTables {
    fn find_nat_ranges(
        &self,
        net: &mut Net,
        vni_opt: Option<Vni>,
    ) -> Option<(Option<&TrieValue>, Option<&TrieValue>)> {
        let vni = vni_opt?;
        let table = self.get_table(vni)?;

        let src_nat_ranges = table.lookup_src_prefixes(&net.src_addr(), &net.dst_addr());
        let dst_nat_ranges = table.lookup_dst_prefixes(&net.dst_addr());

        Some((src_nat_ranges, dst_nat_ranges))
    }
}

#[allow(clippy::new_without_default)]
impl StatelessNat {
    /// Creates a new [`StatelessNat`] processor, providing a writer to its internal `NatTables`.
    #[must_use]
    pub fn new() -> (Self, NatTablesWriter) {
        #![allow(clippy::similar_names)]
        let tablesw = NatTablesWriter::new();
        let tablesr = tablesw.get_reader();
        (Self { tablesr }, tablesw)
    }
    /// Creates a new [`StatelessNat`] processor as `new()`, but uses the provided `NatTablesReader`.
    #[must_use]
    pub fn with_reader(tablesr: NatTablesReader) -> Self {
        Self { tablesr }
    }

    fn translate_src(net: &mut Net, ranges_src_nat: &TrieValue) -> Option<()> {
        let current_src_ip = net.src_addr();
        let target_src_ip = map_ip_src_nat(ranges_src_nat, &current_src_ip);
        match (net, target_src_ip) {
            (Net::Ipv4(hdr), IpAddr::V4(src_ip)) => {
                debug!("Changing ipv4 src: {current_src_ip} -> {src_ip}");
                hdr.set_source(UnicastIpv4Addr::new(src_ip).ok()?);
            }
            (Net::Ipv6(hdr), IpAddr::V6(src_ip)) => {
                debug!("Changing ipv6 src: {current_src_ip} -> {src_ip}");
                hdr.set_source(UnicastIpv6Addr::new(src_ip).ok()?);
            }
            _ => return None,
        }
        Some(())
    }

    fn translate_dst(net: &mut Net, ranges_dst_nat: &TrieValue) -> Option<()> {
        let current_dst_ip = net.dst_addr();
        let target_dst_ip = map_ip_dst_nat(ranges_dst_nat, &current_dst_ip);
        match (net, target_dst_ip) {
            (Net::Ipv4(hdr), IpAddr::V4(dst_ip)) => {
                debug!("Changing ipv4 dst: {current_dst_ip} -> {dst_ip}");
                hdr.set_destination(dst_ip);
            }
            (Net::Ipv6(hdr), IpAddr::V6(dst_ip)) => {
                debug!("Changing ipv6 dst: {current_dst_ip} -> {dst_ip}");
                hdr.set_destination(dst_ip);
            }
            _ => return None,
        }
        Some(())
    }

    /// Applies network address translation to a packet, knowing the current and target ranges.
    fn translate(
        net: &mut Net,
        ranges_src_nat: Option<&TrieValue>,
        ranges_dst_nat: Option<&TrieValue>,
    ) -> Option<()> {
        if let Some(ranges_src) = ranges_src_nat {
            Self::translate_src(net, ranges_src)?; // fixme
        }
        if let Some(ranges_dst) = ranges_dst_nat {
            Self::translate_dst(net, ranges_dst)?; // fixme
        }
        Some(())
    }

    /// Processes one packet. This is the main entry point for processing a packet. This is also the
    /// function that we pass to [`StatelessNat::process`] to iterate over packets.
    #[allow(clippy::unused_self)]
    fn process_packet<Buf: PacketBufferMut>(
        &self,
        nat_tables: &NatTables,
        packet: &mut Packet<Buf>,
    ) {
        let vni = packet.get_meta().src_vni;
        let Some(net) = packet.headers_mut().try_ip_mut() else {
            return;
        };
        let Some((ranges_src_nat, ranges_dst_nat)) = nat_tables.find_nat_ranges(net, vni) else {
            return;
        };

        Self::translate(net, ranges_src_nat, ranges_dst_nat);
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for StatelessNat {
    #[allow(clippy::if_not_else)]
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.filter_map(|mut packet| {
            if !packet.is_done() {
                // fixme: ideally, we'd `enter` once for the whole batch. However,
                // this requires boxing the closures, which may be worse than
                // calling `enter` per packet? ... if not uglier
                if let Some(tablesr) = &self.tablesr.enter() {
                    self.process_packet(tablesr, &mut packet);
                } else {
                    packet.done(DoneReason::InternalFailure);
                }
            } else {
                warn!("Packet is done and will not NATed");
            }
            packet.enforce()
        })
    }
}
