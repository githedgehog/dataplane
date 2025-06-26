// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Stateless NAT implementation

pub mod config;
mod iplist;

use crate::NatDirection;
use config::tables::{NatTables, TrieValue};
use iplist::IpList;
use net::buffer::PacketBufferMut;
use net::headers::{Net, TryHeadersMut, TryIpMut};
use net::ipv4::UnicastIpv4Addr;
use net::ipv6::UnicastIpv6Addr;
use net::packet::Packet;
use net::vxlan::Vni;
use pipeline::NetworkFunction;
use std::net::IpAddr;

fn map_ip_src_nat(ranges: &TrieValue, current_ip: &IpAddr) -> IpAddr {
    let current_range = IpList::new(ranges.orig_prefixes(), ranges.orig_excludes());
    let target_range = IpList::new(ranges.target_prefixes(), ranges.target_excludes());
    let offset = current_range.addr_offset_in_prefix(current_ip);
    target_range.addr_from_prefix_offset(&offset)
}

fn map_ip_dst_nat(ranges: &TrieValue, current_ip: &IpAddr) -> IpAddr {
    let current_range = IpList::new(ranges.target_prefixes(), ranges.target_excludes());
    let target_range = IpList::new(ranges.orig_prefixes(), ranges.orig_excludes());
    let offset = current_range.addr_offset_in_prefix(current_ip);
    target_range.addr_from_prefix_offset(&offset)
}

/// A NAT processor, implementing the [`NetworkFunction`] trait. [`StatelessNat`] processes packets
/// to run source or destination Network Address Translation (NAT) on their IP addresses.
#[derive(Debug)]
pub struct StatelessNat {
    context: NatTables,
    direction: NatDirection,
}

impl StatelessNat {
    /// Creates a new [`StatelessNat`] processor. The `direction` indicates whether this processor
    /// should perform source or destination NAT.
    #[must_use]
    pub fn new(direction: NatDirection) -> Self {
        let context = NatTables::new();
        Self { context, direction }
    }

    /// Updates the VNI tables in the NAT processor.
    pub fn update_tables(&mut self, tables: NatTables) {
        self.context = tables;
    }

    fn find_src_nat_ranges(&self, net: &Net, vni: Vni) -> Option<&TrieValue> {
        let table = self.context.tables.get(&vni.as_u32())?;
        let src_ip = net.src_addr();
        table.lookup_src_prefixes(&src_ip)
    }

    fn find_dst_nat_ranges(&self, net: &Net, vni: Vni) -> Option<&TrieValue> {
        let table = self.context.tables.get(&vni.as_u32())?;
        let dst_ip = net.dst_addr();
        table.lookup_dst_prefixes(&dst_ip)
    }

    fn find_nat_ranges(&self, net: &mut Net, vni_opt: Option<Vni>) -> Option<&TrieValue> {
        let vni = vni_opt?;
        match self.direction {
            NatDirection::SrcNat => self.find_src_nat_ranges(net, vni),
            NatDirection::DstNat => self.find_dst_nat_ranges(net, vni),
        }
    }

    /// Applies network address translation to a packet, knowing the current and target ranges.
    fn translate(&self, net: &mut Net, ranges: &TrieValue) -> Option<()> {
        let target_ip = match self.direction {
            NatDirection::SrcNat => {
                let current_ip = net.src_addr();
                map_ip_src_nat(ranges, &current_ip)
            }
            NatDirection::DstNat => {
                let current_ip = net.dst_addr();
                map_ip_dst_nat(ranges, &current_ip)
            }
        };

        match self.direction {
            NatDirection::SrcNat => match (net, target_ip) {
                (Net::Ipv4(hdr), IpAddr::V4(ip)) => {
                    hdr.set_source(UnicastIpv4Addr::new(ip).ok()?);
                }
                (Net::Ipv6(hdr), IpAddr::V6(ip)) => {
                    hdr.set_source(UnicastIpv6Addr::new(ip).ok()?);
                }
                (_, _) => return None,
            },
            NatDirection::DstNat => match (net, target_ip) {
                (Net::Ipv4(hdr), IpAddr::V4(ip)) => {
                    hdr.set_destination(ip);
                }
                (Net::Ipv6(hdr), IpAddr::V6(ip)) => {
                    hdr.set_destination(ip);
                }
                (_, _) => return None,
            },
        }
        Some(())
    }

    /// Processes one packet. This is the main entry point for processing a packet. This is also the
    /// function that we pass to [`StatelessNat::process`] to iterate over packets.
    fn process_packet<Buf: PacketBufferMut>(&mut self, packet: &mut Packet<Buf>) {
        let vni = packet.get_meta().src_vni;
        let Some(net) = packet.headers_mut().try_ip_mut() else {
            return;
        };
        let Some(ranges) = self.find_nat_ranges(net, vni) else {
            return;
        };

        self.translate(net, ranges);
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for StatelessNat {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.map(|mut packet| {
            self.process_packet(&mut packet);
            packet
        })
    }
}
