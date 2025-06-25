// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::NatDirection;
use crate::iplist::IpList;
use mgmt::models::internal::nat::tables::{NatTables, TrieValue};
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

#[cfg(test)]
mod tests {
    use crate::stateless::StatelessNat;

    use super::*;
    use mgmt::models::external::overlay::vpc::Peering;
    use mgmt::models::external::overlay::vpcpeering::{VpcExpose, VpcManifest};
    use mgmt::models::internal::nat::table_extend;
    use mgmt::models::internal::nat::tables::{NatTables, PerVniTable};
    use net::headers::TryIpv4;
    use net::packet::test_utils::build_test_ipv4_packet;
    use net::vxlan::Vni;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    fn addr_v4(s: &str) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from_str(s).expect("Invalid IPv4 address"))
    }

    fn vni_100() -> Vni {
        Vni::new_checked(100).expect("Failed to create VNI")
    }

    fn build_context() -> NatTables {
        // Build VpcExpose objects
        //
        //     expose:
        //       - ips:
        //         - cidr: 1.1.0.0/16
        //         - cidr: 1.2.0.0/16 # <- 1.2.3.4 will match here
        //         - not: 1.1.5.0/24  # to account for when computing the offset
        //         - not: 1.1.3.0/24  # to account for when computing the offset
        //         - not: 1.1.1.0/24  # to account for when computing the offset
        //         - not: 1.2.2.0/24  # to account for when computing the offset
        //         as:
        //         - cidr: 2.2.0.0/16
        //         - cidr: 2.1.0.0/16 # <- corresp. target range, initially
        //                            # (prefixes in BTreeSet are sorted)
        //                            # offset for 2.1.255.4, before applying exlusions
        //                            # final offset is for 2.2.0.4 after accounting for the one
        //                            # relevant exclusion prefix
        //         - not: 2.1.8.0/24  # to account for when fetching the address in range
        //         - not: 2.2.10.0/24
        //         - not: 2.2.1.0/24  # ignored, offset too low
        //         - not: 2.2.2.0/24  # ignored, offset too low
        //       - ips:
        //         - cidr: 3.0.0.0/16
        //         as:
        //         - cidr: 4.0.0.0/16
        let expose1 = VpcExpose::empty()
            .ip("1.1.0.0/16".into())
            .not("1.1.5.0/24".into())
            .not("1.1.3.0/24".into())
            .not("1.1.1.0/24".into())
            .ip("1.2.0.0/16".into())
            .not("1.2.2.0/24".into())
            .as_range("2.2.0.0/16".into())
            .not_as("2.1.8.0/24".into())
            .not_as("2.2.10.0/24".into())
            .not_as("2.2.1.0/24".into())
            .not_as("2.2.2.0/24".into())
            .as_range("2.1.0.0/16".into());
        let expose2 = VpcExpose::empty()
            .ip("3.0.0.0/16".into())
            .as_range("4.0.0.0/16".into());

        let manifest1 = VpcManifest {
            name: "VPC-1".into(),
            exposes: vec![expose1, expose2],
        };

        //     expose:
        //       - ips:
        //         - cidr: 8.0.0.0/17
        //         - cidr: 9.0.0.0/17
        //         - not: 8.0.0.0/24
        //         as:
        //         - cidr: 3.0.0.0/16
        //         - not: 3.0.1.0/24
        //       - ips:
        //         - cidr: 10.0.0.0/16 # <- corresponding target range
        //         - not: 10.0.1.0/24  # to account for when fetching the address in range
        //         - not: 10.0.2.0/24  # to account for when fetching the address in range
        //         as:
        //         - cidr: 1.1.0.0/17
        //         - cidr: 1.2.0.0/17  # <- 1.2.3.4 will match here
        //         - not: 1.2.0.0/24   # to account for when computing the offset
        //         - not: 1.2.8.0/24
        let expose3 = VpcExpose::empty()
            .ip("8.0.0.0/17".into())
            .not("8.0.0.0/24".into())
            .ip("9.0.0.0/17".into())
            .as_range("3.0.0.0/16".into())
            .not_as("3.0.1.0/24".into());
        let expose4 = VpcExpose::empty()
            .ip("10.0.0.0/16".into())
            .not("10.0.1.0/24".into())
            .not("10.0.2.0/24".into())
            .as_range("1.1.0.0/17".into())
            .as_range("1.2.0.0/17".into())
            .not_as("1.2.0.0/24".into())
            .not_as("1.2.8.0/24".into());

        let manifest2 = VpcManifest {
            name: "VPC-2".into(),
            exposes: vec![expose3, expose4],
        };

        let peering: Peering = Peering {
            name: "test_peering".into(),
            local: manifest1,
            remote: manifest2,
            remote_id: "12345".try_into().expect("Failed to create VPC ID"),
        };

        let mut vni_table = PerVniTable::new();
        table_extend::add_peering(&mut vni_table, &peering).expect("Failed to build NAT tables");

        let vni = vni_100();
        let mut nat_table = NatTables::new();
        nat_table.add_table(vni, vni_table);

        nat_table
    }

    #[test]
    fn test_dst_nat_stateless_44() {
        let nat_tables = build_context();
        let mut nat = StatelessNat::new(NatDirection::DstNat);
        nat.update_tables(nat_tables);

        let packets = vec![build_test_ipv4_packet(u8::MAX).unwrap()]
            .into_iter()
            .map(|mut packet| {
                packet.get_meta_mut().src_vni = Some(vni_100());
                packet
            });

        let packets_out: Vec<_> = nat.process(packets).collect();

        assert_eq!(packets_out.len(), 1);

        let hdr0_out = &packets_out[0]
            .try_ipv4()
            .expect("Failed to get IPv4 header");
        println!("L3 header: {hdr0_out:?}");
        assert_eq!(hdr0_out.destination(), addr_v4("10.0.132.4"));
    }

    #[test]
    fn test_src_nat_stateless_44() {
        let nat_tables = build_context();
        let mut nat = StatelessNat::new(NatDirection::SrcNat);
        nat.update_tables(nat_tables);

        let packets = vec![build_test_ipv4_packet(u8::MAX).unwrap()]
            .into_iter()
            .map(|mut packet| {
                packet.get_meta_mut().src_vni = Some(vni_100());
                packet
            });

        let packets_out: Vec<_> = nat.process(packets).collect();

        assert_eq!(packets_out.len(), 1);

        let hdr0_out = &packets_out[0]
            .try_ipv4()
            .expect("Failed to get IPv4 header");
        println!("L3 header: {hdr0_out:?}");
        assert_eq!(hdr0_out.source().inner(), addr_v4("2.2.0.4"));
    }
}
