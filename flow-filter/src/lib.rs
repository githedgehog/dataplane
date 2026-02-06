// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Flow-filter pipeline stage
//!
//! [`FlowFilter`] is a pipeline stage serving two purposes:
//!
//! - It retrieves the destination VPC discriminant for the packet, when possible, and attaches it
//!   to packet metadata.
//!
//! - It validates that the packet is associated with an existing peering connection, as defined in
//!   the user-provided configuration. Packets that do not have a source IP, port and destination
//!   IP, port corresponding to existing, valid connections between the prefixes in exposed lists of
//!   peerings, get dropped.

use crate::tables::{RemoteData, VpcdLookupResult};
use flow_info::FlowStatus;
use flow_info::flow_info_item::ExtractRef;
use net::buffer::PacketBufferMut;
use net::headers::{TryIp, TryTransport};
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use pipeline::NetworkFunction;
use std::net::IpAddr;
use std::num::NonZero;
use tracing::{debug, error};

mod filter_rw;
mod setup;
mod tables;

pub use filter_rw::{FlowFilterTableReader, FlowFilterTableReaderFactory, FlowFilterTableWriter};
pub use tables::FlowFilterTable;

use tracectl::trace_target;

trace_target!("flow-filter", LevelFilter::INFO, &["pipeline"]);

/// A structure to implement the flow-filter pipeline stage.
pub struct FlowFilter {
    name: String,
    tablesr: FlowFilterTableReader,
}

impl FlowFilter {
    /// Create a new [`FlowFilter`] instance.
    pub fn new(name: &str, tablesr: FlowFilterTableReader) -> Self {
        Self {
            name: name.to_string(),
            tablesr,
        }
    }

    /// Attempt to determine destination vpc from packet's flow-info
    fn check_packet_flow_info<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
    ) -> Option<VpcDiscriminant> {
        let nfi = &self.name;

        let Some(flow_info) = &packet.meta().flow_info else {
            debug!("{nfi}: Packet does not contain any flow-info");
            return None;
        };

        let Ok(locked_info) = flow_info.locked.read() else {
            debug!("{nfi}: Warning! failed to lock flow-info for packet");
            packet.done(DoneReason::InternalFailure);
            return None;
        };

        let vpcd = locked_info
            .dst_vpcd
            .as_ref()
            .and_then(|d| d.extract_ref::<VpcDiscriminant>());

        if let Some(dst_vpcd) = vpcd {
            let status = flow_info.status();
            if status == FlowStatus::Active {
                debug!("{nfi}: dst_vpcd discriminant is {dst_vpcd} (from active flow-info entry)");
                Some(*dst_vpcd)
            } else {
                debug!("{nfi}: Found flow-info with dst_vpcd {dst_vpcd} but status {status}");
                None
            }
        } else {
            debug!("{nfi}: No Vpc discriminant found. Will drop packet");
            None
        }
    }

    /// Process a packet.
    fn process_packet<Buf: PacketBufferMut>(
        &self,
        tablesr: &left_right::ReadGuard<'_, FlowFilterTable>,
        packet: &mut Packet<Buf>,
    ) {
        let nfi = &self.name;

        let Some(net) = packet.try_ip() else {
            debug!("{nfi}: No IP headers found, dropping packet");
            packet.done(DoneReason::NotIp);
            return;
        };

        let Some(src_vpcd) = packet.meta().src_vpcd else {
            debug!("{nfi}: Missing source VPC discriminant, dropping packet");
            packet.done(DoneReason::Unroutable);
            return;
        };

        let src_ip = net.src_addr();
        let dst_ip = net.dst_addr();
        let ports = packet.try_transport().and_then(|t| {
            t.src_port()
                .map(NonZero::get)
                .zip(t.dst_port().map(NonZero::get))
        });

        // For Display
        let tuple = FlowTuple::new(src_vpcd, src_ip, dst_ip, ports);

        let Some(dst_data) = tablesr.lookup(src_vpcd, &src_ip, &dst_ip, ports) else {
            debug!("{nfi}: No valid destination VPC found for flow {tuple}, dropping packet");
            packet.done(DoneReason::Filtered);
            return;
        };

        let dst_vpcd = match dst_data {
            VpcdLookupResult::Single(dst_data) => {
                set_nat_requirements(packet, &dst_data);
                dst_data.vpcd
            }
            VpcdLookupResult::MultipleMatches => {
                debug!(
                    "{nfi}: Found multiple matches for destination VPC for flow {tuple}. Checking for a flow table entry..."
                );

                if let Some(dst_vpcd) = self.check_packet_flow_info(packet) {
                    packet.meta_mut().set_stateful_nat(true);
                    dst_vpcd
                } else {
                    debug!(
                        "{nfi}: No flow table entry found for flow {tuple}, unable to decide what destination VPC to use, dropping packet"
                    );
                    packet.done(DoneReason::Filtered);
                    return;
                }
            }
        };

        debug!("{nfi}: Flow {tuple} is allowed, setting packet dst_vpcd to {dst_vpcd}");
        packet.meta_mut().dst_vpcd = Some(dst_vpcd);
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for FlowFilter {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.filter_map(|mut packet| {
            if let Some(tablesr) = &self.tablesr.enter() {
                if !packet.is_done() && packet.meta().is_overlay() {
                    self.process_packet(tablesr, &mut packet);
                }
            } else {
                error!("{}: failed to read flow filter table", self.name);
                packet.done(DoneReason::InternalFailure);
            }
            packet.enforce()
        })
    }
}

// Only used for Display
struct OptPort(Option<u16>);
impl std::fmt::Display for OptPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(port) = self.0 {
            write!(f, ":{port}")?;
        }
        Ok(())
    }
}

// Only used for Display
struct FlowTuple {
    src_vpcd: VpcDiscriminant,
    src_addr: IpAddr,
    dst_addr: IpAddr,
    src_port: OptPort,
    dst_port: OptPort,
}

impl FlowTuple {
    fn new(
        src_vpcd: VpcDiscriminant,
        src_addr: IpAddr,
        dst_addr: IpAddr,
        ports: Option<(u16, u16)>,
    ) -> Self {
        let ports = ports.unzip();
        Self {
            src_vpcd,
            src_addr,
            dst_addr,
            src_port: OptPort(ports.0),
            dst_port: OptPort(ports.1),
        }
    }
}

impl std::fmt::Display for FlowTuple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "srcVpc={} src={}{} dst={}{}",
            self.src_vpcd, self.src_addr, self.src_port, self.dst_addr, self.dst_port
        )
    }
}

fn set_nat_requirements<Buf: PacketBufferMut>(packet: &mut Packet<Buf>, data: &RemoteData) {
    if data.requires_stateful_nat() {
        packet.meta_mut().set_stateful_nat(true);
    }
    if data.requires_stateless_nat() {
        packet.meta_mut().set_stateless_nat(true);
    }
    if data.requires_port_forwarding() {
        packet.meta_mut().set_port_forwarding(true);
    }
    // FIXME: we should forbid/(warn about) combos that we don't support
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter_rw::FlowFilterTableWriter;
    use crate::tables::NatRequirement;
    use config::external::overlay::Overlay;
    use config::external::overlay::vpc::{Vpc, VpcTable};
    use config::external::overlay::vpcpeering::{
        VpcExpose, VpcManifest, VpcPeering, VpcPeeringTable,
    };
    use lpm::prefix::{PortRange, Prefix};
    use net::buffer::TestBuffer;
    use net::headers::{Net, TryHeadersMut, TryIpMut};
    use net::ipv4::addr::UnicastIpv4Addr;
    use net::ipv6::addr::UnicastIpv6Addr;
    use net::packet::test_utils::{
        IcmpEchoDirection, build_test_icmp4_echo, build_test_ipv4_packet, build_test_ipv6_packet,
    };
    use net::packet::{DoneReason, Packet, VpcDiscriminant};
    use net::vxlan::Vni;
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use tracing_test::traced_test;

    fn vpcd(vni: u32) -> VpcDiscriminant {
        VpcDiscriminant::from_vni(Vni::new_checked(vni).unwrap())
    }

    fn set_src_addr(packet: &mut Packet<TestBuffer>, addr: IpAddr) {
        let net = packet.headers_mut().try_ip_mut().unwrap();
        match net {
            Net::Ipv4(ip) => {
                ip.set_source(UnicastIpv4Addr::try_from(addr).unwrap());
            }
            Net::Ipv6(ip) => {
                ip.set_source(UnicastIpv6Addr::try_from(addr).unwrap());
            }
        }
    }

    fn set_dst_addr(packet: &mut Packet<TestBuffer>, addr: IpAddr) {
        let net = packet.headers_mut().try_ip_mut().unwrap();
        match net {
            Net::Ipv4(ip) => {
                ip.set_destination(UnicastIpv4Addr::try_from(addr).unwrap().into());
            }
            Net::Ipv6(ip) => {
                ip.set_destination(UnicastIpv6Addr::try_from(addr).unwrap().into());
            }
        }
    }

    fn create_test_packet(
        src_vpcd: Option<VpcDiscriminant>,
        src_addr: IpAddr,
        dst_addr: IpAddr,
    ) -> Packet<TestBuffer> {
        let mut packet = match dst_addr {
            IpAddr::V4(_) => build_test_ipv4_packet(100).unwrap(),
            IpAddr::V6(_) => build_test_ipv6_packet(100).unwrap(),
        };
        packet.meta_mut().set_overlay(true);
        set_src_addr(&mut packet, src_addr);
        set_dst_addr(&mut packet, dst_addr);
        packet.meta_mut().src_vpcd = src_vpcd;
        packet
    }

    fn create_test_icmp_v4_packet(
        src_vpcd: Option<VpcDiscriminant>,
        src_addr: Ipv4Addr,
        dst_addr: Ipv4Addr,
    ) -> Packet<TestBuffer> {
        let mut packet =
            build_test_icmp4_echo(src_addr, dst_addr, 1, IcmpEchoDirection::Request).unwrap();
        packet.meta_mut().src_vpcd = src_vpcd;
        packet.meta_mut().set_overlay(true);
        packet
    }

    #[test]
    fn test_flow_filter_packet_allowed() {
        // Setup table
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let dst_data = RemoteData::new(vpcd(200), None, None);

        table
            .insert(
                src_vpcd,
                VpcdLookupResult::Single(dst_data),
                Prefix::from("10.0.0.0/24"),
                None,
                Prefix::from("20.0.0.0/24"),
                None,
            )
            .unwrap();

        let mut writer = FlowFilterTableWriter::new();
        writer.update_flow_filter_table(table);

        let mut flow_filter = FlowFilter::new("test-filter", writer.get_reader());

        // Create test packet
        let packet = create_test_packet(
            Some(src_vpcd),
            "10.0.0.5".parse().unwrap(),
            "20.0.0.10".parse().unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        assert!(!packets[0].is_done());
        assert_eq!(packets[0].meta().dst_vpcd, Some(dst_data.vpcd));
    }

    #[test]
    fn test_flow_filter_packet_filtered() {
        // Setup table
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let dst_data = RemoteData::new(vpcd(200), Some(NatRequirement::Stateful), None);

        table
            .insert(
                src_vpcd,
                VpcdLookupResult::Single(dst_data),
                Prefix::from("10.0.0.0/24"),
                None,
                Prefix::from("20.0.0.0/24"),
                None,
            )
            .unwrap();

        let mut writer = FlowFilterTableWriter::new();
        writer.update_flow_filter_table(table);

        let mut flow_filter = FlowFilter::new("test-filter", writer.get_reader());

        // Create test packet with non-matching destination
        let packet = create_test_packet(
            Some(src_vpcd),
            "10.0.0.5".parse().unwrap(),
            "30.0.0.10".parse().unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].get_done(), Some(DoneReason::Filtered));
    }

    #[test]
    fn test_flow_filter_missing_src_vpcd() {
        let table = FlowFilterTable::new();
        let mut writer = FlowFilterTableWriter::new();
        writer.update_flow_filter_table(table);

        let mut flow_filter = FlowFilter::new("test-filter", writer.get_reader());

        // Create test packet without src_vpcd
        let packet = create_test_packet(
            None,
            "10.0.0.5".parse().unwrap(),
            "20.0.0.10".parse().unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].get_done(), Some(DoneReason::Unroutable));
    }

    #[test]
    fn test_flow_filter_no_matching_src_prefix() {
        // Setup table
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let dst_data = RemoteData::new(vpcd(200), None, None);

        table
            .insert(
                src_vpcd,
                VpcdLookupResult::Single(dst_data),
                Prefix::from("10.0.0.0/24"),
                None,
                Prefix::from("20.0.0.0/24"),
                None,
            )
            .unwrap();

        let mut writer = FlowFilterTableWriter::new();
        writer.update_flow_filter_table(table);

        let mut flow_filter = FlowFilter::new("test-filter", writer.get_reader());

        // Create test packet with non-matching source address
        let packet = create_test_packet(
            Some(src_vpcd),
            "11.0.0.5".parse().unwrap(),
            "20.0.0.10".parse().unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].get_done(), Some(DoneReason::Filtered));
    }

    #[test]
    fn test_flow_filter_multiple_matches_no_dst_vpcd() {
        // Setup table with overlapping destination prefixes from different VPCs
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);

        // Manually set up a scenario where dst_vpcd lookup returns MultipleMatches
        // This happens when the same destination can be reached from multiple VPCs
        table
            .insert(
                src_vpcd,
                VpcdLookupResult::MultipleMatches,
                Prefix::from("10.0.0.0/24"),
                None,
                Prefix::from("20.0.0.0/24"),
                None,
            )
            .unwrap();

        let mut writer = FlowFilterTableWriter::new();
        writer.update_flow_filter_table(table);

        let mut flow_filter = FlowFilter::new("test-filter", writer.get_reader());

        // Create test packet
        let packet = create_test_packet(
            Some(vpcd(100)),
            "10.0.0.5".parse().unwrap(),
            "20.0.0.10".parse().unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        // Without table flow lookup we can't find the right dst_vpcd, so we should drop the packet
        assert!(packets[0].is_done());
        assert!(packets[0].meta().dst_vpcd.is_none());
    }

    #[test]
    fn test_flow_filter_table_overlap_cases() {
        let vni1 = Vni::new_checked(100).unwrap();
        let vni2 = Vni::new_checked(200).unwrap();
        let vni3 = Vni::new_checked(300).unwrap();

        let mut vpc_table = VpcTable::new();
        vpc_table
            .add(Vpc::new("vpc1", "VPC01", vni1.as_u32()).unwrap())
            .unwrap();
        vpc_table
            .add(Vpc::new("vpc2", "VPC02", vni2.as_u32()).unwrap())
            .unwrap();
        vpc_table
            .add(Vpc::new("vpc3", "VPC03", vni3.as_u32()).unwrap())
            .unwrap();

        // - vpc1-to-vpc2:
        //     VPC01:
        //       prefixes:
        //       - 1.0.0.0/24
        //     VPC02:
        //       prefixes:
        //       - 5.0.0.0/24
        //
        // - vpc2-to-vpc3:
        //     VPC02:
        //       prefixes:
        //       - 5.0.0.0/24
        //       - 6.0.0.0/24
        //     VPC03:
        //       prefixes:
        //       - 1.0.0.64/26    // 1.0.0.64 to 1.0.0.127
        let mut peering_table = VpcPeeringTable::new();
        peering_table
            .add(VpcPeering::new(
                "vpc1-to-vpc2",
                VpcManifest {
                    name: "vpc1".to_string(),
                    exposes: vec![VpcExpose::empty().ip("1.0.0.0/24".into())],
                },
                VpcManifest {
                    name: "vpc2".to_string(),
                    exposes: vec![VpcExpose::empty().ip("5.0.0.0/24".into())],
                },
                None,
            ))
            .unwrap();

        peering_table
            .add(VpcPeering::new(
                "vpc2-to-vpc3",
                VpcManifest {
                    name: "vpc2".to_string(),
                    exposes: vec![
                        VpcExpose::empty().ip("5.0.0.0/24".into()),
                        VpcExpose::empty().ip("6.0.0.0/24".into()),
                    ],
                },
                VpcManifest {
                    name: "vpc3".to_string(),
                    exposes: vec![VpcExpose::empty().ip("1.0.0.64/26".into())],
                },
                None,
            ))
            .unwrap();

        let mut overlay = Overlay::new(vpc_table, peering_table);
        // Build overlay.vpc_table's peerings from peering_table, with no validation.
        // We don't validate because overlapping prefixes actually make the config invalid; but it
        // doesn't matter for the test.
        overlay.collect_peerings();

        let table = FlowFilterTable::build_from_overlay(&overlay).unwrap();

        let mut writer = FlowFilterTableWriter::new();
        writer.update_flow_filter_table(table);

        let mut flow_filter = FlowFilter::new("test-filter", writer.get_reader());

        // Test with packets

        // VPC-1 -> VPC-2: No ambiguity
        let packet = create_test_packet(
            Some(vpcd(100)),
            "1.0.0.5".parse().unwrap(),
            "5.0.0.10".parse().unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        assert!(!packets[0].is_done(), "{:?}", packets[0].get_done());
        assert_eq!(packets[0].meta().dst_vpcd, Some(vpcd(vni2.into())));

        // VPC-3 -> VPC-2: No ambiguity
        let packet = create_test_packet(
            Some(vpcd(300)),
            "1.0.0.70".parse().unwrap(),
            "5.0.0.10".parse().unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        assert!(!packets[0].is_done(), "{:?}", packets[0].get_done());
        assert_eq!(packets[0].meta().dst_vpcd, Some(vpcd(vni2.into())));

        // VPC-2 -> VPC-1 using lower non-overlapping destination prefix section
        let packet = create_test_packet(
            Some(vpcd(200)),
            "5.0.0.10".parse().unwrap(),
            "1.0.0.5".parse().unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        assert!(!packets[0].is_done(), "{:?}", packets[0].get_done());
        assert_eq!(packets[0].meta().dst_vpcd, Some(vpcd(vni1.into())));

        // VPC-2 -> VPC-1 using upper non-overlapping destination prefix section
        let packet = create_test_packet(
            Some(vpcd(200)),
            "5.0.0.10".parse().unwrap(),
            "1.0.0.205".parse().unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        assert!(!packets[0].is_done(), "{:?}", packets[0].get_done());
        assert_eq!(packets[0].meta().dst_vpcd, Some(vpcd(vni1.into())));

        // VPC-2 -> VPC-3 using non-overlapping source prefix
        let packet = create_test_packet(
            Some(vpcd(200)),
            "6.0.0.11".parse().unwrap(),
            "1.0.0.70".parse().unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        assert!(!packets[0].is_done(), "{:?}", packets[0].get_done());
        assert_eq!(packets[0].meta().dst_vpcd, Some(vpcd(vni3.into())));

        // VPC-2 -> VPC-??? using overlapping prefix sections: multiple matches
        let packet = create_test_packet(
            Some(vpcd(200)),
            "5.0.0.10".parse().unwrap(),
            "1.0.0.70".parse().unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        assert!(packets[0].is_done(), "{:?}", packets[0].get_done());
        assert_eq!(packets[0].meta().dst_vpcd, None)
    }

    #[test]
    fn test_flow_filter_ipv6() {
        // Setup table
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let dst_data = RemoteData::new(
            vpcd(200),
            Some(NatRequirement::Stateless),
            Some(NatRequirement::Stateless),
        );

        table
            .insert(
                src_vpcd,
                VpcdLookupResult::Single(dst_data),
                Prefix::from("2001:db8::/32"),
                None,
                Prefix::from("2001:db9::/32"),
                None,
            )
            .unwrap();

        let mut writer = FlowFilterTableWriter::new();
        writer.update_flow_filter_table(table);

        let mut flow_filter = FlowFilter::new("test-filter", writer.get_reader());

        // Create test packet
        let packet = create_test_packet(
            Some(src_vpcd),
            "2001:db8::1".parse().unwrap(),
            "2001:db9::1".parse().unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        assert!(!packets[0].is_done());
        assert_eq!(packets[0].meta().dst_vpcd, Some(dst_data.vpcd));
    }

    #[test]
    fn test_flow_filter_packet_icmp_allowed() {
        // Setup table
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let dst_data = RemoteData::new(vpcd(200), Some(NatRequirement::Stateful), None);

        table
            .insert(
                src_vpcd,
                VpcdLookupResult::Single(dst_data),
                Prefix::from("10.0.0.0/24"),
                None,
                Prefix::from("20.0.0.0/24"),
                None,
            )
            .unwrap();

        let mut writer = FlowFilterTableWriter::new();
        writer.update_flow_filter_table(table);

        let mut flow_filter = FlowFilter::new("test-filter", writer.get_reader());

        // Create test packet
        let packet = create_test_icmp_v4_packet(
            Some(src_vpcd),
            Ipv4Addr::from_str("10.0.0.5").unwrap(),
            Ipv4Addr::from_str("20.0.0.10").unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        assert!(!packets[0].is_done());
        assert_eq!(packets[0].meta().dst_vpcd, Some(dst_data.vpcd));
    }

    #[test]
    fn test_flow_filter_packet_icmp_filtered() {
        // Setup table
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let dst_data = RemoteData::new(vpcd(200), None, None);

        table
            .insert(
                src_vpcd,
                VpcdLookupResult::Single(dst_data),
                Prefix::from("10.0.0.0/24"),
                Some(PortRange::new(1025, 1999).unwrap()),
                Prefix::from("20.0.0.0/24"),
                None,
            )
            .unwrap();

        let mut writer = FlowFilterTableWriter::new();
        writer.update_flow_filter_table(table);

        let mut flow_filter = FlowFilter::new("test-filter", writer.get_reader());

        // Create test packet
        let packet = create_test_icmp_v4_packet(
            Some(src_vpcd),
            Ipv4Addr::from_str("10.0.0.5").unwrap(),
            Ipv4Addr::from_str("20.0.0.10").unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        assert!(packets[0].is_done());
        assert_eq!(packets[0].meta().dst_vpcd, None);
    }

    #[traced_test]
    #[test]
    fn test_flow_filter_table_from_overlay() {
        let vni1 = Vni::new_checked(100).unwrap();
        let vni2 = Vni::new_checked(200).unwrap();
        let vni3 = Vni::new_checked(300).unwrap();

        let mut vpc_table = VpcTable::new();
        vpc_table
            .add(Vpc::new("vpc1", "VPC01", vni1.as_u32()).unwrap())
            .unwrap();
        vpc_table
            .add(Vpc::new("vpc2", "VPC02", vni2.as_u32()).unwrap())
            .unwrap();
        vpc_table
            .add(Vpc::new("vpc3", "VPC03", vni3.as_u32()).unwrap())
            .unwrap();

        let mut peering_table = VpcPeeringTable::new();
        peering_table
            .add(VpcPeering::with_default_group(
                "vpc1-to-vpc2",
                VpcManifest {
                    name: "vpc1".to_string(),
                    exposes: vec![VpcExpose::empty().ip("1.0.0.0/24".into())],
                },
                VpcManifest {
                    name: "vpc2".to_string(),
                    exposes: vec![
                        VpcExpose::empty().ip("5.0.0.0/24".into()),
                        VpcExpose::empty().set_default(),
                    ],
                },
            ))
            .unwrap();

        peering_table
            .add(VpcPeering::with_default_group(
                "vpc1-to-vpc3",
                VpcManifest {
                    name: "vpc1".to_string(),
                    exposes: vec![
                        VpcExpose::empty().ip("1.0.0.0/24".into()),
                        VpcExpose::empty().ip("2.0.0.0/24".into()),
                    ],
                },
                VpcManifest {
                    name: "vpc3".to_string(),
                    exposes: vec![VpcExpose::empty().ip("6.0.0.0/24".into())],
                },
            ))
            .unwrap();

        let mut overlay = Overlay::new(vpc_table, peering_table);
        // Validation is necessary to build overlay.vpc_table's peerings from peering_table
        overlay.validate().unwrap();

        let table = FlowFilterTable::build_from_overlay(&overlay).unwrap();

        let mut writer = FlowFilterTableWriter::new();
        writer.update_flow_filter_table(table);

        let mut flow_filter = FlowFilter::new("test-filter", writer.get_reader());

        // Test with packets

        // VPC-1 -> VPC-2 using prefix
        let packet = create_test_packet(
            Some(vni1.into()),
            "1.0.0.5".parse().unwrap(),
            "5.0.0.10".parse().unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        assert!(!packets[0].is_done(), "{:?}", packets[0].get_done());
        assert_eq!(packets[0].meta().dst_vpcd, Some(vpcd(vni2.into())));
        assert!(!packets[0].meta().requires_stateful_nat());
        assert!(!packets[0].meta().requires_stateless_nat());

        // VPC-1 -> VPC-2 using default range
        let packet = create_test_packet(
            Some(vni1.into()),
            "1.0.0.6".parse().unwrap(),
            "17.34.51.68".parse().unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        assert!(!packets[0].is_done(), "{:?}", packets[0].get_done());
        assert_eq!(packets[0].meta().dst_vpcd, Some(vpcd(vni2.into())));

        // VPC-1 -> VPC-3, using source prefix overlapping with VPC-1 <-> VPC-2 peering
        let packet = create_test_packet(
            Some(vni1.into()),
            "1.0.0.7".parse().unwrap(),
            "6.0.0.8".parse().unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        assert!(!packets[0].is_done(), "{:?}", packets[0].get_done());
        assert_eq!(packets[0].meta().dst_vpcd, Some(vpcd(vni3.into())));

        // VPC-1 -> VPC-3, using the other source prefix
        let packet = create_test_packet(
            Some(vni1.into()),
            "2.0.0.24".parse().unwrap(),
            "6.0.0.8".parse().unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        assert!(!packets[0].is_done(), "{:?}", packets[0].get_done());
        assert_eq!(packets[0].meta().dst_vpcd, Some(vpcd(vni3.into())));

        // Invalid: source from VPC-1 <-> VPC-3 peering, but invalid destination
        let packet = create_test_packet(
            Some(vni1.into()),
            "2.0.0.24".parse().unwrap(),
            "25.50.100.200".parse().unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        assert!(packets[0].is_done());
        assert_eq!(packets[0].meta().dst_vpcd, None);
    }

    #[traced_test]
    #[test]
    fn test_flow_filter_table_check_send_from_default() {
        let vni1 = Vni::new_checked(100).unwrap();
        let vni2 = Vni::new_checked(200).unwrap();

        let mut vpc_table = VpcTable::new();
        vpc_table
            .add(Vpc::new("vpc1", "VPC01", vni1.as_u32()).unwrap())
            .unwrap();
        vpc_table
            .add(Vpc::new("vpc2", "VPC02", vni2.as_u32()).unwrap())
            .unwrap();

        let mut peering_table = VpcPeeringTable::new();
        peering_table
            .add(VpcPeering::with_default_group(
                "vpc1-to-vpc2",
                VpcManifest {
                    name: "vpc1".to_string(),
                    exposes: vec![VpcExpose::empty().set_default()],
                },
                VpcManifest {
                    name: "vpc2".to_string(),
                    exposes: vec![VpcExpose::empty().ip("5.0.0.0/24".into())],
                },
            ))
            .unwrap();

        let mut overlay = Overlay::new(vpc_table, peering_table);
        // Validation is necessary to build overlay.vpc_table's peerings from peering_table
        overlay.validate().unwrap();

        let table = FlowFilterTable::build_from_overlay(&overlay).unwrap();

        let mut writer = FlowFilterTableWriter::new();
        writer.update_flow_filter_table(table);

        let mut flow_filter = FlowFilter::new("test-filter", writer.get_reader());

        // Test with a packet

        let packet = create_test_packet(
            Some(vni1.into()),
            "99.99.99.99".parse().unwrap(), // From "default" expose, use any address
            "5.0.0.8".parse().unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        assert!(!packets[0].is_done(), "{:?}", packets[0].get_done());
        assert_eq!(packets[0].meta().dst_vpcd, Some(vni2.into()));
    }

    #[traced_test]
    #[test]
    fn test_flow_filter_table_check_default_to_default() {
        let vni1 = Vni::new_checked(100).unwrap();
        let vni2 = Vni::new_checked(200).unwrap();

        let mut vpc_table = VpcTable::new();
        vpc_table
            .add(Vpc::new("vpc1", "VPC01", vni1.as_u32()).unwrap())
            .unwrap();
        vpc_table
            .add(Vpc::new("vpc2", "VPC02", vni2.as_u32()).unwrap())
            .unwrap();

        let mut peering_table = VpcPeeringTable::new();
        peering_table
            .add(VpcPeering::with_default_group(
                "vpc1-to-vpc2",
                VpcManifest {
                    name: "vpc1".to_string(),
                    exposes: vec![VpcExpose::empty().set_default()],
                },
                VpcManifest {
                    name: "vpc2".to_string(),
                    exposes: vec![VpcExpose::empty().set_default()],
                },
            ))
            .unwrap();

        let mut overlay = Overlay::new(vpc_table, peering_table);
        // Validation is necessary to build overlay.vpc_table's peerings from peering_table
        overlay.validate().unwrap();

        let table = FlowFilterTable::build_from_overlay(&overlay).unwrap();

        let mut writer = FlowFilterTableWriter::new();
        writer.update_flow_filter_table(table);

        let mut flow_filter = FlowFilter::new("test-filter", writer.get_reader());

        // Test with packets

        let packet = create_test_packet(
            Some(vni1.into()),
            "99.99.99.99".parse().unwrap(),
            "77.77.77.77".parse().unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        assert!(!packets[0].is_done(), "{:?}", packets[0].get_done());
        assert_eq!(packets[0].meta().dst_vpcd, Some(vni2.into()));
    }

    #[traced_test]
    #[test]
    fn test_flow_filter_table_check_nat_requirements() {
        let vni1 = Vni::new_checked(100).unwrap();
        let vni2 = Vni::new_checked(200).unwrap();

        let mut vpc_table = VpcTable::new();
        vpc_table
            .add(Vpc::new("vpc1", "VPC01", vni1.as_u32()).unwrap())
            .unwrap();
        vpc_table
            .add(Vpc::new("vpc2", "VPC02", vni2.as_u32()).unwrap())
            .unwrap();

        let mut peering_table = VpcPeeringTable::new();
        peering_table
            .add(VpcPeering::with_default_group(
                "vpc1-to-vpc2",
                VpcManifest {
                    name: "vpc1".to_string(),
                    exposes: vec![
                        VpcExpose::empty().ip("1.0.0.0/24".into()), // No NAT
                        VpcExpose::empty()
                            .make_stateless_nat()
                            .unwrap()
                            .ip("2.0.0.0/24".into())
                            .as_range("20.0.0.0/24".into()), // Stateless NAT
                        VpcExpose::empty()
                            .make_stateful_nat(None)
                            .unwrap()
                            .ip("3.0.0.0/24".into())
                            .as_range("30.0.0.0/24".into()), // Stateful NAT
                        VpcExpose::empty().set_default(),           // Default (no NAT)
                    ],
                },
                VpcManifest {
                    name: "vpc2".to_string(),
                    exposes: vec![
                        VpcExpose::empty().ip("5.0.0.0/24".into()), // No NAT
                        VpcExpose::empty()
                            .make_stateless_nat()
                            .unwrap()
                            .ip("6.0.0.0/24".into())
                            .as_range("60.0.0.0/24".into()), // Stateless NAT
                        VpcExpose::empty()
                            .make_stateful_nat(None)
                            .unwrap()
                            .ip("7.0.0.0/24".into())
                            .as_range("70.0.0.0/24".into()), // Stateful NAT
                        VpcExpose::empty().set_default(),           // Default (no NAT)
                    ],
                },
            ))
            .unwrap();

        let mut overlay = Overlay::new(vpc_table, peering_table);
        // Build overlay.vpc_table's peerings from peering_table, with no validation
        overlay.collect_peerings();

        let table = FlowFilterTable::build_from_overlay(&overlay).unwrap();

        let mut writer = FlowFilterTableWriter::new();
        writer.update_flow_filter_table(table);

        let mut flow_filter = FlowFilter::new("test-filter", writer.get_reader());

        // Test with packets

        // src: no NAT, dst: no NAT
        let packet = create_test_packet(
            Some(Vni::new_checked(100).unwrap().into()),
            "1.0.0.5".parse().unwrap(),
            "5.0.0.10".parse().unwrap(),
        );
        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();
        assert_eq!(packets.len(), 1);
        assert!(!packets[0].is_done(), "{:?}", packets[0].get_done());
        assert_eq!(packets[0].meta().dst_vpcd, Some(vpcd(vni2.into())));
        assert!(!packets[0].meta().requires_stateful_nat());
        assert!(!packets[0].meta().requires_stateless_nat());

        // src: stateless NAT, dst: stateless NAT
        let packet = create_test_packet(
            Some(vni1.into()),
            "2.0.0.5".parse().unwrap(),
            "60.0.0.10".parse().unwrap(),
        );
        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();
        assert!(!packets[0].is_done(), "{:?}", packets[0].get_done());
        assert_eq!(packets[0].meta().dst_vpcd, Some(vpcd(vni2.into())));
        assert!(!packets[0].meta().requires_stateful_nat());
        assert!(packets[0].meta().requires_stateless_nat());

        // src: stateful NAT, dst: no NAT
        let packet = create_test_packet(
            Some(vni1.into()),
            "3.0.0.5".parse().unwrap(),
            "5.0.0.10".parse().unwrap(),
        );
        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();
        assert!(!packets[0].is_done(), "{:?}", packets[0].get_done());
        assert_eq!(packets[0].meta().dst_vpcd, Some(vpcd(vni2.into())));
        assert!(packets[0].meta().requires_stateful_nat());
        assert!(!packets[0].meta().requires_stateless_nat());

        // src: no NAT, dst: stateful NAT
        let packet = create_test_packet(
            Some(vni1.into()),
            "1.0.0.5".parse().unwrap(),
            "70.0.0.10".parse().unwrap(),
        );
        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();
        assert!(!packets[0].is_done(), "{:?}", packets[0].get_done());
        assert_eq!(packets[0].meta().dst_vpcd, Some(vpcd(vni2.into())));
        assert!(packets[0].meta().requires_stateful_nat());
        assert!(!packets[0].meta().requires_stateless_nat());

        // src: stateful NAT, dst: default (no NAT)
        let packet = create_test_packet(
            Some(vni1.into()),
            "3.0.0.5".parse().unwrap(),
            "99.0.0.10".parse().unwrap(),
        );
        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();
        assert!(!packets[0].is_done(), "{:?}", packets[0].get_done());
        assert_eq!(packets[0].meta().dst_vpcd, Some(vpcd(vni2.into())));
        assert!(packets[0].meta().requires_stateful_nat());
        assert!(!packets[0].meta().requires_stateless_nat());
    }

    #[test]
    fn test_flow_filter_batch_processing() {
        // Setup table
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let dst_data = RemoteData::new(vpcd(200), Some(NatRequirement::Stateful), None);

        table
            .insert(
                src_vpcd,
                VpcdLookupResult::Single(dst_data),
                Prefix::from("10.0.0.0/24"),
                None,
                Prefix::from("20.0.0.0/24"),
                None,
            )
            .unwrap();

        let mut writer = FlowFilterTableWriter::new();
        writer.update_flow_filter_table(table);

        let mut flow_filter = FlowFilter::new("test-filter", writer.get_reader());

        // Create multiple test packets
        let packet1 = create_test_packet(
            Some(src_vpcd),
            "10.0.0.5".parse().unwrap(),
            "20.0.0.10".parse().unwrap(),
        );
        let packet2 = create_test_packet(
            Some(src_vpcd),
            "10.0.0.6".parse().unwrap(),
            "30.0.0.10".parse().unwrap(), // Should be filtered
        );
        let packet3 = create_test_packet(
            Some(src_vpcd),
            "10.0.0.7".parse().unwrap(),
            "20.0.0.20".parse().unwrap(),
        );

        let packets = flow_filter
            .process([packet1, packet2, packet3].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 3);
        assert!(!packets[0].is_done());
        assert_eq!(packets[0].meta().dst_vpcd, Some(dst_data.vpcd));
        assert_eq!(packets[1].get_done(), Some(DoneReason::Filtered));
        assert!(!packets[2].is_done());
        assert_eq!(packets[2].meta().dst_vpcd, Some(dst_data.vpcd));
    }

    #[test]
    fn test_format_packet_addrs_ports() {
        let src_vpcd = VpcDiscriminant::VNI(3000.try_into().unwrap());
        let src_addr = "10.0.0.1".parse().unwrap();
        let dst_addr = "20.0.0.2".parse().unwrap();

        let result = FlowTuple::new(src_vpcd, src_addr, dst_addr, Some((8080, 443)));
        assert_eq!(
            result.to_string(),
            "srcVpc=VNI(3000) src=10.0.0.1:8080 dst=20.0.0.2:443"
        );

        let result_no_ports = FlowTuple::new(src_vpcd, src_addr, dst_addr, None);
        assert_eq!(
            result_no_ports.to_string(),
            "srcVpc=VNI(3000) src=10.0.0.1 dst=20.0.0.2"
        );
    }
}
