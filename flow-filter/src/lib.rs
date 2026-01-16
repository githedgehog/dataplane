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

use net::buffer::PacketBufferMut;
use net::headers::{TryIp, TryTransport};
use net::packet::{DoneReason, Packet};
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

        let Some(src_vpcd) = packet.meta.src_vpcd else {
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
        let log_str = format_packet_addrs_ports(&src_ip, &dst_ip, ports);

        if let Some(dst_vpcd) = tablesr.lookup(src_vpcd, &src_ip, &dst_ip, ports) {
            debug!("{nfi}: Flow allowed: {log_str}, setting packet dst_vpcd to {dst_vpcd}");
            packet.meta.dst_vpcd = Some(dst_vpcd);
        } else {
            debug!("{nfi}: Flow not allowed, dropping packet: {log_str}");
            packet.done(DoneReason::Filtered);
        }
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for FlowFilter {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.filter_map(|mut packet| {
            if let Some(tablesr) = &self.tablesr.enter() {
                if !packet.is_done() {
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

fn format_packet_addrs_ports(
    src_addr: &IpAddr,
    dst_addr: &IpAddr,
    ports: Option<(u16, u16)>,
) -> String {
    format!(
        "src={src_addr}{}, dst={dst_addr}{}",
        ports.map_or(String::new(), |p| format!(":{}", p.0)),
        ports.map_or(String::new(), |p| format!(":{}", p.1))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter_rw::FlowFilterTableWriter;
    use crate::tables::OptionalPortRange;
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
        VpcDiscriminant::VNI(Vni::new_checked(vni).unwrap())
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
        src_vpcd: Option<Vni>,
        src_addr: IpAddr,
        dst_addr: IpAddr,
    ) -> Packet<TestBuffer> {
        let mut packet = match dst_addr {
            IpAddr::V4(_) => build_test_ipv4_packet(100).unwrap(),
            IpAddr::V6(_) => build_test_ipv6_packet(100).unwrap(),
        };
        set_src_addr(&mut packet, src_addr);
        set_dst_addr(&mut packet, dst_addr);
        packet.meta.src_vpcd = src_vpcd.map(VpcDiscriminant::VNI);
        packet
    }

    fn create_test_icmp_v4_packet(
        src_vpcd: Option<Vni>,
        src_addr: Ipv4Addr,
        dst_addr: Ipv4Addr,
    ) -> Packet<TestBuffer> {
        let mut packet =
            build_test_icmp4_echo(src_addr, dst_addr, 1, IcmpEchoDirection::Request).unwrap();
        packet.meta.src_vpcd = src_vpcd.map(VpcDiscriminant::VNI);
        packet
    }

    #[test]
    fn test_flow_filter_packet_allowed() {
        // Setup table
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let dst_vpcd = vpcd(200);

        table
            .insert(
                src_vpcd,
                dst_vpcd,
                Prefix::from("10.0.0.0/24"),
                OptionalPortRange::NoPortRangeMeansAllPorts,
                Prefix::from("20.0.0.0/24"),
                OptionalPortRange::NoPortRangeMeansAllPorts,
            )
            .unwrap();

        let mut writer = FlowFilterTableWriter::new();
        writer.update_flow_filter_table(table);

        let mut flow_filter = FlowFilter::new("test-filter", writer.get_reader());

        // Create test packet
        let packet = create_test_packet(
            Some(Vni::new_checked(100).unwrap()),
            "10.0.0.5".parse().unwrap(),
            "20.0.0.10".parse().unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        assert!(!packets[0].is_done());
        assert_eq!(packets[0].meta.dst_vpcd, Some(dst_vpcd));
    }

    #[test]
    fn test_flow_filter_packet_filtered() {
        // Setup table
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let dst_vpcd = vpcd(200);

        table
            .insert(
                src_vpcd,
                dst_vpcd,
                Prefix::from("10.0.0.0/24"),
                OptionalPortRange::NoPortRangeMeansAllPorts,
                Prefix::from("20.0.0.0/24"),
                OptionalPortRange::NoPortRangeMeansAllPorts,
            )
            .unwrap();

        let mut writer = FlowFilterTableWriter::new();
        writer.update_flow_filter_table(table);

        let mut flow_filter = FlowFilter::new("test-filter", writer.get_reader());

        // Create test packet with non-matching destination
        let packet = create_test_packet(
            Some(Vni::new_checked(100).unwrap()),
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
        let dst_vpcd = vpcd(200);

        table
            .insert(
                src_vpcd,
                dst_vpcd,
                Prefix::from("10.0.0.0/24"),
                OptionalPortRange::NoPortRangeMeansAllPorts,
                Prefix::from("20.0.0.0/24"),
                OptionalPortRange::NoPortRangeMeansAllPorts,
            )
            .unwrap();

        let mut writer = FlowFilterTableWriter::new();
        writer.update_flow_filter_table(table);

        let mut flow_filter = FlowFilter::new("test-filter", writer.get_reader());

        // Create test packet with non-matching source address
        let packet = create_test_packet(
            Some(Vni::new_checked(100).unwrap()),
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
    fn test_flow_filter_ipv6() {
        // Setup table
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let dst_vpcd = vpcd(200);

        table
            .insert(
                src_vpcd,
                dst_vpcd,
                Prefix::from("2001:db8::/32"),
                OptionalPortRange::NoPortRangeMeansAllPorts,
                Prefix::from("2001:db9::/32"),
                OptionalPortRange::NoPortRangeMeansAllPorts,
            )
            .unwrap();

        let mut writer = FlowFilterTableWriter::new();
        writer.update_flow_filter_table(table);

        let mut flow_filter = FlowFilter::new("test-filter", writer.get_reader());

        // Create test packet
        let packet = create_test_packet(
            Some(Vni::new_checked(100).unwrap()),
            "2001:db8::1".parse().unwrap(),
            "2001:db9::1".parse().unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        assert!(!packets[0].is_done());
        assert_eq!(packets[0].meta.dst_vpcd, Some(dst_vpcd));
    }

    #[test]
    fn test_flow_filter_packet_icmp_allowed() {
        // Setup table
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let dst_vpcd = vpcd(200);

        table
            .insert(
                src_vpcd,
                dst_vpcd,
                Prefix::from("10.0.0.0/24"),
                OptionalPortRange::NoPortRangeMeansAllPorts,
                Prefix::from("20.0.0.0/24"),
                OptionalPortRange::NoPortRangeMeansAllPorts,
            )
            .unwrap();

        let mut writer = FlowFilterTableWriter::new();
        writer.update_flow_filter_table(table);

        let mut flow_filter = FlowFilter::new("test-filter", writer.get_reader());

        // Create test packet
        let packet = create_test_icmp_v4_packet(
            Some(Vni::new_checked(100).unwrap()),
            Ipv4Addr::from_str("10.0.0.5").unwrap(),
            Ipv4Addr::from_str("20.0.0.10").unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        assert!(!packets[0].is_done());
        assert_eq!(packets[0].meta.dst_vpcd, Some(dst_vpcd));
    }

    #[test]
    fn test_flow_filter_packet_icmp_filtered() {
        // Setup table
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let dst_vpcd = vpcd(200);

        table
            .insert(
                src_vpcd,
                dst_vpcd,
                Prefix::from("10.0.0.0/24"),
                OptionalPortRange::Some(PortRange::new(1025, 1999).unwrap()),
                Prefix::from("20.0.0.0/24"),
                OptionalPortRange::NoPortRangeMeansAllPorts,
            )
            .unwrap();

        let mut writer = FlowFilterTableWriter::new();
        writer.update_flow_filter_table(table);

        let mut flow_filter = FlowFilter::new("test-filter", writer.get_reader());

        // Create test packet
        let packet = create_test_icmp_v4_packet(
            Some(Vni::new_checked(100).unwrap()),
            Ipv4Addr::from_str("10.0.0.5").unwrap(),
            Ipv4Addr::from_str("20.0.0.10").unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        assert!(packets[0].is_done());
        assert_eq!(packets[0].meta.dst_vpcd, None);
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
            .add(VpcPeering::new(
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
                None,
            ))
            .unwrap();

        peering_table
            .add(VpcPeering::new(
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
                None,
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
            Some(Vni::new_checked(100).unwrap()),
            "1.0.0.5".parse().unwrap(),
            "5.0.0.10".parse().unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        assert!(!packets[0].is_done(), "{:?}", packets[0].get_done());
        assert_eq!(packets[0].meta.dst_vpcd, Some(vpcd(vni2.into())));

        // VPC-1 -> VPC-2 using default range
        let packet = create_test_packet(
            Some(Vni::new_checked(100).unwrap()),
            "1.0.0.6".parse().unwrap(),
            "17.34.51.68".parse().unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        assert!(!packets[0].is_done(), "{:?}", packets[0].get_done());
        assert_eq!(packets[0].meta.dst_vpcd, Some(vpcd(vni2.into())));

        // VPC-1 -> VPC-3, using source prefix overlapping with VPC-1 <-> VPC-2 peering
        let packet = create_test_packet(
            Some(Vni::new_checked(100).unwrap()),
            "1.0.0.7".parse().unwrap(),
            "6.0.0.8".parse().unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        assert!(!packets[0].is_done(), "{:?}", packets[0].get_done());
        assert_eq!(packets[0].meta.dst_vpcd, Some(vpcd(vni3.into())));

        // VPC-1 -> VPC-3, using the other source prefix
        let packet = create_test_packet(
            Some(Vni::new_checked(100).unwrap()),
            "2.0.0.24".parse().unwrap(),
            "6.0.0.8".parse().unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        assert!(!packets[0].is_done(), "{:?}", packets[0].get_done());
        assert_eq!(packets[0].meta.dst_vpcd, Some(vpcd(vni3.into())));

        // Invalid: source from VPC-1 <-> VPC-3 peering, but invalid destination
        let packet = create_test_packet(
            Some(Vni::new_checked(100).unwrap()),
            "2.0.0.24".parse().unwrap(),
            "25.50.100.200".parse().unwrap(),
        );

        let packets = flow_filter
            .process([packet].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 1);
        assert!(packets[0].is_done());
        assert_eq!(packets[0].meta.dst_vpcd, None);
    }

    #[test]
    fn test_flow_filter_batch_processing() {
        // Setup table
        let mut table = FlowFilterTable::new();
        let src_vpcd = vpcd(100);
        let dst_vpcd = vpcd(200);

        table
            .insert(
                src_vpcd,
                dst_vpcd,
                Prefix::from("10.0.0.0/24"),
                OptionalPortRange::NoPortRangeMeansAllPorts,
                Prefix::from("20.0.0.0/24"),
                OptionalPortRange::NoPortRangeMeansAllPorts,
            )
            .unwrap();

        let mut writer = FlowFilterTableWriter::new();
        writer.update_flow_filter_table(table);

        let mut flow_filter = FlowFilter::new("test-filter", writer.get_reader());

        // Create multiple test packets
        let packet1 = create_test_packet(
            Some(Vni::new_checked(100).unwrap()),
            "10.0.0.5".parse().unwrap(),
            "20.0.0.10".parse().unwrap(),
        );
        let packet2 = create_test_packet(
            Some(Vni::new_checked(100).unwrap()),
            "10.0.0.6".parse().unwrap(),
            "30.0.0.10".parse().unwrap(), // Should be filtered
        );
        let packet3 = create_test_packet(
            Some(Vni::new_checked(100).unwrap()),
            "10.0.0.7".parse().unwrap(),
            "20.0.0.20".parse().unwrap(),
        );

        let packets = flow_filter
            .process([packet1, packet2, packet3].into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 3);
        assert!(!packets[0].is_done());
        assert_eq!(packets[0].meta.dst_vpcd, Some(dst_vpcd));
        assert_eq!(packets[1].get_done(), Some(DoneReason::Filtered));
        assert!(!packets[2].is_done());
        assert_eq!(packets[2].meta.dst_vpcd, Some(dst_vpcd));
    }

    #[test]
    fn test_format_packet_addrs_ports() {
        let src_addr = "10.0.0.1".parse().unwrap();
        let dst_addr = "20.0.0.2".parse().unwrap();

        let result = format_packet_addrs_ports(&src_addr, &dst_addr, Some((8080, 443)));
        assert_eq!(result, "src=10.0.0.1:8080, dst=20.0.0.2:443");

        let result_no_ports = format_packet_addrs_ports(&src_addr, &dst_addr, None);
        assert_eq!(result_no_ports, "src=10.0.0.1, dst=20.0.0.2");
    }
}
