// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::tables::NatRequirement;
use crate::{
    FlowFilter, FlowFilterTable, FlowFilterTableWriter, FlowTuple, RemoteData, VpcdLookupResult,
};
use config::external::overlay::Overlay;
use config::external::overlay::vpc::{Vpc, VpcTable};
use config::external::overlay::vpcpeering::{VpcExpose, VpcManifest, VpcPeering, VpcPeeringTable};
use lpm::prefix::{L4Protocol, PortRange, Prefix, PrefixWithOptionalPorts};
use net::buffer::{PacketBufferMut, TestBuffer};
use net::flows::FlowInfo;
use net::headers::{Net, TryHeadersMut, TryIpMut};
use net::ip::NextHeader;
use net::ipv4::addr::UnicastIpv4Addr;
use net::ipv6::addr::UnicastIpv6Addr;
use net::packet::test_utils::{
    IcmpEchoDirection, build_test_icmp4_echo, build_test_ipv4_packet_with_transport,
    build_test_ipv6_packet_with_transport,
};
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use net::vxlan::Vni;
use pipeline::NetworkFunction;
use std::collections::HashSet;
use std::net::IpAddr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;
use tracing_test::traced_test;

fn vni(id: u32) -> Vni {
    Vni::new_checked(id).unwrap()
}

fn vpcd(id: u32) -> VpcDiscriminant {
    VpcDiscriminant::from_vni(vni(id))
}

fn needs_masquerade<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> bool {
    packet.meta().requires_stateful_nat()
        && !packet.meta().requires_stateless_nat()
        && !packet.meta().requires_port_forwarding()
}

fn needs_static_nat<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> bool {
    packet.meta().requires_stateless_nat()
        && !packet.meta().requires_stateful_nat()
        && !packet.meta().requires_port_forwarding()
}

fn needs_port_forwarding<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> bool {
    packet.meta().requires_port_forwarding()
        && !packet.meta().requires_stateful_nat()
        && !packet.meta().requires_stateless_nat()
}

fn needs_no_nat<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> bool {
    !packet.meta().requires_stateful_nat()
        && !packet.meta().requires_stateless_nat()
        && !packet.meta().requires_port_forwarding()
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
    match (src_addr, dst_addr) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            create_test_ipv4_udp_packet_with_ports(src_vpcd, src, dst, 1234, 5678)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            create_test_ipv6_udp_packet_with_ports(src_vpcd, src, dst, 1234, 5678)
        }
        _ => panic!("Invalid IP versions combination"),
    }
}

fn create_test_ipv4_udp_packet_with_ports(
    src_vpcd: Option<VpcDiscriminant>,
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> Packet<TestBuffer> {
    let mut packet = build_test_ipv4_packet_with_transport(100, Some(NextHeader::UDP)).unwrap();

    packet.meta_mut().set_overlay(true);
    set_src_addr(&mut packet, src_addr.into());
    set_dst_addr(&mut packet, dst_addr.into());
    packet
        .set_udp_source_port(src_port.try_into().unwrap())
        .unwrap();
    packet
        .set_udp_destination_port(dst_port.try_into().unwrap())
        .unwrap();
    packet.meta_mut().src_vpcd = src_vpcd;
    packet
}

fn create_test_ipv4_tcp_packet_with_ports(
    src_vpcd: Option<VpcDiscriminant>,
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> Packet<TestBuffer> {
    let mut packet = build_test_ipv4_packet_with_transport(100, Some(NextHeader::TCP)).unwrap();

    packet.meta_mut().set_overlay(true);
    set_src_addr(&mut packet, src_addr.into());
    set_dst_addr(&mut packet, dst_addr.into());
    packet
        .set_tcp_source_port(net::tcp::TcpPort::new_checked(src_port).unwrap())
        .unwrap();
    packet
        .set_tcp_destination_port(net::tcp::TcpPort::new_checked(dst_port).unwrap())
        .unwrap();
    packet.meta_mut().src_vpcd = src_vpcd;
    packet
}

fn create_test_ipv6_udp_packet_with_ports(
    src_vpcd: Option<VpcDiscriminant>,
    src_addr: Ipv6Addr,
    dst_addr: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
) -> Packet<TestBuffer> {
    let mut packet = build_test_ipv6_packet_with_transport(100, Some(NextHeader::UDP)).unwrap();

    packet.meta_mut().set_overlay(true);
    set_src_addr(&mut packet, src_addr.into());
    set_dst_addr(&mut packet, dst_addr.into());
    packet
        .set_udp_source_port(src_port.try_into().unwrap())
        .unwrap();
    packet
        .set_udp_destination_port(dst_port.try_into().unwrap())
        .unwrap();
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

fn fake_flow_session<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    dst_vpcd: VpcDiscriminant,
    set_nat_state: bool,
    set_port_fw_state: bool,
) {
    // Create flow_info with dst_vpcd and NAT info and attach it to the packet
    let flow_info = FlowInfo::new(std::time::Instant::now() + std::time::Duration::from_secs(60));
    let mut binding = flow_info.locked.write().unwrap();
    binding.dst_vpcd = Some(dst_vpcd);
    if set_nat_state {
        // Content should be a NatFlowState object but we can't include it in this crate without
        // introducing a circular dependency; just use a bool, as we don't attempt to downcast
        // it anyway.
        binding.nat_state = Some(Box::new(true));
    }
    if set_port_fw_state {
        // Content should be a PortFwState object but we can't include it in this crate without
        // introducing a circular dependency; just use a bool, as we don't attempt to downcast
        // it anyway.
        binding.port_fw_state = Some(Box::new(true));
    }
    drop(binding);
    packet.meta_mut().flow_info = Some(Arc::new(flow_info));
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
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(dst_data.vpcd));
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
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert_eq!(packet_out.get_done(), Some(DoneReason::Filtered));
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
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert_eq!(packet_out.get_done(), Some(DoneReason::Unroutable));
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
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert_eq!(packet_out.get_done(), Some(DoneReason::Filtered));
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
            VpcdLookupResult::MultipleMatches(HashSet::from([
                RemoteData::new(
                    vpcd(200),
                    None,
                    Some(NatRequirement::PortForwarding(L4Protocol::Tcp)), // This rule is for TCP
                ),
                RemoteData::new(
                    vpcd(300),
                    None,
                    Some(NatRequirement::PortForwarding(L4Protocol::Tcp)), // This rule is for TCP
                ),
            ])),
            Prefix::from("10.0.0.0/24"),
            None,
            Prefix::from("20.0.0.0/24"),
            None,
        )
        .unwrap();

    let mut writer = FlowFilterTableWriter::new();
    writer.update_flow_filter_table(table);

    let mut flow_filter = FlowFilter::new("test-filter", writer.get_reader());

    // Create test UDP packet
    let packet = create_test_ipv4_udp_packet_with_ports(
        Some(vpcd(100)),
        "10.0.0.5".parse().unwrap(),
        "20.0.0.10".parse().unwrap(),
        1234,
        5678,
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    // Without table flow lookup we can't find the right dst_vpcd, so we should drop the packet
    assert!(packet_out.is_done());
    assert!(packet_out.meta().dst_vpcd.is_none());
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
            VpcManifest::with_exposes("vpc1", vec![VpcExpose::empty().ip("1.0.0.0/24".into())]),
            VpcManifest::with_exposes("vpc2", vec![VpcExpose::empty().ip("5.0.0.0/24".into())]),
            None,
        ))
        .unwrap();

    peering_table
        .add(VpcPeering::new(
            "vpc2-to-vpc3",
            VpcManifest::with_exposes(
                "vpc2",
                vec![
                    VpcExpose::empty().ip("5.0.0.0/24".into()),
                    VpcExpose::empty().ip("6.0.0.0/24".into()),
                ],
            ),
            VpcManifest::with_exposes("vpc3", vec![VpcExpose::empty().ip("1.0.0.64/26".into())]),
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
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vpcd(vni2.into())));

    // VPC-3 -> VPC-2: No ambiguity
    let packet = create_test_packet(
        Some(vpcd(300)),
        "1.0.0.70".parse().unwrap(),
        "5.0.0.10".parse().unwrap(),
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vpcd(vni2.into())));

    // VPC-2 -> VPC-1 using lower non-overlapping destination prefix section
    let packet = create_test_packet(
        Some(vpcd(200)),
        "5.0.0.10".parse().unwrap(),
        "1.0.0.5".parse().unwrap(),
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vpcd(vni1.into())));

    // VPC-2 -> VPC-1 using upper non-overlapping destination prefix section
    let packet = create_test_packet(
        Some(vpcd(200)),
        "5.0.0.10".parse().unwrap(),
        "1.0.0.205".parse().unwrap(),
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vpcd(vni1.into())));

    // VPC-2 -> VPC-3 using non-overlapping source prefix
    let packet = create_test_packet(
        Some(vpcd(200)),
        "6.0.0.11".parse().unwrap(),
        "1.0.0.70".parse().unwrap(),
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vpcd(vni3.into())));

    // VPC-2 -> VPC-??? using overlapping prefix sections: multiple matches
    let packet = create_test_packet(
        Some(vpcd(200)),
        "5.0.0.10".parse().unwrap(),
        "1.0.0.70".parse().unwrap(),
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, None)
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
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(dst_data.vpcd));
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
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(dst_data.vpcd));
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
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(packet_out.is_done());
    assert_eq!(packet_out.meta().dst_vpcd, None);
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
            VpcManifest::with_exposes("vpc1", vec![VpcExpose::empty().ip("1.0.0.0/24".into())]),
            VpcManifest::with_exposes(
                "vpc2",
                vec![
                    VpcExpose::empty().ip("5.0.0.0/24".into()),
                    VpcExpose::empty().set_default(),
                ],
            ),
        ))
        .unwrap();

    peering_table
        .add(VpcPeering::with_default_group(
            "vpc1-to-vpc3",
            VpcManifest::with_exposes(
                "vpc1",
                vec![
                    VpcExpose::empty().ip("1.0.0.0/24".into()),
                    VpcExpose::empty().ip("2.0.0.0/24".into()),
                ],
            ),
            VpcManifest::with_exposes("vpc3", vec![VpcExpose::empty().ip("6.0.0.0/24".into())]),
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
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vpcd(vni2.into())));
    assert!(needs_no_nat(&packet_out));

    // VPC-1 -> VPC-2 using default range
    let packet = create_test_packet(
        Some(vni1.into()),
        "1.0.0.6".parse().unwrap(),
        "17.34.51.68".parse().unwrap(),
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vpcd(vni2.into())));

    // VPC-1 -> VPC-3, using source prefix overlapping with VPC-1 <-> VPC-2 peering
    let packet = create_test_packet(
        Some(vni1.into()),
        "1.0.0.7".parse().unwrap(),
        "6.0.0.8".parse().unwrap(),
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vpcd(vni3.into())));

    // VPC-1 -> VPC-3, using the other source prefix
    let packet = create_test_packet(
        Some(vni1.into()),
        "2.0.0.24".parse().unwrap(),
        "6.0.0.8".parse().unwrap(),
    );

    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vpcd(vni3.into())));

    // Invalid: source from VPC-1 <-> VPC-3 peering, but invalid destination
    let packet = create_test_packet(
        Some(vni1.into()),
        "2.0.0.24".parse().unwrap(),
        "25.50.100.200".parse().unwrap(),
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(packet_out.is_done());
    assert_eq!(packet_out.meta().dst_vpcd, None);
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
            VpcManifest::with_exposes("vpc1", vec![VpcExpose::empty().set_default()]),
            VpcManifest::with_exposes("vpc2", vec![VpcExpose::empty().ip("5.0.0.0/24".into())]),
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
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vni2.into()));
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
            VpcManifest::with_exposes("vpc1", vec![VpcExpose::empty().set_default()]),
            VpcManifest::with_exposes("vpc2", vec![VpcExpose::empty().set_default()]),
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

    let packet = create_test_packet(
        Some(vni1.into()),
        "99.99.99.99".parse().unwrap(),
        "77.77.77.77".parse().unwrap(),
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vni2.into()));
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
            VpcManifest::with_exposes(
                "vpc1",
                vec![
                    VpcExpose::empty().ip("1.0.0.0/24".into()), // No NAT
                    VpcExpose::empty()
                        .make_stateless_nat()
                        .unwrap()
                        .ip("2.0.0.0/24".into())
                        .as_range("20.0.0.0/24".into()) // Stateless NAT
                        .unwrap(),
                    VpcExpose::empty()
                        .make_stateful_nat(None)
                        .unwrap()
                        .ip("3.0.0.0/24".into())
                        .as_range("30.0.0.0/24".into()) // Stateful NAT
                        .unwrap(),
                    VpcExpose::empty().set_default(), // Default (no NAT)
                ],
            ),
            VpcManifest::with_exposes(
                "vpc2",
                vec![
                    VpcExpose::empty().ip("5.0.0.0/24".into()), // No NAT
                    VpcExpose::empty()
                        .make_stateless_nat()
                        .unwrap()
                        .ip("6.0.0.0/24".into())
                        .as_range("60.0.0.0/24".into()) // Stateless NAT
                        .unwrap(),
                    VpcExpose::empty()
                        .make_stateful_nat(None)
                        .unwrap()
                        .ip("7.0.0.0/24".into())
                        .as_range("70.0.0.0/24".into()) // Stateful NAT
                        .unwrap(),
                    VpcExpose::empty().set_default(), // Default (no NAT)
                ],
            ),
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
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vpcd(vni2.into())));
    assert!(needs_no_nat(&packet_out));

    // src: stateless NAT, dst: stateless NAT
    let packet = create_test_packet(
        Some(vni1.into()),
        "2.0.0.5".parse().unwrap(),
        "60.0.0.10".parse().unwrap(),
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vpcd(vni2.into())));
    assert!(needs_static_nat(&packet_out));

    // src: stateful NAT, dst: no NAT
    let packet = create_test_packet(
        Some(vni1.into()),
        "3.0.0.5".parse().unwrap(),
        "5.0.0.10".parse().unwrap(),
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vpcd(vni2.into())));
    assert!(needs_masquerade(&packet_out));

    // src: no NAT, dst: stateful NAT
    let packet = create_test_packet(
        Some(vni1.into()),
        "1.0.0.5".parse().unwrap(),
        "70.0.0.10".parse().unwrap(),
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    // These are invalid NAT requirements because we cannot currently initiate a connection towards
    // an expose using masquerading, and here there is no flow info attached to packet.
    assert_eq!(packet_out.get_done(), Some(DoneReason::Filtered));

    // src: stateful NAT, dst: default (no NAT)
    let packet = create_test_packet(
        Some(vni1.into()),
        "3.0.0.5".parse().unwrap(),
        "99.0.0.10".parse().unwrap(),
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vpcd(vni2.into())));
    assert!(needs_masquerade(&packet_out));
}

#[traced_test]
#[test]
fn test_flow_filter_table_check_stateful_nat_plus_peer_forwarding() {
    let vni1 = vni(100);
    let vni2 = vni(200);

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
            VpcManifest::with_exposes(
                "vpc1",
                vec![
                    VpcExpose::empty()
                        .make_stateful_nat(None)
                        .unwrap()
                        .ip("1.0.0.0/24".into())
                        .as_range("100.0.0.0/24".into()) // Stateful NAT
                        .unwrap(),
                    VpcExpose::empty()
                        .make_port_forwarding(None, None)
                        .unwrap()
                        .ip(PrefixWithOptionalPorts::new(
                            "1.0.0.27/32".into(),
                            Some(PortRange::new(2000, 2001).unwrap()),
                        ))
                        .as_range(PrefixWithOptionalPorts::new(
                            "100.0.0.27/32".into(),
                            Some(PortRange::new(3000, 3001).unwrap()),
                        )) // Port forwarding
                        .unwrap(),
                ],
            ),
            VpcManifest::with_exposes(
                "vpc2",
                vec![VpcExpose::empty().ip("5.0.0.0/24".into())], // No NAT
            ),
        ))
        .unwrap();

    let mut overlay = Overlay::new(vpc_table, peering_table);
    overlay.validate().unwrap();

    let table = FlowFilterTable::build_from_overlay(&overlay).unwrap();

    let mut writer = FlowFilterTableWriter::new();
    writer.update_flow_filter_table(table);

    let mut flow_filter = FlowFilter::new("test-filter", writer.get_reader());

    // Test with packets

    // VPC 1 to VPC 2, outside of port forwarding IP range: stateful NAT
    let packet = create_test_ipv4_udp_packet_with_ports(
        Some(vni1.into()),
        "1.0.0.4".parse().unwrap(),
        "5.0.0.10".parse().unwrap(),
        2000,
        456,
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vni2.into()));
    assert!(needs_masquerade(&packet_out));

    // VPC 1 to VPC 2, outside of port forwarding port range: stateful NAT
    let packet = create_test_ipv4_udp_packet_with_ports(
        Some(vni1.into()),
        "1.0.0.27".parse().unwrap(),
        "5.0.0.10".parse().unwrap(),
        123,
        456,
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vni2.into()));
    assert!(needs_masquerade(&packet_out));

    // VPC 1 to VPC 2, inside of port forwarding range: still stateful NAT (no existing port
    // forwarding entry in the flow table)
    let packet = create_test_ipv4_udp_packet_with_ports(
        Some(vni1.into()),
        "1.0.0.27".parse().unwrap(),
        "5.0.0.10".parse().unwrap(),
        2000,
        456,
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vni2.into()));
    assert!(needs_masquerade(&packet_out));

    // VPC 2 to VPC 1, outside of port forwarding IP range: reverse stateful NAT
    let packet = create_test_ipv4_udp_packet_with_ports(
        Some(vni2.into()),
        "5.0.0.10".parse().unwrap(),
        "100.0.0.4".parse().unwrap(),
        456,
        2000,
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    // We don't have a flow-info for the packet, and cannot initiate the connection towards an
    // expose using stateful NAT.
    assert_eq!(packet_out.get_done(), Some(DoneReason::Filtered));

    // VPC 2 to VPC 1, outside of port forwarding port range: reverse stateful NAT
    let packet = create_test_ipv4_udp_packet_with_ports(
        Some(vni2.into()),
        "5.0.0.10".parse().unwrap(),
        "100.0.0.27".parse().unwrap(),
        456,
        123,
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    // We don't have a flow-info for the packet, and cannot initiate the connection towards an
    // expose using stateful NAT.
    assert_eq!(packet_out.get_done(), Some(DoneReason::Filtered));

    // VPC 2 to VPC 1, inside of port forwarding range: port forwarding
    let packet = create_test_ipv4_udp_packet_with_ports(
        Some(vni2.into()),
        "5.0.0.10".parse().unwrap(),
        "100.0.0.27".parse().unwrap(),
        456,
        3000,
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vni1.into()));
    assert!(needs_port_forwarding(&packet_out));

    // Back to VPC 1 to VPC 2, inside of port forwarding range, with flow_info attached for
    // stateful NAT: stateful NAT
    let mut packet = create_test_ipv4_udp_packet_with_ports(
        Some(vni1.into()),
        "1.0.0.27".parse().unwrap(),
        "5.0.0.10".parse().unwrap(),
        2000,
        456,
    );
    fake_flow_session(&mut packet, vni2.into(), true, false);
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vni2.into()));
    assert!(needs_masquerade(&packet_out));

    // VPC 1 to VPC 2, inside of port forwarding range, this time with flow_info attached for
    // port forwarding: port forwarding
    let mut packet = create_test_ipv4_udp_packet_with_ports(
        Some(vni1.into()),
        "1.0.0.27".parse().unwrap(),
        "5.0.0.10".parse().unwrap(),
        2000,
        456,
    );
    fake_flow_session(&mut packet, vni2.into(), false, true);
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vni2.into()));
    assert!(needs_port_forwarding(&packet_out));

    // VPC 2 to VPC 1, outside of port forwarding port range, with flow_info attached for stateful NAT: reverse stateful NAT
    let mut packet = create_test_ipv4_udp_packet_with_ports(
        Some(vni2.into()),
        "5.0.0.10".parse().unwrap(),
        "100.0.0.27".parse().unwrap(),
        456,
        123,
    );
    fake_flow_session(&mut packet, vni1.into(), true, false);
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vni1.into()));
    assert!(needs_masquerade(&packet_out));

    // VPC 2 to VPC 1, outside of port forwarding IP range, with flow_info attached for stateful NAT: reverse stateful NAT
    let mut packet = create_test_ipv4_udp_packet_with_ports(
        Some(vni2.into()),
        "5.0.0.10".parse().unwrap(),
        "100.0.0.4".parse().unwrap(),
        456,
        2000,
    );
    fake_flow_session(&mut packet, vni1.into(), true, false);
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vni1.into()));
    assert!(needs_masquerade(&packet_out));
}

#[test]
#[traced_test]
fn test_flow_filter_protocol_aware_port_forwarding() {
    // Test that protocol-specific port forwarding correctly filters by L4 protocol.
    // Setup: TCP-only port forwarding overlapping with stateful NAT.
    // - A TCP packet in the port forwarding range should get port forwarding (dst side)
    //   or stateful NAT (src side, no existing flow).
    // - A UDP packet in the same range should fall back to stateful NAT (the TCP-only
    //   port forwarding entry is filtered out by applies_to()).

    let vni1 = vni(100);
    let vni2 = vni(200);

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
            VpcManifest::with_exposes(
                "vpc1",
                vec![
                    VpcExpose::empty()
                        .make_stateful_nat(None) // Stateful NAT
                        .unwrap()
                        .ip("1.0.0.0/24".into())
                        .as_range("100.0.0.0/24".into())
                        .unwrap(),
                    VpcExpose::empty()
                        .make_port_forwarding(None, Some(L4Protocol::Tcp)) // TCP-only port forwarding
                        .unwrap()
                        .ip(PrefixWithOptionalPorts::new(
                            "1.0.0.27/32".into(),
                            Some(PortRange::new(2000, 2001).unwrap()),
                        ))
                        .as_range(PrefixWithOptionalPorts::new(
                            "100.0.0.27/32".into(),
                            Some(PortRange::new(3000, 3001).unwrap()),
                        ))
                        .unwrap(),
                ],
            ),
            VpcManifest::with_exposes(
                "vpc2",
                vec![VpcExpose::empty().ip("5.0.0.0/24".into())], // No NAT
            ),
        ))
        .unwrap();

    let mut overlay = Overlay::new(vpc_table, peering_table);
    overlay.validate().unwrap();

    let table = FlowFilterTable::build_from_overlay(&overlay).unwrap();

    let mut writer = FlowFilterTableWriter::new();
    writer.update_flow_filter_table(table);

    let mut flow_filter = FlowFilter::new("test-filter", writer.get_reader());

    // Source side: VPC 1 -> VPC 2

    // TCP packet inside port forwarding range: stateful NAT takes precedence on source side
    // (no existing port forwarding flow)
    let packet = create_test_ipv4_tcp_packet_with_ports(
        Some(vni1.into()),
        "1.0.0.27".parse().unwrap(),
        "5.0.0.10".parse().unwrap(),
        2000,
        456,
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vni2.into()));
    assert!(needs_masquerade(&packet_out));

    // UDP packet inside port forwarding range: TCP-only port forwarding is filtered out,
    // only stateful NAT remains -> stateful NAT
    let packet = create_test_ipv4_udp_packet_with_ports(
        Some(vni1.into()),
        "1.0.0.27".parse().unwrap(),
        "5.0.0.10".parse().unwrap(),
        2000,
        456,
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vni2.into()));
    assert!(needs_masquerade(&packet_out));

    // Destination side: VPC 2 -> VPC 1

    // TCP packet inside port forwarding range: port forwarding takes precedence
    let packet = create_test_ipv4_tcp_packet_with_ports(
        Some(vni2.into()),
        "5.0.0.10".parse().unwrap(),
        "100.0.0.27".parse().unwrap(),
        456,
        3000,
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vni1.into()));
    assert!(needs_port_forwarding(&packet_out));

    // UDP packet inside port forwarding range: TCP-only port forwarding is filtered out,
    // only stateful NAT remains (destination NAT), with no flow table entry -> drop packet
    let packet = create_test_ipv4_udp_packet_with_ports(
        Some(vni2.into()),
        "5.0.0.10".parse().unwrap(),
        "100.0.0.27".parse().unwrap(),
        456,
        3000,
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert_eq!(packet_out.get_done(), Some(DoneReason::Filtered));

    // UDP packet inside port forwarding range: TCP-only port forwarding is filtered out,
    // only stateful NAT remains, with flow table entry -> stateful NAT (not dropped!)
    let mut packet = create_test_ipv4_udp_packet_with_ports(
        Some(vni2.into()),
        "5.0.0.10".parse().unwrap(),
        "100.0.0.27".parse().unwrap(),
        456,
        3000,
    );
    fake_flow_session(&mut packet, vni1.into(), true, false);
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vni1.into()));
    assert!(needs_masquerade(&packet_out));
}

#[test]
#[traced_test]
fn test_flow_filter_protocol_any_port_forwarding() {
    // Test that L4Protocol::Any port forwarding works for both TCP and UDP packets.

    let vni1 = vni(100);
    let vni2 = vni(200);

    let mut vpc_table = VpcTable::new();
    vpc_table
        .add(Vpc::new("vpc1", "VPC01", vni1.as_u32()).unwrap())
        .unwrap();
    vpc_table
        .add(Vpc::new("vpc2", "VPC02", vni2.as_u32()).unwrap())
        .unwrap();

    // Port forwarding with L4Protocol::Any (default)
    let mut peering_table = VpcPeeringTable::new();
    peering_table
        .add(VpcPeering::with_default_group(
            "vpc1-to-vpc2",
            VpcManifest::with_exposes(
                "vpc1",
                vec![
                    VpcExpose::empty()
                        .make_stateful_nat(None)
                        .unwrap()
                        .ip("1.0.0.0/24".into())
                        .as_range("100.0.0.0/24".into())
                        .unwrap(),
                    VpcExpose::empty()
                        .make_port_forwarding(None, None)
                        .unwrap()
                        .ip(PrefixWithOptionalPorts::new(
                            "1.0.0.27/32".into(),
                            Some(PortRange::new(2000, 2001).unwrap()),
                        ))
                        .as_range(PrefixWithOptionalPorts::new(
                            "100.0.0.27/32".into(),
                            Some(PortRange::new(3000, 3001).unwrap()),
                        ))
                        .unwrap(),
                ],
            ),
            VpcManifest::with_exposes("vpc2", vec![VpcExpose::empty().ip("5.0.0.0/24".into())]),
        ))
        .unwrap();

    let mut overlay = Overlay::new(vpc_table, peering_table);
    overlay.validate().unwrap();

    let table = FlowFilterTable::build_from_overlay(&overlay).unwrap();

    let mut writer = FlowFilterTableWriter::new();
    writer.update_flow_filter_table(table);

    let mut flow_filter = FlowFilter::new("test-filter", writer.get_reader());

    // Destination side: TCP packet -> port forwarding
    let packet = create_test_ipv4_tcp_packet_with_ports(
        Some(vni2.into()),
        "5.0.0.10".parse().unwrap(),
        "100.0.0.27".parse().unwrap(),
        456,
        3000,
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert!(needs_port_forwarding(&packet_out));

    // Destination side: UDP packet -> port forwarding
    let packet = create_test_ipv4_udp_packet_with_ports(
        Some(vni2.into()),
        "5.0.0.10".parse().unwrap(),
        "100.0.0.27".parse().unwrap(),
        456,
        3000,
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert!(needs_port_forwarding(&packet_out));
}

#[traced_test]
#[test]
fn test_flow_filter_table_from_overlay_masquerade_port_forwarding_private_ips_overlap() {
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
            VpcManifest::with_exposes(
                "vpc1",
                vec![
                    VpcExpose::empty()
                        .ip("192.168.50.0/24".into())
                        .ip("192.168.60.0/24".into()),
                ],
            ),
            VpcManifest::with_exposes(
                "vpc2",
                vec![
                    VpcExpose::empty()
                        .make_port_forwarding(None, Some(L4Protocol::Tcp))
                        .unwrap()
                        .ip(PrefixWithOptionalPorts::new(
                            "192.168.90.100/32".into(), // 192.168.90.100 used privately for VPC02
                            Some(PortRange::new(22, 22).unwrap()),
                        ))
                        .as_range(PrefixWithOptionalPorts::new(
                            "20.10.90.100/32".into(),
                            Some(PortRange::new(2222, 2222).unwrap()),
                        ))
                        .unwrap(),
                    VpcExpose::empty()
                        .make_port_forwarding(None, Some(L4Protocol::Udp))
                        .unwrap()
                        .ip(PrefixWithOptionalPorts::new(
                            "192.168.90.100/32".into(), // 192.168.90.100 used privately for VPC02
                            Some(PortRange::new(53, 53).unwrap()),
                        ))
                        .as_range(PrefixWithOptionalPorts::new(
                            "20.10.90.100/32".into(),
                            Some(PortRange::new(2053, 2053).unwrap()),
                        ))
                        .unwrap(),
                    VpcExpose::empty()
                        .make_port_forwarding(None, Some(L4Protocol::Tcp))
                        .unwrap()
                        .ip(PrefixWithOptionalPorts::new(
                            "192.168.90.100/32".into(), // 192.168.90.100 used privately for VPC02
                            Some(PortRange::new(8080, 8080).unwrap()),
                        ))
                        .as_range(PrefixWithOptionalPorts::new(
                            "20.10.90.100/32".into(),
                            Some(PortRange::new(80, 80).unwrap()),
                        ))
                        .unwrap(),
                    VpcExpose::empty().ip("192.168.80.0/24".into()),
                ],
            ),
        ))
        .unwrap();

    peering_table
        .add(VpcPeering::with_default_group(
            "vpc1-to-vpc3",
            VpcManifest::with_exposes(
                "vpc1",
                vec![
                    VpcExpose::empty()
                        .make_stateless_nat()
                        .unwrap()
                        .ip("192.168.50.0/24".into())
                        .as_range("10.30.50.0/24".into())
                        .unwrap(),
                ],
            ),
            VpcManifest::with_exposes(
                "vpc3",
                vec![
                    VpcExpose::empty().ip("192.168.100.0/24".into()),
                    VpcExpose::empty()
                        .make_stateless_nat()
                        .unwrap()
                        .ip("192.168.128.0/27".into())
                        .as_range("30.10.128.0/27".into())
                        .unwrap(),
                ],
            ),
        ))
        .unwrap();

    peering_table
        .add(VpcPeering::with_default_group(
            "vpc2-to-vpc3",
            VpcManifest::with_exposes(
                "vpc2",
                vec![
                    VpcExpose::empty()
                        .make_stateful_nat(None)
                        .unwrap()
                        .ip("192.168.90.0/24".into()) // Contains 192.168.90.100 used privately for VPC02
                        .as_range("20.30.90.0/24".into())
                        .unwrap(),
                ],
            ),
            VpcManifest::with_exposes(
                "vpc3",
                vec![VpcExpose::empty().ip("192.168.128.0/27".into())],
            ),
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

    // VPC-2 -> VPC-3: ping 192.168.128.7
    //
    // We used to have a bug where we the flow-filter lookup would fail when looking for the
    // source information because of the overlap between addresses exposed for port forwarding
    // and masquerading. For ICMP (or TCP/UDP with unforwarded ports) it would run a LPM lookup
    // on the address, find the port-forwarding entry that only works with ports, and then fail
    // because the packet doesn't have a port (or a port in the relevant range). Fixed now.
    let packet = create_test_icmp_v4_packet(
        Some(vpcd(vni2.into())),
        "192.168.90.100".parse().unwrap(),
        "192.168.128.7".parse().unwrap(),
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vpcd(vni3.into())));
    assert!(needs_masquerade(&packet_out));

    // VPC-2 -> VPC-3: 192.168.90.100:2345 -> 192.168.128.7:6789
    let packet = create_test_ipv4_tcp_packet_with_ports(
        Some(vpcd(vni2.into())),
        "192.168.90.100".parse().unwrap(),
        "192.168.128.7".parse().unwrap(),
        2345,
        6789,
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vpcd(vni3.into())));
    assert!(needs_masquerade(&packet_out));

    // VPC-2 -> VPC-3: 192.168.90.100:22 -> 192.168.128.7:6789
    //
    // Must use masquerading even though we have overlap on source IP/port with port forwarding
    // rules, because of unambiguous destination
    let packet = create_test_ipv4_tcp_packet_with_ports(
        Some(vpcd(vni2.into())),
        "192.168.90.100".parse().unwrap(),
        "192.168.128.7".parse().unwrap(),
        22,
        6789,
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vpcd(vni3.into())));
    assert!(needs_masquerade(&packet_out));

    // VPC-2 -> VPC-1: 192.168.90.100:22 -> 192.168.50.7:6789
    //
    // Overlap on source IP/port with masquerading rule, the destination is unambiguous and we find
    // a source NAT port forwarding requirement, but there's no associated flow table entry and we
    // cannot initiate a port forwarding session on the source side, so we drop
    let packet = create_test_ipv4_tcp_packet_with_ports(
        Some(vpcd(vni2.into())),
        "192.168.90.100".parse().unwrap(),
        "192.168.50.7".parse().unwrap(),
        22,
        6789,
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert_eq!(packet_out.get_done(), Some(DoneReason::Filtered));

    // VPC-2 -> VPC-1: 192.168.90.100:22 -> 192.168.50.7:6789
    //
    // Must use port forwarding even though we have overlap on source IP/port with masquerading
    // rule, because of unambiguous destination, and we have a flow table entry so source-side port
    // forwarding is allowed
    let mut packet = create_test_ipv4_tcp_packet_with_ports(
        Some(vpcd(vni2.into())),
        "192.168.90.100".parse().unwrap(),
        "192.168.50.7".parse().unwrap(),
        22,
        6789,
    );
    fake_flow_session(&mut packet, vni1.into(), false, true);
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vpcd(vni1.into())));
    assert!(needs_port_forwarding(&packet_out));
}

// This is close to the previous test: We check that for masquerade and port forwarding on a
// manifest, using the same private IPs, the flow-filter stage behaves as expected. Contrary to
// the previous example, the prefix CIDR used for masquerade is smaller than the one for port
// forwarding, although the latter is restricted to specific ports. This test validates that
// prefix splitting occurs correctly for this configuration, and that we find the right
// destination and NAT requirements.
#[traced_test]
#[test]
fn test_flow_filter_table_from_overlay_masquerade_port_forwarding_private_ips_overlap_smaller_masquerade()
 {
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
            VpcManifest::with_exposes(
                "vpc1",
                vec![
                    VpcExpose::empty()
                        .ip("192.168.50.0/24".into())
                        .ip("192.168.60.0/24".into()),
                ],
            ),
            VpcManifest::with_exposes(
                "vpc2",
                vec![
                    VpcExpose::empty()
                        .make_port_forwarding(None, Some(L4Protocol::Tcp))
                        .unwrap()
                        .ip(PrefixWithOptionalPorts::new(
                            "192.168.90.0/24".into(), // Contains 192.168.90.100 used privately from VPC 2
                            Some(PortRange::new(22, 22).unwrap()),
                        ))
                        .as_range(PrefixWithOptionalPorts::new(
                            "20.10.90.0/24".into(),
                            Some(PortRange::new(2222, 2222).unwrap()),
                        ))
                        .unwrap(),
                    VpcExpose::empty()
                        .make_port_forwarding(None, Some(L4Protocol::Udp))
                        .unwrap()
                        .ip(PrefixWithOptionalPorts::new(
                            "192.168.90.0/24".into(), // Contains 192.168.90.100 used privately from VPC 2
                            Some(PortRange::new(53, 53).unwrap()),
                        ))
                        .as_range(PrefixWithOptionalPorts::new(
                            "20.10.90.0/24".into(),
                            Some(PortRange::new(2053, 2053).unwrap()),
                        ))
                        .unwrap(),
                    VpcExpose::empty()
                        .make_port_forwarding(None, Some(L4Protocol::Tcp))
                        .unwrap()
                        .ip(PrefixWithOptionalPorts::new(
                            "192.168.90.100/32".into(), // 192.168.90.100 used privately from VPC 2
                            Some(PortRange::new(8080, 8080).unwrap()),
                        ))
                        .as_range(PrefixWithOptionalPorts::new(
                            "20.10.90.100/32".into(),
                            Some(PortRange::new(80, 80).unwrap()),
                        ))
                        .unwrap(),
                    VpcExpose::empty()
                        .make_stateful_nat(None)
                        .unwrap()
                        .ip("192.168.90.0/24".into())
                        .not("192.168.90.0/27".into())
                        .as_range("1.2.3.4/32".into())
                        .unwrap(),
                    VpcExpose::empty().ip("192.168.80.0/24".into()),
                ],
            ),
        ))
        .unwrap();

    peering_table
        .add(VpcPeering::with_default_group(
            "vpc1-to-vpc3",
            VpcManifest::with_exposes(
                "vpc1",
                vec![
                    VpcExpose::empty()
                        .make_stateless_nat()
                        .unwrap()
                        .ip("192.168.50.0/24".into())
                        .as_range("10.30.50.0/24".into())
                        .unwrap(),
                ],
            ),
            VpcManifest::with_exposes(
                "vpc3",
                vec![
                    VpcExpose::empty().ip("192.168.100.0/24".into()),
                    VpcExpose::empty()
                        .make_stateless_nat()
                        .unwrap()
                        .ip("192.168.128.0/27".into())
                        .as_range("30.10.128.0/27".into())
                        .unwrap(),
                ],
            ),
        ))
        .unwrap();

    peering_table
        .add(VpcPeering::with_default_group(
            "vpc2-to-vpc3",
            VpcManifest::with_exposes(
                "vpc2",
                vec![
                    VpcExpose::empty()
                        .make_stateful_nat(None)
                        .unwrap()
                        .ip("192.168.90.0/24".into())
                        .as_range("20.30.90.30/32".into())
                        .unwrap(),
                ],
            ),
            VpcManifest::with_exposes(
                "vpc3",
                vec![VpcExpose::empty().ip("192.168.128.0/27".into())],
            ),
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

    // VPC-2 -> VPC-3: ping 192.168.128.7
    //
    // We used to have a bug where we the flow-filter lookup would fail when looking for the
    // source information because of the overlap between addresses exposed for port forwarding
    // and masquerading. For ICMP (or TCP/UDP with unforwarded ports) it would run a LPM lookup
    // on the address, find the port-forwarding entry that only works with ports, and then fail
    // because the packet doesn't have a port (or a port in the relevant range). Fixed now.
    let packet = create_test_icmp_v4_packet(
        Some(vpcd(vni2.into())),
        "192.168.90.100".parse().unwrap(),
        "192.168.128.7".parse().unwrap(),
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vpcd(vni3.into())));
    assert!(needs_masquerade(&packet_out));

    // VPC-2 -> VPC-3: 192.168.90.100:2345 -> 192.168.128.7:6789
    let packet = create_test_ipv4_tcp_packet_with_ports(
        Some(vpcd(vni2.into())),
        "192.168.90.100".parse().unwrap(),
        "192.168.128.7".parse().unwrap(),
        2345,
        6789,
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vpcd(vni3.into())));
    assert!(needs_masquerade(&packet_out));

    // VPC-2 -> VPC-3: 192.168.90.100:22 -> 192.168.128.7:6789
    //
    // Must use masquerading even though we have overlap on source IP/port with port forwarding
    // rules, because of unambiguous destination
    let packet = create_test_ipv4_tcp_packet_with_ports(
        Some(vpcd(vni2.into())),
        "192.168.90.100".parse().unwrap(),
        "192.168.128.7".parse().unwrap(),
        22,
        6789,
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vpcd(vni3.into())));
    assert!(needs_masquerade(&packet_out));

    // VPC-2 -> VPC-1: 192.168.90.100:22 -> 192.168.50.7:6789
    //
    // Destination VPC is not ambiguous, but NAT mode is. Here we must use masquerading even
    // though we have overlap on source IP/port with port forwarding rule, because we don't have
    // flow information for the packet, so we favor masquerading so the packet can go out.
    let packet = create_test_ipv4_tcp_packet_with_ports(
        Some(vpcd(vni2.into())),
        "192.168.90.100".parse().unwrap(),
        "192.168.50.7".parse().unwrap(),
        22,
        6789,
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vpcd(vni1.into())));
    assert!(needs_masquerade(&packet_out));
}

#[traced_test]
#[test]
fn test_flow_filter_table_from_overlay_masquerade_port_forwarding_private_ips_overlap_to_default() {
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
            VpcManifest::with_exposes("vpc1", vec![VpcExpose::empty().set_default()]),
            VpcManifest::with_exposes(
                "vpc2",
                vec![
                    VpcExpose::empty()
                        .make_port_forwarding(None, Some(L4Protocol::Tcp))
                        .unwrap()
                        .ip(PrefixWithOptionalPorts::new(
                            "1.0.0.1/32".into(),
                            Some(PortRange::new(22, 22).unwrap()),
                        ))
                        .as_range(PrefixWithOptionalPorts::new(
                            "10.0.0.1/32".into(),
                            Some(PortRange::new(2222, 2222).unwrap()),
                        ))
                        .unwrap(),
                    VpcExpose::empty()
                        .make_stateful_nat(None)
                        .unwrap()
                        .ip("1.0.0.0/24".into())
                        .as_range("10.0.0.0/24".into())
                        .unwrap(),
                ],
            ),
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

    // VPC-1 -> VPC-2, outside of port forwarding range, no flow info attached
    //
    // Only masquerading applies but we cannot initiate the connection towards the expose using
    // masquerading.
    let packet = create_test_ipv4_tcp_packet_with_ports(
        Some(vpcd(vni1.into())),
        "7.7.7.7".parse().unwrap(),
        "10.0.0.1".parse().unwrap(),
        1234,
        5678,
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert_eq!(packet_out.get_done(), Some(DoneReason::Filtered));

    // VPC-1 -> VPC-2, outside of port forwarding range, with flow info attached
    //
    // Only masquerading applies.
    let mut packet = create_test_ipv4_tcp_packet_with_ports(
        Some(vpcd(vni1.into())),
        "7.7.7.7".parse().unwrap(),
        "10.0.0.1".parse().unwrap(),
        1234,
        5678,
    );
    fake_flow_session(&mut packet, vni2.into(), true, false);
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vpcd(vni2.into())));
    assert!(needs_masquerade(&packet_out));

    // VPC-1 -> VPC-2, inside port forwarding range
    //
    // Given that we have no flow table entry, port forwarding should take precedence in that
    // direction.
    let packet = create_test_ipv4_tcp_packet_with_ports(
        Some(vpcd(vni1.into())),
        "7.7.7.7".parse().unwrap(),
        "10.0.0.1".parse().unwrap(),
        1234,
        2222,
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vpcd(vni2.into())));
    assert!(needs_port_forwarding(&packet_out));

    // VPC-2 -> VPC-1, inside port forwarding range
    //
    // Given that we have no flow table entry, masquerading should take precedence in that
    // direction.
    let packet = create_test_ipv4_tcp_packet_with_ports(
        Some(vpcd(vni2.into())),
        "1.0.0.1".parse().unwrap(),
        "7.7.7.7".parse().unwrap(),
        22,
        1234,
    );
    let packet_out = flow_filter.process([packet].into_iter()).next().unwrap();
    assert!(!packet_out.is_done(), "{:?}", packet_out.get_done());
    assert_eq!(packet_out.meta().dst_vpcd, Some(vpcd(vni1.into())));
    assert!(needs_masquerade(&packet_out));
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
