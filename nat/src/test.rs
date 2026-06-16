// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! NAT tests

#![cfg(test)]

use super::*;
use crate::masquerade::{NatAllocatorWriter, StatefulNatConfig};
use crate::portfw::{PortForwarder, PortFwTableWriter};
use crate::static_nat::NatTablesWriter;
use crate::static_nat::setup::build_nat_configuration;
use concurrency::sync::Arc;
use config::external::overlay::vpc::{Vpc, VpcTable};
use config::external::overlay::vpcpeering::{VpcExpose, VpcManifest, VpcPeering, VpcPeeringTable};
use config::external::overlay::{Overlay, ValidatedOverlay};
use flow_entry::flow_table::FlowLookup;
use flow_entry::flow_table::FlowTable;
use flow_filter::{FlowFilter, FlowFilterTable, FlowFilterTableWriter};
use lpm::prefix::{PortRange, PrefixWithOptionalPorts};
use net::buffer::TestBuffer;
use net::eth::mac::Mac;
use net::headers::TryEmbeddedTransport;
use net::headers::{EmbeddedTransport, TryInnerIpv4};
use net::ip::NextHeader;
use net::packet::Packet;
use net::packet::test_utils::{
    addr_v4, build_test_icmp4_destination_unreachable_packet, build_test_udp_ipv4_frame,
};
use net::vxlan::Vni;
use pipeline::{DynPipeline, NetworkFunction};
use tracectl::get_trace_ctl;

fn addr(s: &str) -> IpAddr {
    addr_v4(s).into()
}

fn pwp(s: &str, start: u16, end: u16) -> PrefixWithOptionalPorts {
    PrefixWithOptionalPorts::new(s.into(), Some(PortRange::new(start, end).unwrap()))
}

fn vni(vni: u32) -> Vni {
    Vni::new_checked(vni).expect("Failed to create VNI")
}

fn build_packet(
    src_ip: &str,
    dst_ip: &str,
    src_port: u16,
    dst_port: u16,
    src_vni: Vni,
) -> Packet<TestBuffer> {
    let mut packet: Packet<TestBuffer> = build_test_udp_ipv4_frame(
        Mac([0x2, 0, 0, 0, 0, 1]),
        Mac([0x2, 0, 0, 0, 0, 2]),
        src_ip,
        dst_ip,
        src_port,
        dst_port,
    );
    packet.meta_mut().set_overlay(true);
    packet.meta_mut().src_vpcd = Some(src_vni.into());
    println!("built packet:\n{packet}");
    packet
}

fn setup_masq_pipeline(
    overlay: &ValidatedOverlay,
) -> (
    DynPipeline<TestBuffer>,
    Arc<FlowTable>,
    FlowFilterTableWriter,
    NatTablesWriter,
    PortFwTableWriter,
    NatAllocatorWriter,
) {
    let mut pipeline: DynPipeline<TestBuffer> = DynPipeline::new();

    // Flow table
    let flow_table = Arc::new(FlowTable::default());

    // ICMP Error messages handler
    let icmp_error_handler = IcmpErrorHandler::new(flow_table.clone());
    pipeline = pipeline.add_stage(icmp_error_handler);

    // Flow table lookup
    let flow_lookup = FlowLookup::new("flow-lookup", flow_table.clone());
    pipeline = pipeline.add_stage(flow_lookup);

    // Flow-filter
    let flow_filter_table = FlowFilterTable::build_from_overlay(overlay).unwrap();
    println!("{flow_filter_table}");
    let mut flow_filter_writer = FlowFilterTableWriter::new();
    flow_filter_writer.update_flow_filter_table(flow_filter_table);
    let flow_filter = FlowFilter::new("flow-filter", flow_filter_writer.get_reader());
    pipeline = pipeline.add_stage(flow_filter);

    // Static NAT stage
    let static_nat_tables = build_nat_configuration(overlay.vpc_table()).unwrap();
    println!("{static_nat_tables}");
    let mut static_nat_writer = NatTablesWriter::new();
    static_nat_writer.update_nat_tables(static_nat_tables);
    let static_nat = StaticNat::with_reader("static-NAT-1", static_nat_writer.get_reader());
    pipeline = pipeline.add_stage(static_nat);

    // Port forwarding
    let mut portfw_writer = PortFwTableWriter::new();
    portfw_writer
        .update_from_vpc_table(overlay.vpc_table())
        .unwrap();
    let portfw = PortForwarder::new("port-forwarder", portfw_writer.reader(), flow_table.clone());
    if let Some(table) = portfw_writer.enter() {
        println!("{}", table.as_ref());
    }
    pipeline = pipeline.add_stage(portfw);

    // Masquerade
    let mut allocator = NatAllocatorWriter::new();
    let masquerade = StatefulNat::new("masquerade", flow_table.clone(), allocator.get_reader());
    let masquerade_config = StatefulNatConfig::new(overlay.vpc_table(), 1);
    allocator.update_nat_allocator(masquerade_config, &flow_table);
    if let Some(state) = allocator.get_reader().get() {
        println!("{state}");
    }
    pipeline = pipeline.add_stage(masquerade);

    (
        pipeline,
        flow_table,
        flow_filter_writer,
        static_nat_writer,
        portfw_writer,
        allocator,
    )
}

#[tokio::test]
async fn test_nat_combination_static_masquerade() {
    #[cfg(not(miri))]
    let _tctl = get_trace_ctl().setup_from_string("pipeline=debug");

    let vni1 = vni(100);
    let vni2 = vni(200);
    let orig_src_ip = "1.2.3.4";
    let orig_dst_ip = "5.6.7.8";
    let orig_src_port = 1234;
    let orig_dst_port = 5678;
    let target_src_ip = "5.5.5.5";
    let target_dst_ip = "192.168.0.8";

    // Build overlay
    let mut vpc_table = VpcTable::new();
    vpc_table
        .add(Vpc::new("vpc1", "VPC01", vni1.as_u32()).unwrap())
        .unwrap();
    vpc_table
        .add(Vpc::new("vpc2", "VPC02", vni2.as_u32()).unwrap())
        .unwrap();
    let mut peering_table = VpcPeeringTable::new();
    peering_table
        .add(VpcPeering::new(
            "vpc1-to-vpc2",
            VpcManifest::with_exposes(
                "vpc1",
                vec![
                    VpcExpose::empty()
                        .make_stateful_nat(None) // Masquerade
                        .unwrap()
                        .ip("1.2.3.0/24".into())
                        .as_range("5.5.5.5/32".into())
                        .unwrap(),
                ],
            ),
            VpcManifest::with_exposes(
                "vpc2",
                vec![
                    VpcExpose::empty()
                        .make_static_nat() // Static NAT (no ports)
                        .unwrap()
                        .ip("192.168.0.0/24".into())
                        .as_range("5.6.7.0/24".into())
                        .unwrap(),
                ],
            ),
            None,
        ))
        .unwrap();
    let overlay = Overlay::new(vpc_table, peering_table).validate().unwrap();

    // Build pipeline
    //
    // Retrieve the writer handles even if we don't use them, to avoid them being dropped when we
    // exit setup_masq_pipeline().
    let (
        mut pipeline,
        flow_table,
        _flow_filter_writer,
        _static_nat_writer,
        _portfw_writer,
        _masquerade_writer,
    ) = setup_masq_pipeline(&overlay);

    // Test packet: | 1.2.3.4:1234 > 5.6.7.8:5678 | becomes | 5.5.5.5:XXXX > 192.168.0.8:5678 |
    let packet = build_packet(orig_src_ip, orig_dst_ip, orig_src_port, orig_dst_port, vni1);
    let output: Vec<_> = pipeline.process(std::iter::once(packet)).collect();
    assert_eq!(output.len(), 1);
    let packet_out = output.first().unwrap();
    println!("packet_out:\n{packet_out}\n{flow_table}");
    assert_eq!(packet_out.get_done(), None);
    assert_eq!(packet_out.ip_source(), Some(addr(target_src_ip)));
    assert_eq!(packet_out.ip_destination(), Some(addr(target_dst_ip)));

    let target_src_port = packet_out.transport_src_port().unwrap().get();
    let target_dst_port = orig_dst_port;

    // Reply packet: | 192.168.0.8:5678 > 5.5.5.5:XXXX | becomes | 5.6.7.8:5678 > 1.2.3.4:1234 |
    let packet_reply = build_packet(
        target_dst_ip,
        target_src_ip,
        target_dst_port,
        target_src_port,
        vni2,
    );
    let output_reply: Vec<_> = pipeline.process(std::iter::once(packet_reply)).collect();
    assert_eq!(output_reply.len(), 1);
    let packet_out_reply = output_reply.first().unwrap();
    println!("packet_out_reply:\n{packet_out_reply}\n{flow_table}");
    assert_eq!(packet_out_reply.get_done(), None);
    assert_eq!(packet_out_reply.ip_source(), Some(addr(orig_dst_ip)));
    assert_eq!(packet_out_reply.ip_destination(), Some(addr(orig_src_ip)));

    // Test initial packet again now that the session is established
    let packet = build_packet(orig_src_ip, orig_dst_ip, orig_src_port, orig_dst_port, vni1);
    let output: Vec<_> = pipeline.process(std::iter::once(packet)).collect();
    assert_eq!(output.len(), 1);
    let packet_out = output.first().unwrap();
    println!("packet_out:\n{packet_out}\n{flow_table}");
    assert_eq!(packet_out.get_done(), None);
    assert_eq!(packet_out.ip_source(), Some(addr(target_src_ip)));
    assert_eq!(packet_out.ip_destination(), Some(addr(target_dst_ip)));
    assert_eq!(flow_table.len(), Some(2));
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_nat_combination_static_portfw() {
    #[cfg(not(miri))]
    let _tctl = get_trace_ctl().setup_from_string("pipeline=debug");

    let vni1 = vni(100);
    let vni2 = vni(200);
    let orig_src_ip = "1.2.3.4";
    let orig_dst_ip = "5.6.7.8";
    let orig_src_port = 1234;
    let orig_dst_port = 5678;
    let target_src_ip = "5.5.5.4";
    let target_dst_ip = "192.168.0.8";
    let target_src_port = 1734;
    let target_dst_port = 7678;

    // Build overlay
    let mut vpc_table = VpcTable::new();
    vpc_table
        .add(Vpc::new("vpc1", "VPC01", vni1.as_u32()).unwrap())
        .unwrap();
    vpc_table
        .add(Vpc::new("vpc2", "VPC02", vni2.as_u32()).unwrap())
        .unwrap();
    let mut peering_table = VpcPeeringTable::new();
    peering_table
        .add(VpcPeering::new(
            "vpc1-to-vpc2",
            VpcManifest::with_exposes(
                "vpc1",
                vec![
                    VpcExpose::empty()
                        .make_static_nat() // Static NAT (with ports)
                        .unwrap()
                        .ip(pwp("1.2.3.0/24", 1201, 1300))
                        .as_range(pwp("5.5.5.0/24", 1701, 1800))
                        .unwrap(),
                ],
            ),
            VpcManifest::with_exposes(
                "vpc2",
                vec![
                    VpcExpose::empty()
                        .make_port_forwarding(None, None) // Port forwarding
                        .unwrap()
                        .ip(pwp("192.168.0.0/24", 7001, 8000))
                        .as_range(pwp("5.6.7.0/24", 5001, 6000))
                        .unwrap(),
                ],
            ),
            None,
        ))
        .unwrap();
    let overlay = Overlay::new(vpc_table, peering_table).validate().unwrap();

    // Build pipeline
    //
    // Retrieve the writer handles even if we don't use them, to avoid them being dropped when we
    // exit setup_masq_pipeline().
    let (
        mut pipeline,
        flow_table,
        _flow_filter_writer,
        _static_nat_writer,
        _portfw_writer,
        _masquerade_writer,
    ) = setup_masq_pipeline(&overlay);

    // Test packet: | 1.2.3.4:1234 > 5.6.7.8:5678 | becomes | 5.5.5.4:1734 > 192.168.0.8:7678 |
    let packet = build_packet(orig_src_ip, orig_dst_ip, orig_src_port, orig_dst_port, vni1);
    let output: Vec<_> = pipeline.process(std::iter::once(packet)).collect();
    assert_eq!(output.len(), 1);
    let packet_out = output.first().unwrap();
    println!("packet_out:\n{packet_out}\n{flow_table}");
    assert_eq!(packet_out.get_done(), None);
    assert_eq!(packet_out.ip_source(), Some(addr(target_src_ip)));
    assert_eq!(packet_out.ip_destination(), Some(addr(target_dst_ip)));
    assert_eq!(
        packet_out.udp_source_port().unwrap().as_u16(),
        target_src_port
    );
    assert_eq!(
        packet_out.udp_destination_port().unwrap().as_u16(),
        target_dst_port
    );

    // Reply packet: | 192.168.0.8:7678 > 5.5.5.4:1734 | becomes | 5.6.7.8:5678 > 1.2.3.4:1234 |
    let packet_reply = build_packet(
        target_dst_ip,
        target_src_ip,
        target_dst_port,
        target_src_port,
        vni2,
    );
    let output_reply: Vec<_> = pipeline.process(std::iter::once(packet_reply)).collect();
    assert_eq!(output_reply.len(), 1);
    let packet_out_reply = output_reply.first().unwrap();
    println!("packet_out_reply:\n{packet_out_reply}\n{flow_table}");
    assert_eq!(packet_out_reply.get_done(), None);
    assert_eq!(packet_out_reply.ip_source(), Some(addr(orig_dst_ip)));
    assert_eq!(packet_out_reply.ip_destination(), Some(addr(orig_src_ip)));
    assert_eq!(
        packet_out_reply.udp_source_port().unwrap().as_u16(),
        orig_dst_port
    );
    assert_eq!(
        packet_out_reply.udp_destination_port().unwrap().as_u16(),
        orig_src_port
    );
    assert_eq!(flow_table.len(), Some(2));

    // Test initial packet again now that the session is established
    let packet = build_packet(orig_src_ip, orig_dst_ip, orig_src_port, orig_dst_port, vni1);
    let output: Vec<_> = pipeline.process(std::iter::once(packet)).collect();
    assert_eq!(output.len(), 1);
    let packet_out = output.first().unwrap();
    println!("packet_out:\n{packet_out}\n{flow_table}");
    assert_eq!(packet_out.get_done(), None);
    assert_eq!(packet_out.ip_source(), Some(addr(target_src_ip)));
    assert_eq!(packet_out.ip_destination(), Some(addr(target_dst_ip)));
}

// Static NAT + masquerade: Check that ICMP errors are handled correctly
#[tokio::test]
async fn test_nat_combination_static_masq_icmp_error() {
    #[cfg(not(miri))]
    let _tctl = get_trace_ctl().setup_from_string("pipeline=debug");

    let vni1 = vni(100);
    let vni2 = vni(200);
    let orig_src_ip = "1.2.3.4";
    let orig_dst_ip = "5.6.7.8";
    let orig_src_port = 1234;
    let orig_dst_port = 5678;
    let target_src_ip = "5.5.5.5";
    let target_dst_ip = "192.168.0.8";

    // Build overlay
    let mut vpc_table = VpcTable::new();
    vpc_table
        .add(Vpc::new("vpc1", "VPC01", vni1.as_u32()).unwrap())
        .unwrap();
    vpc_table
        .add(Vpc::new("vpc2", "VPC02", vni2.as_u32()).unwrap())
        .unwrap();
    let mut peering_table = VpcPeeringTable::new();
    peering_table
        .add(VpcPeering::new(
            "vpc1-to-vpc2",
            VpcManifest::with_exposes(
                "vpc1",
                vec![
                    VpcExpose::empty()
                        .make_stateful_nat(None) // Masquerade
                        .unwrap()
                        .ip("1.2.3.0/24".into())
                        .as_range("5.5.5.5/32".into())
                        .unwrap(),
                ],
            ),
            VpcManifest::with_exposes(
                "vpc2",
                vec![
                    VpcExpose::empty()
                        .make_static_nat() // Static NAT (no ports)
                        .unwrap()
                        .ip("192.168.0.0/24".into())
                        .as_range("5.6.7.0/24".into())
                        .unwrap(),
                ],
            ),
            None,
        ))
        .unwrap();
    let overlay = Overlay::new(vpc_table, peering_table).validate().unwrap();

    // Build pipeline
    //
    // Retrieve the writer handles even if we don't use them, to avoid them being dropped when we
    // exit setup_masq_pipeline().
    let (
        mut pipeline,
        flow_table,
        _flow_filter_writer,
        _static_nat_writer,
        _portfw_writer,
        _masquerade_writer,
    ) = setup_masq_pipeline(&overlay);

    // Test packet: | 1.2.3.4:1234 > 5.6.7.8:5678 | becomes | 5.5.5.5:XXXX > 192.168.0.8:5678 |
    let packet = build_packet(orig_src_ip, orig_dst_ip, orig_src_port, orig_dst_port, vni1);
    let output: Vec<_> = pipeline.process(std::iter::once(packet)).collect();
    assert_eq!(output.len(), 1);
    let packet_out = output.first().unwrap();
    println!("packet_out:\n{packet_out}\n{flow_table}");
    assert_eq!(packet_out.get_done(), None);
    assert_eq!(packet_out.ip_source(), Some(addr(target_src_ip)));
    assert_eq!(packet_out.ip_destination(), Some(addr(target_dst_ip)));

    let target_src_port = packet_out.transport_src_port().unwrap().get();
    let target_dst_port = orig_dst_port;

    // Test packet didn't reach its final destination! Instead, a router sends an ICMP error back
    // Outer header: | 9.10.11.12 > 5.5.5.5 | becomes | 9.10.11.12 > 1.2.3.4 |
    // Inner header: | 5.5.5.5:XXXX > 192.168.0.8:5678 | becomes | 1.2.3.4:1234 > 5.6.7.8:5678 |
    let router_ip = "9.10.11.12";
    let mut icmp_error = build_test_icmp4_destination_unreachable_packet(
        addr_v4(router_ip),
        addr_v4(target_src_ip),
        addr_v4(target_src_ip),
        addr_v4(target_dst_ip),
        NextHeader::UDP,
        target_src_port,
        target_dst_port,
    )
    .unwrap();
    icmp_error.meta_mut().set_overlay(true);
    icmp_error.meta_mut().src_vpcd = Some(vni2.into());
    println!("built packet:\n{icmp_error}");

    let output_reply: Vec<_> = pipeline.process(std::iter::once(icmp_error)).collect();
    assert_eq!(output_reply.len(), 1);
    let packet_out_reply = output_reply.first().unwrap();
    println!("packet_out_reply:\n{packet_out_reply}\n{flow_table}");
    assert_eq!(packet_out_reply.get_done(), None);

    // Check outer IP addresses
    assert_eq!(packet_out_reply.ip_source(), Some(addr(router_ip)));
    assert_eq!(packet_out_reply.ip_destination(), Some(addr(orig_src_ip)));

    // Check inner IP addresses
    let embedded_ip = packet_out_reply.try_inner_ipv4().unwrap();
    assert_eq!(
        embedded_ip.source(),
        addr_v4(orig_src_ip).try_into().unwrap()
    );
    assert_eq!(embedded_ip.destination(), addr_v4(orig_dst_ip));

    // Check inner UDP ports
    let EmbeddedTransport::Udp(embedded_udp) = packet_out_reply.try_embedded_transport().unwrap()
    else {
        panic!("expected UDP transport");
    };
    assert_eq!(embedded_udp.source().as_u16(), orig_src_port);
    assert_eq!(embedded_udp.destination().as_u16(), orig_dst_port);
}

// Static NAT + port forwarding: Check that ICMP errors are handled correctly
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_nat_combination_static_portfwd_icmp_error() {
    #[cfg(not(miri))]
    let _tctl = get_trace_ctl().setup_from_string("pipeline=debug");

    let vni1 = vni(100);
    let vni2 = vni(200);
    let orig_src_ip = "1.2.3.4";
    let orig_dst_ip = "5.6.7.8";
    let orig_src_port = 1234;
    let orig_dst_port = 5678;
    let target_src_ip = "5.5.5.4";
    let target_dst_ip = "192.168.0.8";
    let target_src_port = orig_src_port;
    let target_dst_port = 7678;

    // Build overlay
    let mut vpc_table = VpcTable::new();
    vpc_table
        .add(Vpc::new("vpc1", "VPC01", vni1.as_u32()).unwrap())
        .unwrap();
    vpc_table
        .add(Vpc::new("vpc2", "VPC02", vni2.as_u32()).unwrap())
        .unwrap();
    let mut peering_table = VpcPeeringTable::new();
    peering_table
        .add(VpcPeering::new(
            "vpc1-to-vpc2",
            VpcManifest::with_exposes(
                "vpc1",
                vec![
                    VpcExpose::empty()
                        .make_static_nat() // Static NAT
                        .unwrap()
                        .ip("1.2.3.0/24".into())
                        .as_range("5.5.5.0/24".into())
                        .unwrap(),
                ],
            ),
            VpcManifest::with_exposes(
                "vpc2",
                vec![
                    VpcExpose::empty()
                        .make_port_forwarding(None, None) // Port forwarding
                        .unwrap()
                        .ip(pwp("192.168.0.0/24", 7001, 8000))
                        .as_range(pwp("5.6.7.0/24", 5001, 6000))
                        .unwrap(),
                ],
            ),
            None,
        ))
        .unwrap();
    let overlay = Overlay::new(vpc_table, peering_table).validate().unwrap();

    // Build pipeline
    //
    // Retrieve the writer handles even if we don't use them, to avoid them being dropped when we
    // exit setup_masq_pipeline().
    let (
        mut pipeline,
        flow_table,
        _flow_filter_writer,
        _static_nat_writer,
        _portfw_writer,
        _masquerade_writer,
    ) = setup_masq_pipeline(&overlay);

    // Test packet: | 1.2.3.4:1234 > 5.6.7.8:5678 | becomes | 5.5.5.4:1734 > 192.168.0.8:7678 |
    let packet = build_packet(orig_src_ip, orig_dst_ip, orig_src_port, orig_dst_port, vni1);
    let output: Vec<_> = pipeline.process(std::iter::once(packet)).collect();
    assert_eq!(output.len(), 1);
    let packet_out = output.first().unwrap();
    println!("packet_out:\n{packet_out}\n{flow_table}");
    assert_eq!(packet_out.get_done(), None);
    assert_eq!(packet_out.ip_source(), Some(addr(target_src_ip)));
    assert_eq!(packet_out.ip_destination(), Some(addr(target_dst_ip)));
    assert_eq!(
        packet_out.udp_source_port().unwrap().as_u16(),
        target_src_port
    );
    assert_eq!(
        packet_out.udp_destination_port().unwrap().as_u16(),
        target_dst_port
    );

    // Test packet didn't reach its final destination! Instead, a router sends an ICMP error back
    // Outer header: | 9.10.11.12 > 5.5.5.4 | becomes | 9.10.11.12 > 1.2.3.4 |
    // Inner header: | 5.5.5.4:1734 > 192.168.0.8:7678 | becomes | 1.2.3.4:1234 > 5.6.7.8:5678 |
    let router_ip = "9.10.11.12";
    let mut icmp_error = build_test_icmp4_destination_unreachable_packet(
        addr_v4(router_ip),
        addr_v4(target_src_ip),
        addr_v4(target_src_ip),
        addr_v4(target_dst_ip),
        NextHeader::UDP,
        target_src_port,
        target_dst_port,
    )
    .unwrap();
    icmp_error.meta_mut().set_overlay(true);
    icmp_error.meta_mut().src_vpcd = Some(vni2.into());
    println!("built packet:\n{icmp_error}");

    let output_reply: Vec<_> = pipeline.process(std::iter::once(icmp_error)).collect();
    assert_eq!(output_reply.len(), 1);
    let packet_out_reply = output_reply.first().unwrap();
    println!("packet_out_reply:\n{packet_out_reply}\n{flow_table}");
    assert_eq!(packet_out_reply.get_done(), None);

    // Check outer IP addresses and ports
    assert_eq!(packet_out_reply.ip_source(), Some(addr(orig_dst_ip))); // Note: We always overwrite the router IP with the original destination IP.
    assert_eq!(packet_out_reply.ip_destination(), Some(addr(orig_src_ip)));

    // Check inner IP addresses
    let embedded_ip = packet_out_reply.try_inner_ipv4().unwrap();
    assert_eq!(
        embedded_ip.source(),
        addr_v4(orig_src_ip).try_into().unwrap()
    );
    assert_eq!(embedded_ip.destination(), addr_v4(orig_dst_ip));

    // Check inner UDP ports
    let EmbeddedTransport::Udp(embedded_udp) = packet_out_reply.try_embedded_transport().unwrap()
    else {
        panic!("expected UDP transport");
    };
    assert_eq!(embedded_udp.source().as_u16(), orig_src_port);
    assert_eq!(embedded_udp.destination().as_u16(), orig_dst_port);
}
