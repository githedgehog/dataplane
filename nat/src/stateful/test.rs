// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![cfg(test)]

use crate::common::{NatAction, NatFlowStatus};
use crate::stateful::state::MasqueradeState;
use crate::stateful::{NatAllocatorWriter, StatefulNatConfig};
use crate::{IcmpErrorHandler, StatefulNat};
use ahash::HashMap;
use common::cliprovider::Frame;
use concurrency::sync::Arc;
use config::external::overlay::Overlay;
use config::external::overlay::vpc::{Vpc, VpcTable};
use config::external::overlay::vpcpeering::{VpcExpose, VpcManifest, VpcPeering, VpcPeeringTable};
use config::{ConfigError, GenId};
use flow_entry::flow_table::{FlowLookup, FlowTable};
use flow_filter::{FlowFilter, FlowFilterTable, FlowFilterTableWriter};
use net::buffer::{PacketBufferMut, TestBuffer};
use net::eth::mac::Mac;
use net::flow_key::Uni;
use net::flows::FlowStatus;
use net::flows::flow_info_item::ExtractRef;
use net::headers::TryTcpMut;
use net::headers::{
    EmbeddedTransport, TryEmbeddedTransport as _, TryIcmp4, TryInnerIpv4, TryIpv4, TryUdp,
};
use net::icmp4::Icmp4Type;
use net::icmp4::TruncatedIcmp4;
use net::ip::NextHeader;
use net::packet::test_utils::build_test_tcp_ipv4_packet;
use net::packet::test_utils::{
    IcmpEchoDirection, build_test_icmp4_destination_unreachable_packet, build_test_icmp4_echo,
    build_test_udp_ipv4_frame,
};
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use net::tcp::TruncatedTcp;
use net::udp::{TruncatedUdp, UdpPort};
use net::vxlan::Vni;
use net::{FlowKey, IpProtoKey, UdpProtoKey};
use pipeline::DynPipeline;
use pipeline::NetworkFunction;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::{Duration, Instant};
use tracectl::get_trace_ctl;
use tracing::debug;
use tracing_test::traced_test;

const ONE_MINUTE: Duration = Duration::from_mins(1);
use crate::stateless::test::build_gwconfig_from_overlay;

fn test_case(msg: &str) {
    debug!("{}", Frame(msg));
}

#[derive(Default)]
struct TestFlowFilter(HashMap<VpcDiscriminant, VpcDiscriminant>);
impl TestFlowFilter {
    fn with_peerings(peerings: Vec<(VpcDiscriminant, VpcDiscriminant)>) -> Self {
        let mut new = TestFlowFilter::default();
        for (src_vpcd, dst_vpcd) in peerings {
            new.0.insert(src_vpcd, dst_vpcd);
            new.0.insert(dst_vpcd, src_vpcd);
        }
        new
    }
}
impl NetworkFunction<TestBuffer> for TestFlowFilter {
    fn process<'a, Input: Iterator<Item = Packet<TestBuffer>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<TestBuffer>> + 'a {
        input.map(|mut packet| {
            let src_vpcd = packet.meta().src_vpcd.unwrap(); // packets must have src vpcd
            debug!("packet comes from {src_vpcd}");
            let Some(dst_vpcd) = self.0.get(&src_vpcd) else {
                panic!("Did not find dst vpcd for source  vpcd: {src_vpcd}");
            };
            debug!(" ... and goes to {dst_vpcd}");
            packet.meta_mut().dst_vpcd = Some(*dst_vpcd);
            packet
        })
    }
}

// build pipeline: icmp-error-handler|flow-lookup|stateful-NAT
fn setup_pipeline_stateful_nat(
    flow_filter: TestFlowFilter,
) -> (Arc<FlowTable>, DynPipeline<TestBuffer>, NatAllocatorWriter) {
    let alloc_writer = NatAllocatorWriter::new();
    let alloc_reader = alloc_writer.get_reader_factory().handle();

    let flow_table = Arc::new(FlowTable::default());
    let flow_lookup = FlowLookup::new("flow-lookup", flow_table.clone());
    let icmp_error_handler = IcmpErrorHandler::new(flow_table.clone());
    let nat = StatefulNat::new("masq", flow_table.clone(), alloc_reader);
    let pipeline: DynPipeline<TestBuffer> = DynPipeline::new()
        .add_stage(icmp_error_handler)
        .add_stage(flow_lookup)
        .add_stage(flow_filter)
        .add_stage(nat);

    (flow_table, pipeline, alloc_writer)
}

fn test_setup(
    genid: GenId,
    mut overlay: Overlay,
) -> (Arc<FlowTable>, DynPipeline<TestBuffer>, NatAllocatorWriter) {
    overlay.validate().unwrap();

    // build the configuration for the nat allocator
    let nat_config = StatefulNatConfig::new(&overlay.vpc_table, genid);

    // build the config for the test flow filter and the flow filter
    let peerings: Vec<_> = nat_config
        .iter()
        .map(|p| (p.src_vpcd, p.dst_vpcd))
        .collect();
    let flow_filter = TestFlowFilter::with_peerings(peerings);

    // build pipeline: icmp-error-handler|flow-lookup|TestFlowFilter|stateful-NAT
    let (flow_table, pipeline, mut alloc_writer) = setup_pipeline_stateful_nat(flow_filter);

    // setup the NAT allocator
    alloc_writer.update_nat_allocator(nat_config, &flow_table);

    (flow_table, pipeline, alloc_writer)
}

fn addr_v4(addr: &str) -> Ipv4Addr {
    Ipv4Addr::from_str(addr).expect("Failed to create IPv4 address")
}

fn vni(vni: u32) -> Vni {
    Vni::new_checked(vni).expect("Failed to create VNI")
}

fn vpcd(vni_id: u32) -> VpcDiscriminant {
    VpcDiscriminant::from_vni(vni(vni_id))
}

#[allow(clippy::too_many_lines)]
fn build_overlay_4vpcs() -> Overlay {
    let mut vpc_table = VpcTable::new();
    let _ = vpc_table.add(Vpc::new("VPC-1", "AAAAA", 100).expect("Failed to add VPC"));
    let _ = vpc_table.add(Vpc::new("VPC-2", "BBBBB", 200).expect("Failed to add VPC"));
    let _ = vpc_table.add(Vpc::new("VPC-3", "CCCCC", 300).expect("Failed to add VPC"));
    let _ = vpc_table.add(Vpc::new("VPC-4", "DDDDD", 400).expect("Failed to add VPC"));

    // VPC1 --------- VPC 2
    //  |    \           |
    //  |      \         |
    //  |        \       |
    //  |          \     |
    //  |            \   |
    // VPC3 --------- VPC 4

    // VPC1 <-> VPC2
    let expose121 = VpcExpose::empty()
        .make_stateful_nat(Some(ONE_MINUTE))
        .unwrap()
        .ip("1.1.0.0/16".into())
        .as_range("10.12.0.0/16".into())
        .unwrap();
    let expose122 = VpcExpose::empty()
        .make_stateful_nat(None)
        .unwrap()
        .ip("1.2.0.0/16".into())
        .as_range("10.98.128.0/17".into())
        .unwrap()
        .as_range("10.99.0.0/17".into())
        .unwrap();
    let expose123 = VpcExpose::empty()
        .make_stateful_nat(None)
        .unwrap()
        .ip("1.3.0.0/24".into())
        .as_range("10.100.0.0/24".into())
        .unwrap();
    let expose211 = VpcExpose::empty().ip("10.201.201.0/24".into());
    let expose212 = VpcExpose::empty().ip("10.201.202.0/24".into());
    let expose213 = VpcExpose::empty().ip("10.201.203.0/24".into());
    let expose214 = VpcExpose::empty().ip("10.201.204.192/28".into());

    // VPC1 <-> VPC3
    let expose131 = VpcExpose::empty()
        .make_stateful_nat(None)
        .unwrap()
        .ip("1.1.0.0/16".into())
        .as_range("3.3.0.0/16".into())
        .unwrap();
    let expose132 = VpcExpose::empty()
        .make_stateful_nat(None)
        .unwrap()
        .ip("1.2.0.0/16".into())
        .as_range("3.1.0.0/16".into())
        .unwrap()
        .not_as("3.1.128.0/17".into())
        .unwrap()
        .as_range("3.2.0.0/17".into())
        .unwrap();
    let expose311 = VpcExpose::empty().ip("3.3.3.0/24".into());

    // VPC1 <-> VPC4
    let expose141 = VpcExpose::empty()
        .make_stateful_nat(None)
        .unwrap()
        .ip("1.1.0.0/16".into())
        .as_range("4.4.0.0/16".into())
        .unwrap();
    let expose411 = VpcExpose::empty().ip("4.5.0.0/16".into());

    // VPC2 <-> VPC4
    let expose241 = VpcExpose::empty()
        .make_stateful_nat(None)
        .unwrap()
        .ip("2.4.0.0/16".into())
        .not("2.4.1.0/24".into())
        .as_range("44.0.0.0/16".into())
        .unwrap()
        .not_as("44.0.200.0/24".into())
        .unwrap();
    let expose421 = VpcExpose::empty()
        .ip("44.4.0.0/16".into())
        .not("44.4.64.0/18".into());

    // VPC3 <-> VPC4
    let expose341 = VpcExpose::empty()
        .make_stateful_nat(None)
        .unwrap()
        .ip("192.168.100.0/24".into())
        .as_range("34.34.34.0/24".into())
        .unwrap();
    let expose431 = VpcExpose::empty().ip("4.4.0.0/24".into());

    // VPC1 <-> VPC2
    let manifest12 = VpcManifest::new("VPC-1")
        .exposing(expose121)
        .exposing(expose122)
        .exposing(expose123);

    let manifest21 = VpcManifest::new("VPC-2")
        .exposing(expose211)
        .exposing(expose212)
        .exposing(expose213)
        .exposing(expose214);

    // VPC1 <-> VPC3
    let manifest13 = VpcManifest::new("VPC-1")
        .exposing(expose131)
        .exposing(expose132);
    let manifest31 = VpcManifest::new("VPC-3").exposing(expose311);

    // VPC1 <-> VPC4
    let manifest14 = VpcManifest::new("VPC-1").exposing(expose141);
    let manifest41 = VpcManifest::new("VPC-4").exposing(expose411);

    // VPC2 <-> VPC4
    let manifest24 = VpcManifest::new("VPC-2").exposing(expose241);
    let manifest42 = VpcManifest::new("VPC-4").exposing(expose421);

    // VPC3 <-> VPC4
    let manifest34 = VpcManifest::new("VPC-3").exposing(expose341);
    let manifest43 = VpcManifest::new("VPC-4").exposing(expose431);

    let peering12 = VpcPeering::with_default_group("VPC-1--VPC-2", manifest12, manifest21);
    let peering31 = VpcPeering::with_default_group("VPC-3--VPC-1", manifest31, manifest13);
    let peering14 = VpcPeering::with_default_group("VPC-1--VPC-4", manifest14, manifest41);
    let peering24 = VpcPeering::with_default_group("VPC-2--VPC-4", manifest24, manifest42);
    let peering34 = VpcPeering::with_default_group("VPC-3--VPC-4", manifest34, manifest43);

    let mut peering_table = VpcPeeringTable::new();
    peering_table.add(peering12).expect("Failed to add peering");
    peering_table.add(peering31).expect("Failed to add peering");
    peering_table.add(peering14).expect("Failed to add peering");
    peering_table.add(peering24).expect("Failed to add peering");
    peering_table.add(peering34).expect("Failed to add peering");

    Overlay::new(vpc_table, peering_table)
}

fn build_overlay_2vpcs() -> Overlay {
    let mut vpc_table = VpcTable::new();
    let _ = vpc_table.add(Vpc::new("VPC-1", "AAAAA", 100).expect("Failed to add VPC"));
    let _ = vpc_table.add(Vpc::new("VPC-2", "BBBBB", 200).expect("Failed to add VPC"));

    let expose121 = VpcExpose::empty()
        .make_stateful_nat(None)
        .unwrap()
        .ip("1.1.0.0/16".into())
        .as_range("2.2.0.0/16".into())
        .unwrap();
    let expose211 = VpcExpose::empty().ip("3.3.3.0/24".into());

    let manifest12 = VpcManifest::new("VPC-1").exposing(expose121);
    let manifest21 = VpcManifest::new("VPC-2").exposing(expose211);
    let peering12 = VpcPeering::with_default_group("VPC-1--VPC-2", manifest12, manifest21);

    let mut peering_table = VpcPeeringTable::new();
    peering_table.add(peering12).expect("Failed to add peering");

    Overlay::new(vpc_table, peering_table)
}

// identical to build_overlay_2vpcs() but masquerading with 4.4.0.0/16
fn build_overlay_2vpcs_modified() -> Overlay {
    let mut vpc_table = VpcTable::new();
    let _ = vpc_table.add(Vpc::new("VPC-1", "AAAAA", 100).expect("Failed to add VPC"));
    let _ = vpc_table.add(Vpc::new("VPC-2", "BBBBB", 200).expect("Failed to add VPC"));

    let expose121 = VpcExpose::empty()
        .make_stateful_nat(None)
        .unwrap()
        .ip("1.1.0.0/16".into())
        .as_range("4.4.0.0/16".into())
        .unwrap();
    let expose211 = VpcExpose::empty().ip("3.3.3.0/24".into());

    let manifest12 = VpcManifest::new("VPC-1").exposing(expose121);
    let manifest21 = VpcManifest::new("VPC-2").exposing(expose211);
    let peering12 = VpcPeering::with_default_group("VPC-1--VPC-2", manifest12, manifest21);

    let mut peering_table = VpcPeeringTable::new();
    peering_table.add(peering12).expect("Failed to add peering");

    Overlay::new(vpc_table, peering_table)
}

fn check_packet(
    nat: &mut StatefulNat,
    src_vni: Vni,
    dst_vni: Vni,
    src_ip: &str,
    dst_ip: &str,
    sport: u16,
    dport: u16,
) -> (Ipv4Addr, Ipv4Addr, u16, u16, Option<DoneReason>) {
    let mut packet: Packet<TestBuffer> = build_test_udp_ipv4_frame(
        Mac([0x2, 0, 0, 0, 0, 1]),
        Mac([0x2, 0, 0, 0, 0, 2]),
        src_ip,
        dst_ip,
        sport,
        dport,
    );
    packet.meta_mut().set_overlay(true);
    packet.meta_mut().set_stateful_nat(true);
    packet.meta_mut().src_vpcd = Some(VpcDiscriminant::VNI(src_vni));
    packet.meta_mut().dst_vpcd = Some(VpcDiscriminant::VNI(dst_vni));

    flow_lookup(nat.sessions(), &mut packet);

    let packets_out: Vec<_> = nat.process(vec![packet].into_iter()).collect();
    let hdr_out = packets_out[0].try_ipv4().unwrap();
    let udp_out = packets_out[0].try_udp().unwrap();
    let done_reason = packets_out[0].get_done();

    (
        hdr_out.source().inner(),
        hdr_out.destination(),
        udp_out.source().into(),
        udp_out.destination().into(),
        done_reason,
    )
}

fn flow_lookup<Buf: PacketBufferMut>(flow_table: &FlowTable, packet: &mut Packet<Buf>) {
    let flow_key = FlowKey::try_from(Uni(&*packet)).unwrap();
    if let Some(flow_info) = flow_table.lookup(&flow_key) {
        packet.meta_mut().flow_info = Some(flow_info);
    }
}

#[tokio::test]
#[traced_test]
#[allow(clippy::too_many_lines)]
async fn test_full_config() {
    let mut config = build_gwconfig_from_overlay(build_overlay_4vpcs());
    config.validate().unwrap();

    let flow_table = FlowTable::new(16);

    // Check that we can validate the allocator
    let (mut nat, mut allocator) = StatefulNat::new_with_defaults();
    let nat_config = StatefulNatConfig::new(&config.external.overlay.vpc_table, 1);
    allocator.update_nat_allocator(nat_config, &flow_table);

    // No NAT
    let (orig_src, orig_dst) = ("8.8.8.8", "9.9.9.9");
    let (output_src, output_dst, output_src_port, output_dst_port, done_reason) =
        check_packet(&mut nat, vni(100), vni(200), orig_src, orig_dst, 9998, 443);
    assert_eq!(output_src, addr_v4(orig_src));
    assert_eq!(output_dst, addr_v4(orig_dst));
    assert_eq!(output_src_port, 9998);
    assert_eq!(output_dst_port, 443);
    assert_eq!(done_reason, Some(DoneReason::Filtered));

    // NAT: expose121 <-> expose211
    let (orig_src, orig_dst) = ("1.1.2.3", "10.201.201.18");
    let target_src = "10.12.0.0";
    let (output_src, output_dst, output_src_port, output_dst_port, done_reason) =
        check_packet(&mut nat, vni(100), vni(200), orig_src, orig_dst, 9998, 443);
    assert_eq!(done_reason, None);

    assert_eq!(output_src, addr_v4(target_src));
    assert_eq!(output_dst, addr_v4(orig_dst));
    // Reverse path
    let (
        return_output_src,
        return_output_dst,
        return_output_src_port,
        return_output_dst_port,
        done_reason,
    ) = check_packet(
        &mut nat,
        vni(200),
        vni(100),
        orig_dst,
        target_src,
        output_dst_port,
        output_src_port,
    );
    assert_eq!(return_output_src, addr_v4(orig_dst));
    assert_eq!(return_output_dst, addr_v4(orig_src));
    assert_eq!(return_output_src_port, 443);
    assert_eq!(return_output_dst_port, 9998);
    assert_eq!(done_reason, None);

    // Get corresponding session table entries and check idle timeout
    let Some((_, idle_timeout)) = nat.get_session(
        Some(vpcd(100)),
        IpAddr::from_str(orig_src).unwrap(),
        IpAddr::from_str(orig_dst).unwrap(),
        IpProtoKey::Udp(UdpProtoKey {
            src_port: UdpPort::new_checked(9998).unwrap(),
            dst_port: UdpPort::new_checked(443).unwrap(),
        }),
    ) else {
        unreachable!()
    };
    assert_eq!(idle_timeout, ONE_MINUTE);
    // Reverse path
    let Some((_, idle_timeout)) = nat.get_session(
        Some(vpcd(200)),
        IpAddr::from_str(orig_dst).unwrap(),
        IpAddr::from_str(target_src).unwrap(),
        IpProtoKey::Udp(UdpProtoKey {
            src_port: UdpPort::new_checked(output_dst_port).unwrap(),
            dst_port: UdpPort::new_checked(output_src_port).unwrap(),
        }),
    ) else {
        unreachable!()
    };
    assert_eq!(idle_timeout, ONE_MINUTE);

    // Update config and allocator
    let mut new_config = build_gwconfig_from_overlay(build_overlay_2vpcs());
    new_config.validate().unwrap();
    let nat_config = StatefulNatConfig::new(&new_config.external.overlay.vpc_table, 2);
    allocator.update_nat_allocator(nat_config, &flow_table);

    // Check existing connection
    // TODO: We should drop this connection after updating the allocator in the future, as a
    // result these steps should fail
    let (orig_src, orig_dst) = ("1.1.2.3", "10.201.201.18");
    let target_src = "10.12.0.0";
    let (output_src, output_dst, output_src_port, output_dst_port, done_reason) =
        check_packet(&mut nat, vni(100), vni(200), orig_src, orig_dst, 9998, 443);
    assert_eq!(output_src, addr_v4(target_src));
    assert_eq!(output_dst, addr_v4(orig_dst));
    assert_eq!(done_reason, None);
    // Reverse path
    let (
        return_output_src,
        return_output_dst,
        return_output_src_port,
        return_output_dst_port,
        done_reason,
    ) = check_packet(
        &mut nat,
        vni(200),
        vni(100),
        orig_dst,
        target_src,
        output_dst_port,
        output_src_port,
    );
    assert_eq!(return_output_src, addr_v4(orig_dst));
    assert_eq!(return_output_dst, addr_v4(orig_src));
    assert_eq!(return_output_src_port, 443);
    assert_eq!(return_output_dst_port, 9998);
    assert_eq!(done_reason, None);

    // Check new valid connection
    let (orig_src, orig_dst) = ("1.1.2.3", "3.3.3.3");
    let target_src = "2.2.0.0";
    let (output_src, output_dst, output_src_port, output_dst_port, done_reason) =
        check_packet(&mut nat, vni(100), vni(200), orig_src, orig_dst, 9998, 80);
    assert_eq!(output_src, addr_v4(target_src));
    assert_eq!(output_dst, addr_v4(orig_dst));
    assert_eq!(done_reason, None);
    // Reverse path
    let (
        return_output_src,
        return_output_dst,
        return_output_src_port,
        return_output_dst_port,
        done_reason,
    ) = check_packet(
        &mut nat,
        vni(200),
        vni(100),
        orig_dst,
        target_src,
        output_dst_port,
        output_src_port,
    );
    assert_eq!(return_output_src, addr_v4(orig_dst));
    assert_eq!(return_output_dst, addr_v4(orig_src));
    assert_eq!(return_output_src_port, 80);
    assert_eq!(return_output_dst_port, 9998);
    assert_eq!(done_reason, None);
}

fn build_overlay_2vpcs_no_nat() -> Overlay {
    let mut vpc_table = VpcTable::new();
    let _ = vpc_table.add(Vpc::new("VPC-1", "AAAAA", 100).expect("Failed to add VPC"));
    let _ = vpc_table.add(Vpc::new("VPC-2", "BBBBB", 200).expect("Failed to add VPC"));

    let expose121 = VpcExpose::empty().ip("1.1.0.0/16".into());
    let expose211 = VpcExpose::empty().ip("2.2.0.0/16".into());

    let manifest12 = VpcManifest::new("VPC-1").exposing(expose121);
    let manifest21 = VpcManifest::new("VPC-2").exposing(expose211);
    let peering12 = VpcPeering::with_default_group("VPC-1--VPC-2", manifest12, manifest21);

    let mut peering_table = VpcPeeringTable::new();
    peering_table.add(peering12).expect("Failed to add peering");

    Overlay::new(vpc_table, peering_table)
}

#[test]
#[traced_test]
fn test_full_config_no_nat() {
    let mut config = build_gwconfig_from_overlay(build_overlay_2vpcs_no_nat());
    config.validate().unwrap();

    // Check that we can validate the allocator
    let (_, mut allocator) = StatefulNat::new_with_defaults();
    let nat_config = StatefulNatConfig::new(&config.external.overlay.vpc_table, 1);
    allocator.update_nat_allocator(nat_config, &FlowTable::new(16));
}

fn check_packet_icmp_echo(
    nat: &mut StatefulNat,
    src_vni: Vni,
    dst_vni: Vni,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    direction: IcmpEchoDirection,
    identifier: u16,
) -> (Ipv4Addr, Ipv4Addr, u16, Option<DoneReason>) {
    let mut packet: Packet<TestBuffer> =
        build_test_icmp4_echo(src_ip, dst_ip, identifier, direction).unwrap();
    packet.meta_mut().set_overlay(true);
    packet.meta_mut().set_stateful_nat(true);
    packet.meta_mut().src_vpcd = Some(VpcDiscriminant::VNI(src_vni));
    packet.meta_mut().dst_vpcd = Some(VpcDiscriminant::VNI(dst_vni));

    flow_lookup(nat.sessions(), &mut packet);

    let packets_out: Vec<_> = nat.process(vec![packet].into_iter()).collect();
    let hdr_out = packets_out[0].try_ipv4().unwrap();
    let icmp_out = packets_out[0].try_icmp4().unwrap();
    let done_reason = packets_out[0].get_done();

    (
        hdr_out.source().inner(),
        hdr_out.destination(),
        icmp_out.identifier().unwrap(),
        done_reason,
    )
}

fn check_packet_icmp_echo_new(
    pipeline: &mut DynPipeline<TestBuffer>,
    src_vni: Vni,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    direction: IcmpEchoDirection,
    identifier: u16,
) -> (Ipv4Addr, Ipv4Addr, u16, Option<DoneReason>) {
    let mut packet: Packet<TestBuffer> =
        build_test_icmp4_echo(src_ip, dst_ip, identifier, direction).unwrap();
    packet.meta_mut().set_overlay(true);
    packet.meta_mut().set_stateful_nat(true);
    packet.meta_mut().src_vpcd = Some(VpcDiscriminant::VNI(src_vni));

    let packets_out: Vec<_> = pipeline.process(vec![packet].into_iter()).collect();
    let hdr_out = packets_out[0].try_ipv4().unwrap();
    let icmp_out = packets_out[0].try_icmp4().unwrap();
    let done_reason = packets_out[0].get_done();

    (
        hdr_out.source().inner(),
        hdr_out.destination(),
        icmp_out.identifier().unwrap(),
        done_reason,
    )
}

#[tokio::test]
#[traced_test]
async fn test_icmp_echo_nat() {
    let mut config = build_gwconfig_from_overlay(build_overlay_2vpcs());
    config.validate().unwrap();

    // Check that we can validate the allocator
    let (mut nat, mut allocator) = StatefulNat::new_with_defaults();
    let nat_config = StatefulNatConfig::new(&config.external.overlay.vpc_table, 1);
    allocator.update_nat_allocator(nat_config, &FlowTable::new(16));

    // No NAT
    let (orig_src, orig_dst, orig_identifier) = (addr_v4("8.8.8.8"), addr_v4("9.9.9.9"), 1337);
    let (output_src, output_dst, output_identifier, done_reason) = check_packet_icmp_echo(
        &mut nat,
        vni(100),
        vni(200),
        orig_src,
        orig_dst,
        IcmpEchoDirection::Request,
        orig_identifier,
    );
    assert_eq!(output_src, orig_src);
    assert_eq!(output_dst, orig_dst);
    assert_eq!(output_identifier, orig_identifier);
    assert_eq!(done_reason, Some(DoneReason::Filtered));

    // NAT: expose121 <-> expose211
    let (orig_src, orig_dst, orig_identifier) = (addr_v4("1.1.2.3"), addr_v4("3.3.3.3"), 1337);
    let target_src = addr_v4("2.2.0.0");
    let (output_src, output_dst, output_identifier_1, done_reason) = check_packet_icmp_echo(
        &mut nat,
        vni(100),
        vni(200),
        orig_src,
        orig_dst,
        IcmpEchoDirection::Request,
        orig_identifier,
    );
    assert_eq!(output_src, target_src);
    assert_eq!(output_dst, orig_dst);
    assert!(output_identifier_1.is_multiple_of(256)); // First port of a 256-port "port block" from allocator
    assert_eq!(done_reason, None);

    // Reverse path
    let (return_output_src, return_output_dst, return_output_identifier, done_reason) =
        check_packet_icmp_echo(
            &mut nat,
            vni(200),
            vni(100),
            orig_dst,
            target_src,
            IcmpEchoDirection::Reply,
            output_identifier_1,
        );
    assert_eq!(return_output_src, orig_dst);
    assert_eq!(return_output_dst, orig_src);
    assert_eq!(return_output_identifier, orig_identifier);
    assert_eq!(done_reason, None);

    // Second request with same identifier: no reallocation
    let (orig_src, orig_dst) = (addr_v4("1.1.2.3"), addr_v4("3.3.3.3"));
    let target_src = addr_v4("2.2.0.0");
    let (output_src, output_dst, output_identifier_2, done_reason) = check_packet_icmp_echo(
        &mut nat,
        vni(100),
        vni(200),
        orig_src,
        orig_dst,
        IcmpEchoDirection::Request,
        orig_identifier,
    );
    assert_eq!(output_src, target_src);
    assert_eq!(output_dst, orig_dst);
    assert_eq!(output_identifier_2, output_identifier_1); // Same identifier as before
    assert_eq!(done_reason, None);

    // NAT: expose121 <-> expose211 again, but with identifier 0 (corner case)
    let (orig_src, orig_dst, orig_identifier) = (addr_v4("1.1.2.3"), addr_v4("3.3.3.3"), 0);
    let target_src = addr_v4("2.2.0.0");
    let (output_src, output_dst, output_identifier_3, done_reason) = check_packet_icmp_echo(
        &mut nat,
        vni(100),
        vni(200),
        orig_src,
        orig_dst,
        IcmpEchoDirection::Request,
        orig_identifier,
    );

    assert_eq!(output_src, target_src);
    assert_eq!(output_dst, orig_dst);
    assert_eq!(output_identifier_3, output_identifier_1 + 1); // Second port of the same 256-port "port block" from allocator
    assert_eq!(done_reason, None);
}

#[allow(clippy::too_many_arguments)]
fn check_packet_icmp_error(
    pipeline: &mut DynPipeline<TestBuffer>,
    src_vni: Vni,
    dst_vni: Vni,
    outer_src_ip: Ipv4Addr,
    outer_dst_ip: Ipv4Addr,
    inner_src_ip: Ipv4Addr,
    inner_dst_ip: Ipv4Addr,
    next_header: NextHeader,
    inner_param_1: u16,
    inner_param_2: u16,
) -> (
    Ipv4Addr,
    Ipv4Addr,
    Ipv4Addr,
    Ipv4Addr,
    u16,
    u16,
    Option<DoneReason>,
) {
    let mut packet: Packet<TestBuffer> = build_test_icmp4_destination_unreachable_packet(
        outer_src_ip,
        outer_dst_ip,
        inner_src_ip,
        inner_dst_ip,
        next_header,
        inner_param_1,
        inner_param_2,
    )
    .unwrap();
    packet.meta_mut().set_overlay(true);
    packet.meta_mut().set_stateful_nat(false); // set to false since ICMP error handler will take care
    packet.meta_mut().src_vpcd = Some(VpcDiscriminant::VNI(src_vni));
    packet.meta_mut().dst_vpcd = Some(VpcDiscriminant::VNI(dst_vni));
    packet.meta_mut().dst_vpcd.take(); // remove to force processing by stateful

    let packets_out: Vec<_> = pipeline.process(std::iter::once(packet)).collect();

    let hdr_out = packets_out[0].try_ipv4().unwrap();
    let inner_ip_out = packets_out[0].try_inner_ipv4().unwrap();
    let inner_transport_out = packets_out[0].try_embedded_transport().unwrap();
    let (out_inner_param_1, out_inner_param_2) = match inner_transport_out {
        EmbeddedTransport::Tcp(TruncatedTcp::FullHeader(tcp)) => {
            (tcp.source().into(), tcp.destination().into())
        }
        EmbeddedTransport::Udp(TruncatedUdp::FullHeader(udp)) => {
            (udp.source().into(), udp.destination().into())
        }
        EmbeddedTransport::Icmp4(TruncatedIcmp4::FullHeader(icmp)) => {
            let Icmp4Type::EchoRequest(echo) = icmp.icmp_type() else {
                unreachable!();
            };
            (echo.id, echo.seq)
        }
        _ => unreachable!(),
    };
    let done_reason = packets_out[0].get_done();

    (
        hdr_out.source().inner(),
        hdr_out.destination(),
        inner_ip_out.source().inner(),
        inner_ip_out.destination(),
        out_inner_param_1,
        out_inner_param_2,
        done_reason,
    )
}

#[tokio::test]
#[traced_test]
async fn test_icmp_error_nat() {
    // build setup: 2 vpcs with masquerading, vni 100 -> vni 200
    let (flow_table, mut pipeline, _allocw) = test_setup(1, build_overlay_2vpcs());

    // ICMP Error msg: expose211 -> expose121, no previous session for inner packet
    test_case("Processing icmp error with no prior state");
    let (
        router_src,
        orig_outer_dst,
        orig_inner_src,
        orig_inner_dst,
        orig_echo_identifier,
        orig_echo_seq_number,
    ) = (
        // Host 1.1.2.3 in VPC1 sent imaginary ICMP Echo packet to 3.3.3.3 in VPC2,
        // which imaginarily got translated as 2.2.0.0 -> 3.3.3.3.
        // Router 1.2.2.18 from VPC2 returns Destination Unreachable to 2.2.0.0 with initial
        // datagram embedded in it
        addr_v4("1.2.2.18"),
        addr_v4("2.2.0.0"),
        addr_v4("2.2.0.0"),
        addr_v4("3.3.3.3"),
        1337,
        0,
    );
    let (
        output_outer_src,
        output_outer_dst,
        output_inner_src,
        output_inner_dst,
        output_inner_identifier,
        output_inner_seq_number,
        done_reason,
    ) = check_packet_icmp_error(
        &mut pipeline,
        vni(200),
        vni(100),
        router_src,
        orig_outer_dst,
        orig_inner_src,
        orig_inner_dst,
        NextHeader::ICMP,
        orig_echo_identifier,
        orig_echo_seq_number,
    );
    assert_eq!(output_outer_src, router_src);
    assert_eq!(output_outer_dst, orig_outer_dst);
    assert_eq!(output_inner_src, orig_inner_src);
    assert_eq!(output_inner_dst, orig_inner_dst);
    assert_eq!(output_inner_identifier, orig_echo_identifier);
    assert_eq!(output_inner_seq_number, orig_echo_seq_number);
    assert_eq!(done_reason, None);

    // ICMP Echo Request expose121 -> expose211
    test_case("Processing ICMP echo request");
    let (orig_echo_src, orig_echo_dst, target_echo_src, target_echo_dst) = (
        addr_v4("1.1.2.3"),
        addr_v4("3.3.3.3"),
        addr_v4("2.2.0.0"),
        addr_v4("3.3.3.3"),
    );
    let (output_echo_src, output_echo_dst, output_echo_identifier, done_reason) =
        check_packet_icmp_echo_new(
            &mut pipeline,
            vni(100),
            orig_echo_src,
            orig_echo_dst,
            IcmpEchoDirection::Request,
            orig_echo_identifier,
        );
    assert_eq!(output_echo_src, target_echo_src);
    assert_eq!(output_echo_dst, target_echo_dst);
    assert!(output_echo_identifier.is_multiple_of(256)); // First port of a 256-port "port block" from allocator
    assert_eq!(done_reason, None);

    debug!("Flow table contents:\n{flow_table}");

    // ICMP Error message: expose211 -> expose121, after establishing session for inner packet
    //
    // Same IPs as before, this time we've actually sent the ICMP Echo Request from 1.1.2.3 to
    // 3.3.3.3 and we have a session for the inner packet
    //
    // Output packet received by Echo Request emitter should be:
    // - Outer source IP: 3.3.3.3 (original destination for Echo Request)
    // - Outer destination IP: 1.1.2.3 (original emitter of Echo Request)
    // - Inner source IP: 1.1.2.3 (original emitter of Echo Request)
    // - Inner destination IP: 3.3.3.3 (original destination for Echo Request)
    // - Inner identifier: original identifier from Echo Request
    // - Inner sequence number: always unchanged
    test_case("Processing icmp error after establishing state");
    let (
        output_outer_src,
        output_outer_dst,
        output_inner_src,
        output_inner_dst,
        output_inner_identifier,
        output_inner_seq_number,
        done_reason,
    ) = check_packet_icmp_error(
        &mut pipeline,
        vni(200),
        vni(100),
        router_src,
        target_echo_src,
        target_echo_src,
        target_echo_dst,
        NextHeader::ICMP,
        output_echo_identifier,
        orig_echo_seq_number,
    );

    // Outer source remains unchanged, see comments in deal_with_icmp_error_msg()
    assert_eq!(output_outer_src, router_src);
    assert_eq!(output_outer_dst, orig_echo_src);
    assert_eq!(output_inner_src, orig_echo_src);
    assert_eq!(output_inner_dst, orig_echo_dst);
    assert_eq!(output_inner_identifier, orig_echo_identifier);
    assert_eq!(output_inner_seq_number, orig_echo_seq_number);
    assert_eq!(done_reason, None);
}

fn build_overlay_2vpcs_with_default() -> Overlay {
    let mut vpc_table = VpcTable::new();
    let _ = vpc_table.add(Vpc::new("VPC-1", "AAAAA", 100).expect("Failed to add VPC"));
    let _ = vpc_table.add(Vpc::new("VPC-2", "BBBBB", 200).expect("Failed to add VPC"));

    let expose121 = VpcExpose::empty()
        .make_stateful_nat(None)
        .unwrap()
        .ip("1.1.0.0/16".into())
        .as_range("2.2.0.0/16".into())
        .unwrap();
    let expose211 = VpcExpose::empty().ip("3.3.3.0/24".into());
    let expose212 = VpcExpose::empty().set_default();

    let manifest12 = VpcManifest::new("VPC-1").exposing(expose121);
    let manifest21 = VpcManifest::new("VPC-2")
        .exposing(expose211)
        .exposing(expose212);
    let peering12 = VpcPeering::with_default_group("VPC-1--VPC-2", manifest12, manifest21);

    let mut peering_table = VpcPeeringTable::new();
    peering_table.add(peering12).expect("Failed to add peering");

    Overlay::new(vpc_table, peering_table)
}

#[tokio::test]
async fn test_default_expose() {
    let mut config = build_gwconfig_from_overlay(build_overlay_2vpcs_with_default());
    config.validate().unwrap();

    // Check that we can validate the allocator
    let (mut nat, mut allocator) = StatefulNat::new_with_defaults();
    let nat_config = StatefulNatConfig::new(&config.external.overlay.vpc_table, 1);
    allocator.update_nat_allocator(nat_config, &FlowTable::new(16));

    // Using the expose with a prefix
    let (orig_src, orig_dst, orig_src_port, orig_dst_port) = ("1.1.0.1", "3.3.3.3", 9999, 443);
    let target_src = "2.2.0.0";
    let (output_src, output_dst, output_src_port, output_dst_port, done_reason) = check_packet(
        &mut nat,
        vni(100),
        vni(200),
        orig_src,
        orig_dst,
        orig_src_port,
        orig_dst_port,
    );
    assert_eq!(done_reason, None);
    assert_eq!(output_src, addr_v4(target_src));
    assert_eq!(output_dst, addr_v4(orig_dst));

    // Reverse path
    let (
        return_output_src,
        return_output_dst,
        return_output_src_port,
        return_output_dst_port,
        done_reason,
    ) = check_packet(
        &mut nat,
        vni(200),
        vni(100),
        orig_dst,
        target_src,
        output_dst_port,
        output_src_port,
    );
    assert_eq!(done_reason, None);
    assert_eq!(return_output_src, addr_v4(orig_dst));
    assert_eq!(return_output_dst, addr_v4(orig_src));
    assert_eq!(return_output_src_port, orig_dst_port);
    assert_eq!(return_output_dst_port, orig_src_port);

    // Using the default expose
    let (orig_src, orig_dst, orig_src_port, orig_dst_port) = ("1.1.0.1", "10.11.12.13", 9999, 443);
    let target_src = "2.2.0.0";
    let (output_src, output_dst, output_src_port, output_dst_port, done_reason) = check_packet(
        &mut nat,
        vni(100),
        vni(200),
        orig_src,
        orig_dst,
        orig_src_port,
        orig_dst_port,
    );
    assert_eq!(done_reason, None);
    assert_eq!(output_src, addr_v4(target_src));
    assert_eq!(output_dst, addr_v4(orig_dst));

    // Reverse path
    let (
        return_output_src,
        return_output_dst,
        return_output_src_port,
        return_output_dst_port,
        done_reason,
    ) = check_packet(
        &mut nat,
        vni(200),
        vni(100),
        orig_dst,
        target_src,
        output_dst_port,
        output_src_port,
    );
    assert_eq!(done_reason, None);
    assert_eq!(return_output_src, addr_v4(orig_dst));
    assert_eq!(return_output_dst, addr_v4(orig_src));
    assert_eq!(return_output_src_port, orig_dst_port);
    assert_eq!(return_output_dst_port, orig_src_port);
}

fn build_overlay_3vpcs_unidirectional_nat_overlapping_addr() -> Overlay {
    let mut vpc_table = VpcTable::new();
    let _ = vpc_table.add(Vpc::new("VPC-1", "AAAAA", 100).unwrap());
    let _ = vpc_table.add(Vpc::new("VPC-2", "BBBBB", 200).unwrap());
    let _ = vpc_table.add(Vpc::new("VPC-3", "CCCCC", 300).unwrap());

    // VPC-1 <-> VPC-2 <-> VPC-3; No connection between VPC-1 and VPC-3

    // VPC-1 (NAT) <-> VPC-2 (no NAT)
    let expose12 = VpcExpose::empty()
        .make_stateful_nat(None)
        .unwrap()
        .ip("1.0.0.0/24".into())
        .as_range("2.0.0.0/24".into())
        .unwrap();
    let expose21 = VpcExpose::empty().ip("5.0.0.0/24".into());

    let manifest12 = VpcManifest::new("VPC-1").exposing(expose12);
    let manifest21 = VpcManifest::new("VPC-2").exposing(expose21);
    let peering12 = VpcPeering::with_default_group("VPC-1--VPC-2", manifest12, manifest21);

    // VPC-2 (no NAT) <-> VPC-3 (NAT)
    let expose32 = VpcExpose::empty()
        .make_stateful_nat(None)
        .unwrap()
        .ip("1.0.0.0/24".into())
        .as_range("2.0.0.0/24".into())
        .unwrap();
    let expose23 = VpcExpose::empty().ip("5.0.0.0/24".into());

    let manifest23 = VpcManifest::new("VPC-2").exposing(expose23);
    let manifest32 = VpcManifest::new("VPC-3").exposing(expose32);
    let peering23 = VpcPeering::with_default_group("VPC-2--VPC-3", manifest23, manifest32);

    let mut peering_table = VpcPeeringTable::new();
    peering_table.add(peering12).unwrap();
    peering_table.add(peering23).unwrap();

    Overlay::new(vpc_table, peering_table)
}

#[allow(clippy::too_many_arguments)]
fn check_packet_with_vpcd_lookup(
    nat: &mut StatefulNat,
    vpcdlookup: &mut FlowFilter,
    flow_lookup_stage: Option<&mut FlowLookup>,
    src_vni: Vni,
    src_ip: &str,
    dst_ip: &str,
    sport: u16,
    dport: u16,
) -> (
    Option<VpcDiscriminant>,
    Ipv4Addr,
    Ipv4Addr,
    u16,
    u16,
    Option<DoneReason>,
) {
    let mut packet: Packet<TestBuffer> = build_test_udp_ipv4_frame(
        Mac([0x2, 0, 0, 0, 0, 1]),
        Mac([0x2, 0, 0, 0, 0, 2]),
        src_ip,
        dst_ip,
        sport,
        dport,
    );
    packet.meta_mut().set_overlay(true);
    packet.meta_mut().src_vpcd = Some(VpcDiscriminant::VNI(src_vni));

    // Flow table lookup
    let packets_from_flow_lookup: Vec<_> = if let Some(stage) = flow_lookup_stage {
        // Use dedicated stage, which attaches the destination VPC discriminant to the packet,
        // if any is found from the flow table.
        stage
            .process::<std::vec::IntoIter<Packet<TestBuffer>>>(vec![packet].into_iter())
            .collect()
    } else {
        // Simple flow lookup, without attaching the destination VPC discriminant to the packet.
        flow_lookup(nat.sessions(), &mut packet.clone());
        vec![packet]
    };

    // VPC discriminant lookup
    let packets_from_vpcd_lookup: Vec<_> = vpcdlookup
        .process::<std::vec::IntoIter<Packet<TestBuffer>>>(packets_from_flow_lookup.into_iter())
        .collect();

    // NAT
    let packets_out: Vec<_> = nat
        .process::<std::vec::IntoIter<Packet<TestBuffer>>>(packets_from_vpcd_lookup.into_iter())
        .collect();

    let dst_vpcd = packets_out[0].meta().dst_vpcd;
    let hdr_out = packets_out[0].try_ipv4().unwrap();
    let udp_out = packets_out[0].try_udp().unwrap();
    let done_reason = packets_out[0].get_done();

    (
        dst_vpcd,
        hdr_out.source().inner(),
        hdr_out.destination(),
        udp_out.source().into(),
        udp_out.destination().into(),
        done_reason,
    )
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_full_config_unidirectional_nat_overlapping_destination() {
    let tctl = get_trace_ctl();
    let _ = tctl.setup_from_string("vpc-routing=debug,flow-lookup=debug,stateful-nat=debug");

    let mut config =
        build_gwconfig_from_overlay(build_overlay_3vpcs_unidirectional_nat_overlapping_addr());
    config.validate().unwrap();

    // Build VPC discriminant lookup stage
    let vpcd_tables = FlowFilterTable::build_from_overlay(&config.external.overlay).unwrap();
    let mut vpcdtablesw = FlowFilterTableWriter::new();
    vpcdtablesw.update_flow_filter_table(vpcd_tables);
    let mut vpcdlookup = FlowFilter::new("vpcd-lookup", vpcdtablesw.get_reader());

    /////////////////////////////////////////////////////////////////
    // First NAT stage: We do not search for the destination VPC discriminant in the flow table.
    // We expect return packets to fail to find a destination VPC ID due to the conflicts
    // between the IPs exposed by VPC-2 for both VPC-1 and VPC-3, and to be dropped.

    // Build NAT stage
    let (mut nat, mut allocator) = StatefulNat::new_with_defaults();
    let nat_config = StatefulNatConfig::new(&config.external.overlay.vpc_table, 1);

    // Check that we can validate the allocator
    allocator.update_nat_allocator(nat_config, &FlowTable::new(16));

    // NAT: expose12 <-> expose21
    let (orig_src, orig_dst, orig_src_port, orig_dst_port) = ("1.0.0.18", "5.0.0.5", 9998, 443);
    let target_src = "2.0.0.0";
    let (dst_vpcd, output_src, output_dst, output_src_port, output_dst_port, done_reason) =
        check_packet_with_vpcd_lookup(
            &mut nat,
            &mut vpcdlookup,
            // Simple lookup without attaching the destination VPC ID to the packet.
            None,
            vni(100),
            orig_src,
            orig_dst,
            orig_src_port,
            orig_dst_port,
        );
    assert_eq!(dst_vpcd, Some(VpcDiscriminant::VNI(vni(200))));
    assert_eq!(output_src, addr_v4(target_src));
    assert_eq!(output_dst, addr_v4(orig_dst));
    assert!(
        output_src_port.is_multiple_of(256) || output_src_port == 1,
        "{output_src_port}"
    ); // We never use port 0
    assert_eq!(output_dst_port, orig_dst_port);
    assert_eq!(done_reason, None);

    // Reverse path - 5.0.0.5 -> 2.0.0.0, destination is ambiguous (could be VPC-1 or VPC-3)
    let (
        return_vpcd,
        return_output_src,
        return_output_dst,
        return_output_src_port,
        return_output_dst_port,
        return_done_reason,
    ) = check_packet_with_vpcd_lookup(
        &mut nat,
        &mut vpcdlookup,
        // Simple lookup without attaching the destination VPC ID to the packet.
        None,
        vni(200),
        orig_dst,
        target_src,
        output_dst_port,
        output_src_port,
    );
    assert_eq!(return_vpcd, None);
    assert_eq!(return_output_src, addr_v4(orig_dst));
    assert_eq!(return_output_dst, addr_v4(target_src));
    assert_eq!(return_output_src_port, output_dst_port);
    assert_eq!(return_output_dst_port, output_src_port);
    assert_eq!(return_done_reason, Some(DoneReason::Filtered));

    /////////////////////////////////////////////////////////////////
    // Second NAT stage: We update the VPC discriminant lookup table.
    // Check that we can NAT and route the return packet.

    // Build flow table lookup stage
    let flow_table = Arc::new(FlowTable::default());
    let mut flow_lookup = FlowLookup::new("flow-lookup", flow_table.clone());

    // Build a new NAT stage
    let mut allocator = NatAllocatorWriter::new();
    let mut nat = StatefulNat::new("stateful-nat", flow_table.clone(), allocator.get_reader());
    let nat_config =
        StatefulNatConfig::new(&config.external.overlay.vpc_table, 2).set_randomize(false);

    // Check that we can validate the allocator
    //
    // When we build the allocator, turn off randomness to check whether we may get collisions
    // for port allocation
    allocator.update_nat_allocator(nat_config, &flow_table);

    // NAT: expose12 <-> expose21
    let (orig_src, orig_dst, orig_src_port, orig_dst_port) = ("1.0.0.18", "5.0.0.5", 9998, 443);
    let target_src = "2.0.0.0";
    let (dst_vpcd, output_src, output_dst, output_src_port, output_dst_port, done_reason) =
        check_packet_with_vpcd_lookup(
            &mut nat,
            &mut vpcdlookup,
            Some(&mut flow_lookup),
            vni(100),
            orig_src,
            orig_dst,
            orig_src_port,
            orig_dst_port,
        );
    assert_eq!(dst_vpcd, Some(VpcDiscriminant::VNI(vni(200))));
    assert_eq!(output_src, addr_v4(target_src));
    assert_eq!(output_dst, addr_v4(orig_dst));
    assert!(
        output_src_port.is_multiple_of(256) || output_src_port == 1,
        "{output_src_port}"
    );
    assert_eq!(output_dst_port, orig_dst_port);
    assert_eq!(done_reason, None);

    // Reverse path - 5.0.0.5 -> 2.0.0.0, destination is ambiguous (could be VPC-1 or VPC-3) but
    // the flow table lookup should resolve it to VPC-1
    let (
        return_vpcd,
        return_output_src,
        return_output_dst,
        return_output_src_port,
        return_output_dst_port,
        return_done_reason,
    ) = check_packet_with_vpcd_lookup(
        &mut nat,
        &mut vpcdlookup,
        Some(&mut flow_lookup),
        vni(200),
        orig_dst,
        target_src,
        output_dst_port,
        output_src_port,
    );
    println!("{flow_table}");
    assert_eq!(return_vpcd, Some(VpcDiscriminant::VNI(vni(100))));
    assert_eq!(return_output_src, addr_v4(orig_dst));
    assert_eq!(return_output_dst, addr_v4(orig_src));
    assert_eq!(return_output_src_port, orig_dst_port);
    assert_eq!(return_output_dst_port, orig_src_port);
    assert_eq!(return_done_reason, None);

    /////////////////////////////////////////////////////////////////
    // Still with the second NAT stage, send a packet from VPC-3 to VPC-2, using same IPs and
    // ports as for VPC-1 to VPC-2.
    // Check that updating the flow table for this new connection does not affect destination
    // VPC discriminant lookup from the flow table for the previous connection; in other words,
    // check that there's no session or allocation conflict.

    // Reverse path from previous connection: 5.0.0.5 -> 2.0.0.0, session is still valid
    let (
        return_vpcd,
        return_output_src,
        return_output_dst,
        return_output_src_port,
        return_output_dst_port,
        return_done_reason,
    ) = check_packet_with_vpcd_lookup(
        &mut nat,
        &mut vpcdlookup,
        Some(&mut flow_lookup),
        vni(200),
        orig_dst,
        target_src,
        output_dst_port,
        output_src_port,
    );
    println!("{flow_table}");
    assert_eq!(return_vpcd, Some(VpcDiscriminant::VNI(vni(100))));
    assert_eq!(return_output_src, addr_v4(orig_dst));
    assert_eq!(return_output_dst, addr_v4(orig_src));
    assert_eq!(return_output_src_port, orig_dst_port);
    assert_eq!(return_output_dst_port, orig_src_port);
    assert_eq!(return_done_reason, None);

    // NAT: expose32 <-> expose23 - Connection from VPC-3 to VPC-2, using the same IPs and ports
    // as for VPC-1 to VPC-2 connection
    let (orig_src_32, orig_dst_32, orig_src_port_32, orig_dst_port_32) =
        ("1.0.0.18", "5.0.0.5", 9998, 443);
    let target_src_32 = "2.0.0.0";
    let (
        dst_vpcd_32,
        output_src_32,
        output_dst_32,
        output_src_port_32,
        output_dst_port_32,
        done_reason_32,
    ) = check_packet_with_vpcd_lookup(
        &mut nat,
        &mut vpcdlookup,
        Some(&mut flow_lookup),
        vni(300), // from VPC-3
        orig_src_32,
        orig_dst_32,
        orig_src_port_32,
        orig_dst_port_32,
    );
    println!("{flow_table}");
    assert_eq!(dst_vpcd_32, Some(VpcDiscriminant::VNI(vni(200))));
    assert_eq!(output_src_32, addr_v4(target_src_32));
    assert_eq!(output_dst_32, addr_v4(orig_dst_32));
    assert!(
        output_src_port_32 % 256 == 1 || output_src_port_32 != 1 && output_src_port_32 == 2,
        "{output_src_port_32}"
    );
    assert_eq!(output_dst_port_32, orig_dst_port_32);
    assert_eq!(done_reason_32, None);

    // Back to 5.0.0.5 -> 2.0.0.0 from VPC-2 to VPC-1
    let (
        return_vpcd,
        return_output_src,
        return_output_dst,
        return_output_src_port,
        return_output_dst_port,
        return_done_reason,
    ) = check_packet_with_vpcd_lookup(
        &mut nat,
        &mut vpcdlookup,
        Some(&mut flow_lookup),
        vni(200), // from VPC-2 again
        orig_dst,
        target_src,
        output_dst_port,
        output_src_port,
    );

    println!("{flow_table}");
    assert_eq!(return_vpcd, Some(VpcDiscriminant::VNI(vni(100))));
    assert_eq!(return_output_src, addr_v4(orig_dst));
    assert_eq!(return_output_dst, addr_v4(orig_src));
    assert_eq!(return_output_src_port, orig_dst_port);
    assert_eq!(return_output_dst_port, orig_src_port);
    assert_eq!(return_done_reason, None);
}

fn build_overlay_2vpcs_unidirectional_nat_overlapping_exposes() -> Overlay {
    let mut vpc_table = VpcTable::new();
    let _ = vpc_table.add(Vpc::new("VPC-1", "AAAAA", 100).unwrap());
    let _ = vpc_table.add(Vpc::new("VPC-2", "BBBBB", 200).unwrap());

    // Peering 1
    let expose1_1 = VpcExpose::empty()
        .make_stateful_nat(None)
        .unwrap()
        .ip("1.0.0.0/24".into())
        .as_range("2.0.0.0/24".into())
        .unwrap();
    let expose1_2 = VpcExpose::empty().ip("5.0.0.0/24".into());

    let manifest1_1 = VpcManifest::new("VPC-1").exposing(expose1_1);
    let manifest1_2 = VpcManifest::new("VPC-2").exposing(expose1_2);
    let peering1 = VpcPeering::with_default_group("VPC-1--VPC-2--1", manifest1_1, manifest1_2);

    // Peering 2 - Overlap with Peering 1

    let expose2_1 = VpcExpose::empty()
        .make_stateful_nat(None)
        .unwrap()
        .ip("3.0.0.0/24".into())
        .as_range("2.0.0.0/24".into()) // Overlap
        .unwrap();
    let expose2_2 = VpcExpose::empty().ip("6.0.0.0/24".into());

    let manifest2_1 = VpcManifest::new("VPC-1").exposing(expose2_1);
    let manifest2_2 = VpcManifest::new("VPC-2").exposing(expose2_2);
    let peering2 = VpcPeering::with_default_group("VPC-1--VPC-2--2", manifest2_1, manifest2_2);

    // Peering table

    let mut peering_table = VpcPeeringTable::new();
    peering_table.add(peering1).unwrap();
    peering_table.add(peering2).unwrap();

    Overlay::new(vpc_table, peering_table)
}

#[tokio::test]
#[traced_test]
#[allow(clippy::too_many_lines)]
async fn test_full_config_unidirectional_nat_overlapping_exposes_for_single_peering() {
    let mut config =
        build_gwconfig_from_overlay(build_overlay_2vpcs_unidirectional_nat_overlapping_exposes());
    // Validation fails - We currently forbid multiple peerings between any pair of VPCs. We
    // could probably allow them for stateful NAT, but we still need the restriction for
    // stateless NAT. We can carry on with the test anyway.
    assert_eq!(
        config.validate(),
        Err(ConfigError::DuplicateVpcPeerings(
            "VPC-1--VPC-2--2".to_owned()
        ))
    );

    // Build VPC discriminant lookup stage
    let vpcd_tables = FlowFilterTable::build_from_overlay(&config.external.overlay).unwrap();
    let mut vpcdtablesw = FlowFilterTableWriter::new();
    vpcdtablesw.update_flow_filter_table(vpcd_tables);
    let mut vpcdlookup = FlowFilter::new("vpcd-lookup", vpcdtablesw.get_reader());

    // Build flow table lookup stage
    let flow_table = Arc::new(FlowTable::default());
    let mut flow_lookup = FlowLookup::new("flow-lookup", flow_table.clone());

    /////////////////////////////////////////////////////////////////
    // Build a NAT stage and send a packet through peering1.
    // Check that NAT occurs as expected.

    // Build a new NAT stage
    let mut allocator = NatAllocatorWriter::new();
    let mut nat = StatefulNat::new("stateful-nat", flow_table.clone(), allocator.get_reader());
    let nat_config = StatefulNatConfig::new(&config.external.overlay.vpc_table, 1);

    // Check that we can validate the allocator
    allocator.update_nat_allocator(nat_config, &FlowTable::new(16));

    // NAT: expose1_1 -> expose1_2
    let (orig_src, orig_dst, orig_src_port, orig_dst_port) = ("1.0.0.18", "5.0.0.5", 9998, 443);
    let target_src = "2.0.0.0";
    let (dst_vpcd, output_src, output_dst, output_src_port, output_dst_port, done_reason) =
        check_packet_with_vpcd_lookup(
            &mut nat,
            &mut vpcdlookup,
            Some(&mut flow_lookup),
            vni(100),
            orig_src,
            orig_dst,
            orig_src_port,
            orig_dst_port,
        );
    assert_eq!(dst_vpcd, Some(VpcDiscriminant::VNI(vni(200))));
    assert_eq!(output_src, addr_v4(target_src));
    assert_eq!(output_dst, addr_v4(orig_dst));
    assert!(
        output_src_port.is_multiple_of(256) || output_src_port == 1,
        "{output_src_port}"
    );
    assert_eq!(output_dst_port, orig_dst_port);
    assert_eq!(done_reason, None);

    // Reverse path - 5.0.0.5 -> 2.0.0.0, destination is ambiguous (could be peering1 or peering2)
    let (
        return_vpcd,
        return_output_src,
        return_output_dst,
        return_output_src_port,
        return_output_dst_port,
        return_done_reason,
    ) = check_packet_with_vpcd_lookup(
        &mut nat,
        &mut vpcdlookup,
        Some(&mut flow_lookup),
        vni(200),
        orig_dst,
        target_src,
        output_dst_port,
        output_src_port,
    );
    assert_eq!(return_vpcd, Some(VpcDiscriminant::VNI(vni(100))));
    assert_eq!(return_output_src, addr_v4(orig_dst));
    assert_eq!(return_output_dst, addr_v4(orig_src));
    assert_eq!(return_output_src_port, orig_dst_port);
    assert_eq!(return_output_dst_port, orig_src_port);
    assert_eq!(return_done_reason, None);

    /////////////////////////////////////////////////////////////////
    // With the same NAT stage, send a packet through peering2.
    // Check that updating the flow table for this new connection does not affect
    // translation for the previous connection.

    // Reverse path from previous connection: 5.0.0.5 -> 2.0.0.0, session is still valid
    let (
        return_vpcd,
        return_output_src,
        return_output_dst,
        return_output_src_port,
        return_output_dst_port,
        return_done_reason,
    ) = check_packet_with_vpcd_lookup(
        &mut nat,
        &mut vpcdlookup,
        Some(&mut flow_lookup),
        vni(200),
        orig_dst,
        target_src,
        output_dst_port,
        output_src_port,
    );
    assert_eq!(return_vpcd, Some(VpcDiscriminant::VNI(vni(100))));
    assert_eq!(return_output_src, addr_v4(orig_dst));
    assert_eq!(return_output_dst, addr_v4(orig_src));
    assert_eq!(return_output_src_port, orig_dst_port);
    assert_eq!(return_output_dst_port, orig_src_port);
    assert_eq!(return_done_reason, None);

    // NAT: expose2_1 <-> expose2_2 - Connection through peering2
    let (orig_src_2, orig_dst_2, orig_src_port_2, orig_dst_port_2) =
        ("3.0.0.4", "6.0.0.12", 8887, 800);
    let target_src_2 = "2.0.0.0";
    let (
        dst_vpcd_2,
        output_src_2,
        output_dst_2,
        output_src_port_2,
        output_dst_port_2,
        done_reason_2,
    ) = check_packet_with_vpcd_lookup(
        &mut nat,
        &mut vpcdlookup,
        Some(&mut flow_lookup),
        vni(100),
        orig_src_2,
        orig_dst_2,
        orig_src_port_2,
        orig_dst_port_2,
    );
    assert_eq!(dst_vpcd_2, Some(VpcDiscriminant::VNI(vni(200))));
    assert_eq!(output_src_2, addr_v4(target_src_2));
    assert_eq!(output_dst_2, addr_v4(orig_dst_2));
    assert!(
        output_src_port_2.is_multiple_of(256) || output_src_port_2 == 1,
        "{output_src_port_2}"
    );
    assert_eq!(output_dst_port_2, orig_dst_port_2);
    assert_eq!(done_reason_2, None);

    // Back to 5.0.0.5 -> 2.0.0.0 through peering1
    let (
        return_vpcd,
        return_output_src,
        return_output_dst,
        return_output_src_port,
        return_output_dst_port,
        return_done_reason,
    ) = check_packet_with_vpcd_lookup(
        &mut nat,
        &mut vpcdlookup,
        Some(&mut flow_lookup),
        vni(200),
        orig_dst,
        target_src,
        output_dst_port,
        output_src_port,
    );
    assert_eq!(return_vpcd, Some(VpcDiscriminant::VNI(vni(100))));
    assert_eq!(return_output_src, addr_v4(orig_dst));
    assert_eq!(return_output_dst, addr_v4(orig_src));
    assert_eq!(return_output_src_port, orig_dst_port);
    assert_eq!(return_output_dst_port, orig_src_port);
    assert_eq!(return_done_reason, None);
}

fn tcp_packet_to_masquerade() -> Packet<TestBuffer> {
    let mut packet = build_test_tcp_ipv4_packet("1.1.0.1", "3.3.3.1", 4321, 80);
    packet.try_tcp_mut().unwrap().set_syn(false);
    packet.try_tcp_mut().unwrap().set_ack(false);
    packet.try_tcp_mut().unwrap().set_fin(false);
    packet.try_tcp_mut().unwrap().set_rst(false);

    packet.meta_mut().set_overlay(true);
    packet.meta_mut().src_vpcd = Some(vpcd(100));
    packet.meta_mut().set_stateful_nat(true);
    packet
}
fn flow_status(packet: &Packet<TestBuffer>) -> Option<FlowStatus> {
    packet
        .meta()
        .flow_info
        .as_ref()
        .map(|flow_info| flow_info.status())
}
fn flow_genid(packet: &Packet<TestBuffer>) -> Option<i64> {
    packet
        .meta()
        .flow_info
        .as_ref()
        .map(|flow_info| flow_info.genid())
}
fn nat_flow_status(packet: &Packet<TestBuffer>) -> Option<NatFlowStatus> {
    packet
        .meta()
        .flow_info
        .as_ref()?
        .locked
        .read()
        .unwrap()
        .nat_state
        .as_ref()
        .and_then(|s| s.extract_ref::<MasqueradeState>())
        .map(|state| state.status.load())
}

fn masquerade_state(packet: &Packet<TestBuffer>) -> Option<MasqueradeState> {
    packet
        .meta()
        .flow_info
        .as_ref()?
        .locked
        .read()
        .unwrap()
        .nat_state
        .as_ref()
        .and_then(|s| s.extract_ref::<MasqueradeState>())
        .cloned()
}

fn build_reply(packet: &Packet<TestBuffer>) -> Packet<TestBuffer> {
    let dst_vpcd = packet.meta().dst_vpcd;
    let src_mac = packet.eth_source().unwrap();
    let dst_mac = packet.eth_destination().unwrap();
    let src_ip = packet.ip_source().unwrap();
    let dst_ip = packet.ip_destination().unwrap();
    let src_port = packet.transport_src_port().unwrap();
    let dst_port = packet.transport_dst_port().unwrap();

    let mut reply = packet.clone();
    reply.meta_reset();
    reply.meta_mut().src_vpcd = dst_vpcd;
    reply.meta_mut().set_stateful_nat(true);
    reply.meta_mut().set_overlay(true);

    reply.set_eth_source(dst_mac).unwrap();
    reply.set_eth_destination(src_mac).unwrap();
    reply.set_ip_source(dst_ip.try_into().unwrap()).unwrap();
    reply.set_ip_destination(src_ip).unwrap();
    reply.set_source_port(dst_port).unwrap();
    reply.set_destination_port(src_port).unwrap();

    if reply.is_tcp() {
        let tcp = reply.try_tcp_mut().unwrap();
        if tcp.syn() && tcp.ack() {
            tcp.set_syn(false);
        }
        tcp.set_ack(true);
    }
    reply
}

fn process_packet(
    pipeline: &mut DynPipeline<TestBuffer>,
    packet: Packet<TestBuffer>,
) -> Packet<TestBuffer> {
    println!("INPUT:{packet}");
    let output: Vec<_> = pipeline.process(std::iter::once(packet)).collect();
    let output = output.first().unwrap();
    println!("OUTPUT:{output}");
    output.clone()
}

fn establish_tcp_connection(pipeline: &mut DynPipeline<TestBuffer>) {
    // process TCP SYN packet: flow state should be created in both directions
    let mut packet = tcp_packet_to_masquerade();
    packet.try_tcp_mut().unwrap().set_syn(true);

    let output = process_packet(pipeline, packet);
    assert!(!output.is_done());

    // process TCP SYN|ACK packet in reverse direction: flow entry should be found. State should become twoway
    let reply = build_reply(&output);
    let output: Packet<TestBuffer> = process_packet(pipeline, reply);
    assert!(output.meta().flow_info.is_some());
    assert_eq!(flow_status(&output), Some(FlowStatus::Active));
    assert_eq!(nat_flow_status(&output), Some(NatFlowStatus::TwoWay));

    // process TCP ACK packet in forward direction
    let mut packet = tcp_packet_to_masquerade();
    packet.try_tcp_mut().unwrap().set_ack(true);

    // state should transition to established
    let output = process_packet(pipeline, packet);
    assert!(!output.is_done());
    assert_eq!(flow_status(&output), Some(FlowStatus::Active));
    assert_eq!(nat_flow_status(&output), Some(NatFlowStatus::Established));

    // configured timeout for the flow
    let timeout = masquerade_state(&output).unwrap().idle_timeout();

    // check that flow timeouts "match" the ones configured, allowing for 5 second error (for the test)
    let flow_info_ack = output.meta().flow_info.as_ref().unwrap();
    let related = flow_info_ack.related.as_ref().unwrap().upgrade().unwrap();
    let valid_until = (Instant::now() + timeout)
        .checked_sub(Duration::from_secs(5))
        .unwrap();
    assert!(flow_info_ack.expires_at() >= valid_until);
    assert!(related.expires_at() >= valid_until);
}

#[tokio::test]
#[traced_test]
async fn test_masquerade_tcp_establish() {
    // build setup: 2 vpcs with masquerading (vni 100 -> vni 200)
    let (flow_table, mut pipeline, _allocw) = test_setup(1, build_overlay_2vpcs());
    establish_tcp_connection(&mut pipeline);
    assert_eq!(flow_table.active_len(), Some(2));
}

#[tokio::test]
#[traced_test]
async fn test_masquerade_check() {
    // build setup: 2 vpcs with masquerading (vni 100 -> vni 200)
    let (flow_table, mut pipeline, _allocw) = test_setup(1, build_overlay_2vpcs());

    test_case("Establish TCP over masquerade peering");
    establish_tcp_connection(&mut pipeline);
    assert_eq!(flow_table.active_len(), Some(2));

    test_case("Process packet masquerade source nat");
    // process one packet in src nat direction
    let packet = tcp_packet_to_masquerade();
    let out = process_packet(&mut pipeline, packet);

    // packet hit flow with SRC nat rule
    let state = masquerade_state(&out).expect("Must have flow info w/ masquerade state");
    assert_eq!(state.action(), NatAction::SrcNat);

    test_case("Process packet masquerade dest nat");
    // process packet in dst nat direction
    let reply = build_reply(&out);
    let out = process_packet(&mut pipeline, reply);

    // packet hit flow with dst nat rule
    let state = masquerade_state(&out).expect("Must have flow info w/ masquerade state");
    assert_eq!(state.action(), NatAction::DstNat);
    assert_eq!(nat_flow_status(&out).unwrap(), NatFlowStatus::Established);
    assert_eq!(flow_status(&out).unwrap(), FlowStatus::Active);

    // packet should make it to tcp source
    assert_eq!(out.ip_source().unwrap(), addr_v4("3.3.3.1"));
    assert_eq!(out.ip_destination().unwrap(), addr_v4("1.1.0.1"));
    assert_eq!(out.transport_src_port().unwrap().get(), 80);
    assert_eq!(out.transport_dst_port().unwrap().get(), 4321);

    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(flow_table.active_len(), Some(2));
}

#[tokio::test]
#[traced_test]
async fn test_masquerade_tcp_reset() {
    // build setup: 2 vpcs with masquerading (vni 100 -> vni 200)
    let (flow_table, mut pipeline, _allocw) = test_setup(1, build_overlay_2vpcs());
    establish_tcp_connection(&mut pipeline);
    assert_eq!(flow_table.active_len(), Some(2));

    // process one packet in src nat direction
    let packet = tcp_packet_to_masquerade();
    let out = process_packet(&mut pipeline, packet);

    // process packet in dst nat direction with RST flag set
    let mut reply = build_reply(&out);
    reply.try_tcp_mut().unwrap().set_rst(true);
    reply.try_tcp_mut().unwrap().set_ack(false);
    let reply_out = process_packet(&mut pipeline, reply);

    // packet hits flow with dst nat rule. Nat flow status becomes reset and flow is cancelled
    let state = masquerade_state(&reply_out).expect("Must have flow info w/ masquerade state");
    assert_eq!(state.action(), NatAction::DstNat);
    assert_eq!(nat_flow_status(&out).unwrap(), NatFlowStatus::Reset);
    assert_eq!(flow_status(&reply_out).unwrap(), FlowStatus::Cancelled);

    // packet (RST) should make it to tcp source
    assert_eq!(reply_out.ip_source().unwrap(), addr_v4("3.3.3.1"));
    assert_eq!(reply_out.ip_destination().unwrap(), addr_v4("1.1.0.1"));
    assert_eq!(reply_out.transport_src_port().unwrap().get(), 80);
    assert_eq!(reply_out.transport_dst_port().unwrap().get(), 4321);

    // flows get expired
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(flow_table.active_len(), Some(0));
}

#[tokio::test]
#[traced_test]
async fn test_masquerade_reconfig_keep_flow() {
    let genid = 1;
    // build setup: 2 vpcs with masquerading (vni 100 -> vni 200)
    let (flow_table, mut pipeline, mut allocw) = test_setup(genid, build_overlay_2vpcs());
    establish_tcp_connection(&mut pipeline);
    assert_eq!(flow_table.active_len(), Some(2));

    // process one packet in src nat direction
    let packet = tcp_packet_to_masquerade();
    let out = process_packet(&mut pipeline, packet);

    // process packet in dst nat direction
    let reply = build_reply(&out);
    let out = process_packet(&mut pipeline, reply);
    assert_eq!(nat_flow_status(&out).unwrap(), NatFlowStatus::Established);
    assert_eq!(flow_status(&out).unwrap(), FlowStatus::Active);
    assert_eq!(flow_genid(&out).unwrap(), genid);

    // update the NAT allocator with an identical config
    let mut overlay = build_overlay_2vpcs();
    overlay.validate().unwrap();
    let nat_config = StatefulNatConfig::new(&overlay.vpc_table, genid + 1);
    allocw.update_nat_allocator(nat_config, &flow_table);

    // process a packet: it should hit identical flows, except for genid
    let packet = tcp_packet_to_masquerade();
    let out = process_packet(&mut pipeline, packet);
    assert_eq!(nat_flow_status(&out).unwrap(), NatFlowStatus::Established);
    assert_eq!(flow_status(&out).unwrap(), FlowStatus::Active);
    assert_eq!(flow_genid(&out).unwrap(), genid + 1);

    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(flow_table.active_len(), Some(2));
}

#[tokio::test]
#[traced_test]
async fn test_masquerade_reconfig_drop_flow() {
    let genid = 1;
    // build setup: 2 vpcs with masquerading (vni 100 -> vni 200)
    let (flow_table, mut pipeline, mut allocw) = test_setup(genid, build_overlay_2vpcs());
    establish_tcp_connection(&mut pipeline);
    assert_eq!(flow_table.active_len(), Some(2));

    // process one packet in src nat direction
    let packet = tcp_packet_to_masquerade();
    let out = process_packet(&mut pipeline, packet);

    // process packet in dst nat direction
    let reply = build_reply(&out);
    let out = process_packet(&mut pipeline, reply);
    assert_eq!(nat_flow_status(&out).unwrap(), NatFlowStatus::Established);
    assert_eq!(flow_status(&out).unwrap(), FlowStatus::Active);
    assert_eq!(flow_genid(&out).unwrap(), genid);

    // update the NAT allocator with an identical config
    let mut overlay = build_overlay_2vpcs_modified();
    overlay.validate().unwrap();
    let nat_config = StatefulNatConfig::new(&overlay.vpc_table, genid + 1);
    allocw.update_nat_allocator(nat_config, &flow_table);

    // process a packet: it should hit identical flows
    let packet = tcp_packet_to_masquerade();
    let out = process_packet(&mut pipeline, packet);
    assert_eq!(nat_flow_status(&out).unwrap(), NatFlowStatus::Established);
    assert_ne!(flow_status(&out).unwrap(), FlowStatus::Active);
    assert_eq!(flow_genid(&out).unwrap(), genid); // genid not upgraded
    assert_eq!(out.get_done(), Some(DoneReason::Filtered)); // packet is not let through

    // flows should have been removed
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(flow_table.active_len(), Some(0));
}
