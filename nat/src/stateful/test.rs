// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#[cfg(test)]
mod tests {
    use crate::StatefulNat;
    use crate::stateful::NatAllocatorWriter;
    use concurrency::sync::Arc;
    use config::external::ExternalConfigBuilder;
    use config::external::communities::PriorityCommunityTable;
    use config::external::gwgroup::GwGroupTable;
    use config::external::overlay::Overlay;
    use config::external::overlay::vpc::{Vpc, VpcTable};
    use config::external::overlay::vpcpeering::{
        VpcExpose, VpcManifest, VpcPeering, VpcPeeringTable,
    };
    use config::external::underlay::Underlay;
    use config::internal::device::DeviceConfig;

    use config::internal::device::settings::DeviceSettings;
    use config::internal::interfaces::interface::{IfVtepConfig, InterfaceConfig, InterfaceType};
    use config::internal::routing::bgp::BgpConfig;
    use config::internal::routing::vrf::VrfConfig;
    use config::{ConfigError, GwConfig};
    use etherparse::Icmpv4Type;
    use fixin::wrap;
    use net::buffer::{PacketBufferMut, TestBuffer};
    use net::eth::mac::Mac;
    use net::headers::{
        EmbeddedTransport, TryEmbeddedTransport as _, TryIcmp4, TryInnerIpv4, TryIpv4, TryUdp,
    };
    use net::icmp4::TruncatedIcmp4;
    use net::ip::NextHeader;
    use net::packet::test_utils::{
        IcmpEchoDirection, build_test_icmp4_destination_unreachable_packet, build_test_icmp4_echo,
        build_test_udp_ipv4_frame,
    };
    use net::packet::{DoneReason, Packet, VpcDiscriminant};
    use net::tcp::TruncatedTcp;
    use net::udp::{TruncatedUdp, UdpPort};
    use net::vxlan::Vni;
    use pipeline::NetworkFunction;
    use pkt_meta::dst_vpcd_lookup::setup::build_dst_vni_lookup_configuration;
    use pkt_meta::dst_vpcd_lookup::{DstVpcdLookup, VpcDiscTablesWriter};
    use pkt_meta::flow_table::flow_key::Uni;
    use pkt_meta::flow_table::{FlowKey, FlowTable, IpProtoKey, LookupNF, UdpProtoKey};
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;
    use std::time::Duration;
    use test_utils::with_gw_name;
    use tracectl::get_trace_ctl;
    use tracing_test::traced_test;

    const FIVE_MINUTES: Duration = Duration::from_secs(5 * 60);
    const ONE_MINUTE: Duration = Duration::from_secs(60);

    fn addr_v4(addr: &str) -> Ipv4Addr {
        Ipv4Addr::from_str(addr).expect("Failed to create IPv4 address")
    }

    fn vni(vni: u32) -> Vni {
        Vni::new_checked(vni).expect("Failed to create VNI")
    }

    // Use a default configuration to build a valid GwConfig, the details are not really relevant to
    // our tests
    fn build_sample_config(overlay: Overlay) -> GwConfig {
        let device_config = DeviceConfig::new(DeviceSettings::new("sample"));

        let vtep = InterfaceConfig::new(
            "vtep",
            InterfaceType::Vtep(IfVtepConfig {
                mac: Some(Mac::from([0xca, 0xfe, 0xba, 0xbe, 0x00, 0x01])),
                local: Ipv4Addr::from_str("127.0.0.1").expect("Failed to create local address"),
                ttl: None,
                vni: None,
            }),
            false,
        );
        let mut vrf_config = VrfConfig::new("default", None, true);
        vrf_config.add_interface_config(vtep);
        let bgp = BgpConfig::new(1);
        vrf_config.set_bgp(bgp);
        let underlay = Underlay {
            vrf: vrf_config,
            vtep: None,
        };

        let mut external_builder = ExternalConfigBuilder::default();
        external_builder.genid(1);
        external_builder.device(device_config);
        external_builder.underlay(underlay);
        external_builder.overlay(overlay);
        external_builder.gwgroups(GwGroupTable::new());
        external_builder.communities(PriorityCommunityTable::new());

        let external_config = external_builder
            .build()
            .expect("Failed to build external config");

        GwConfig::new(external_config)
    }

    #[allow(clippy::too_many_lines)]
    fn build_overlay_4vpcs() -> Overlay {
        fn add_expose(manifest: &mut VpcManifest, expose: VpcExpose) {
            manifest.add_expose(expose).expect("Failed to add expose");
        }

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
            .make_stateful_nat(Some(FIVE_MINUTES))
            .unwrap()
            .ip("1.1.0.0/16".into())
            .as_range("10.12.0.0/16".into());
        let expose122 = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("1.2.0.0/16".into())
            .as_range("10.98.128.0/17".into())
            .as_range("10.99.0.0/17".into());
        let expose123 = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("1.3.0.0/24".into())
            .as_range("10.100.0.0/24".into());
        let expose211 = VpcExpose::empty()
            .make_stateful_nat(Some(ONE_MINUTE))
            .unwrap()
            .ip("1.2.2.0/24".into())
            .as_range("10.201.201.0/24".into());
        let expose212 = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("1.2.3.0/24".into())
            .as_range("10.201.202.0/24".into());
        let expose213 = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("2.0.0.0/24".into())
            .as_range("10.201.203.0/24".into());
        let expose214 = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("2.0.1.0/28".into())
            .as_range("10.201.204.192/28".into());

        // VPC1 <-> VPC3
        let expose131 = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("1.1.0.0/16".into())
            .as_range("3.3.0.0/16".into());
        let expose132 = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("1.2.0.0/16".into())
            .as_range("3.1.0.0/16".into())
            .not_as("3.1.128.0/17".into())
            .as_range("3.2.0.0/17".into());
        let expose311 = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("192.168.128.0/24".into())
            .as_range("3.3.3.0/24".into());

        // VPC1 <-> VPC4
        let expose141 = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("1.1.0.0/16".into())
            .as_range("4.4.0.0/16".into());
        let expose411 = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("1.1.0.0/16".into())
            .as_range("4.5.0.0/16".into());

        // VPC2 <-> VPC4
        let expose241 = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("2.4.0.0/16".into())
            .not("2.4.1.0/24".into())
            .as_range("44.0.0.0/16".into())
            .not_as("44.0.200.0/24".into());
        let expose421 = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("4.4.0.0/16".into())
            .not("4.4.128.0/18".into())
            .as_range("44.4.0.0/16".into())
            .not_as("44.4.64.0/18".into());

        // VPC3 <-> VPC4
        let expose341 = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("192.168.100.0/24".into())
            .as_range("34.34.34.0/24".into());
        let expose431 = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("4.4.0.0/24".into());

        // VPC1 <-> VPC2
        let mut manifest12 = VpcManifest::new("VPC-1");
        add_expose(&mut manifest12, expose121);
        add_expose(&mut manifest12, expose122);
        add_expose(&mut manifest12, expose123);
        let mut manifest21 = VpcManifest::new("VPC-2");
        add_expose(&mut manifest21, expose211);
        add_expose(&mut manifest21, expose212);
        add_expose(&mut manifest21, expose213);
        add_expose(&mut manifest21, expose214);

        // VPC1 <-> VPC3
        let mut manifest13 = VpcManifest::new("VPC-1");
        add_expose(&mut manifest13, expose131);
        add_expose(&mut manifest13, expose132);
        let mut manifest31 = VpcManifest::new("VPC-3");
        add_expose(&mut manifest31, expose311);

        // VPC1 <-> VPC4
        let mut manifest14 = VpcManifest::new("VPC-1");
        add_expose(&mut manifest14, expose141);
        let mut manifest41 = VpcManifest::new("VPC-4");
        add_expose(&mut manifest41, expose411);

        // VPC2 <-> VPC4
        let mut manifest24 = VpcManifest::new("VPC-2");
        add_expose(&mut manifest24, expose241);
        let mut manifest42 = VpcManifest::new("VPC-4");
        add_expose(&mut manifest42, expose421);

        // VPC3 <-> VPC4
        let mut manifest34 = VpcManifest::new("VPC-3");
        add_expose(&mut manifest34, expose341);
        let mut manifest43 = VpcManifest::new("VPC-4");
        add_expose(&mut manifest43, expose431);

        let peering12 = VpcPeering::new("VPC-1--VPC-2", manifest12, manifest21, None);
        let peering31 = VpcPeering::new("VPC-3--VPC-1", manifest31, manifest13, None);
        let peering14 = VpcPeering::new("VPC-1--VPC-4", manifest14, manifest41, None);
        let peering24 = VpcPeering::new("VPC-2--VPC-4", manifest24, manifest42, None);
        let peering34 = VpcPeering::new("VPC-3--VPC-4", manifest34, manifest43, None);

        let mut peering_table = VpcPeeringTable::new();
        peering_table.add(peering12).expect("Failed to add peering");
        peering_table.add(peering31).expect("Failed to add peering");
        peering_table.add(peering14).expect("Failed to add peering");
        peering_table.add(peering24).expect("Failed to add peering");
        peering_table.add(peering34).expect("Failed to add peering");

        Overlay::new(vpc_table, peering_table)
    }

    fn build_overlay_2vpcs() -> Overlay {
        fn add_expose(manifest: &mut VpcManifest, expose: VpcExpose) {
            manifest.add_expose(expose).expect("Failed to add expose");
        }

        let mut vpc_table = VpcTable::new();
        let _ = vpc_table.add(Vpc::new("VPC-1", "AAAAA", 100).expect("Failed to add VPC"));
        let _ = vpc_table.add(Vpc::new("VPC-2", "BBBBB", 200).expect("Failed to add VPC"));

        let expose121 = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("1.1.0.0/16".into())
            .as_range("2.2.0.0/16".into());
        let expose211 = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("1.2.2.0/24".into())
            .as_range("3.3.3.0/24".into());

        let mut manifest12 = VpcManifest::new("VPC-1");
        add_expose(&mut manifest12, expose121);
        let mut manifest21 = VpcManifest::new("VPC-2");
        add_expose(&mut manifest21, expose211);

        let peering12 = VpcPeering::new("VPC-1--VPC-2", manifest12, manifest21, None);

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
        packet.get_meta_mut().set_nat(true);
        packet.get_meta_mut().src_vpcd = Some(VpcDiscriminant::VNI(src_vni));
        packet.get_meta_mut().dst_vpcd = Some(VpcDiscriminant::VNI(dst_vni));

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
        fn get_flow_key<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> FlowKey {
            FlowKey::try_from(Uni(packet)).unwrap()
        }

        let flow_key = get_flow_key(packet);
        if let Some(flow_info) = flow_table.lookup(&flow_key) {
            packet.meta.flow_info = Some(flow_info);
        }
    }

    #[test]
    #[traced_test]
    #[wrap(with_gw_name())]
    #[allow(clippy::too_many_lines)]
    fn test_full_config() {
        let mut config = build_sample_config(build_overlay_4vpcs());
        config.validate().unwrap();

        // Check that we can validate the allocator
        let (mut nat, mut allocator) = StatefulNat::new_with_defaults();
        allocator
            .update_allocator(&config.external.overlay.vpc_table)
            .unwrap();

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
        let (target_src, target_dst) = ("10.12.0.0", "1.2.2.0");
        let (output_src, output_dst, output_src_port, output_dst_port, done_reason) =
            check_packet(&mut nat, vni(100), vni(200), orig_src, orig_dst, 9998, 443);
        assert_eq!(done_reason, None);

        assert_eq!(output_src, addr_v4(target_src));
        assert_eq!(output_dst, addr_v4(target_dst));
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
            target_dst,
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
        let Some((_, idle_timeout)) = nat.get_session::<Ipv4Addr>(
            VpcDiscriminant::VNI(vni(100)),
            IpAddr::from_str(orig_src).unwrap(),
            VpcDiscriminant::VNI(vni(200)),
            IpAddr::from_str(orig_dst).unwrap(),
            IpProtoKey::Udp(UdpProtoKey {
                src_port: UdpPort::new_checked(9998).unwrap(),
                dst_port: UdpPort::new_checked(443).unwrap(),
            }),
        ) else {
            unreachable!()
        };
        // We expect to find the minimum (non-empty) value between the two VPCs involved
        assert_eq!(idle_timeout, ONE_MINUTE);
        // Reverse path
        let Some((_, idle_timeout)) = nat.get_session::<Ipv4Addr>(
            VpcDiscriminant::VNI(vni(200)),
            IpAddr::from_str(target_dst).unwrap(),
            VpcDiscriminant::VNI(vni(100)),
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
        let mut new_config = build_sample_config(build_overlay_2vpcs());
        new_config.validate().unwrap();
        allocator
            .update_allocator(&new_config.external.overlay.vpc_table)
            .unwrap();

        // Check existing connection
        // TODO: We should drop this connection after updating the allocator in the future, as a
        // result these steps should fail
        let (orig_src, orig_dst) = ("1.1.2.3", "10.201.201.18");
        let (target_src, target_dst) = ("10.12.0.0", "1.2.2.0");
        let (output_src, output_dst, output_src_port, output_dst_port, done_reason) =
            check_packet(&mut nat, vni(100), vni(200), orig_src, orig_dst, 9998, 443);
        assert_eq!(output_src, addr_v4(target_src));
        assert_eq!(output_dst, addr_v4(target_dst));
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
            target_dst,
            target_src,
            output_dst_port,
            output_src_port,
        );
        assert_eq!(return_output_src, addr_v4(orig_dst));
        assert_eq!(return_output_dst, addr_v4(orig_src));
        assert_eq!(return_output_src_port, 443);
        assert_eq!(return_output_dst_port, 9998);
        assert_eq!(done_reason, None);

        // Check new connection: valid source NAT but invalid destination NAT
        let (orig_src, orig_dst) = ("1.1.2.3", "10.201.201.17");
        let target_src = "2.2.0.0";
        let (output_src, output_dst, output_src_port, output_dst_port, done_reason) =
            check_packet(&mut nat, vni(100), vni(200), orig_src, orig_dst, 9998, 80);
        assert_eq!(output_src, addr_v4(target_src));
        assert_eq!(output_dst, addr_v4(orig_dst));
        assert_eq!(output_dst_port, 80);
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

        // Check new valid connection
        let (orig_src, orig_dst) = ("1.1.2.3", "3.3.3.3");
        let (target_src, target_dst) = ("2.2.0.0", "1.2.2.0");
        let (output_src, output_dst, output_src_port, output_dst_port, done_reason) =
            check_packet(&mut nat, vni(100), vni(200), orig_src, orig_dst, 9998, 80);
        assert_eq!(output_src, addr_v4(target_src));
        assert_eq!(output_dst, addr_v4(target_dst));
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
            target_dst,
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

    fn build_overlay_2vpcs_unidirectional_nat() -> Overlay {
        fn add_expose(manifest: &mut VpcManifest, expose: VpcExpose) {
            manifest.add_expose(expose).expect("Failed to add expose");
        }

        let mut vpc_table = VpcTable::new();
        let _ = vpc_table.add(Vpc::new("VPC-1", "AAAAA", 100).expect("Failed to add VPC"));
        let _ = vpc_table.add(Vpc::new("VPC-2", "BBBBB", 200).expect("Failed to add VPC"));

        let expose121 = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("1.1.0.0/16".into())
            .as_range("2.2.0.0/16".into());
        let expose211 = VpcExpose::empty().ip("5.0.0.0/8".into());

        let mut manifest12 = VpcManifest::new("VPC-1");
        add_expose(&mut manifest12, expose121);
        let mut manifest21 = VpcManifest::new("VPC-2");
        add_expose(&mut manifest21, expose211);

        let peering12 = VpcPeering::new("VPC-1--VPC-2", manifest12, manifest21, None);

        let mut peering_table = VpcPeeringTable::new();
        peering_table.add(peering12).expect("Failed to add peering");

        Overlay::new(vpc_table, peering_table)
    }

    #[test]
    #[wrap(with_gw_name())]
    #[traced_test]
    fn test_full_config_unidirectional_nat() {
        let mut config = build_sample_config(build_overlay_2vpcs_unidirectional_nat());
        config.validate().unwrap();

        // Check that we can validate the allocator
        let (mut nat, mut allocator) = StatefulNat::new_with_defaults();
        allocator
            .update_allocator(&config.external.overlay.vpc_table)
            .unwrap();

        // No NAT
        let (orig_src, orig_dst) = ("8.8.8.8", "9.9.9.9");
        let (output_src, output_dst, output_src_port, output_dst_port, done_reason) =
            check_packet(&mut nat, vni(100), vni(200), orig_src, orig_dst, 9998, 443);
        assert_eq!(output_src, addr_v4(orig_src));
        assert_eq!(output_dst, addr_v4(orig_dst));
        assert_eq!(output_src_port, 9998);
        assert_eq!(output_dst_port, 443);
        assert_eq!(done_reason, Some(DoneReason::Filtered));

        // NAT: expose121 <-> expose211 (valid source NAT, no destination NAT)
        let (orig_src, orig_dst) = ("1.1.2.3", "5.0.0.5");
        let (target_src, target_dst) = ("2.2.0.0", "5.0.0.5");
        let (output_src, output_dst, output_src_port, output_dst_port, done_reason) =
            check_packet(&mut nat, vni(100), vni(200), orig_src, orig_dst, 9998, 443);
        assert_eq!(output_src, addr_v4(target_src));
        assert_eq!(output_dst, addr_v4(target_dst));
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
            target_dst,
            target_src,
            output_dst_port,
            output_src_port,
        );
        assert_eq!(return_output_src, addr_v4(orig_dst));
        assert_eq!(return_output_dst, addr_v4(orig_src));
        assert_eq!(return_output_src_port, 443);
        assert_eq!(return_output_dst_port, 9998);
        assert_eq!(done_reason, None);

        // NAT: expose211 <-> expose121 (no source NAT - no NAT happens, packet will be dropped at routing stage)
        let (orig_src, orig_dst) = ("5.0.0.5", "2.2.0.2");
        let (target_src, target_dst) = ("5.0.0.5", "2.2.0.2");
        let (output_src, output_dst, _, _, done_reason) =
            check_packet(&mut nat, vni(200), vni(100), orig_src, orig_dst, 9090, 8080);
        assert_eq!(output_src, addr_v4(target_src));
        assert_eq!(output_dst, addr_v4(target_dst));
        assert_eq!(done_reason, None);
    }

    fn build_overlay_2vpcs_no_nat() -> Overlay {
        fn add_expose(manifest: &mut VpcManifest, expose: VpcExpose) {
            manifest.add_expose(expose).expect("Failed to add expose");
        }

        let mut vpc_table = VpcTable::new();
        let _ = vpc_table.add(Vpc::new("VPC-1", "AAAAA", 100).expect("Failed to add VPC"));
        let _ = vpc_table.add(Vpc::new("VPC-2", "BBBBB", 200).expect("Failed to add VPC"));

        let expose121 = VpcExpose::empty().ip("1.1.0.0/16".into());
        let expose211 = VpcExpose::empty().ip("2.2.0.0/16".into());

        let mut manifest12 = VpcManifest::new("VPC-1");
        add_expose(&mut manifest12, expose121);
        let mut manifest21 = VpcManifest::new("VPC-2");
        add_expose(&mut manifest21, expose211);

        let peering12 = VpcPeering::new("VPC-1--VPC-2", manifest12, manifest21, None);

        let mut peering_table = VpcPeeringTable::new();
        peering_table.add(peering12).expect("Failed to add peering");

        Overlay::new(vpc_table, peering_table)
    }

    #[test]
    #[wrap(with_gw_name())]
    #[traced_test]
    fn test_full_config_no_nat() {
        let mut config = build_sample_config(build_overlay_2vpcs_no_nat());
        config.validate().unwrap();

        // Check that we can validate the allocator
        let (mut nat, mut allocator) = StatefulNat::new_with_defaults();
        allocator
            .update_allocator(&config.external.overlay.vpc_table)
            .unwrap();

        // No NAT, and no exposed IPs
        let (orig_src, orig_dst, orig_src_port, orig_dst_port) = ("8.8.8.8", "9.9.9.9", 9998, 443);
        let (output_src, output_dst, output_src_port, output_dst_port, done_reason) = check_packet(
            &mut nat,
            vni(100),
            vni(200),
            orig_src,
            orig_dst,
            orig_src_port,
            orig_dst_port,
        );
        assert_eq!(output_src, addr_v4(orig_src));
        assert_eq!(output_dst, addr_v4(orig_dst));
        assert_eq!(output_src_port, orig_src_port);
        assert_eq!(output_dst_port, orig_dst_port);
        assert_eq!(done_reason, Some(DoneReason::Filtered));

        // No NAT, with valid exposed IPs
        let (orig_src, orig_dst, orig_src_port, orig_dst_port) = ("1.1.2.3", "2.2.4.5", 9998, 443);
        let (output_src, output_dst, output_src_port, output_dst_port, done_reason) = check_packet(
            &mut nat,
            vni(100),
            vni(200),
            orig_src,
            orig_dst,
            orig_src_port,
            orig_dst_port,
        );
        assert_eq!(output_src, addr_v4(orig_src));
        assert_eq!(output_dst, addr_v4(orig_dst));
        assert_eq!(output_src_port, orig_src_port);
        assert_eq!(output_dst_port, orig_dst_port);
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
            orig_src,
            output_dst_port,
            output_src_port,
        );
        assert_eq!(return_output_src, addr_v4(orig_dst));
        assert_eq!(return_output_dst, addr_v4(orig_src));
        assert_eq!(return_output_src_port, orig_dst_port);
        assert_eq!(return_output_dst_port, orig_src_port);
        assert_eq!(done_reason, None);
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
        packet.get_meta_mut().set_nat(true);
        packet.get_meta_mut().src_vpcd = Some(VpcDiscriminant::VNI(src_vni));
        packet.get_meta_mut().dst_vpcd = Some(VpcDiscriminant::VNI(dst_vni));

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

    #[test]
    #[wrap(with_gw_name())]
    #[traced_test]
    fn test_icmp_echo_nat() {
        let mut config = build_sample_config(build_overlay_2vpcs());
        config.validate().unwrap();

        // Check that we can validate the allocator
        let (mut nat, mut allocator) = StatefulNat::new_with_defaults();
        allocator
            .update_allocator(&config.external.overlay.vpc_table)
            .unwrap();

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
        let (target_src, target_dst) = (addr_v4("2.2.0.0"), addr_v4("1.2.2.0"));
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
        assert_eq!(output_dst, target_dst);
        assert!(output_identifier_1.is_multiple_of(256)); // First port of a 256-port "port block" from allocator
        assert_eq!(done_reason, None);

        // Reverse path
        let (return_output_src, return_output_dst, return_output_identifier, done_reason) =
            check_packet_icmp_echo(
                &mut nat,
                vni(200),
                vni(100),
                target_dst,
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
        let (target_src, target_dst) = (addr_v4("2.2.0.0"), addr_v4("1.2.2.0"));
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
        assert_eq!(output_dst, target_dst);
        assert_eq!(output_identifier_2, output_identifier_1); // Same identifier as before
        assert_eq!(done_reason, None);

        // NAT: expose121 <-> expose211 again, but with identifier 0 (corner case)
        let (orig_src, orig_dst, orig_identifier) = (addr_v4("1.1.2.3"), addr_v4("3.3.3.3"), 0);
        let (target_src, target_dst) = (addr_v4("2.2.0.0"), addr_v4("1.2.2.0"));
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
        assert_eq!(output_dst, target_dst);
        assert_eq!(output_identifier_3, output_identifier_1 + 1); // Second port of the same 256-port "port block" from allocator
        assert_eq!(done_reason, None);
    }

    #[test]
    #[wrap(with_gw_name())]
    #[traced_test]
    fn test_icmp_echo_unidirectional_nat() {
        let mut config = build_sample_config(build_overlay_2vpcs_unidirectional_nat());
        config.validate().unwrap();

        // Check that we can validate the allocator
        let (mut nat, mut allocator) = StatefulNat::new_with_defaults();
        allocator
            .update_allocator(&config.external.overlay.vpc_table)
            .unwrap();

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
        let (orig_src, orig_dst, orig_identifier) = (addr_v4("1.1.2.3"), addr_v4("5.0.0.5"), 1337);
        let (target_src, target_dst) = (addr_v4("2.2.0.0"), addr_v4("5.0.0.5"));
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
        assert_eq!(output_dst, target_dst);
        assert!(output_identifier_1.is_multiple_of(256)); // First port of a 256-port "port block" from allocator
        assert_eq!(done_reason, None);

        // Reverse path
        let (return_output_src, return_output_dst, return_output_identifier, done_reason) =
            check_packet_icmp_echo(
                &mut nat,
                vni(200),
                vni(100),
                target_dst,
                target_src,
                IcmpEchoDirection::Reply,
                output_identifier_1,
            );
        assert_eq!(return_output_src, orig_dst);
        assert_eq!(return_output_dst, orig_src);
        assert_eq!(return_output_identifier, orig_identifier);
        assert_eq!(done_reason, None);

        // Second request with same identifier: no reallocation
        let (orig_src, orig_dst) = (addr_v4("1.1.2.3"), addr_v4("5.0.0.5"));
        let (target_src, target_dst) = (addr_v4("2.2.0.0"), addr_v4("5.0.0.5"));
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
        assert_eq!(output_dst, target_dst);
        assert_eq!(output_identifier_2, output_identifier_1); // Same identifier as before
        assert_eq!(done_reason, None);
    }

    #[allow(clippy::too_many_arguments)]
    fn check_packet_icmp_error(
        nat: &mut StatefulNat,
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
        packet.get_meta_mut().set_nat(true);
        packet.get_meta_mut().src_vpcd = Some(VpcDiscriminant::VNI(src_vni));
        packet.get_meta_mut().dst_vpcd = Some(VpcDiscriminant::VNI(dst_vni));

        flow_lookup(nat.sessions(), &mut packet);

        let packets_out: Vec<_> = nat.process(vec![packet].into_iter()).collect();
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
                let Icmpv4Type::EchoRequest(echo_header) = icmp.icmp_type() else {
                    unreachable!();
                };
                (echo_header.id, echo_header.seq)
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

    #[test]
    #[wrap(with_gw_name())]
    #[traced_test]
    fn test_icmp_error_nat() {
        let mut config = build_sample_config(build_overlay_2vpcs());
        config.validate().unwrap();

        // Check that we can validate the allocator
        let (mut nat, mut allocator) = StatefulNat::new_with_defaults();
        allocator
            .update_allocator(&config.external.overlay.vpc_table)
            .unwrap();

        // ICMP Error msg: expose211 -> expose121, no previous session for inner packet
        let (
            router_src,
            orig_outer_dst,
            orig_inner_src,
            orig_inner_dst,
            orig_echo_identifier,
            orig_echo_seq_number,
        ) = (
            // Host 1.1.2.3 in VPC1 sent imaginary ICMP Echo packet to 3.3.3.3 in VPC2,
            // which imaginarily got translated as 2.2.0.0 -> 1.2.2.0.
            // Router 1.2.2.18 from VPC2 returns Destination Unreachable to 2.2.0.0 with initial
            // datagram embedded in it
            addr_v4("1.2.2.18"),
            addr_v4("2.2.0.0"),
            addr_v4("2.2.0.0"),
            addr_v4("1.2.2.0"),
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
            &mut nat,
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
        assert_eq!(done_reason, Some(DoneReason::Filtered));

        // ICMP Echo Request expose121 -> expose211
        let (orig_echo_src, orig_echo_dst, target_echo_src, target_echo_dst) = (
            addr_v4("1.1.2.3"),
            addr_v4("3.3.3.3"),
            addr_v4("2.2.0.0"),
            addr_v4("1.2.2.0"),
        );
        let (output_echo_src, output_echo_dst, output_echo_identifier, done_reason) =
            check_packet_icmp_echo(
                &mut nat,
                vni(100),
                vni(200),
                orig_echo_src,
                orig_echo_dst,
                IcmpEchoDirection::Request,
                orig_echo_identifier,
            );
        assert_eq!(output_echo_src, target_echo_src);
        assert_eq!(output_echo_dst, target_echo_dst);
        assert!(output_echo_identifier.is_multiple_of(256)); // First port of a 256-port "port block" from allocator
        assert_eq!(done_reason, None);

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
        let (
            output_outer_src,
            output_outer_dst,
            output_inner_src,
            output_inner_dst,
            output_inner_identifier,
            output_inner_seq_number,
            done_reason,
        ) = check_packet_icmp_error(
            &mut nat,
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

    fn build_overlay_3vpcs_unidirectional_nat_overlapping_addr() -> Overlay {
        fn add_expose(manifest: &mut VpcManifest, expose: VpcExpose) {
            manifest.add_expose(expose).expect("Failed to add expose");
        }

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
            .as_range("2.0.0.0/24".into());
        let expose21 = VpcExpose::empty().ip("5.0.0.0/24".into());

        let mut manifest12 = VpcManifest::new("VPC-1");
        add_expose(&mut manifest12, expose12);
        let mut manifest21 = VpcManifest::new("VPC-2");
        add_expose(&mut manifest21, expose21);

        let peering12 = VpcPeering::new("VPC-1--VPC-2", manifest12, manifest21, None);

        // VPC-2 (no NAT) <-> VPC-3 (NAT)
        let expose32 = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("1.0.0.0/24".into())
            .as_range("2.0.0.0/24".into());
        let expose23 = VpcExpose::empty().ip("5.0.0.0/24".into());

        let mut manifest23 = VpcManifest::new("VPC-2");
        add_expose(&mut manifest23, expose23);
        let mut manifest32 = VpcManifest::new("VPC-3");
        add_expose(&mut manifest32, expose32);

        let peering23 = VpcPeering::new("VPC-2--VPC-3", manifest23, manifest32, None);

        let mut peering_table = VpcPeeringTable::new();
        peering_table.add(peering12).unwrap();
        peering_table.add(peering23).unwrap();

        Overlay::new(vpc_table, peering_table)
    }

    #[allow(clippy::too_many_arguments)]
    fn check_packet_with_vpcd_lookup(
        nat: &mut StatefulNat,
        vpcdlookup: &mut DstVpcdLookup,
        flow_lookup_stage: Option<&mut LookupNF>,
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
        packet.get_meta_mut().set_nat(true);
        packet.get_meta_mut().src_vpcd = Some(VpcDiscriminant::VNI(src_vni));

        // VPC discriminant lookup
        let packets_from_vpcd_lookup: Vec<_> = vpcdlookup
            .process::<std::vec::IntoIter<Packet<TestBuffer>>>(vec![packet].into_iter())
            .collect();

        // Flow table lookup
        let packets_from_flow_lookup: Vec<_> = if let Some(stage) = flow_lookup_stage {
            // Use dedicated stage, which attaches the destination VPC discriminant to the packet,
            // if any is found from the flow table.
            stage
                .process::<std::vec::IntoIter<Packet<TestBuffer>>>(
                    packets_from_vpcd_lookup.into_iter(),
                )
                .collect()
        } else {
            // Simple flow lookup, without attaching the destination VPC discriminant to the packet.
            let packet = packets_from_vpcd_lookup[0].clone();
            flow_lookup(nat.sessions(), &mut packet.clone());
            vec![packet]
        };

        // NAT
        let packets_out: Vec<_> = nat
            .process::<std::vec::IntoIter<Packet<TestBuffer>>>(packets_from_flow_lookup.into_iter())
            .collect();

        let dst_vpcd = packets_out[0].get_meta().dst_vpcd;
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

    #[test]
    #[wrap(with_gw_name())]
    #[allow(clippy::too_many_lines)]
    fn test_full_config_unidirectional_nat_overlapping_destination() {
        let tctl = get_trace_ctl();
        let _ = tctl.setup_from_string("vpc-routing=debug,flow-lookup=debug,stateful-nat=debug");

        let mut config =
            build_sample_config(build_overlay_3vpcs_unidirectional_nat_overlapping_addr());
        config.validate().unwrap();

        // Build VPC discriminant lookup stage
        let vpcd_tables = build_dst_vni_lookup_configuration(&config.external.overlay).unwrap();
        let mut vpcdtablesw = VpcDiscTablesWriter::new();
        vpcdtablesw.update_vpcd_tables(vpcd_tables);
        let mut vpcdlookup = DstVpcdLookup::new("vpcd-lookup", vpcdtablesw.get_reader());

        /////////////////////////////////////////////////////////////////
        // First NAT stage: We do not search for the destination VPC discriminant in the flow table.
        // We expect return packets to fail to find a destination VPC ID due to the conflicts
        // between the IPs exposed by VPC-2 for both VPC-1 and VPC-3, and to be dropped.

        // Build NAT stage
        let (mut nat, mut allocator) = StatefulNat::new_with_defaults();

        // Check that we can validate the allocator
        allocator
            .update_allocator(&config.external.overlay.vpc_table)
            .unwrap();

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
        assert_eq!(return_done_reason, Some(DoneReason::Unroutable));

        /////////////////////////////////////////////////////////////////
        // Second NAT stage: We update the VPC discriminant lookup table.
        // Check that we can NAT and route the return packet.

        // Build flow table lookup stage
        let flow_table = Arc::new(FlowTable::default());
        let mut flow_lookup = LookupNF::new("flow-lookup", flow_table.clone());

        // Build a new NAT stage
        let mut allocator = NatAllocatorWriter::new();
        let mut nat = StatefulNat::new("stateful-nat", flow_table.clone(), allocator.get_reader());

        // Check that we can validate the allocator
        //
        // When we build the allocator, turn off randomness to check whether we may get collisions
        // for port allocation
        allocator
            .update_allocator_and_turn_off_randomness(&config.external.overlay.vpc_table)
            .unwrap();

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

        assert_eq!(return_vpcd, Some(VpcDiscriminant::VNI(vni(100))));
        assert_eq!(return_output_src, addr_v4(orig_dst));
        assert_eq!(return_output_dst, addr_v4(orig_src));
        assert_eq!(return_output_src_port, orig_dst_port);
        assert_eq!(return_output_dst_port, orig_src_port);
        assert_eq!(return_done_reason, None);
    }

    fn build_overlay_2vpcs_unidirectional_nat_overlapping_exposes() -> Overlay {
        fn add_expose(manifest: &mut VpcManifest, expose: VpcExpose) {
            manifest.add_expose(expose).expect("Failed to add expose");
        }

        let mut vpc_table = VpcTable::new();
        let _ = vpc_table.add(Vpc::new("VPC-1", "AAAAA", 100).unwrap());
        let _ = vpc_table.add(Vpc::new("VPC-2", "BBBBB", 200).unwrap());

        // Peering 1

        let expose1_1 = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("1.0.0.0/24".into())
            .as_range("2.0.0.0/24".into());
        let expose1_2 = VpcExpose::empty().ip("5.0.0.0/24".into());

        let mut manifest1_1 = VpcManifest::new("VPC-1");
        add_expose(&mut manifest1_1, expose1_1);
        let mut manifest1_2 = VpcManifest::new("VPC-2");
        add_expose(&mut manifest1_2, expose1_2);

        let peering1 = VpcPeering::new("VPC-1--VPC-2--1", manifest1_1, manifest1_2, None);

        // Peering 2 - Overlap with Peering 1

        let expose2_1 = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("3.0.0.0/24".into())
            .as_range("2.0.0.0/24".into()); // Overlap
        let expose2_2 = VpcExpose::empty().ip("6.0.0.0/24".into());

        let mut manifest2_1 = VpcManifest::new("VPC-1");
        add_expose(&mut manifest2_1, expose2_1);
        let mut manifest2_2 = VpcManifest::new("VPC-2");
        add_expose(&mut manifest2_2, expose2_2);

        let peering2 = VpcPeering::new("VPC-1--VPC-2--2", manifest2_1, manifest2_2, None);

        // Peering table

        let mut peering_table = VpcPeeringTable::new();
        peering_table.add(peering1).unwrap();
        peering_table.add(peering2).unwrap();

        Overlay::new(vpc_table, peering_table)
    }

    #[test]
    #[traced_test]
    #[wrap(with_gw_name())]
    #[allow(clippy::too_many_lines)]
    fn test_full_config_unidirectional_nat_overlapping_exposes_for_single_peering() {
        let mut config =
            build_sample_config(build_overlay_2vpcs_unidirectional_nat_overlapping_exposes());
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
        let vpcd_tables = build_dst_vni_lookup_configuration(&config.external.overlay).unwrap();
        let mut vpcdtablesw = VpcDiscTablesWriter::new();
        vpcdtablesw.update_vpcd_tables(vpcd_tables);
        let mut vpcdlookup = DstVpcdLookup::new("vpcd-lookup", vpcdtablesw.get_reader());

        // Build flow table lookup stage
        let flow_table = Arc::new(FlowTable::default());
        let mut flow_lookup = LookupNF::new("flow-lookup", flow_table.clone());

        /////////////////////////////////////////////////////////////////
        // Build a NAT stage and send a packet through peering1.
        // Check that NAT occurs as expected.

        // Build a new NAT stage
        let mut allocator = NatAllocatorWriter::new();
        let mut nat = StatefulNat::new("stateful-nat", flow_table.clone(), allocator.get_reader());

        // Check that we can validate the allocator
        allocator
            .update_allocator(&config.external.overlay.vpc_table)
            .unwrap();

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
}
