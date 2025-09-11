// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#[cfg(test)]
mod tests {
    use config::GwConfig;
    use config::external::ExternalConfigBuilder;
    use config::external::overlay::Overlay;
    use config::external::overlay::vpc::{Vpc, VpcTable};
    use config::external::overlay::vpcpeering::{
        VpcExpose, VpcManifest, VpcPeering, VpcPeeringTable,
    };
    use config::external::underlay::Underlay;
    use config::internal::device::DeviceConfig;
    use config::internal::device::settings::DeviceSettings;
    use config::internal::interfaces::interface::InterfaceConfig;
    use config::internal::interfaces::interface::{IfVtepConfig, InterfaceType};
    use config::internal::routing::bgp::BgpConfig;
    use config::internal::routing::vrf::VrfConfig;

    use crate::StatefulNat;

    use net::buffer::TestBuffer;
    use net::eth::mac::Mac;
    use net::headers::{TryIpv4, TryUdp};
    use net::packet::test_utils::build_test_udp_ipv4_frame;
    use net::packet::{Packet, VpcDiscriminant};
    use net::vxlan::Vni;
    use pipeline::NetworkFunction;
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use tracing_test::traced_test;

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
            .ip("1.1.0.0/16".into())
            .as_range("10.12.0.0/16".into());
        let expose122 = VpcExpose::empty()
            .ip("1.2.0.0/16".into())
            .as_range("10.98.128.0/17".into())
            .as_range("10.99.0.0/17".into());
        let expose123 = VpcExpose::empty()
            .ip("1.3.0.0/24".into())
            .as_range("10.100.0.0/24".into());
        let expose211 = VpcExpose::empty()
            .ip("1.2.2.0/24".into())
            .as_range("10.201.201.0/24".into());
        let expose212 = VpcExpose::empty()
            .ip("1.2.3.0/24".into())
            .as_range("10.201.202.0/24".into());
        let expose213 = VpcExpose::empty()
            .ip("2.0.0.0/24".into())
            .as_range("10.201.203.0/24".into());
        let expose214 = VpcExpose::empty()
            .ip("2.0.1.0/28".into())
            .as_range("10.201.204.192/28".into());

        // VPC1 <-> VPC3
        let expose131 = VpcExpose::empty()
            .ip("1.1.0.0/16".into())
            .as_range("3.3.0.0/16".into());
        let expose132 = VpcExpose::empty()
            .ip("1.2.0.0/16".into())
            .as_range("3.1.0.0/16".into())
            .not_as("3.1.128.0/17".into())
            .as_range("3.2.0.0/17".into());
        let expose311 = VpcExpose::empty()
            .ip("192.168.128.0/24".into())
            .as_range("3.3.3.0/24".into());

        // VPC1 <-> VPC4
        let expose141 = VpcExpose::empty()
            .ip("1.1.0.0/16".into())
            .as_range("4.4.0.0/16".into());
        let expose411 = VpcExpose::empty()
            .ip("1.1.0.0/16".into())
            .as_range("4.5.0.0/16".into());

        // VPC2 <-> VPC4
        let expose241 = VpcExpose::empty()
            .ip("2.4.0.0/16".into())
            .not("2.4.1.0/24".into())
            .as_range("44.0.0.0/16".into())
            .not_as("44.0.200.0/24".into());
        let expose421 = VpcExpose::empty()
            .ip("4.4.0.0/16".into())
            .not("4.4.128.0/18".into())
            .as_range("44.4.0.0/16".into())
            .not_as("44.4.64.0/18".into());

        // VPC3 <-> VPC4
        let expose341 = VpcExpose::empty()
            .ip("192.168.100.0/24".into())
            .as_range("34.34.34.0/24".into());
        let expose431 = VpcExpose::empty().ip("4.4.0.0/24".into());

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

        let peering12 = VpcPeering::new("VPC-1--VPC-2", manifest12, manifest21);
        let peering31 = VpcPeering::new("VPC-3--VPC-1", manifest31, manifest13);
        let peering14 = VpcPeering::new("VPC-1--VPC-4", manifest14, manifest41);
        let peering24 = VpcPeering::new("VPC-2--VPC-4", manifest24, manifest42);
        let peering34 = VpcPeering::new("VPC-3--VPC-4", manifest34, manifest43);

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
            .ip("1.1.0.0/16".into())
            .as_range("2.2.0.0/16".into());
        let expose211 = VpcExpose::empty()
            .ip("1.2.2.0/24".into())
            .as_range("3.3.3.0/24".into());

        let mut manifest12 = VpcManifest::new("VPC-1");
        add_expose(&mut manifest12, expose121);
        let mut manifest21 = VpcManifest::new("VPC-2");
        add_expose(&mut manifest21, expose211);

        let peering12 = VpcPeering::new("VPC-1--VPC-2", manifest12, manifest21);

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
    ) -> (Ipv4Addr, Ipv4Addr, u16, u16) {
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

        let packets_out: Vec<_> = nat.process(vec![packet].into_iter()).collect();
        let hdr_out = packets_out[0].try_ipv4().unwrap();
        let udp_out = packets_out[0].try_udp().unwrap();

        (
            hdr_out.source().inner(),
            hdr_out.destination(),
            udp_out.source().into(),
            udp_out.destination().into(),
        )
    }

    #[test]
    #[traced_test]
    #[allow(clippy::too_many_lines)]
    fn test_full_config() {
        let mut config = build_sample_config(build_overlay_4vpcs());
        config.validate().unwrap();

        // Check that we can validate the allocator
        let (mut nat, mut allocator) = StatefulNat::new("test-nat");
        allocator
            .update_allocator(&config.external.overlay.vpc_table)
            .unwrap();

        // No NAT
        let (orig_src, orig_dst) = ("8.8.8.8", "9.9.9.9");
        let (output_src, output_dst, output_src_port, output_dst_port) =
            check_packet(&mut nat, vni(100), vni(200), orig_src, orig_dst, 9998, 443);
        assert_eq!(output_src, addr_v4(orig_src));
        assert_eq!(output_dst, addr_v4(orig_dst));
        assert_eq!(output_src_port, 9998);
        assert_eq!(output_dst_port, 443);

        // NAT: expose121 <-> expose211
        let (orig_src, orig_dst) = ("1.1.2.3", "10.201.201.18");
        let (target_src, target_dst) = ("10.12.0.0", "1.2.2.0");
        let (output_src, output_dst, output_src_port, output_dst_port) =
            check_packet(&mut nat, vni(100), vni(200), orig_src, orig_dst, 9998, 443);

        assert_eq!(output_src, addr_v4(target_src));
        assert_eq!(output_dst, addr_v4(target_dst));
        // Reverse path
        let (return_output_src, return_output_dst, return_output_src_port, return_output_dst_port) =
            check_packet(
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
        let (output_src, output_dst, output_src_port, output_dst_port) =
            check_packet(&mut nat, vni(100), vni(200), orig_src, orig_dst, 9998, 443);

        assert_eq!(output_src, addr_v4(target_src));
        assert_eq!(output_dst, addr_v4(target_dst));
        // Reverse path
        let (return_output_src, return_output_dst, return_output_src_port, return_output_dst_port) =
            check_packet(
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

        // Check new connection: valid source NAT but invalid destination NAT
        let (orig_src, orig_dst) = ("1.1.2.3", "10.201.201.17");
        let target_src = "2.2.0.0";
        let (output_src, output_dst, output_src_port, output_dst_port) =
            check_packet(&mut nat, vni(100), vni(200), orig_src, orig_dst, 9998, 80);
        assert_eq!(output_src, addr_v4(target_src));
        assert_eq!(output_dst, addr_v4(orig_dst));
        assert_eq!(output_dst_port, 80);
        // Reverse path
        let (return_output_src, return_output_dst, return_output_src_port, return_output_dst_port) =
            check_packet(
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

        // Check new valid connection
        let (orig_src, orig_dst) = ("1.1.2.3", "3.3.3.3");
        let (target_src, target_dst) = ("2.2.0.0", "1.2.2.0");
        let (output_src, output_dst, output_src_port, output_dst_port) =
            check_packet(&mut nat, vni(100), vni(200), orig_src, orig_dst, 9998, 80);
        assert_eq!(output_src, addr_v4(target_src));
        assert_eq!(output_dst, addr_v4(target_dst));
        // Reverse path
        let (return_output_src, return_output_dst, return_output_src_port, return_output_dst_port) =
            check_packet(
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
    }
}
