// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! NAT configuration tests .. and actual NAT function

#[cfg(test)]
mod tests {
    use config::GwConfig;
    use config::external::ExternalConfigBuilder;
    use config::external::overlay::Overlay;
    use config::external::overlay::vpc::{Peering, Vpc, VpcTable};
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

    use crate::StatelessNat;
    use crate::stateless::setup::build_nat_configuration;
    use crate::stateless::setup::tables::{NatTables, PerVniTable};

    use net::buffer::PacketBufferMut;
    use net::eth::mac::Mac;
    use net::headers::{TryHeadersMut, TryIpv4, TryIpv4Mut};
    use net::packet::Packet;
    use net::packet::test_utils::build_test_ipv4_packet;
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

    fn get_src_ip_v4<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> Ipv4Addr {
        packet
            .get_headers()
            .try_ipv4()
            .expect("Failed to get IPv4 header")
            .source()
            .inner()
    }

    fn get_dst_ip_v4<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> Ipv4Addr {
        packet
            .get_headers()
            .try_ipv4()
            .expect("Failed to get IPv4 header")
            .destination()
    }

    fn set_addresses_v4<Buf: PacketBufferMut>(
        packet: &mut Packet<Buf>,
        src_addr: Ipv4Addr,
        dst_addr: Ipv4Addr,
    ) -> &Packet<Buf> {
        let hdr = packet
            .headers_mut()
            .try_ipv4_mut()
            .expect("Failed to get IPv4 header");
        hdr.set_source(src_addr.try_into().expect("Invalid Unicast IPv4 address"));
        hdr.set_destination(dst_addr);
        packet
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
        //         - cidr: 5.5.0.0/17
        //         - cidr: 5.6.0.0/17  # <- 5.6.7.8 will match here
        //         - not: 5.6.0.0/24   # to account for when computing the offset
        //         - not: 5.6.8.0/24
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
            .as_range("5.5.0.0/17".into())
            .as_range("5.6.0.0/17".into())
            .not_as("5.6.0.0/24".into())
            .not_as("5.6.8.0/24".into());

        let manifest2 = VpcManifest {
            name: "VPC-2".into(),
            exposes: vec![expose3, expose4],
        };

        let peering1 = Peering {
            name: "test_peering1".into(),
            local: manifest1.clone(),
            remote: manifest2.clone(),
            remote_id: "12345".try_into().expect("Failed to create VPC ID"),
        };
        let peering2 = Peering {
            name: "test_peering2".into(),
            local: manifest2,
            remote: manifest1,
            remote_id: "67890".try_into().expect("Failed to create VPC ID"),
        };

        // This code is extremely convoluted
        let mut vpctable = VpcTable::new();

        // vpc-1
        let vni1 = Vni::new_checked(100).unwrap();
        let mut vpc1 = Vpc::new("VPC-1", "67890", vni1.as_u32()).unwrap();
        vpc1.peerings.push(peering1.clone());
        vpctable.add(vpc1).unwrap();

        // vpc-2
        let vni2 = Vni::new_checked(200).unwrap();
        let mut vpc2 = Vpc::new("VPC-2", "12345", vni2.as_u32()).unwrap();
        vpc2.peerings.push(peering2.clone());
        vpctable.add(vpc2).unwrap();

        let mut nat_table = NatTables::new();

        let mut vni_table1 = PerVniTable::new(vni1);
        vni_table1
            .add_peering(&peering1, vni2)
            .expect("Failed to build NAT tables");

        let mut vni_table2 = PerVniTable::new(vni2);
        vni_table2
            .add_peering(&peering2, vni1)
            .expect("Failed to build NAT tables");

        nat_table.add_table(vni_table1);
        nat_table.add_table(vni_table2);

        nat_table
    }

    #[test]
    fn test_dst_nat_stateless_44() {
        const TARGET_SRC_IP: Ipv4Addr = Ipv4Addr::new(2, 2, 0, 4);
        const TARGET_DST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 136, 8);

        let nat_tables = build_context();
        let (mut nat, mut tablesw) = StatelessNat::new("stateless-nat");
        tablesw.update_nat_tables(nat_tables);

        let mut packet = build_test_ipv4_packet(u8::MAX).unwrap();
        let mut packet_reply = packet.clone();
        packet.get_meta_mut().src_vni = Some(vni(100));
        packet.get_meta_mut().dst_vni = Some(vni(200));
        packet_reply.get_meta_mut().src_vni = Some(vni(200));
        packet_reply.get_meta_mut().dst_vni = Some(vni(100));
        packet.get_meta_mut().set_nat(true);
        packet_reply.get_meta_mut().set_nat(true);

        let orig_src_ip = get_src_ip_v4(&packet);
        let orig_dst_ip = get_dst_ip_v4(&packet);

        // Check request. We expect:
        //
        // {orig_src_ip, orig_dst_ip} -> {orig_src_ip, TARGET_DST_IP}
        let packets_out: Vec<_> = nat.process(vec![packet].into_iter()).collect();
        assert_eq!(packets_out.len(), 1);

        let hdr_out = &packets_out[0]
            .try_ipv4()
            .expect("Failed to get IPv4 header");
        println!("L3 header: {hdr_out:?}");
        assert_eq!(hdr_out.source().inner(), TARGET_SRC_IP);
        assert_eq!(hdr_out.destination(), TARGET_DST_IP);

        // Check that reply gets reverse source NAT. We expect:
        //
        // {TARGET_DST_IP, orig_src_ip} -> {orig_dst_ip, orig_src_ip}
        set_addresses_v4(&mut packet_reply, TARGET_DST_IP, TARGET_SRC_IP);

        let packets_out_reply: Vec<_> = nat.process(vec![packet_reply].into_iter()).collect();
        assert_eq!(packets_out_reply.len(), 1);

        let hdr_out_reply = &packets_out_reply[0]
            .try_ipv4()
            .expect("Failed to get IPv4 header");
        println!("L3 header: {hdr_out_reply:?}");
        assert_eq!(hdr_out_reply.source().inner(), orig_dst_ip);
        assert_eq!(hdr_out_reply.destination(), orig_src_ip);
    }

    #[allow(clippy::too_many_lines)]
    fn build_sample_config() -> GwConfig {
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

        let overlay = Overlay::new(vpc_table, peering_table);

        // Now comes some default configuration to build a valid GwConfig, not really relevant to
        // our tests

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
        let underlay = Underlay { vrf: vrf_config };

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

    fn check_packet(
        nat: &mut StatelessNat,
        src_vni: Vni,
        dst_vni: Vni,
        orig_src_ip: Ipv4Addr,
        orig_dst_ip: Ipv4Addr,
    ) -> (Ipv4Addr, Ipv4Addr) {
        let mut packet = build_test_ipv4_packet(u8::MAX).unwrap();
        packet.get_meta_mut().set_nat(true);
        packet.get_meta_mut().src_vni = Some(src_vni);
        packet.get_meta_mut().dst_vni = Some(dst_vni);
        set_addresses_v4(&mut packet, orig_src_ip, orig_dst_ip);

        let packets_out: Vec<_> = nat.process(vec![packet].into_iter()).collect();
        let hdr_out = packets_out[0]
            .try_ipv4()
            .expect("Failed to get IPv4 header");

        (hdr_out.source().inner(), hdr_out.destination())
    }

    #[test]
    #[traced_test]
    #[allow(clippy::too_many_lines)]
    fn test_full_config() {
        let mut config = build_sample_config();
        config.validate().expect("Failed to validate config");

        let nat_tables = build_nat_configuration(&config.external.overlay).unwrap();
        println!("Nat tables: {:#?}", &nat_tables);

        let (mut nat, mut tablesw) = StatelessNat::new("stateless-nat");
        tablesw.update_nat_tables(nat_tables.clone());

        // Template for other packets
        let _pt = build_test_ipv4_packet(u8::MAX).unwrap();

        // No NAT
        let (orig_src, orig_dst) = (addr_v4("8.8.8.8"), addr_v4("9.9.9.9"));
        let (output_src, output_dst) =
            check_packet(&mut nat, vni(100), vni(200), orig_src, orig_dst);
        assert_eq!(output_src, orig_src);
        assert_eq!(output_dst, orig_dst);

        // expose121 <-> expose211
        let (orig_src, orig_dst) = (addr_v4("1.1.2.3"), addr_v4("10.201.201.18"));
        let (target_src, target_dst) = (addr_v4("10.12.2.3"), addr_v4("1.2.2.18"));
        let (output_src, output_dst) =
            check_packet(&mut nat, vni(100), vni(200), orig_src, orig_dst);
        assert_eq!(output_src, target_src);
        assert_eq!(output_dst, target_dst);
        // Reverse path
        let (output_src, output_dst) =
            check_packet(&mut nat, vni(200), vni(100), target_dst, target_src);
        assert_eq!(output_src, orig_dst);
        assert_eq!(output_dst, orig_src);

        // expose122 <-> expose211
        let (orig_src, orig_dst) = (addr_v4("1.2.129.3"), addr_v4("10.201.201.22"));
        let (target_src, target_dst) = (addr_v4("10.99.1.3"), addr_v4("1.2.2.22"));
        let (output_src, output_dst) =
            check_packet(&mut nat, vni(100), vni(200), orig_src, orig_dst);
        assert_eq!(output_src, target_src);
        assert_eq!(output_dst, target_dst);
        // Reverse path
        let (output_src, output_dst) =
            check_packet(&mut nat, vni(200), vni(100), target_dst, target_src);
        assert_eq!(output_src, orig_dst);
        assert_eq!(output_dst, orig_src);

        // expose123 <-> expose214
        let (orig_src, orig_dst) = (addr_v4("1.3.0.7"), addr_v4("10.201.204.193"));
        let (target_src, target_dst) = (addr_v4("10.100.0.7"), addr_v4("2.0.1.1"));
        let (output_src, output_dst) =
            check_packet(&mut nat, vni(100), vni(200), orig_src, orig_dst);
        assert_eq!(output_src, target_src);
        assert_eq!(output_dst, target_dst);
        // Reverse path
        let (output_src, output_dst) =
            check_packet(&mut nat, vni(200), vni(100), target_dst, target_src);
        assert_eq!(output_src, orig_dst);
        assert_eq!(output_dst, orig_src);

        // expose131 <-> expose311 (reusing expose121 private IPs)
        let (orig_src, orig_dst) = (addr_v4("1.1.3.3"), addr_v4("3.3.3.3"));
        let (target_src, target_dst) = (addr_v4("3.3.3.3"), addr_v4("192.168.128.3"));
        let (output_src, output_dst) =
            check_packet(&mut nat, vni(100), vni(300), orig_src, orig_dst);
        assert_eq!(output_src, target_src);
        assert_eq!(output_dst, target_dst);
        // Reverse path
        let (output_src, output_dst) =
            check_packet(&mut nat, vni(300), vni(100), target_dst, target_src);
        assert_eq!(output_src, orig_dst);
        assert_eq!(output_dst, orig_src);

        // expose132 <-> expose311
        let (orig_src, orig_dst) = (addr_v4("1.2.130.1"), addr_v4("3.3.3.3"));
        let (target_src, target_dst) = (addr_v4("3.2.2.1"), addr_v4("192.168.128.3"));
        let (output_src, output_dst) =
            check_packet(&mut nat, vni(100), vni(300), orig_src, orig_dst);
        assert_eq!(output_src, target_src);
        assert_eq!(output_dst, target_dst);
        // Reverse path
        let (output_src, output_dst) =
            check_packet(&mut nat, vni(300), vni(100), target_dst, target_src);
        assert_eq!(output_src, orig_dst);
        assert_eq!(output_dst, orig_src);

        // expose141 <-> expose411
        let (orig_src, orig_dst) = (addr_v4("1.1.1.1"), addr_v4("4.5.1.1"));
        let (target_src, target_dst) = (addr_v4("4.4.1.1"), addr_v4("1.1.1.1"));
        let (output_src, output_dst) =
            check_packet(&mut nat, vni(100), vni(400), orig_src, orig_dst);
        assert_eq!(output_src, target_src);
        assert_eq!(output_dst, target_dst);
        // Reverse path
        let (output_src, output_dst) =
            check_packet(&mut nat, vni(400), vni(100), target_dst, target_src);
        assert_eq!(output_src, orig_dst);
        assert_eq!(output_dst, orig_src);

        // expose241 <-> expose421 (first/last addresses of ranges)
        let (orig_src, orig_dst) = (addr_v4("2.4.255.255"), addr_v4("44.4.0.0"));
        let (target_src, target_dst) = (addr_v4("44.0.255.255"), addr_v4("4.4.0.0"));
        let (output_src, output_dst) =
            check_packet(&mut nat, vni(200), vni(400), orig_src, orig_dst);
        assert_eq!(output_src, target_src);
        assert_eq!(output_dst, target_dst);
        // Reverse path
        let (output_src, output_dst) =
            check_packet(&mut nat, vni(400), vni(200), target_dst, target_src);
        assert_eq!(output_src, orig_dst);
        assert_eq!(output_dst, orig_src);

        // expose241 <-> expose421 (playing with not/not_as)
        let (orig_src, orig_dst) = (addr_v4("2.4.2.1"), addr_v4("44.4.136.2"));
        let (target_src, target_dst) = (addr_v4("44.0.1.1"), addr_v4("4.4.72.2"));
        let (output_src, output_dst) =
            check_packet(&mut nat, vni(200), vni(400), orig_src, orig_dst);
        assert_eq!(output_src, target_src);
        assert_eq!(output_dst, target_dst);
        // Reverse path
        let (output_src, output_dst) =
            check_packet(&mut nat, vni(400), vni(200), target_dst, target_src);
        assert_eq!(output_src, orig_dst);
        assert_eq!(output_dst, orig_src);

        // expose341 <-> expose431 (one-side NAT)
        let (orig_src, orig_dst) = (addr_v4("192.168.100.34"), addr_v4("4.4.0.43"));
        let (target_src, target_dst) = (addr_v4("34.34.34.34"), addr_v4("4.4.0.43"));
        let (output_src, output_dst) =
            check_packet(&mut nat, vni(300), vni(400), orig_src, orig_dst);
        assert_eq!(output_src, target_src);
        assert_eq!(output_dst, target_dst);
        // Reverse path
        let (output_src, output_dst) =
            check_packet(&mut nat, vni(400), vni(300), target_dst, target_src);
        assert_eq!(output_src, orig_dst);
        assert_eq!(output_dst, orig_src);
    }
}
