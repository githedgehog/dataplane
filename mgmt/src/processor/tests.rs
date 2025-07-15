// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#[cfg(test)]
#[allow(dead_code)]
pub mod test {
    use lpm::prefix::Prefix;
    use nat::stateless::NatTablesWriter;
    use net::eth::mac::Mac;
    use net::interface::Mtu;
    use tracing_test::traced_test;

    use crate::models::internal::device::settings::KernelPacketConfig;
    use crate::models::internal::device::settings::PacketDriver;
    use crate::models::internal::interfaces::interface::InterfaceConfig;
    use crate::models::internal::interfaces::interface::*;
    use crate::models::internal::routing::bgp::AfIpv4Ucast;
    use crate::models::internal::routing::bgp::AfL2vpnEvpn;
    use crate::models::internal::routing::bgp::BgpConfig;
    use crate::models::internal::routing::bgp::BgpNeighCapabilities;
    use crate::models::internal::routing::bgp::BgpNeighbor;
    use crate::models::internal::routing::bgp::BgpOptions;
    use crate::models::internal::routing::bgp::NeighSendCommunities;
    use crate::models::internal::routing::ospf::{OspfInterface, OspfNetwork};
    use crate::models::internal::routing::vrf::VrfConfig;
    use crate::models::internal::{device::DeviceConfig, routing::ospf::Ospf};
    use crate::{
        frr::renderer::builder::Render, models::internal::device::settings::DeviceSettings,
    };
    use caps::Capability::CAP_NET_ADMIN;
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use test_utils::with_caps;
    use tracing::{Level, error};

    use crate::processor::confbuild::internal::build_internal_config;

    //    use crate::models::internal::routing::evpn::VtepConfig;

    use crate::models::external::gwconfig::ExternalConfig;
    use crate::models::external::gwconfig::ExternalConfigBuilder;
    use crate::models::external::gwconfig::GwConfig;
    use crate::models::external::gwconfig::Underlay;
    // use crate::models::external::configdb::gwconfigdb::GwConfigDatabase;

    use crate::models::external::overlay::Overlay;
    use crate::models::external::overlay::vpc::{Vpc, VpcTable};
    use crate::models::external::overlay::vpcpeering::{
        VpcExpose, VpcManifest, VpcPeering, VpcPeeringTable,
    };

    use crate::processor::proc::ConfigProcessor;
    use routing::{Router, RouterParamsBuilder};
    use tracing::debug;

    use stats::VpcMapName;
    use vpcmap::map::VpcMapWriter;

    /* OVERLAY config sample builders */
    fn sample_vpc_table() -> VpcTable {
        let mut vpc_table = VpcTable::new();
        let _ = vpc_table.add(Vpc::new("VPC-1", "AAAAA", 3000).expect("Should succeed"));
        let _ = vpc_table.add(Vpc::new("VPC-2", "BBBBB", 4000).expect("Should succeed"));
        let _ = vpc_table.add(Vpc::new("VPC-3", "CCCCC", 2000).expect("Should succeed"));
        vpc_table
    }
    fn man_vpc1_with_vpc2() -> VpcManifest {
        let mut m1 = VpcManifest::new("VPC-1");
        let expose = VpcExpose::empty()
            .ip(Prefix::expect_from(("192.168.60.0", 24)))
            .not(Prefix::expect_from(("192.168.60.13", 32)));
        m1.add_expose(expose).expect("Should succeed");

        let expose = VpcExpose::empty()
            .ip(Prefix::expect_from(("192.168.50.0", 24)))
            .as_range(Prefix::expect_from(("100.100.50.0", 24)));
        m1.add_expose(expose).expect("Should succeed");

        let expose = VpcExpose::empty()
            .ip(Prefix::expect_from(("192.168.30.0", 24)))
            .as_range(Prefix::expect_from(("100.100.30.0", 24)));
        m1.add_expose(expose).expect("Should succeed");
        m1
    }
    fn man_vpc2_with_vpc1() -> VpcManifest {
        let mut m1 = VpcManifest::new("VPC-2");
        let expose = VpcExpose::empty()
            .ip(Prefix::expect_from(("192.168.80.0", 24)))
            .not(Prefix::expect_from(("192.168.80.2", 32)));
        m1.add_expose(expose).expect("Should succeed");

        let expose = VpcExpose::empty()
            .ip(Prefix::expect_from(("192.168.70.0", 24)))
            .as_range(Prefix::expect_from(("200.200.70.0", 24)));
        m1.add_expose(expose).expect("Should succeed");

        let expose = VpcExpose::empty()
            .ip(Prefix::expect_from(("192.168.90.0", 24)))
            .as_range(Prefix::expect_from(("200.200.90.0", 24)));
        m1.add_expose(expose).expect("Should succeed");
        m1
    }
    fn man_vpc1_with_vpc3() -> VpcManifest {
        let mut m1 = VpcManifest::new("VPC-1");
        let expose = VpcExpose::empty()
            .ip(Prefix::expect_from(("192.168.60.0", 24)))
            .as_range(Prefix::expect_from(("100.100.60.0", 24)));
        m1.add_expose(expose).expect("Should succeed");
        m1
    }
    fn man_vpc3_with_vpc1() -> VpcManifest {
        let mut m1 = VpcManifest::new("VPC-3");
        let expose = VpcExpose::empty()
            .ip(Prefix::expect_from(("192.168.128.0", 27)))
            .as_range(Prefix::expect_from(("100.30.128.0", 27)));
        m1.add_expose(expose).expect("Should succeed");

        let expose = VpcExpose::empty()
            .ip(Prefix::expect_from(("192.168.100.0", 24)))
            .as_range(Prefix::expect_from(("192.168.100.0", 24)));
        m1.add_expose(expose).expect("Should succeed");
        m1
    }
    fn sample_vpc_peering_table() -> VpcPeeringTable {
        let mut peering_table = VpcPeeringTable::new();
        peering_table
            .add(VpcPeering::new(
                "VPC-1--VPC-2",
                man_vpc1_with_vpc2(),
                man_vpc2_with_vpc1(),
            ))
            .expect("Should succeed");

        peering_table
            .add(VpcPeering::new(
                "VPC-1--VPC-3",
                man_vpc1_with_vpc3(),
                man_vpc3_with_vpc1(),
            ))
            .expect("Should succeed");

        peering_table
    }
    fn sample_overlay() -> Overlay {
        let vpc_table = sample_vpc_table();
        let peering_table = sample_vpc_peering_table();
        /* Overlay config */
        Overlay::new(vpc_table, peering_table)
    }

    /* DEVICE configuration */
    fn sample_device_config() -> DeviceConfig {
        /* device settings */
        let settings = DeviceSettings::new("GW1")
            .set_loglevel(Level::DEBUG)
            .set_packet_driver(PacketDriver::Kernel(KernelPacketConfig {}));

        /* device config */
        DeviceConfig::new(settings)
    }

    /* UNDERLAY, default VRF BGP AF configs */
    fn sample_config_bgp_default_vrf_af_config(bgp: &mut BgpConfig) {
        /* build AF L2vn evpn config */
        let af_l2vpn_evpn = AfL2vpnEvpn::new()
            .set_adv_all_vni(true)
            .set_adv_svi_ip(false)
            .set_adv_default_gw(false);

        /* build AF IPv4 unicast config */
        let af_ipv4unicast = AfIpv4Ucast::new();

        /* set them in bgp config */
        bgp.set_af_ipv4unicast(af_ipv4unicast);
        bgp.set_af_l2vpn_evpn(af_l2vpn_evpn);
    }

    /* UNDERLAY, default VRF BGP config */
    fn sample_config_bgp_default_vrf(asn: u32, loopback: IpAddr, router_id: Ipv4Addr) -> BgpConfig {
        let mut bgp = BgpConfig::new(asn);
        bgp.set_router_id(router_id);
        bgp.set_bgp_options(BgpOptions::default());

        /* configure address AFs */
        sample_config_bgp_default_vrf_af_config(&mut bgp);

        /* build capabilities for neighbor */
        let capabilities: BgpNeighCapabilities = BgpNeighCapabilities::new()
            .dynamic(true)
            .ext_nhop(true)
            .software_ver(true);

        /* add neighbor */
        let neigh = BgpNeighbor::new_host(IpAddr::from_str("7.0.0.2").expect("Bad address"))
            .set_remote_as(65000)
            .set_description("Spine switch")
            .set_update_source_address(loopback)
            .set_send_community(NeighSendCommunities::All)
            .l2vpn_evpn_activate(true)
            .ipv4_unicast_activate(false)
            .set_allow_as_in(false)
            .set_capabilities(capabilities)
            .set_default_originate(false);

        bgp.add_neighbor(neigh);
        bgp
    }

    /* UNDERLAY, default VRF OSPF config */
    fn sample_config_ospf_default_vrf(router_id: Ipv4Addr) -> Ospf {
        Ospf::new(router_id)
    }

    /* UNDERLAY, default VRF interface table */
    fn sample_config_default_vrf_interfaces(vrf_cfg: &mut VrfConfig, loopback: IpAddr) {
        /* configure loopback interface */
        let ospf =
            OspfInterface::new(Ipv4Addr::from_str("0.0.0.0").expect("Bad area")).set_passive(true);
        let lo = InterfaceConfig::new("lo", InterfaceType::Loopback, false)
            .set_description("Main loopback interface")
            .add_address(loopback, 32)
            .set_ospf(ospf);
        vrf_cfg.add_interface_config(lo);

        let vtep_addr = match loopback {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(_) => panic!("Bad Vtep address from loopback, address must be IPv4"),
        };
        let vtep = InterfaceConfig::new(
            "vtep",
            InterfaceType::Vtep(IfVtepConfig {
                mac: Some(Mac::from([0xca, 0xfe, 0xba, 0xbe, 0x00, 0x01])),
                local: vtep_addr,
                ttl: None,
                vni: None,
            }),
            false,
        );
        vrf_cfg.add_interface_config(vtep);

        /* configure eth0 interface */
        let ospf = OspfInterface::new(Ipv4Addr::from_str("0.0.0.0").expect("Bad area"))
            .set_passive(false)
            .set_network(OspfNetwork::Point2Point);
        let eth0 = InterfaceConfig::new(
            "eth0",
            InterfaceType::Ethernet(IfEthConfig { mac: None }),
            false,
        )
        .set_description("Link to spine")
        .add_address(IpAddr::from_str("10.0.0.14").expect("Bad address"), 30)
        .set_ospf(ospf);
        vrf_cfg.add_interface_config(eth0);

        /* configure eth1 interface */
        let eth1 = InterfaceConfig::new(
            "eth1",
            InterfaceType::Ethernet(IfEthConfig { mac: None }),
            false,
        )
        .set_description("Link to external device ext-1")
        .add_address(IpAddr::from_str("172.16.0.1").expect("Bad address"), 24)
        .set_mtu(Mtu::try_from(1500).expect("Bad MTU"));
        vrf_cfg.add_interface_config(eth1);

        /* configure eth2 interface */
        let ospf = OspfInterface::new(Ipv4Addr::from_str("0.0.0.0").expect("Bad area"))
            .set_passive(false)
            .set_network(OspfNetwork::Point2Point);
        let eth2 = InterfaceConfig::new(
            "eth2",
            InterfaceType::Ethernet(IfEthConfig { mac: None }),
            false,
        )
        .set_description("Link to spine")
        .add_address(IpAddr::from_str("10.0.1.14").expect("Bad address"), 30)
        .set_ospf(ospf);
        vrf_cfg.add_interface_config(eth2);
    }

    /* UNDERLAY, default VRF */
    fn sample_config_default_vrf(asn: u32, loopback: IpAddr, router_id: Ipv4Addr) -> VrfConfig {
        /* create default vrf config object */
        let mut vrf_cfg = VrfConfig::new("default", None, true);

        /* Add BGP configuration */
        let bgp = sample_config_bgp_default_vrf(asn, loopback, router_id);
        vrf_cfg.set_bgp(bgp);

        /* Add OSPF configuration */
        let ospf = sample_config_ospf_default_vrf(router_id);
        vrf_cfg.set_ospf(ospf);

        /* Add interface configuration */
        sample_config_default_vrf_interfaces(&mut vrf_cfg, loopback);
        vrf_cfg
    }

    fn get_v4_addr(address: IpAddr) -> Ipv4Addr {
        match address {
            IpAddr::V4(a) => a,
            _ => panic!("Can't get ipv4 from ipv6"),
        }
    }

    /* build sample underlay config */
    fn sample_underlay_config() -> Underlay {
        /* main loopback for BGP and vtep */
        let loopback = IpAddr::from_str("7.0.0.100").expect("Bad address");
        let router_id = get_v4_addr(loopback);
        let asn = 65000;

        let default_vrf = sample_config_default_vrf(asn, loopback, router_id);
        Underlay { vrf: default_vrf }
    }

    /* build sample external config as it would be received via gRPC */
    pub fn sample_external_config() -> ExternalConfig {
        /* build sample DEVICE config and add it to config */
        let device_cfg = sample_device_config();

        /* build sample UNDERLAY config */
        let underlay = sample_underlay_config();

        /* build sample OVERLAY config (VPCs and peerings) and add it to config */
        let overlay = sample_overlay();

        /* assemble external config */
        let mut external_builder = ExternalConfigBuilder::default();
        external_builder.genid(1);
        external_builder.device(device_cfg);
        external_builder.underlay(underlay);
        external_builder.overlay(overlay);
        external_builder.build().expect("Should succeed")

        /* set VTEP configuration: FIXME, need to accommodate this to internal model */
        //let vtep = VtepConfig::new(loopback, Mac::from([0x2, 0x0, 0x0, 0x0, 0xaa, 0xbb]));
    }

    #[traced_test]
    #[test]
    fn check_frr_config() {
        /* Not really a test but a tool to check generated FRR configs given a gateway config */
        let external = sample_external_config();
        let mut config = GwConfig::new(external);
        config.validate().expect("Config validation failed");
        if false {
            let vpc_table = &config.external.overlay.vpc_table;
            let peering_table = &config.external.overlay.peering_table;
            println!("\n{vpc_table}\n{peering_table}");
        }
        let internal = build_internal_config(&config).expect("Should succeed");
        let rendered = internal.render(&config.genid());
        println!("{rendered}");
    }

    #[traced_test]
    #[tokio::test]
    #[fixin::wrap(with_caps([CAP_NET_ADMIN]))]
    async fn test_sample_config() {
        /* build sample external config */
        let external = sample_external_config();

        /* build a gw config from a sample external config */
        let config = GwConfig::new(external);

        /* build router config */
        let router_params = RouterParamsBuilder::default()
            .cpi_sock_path("/tmp/cpi.sock")
            .cli_sock_path("/tmp/cli.sock")
            .frr_agent_path("/tmp/frr-agent.sock")
            .build()
            .expect("Should succeed due to defaults");

        /* start router */
        let router = Router::new(router_params);
        if let Err(e) = &router {
            error!("New router failed: {e}");
            panic!();
        }
        let mut router = router.unwrap();

        /* router control */
        let ctl = router.get_ctl_tx();

        /* vpcmappings for vpc name resolution for vpc stats */
        let vpcmapw = VpcMapWriter::<VpcMapName>::new();

        /* crate NatTables for stateless nat */
        let nattablesw = NatTablesWriter::new();

        /* build config processor to test the processing of a config. The processor embeds the config database
        and has the frrmi. In this test, we don't use any channel to communicate the config. */
        let (mut processor, _sender) = ConfigProcessor::new(ctl, vpcmapw, nattablesw);

        /* let the processor process the config */
        match processor.process_incoming_config(config).await {
            Ok(()) => {}
            Err(e) => {
                error!("{e}");
                panic!("{e}");
            }
        }

        /* stop the router */
        debug!("Stopping the router...");
        router.stop();
    }
}
