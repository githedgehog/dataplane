// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

/// How many cases a run needs before a health check may assert on a *rate*.
///
/// The properties below print how much of their input reached the interesting part and
/// then assert that the fraction has not collapsed. Those assertions are only meaningful
/// when there is a sample behind them: under miri and under qemu a property gets a
/// handful of cases, where a ratio measures nothing and a threshold is pure flake. Below
/// this many cases the counts are still printed, and coverage data is the thing to watch.
#[cfg(test)]
const ENOUGH_CASES: usize = 200;

#[cfg(test)]
#[allow(dead_code)]
pub mod test {
    use acl_filter::AclFilterContextWriter;
    use config::external::communities::PriorityCommunityTable;
    use config::external::gwgroup::GwGroup;
    use config::external::gwgroup::GwGroupMember;
    use config::external::gwgroup::GwGroupTable;

    use flow_entry::flow_table::FlowTable;
    use lpm::prefix::Prefix;
    use net::eth::mac::Mac;
    use net::interface::Mtu;
    use pipeline::PipelineData;
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use tracing_test::traced_test;

    use config::external::ExternalConfigBuilder;
    use config::external::overlay::Overlay;
    use config::external::overlay::vpc::{Vpc, VpcTable};
    use config::external::overlay::vpcpeering::{
        VpcExpose, VpcManifest, VpcPeering, VpcPeeringTable,
    };
    use config::external::underlay::Underlay;

    use config::ExternalConfig;
    use config::internal::device::DeviceConfig;
    use config::internal::interfaces::interface::{
        IfEthConfig, IfVtepConfig, InterfaceConfig, InterfaceType,
    };
    use config::internal::routing::bgp::*;
    use config::internal::routing::ospf::{Ospf, OspfInterface, OspfNetwork};
    use config::internal::routing::vrf::VrfConfig;

    use routing::Render;

    use crate::processor::confbuild::internal::build_internal_config;
    use crate::processor::proc::{ConfigProcessor, ConfigProcessorParams};
    use concurrency::sync::Arc;
    use config::internal::status::DataplaneStatus;
    use flow_filter::FlowFilterContextWriter;
    use nat::masquerade::NatAllocatorWriter;
    use nat::portfw::PortFwTableWriter;
    use nat::static_nat::NatTablesWriter;
    use routing::{Router, RouterParamsBuilder};
    use stats::VpcMapName;
    use stats::VpcStatsStore;
    use tokio::sync::RwLock;
    use tracectl::get_trace_ctl;
    use tracing::{debug, error};
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
            .ip(Prefix::expect_from(("192.168.60.0", 24)).into())
            .not(Prefix::expect_from(("192.168.60.13", 32)).into());
        m1.add_expose(expose);

        let expose = VpcExpose::empty()
            .make_static_nat()
            .unwrap()
            .ip(Prefix::expect_from(("192.168.50.0", 24)).into())
            .as_range(Prefix::expect_from(("100.100.50.0", 24)).into())
            .unwrap();
        m1.add_expose(expose);

        let expose = VpcExpose::empty()
            .make_static_nat()
            .unwrap()
            .ip(Prefix::expect_from(("192.168.30.0", 24)).into())
            .as_range(Prefix::expect_from(("100.100.30.0", 24)).into())
            .unwrap();
        m1.add_expose(expose);
        m1
    }
    fn man_vpc2_with_vpc1() -> VpcManifest {
        let mut m1 = VpcManifest::new("VPC-2");
        let expose = VpcExpose::empty()
            .ip(Prefix::expect_from(("192.168.80.0", 24)).into())
            .not(Prefix::expect_from(("192.168.80.2", 32)).into());
        m1.add_expose(expose);

        let expose = VpcExpose::empty()
            .make_static_nat()
            .unwrap()
            .ip(Prefix::expect_from(("192.168.70.0", 24)).into())
            .as_range(Prefix::expect_from(("200.200.70.0", 24)).into())
            .unwrap();
        m1.add_expose(expose);

        let expose = VpcExpose::empty()
            .make_static_nat()
            .unwrap()
            .ip(Prefix::expect_from(("192.168.90.0", 24)).into())
            .as_range(Prefix::expect_from(("200.200.90.0", 24)).into())
            .unwrap();
        m1.add_expose(expose);
        m1
    }
    fn man_vpc1_with_vpc3() -> VpcManifest {
        let mut m1 = VpcManifest::new("VPC-1");
        let expose = VpcExpose::empty()
            .make_static_nat()
            .unwrap()
            .ip(Prefix::expect_from(("192.168.60.0", 24)).into())
            .as_range(Prefix::expect_from(("100.100.60.0", 24)).into())
            .unwrap();
        m1.add_expose(expose);
        m1
    }
    fn man_vpc3_with_vpc1() -> VpcManifest {
        let mut m1 = VpcManifest::new("VPC-3");
        let expose = VpcExpose::empty()
            .make_static_nat()
            .unwrap()
            .ip(Prefix::expect_from(("192.168.128.0", 27)).into())
            .as_range(Prefix::expect_from(("100.30.128.0", 27)).into())
            .unwrap();
        m1.add_expose(expose);

        let expose = VpcExpose::empty()
            .make_static_nat()
            .unwrap()
            .ip(Prefix::expect_from(("192.168.100.0", 24)).into())
            .as_range(Prefix::expect_from(("192.168.100.0", 24)).into())
            .unwrap();
        m1.add_expose(expose);
        m1
    }
    fn sample_vpc_peering_table() -> VpcPeeringTable {
        let mut peering_table = VpcPeeringTable::new();
        peering_table
            .add(VpcPeering::new(
                "VPC-1--VPC-2",
                man_vpc1_with_vpc2(),
                man_vpc2_with_vpc1(),
                "gw-group-1".to_string(),
            ))
            .expect("Should succeed");

        peering_table
            .add(VpcPeering::new(
                "VPC-1--VPC-3",
                man_vpc1_with_vpc3(),
                man_vpc3_with_vpc1(),
                "gw-group-1".to_string(),
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
    pub(super) fn sample_device_config() -> DeviceConfig {
        DeviceConfig::new()
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
        let mut neigh = BgpNeighbor::new_host(IpAddr::from_str("7.0.0.2").expect("Bad address"))
            .set_remote_as(65000)
            .set_description("Spine switch")
            .set_update_source_address(loopback)
            .set_send_community(NeighSendCommunities::All)
            .set_allow_as_in(false)
            .set_capabilities(capabilities)
            .set_default_originate(false);
        neigh.l2vpn_evpn_activate(BgpNeighAF::default());

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
    pub(super) fn sample_underlay_config() -> Underlay {
        /* main loopback for BGP and vtep */
        let loopback = IpAddr::from_str("7.0.0.100").expect("Bad address");
        let router_id = get_v4_addr(loopback);
        let asn = 65000;

        let default_vrf = sample_config_default_vrf(asn, loopback, router_id);
        Underlay {
            vrf: default_vrf,
            vtep: None,
        }
    }

    #[rustfmt::skip]
    pub(super) fn sample_gw_groups() -> GwGroupTable {
        let mut gwt = GwGroupTable::new();
        let mut group = GwGroup::new("gw-group-1");
        group.add_member(GwGroupMember::new("gw1", 1, IpAddr::from_str("172.128.0.1").unwrap())).unwrap();
        group.add_member(GwGroupMember::new("gw2", 2, IpAddr::from_str("172.128.0.2").unwrap())).unwrap();
        group.add_member(GwGroupMember::new("gw3", 3, IpAddr::from_str("172.128.0.3").unwrap())).unwrap();
        gwt.add_group(group).unwrap();

        let mut group = GwGroup::new("gw-group-2");
        group.add_member(GwGroupMember::new("gw2", 2, IpAddr::from_str("172.128.0.2").unwrap())).unwrap();
        group.add_member(GwGroupMember::new("gw3", 1, IpAddr::from_str("172.128.0.3").unwrap())).unwrap();
        gwt.add_group(group).unwrap();
        gwt
    }

    pub(super) fn sample_community_table() -> PriorityCommunityTable {
        let mut comtable = PriorityCommunityTable::new();
        comtable.insert(0, "65000:800").unwrap();
        comtable.insert(1, "65000:801").unwrap();
        comtable.insert(2, "65000:802").unwrap();
        comtable.insert(3, "65000:803").unwrap();
        comtable.insert(4, "65000:804").unwrap();
        comtable
    }

    /* build sample external config as it would be received via gRPC/k8s */
    pub fn sample_external_config() -> ExternalConfig {
        /* build sample DEVICE config and add it to config */
        let device_cfg = sample_device_config();

        /* build sample UNDERLAY config */
        let underlay = sample_underlay_config();

        /* build sample OVERLAY config (VPCs and peerings) and add it to config */
        let overlay = sample_overlay();

        /* build sample gateway groups */
        let groups = sample_gw_groups();

        /* build sample community table */
        let comtable = sample_community_table();

        /* assemble external config */
        ExternalConfigBuilder::default()
            .gwname("test-gw".to_string())
            .genid(1)
            .device(device_cfg)
            .underlay(underlay)
            .overlay(overlay)
            .gwgroups(groups)
            .communities(comtable)
            .build()
            .expect("Should succeed")
    }

    #[cfg_attr(not(emulated), traced_test)]
    #[test]
    fn check_frr_config() {
        /* Not really a test but a tool to check generated FRR configs given a gateway config */
        let external = sample_external_config();
        let peering_table = external.overlay.peering_table.clone();
        let validated_config = external.validate().expect("Config validation failed");
        if false {
            let vpc_table = validated_config.external().overlay().vpc_table();
            println!("\n{}\n{peering_table}", vpc_table.as_summary());
        }
        let bmp_config = None;
        let internal =
            build_internal_config(&validated_config, bmp_config).expect("Should succeed");
        let rendered = internal.render(&validated_config.genid());
        println!("{rendered}");
    }

    #[ignore = "temporarily disabled during vm test runner refactor"]
    #[n_vm::in_vm]
    #[tokio::test]
    async fn test_sample_config() {
        // Applying the config builds the rte_acl-backed ACL filter and flow-filter contexts, which
        // need the EAL up
        let _eal = dpdk::test_support::start_eal();

        get_trace_ctl()
            .setup_from_string("cpi=debug,mgmt=debug,routing=debug")
            .unwrap();

        /* build sample external config */
        let external = sample_external_config();
        println!("External config is:\n{external:#?}");

        let dp_status_r: Arc<RwLock<DataplaneStatus>> =
            Arc::new(RwLock::new(DataplaneStatus::new()));

        /* build router config */
        let router_params = RouterParamsBuilder::default()
            .cpi_sock_path("/tmp/cpi.sock")
            .cli_sock_path("/tmp/cli.sock")
            .frr_agent_path("/tmp/frr-agent.sock")
            .build()
            .expect("Should succeed due to defaults");

        /* start router */
        let test_router = lifecycle::Subsystem::new("router", lifecycle::CancellationToken::new());
        let router = Router::new(&test_router, router_params, None);
        if let Err(e) = &router {
            error!("New router failed: {e}");
            panic!();
        }
        let mut router = router.unwrap();

        /* router control */
        let router_ctl = router.get_ctl_tx();

        /* vpcmappings for vpc name resolution for vpc stats */
        let vpcmapw = VpcMapWriter::<VpcMapName>::new();

        /* create NatTables for static nat */
        let nattablesw = NatTablesWriter::new();

        /* create NatAllocator for masquerade */
        let natallocatorw = NatAllocatorWriter::new();

        /* create FlowFilterContext for flow filtering */
        let flow_filter_writer = FlowFilterContextWriter::new();

        /* create AclFilterContext for ACL filtering */
        let aclfilterw = AclFilterContextWriter::new();

        /* create port forwarding table */
        let portfw_w = PortFwTableWriter::new();

        /* create VPC stats store (Arc) */
        let vpc_stats_store = VpcStatsStore::new();

        /* pipeline data */
        let pipeline_data = Arc::from(PipelineData::default());

        /* flow table */
        let flow_table = Arc::from(FlowTable::new(16));

        /* build configuration of mgmt config processor */
        let processor_config = ConfigProcessorParams {
            router_ctl,
            pipeline_data,
            flow_table,
            vpcmapw,
            nattablesw,
            natallocatorw,
            flow_filter_writer,
            aclfilterw,
            portfw_w,
            vpc_stats_store,
            dp_status_r,
            bmp_options: None,
        };

        let rth = tokio::runtime::Handle::current();

        /* start config processor to test the processing of a config. The processor embeds the
        config database . In this test, we don't use any channel to communicate the config. */
        let (mut processor, _) = ConfigProcessor::new(processor_config, &rth);

        /* let the processor process the config */
        match processor.process_incoming_config(external).await {
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

#[cfg(test)]
mod peering_chain {
    use bolero::{Driver, ValueGenerator};
    use config::ConfigError;
    use config::ExternalConfig;
    use config::external::ExternalConfigBuilder;
    use config::external::gwgroup::{GwGroup, GwGroupMember, GwGroupTable};
    use config::external::overlay::vpcpeering::VpcExpose;
    use config::external::overlay::vpcpeering::contract::{
        Family, LOCAL_VNI, MasqueradeExpose, PortForwardingExpose, REMOTE_VNI, StaticNatExpose,
        overlay_with_exposes,
    };
    use routing::Render;
    use std::net::IpAddr;
    use std::ops::Bound::Included;
    use std::str::FromStr;

    use super::test::{
        sample_community_table, sample_device_config, sample_gw_groups, sample_underlay_config,
    };
    use crate::processor::confbuild::internal::{EVPN_RMAP_NO_ADV_COMM, build_internal_config};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Flavour {
        PortForwarding,
        Masquerade,
        Static,
    }

    const MAX_EXPOSES: u8 = 3;

    const UNDERLAY_ASN: u32 = 65000;

    #[derive(Debug, Clone, Copy, Default)]
    struct AnyNatExposes;

    impl ValueGenerator for AnyNatExposes {
        type Output = Vec<(Flavour, VpcExpose)>;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let count = driver.gen_u8(Included(&1), Included(&MAX_EXPOSES))?;
            // One family for the whole list. These all land in a single manifest, and a
            // manifest may not mix families, so letting each expose draw its own made
            // most multi-expose offerings illegal by construction.
            let family = if driver.produce::<bool>()? {
                Family::V4
            } else {
                Family::V6
            };
            let mut out = Vec::with_capacity(usize::from(count));
            for _ in 0..count {
                out.push(match driver.gen_u8(Included(&0), Included(&2))? {
                    0 => (
                        Flavour::PortForwarding,
                        PortForwardingExpose { family }.generate(driver)?,
                    ),
                    1 => (
                        Flavour::Masquerade,
                        MasqueradeExpose { family }.generate(driver)?,
                    ),
                    _ => (
                        Flavour::Static,
                        StaticNatExpose { family }.generate(driver)?,
                    ),
                });
            }
            Some(out)
        }
    }

    /// The groups the offered configuration carries.
    ///
    /// The gateway has to be a member of the group its peering names. `VpcPeering::
    /// with_default_group` names "default", and `build_routing_config` looks the gateway
    /// up in that group and skips the peer when it is not there. With a member of some
    /// other name, the whole per-peering half of the FRR build never ran: no advertised
    /// networks, no prefix lists, no route-map entries, and none of the generated exposes
    /// reached any routing code.
    fn gw_groups_with_default() -> GwGroupTable {
        let mut groups = sample_gw_groups();
        let mut default = GwGroup::new("default");
        default
            .add_member(GwGroupMember::new(
                GW_NAME,
                1,
                IpAddr::from_str("172.128.0.9").unwrap_or_else(|_| unreachable!()),
            ))
            .unwrap_or_else(|e| unreachable!("{e}"));
        groups
            .add_group(default)
            .unwrap_or_else(|e| unreachable!("{e}"));
        groups
    }

    /// The name this configuration gives the gateway building it. It has to match the
    /// member added to the "default" group by [`gw_groups_with_default`].
    const GW_NAME: &str = "test-gw";

    /// Whether an expose offers IPv6. The validator already forces one family across an
    /// expose, so the first prefix decides it.
    fn is_v6(expose: &VpcExpose) -> bool {
        expose
            .ips
            .first()
            .is_some_and(|prefix| prefix.prefix().is_ipv6())
    }

    fn external_offering(exposes: Vec<VpcExpose>) -> ExternalConfig {
        let overlay = overlay_with_exposes(exposes).unwrap_or_else(|e| unreachable!("{e}"));
        ExternalConfigBuilder::default()
            .gwname(GW_NAME.to_string())
            .genid(1)
            .device(sample_device_config())
            .underlay(sample_underlay_config())
            .overlay(overlay)
            .gwgroups(gw_groups_with_default())
            .communities(sample_community_table())
            .build()
            .unwrap_or_else(|e| unreachable!("{e}"))
    }

    #[test]
    fn a_config_with_a_nat_peering_builds_and_renders() {
        use concurrency::sync::atomic::{AtomicUsize, Ordering};
        static SEEN: AtomicUsize = AtomicUsize::new(0);
        static BUILT: AtomicUsize = AtomicUsize::new(0);
        static MULTI: AtomicUsize = AtomicUsize::new(0);
        static UNSUPPORTED_V6: AtomicUsize = AtomicUsize::new(0);

        bolero::check!()
            .with_generator(AnyNatExposes)
            .cloned()
            .for_each(|offered: Vec<(Flavour, VpcExpose)>| {
                SEEN.fetch_add(1, Ordering::Relaxed);
                let flavours: Vec<Flavour> = offered.iter().map(|(f, _)| *f).collect();
                let exposes: Vec<VpcExpose> = offered.iter().map(|(_, e)| e.clone()).collect();
                let external = external_offering(exposes.clone());

                let validated = match external.validate() {
                    Ok(validated) => validated,
                    Err(e) => {
                        assert!(
                            exposes.len() > 1,
                            "a single {:?} expose that is valid by construction was refused: {e}\n{exposes:#?}",
                            flavours[0]
                        );
                        return;
                    }
                };
                BUILT.fetch_add(1, Ordering::Relaxed);
                if exposes.len() > 1 {
                    MULTI.fetch_add(1, Ordering::Relaxed);
                }

                let internal = match build_internal_config(&validated, None) {
                    Ok(internal) => internal,
                    // The FRR configuration built from a peering is IPv4-only, so a
                    // validated IPv6 peering cannot be rendered. That gap is real and the
                    // user meets it at apply time, not at submit time. Check it here
                    // rather than skip past it: only an IPv6 configuration may reach this,
                    // and if one ever builds, this arm is what says the limitation lifted.
                    Err(ConfigError::Unsupported(_)) => {
                        assert!(
                            exposes.iter().any(is_v6),
                            "an IPv4 {flavours:?} configuration was refused as unsupported\n{exposes:#?}"
                        );
                        UNSUPPORTED_V6.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    Err(e) => panic!(
                        "a validated {flavours:?} configuration would not build: {e}\n{exposes:#?}"
                    ),
                };

                let vnis: Vec<u32> = internal
                    .vrfs
                    .iter_by_name()
                    .filter_map(|vrf| vrf.vni.map(|vni| vni.as_u32()))
                    .collect();
                for vni in [LOCAL_VNI, REMOTE_VNI] {
                    assert!(
                        vnis.contains(&vni),
                        "vni {vni} of the peering is missing from the built config, got {vnis:?}"
                    );
                }

                assert!(
                    internal.vrfs.default_vrf_config().is_some(),
                    "the built config has no default vrf"
                );

                for order in 0..5 {
                    assert_eq!(
                        internal.commtable.get_community(order),
                        validated.external().communities().get_community(order),
                        "community {order} did not survive the build"
                    );
                }

                assert!(
                    internal
                        .rmap_table
                        .values()
                        .any(|rmap| rmap.name == EVPN_RMAP_NO_ADV_COMM),
                    "the evpn no-advertise route-map is missing from the built config"
                );

                let text = internal.render(&validated.genid()).to_string();

                // What a peering advertises has to survive into the rendered config. This
                // is the only assertion here that depends on the per-peering half of the
                // build having run at all; without it that whole half could return early
                // and everything else above would still hold.
                //
                // The prefixes are read back out of the validated config rather than off
                // the offered exposes, because validation collapses and normalises them
                // and it is the collapsed form that gets rendered.
                let mut advertised = 0usize;
                for vpc in validated.external().overlay().vpc_table().values() {
                    for peering in vpc.peerings().iter() {
                        for expose in peering.remote().valexp() {
                            for prefix in expose.adv_prefixes() {
                                advertised += 1;
                                assert!(
                                    text.contains(&prefix.to_string()),
                                    "{prefix} is advertised by a peering but never reaches the \
                                     rendered config\n{exposes:#?}"
                                );
                            }
                        }
                    }
                }
                assert!(
                    advertised > 0,
                    "the peering advertises nothing, so this checked no routing at all\n{exposes:#?}"
                );

                assert!(
                    text.contains("! config for gen 1"),
                    "the rendered config does not say which generation it is for"
                );
                assert!(
                    text.contains(EVPN_RMAP_NO_ADV_COMM),
                    "the evpn no-advertise route-map is missing from the rendered config"
                );
                assert!(
                    text.contains(&format!("router bgp {UNDERLAY_ASN}")),
                    "the underlay bgp instance is missing from the rendered config"
                );
                for vni in [LOCAL_VNI, REMOTE_VNI] {
                    assert!(
                        text.contains(&format!(" vni {vni}")),
                        "vni {vni} is missing from the rendered config"
                    );
                }
            });

        let seen = SEEN.load(Ordering::Relaxed);
        let built = BUILT.load(Ordering::Relaxed);
        let multi = MULTI.load(Ordering::Relaxed);
        let unsupported = UNSUPPORTED_V6.load(Ordering::Relaxed);
        println!(
            "{built}/{seen} configurations built, {multi} of them with several exposes, \
             {unsupported} refused as ipv6"
        );
        // A rate needs a sample. Under miri and qemu this property gets a handful of
        // cases, where these would measure nothing and flake; the counts above still
        // print for a human or a coverage run.
        if seen > super::ENOUGH_CASES {
            assert!(
                built * 2 >= seen,
                "most configurations were skipped: {built}/{seen}"
            );
            assert!(
                multi > 0,
                "no configuration with more than one expose was built"
            );
            // Half the generated exposes are IPv6, so the refusal has to be getting hit.
            // If it stops, either the generator went IPv4-only or the builder learned to
            // render IPv6, and either way the arm above needs revisiting.
            assert!(
                unsupported > 0,
                "no ipv6 configuration reached the builder, so the ipv4-only limitation is \
                 no longer being exercised"
            );
        }
    }
}

#[cfg(test)]
mod dataplane_tables {
    use config::{ExternalConfig, ValidatedGwConfig};
    use flow_entry::flow_table::FlowTable;
    use k8s_intf::bolero::NatFlavour;
    use k8s_intf::bolero::crd::GatewayAgentBuilder;
    use nat::masquerade::{MasqueradeConfig, NatAllocatorWriter};
    use nat::portfw::{PortFwTableWriter, build_port_forwarding_configuration};
    use nat::static_nat::NatTablesWriter;
    use nat::static_nat::setup::build_nat_configuration;

    fn build_tables(validated: &ValidatedGwConfig, flavour: NatFlavour) {
        let vpc_table = validated.external().overlay().vpc_table();

        let nat_tables = build_nat_configuration(vpc_table).unwrap_or_else(|e| {
            panic!("a validated {flavour:?} configuration would not build static NAT: {e}")
        });
        let mut nattablesw = NatTablesWriter::new();
        nattablesw.update_nat_tables(nat_tables);

        let masquerade = MasqueradeConfig::new(vpc_table).set_randomize(false);
        let mut natallocatorw = NatAllocatorWriter::new();
        let flow_table = FlowTable::new(16);
        natallocatorw.update_nat_allocator(masquerade, validated.genid(), &flow_table);

        let ruleset = build_port_forwarding_configuration(vpc_table).unwrap_or_else(|e| {
            panic!("a validated {flavour:?} configuration would not build port forwarding: {e}")
        });
        let mut portfw_w = PortFwTableWriter::new();
        portfw_w.update_table(&ruleset).unwrap_or_else(|e| {
            panic!("a validated {flavour:?} port-forwarding ruleset was refused by the table: {e}")
        });
    }

    /// Drive one NAT flavour through validation and every dataplane table it implies.
    ///
    /// A macro rather than a function because `bolero::check!()` registers a fuzz target
    /// named for the item that encloses it. Four tests sharing one helper therefore
    /// registered one target under the helper's name, and no test could be selected by
    /// it: `cargo bolero list` reported a target that could not be run. Expanding at each
    /// call site gives each test its own.
    macro_rules! drive {
        ($flavour:expr) => {{
            use concurrency::sync::atomic::{AtomicUsize, Ordering};
            let flavour: NatFlavour = $flavour;
            let seen = AtomicUsize::new(0);
            let built = AtomicUsize::new(0);

            let generator = GatewayAgentBuilder::new().flavours(vec![flavour]).build();

            bolero::check!()
                .with_generator(generator)
                .cloned()
                .for_each(|agent| {
                    seen.fetch_add(1, Ordering::Relaxed);
                    let external = ExternalConfig::try_from(&agent)
                        .unwrap_or_else(|e| panic!("a schema-legal CRD did not convert: {e}"));
                    let Ok(validated) = external.validate() else {
                        return;
                    };
                    built.fetch_add(1, Ordering::Relaxed);
                    build_tables(&validated, flavour);
                });

            let seen = seen.load(Ordering::Relaxed);
            let built = built.load(Ordering::Relaxed);
            println!("{flavour:?}: {built}/{seen} configurations validated and built their tables");
            // Masquerade already gets two orders of magnitude fewer cases than its
            // siblings in the same budget, and every flavour drops to a handful under miri
            // and qemu, so this rate only means something once there is a sample behind it.
            if seen > super::ENOUGH_CASES {
                assert!(
                    built * 2 >= seen,
                    "only {built} of {seen} {flavour:?} configurations validated, so this checked \
                     much less than it looks like it did"
                );
            }
        }};
    }

    #[test]
    fn a_static_nat_configuration_builds_its_tables() {
        drive!(NatFlavour::Static);
    }

    #[test]
    fn a_masquerade_configuration_builds_its_tables() {
        drive!(NatFlavour::Masquerade);
    }

    #[test]
    fn a_port_forwarding_configuration_builds_its_tables() {
        drive!(NatFlavour::PortForward);
    }

    #[test]
    fn a_configuration_with_no_nat_builds_its_tables() {
        drive!(NatFlavour::None);
    }
}

#[cfg(test)]
#[cfg(test)]
mod enacted {
    use config::{ConfigError, ExternalConfig, ValidatedGwConfig};
    use flow_entry::flow_table::FlowTable;
    use k8s_intf::gateway_agent_crd::GatewayAgent;
    use nat::masquerade::{MasqueradeConfig, NatAllocatorWriter};
    use nat::portfw::{PortFwTableWriter, build_port_forwarding_configuration};
    use nat::static_nat::setup::build_nat_configuration;
    use routing::Render;

    use crate::processor::confbuild::internal::build_internal_config;

    pub(super) fn validator(crd: &GatewayAgent) -> Result<ValidatedGwConfig, ConfigError> {
        let external = ExternalConfig::try_from(crd)
            .map_err(|e| ConfigError::Invalid(format!("conversion: {e}")))?;
        external.validate()
    }

    pub(super) struct Artifacts {
        pub frr: Vec<String>,
        pub static_nat: Vec<String>,
        pub port_forwarding: Vec<String>,
        pub masquerade: Vec<String>,
    }

    fn lines(text: &str) -> Vec<String> {
        let mut out: Vec<String> = text
            .lines()
            .map(|line| line.trim_end().to_string())
            .filter(|line| !line.is_empty())
            .collect();
        out.sort();
        out
    }

    impl Artifacts {
        pub(super) fn of(validated: &ValidatedGwConfig) -> Option<Self> {
            let genid = validated.genid();
            let internal = build_internal_config(validated, None).ok()?;
            let vpc_table = validated.external().overlay().vpc_table();

            let nat_tables = build_nat_configuration(vpc_table).ok()?;
            let ruleset = build_port_forwarding_configuration(vpc_table).ok()?;
            let mut portfw = PortFwTableWriter::new();
            portfw.update_table(&ruleset).ok()?;

            let masquerade = MasqueradeConfig::new(vpc_table).set_randomize(false);
            let mut writer = NatAllocatorWriter::new();
            writer.update_nat_allocator(masquerade, genid, &FlowTable::new(16));
            let allocator = writer.get_reader().get();

            Some(Self {
                frr: lines(&internal.render(&genid).to_string()),
                static_nat: lines(&nat_tables.to_string()),
                port_forwarding: lines(
                    &ruleset
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                masquerade: allocator
                    .map(|allocator| lines(&allocator.to_string()))
                    .unwrap_or_default(),
            })
        }

        pub(super) fn all(&self) -> Vec<String> {
            let mut out = self.frr.clone();
            out.extend(self.static_nat.iter().cloned());
            out.extend(self.port_forwarding.iter().cloned());
            out.extend(self.masquerade.iter().cloned());
            out.sort();
            out
        }
    }
}

mod validator_completeness {
    use super::enacted::validator;
    use concurrency::sync::atomic::{AtomicUsize, Ordering};
    use config::{ConfigError, ValidatedGwConfig};
    use flow_entry::flow_table::FlowTable;
    use k8s_intf::bolero::AddressFamily;
    use k8s_intf::bolero::crd::GatewayAgentBuilder;
    use k8s_intf::bolero::mutate::{MutatedAgents, Mutation};
    use k8s_intf::gateway_agent_crd::GatewayAgent;
    use nat::masquerade::{MasqueradeConfig, NatAllocatorWriter};
    use nat::portfw::{PortFwTableWriter, build_port_forwarding_configuration};
    use nat::static_nat::NatTablesWriter;
    use nat::static_nat::setup::build_nat_configuration;
    use routing::Render;

    use crate::processor::confbuild::internal::build_internal_config;

    /// Build every dataplane artifact a validated configuration implies.
    ///
    /// `mutation` names the mutation that was *drawn*, which is not the same as one that
    /// was applied. The caller reaches this only when the mutation found no target, since
    /// a mutation that did apply is required to have been refused. So the mutation names
    /// in the messages below are there to identify the draw, not to describe a
    /// configuration that carries the mutation: the enactment half of this property runs
    /// on unmutated input, and the mutations earn their keep in the refusal half.
    fn enact(validated: &ValidatedGwConfig, mutation: Mutation) {
        let genid = validated.genid();

        let internal = build_internal_config(validated, None).unwrap_or_else(|e| {
            panic!("{mutation:?}: validator accepted a config the builder rejects: {e}")
        });
        let _ = internal.render(&genid).to_string();

        let vpc_table = validated.external().overlay().vpc_table();

        let nat_tables = build_nat_configuration(vpc_table).unwrap_or_else(|e| {
            panic!("{mutation:?}: validator accepted a config static NAT rejects: {e}")
        });
        NatTablesWriter::new().update_nat_tables(nat_tables);

        let masquerade = MasqueradeConfig::new(vpc_table).set_randomize(false);
        NatAllocatorWriter::new().update_nat_allocator(masquerade, genid, &FlowTable::new(16));

        let ruleset = build_port_forwarding_configuration(vpc_table).unwrap_or_else(|e| {
            panic!("{mutation:?}: validator accepted a config port forwarding rejects: {e}")
        });
        // Cannot fire yet: `validate_ruleset` is a stub returning `Ok`, so `update_table`
        // is infallible. The (04) PR in this stack gives it a real `PortFwTable::dry_run`,
        // at which point this starts checking something. Left in place for that.
        PortFwTableWriter::new()
            .update_table(&ruleset)
            .unwrap_or_else(|e| {
                panic!("{mutation:?}: validator accepted a ruleset the table rejects: {e}")
            });
    }

    #[test]
    fn whatever_the_validator_accepts_can_be_enacted_over_ipv4() {
        let families = vec![AddressFamily::V4];

        const N: usize = Mutation::COUNT;
        #[allow(clippy::declare_interior_mutable_const)]
        const ZERO: AtomicUsize = AtomicUsize::new(0);
        static DRAWN: [AtomicUsize; N] = [ZERO; N];
        static APPLIED: [AtomicUsize; N] = [ZERO; N];
        static REFUSED: [AtomicUsize; N] = [ZERO; N];

        bolero::check!()
            .with_generator(MutatedAgents::new(
                GatewayAgentBuilder::new().families(families).build(),
            ))
            .cloned()
            .for_each(|(mutation, bit, agent): (Mutation, bool, GatewayAgent)| {
                let outcome = validator(&agent);
                let accepted = outcome.is_ok();

                if let Ok(validated) = &outcome {
                    assert!(
                        !bit,
                        "{mutation:?} broke a rule outright and the validator accepted the result, \
                         so nothing downstream will ever report it"
                    );
                    enact(validated, mutation);
                } else if let Err(e) = &outcome {
                    assert!(
                        mutation != Mutation::None,
                        "an unmutated configuration was refused, so the generator is producing \
                         illegal input and every mutated case is suspect: {e}"
                    );

                    assert!(
                        !matches!(e, ConfigError::InternalFailure(_)),
                        "{mutation:?}: rejected with an internal failure, which tells the user \
                         nothing they can act on: {e}"
                    );
                }

                let slot = mutation.index();
                DRAWN[slot].fetch_add(1, Ordering::Relaxed);
                if bit {
                    APPLIED[slot].fetch_add(1, Ordering::Relaxed);
                }
                if !accepted {
                    REFUSED[slot].fetch_add(1, Ordering::Relaxed);
                }
            });

        #[cfg(fuzzing)]
        println!("under a coverage-guided engine: skipping the generator-health checks");

        #[cfg(not(fuzzing))]
        check_generator_health(&DRAWN, &APPLIED, &REFUSED);
    }

    #[cfg(not(fuzzing))]
    fn check_generator_health(
        drawn_at: &[AtomicUsize; Mutation::COUNT],
        applied_at: &[AtomicUsize; Mutation::COUNT],
        refused_at: &[AtomicUsize; Mutation::COUNT],
    ) {
        let mut total = 0;
        for mutation in Mutation::all() {
            let slot = mutation.index();
            let drawn = drawn_at[slot].load(Ordering::Relaxed);
            let applied = applied_at[slot].load(Ordering::Relaxed);
            let refused = refused_at[slot].load(Ordering::Relaxed);
            println!("{mutation:<32?} {drawn:>7} drawn {applied:>7} applied {refused:>7} refused");
            total += drawn;
        }

        let cases_for_drawn = 50 * Mutation::COUNT;
        let cases_for_applied = 2_000 * Mutation::COUNT;
        if total < cases_for_drawn {
            println!(
                "only {total} cases: too few to say anything about mutation coverage \
                 (needs {cases_for_drawn} to check each was drawn, {cases_for_applied} to check each \
                 found a target)"
            );
            return;
        }

        for mutation in Mutation::all() {
            assert!(
                drawn_at[mutation.index()].load(Ordering::Relaxed) > 0,
                "{mutation:?} was never drawn in {total} cases"
            );
        }

        if total < cases_for_applied {
            println!(
                "{total} cases: enough to check every mutation was drawn, too few to check each \
                 found a target (needs {cases_for_applied})"
            );
            return;
        }

        for mutation in Mutation::all().into_iter().filter(|m| *m != Mutation::None) {
            assert!(
                applied_at[mutation.index()].load(Ordering::Relaxed) > 0,
                "{mutation:?} never found anything to break in {total} cases, so it is testing \
                 nothing"
            );
        }
    }
}

mod ambiguity {
    use super::enacted::{Artifacts, validator};
    use concurrency::sync::atomic::{AtomicUsize, Ordering};
    use k8s_intf::bolero::mutate::Mutation;
    use k8s_intf::bolero::permute::PermutedAgents;
    use k8s_intf::gateway_agent_crd::GatewayAgent;

    #[test]
    fn a_configuration_has_only_one_meaning() {
        static MOVED: AtomicUsize = AtomicUsize::new(0);
        static COMPARED: AtomicUsize = AtomicUsize::new(0);

        bolero::check!()
            .with_generator(PermutedAgents::new(
                k8s_intf::bolero::mutate::MutatedAgents::new(
                    k8s_intf::bolero::crd::GatewayAgentBuilder::new()
                        .families(vec![k8s_intf::bolero::AddressFamily::V4])
                        .build(),
                ),
            ))
            .cloned()
            .for_each(
                |(mutation, agent, permuted, moved): (Mutation, GatewayAgent, GatewayAgent, bool)| {
                let Ok(first) = validator(&agent) else {
                    return;
                };

                let second = validator(&permuted).unwrap_or_else(|e| {
                    panic!(
                        "{mutation:?}: reordering a configuration's sets made the validator refuse \
                         it, so it is treating list order as meaning: {e}"
                    )
                });

                let (Some(before), Some(after)) = (Artifacts::of(&first), Artifacts::of(&second))
                else {
                    return;
                };
                let (before, after) = (before.all(), after.all());

                if moved {
                    MOVED.fetch_add(1, Ordering::Relaxed);
                }
                COMPARED.fetch_add(1, Ordering::Relaxed);

                if before != after {
                    let mut differences: Vec<String> = Vec::new();
                    for line in &before {
                        if !after.contains(line) {
                            differences.push(format!("  only before: {line}"));
                        }
                    }
                    for line in &after {
                        if !before.contains(line) {
                            differences.push(format!("  only after:  {line}"));
                        }
                    }
                    differences.truncate(20);
                    panic!(
                        "{mutation:?}: reordering a configuration's sets changed what the dataplane \
                         installs, so the configuration had more than one meaning and the chain \
                         picked one:\n{}",
                        differences.join("\n")
                    );
                }
                },
            );

        let compared = COMPARED.load(Ordering::Relaxed);
        let moved = MOVED.load(Ordering::Relaxed);
        println!("{moved} of {compared} comparisons were of a genuinely reordered configuration");
        // Only a run with enough cases can say anything about a rate. Under miri and qemu
        // this property gets a handful, where a ratio measures nothing and would only
        // flake, so the count above is left for a human or a coverage run to read.
        #[cfg(not(fuzzing))]
        if compared > 200 {
            // Measured at roughly 9%: a list needs a second entry before it can be
            // reordered at all, and most exposes carry a single prefix. This is a
            // tripwire for the permutation dying altogether, not a coverage target.
            assert!(
                moved * 25 >= compared,
                "only {moved} of {compared} comparisons actually reordered anything: the \
                 permutation is not doing any work"
            );
        }
    }
}

mod relevance {
    use super::enacted::{Artifacts, validator};
    use concurrency::sync::atomic::{AtomicUsize, Ordering};
    use k8s_intf::bolero::NatFlavour;
    use k8s_intf::bolero::mutate::Mutation;
    use k8s_intf::bolero::reduce::{Dropped, ReducedAgents};
    use k8s_intf::gateway_agent_crd::GatewayAgent;

    fn handled_here(agent: &GatewayAgent, peering: &str) -> bool {
        let Some(name) = agent.metadata.name.as_deref() else {
            return false;
        };
        let Some(group) = agent
            .spec
            .peerings
            .as_ref()
            .and_then(|peerings| peerings.get(peering))
            .and_then(|peering| peering.gateway_group.as_deref())
        else {
            return false;
        };
        agent
            .spec
            .groups
            .as_ref()
            .and_then(|groups| groups.get(group))
            .and_then(|group| group.members.as_ref())
            .is_some_and(|members| members.iter().any(|m| m.name == name))
    }

    fn difference(left: &[String], right: &[String]) -> Option<String> {
        if left == right {
            return None;
        }
        let mut out: Vec<String> = Vec::new();
        for line in left {
            if !right.contains(line) {
                out.push(format!("  only with it:    {line}"));
            }
        }
        for line in right {
            if !left.contains(line) {
                out.push(format!("  only without it: {line}"));
            }
        }
        out.truncate(10);
        Some(out.join("\n"))
    }

    #[test]
    fn every_expose_leaves_a_trace() {
        static CHECKED: AtomicUsize = AtomicUsize::new(0);
        static NOTHING_TO_DROP: AtomicUsize = AtomicUsize::new(0);
        static REFUSED_WITHOUT: AtomicUsize = AtomicUsize::new(0);
        static NOT_OURS: AtomicUsize = AtomicUsize::new(0);
        static TRANSLATING: AtomicUsize = AtomicUsize::new(0);

        bolero::check!()
            .with_generator(ReducedAgents::new(
                k8s_intf::bolero::mutate::MutatedAgents::new(
                    k8s_intf::bolero::crd::GatewayAgentBuilder::new()
                        .families(vec![k8s_intf::bolero::AddressFamily::V4])
                        .sizes(4, 3, 4, 3)
                        .build(),
                ),
            ))
            .cloned()
            .for_each(
                |(mutation, agent, reduced, dropped): (
                    Mutation,
                    GatewayAgent,
                    GatewayAgent,
                    Option<Dropped>,
                )| {
                    let Some(dropped) = dropped else {
                        NOTHING_TO_DROP.fetch_add(1, Ordering::Relaxed);
                        return;
                    };
                    let Ok(whole) = validator(&agent) else {
                        return;
                    };
                    let Ok(less) = validator(&reduced) else {
                        REFUSED_WITHOUT.fetch_add(1, Ordering::Relaxed);
                        return;
                    };
                    let (Some(with), Some(without)) = (Artifacts::of(&whole), Artifacts::of(&less))
                    else {
                        return;
                    };

                    if !handled_here(&agent, &dropped.peering) {
                        NOT_OURS.fetch_add(1, Ordering::Relaxed);
                        return;
                    }

                    CHECKED.fetch_add(1, Ordering::Relaxed);

                    assert!(
                        difference(&with.frr, &without.frr).is_some(),
                        "{mutation:?}: removing {dropped} changed nothing in the routing \
                         configuration, so the dataplane was never routing it"
                    );

                    // Exhaustive over `NatFlavour`, so adding a translation mode is a
                    // build error here rather than an `unreachable!` during a fuzz run.
                    let (table, name) = match dropped.nat {
                        None | Some(NatFlavour::None) => return,
                        Some(NatFlavour::Static) => (&with.static_nat, &without.static_nat),
                        Some(NatFlavour::PortForward) => {
                            (&with.port_forwarding, &without.port_forwarding)
                        }
                        Some(NatFlavour::Masquerade) => (&with.masquerade, &without.masquerade),
                    };
                    TRANSLATING.fetch_add(1, Ordering::Relaxed);
                    assert!(
                        difference(table, name).is_some(),
                        "{mutation:?}: removing {dropped} changed nothing in the table for its own \
                         NAT mode, so that translation was never installed"
                    );
                },
            );

        let checked = CHECKED.load(Ordering::Relaxed);
        let nothing = NOTHING_TO_DROP.load(Ordering::Relaxed);
        let refused = REFUSED_WITHOUT.load(Ordering::Relaxed);
        let not_ours = NOT_OURS.load(Ordering::Relaxed);
        let translating = TRANSLATING.load(Ordering::Relaxed);
        println!(
            "{checked} exposes checked ({translating} of them translating); {nothing} \
             configurations had nothing to drop, {refused} became illegal without it, {not_ours} \
             sat in a peering this gateway does not handle"
        );

        let seen = checked + nothing + refused + not_ours;
        #[cfg(not(fuzzing))]
        if seen > 200 {
            // Measured at 2.0% to 3.0% across runs. Most of the loss is upstream and
            // legitimate: an expose can only be dropped from a manifest that has two, and
            // at these knobs a majority of configurations carry no peering at all. A floor
            // of 1% is a tripwire for the property going silent, not a coverage target.
            // Raising the useful fraction needs a generator biased to guarantee a peering,
            // which is what `ValueGenerator` is for; until then, watch coverage.
            assert!(
                checked * 100 > seen,
                "only {checked} of {seen} cases got as far as comparing artifacts: this property has \
                 become mostly skips"
            );
        }
    }
}

#[cfg(test)]
mod filters {
    //! The rte_acl-backed ACL filter and the flow filter.
    //!
    //! These are the two steps of `apply_gw_config` that nothing else here touches.
    //! `the_properties_are_not_vacuous` reports that around half of validated
    //! configurations carry an ACL, and mgmt depends on dpdk precisely so this table can
    //! be built in a test, but no property was building it. A generated ACL that the
    //! validator accepts and rte_acl refuses would have gone unnoticed.
    //!
    //! They live in their own property rather than being folded into the other enactment
    //! helpers because building an rte_acl table is expensive, and the sibling properties
    //! are worth more cases than they are worth ACL coverage.
    use acl_filter::AclFilterContext;
    use concurrency::sync::atomic::{AtomicUsize, Ordering};
    use config::ExternalConfig;
    use flow_filter::FlowFilterContext;
    use k8s_intf::bolero::AddressFamily;
    use k8s_intf::bolero::crd::GatewayAgentBuilder;

    #[test]
    fn whatever_validates_builds_its_filters() {
        // Idempotent: `start_eal` initialises a static once per process.
        let _eal = dpdk::test_support::start_eal();

        let seen = AtomicUsize::new(0);
        let validated_count = AtomicUsize::new(0);
        let with_acl = AtomicUsize::new(0);

        bolero::check!()
            .with_generator(
                GatewayAgentBuilder::new()
                    .families(vec![AddressFamily::V4])
                    .build(),
            )
            .cloned()
            .for_each(|agent| {
                seen.fetch_add(1, Ordering::Relaxed);
                let external = ExternalConfig::try_from(&agent)
                    .unwrap_or_else(|e| panic!("a schema-legal CRD did not convert: {e}"));
                let Ok(validated) = external.validate() else {
                    return;
                };
                validated_count.fetch_add(1, Ordering::Relaxed);

                let overlay = validated.external().overlay();
                if overlay
                    .vpc_table()
                    .values()
                    .flat_map(config::external::overlay::vpc::ValidatedVpc::peerings)
                    .any(|peering| peering.acl().is_some())
                {
                    with_acl.fetch_add(1, Ordering::Relaxed);
                }

                AclFilterContext::try_from(overlay).unwrap_or_else(|e| {
                    panic!("the validator accepted an acl the filter cannot build: {e}")
                });
                FlowFilterContext::try_from(overlay).unwrap_or_else(|e| {
                    panic!("the validator accepted a config the flow filter cannot build: {e}")
                });
            });

        let seen = seen.load(Ordering::Relaxed);
        let validated_count = validated_count.load(Ordering::Relaxed);
        let with_acl = with_acl.load(Ordering::Relaxed);
        println!(
            "{validated_count}/{seen} validated and built their filters, {with_acl} carrying an acl"
        );
        if seen > super::ENOUGH_CASES {
            assert!(
                with_acl > 0,
                "no configuration carried an acl, so the rte_acl build was never exercised"
            );
        }
    }
}
