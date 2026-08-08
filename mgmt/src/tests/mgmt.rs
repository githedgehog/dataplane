// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

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

/// Properties over the third arrow of the configuration chain, with peerings.
///
/// A gateway configuration passes through
///
/// ```text
/// GatewayAgent (CRD) ─▶ ExternalConfig ─▶ validated ─▶ InternalConfig ─▶ FRR
/// ```
///
/// and `build_internal_config` -- the third arrow -- had only ever been given hand-built input:
/// `test::check_frr_config` above builds one sample configuration, renders it and prints the result.
///
/// The properties in `processor::confbuild::internal` drive the whole chain from a generated
/// `GatewayAgent`, but measuring them showed that **no generated configuration with a peering ever
/// survives validation**, so the arrow has never been exercised for the half of the model that
/// carries the exposes, the NAT and the ACLs. Fixing that in the CRD generators is a separate piece
/// of work.
///
/// This gets at the same question from the other side, and today rather than after that work:
/// `config`'s own contract generators already produce exposes that are valid *by construction* for
/// each of the three NAT flavours, so an overlay built around one of those, spliced into the sample
/// underlay, reaches the builder with a peering in it.
///
/// The claim is the one that matters: **a configuration that validates can be built and rendered.**
/// A configuration that validates and then fails to build is a half-applied dataplane --
/// `apply_gw_config` is a linear `?`-chain with no transaction, so by the time a late step fails the
/// kernel interfaces, the flow filter, the ACLs, static NAT and the masquerade allocator have all
/// been committed, and rolling the configuration back does not restore the masquerade flows already
/// torn down.
#[cfg(test)]
mod peering_chain {
    use bolero::{Driver, ValueGenerator};
    use config::ExternalConfig;
    use config::external::ExternalConfigBuilder;
    use config::external::gwgroup::{GwGroup, GwGroupMember, GwGroupTable};
    use config::external::overlay::vpcpeering::VpcExpose;
    use config::external::overlay::vpcpeering::contract::{
        LOCAL_VNI, MasqueradeExpose, PortForwardingExpose, REMOTE_VNI, StaticNatExpose,
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

    /// Which NAT flavour a generated expose uses.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Flavour {
        PortForwarding,
        Masquerade,
        Static,
    }

    /// The most exposes one generated manifest offers.
    ///
    /// More than one because the interesting rejections, and the interesting things for the builder
    /// to get wrong, are *between* exposes rather than within one.
    const MAX_EXPOSES: u8 = 3;

    /// The autonomous system the sample underlay uses, so the rendered text can be checked for it.
    const UNDERLAY_ASN: u32 = 65000;

    /// Draws exposes of each NAT flavour, each valid by construction, for one manifest.
    #[derive(Debug, Clone, Copy, Default)]
    struct AnyNatExposes;

    impl ValueGenerator for AnyNatExposes {
        type Output = Vec<(Flavour, VpcExpose)>;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let count = driver.gen_u8(Included(&1), Included(&MAX_EXPOSES))?;
            let mut out = Vec::with_capacity(usize::from(count));
            for _ in 0..count {
                out.push(match driver.gen_u8(Included(&0), Included(&2))? {
                    0 => (
                        Flavour::PortForwarding,
                        PortForwardingExpose.generate(driver)?,
                    ),
                    1 => (Flavour::Masquerade, MasqueradeExpose.generate(driver)?),
                    _ => (Flavour::Static, StaticNatExpose.generate(driver)?),
                });
            }
            Some(out)
        }
    }

    /// The sample gateway groups, plus the `default` group the contract module's peering names.
    ///
    /// `VpcPeering::with_default_group` sets the group to `"default"`, and whole-config validation
    /// checks that a peering's group exists. Validating the overlay on its own -- which is what
    /// `overlay_offering` does, and what every existing user of these generators does -- cannot make
    /// that check, because the group table sits beside the overlay rather than in it. So an overlay
    /// those generators produce is not embeddable in a whole configuration without this.
    fn gw_groups_with_default() -> GwGroupTable {
        let mut groups = sample_gw_groups();
        let mut default = GwGroup::new("default");
        default
            .add_member(GwGroupMember::new(
                "gw-default",
                1,
                IpAddr::from_str("172.128.0.9").unwrap_or_else(|_| unreachable!()),
            ))
            .unwrap_or_else(|e| unreachable!("{e}"));
        groups
            .add_group(default)
            .unwrap_or_else(|e| unreachable!("{e}"));
        groups
    }

    /// A whole configuration: the sample underlay, and an overlay whose local vpc offers `exposes`.
    fn external_offering(exposes: Vec<VpcExpose>) -> ExternalConfig {
        let overlay = overlay_with_exposes(exposes).unwrap_or_else(|e| unreachable!("{e}"));
        ExternalConfigBuilder::default()
            .gwname("test-gw".to_string())
            .genid(1)
            .device(sample_device_config())
            .underlay(sample_underlay_config())
            .overlay(overlay)
            .gwgroups(gw_groups_with_default())
            .communities(sample_community_table())
            .build()
            .unwrap_or_else(|e| unreachable!("{e}"))
    }

    /// A configuration carrying a peering with NAT validates, builds, and renders.
    ///
    /// A single expose is always accepted -- the generators make it valid by construction -- but
    /// several together may legitimately be refused, for overlapping prefixes or a port range
    /// claimed twice. Those are skipped rather than treated as findings, and counted so that the
    /// property cannot quietly become vacuous.
    #[test]
    fn a_config_with_a_nat_peering_builds_and_renders() {
        use concurrency::sync::atomic::{AtomicUsize, Ordering};
        static SEEN: AtomicUsize = AtomicUsize::new(0);
        static BUILT: AtomicUsize = AtomicUsize::new(0);
        static MULTI: AtomicUsize = AtomicUsize::new(0);

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
                        // one expose on its own is valid by construction, so a rejection there is a
                        // finding; several may disagree with each other, which is not
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

                let internal = build_internal_config(&validated, None).unwrap_or_else(|e| {
                    panic!("a validated {flavours:?} configuration would not build: {e}\n{exposes:#?}")
                });

                // both vpcs of the peering reach the built configuration
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

                // the underlay's own vrf reaches the built config too. Checking the overlay vnis
                // alone would not notice it going missing, since the default vrf carries no vni.
                assert!(
                    internal.vrfs.default_vrf_config().is_some(),
                    "the built config has no default vrf"
                );

                // the community table is carried across unchanged. It is copied rather than derived,
                // so nothing else in this property would notice it being dropped -- and the
                // communities are what the overlay's route maps tag routes with.
                for order in 0..5 {
                    assert_eq!(
                        internal.commtable.get_community(order),
                        validated.external().communities().get_community(order),
                        "community {order} did not survive the build"
                    );
                }

                // the route-map that keeps learnt evpn routes from being re-advertised. Only
                // `configure_bgp_peers` adds it, and it is what applies to the underlay neighbours'
                // l2vpn-evpn address family -- so its absence means the neighbours were never
                // configured, which the vni checks above would not notice.
                assert!(
                    internal
                        .rmap_table
                        .values()
                        .any(|rmap| rmap.name == EVPN_RMAP_NO_ADV_COMM),
                    "the evpn no-advertise route-map is missing from the built config"
                );

                let text = internal.render(&validated.genid()).to_string();
                assert!(
                    text.contains("! config for gen 1"),
                    "the rendered config does not say which generation it is for"
                );
                assert!(
                    text.contains(EVPN_RMAP_NO_ADV_COMM),
                    "the evpn no-advertise route-map is missing from the rendered config"
                );
                // and the underlay's bgp instance reaches the rendered text, which is what ties the
                // asn the overlay vrfs are built with back to the configuration it came from
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
        println!("{built}/{seen} configurations built, {multi} of them with several exposes");
        assert!(
            built * 2 >= seen,
            "most configurations were skipped: {built}/{seen}"
        );
        assert!(
            multi > 0,
            "no configuration with more than one expose was built"
        );
    }
}

/// Properties over the *rest* of applying a configuration: the dataplane tables.
///
/// `build_internal_config` turns a validated configuration into the FRR half of it, and the chain
/// properties in `processor::confbuild::internal` cover that. The other half is the dataplane's own
/// tables, built from the same validated configuration by
///
/// * `build_nat_configuration` -- static NAT,
/// * `MasqueradeConfig::new` and `update_nat_allocator` -- masquerade,
/// * `build_port_forwarding_configuration` and `PortFwTableWriter::update_table` -- port forwarding.
///
/// All of them are fallible from a configuration that has already validated, and the last is where
/// the one confirmed bug of this class actually fired: `PortFwEntry::is_valid` refused a rule whose
/// two sides had matching address-port *totals* but mismatched prefix lengths, during apply, at the
/// last of the NAT stages -- by which point the kernel interfaces, the flow filter, the ACLs, the
/// static NAT tables and the masquerade allocator had all been committed. See
/// `fix(config): Refuse a port-forwarding expose the dataplane cannot build`.
///
/// So the claim is the same one, carried one step further: **a configuration that validates builds
/// every table it implies.**
///
/// One property per NAT flavour rather than one over all of them, using the generator knobs. A
/// single property over the default flavour mix reaches each flavour eventually; asking for one
/// reaches it in every case, and says in its name which one failed.
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

    /// Build every dataplane table the configuration implies, in the order `apply_gw_config` does.
    fn build_tables(validated: &ValidatedGwConfig, flavour: NatFlavour) {
        let vpc_table = validated.external().overlay().vpc_table();

        let nat_tables = build_nat_configuration(vpc_table).unwrap_or_else(|e| {
            panic!("a validated {flavour:?} configuration would not build static NAT: {e}")
        });
        let mut nattablesw = NatTablesWriter::new();
        nattablesw.update_nat_tables(nat_tables);

        let masquerade = MasqueradeConfig::new(vpc_table, validated.genid()).set_randomize(false);
        let mut natallocatorw = NatAllocatorWriter::new();
        let flow_table = FlowTable::new(16);
        natallocatorw.update_nat_allocator(masquerade, &flow_table);

        let ruleset = build_port_forwarding_configuration(vpc_table).unwrap_or_else(|e| {
            panic!("a validated {flavour:?} configuration would not build port forwarding: {e}")
        });
        let mut portfw_w = PortFwTableWriter::new();
        // The step that used to fail during apply: the ruleset builds and the table still refuses
        // it, because a rule can be well-formed as configuration and unrepresentable as a rule.
        portfw_w.update_table(&ruleset).unwrap_or_else(|e| {
            panic!("a validated {flavour:?} port-forwarding ruleset was refused by the table: {e}")
        });
    }

    /// Drive the whole chain for one NAT flavour, and report how much of it got through.
    fn drive(flavour: NatFlavour) {
        use concurrency::sync::atomic::{AtomicUsize, Ordering};
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
        assert!(
            built * 2 >= seen,
            "only {built} of {seen} {flavour:?} configurations validated, so this checked much \
             less than it looks like it did"
        );
    }

    #[test]
    fn a_static_nat_configuration_builds_its_tables() {
        drive(NatFlavour::Static);
    }

    #[test]
    fn a_masquerade_configuration_builds_its_tables() {
        drive(NatFlavour::Masquerade);
    }

    /// The flavour the historical bug was in.
    #[test]
    fn a_port_forwarding_configuration_builds_its_tables() {
        drive(NatFlavour::PortForward);
    }

    #[test]
    fn a_configuration_with_no_nat_builds_its_tables() {
        drive(NatFlavour::None);
    }
}

/// The property the whole validation chain exists for.
///
/// The validator ships as a wasm module in a process of its own. Its entire surface is
///
/// ```text
/// ExternalConfig::try_from(&crd)?.validate()?
/// ```
///
/// -- convert, then validate, and nothing else. If it blesses a configuration, that process writes
/// the configuration to Kubernetes. The dataplane runs the same two steps later, but it has no way to
/// tell anyone that something is wrong: by then the configuration is already the desired state.
///
/// So the requirement is not "the dataplane reports bad configurations well". It is:
///
/// > **anything the validator accepts must be enactable.**
///
/// A validator that is too strict is a nuisance -- the user sees an error and fixes their input. A
/// validator that is too permissive is unrecoverable, and every check that lives only in a
/// downstream builder is exactly that kind of gap. Nothing downstream of `validate` can help.
///
/// A panic is the same failure in a different coat: in wasm it traps, so the calling process gets a
/// failure with no `ValidateError` in it and the user gets nothing to act on.
///
/// The generator here is the near-miss one: a legal configuration with **one** rule deliberately
/// broken, which is the input most likely to slip past. The valid-by-construction properties
/// elsewhere test everything downstream of validation; these test validation itself.
#[cfg(test)]
mod validator_completeness {
    use concurrency::sync::atomic::{AtomicUsize, Ordering};
    use config::{ConfigError, ExternalConfig, ValidatedGwConfig};
    use flow_entry::flow_table::FlowTable;
    use k8s_intf::bolero::mutate::{MutatedAgents, Mutation};
    use k8s_intf::gateway_agent_crd::GatewayAgent;
    use nat::masquerade::{MasqueradeConfig, NatAllocatorWriter};
    use nat::portfw::{PortFwTableWriter, build_port_forwarding_configuration};
    use nat::static_nat::NatTablesWriter;
    use nat::static_nat::setup::build_nat_configuration;
    use routing::Render;

    use crate::processor::confbuild::internal::build_internal_config;

    /// Exactly what the wasm validator does, and nothing more.
    fn validator(crd: &GatewayAgent) -> Result<ValidatedGwConfig, ConfigError> {
        // The conversion's error type is not `ConfigError`, and a conversion failure is a rejection
        // just as much as a validation failure is, so it is folded in here.
        let external = ExternalConfig::try_from(crd)
            .map_err(|e| ConfigError::Invalid(format!("conversion: {e}")))?;
        external.validate()
    }

    /// Everything the dataplane has to be able to do with a blessed configuration.
    ///
    /// Any error here is the failure this module exists to find: the validator said yes and the
    /// dataplane cannot comply, with nowhere to report it.
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

        let masquerade = MasqueradeConfig::new(vpc_table, genid).set_randomize(false);
        NatAllocatorWriter::new().update_nat_allocator(masquerade, &FlowTable::new(16));

        let ruleset = build_port_forwarding_configuration(vpc_table).unwrap_or_else(|e| {
            panic!("{mutation:?}: validator accepted a config port forwarding rejects: {e}")
        });
        PortFwTableWriter::new()
            .update_table(&ruleset)
            .unwrap_or_else(|e| {
                panic!("{mutation:?}: validator accepted a ruleset the table rejects: {e}")
            });
    }

    /// Whatever the validator accepts, the dataplane can enact.
    ///
    /// **What this property cannot see.** It catches permissiveness that leads to a configuration the
    /// dataplane cannot build. It does not catch permissiveness about rules with no downstream
    /// enforcement -- `Mutation::OverlapWithAnotherPeer` is the worked example: deleting the
    /// `OverlappingPrefixes` check from `VpcRouteTable::validate` leaves this property passing,
    /// because two routes to one destination build perfectly well and the dataplane simply picks one.
    /// Those rules are about *ambiguity* rather than *feasibility*, and policing them needs a
    /// companion property -- "a mutation that breaks a rule must be refused" -- which in turn needs
    /// each mutation to report whether the case it built is certainly illegal, since several of them
    /// are legitimately legal some of the time.
    ///
    /// Also: it never panics, since reaching the assertions at all means it returned. In wasm a panic
    /// is a trap, so it is a rejection with no reason attached -- worse for the user than any error.
    #[test]
    fn whatever_the_validator_accepts_can_be_enacted() {
        // What each mutation did, so the run can say whether the generator is doing any work: how
        // often it was drawn, how often it found a target, and how often the result was refused.
        // Counters per mutation rather than a map behind a lock, since a lock is not wanted here.
        const N: usize = Mutation::COUNT;
        #[allow(clippy::declare_interior_mutable_const)]
        const ZERO: AtomicUsize = AtomicUsize::new(0);
        static DRAWN: [AtomicUsize; N] = [ZERO; N];
        static APPLIED: [AtomicUsize; N] = [ZERO; N];
        static REFUSED: [AtomicUsize; N] = [ZERO; N];

        bolero::check!()
            .with_generator(MutatedAgents::default())
            .cloned()
            .for_each(|(mutation, bit, agent): (Mutation, bool, GatewayAgent)| {
                let outcome = validator(&agent);
                let accepted = outcome.is_ok();

                if let Ok(validated) = &outcome {
                    enact(validated, mutation);
                } else if let Err(e) = &outcome {
                    // The control is legal by construction, so a rejection of it is a defect in the
                    // *generator*, and asserted rather than counted so bolero shrinks it. Counting it
                    // instead hid a real one for a long while: the tally said "6% of controls
                    // refused", which reads as tolerable noise, and finding the cause from a tally
                    // means reading configurations by eye. Asserted, the shrinker hands over a
                    // two-line counterexample.
                    assert!(
                        mutation != Mutation::None,
                        "an unmutated configuration was refused, so the generator is producing \
                         illegal input and every mutated case is suspect: {e}"
                    );

                    // A rejection has to say something the user can act on. An internal failure says
                    // "this is our bug", which is not something anyone can fix from the outside.
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

        // Everything from here on describes the *distribution* of the inputs, which is the random
        // engine's contract and not a coverage-guided one's. libfuzzer keeps a corpus and steers
        // toward inputs that reach new code, so it will happily spend a run replaying one mutation
        // ten thousand times -- the right behaviour for finding a gap, and fatal to a check that
        // every mutation gets drawn. The property above is what a fuzzing engine is here to break;
        // these are here to catch the generator rotting, which only the random engine can see.
        #[cfg(fuzzing)]
        println!("under a coverage-guided engine: skipping the generator-health checks");

        #[cfg(not(fuzzing))]
        check_generator_health(&DRAWN, &APPLIED, &REFUSED);
    }

    /// The generator-health checks, which only hold under the uniform random engine.
    ///
    /// Split out so the `cfg` above gates one call rather than half a function body.
    #[cfg(not(fuzzing))]
    fn check_generator_health(
        drawn_at: &[AtomicUsize; Mutation::COUNT],
        applied_at: &[AtomicUsize; Mutation::COUNT],
        refused_at: &[AtomicUsize; Mutation::COUNT],
    ) {
        let mut total_applied = 0;
        let mut total_refused = 0;
        for mutation in Mutation::all() {
            let slot = mutation.index();
            let drawn = drawn_at[slot].load(Ordering::Relaxed);
            let applied = applied_at[slot].load(Ordering::Relaxed);
            let refused = refused_at[slot].load(Ordering::Relaxed);
            println!("{mutation:<32?} {drawn:>7} drawn {applied:>7} applied {refused:>7} refused");
            assert!(drawn > 0, "{mutation:?} was never drawn");
            if mutation != Mutation::None {
                total_applied += applied;
                total_refused += refused;
            }
        }

        // Nothing here about the control's rejection rate: it is asserted to be zero above, which
        // is both stronger and shrinkable.

        // And a mutation that finds a target should usually be refused. This does not have to hold
        // case by case -- `DemandFlowScope` on a peering that *is* stateful throughout is legal --
        // but a mutation that has quietly stopped breaking anything shows up here.
        assert!(
            total_applied > 0 && total_refused * 2 >= total_applied,
            "only {total_refused} of {total_applied} applied mutations were refused: the near-miss \
             generator is mostly producing legal configurations"
        );
    }
}

/// A validated configuration must have exactly *one* meaning.
///
/// [`super::validator_completeness`] asks whether an accepted configuration can be **enacted**. This
/// asks whether it can be enacted only one way, which is a different failure and a worse one. An
/// unenactable configuration fails to build, and something gets an error. An ambiguous one builds
/// perfectly: two readings, both valid outputs of the code as written, and the chain takes whichever
/// its containers hand it first. There is no error to report, so nothing reports it -- only traffic
/// going somewhere nobody chose, discovered much later.
///
/// The oracle is permutation, and its virtue is that it restates no rule: it notices an ambiguity
/// whether or not anyone thought to forbid it. See `k8s_intf::bolero::permute`.
///
/// # What this catches, and what it does not
///
/// It catches ambiguity the chain resolves **at build time**: two readings of the input, one artifact,
/// and a container's iteration order deciding which. That is a real class and this is a real guard on
/// it, run over near-misses so the question is asked of configurations the validator was willing to
/// bless rather than only of ones the generator took care to keep clean.
///
/// It does **not** catch ambiguity the chain resolves at *run* time, and the break test says so
/// plainly. Delete the `OverlappingPrefixes` check from `VpcRouteTable::validate`, so that two peers
/// of one vpc may advertise the same destination, and this property stays silent across 13,908
/// comparisons. The reason is structural: an import prefix-list is rendered per peer, so both routes
/// are installed, in two lists, and the rendered configuration is **the same whichever order the
/// peerings are walked in**. Nothing was silently picked at build time. The picking happens later, in
/// the forwarding plane, on a packet.
///
/// So the ambiguity concern has two halves and this is one of them:
///
/// * **build-time** -- one artifact, two possible contents. Covered here.
/// * **run-time** -- one artifact, two rules inside it that match the same packet. *Not* covered, by
///   anything, and it is the half that misbehaves in production rather than in a build.
///
/// The second needs a different oracle: a check over the *installed tables* that no two entries match
/// one packet with different actions. Worth knowing before writing it that for a rule with no
/// downstream consumer -- and the overlap rule is exactly that, as its green break test showed -- such
/// a check is necessarily a second statement of the requirement rather than an independent one. It
/// would still earn its place, since it would fail if the validator regressed, but it should be
/// written knowing what it is.
mod ambiguity {
    use concurrency::sync::atomic::{AtomicUsize, Ordering};
    use config::{ConfigError, ExternalConfig, ValidatedGwConfig};
    use flow_entry::flow_table::FlowTable;
    use k8s_intf::bolero::mutate::Mutation;
    use k8s_intf::bolero::permute::PermutedAgents;
    use k8s_intf::gateway_agent_crd::GatewayAgent;
    use nat::masquerade::{MasqueradeConfig, NatAllocatorWriter};
    use nat::portfw::{PortFwTableWriter, build_port_forwarding_configuration};
    use nat::static_nat::setup::build_nat_configuration;
    use routing::Render;

    use crate::processor::confbuild::internal::build_internal_config;

    /// Exactly what the wasm validator does, as in the near-miss property.
    fn validator(crd: &GatewayAgent) -> Result<ValidatedGwConfig, ConfigError> {
        let external = ExternalConfig::try_from(crd)
            .map_err(|e| ConfigError::Invalid(format!("conversion: {e}")))?;
        external.validate()
    }

    /// Everything the dataplane installs, as text, in a form two runs can be compared in.
    ///
    /// Lines are sorted. Some of these tables are hash maps, so their iteration order is not part of
    /// the configuration's meaning and comparing it would give false alarms. Sorting costs nothing
    /// that matters: the artifacts whose order *is* semantic -- route maps, prefix lists -- carry
    /// their sequence numbers in the text, so reordering those changes the lines themselves and is
    /// still caught.
    fn artifacts(validated: &ValidatedGwConfig) -> Option<Vec<String>> {
        let genid = validated.genid();
        let internal = build_internal_config(validated, None).ok()?;
        let vpc_table = validated.external().overlay().vpc_table();

        let nat_tables = build_nat_configuration(vpc_table).ok()?;
        let ruleset = build_port_forwarding_configuration(vpc_table).ok()?;
        let mut portfw = PortFwTableWriter::new();
        portfw.update_table(&ruleset).ok()?;

        let masquerade = MasqueradeConfig::new(vpc_table, genid).set_randomize(false);
        let mut allocator = NatAllocatorWriter::new();
        allocator.update_nat_allocator(masquerade, &FlowTable::new(16));

        let mut lines: Vec<String> =
            format!("{}\n{nat_tables}\n{ruleset:#?}", internal.render(&genid))
                .lines()
                .map(|line| line.trim_end().to_string())
                .filter(|line| !line.is_empty())
                .collect();
        lines.sort();
        Some(lines)
    }

    /// Reordering a configuration's sets does not change what it means.
    #[test]
    fn a_configuration_has_only_one_meaning() {
        static MOVED: AtomicUsize = AtomicUsize::new(0);
        static COMPARED: AtomicUsize = AtomicUsize::new(0);

        bolero::check!()
            .with_generator(PermutedAgents::default())
            .cloned()
            .for_each(
                |(mutation, agent, permuted, moved): (Mutation, GatewayAgent, GatewayAgent, bool)| {
                let Ok(first) = validator(&agent) else {
                    // Refused, which is the validator doing its job. Only what it *accepts* has to
                    // have one meaning.
                    return;
                };

                // A permutation cannot make a legal configuration illegal. If it does, the validator
                // is reading order as meaning, which is its own kind of ambiguity.
                let second = validator(&permuted).unwrap_or_else(|e| {
                    panic!(
                        "{mutation:?}: reordering a configuration's sets made the validator refuse \
                         it, so it is treating list order as meaning: {e}"
                    )
                });

                let (Some(before), Some(after)) = (artifacts(&first), artifacts(&second)) else {
                    return;
                };

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

        // Without this the property passes trivially on configurations with nothing to reorder --
        // one peering with one expose holding one prefix has no second order to be in. A tenth is
        // well above what a dead permutation would give and well below what is observed (a fifth,
        // driven by near-misses, since several mutations shorten the very lists this reorders).
        let compared = COMPARED.load(Ordering::Relaxed);
        let moved = MOVED.load(Ordering::Relaxed);
        println!("{moved} of {compared} comparisons were of a genuinely reordered configuration");
        assert!(
            compared > 0 && moved * 10 >= compared,
            "only {moved} of {compared} comparisons actually reordered anything: the permutation is \
             not doing any work"
        );
    }
}
