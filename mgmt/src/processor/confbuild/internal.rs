// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Methods to build internal configurations

#[allow(unused)]
use tracing::{debug, error, warn};

const IMPORT_VRFS: bool = false;

use config::external::overlay::Overlay;
use config::external::overlay::vpc::{Peering, Vpc};
use config::external::overlay::vpcpeering::VpcManifest;
use config::{ConfigError, ConfigResult};

use lpm::prefix::Prefix;
use net::route::RouteTableId;
use net::vxlan::Vni;
use std::net::Ipv4Addr;

use crate::processor::confbuild::namegen::{VpcConfigNames, VpcInterfacesNames};

use config::internal::routing::bfd::peers_from_bgp_neighbors;
use config::internal::routing::bgp::BmpOptions;
use config::internal::routing::bgp::{AfIpv4Ucast, AfL2vpnEvpn};
use config::internal::routing::bgp::{BgpConfig, BgpOptions, VrfImports};
use config::internal::routing::prefixlist::{
    IpVer, PrefixList, PrefixListAction, PrefixListEntry, PrefixListMatchLen, PrefixListPrefix,
};
use config::internal::routing::routemap::{
    Community, MatchingPolicy, RouteMap, RouteMapEntry, RouteMapMatch, RouteMapSetAction,
};
use config::internal::routing::statics::StaticRoute;
use config::internal::routing::vrf::VrfConfig;
use config::{ExternalConfig, GwConfig, InternalConfig};

/// Build a drop route
#[must_use]
fn build_drop_route(prefix: &Prefix) -> StaticRoute {
    StaticRoute::new(*prefix).nhop_reject()
}

/// Populate a prefix list to import routes into a vpc vrf
fn vpc_import_prefix_list_for_peer(
    vpc: &Vpc,
    rmanifest: &VpcManifest,
) -> Result<PrefixList, ConfigError> {
    let mut plist = PrefixList::new(
        &vpc.import_plist_peer(&rmanifest.name),
        IpVer::V4,
        Some(vpc.import_plist_peer_desc(&rmanifest.name)),
    );
    for expose in &rmanifest.exposes {
        // allow native prefixes, natted or not
        let native_prefixes =
            expose
                .ips
                .iter()
                .filter(|p| p.prefix().is_ipv4())
                .map(|prefix_with_ports| {
                    PrefixListEntry::new(
                        PrefixListAction::Permit,
                        PrefixListPrefix::Prefix(prefix_with_ports.prefix()),
                        Some(PrefixListMatchLen::Ge(prefix_with_ports.prefix().length())),
                    )
                });
        plist.add_entries(native_prefixes)?;

        // disallow prefix exceptions, whether there's nat or not
        let nots = expose
            .nots
            .iter()
            .filter(|p| p.prefix().is_ipv4())
            .map(|prefix_with_ports| {
                PrefixListEntry::new(
                    PrefixListAction::Deny,
                    PrefixListPrefix::Prefix(prefix_with_ports.prefix()),
                    None,
                )
            });
        plist.add_entries(nots)?;
    }
    Ok(plist)
}

#[must_use]
fn build_vpc_drop_routes(rmanifest: &VpcManifest) -> Vec<StaticRoute> {
    let mut sroute_vec: Vec<StaticRoute> = vec![];
    for expose in &rmanifest.exposes {
        let mut statics: Vec<StaticRoute> = expose
            .nots
            .iter()
            .map(|prefix_with_ports| build_drop_route(&prefix_with_ports.prefix()))
            .collect();
        sroute_vec.append(&mut statics);
    }
    sroute_vec
}

/// Build AF l2vpn EVPN config for a VPC VRF
#[must_use]
fn vpc_bgp_af_l2vpn_evpn(vpc: &Vpc) -> AfL2vpnEvpn {
    AfL2vpnEvpn::new()
        .set_adv_all_vni(false)
        .set_adv_default_gw(false)
        .set_adv_svi_ip(false)
        .set_adv_ipv4_unicast(true)
        .set_adv_ipv4_unicast_rmap(vpc.adv_rmap())
}

/// Build BGP options for a VPC VRF
#[must_use]
fn vpc_bgp_options() -> BgpOptions {
    BgpOptions::new()
        .set_network_import_check(false)
        .set_ebgp_requires_policy(false)
        .set_bgp_default_unicast(false)
        .set_supress_duplicates(true)
        .set_always_compare_med(true)
        .set_bestpath_aspath_relax(true)
}

struct VpcRoutingConfigIpv4 {
    /* imports */
    import_rmap: RouteMap,          /* import route-map, one entry per peer */
    import_plists: Vec<PrefixList>, /* import prefix list per peer */
    vrf_imports: VrfImports,        /* import config summary */

    /* advertise */
    adv_nets: Vec<Prefix>,
    adv_rmap: RouteMap,
    adv_plist: Vec<PrefixList>,

    /* static routes */
    sroutes: Vec<StaticRoute>,
}
impl VpcRoutingConfigIpv4 {
    #[must_use]
    fn new(vpc: &Vpc) -> Self {
        Self {
            import_rmap: RouteMap::new(&vpc.import_rmap_ipv4()),
            import_plists: Vec::with_capacity(vpc.num_peerings()),
            vrf_imports: VrfImports::new().set_routemap(&vpc.import_rmap_ipv4()),
            adv_nets: vec![],
            adv_rmap: RouteMap::new(&vpc.adv_rmap()),
            adv_plist: vec![],
            sroutes: vec![],
        }
    }
    fn build_routing_config_peer(&mut self, vpc: &Vpc, peer: &Peering) -> ConfigResult {
        /* remote manifest */
        let rmanifest = &peer.remote;

        /* static drops for excluded prefixes (optional) */
        let mut statics = build_vpc_drop_routes(rmanifest);
        self.sroutes.append(&mut statics);

        /* create import route-map entry */
        if IMPORT_VRFS {
            /* we import from this vrf */
            self.vrf_imports.add_vrf(peer.remote_id.vrf_name().as_ref());

            /* build prefix list for the peer from its remote manifest */
            let plist = vpc_import_prefix_list_for_peer(vpc, rmanifest)?;

            let import_rmap_e = RouteMapEntry::new(MatchingPolicy::Permit)
                .add_match(RouteMapMatch::Ipv4AddressPrefixList(plist.name.clone()))
                .add_match(RouteMapMatch::SrcVrf(peer.remote_id.vrf_name().to_string()));

            /* add entry */
            self.import_rmap.add_entry(None, import_rmap_e)?;

            /* add prefix list to vector */
            self.import_plists.push(plist);
        }

        /* advertise */
        let nets = rmanifest.exposes.iter().flat_map(|e| e.adv_prefixes());

        self.adv_nets.extend(nets);

        /* build adv prefix list and route-map */
        let mut adv_plist = PrefixList::new(
            &vpc.adv_plist(&rmanifest.name),
            IpVer::V4,
            Some(vpc.adv_plist_desc(&rmanifest.name)),
        );
        for expose in rmanifest.exposes.iter() {
            let prefixes = expose.adv_prefixes().into_iter();
            let plists = prefixes.map(|p| {
                PrefixListEntry::new(PrefixListAction::Permit, PrefixListPrefix::Prefix(p), None)
            });
            adv_plist.add_entries(plists)?;
        }
        self.adv_plist.push(adv_plist);

        /* collect communities for this peering */
        let communities: Vec<_> = peer
            .adv_communities
            .iter()
            .map(|c| Community::String(c.clone()))
            .collect();

        /* create adv route-map entry matching prefixes and adding communities if needed */
        let mut adv_rmape = RouteMapEntry::new(MatchingPolicy::Permit);
        adv_rmape = adv_rmape.add_match(RouteMapMatch::Ipv4AddressPrefixList(
            vpc.adv_plist(&rmanifest.name),
        ));
        if !communities.is_empty() {
            adv_rmape = adv_rmape.add_action(RouteMapSetAction::Community(communities, true));
        }

        /* add entry */
        self.adv_rmap.add_entry(None, adv_rmape)?;
        Ok(())
    }

    fn build_routing_config(&mut self, vpc: &Vpc) -> ConfigResult {
        for peer in vpc.peerings.iter() {
            self.build_routing_config_peer(vpc, peer)?;
        }
        Ok(())
    }
}

/// Build BGP config for a VPC VRF
fn vpc_vrf_bgp_config(
    vpc: &Vpc,
    asn: u32,
    router_id: Option<Ipv4Addr>,
    bmp: Option<&BmpOptions>,
) -> BgpConfig {
    let mut bgp = BgpConfig::new(asn).set_vrf_name(vpc.vrf_name());
    if let Some(router_id) = router_id {
        bgp.set_router_id(router_id);
    }
    bgp.set_bgp_options(vpc_bgp_options());

    // If global BMP is provided, clone and add this VRF to its import list,
    // then attach that per-VRF BMP to the VRF BGP. The renderer can later
    // collate all VRF names and emit `bmp import-vrf-view <vrf>` under default BGP.
    if let Some(global_bmp) = bmp {
        let mut per_vrf_bmp = global_bmp.clone();
        per_vrf_bmp.push_import_vrf_view(vpc.vrf_name());
        bgp.set_bmp_options(per_vrf_bmp);
    }

    bgp
}

/// Build VRF config for a VPC
fn vpc_vrf_config(vpc: &Vpc) -> Result<VrfConfig, ConfigError> {
    debug!("Building VRF config for vpc '{}'", vpc.name);
    /* build vrf config */
    let mut vrf_cfg = VrfConfig::new(&vpc.vrf_name(), Some(vpc.vni), false)
        .set_vpc_id(vpc.id.clone())
        .set_description(&vpc.name);

    // Here we set the table-id for the VRF. This is the table-id that will be used to create a VRF net device.
    // Table ids should be unique per VRF. We could track them and pick unused ones. Alternatively, we need
    // a 1:1 mapping to VNIs which are guaranteed to be unique. The easiest is to let table ids match the Vni,
    // except for Vnis that could match reserved table ids such as 253-255
    let table_id = match vpc.vni.as_u32() {
        253_u32 => Vni::MAX + 1, // local
        254_u32 => Vni::MAX + 2, // main
        255_u32 => Vni::MAX + 3, // default
        _ => vpc.vni.as_u32(),
    };
    let table_id = RouteTableId::try_from(table_id).map_err(|_| {
        let emsg = format!(
            "Could not create RouteTableId from {table_id} for VPC {}",
            vpc.name
        );
        error!(emsg);
        ConfigError::InternalFailure(emsg)
    })?;

    vrf_cfg = vrf_cfg.set_table_id(table_id);
    Ok(vrf_cfg)
}

fn vpc_bgp_af_ipv4_unicast(vpc_rconf: &VpcRoutingConfigIpv4) -> AfIpv4Ucast {
    let mut af = AfIpv4Ucast::new();
    if IMPORT_VRFS {
        af.set_vrf_imports(vpc_rconf.vrf_imports.clone());
    }
    af.add_networks(vpc_rconf.adv_nets.clone());
    af
}

fn build_vpc_internal_config(
    vpc: &Vpc,
    asn: u32,
    router_id: Option<Ipv4Addr>,
    internal: &mut InternalConfig,
    bmp: Option<&BmpOptions>,
) -> ConfigResult {
    debug!("Building internal config for vpc '{}'", vpc.name);

    /* build VRF config */
    let mut vrf_cfg = vpc_vrf_config(vpc)?;

    /* build bgp config */
    let mut bgp = vpc_vrf_bgp_config(vpc, asn, router_id, bmp);

    if vpc.num_peerings() > 0 {
        let mut vpc_rconfig = VpcRoutingConfigIpv4::new(vpc); // fixme build from scratch / no mut
        vpc_rconfig.build_routing_config(vpc)?;
        bgp.set_af_ipv4unicast(vpc_bgp_af_ipv4_unicast(&vpc_rconfig));
        bgp.set_af_l2vpn_evpn(vpc_bgp_af_l2vpn_evpn(vpc));

        if IMPORT_VRFS {
            internal.add_route_map(vpc_rconfig.import_rmap.clone());
            internal.add_prefix_lists(vpc_rconfig.import_plists.clone());
        }

        internal.add_route_map(vpc_rconfig.adv_rmap.clone());
        internal.add_prefix_lists(vpc_rconfig.adv_plist.clone());
        vrf_cfg.add_static_routes(vpc_rconfig.sroutes.clone());
    }

    /* set bgp config */
    vrf_cfg.set_bgp(bgp);
    internal.add_vrf_config(vrf_cfg)?;
    Ok(())
}

fn build_internal_overlay_config(
    overlay: &Overlay,
    asn: u32,
    router_id: Option<Ipv4Addr>,
    internal: &mut InternalConfig,
    bmp: Option<&BmpOptions>,
) -> ConfigResult {
    debug!("Building overlay config ({} VPCs)", overlay.vpc_table.len());

    /* Vpcs and peerings */
    for vpc in overlay.vpc_table.values() {
        build_vpc_internal_config(vpc, asn, router_id, internal, bmp)?;
    }
    Ok(())
}

/// Public entry — build without BMP
pub fn build_internal_config(config: &GwConfig) -> Result<InternalConfig, ConfigError> {
    build_internal_config_with_bmp(config, None)
}

/// Public entry — build with BMP (global options replicated per VRF with import list)
pub fn build_internal_config_with_bmp(
    config: &GwConfig,
    bmp: Option<BmpOptions>,
) -> Result<InternalConfig, ConfigError> {
    let genid = config.genid();
    debug!("Building internal config for gen {genid}");
    let external = &config.external;

    /* Build internal config: device and underlay configs are copied as received */
    let mut internal = InternalConfig::new(&config.gwname, external.device.clone());
    internal.add_vrf_config(external.underlay.vrf.clone())?;
    internal.set_vtep(external.underlay.vtep.clone());

    // Build BFD peers from underlay BGP neighbors
    if let Some(bgp) = &external.underlay.vrf.bgp {
        internal.set_bfd_peers(peers_from_bgp_neighbors(&bgp.neighbors));
    }

    /* Build overlay config */
    if let Some(bgp) = &external.underlay.vrf.bgp {
        let asn = bgp.asn;
        let router_id = bgp.router_id;
        if !external.overlay.vpc_table.is_empty() {
            build_internal_overlay_config(
                &external.overlay,
                asn,
                router_id,
                &mut internal,
                bmp.as_ref(), /* pass BMP down */
            )?;
        } else {
            debug!("The configuration does not specify any VPCs...");
        }
    } else if config.genid() != ExternalConfig::BLANK_GENID {
        warn!("Config has no BGP configuration");
    }
    /* done */
    debug!("Successfully built internal config for genid {genid}");
    if genid != ExternalConfig::BLANK_GENID {
        debug!("Internal config is:\n{internal:#?}");
    }
    Ok(internal)
}
