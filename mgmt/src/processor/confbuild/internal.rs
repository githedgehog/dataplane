// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Methods to build internal configurations

#[allow(unused)]
use tracing::{debug, error, warn};

use config::external::overlay::Overlay;
use config::external::overlay::vpc::{Peering, Vpc};
use config::external::overlay::vpcpeering::VpcManifest;
use config::{ConfigError, ConfigResult};

use lpm::prefix::Prefix;
use net::eth::mac::SourceMac;
use net::ipv4::UnicastIpv4Addr;
use net::route::RouteTableId;
use std::net::Ipv4Addr;

use crate::processor::confbuild::namegen::{VpcConfigNames, VpcInterfacesNames};

use config::internal::interfaces::interface::InterfaceType;
use config::internal::routing::bgp::{AfIpv4Ucast, AfL2vpnEvpn};
use config::internal::routing::bgp::{BgpConfig, BgpOptions, VrfImports};
use config::internal::routing::evpn::VtepConfig;
use config::internal::routing::prefixlist::{
    IpVer, PrefixList, PrefixListAction, PrefixListEntry, PrefixListMatchLen, PrefixListPrefix,
};
use config::internal::routing::routemap::{MatchingPolicy, RouteMap, RouteMapEntry, RouteMapMatch};
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
        let native_prefixes = expose.ips.iter().filter(|p| p.is_ipv4()).map(|prefix| {
            PrefixListEntry::new(
                PrefixListAction::Permit,
                PrefixListPrefix::Prefix(*prefix),
                Some(PrefixListMatchLen::Ge(prefix.length())),
            )
        });
        plist.add_entries(native_prefixes)?;

        // disallow prefix exceptions, whether there's nat or not
        let nots = expose.nots.iter().filter(|p| p.is_ipv4()).map(|prefix| {
            PrefixListEntry::new(
                PrefixListAction::Deny,
                PrefixListPrefix::Prefix(*prefix),
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
        let mut statics: Vec<StaticRoute> = expose.nots.iter().map(build_drop_route).collect();
        sroute_vec.append(&mut statics);
    }
    sroute_vec
}

/// Build AF l2vpn EVPN config for a VPC VRF
fn vpc_bgp_af_l2vpn_evpn(vpc: &Vpc) -> AfL2vpnEvpn {
    AfL2vpnEvpn::new()
        .set_adv_all_vni(false)
        .set_adv_default_gw(false)
        .set_adv_svi_ip(false)
        .set_adv_ipv4_unicast(true)
        .set_adv_ipv4_unicast_rmap(vpc.adv_rmap())
}

/// Build BGP options for a VPC VRF
fn vpc_bgp_options() -> BgpOptions {
    BgpOptions::new()
        .set_network_import_check(false)
        .set_ebgp_requires_policy(false)
        .set_bgp_default_unicast(false)
        .set_supress_duplicates(true)
}

struct VpcRoutingConfigIpv4 {
    /* imports */
    import_rmap: RouteMap,          /* import route-map, one entry per peer */
    import_plists: Vec<PrefixList>, /* import prefix list per peer */
    vrf_imports: VrfImports,        /* import config summary */

    /* advertise */
    adv_nets: Vec<Prefix>,
    adv_rmap: RouteMap,    /* one entry per peer */
    adv_plist: PrefixList, /* one prefix list, one entry per peer */

    /* static routes */
    sroutes: Vec<StaticRoute>,
}
impl VpcRoutingConfigIpv4 {
    fn new(vpc: &Vpc) -> Self {
        Self {
            import_rmap: RouteMap::new(&vpc.import_rmap_ipv4()),
            import_plists: Vec::with_capacity(vpc.num_peerings()),
            vrf_imports: VrfImports::new().set_routemap(&vpc.import_rmap_ipv4()),
            adv_nets: vec![],
            adv_rmap: RouteMap::new(&vpc.adv_rmap()),
            adv_plist: PrefixList::new(&vpc.adv_plist(), IpVer::V4, Some(vpc.adv_plist_desc())),
            sroutes: vec![],
        }
    }
    fn build_routing_config_peer(&mut self, vpc: &Vpc, peer: &Peering) -> ConfigResult {
        /* remote manifest */
        let rmanifest = &peer.remote;

        /* we import from this vrf */
        self.vrf_imports.add_vrf(peer.remote_id.vrf_name().as_ref());

        /* build prefix list for the peer from its remote manifest */
        let plist = vpc_import_prefix_list_for_peer(vpc, rmanifest)?;

        /* static drops for excluded prefixes (optional) */
        let mut statics = build_vpc_drop_routes(rmanifest);
        self.sroutes.append(&mut statics);

        /* create import route-map entry */
        let import_rmap_e = RouteMapEntry::new(MatchingPolicy::Permit)
            .add_match(RouteMapMatch::Ipv4AddressPrefixList(plist.name.clone()))
            .add_match(RouteMapMatch::SrcVrf(peer.remote_id.vrf_name().to_string()));

        /* add entry */
        self.import_rmap.add_entry(None, import_rmap_e)?;

        /* add prefix list to vector */
        self.import_plists.push(plist);

        /* advertise */
        let nets = rmanifest.exposes.iter().flat_map(|e| e.public_ips().iter());
        self.adv_nets.extend(nets);

        /* build adv prefix list */
        for expose in rmanifest.exposes.iter() {
            let prefixes = expose.public_ips().iter();
            let plists = prefixes.map(|prefix| {
                PrefixListEntry::new(
                    PrefixListAction::Permit,
                    PrefixListPrefix::Prefix(*prefix),
                    None,
                )
            });
            self.adv_plist.add_entries(plists)?;
        }

        /* create adv route-map entry and add it */
        let adv_rmap_e = RouteMapEntry::new(MatchingPolicy::Permit).add_match(
            RouteMapMatch::Ipv4AddressPrefixList(self.adv_plist.name.clone()),
        );
        self.adv_rmap.add_entry(None, adv_rmap_e)?;
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
fn vpc_vrf_bgp_config(vpc: &Vpc, asn: u32, router_id: Option<Ipv4Addr>) -> BgpConfig {
    let mut bgp = BgpConfig::new(asn).set_vrf_name(vpc.vrf_name());
    if let Some(router_id) = router_id {
        bgp.set_router_id(router_id);
    }
    bgp.set_bgp_options(vpc_bgp_options());
    bgp
}

/// Build VRF config for a VPC
fn vpc_vrf_config(vpc: &Vpc) -> Result<VrfConfig, ConfigError> {
    debug!("Building VRF config for vpc '{}'", vpc.name);
    /* build vrf config */
    let mut vrf_cfg = VrfConfig::new(&vpc.vrf_name(), Some(vpc.vni), false)
        .set_vpc_id(vpc.id.clone())
        .set_description(&vpc.name);

    /* set table-id: table ids should be unique per VRF. We should track them and pick unused ones.
    Setting this to the VNI is not too bad atm, except that we should avoid picking reserved values
    which may cause internal failures. FIXME: fredi */
    if vpc.vni.as_u32() == 254_u32 {
        error!("Invalid configuration: Vni 254 is reserved");
        return Err(ConfigError::InvalidVpcVni(vpc.vni.as_u32()));
    }
    let table_id = RouteTableId::try_from(vpc.vni.as_u32()).unwrap_or_else(|_| unreachable!());
    vrf_cfg = vrf_cfg.set_table_id(table_id);
    Ok(vrf_cfg)
}

fn vpc_bgp_af_ipv4_unicast(vpc_rconf: &VpcRoutingConfigIpv4) -> AfIpv4Ucast {
    let mut af = AfIpv4Ucast::new();
    //af.set_vrf_imports(vpc_rconf.vrf_imports.clone());
    af.add_networks(vpc_rconf.adv_nets.clone());
    af
}

fn build_vpc_internal_config(
    vpc: &Vpc,
    asn: u32,
    router_id: Option<Ipv4Addr>,
    internal: &mut InternalConfig,
) -> ConfigResult {
    debug!("Building internal config for vpc '{}'", vpc.name);

    /* build VRF config */
    let mut vrf_cfg = vpc_vrf_config(vpc)?;

    /* build bgp config */
    let mut bgp = vpc_vrf_bgp_config(vpc, asn, router_id);

    if vpc.num_peerings() > 0 {
        let mut vpc_rconfig = VpcRoutingConfigIpv4::new(vpc); // fixme build from scratch / no mut
        vpc_rconfig.build_routing_config(vpc)?;
        bgp.set_af_ipv4unicast(vpc_bgp_af_ipv4_unicast(&vpc_rconfig));
        bgp.set_af_l2vpn_evpn(vpc_bgp_af_l2vpn_evpn(vpc));
        internal.add_route_map(vpc_rconfig.import_rmap.clone());
        internal.add_route_map(vpc_rconfig.adv_rmap.clone());
        internal.add_prefix_lists(vpc_rconfig.import_plists.clone());
        internal.add_prefix_list(vpc_rconfig.adv_plist.clone());
        vrf_cfg.add_static_routes(vpc_rconfig.sroutes.clone());
    }

    /* set bgp config */
    vrf_cfg.set_bgp(bgp);
    internal.add_vrf_config(vrf_cfg)?;
    Ok(())
}

struct VtepInfo {
    ip: UnicastIpv4Addr,
    mac: SourceMac,
}

fn get_vtep_info(external: &ExternalConfig) -> Result<VtepInfo, ConfigError> {
    let Some(intf) = external.underlay.get_vtep_interface()? else {
        return Err(ConfigError::InternalFailure(
            "No VTEP configured".to_string(),
        ));
    };
    match &intf.iftype {
        InterfaceType::Vtep(vtep) => {
            let mac = match vtep.mac {
                Some(mac) => SourceMac::new(mac).map_err(|_| {
                    ConfigError::BadVtepMacAddress(
                        mac,
                        "mac address is not a valid source mac address",
                    )
                }),
                None => {
                    return Err(ConfigError::InternalFailure(format!(
                        "Missing VTEP MAC address on {}",
                        intf.name
                    )));
                }
            }?;

            let ip = UnicastIpv4Addr::new(vtep.local).map_err(|_| {
                ConfigError::InternalFailure(format!(
                    "VTEP local address is not a valid unicast address {}",
                    vtep.local
                ))
            })?;
            Ok(VtepInfo { ip, mac })
        }
        _ => unreachable!(),
    }
}

fn build_vtep_config(external: &ExternalConfig) -> Result<VtepConfig, ConfigError> {
    let vtep_info = get_vtep_info(external)?;
    let vtep = VtepConfig {
        address: vtep_info.ip.into(),
        mac: vtep_info.mac,
    };
    Ok(vtep)
}

fn build_internal_overlay_config(
    overlay: &Overlay,
    asn: u32,
    router_id: Option<Ipv4Addr>,
    internal: &mut InternalConfig,
) -> ConfigResult {
    debug!("Building overlay config ({} VPCs)", overlay.vpc_table.len());

    /* Vpcs and peerings */
    for vpc in overlay.vpc_table.values() {
        build_vpc_internal_config(vpc, asn, router_id, internal)?;
    }
    Ok(())
}

/// Top-level function to build internal config from external config
pub fn build_internal_config(config: &GwConfig) -> Result<InternalConfig, ConfigError> {
    let genid = config.genid();
    debug!("Building internal config for gen {genid}");
    let external = &config.external;

    /* Build internal config: device and underlay configs are copied as received */
    let mut internal = InternalConfig::new(external.device.clone());
    internal.add_vrf_config(external.underlay.vrf.clone())?;
    if !external.overlay.vpc_table.is_empty() {
        internal.set_vtep(build_vtep_config(external)?);
    }

    /* Build overlay config */
    if let Some(bgp) = &external.underlay.vrf.bgp {
        let asn = bgp.asn;
        let router_id = bgp.router_id;
        if !external.overlay.vpc_table.is_empty() {
            build_internal_overlay_config(&external.overlay, asn, router_id, &mut internal)?;
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
