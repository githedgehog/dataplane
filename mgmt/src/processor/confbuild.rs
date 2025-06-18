// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#[allow(unused)]
use tracing::{debug, error, warn};

use crate::models::external::overlay::vpcpeering::VpcManifest;
use crate::models::external::{ConfigError, overlay::Overlay};
use crate::models::external::{ConfigResult, overlay::vpc::Vpc};
use net::eth::mac::SourceMac;
use net::ipv4::UnicastIpv4Addr;
use net::route::RouteTableId;
use routing::prefix::Prefix;
use std::net::Ipv4Addr;

use crate::models::external::gwconfig::{ExternalConfig, GwConfig};
use crate::models::internal::InternalConfig;
use crate::models::internal::interfaces::interface::InterfaceType;
use crate::models::internal::nat::table_extend::add_peering;
use crate::models::internal::nat::tables::{NatTables, PerVniTable};
use crate::models::internal::routing::bgp::{AfIpv4Ucast, AfL2vpnEvpn};
use crate::models::internal::routing::bgp::{BgpConfig, BgpOptions, VrfImports};
use crate::models::internal::routing::evpn::VtepConfig;
use crate::models::internal::routing::prefixlist::{
    PrefixList, PrefixListAction, PrefixListEntry, PrefixListPrefix,
};
use crate::models::internal::routing::routemap::{
    MatchingPolicy, RouteMap, RouteMapEntry, RouteMapMatch,
};
use crate::models::internal::routing::statics::StaticRoute;
use crate::models::internal::routing::vrf::VrfConfig;

/// Build a drop route
#[must_use]
fn build_drop_route(prefix: &Prefix) -> StaticRoute {
    StaticRoute::new(*prefix).nhop_reject()
}

/// Populate a prefix list from a remote manifest
#[must_use]
fn populate_prefix_list(plist: &mut PrefixList, rmanifest: &VpcManifest) -> Vec<StaticRoute> {
    let mut sroute_vec: Vec<StaticRoute> = vec![];
    let mut seq: u32 = 1;
    for expose in &rmanifest.exposes {
        if expose.as_range.is_empty() {
            for prefix in expose.ips.iter() {
                let entry = PrefixListEntry::new(
                    seq,
                    PrefixListAction::Permit,
                    PrefixListPrefix::Prefix(*prefix),
                    None,
                );
                plist.add_entry(entry);
                seq += 1;
            }
            sroute_vec = expose.nots.iter().map(build_drop_route).collect();
        } else {
            // NAT
            for prefix in expose.as_range.iter() {
                let entry = PrefixListEntry::new(
                    seq,
                    PrefixListAction::Permit,
                    PrefixListPrefix::Prefix(*prefix),
                    None,
                );
                plist.add_entry(entry);
                seq += 1;
            }
        }
    }
    sroute_vec
}

/// Build a vector of prefix lists, one per peering, and a route-map for a given VPC
#[must_use]
fn vpc_ipv4_import_configuration(vpc: &Vpc) -> (RouteMap, Vec<PrefixList>, Vec<StaticRoute>) {
    debug!("Building import config for vpc '{}'", vpc.name);
    let mut seq: u32 = 10; /* route-map sequence number */
    let mut plist_vec = vec![]; /* a vector of prefix lists to return */
    let mut sroute_vec = vec![];
    let mut rmap = RouteMap::new(&vpc.import_route_map_ipv4()); /* import route-map for this vpc */
    for p in vpc.peerings.iter() {
        let rmanifest = &p.remote;
        /* build prefix list from remote manifest */
        let mut plist = PrefixList::new(
            &vpc.plist_with_vpc(&rmanifest.name),
            Some(vpc.plist_with_vpc_descr(&rmanifest.name)),
        );

        /* populate prefix list and build static drops for excluded prefixes */
        let mut statics = populate_prefix_list(&mut plist, rmanifest);
        sroute_vec.append(&mut statics);

        /* update route-map */
        let entry = RouteMapEntry::new(seq, MatchingPolicy::Permit)
            .add_match(RouteMapMatch::Ipv4AddressPrefixList(plist.name.clone()))
            .add_match(RouteMapMatch::SrcVrf(p.remote_id.vrf_name().to_string()));
        rmap.add_entry(entry);
        seq += 10;

        /* add prefix list to vector */
        plist_vec.push(plist);
    }
    (rmap, plist_vec, sroute_vec)
}

/// Determine ipv4 imports for a VPC
fn vpc_ipv4_imports(vpc: &Vpc) -> VrfImports {
    let mut imports = VrfImports::new().set_routemap(&vpc.import_route_map_ipv4());
    for p in vpc.peerings.iter() {
        imports.add_vrf(p.remote_id.vrf_name().as_ref());
    }
    imports
}

/// Build AF Ipv4 unicast config for a VPC VRF
fn vpc_bgp_af_ipv4(vpc: &Vpc) -> AfIpv4Ucast {
    let mut af = AfIpv4Ucast::new();
    if vpc.num_peerings() > 0 {
        af.set_vrf_imports(vpc_ipv4_imports(vpc));
    }
    af
}

/// Build AF l2vpn EVPN config for a VPC VRF
fn vpc_bgp_af_l2vpn_evpn(_vpc: &Vpc) -> AfL2vpnEvpn {
    AfL2vpnEvpn::new()
        .set_adv_all_vni(false)
        .set_adv_default_gw(false)
        .set_adv_svi_ip(false)
        .set_adv_ipv4_unicast(true)
}

/// Build BGP options for a VPC VRF
fn vpc_bgp_options() -> BgpOptions {
    BgpOptions::new()
        .set_network_import_check(false)
        .set_ebgp_requires_policy(false)
        .set_bgp_default_unicast(false)
        .set_supress_duplicates(true)
}

/// Build BGP config for a VPC VRF
fn vpc_vrf_bgp_config(vpc: &Vpc, asn: u32, router_id: Option<Ipv4Addr>) -> BgpConfig {
    let mut bgp = BgpConfig::new(asn).set_vrf_name(vpc.vrf_name());
    if let Some(router_id) = router_id {
        bgp.set_router_id(router_id);
    }
    bgp.set_bgp_options(vpc_bgp_options());
    bgp.set_af_l2vpn_evpn(vpc_bgp_af_l2vpn_evpn(vpc));
    bgp.set_af_ipv4unicast(vpc_bgp_af_ipv4(vpc));
    bgp
}

/// Build VRF config for a VPC
fn vpc_vrf_config(vpc: &Vpc, asn: u32, router_id: Option<Ipv4Addr>) -> VrfConfig {
    debug!("Building VRF config for vpc '{}'", vpc.name);
    /* build vrf config */
    let mut vrf_cfg =
        VrfConfig::new(&vpc.vrf_name(), Some(vpc.vni), false).set_vpc_id(vpc.id.clone());

    /* set table-id: table ids should be unique per VRF. We should track them and pick unused ones.
    Setting this to the VNI is not too bad atm, except that we should avoid picking reserved values
    which may cause internal failures. FIXME: fredi */
    // TODO: we can't just unwrap here
    vrf_cfg = vrf_cfg.set_table_id(RouteTableId::try_from(vpc.vni.as_u32()).unwrap());

    /* build BGP config for vrf */
    vrf_cfg.set_bgp(vpc_vrf_bgp_config(vpc, asn, router_id));

    vrf_cfg
}

fn build_vpc_internal_config(
    vpc: &Vpc,
    asn: u32,
    router_id: Option<Ipv4Addr>,
    internal: &mut InternalConfig,
) -> ConfigResult {
    debug!("Building internal config for vpc '{}'", vpc.name);

    /* build VRF config */
    let mut vrf_cfg = vpc_vrf_config(vpc, asn, router_id);

    /* build import configuration */
    let (rmap, plists, statics) = vpc_ipv4_import_configuration(vpc);

    /* add route-map */
    internal.add_route_map(rmap);

    /* add prefix lists */
    plists
        .into_iter()
        .for_each(|plist| internal.add_prefix_list(plist));

    /* add static routes */
    statics
        .into_iter()
        .for_each(|static_route| vrf_cfg.add_static_route(static_route));

    /* add vrf config */
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

fn build_vtep_config(external: &ExternalConfig, internal: &mut InternalConfig) -> ConfigResult {
    let vtep_info = get_vtep_info(external)?;

    let vtep = VtepConfig {
        address: vtep_info.ip.into(),
        mac: vtep_info.mac,
    };
    internal.set_vtep(vtep);
    Ok(())
}

fn build_nat_internal_config(overlay: &Overlay, internal: &mut InternalConfig) -> ConfigResult {
    let mut nat_tables = NatTables::new();
    for vpc in overlay.vpc_table.values() {
        let mut table = PerVniTable::new();
        for peering in &vpc.peerings {
            add_peering(&mut table, peering)
                .map_err(|e| ConfigError::FailureApply(e.to_string()))?;
        }
        nat_tables.add_table(vpc.vni, table);
    }
    internal.add_nat_tables(nat_tables);
    Ok(())
}

fn build_internal_overlay_config(
    overlay: &Overlay,
    asn: u32,
    router_id: Option<Ipv4Addr>,
    internal: &mut InternalConfig,
) -> ConfigResult {
    debug!("Building overlay config...");
    for vpc in overlay.vpc_table.values() {
        build_vpc_internal_config(vpc, asn, router_id, internal)?;
    }
    build_nat_internal_config(overlay, internal)?;
    debug!("Internal config is:\n{internal:#?}");
    Ok(())
}

/// Top-level function to build internal config from external config
pub fn build_internal_config(config: &GwConfig) -> Result<InternalConfig, ConfigError> {
    let genid = config.genid();
    debug!("Building internal config for gen {genid}");
    let external = &config.external;

    /* Build internal config object: device and underlay configs are copied as received */
    let mut internal = InternalConfig::new(external.device.clone());
    internal.add_vrf_config(external.underlay.vrf.clone())?;

    /* Build overlay config */
    if let Some(bgp) = &external.underlay.vrf.bgp {
        let asn = bgp.asn;
        let router_id = bgp.router_id;
        build_internal_overlay_config(&external.overlay, asn, router_id, &mut internal)?;
        if internal.vrfs.vpc_vrfs().count() > 0 {
            build_vtep_config(external, &mut internal)?;
        }
    } else if config.genid() != ExternalConfig::BLANK_GENID {
        warn!("Config has no BGP configuration");
    }

    debug!("Successfully built internal config for genid {genid}");
    Ok(internal)
}
