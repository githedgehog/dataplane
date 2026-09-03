// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Methods to build internal configurations

#[allow(unused)]
use tracing::{debug, error, warn};

/// Whether a vpc's routing configuration imports routes from the vrfs it peers with.
///
/// Compile-time false, so `vpc_import_prefix_list_for_peer` and the two other sites
/// guarded by it are unreachable today. Worth knowing before flipping it: those sites
/// used to drop IPv6 prefixes silently and now refuse the whole configuration by name,
/// so turning this on turns a quiet omission into a hard failure for any peering that
/// carries IPv6.
const IMPORT_VRFS: bool = false;

use config::external::communities::PriorityCommunityTable;
use config::external::gwgroup::GwGroupTable;
use config::external::overlay::ValidatedOverlay;
use config::external::overlay::vpc::{ValidatedPeering, ValidatedVpc};
use config::external::overlay::vpcpeering::ValidatedManifest;
use config::{ConfigError, ConfigResult};

use lpm::prefix::{Prefix, PrefixWithOptionalPorts};
use net::route::RouteTableId;
use net::vxlan::Vni;
use std::net::Ipv4Addr;

use crate::processor::confbuild::namegen::{VpcConfigNames, VpcInterfacesNames};
use config::internal::routing::bfd::peers_from_bgp_neighbors;
use config::internal::routing::bgp::{AfIpv4Ucast, AfL2vpnEvpn, BgpNeighAF, NeighSendCommunities};
use config::internal::routing::bgp::{BgpConfig, BgpNeighCapabilities, BgpOptions, VrfImports};
use config::internal::routing::bmp::BmpOptions;
use config::internal::routing::prefixlist::{
    IpVer, PrefixList, PrefixListAction, PrefixListEntry, PrefixListMatchLen, PrefixListPrefix,
};
use config::internal::routing::routemap::{
    Community, MatchingPolicy, RouteMap, RouteMapEntry, RouteMapMatch, RouteMapSetAction,
};
use config::internal::routing::statics::StaticRoute;
use config::internal::routing::vrf::VrfConfig;
use config::{InternalConfig, ValidatedGwConfig};

/// Populate a prefix list to import routes into a vpc vrf
fn vpc_import_prefix_list_for_peer(
    vpc: &ValidatedVpc,
    rmanifest: &ValidatedManifest,
) -> Result<PrefixList, ConfigError> {
    let mut plist = PrefixList::new(
        &vpc.import_plist_peer(rmanifest.name()),
        IpVer::V4,
        Some(vpc.import_plist_peer_desc(rmanifest.name())),
    );
    for expose in rmanifest.valexp() {
        reject_ipv6(expose.ips().iter().map(PrefixWithOptionalPorts::prefix))?;
        // allow native prefixes, natted or not
        let native_prefixes = expose.ips().iter().map(|prefix_with_ports| {
            PrefixListEntry::new(
                PrefixListAction::Permit,
                PrefixListPrefix::Prefix(prefix_with_ports.prefix()),
                Some(PrefixListMatchLen::Ge(prefix_with_ports.prefix().length())),
            )
        });
        plist.add_entries(native_prefixes)?;
    }
    Ok(plist)
}

fn reject_ipv6(prefixes: impl IntoIterator<Item = Prefix>) -> ConfigResult {
    if prefixes.into_iter().any(|prefix| prefix.is_ipv6()) {
        return Err(ConfigError::Unsupported(
            "IPv6 prefixes in a vpc peering: the FRR configuration built from a peering is \
             IPv4-only, so such a peering cannot be rendered",
        ));
    }
    Ok(())
}

/// Build AF l2vpn EVPN config for a VPC VRF
#[must_use]
fn vpc_bgp_af_l2vpn_evpn(vpc: &ValidatedVpc) -> AfL2vpnEvpn {
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
    fn new(vpc: &ValidatedVpc) -> Self {
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
    fn build_routing_config_peer(
        &mut self,
        vpc: &ValidatedVpc,
        peer: &ValidatedPeering,
        community: Community,
    ) -> ConfigResult {
        /* remote manifest */
        let rmanifest = peer.remote();

        /* create import route-map entry */
        if IMPORT_VRFS {
            /* we import from this vrf */
            self.vrf_imports
                .add_vrf(peer.remote_id().vrf_name().as_ref());

            /* build prefix list for the peer from its remote manifest */
            let plist = vpc_import_prefix_list_for_peer(vpc, rmanifest)?;

            let import_rmap_e = RouteMapEntry::new(MatchingPolicy::Permit)
                .add_match(RouteMapMatch::Ipv4AddressPrefixList(plist.name.clone()))
                .add_match(RouteMapMatch::SrcVrf(
                    peer.remote_id().vrf_name().to_string(),
                ));

            /* add entry */
            self.import_rmap.add_entry(None, import_rmap_e)?;

            /* add prefix list to vector */
            self.import_plists.push(plist);
        }

        /* remote prefixes on this peering */
        let mut nets: Vec<Prefix> = rmanifest
            .valexp()
            .iter()
            .flat_map(|e| e.adv_prefixes())
            .collect();

        /* sort and remove duplicates */
        nets.sort_unstable();
        nets.dedup();

        reject_ipv6(nets.iter().copied())?;

        /* list of advertised prefixes */
        self.adv_nets.extend(nets.clone());

        /* build adv prefix list and route-map */
        let mut adv_plist = PrefixList::new(
            &vpc.adv_plist(rmanifest.name()),
            IpVer::V4,
            Some(vpc.adv_plist_desc(rmanifest.name())),
        );
        let pl_entries = nets.iter().map(|p| {
            PrefixListEntry::new(PrefixListAction::Permit, PrefixListPrefix::Prefix(*p), None)
        });
        adv_plist.add_entries(pl_entries)?;
        self.adv_plist.push(adv_plist);

        /* create adv route-map entry matching prefixes and adding communities */
        let mut adv_rmape = RouteMapEntry::new(MatchingPolicy::Permit);
        adv_rmape = adv_rmape
            .add_match(RouteMapMatch::Ipv4AddressPrefixList(
                vpc.adv_plist(rmanifest.name()),
            ))
            .add_action(RouteMapSetAction::Community(vec![community], true));

        /* add entry */
        self.adv_rmap.add_entry(None, adv_rmape)?;
        Ok(())
    }

    fn build_routing_config(
        &mut self,
        gwname: &str,
        vpc: &ValidatedVpc,
        grouptable: &GwGroupTable,
        commtable: &PriorityCommunityTable,
    ) -> ConfigResult {
        for peer in vpc.peerings().iter() {
            if let Some(rank) = grouptable.get_group_member_rank(peer.gwgroup(), gwname)
                && let Some(comm) = commtable.get_community(rank)
            {
                self.build_routing_config_peer(vpc, peer, Community::String(comm.clone()))?;
            }
        }
        Ok(())
    }
}

/// Build BGP config for a VPC VRF (bmp is applied elsewhere)
fn vpc_vrf_bgp_config(vpc: &ValidatedVpc, asn: u32, router_id: Option<Ipv4Addr>) -> BgpConfig {
    let mut bgp = BgpConfig::new(asn).set_vrf_name(vpc.vrf_name());
    if let Some(router_id) = router_id {
        bgp.set_router_id(router_id);
    }
    bgp.set_bgp_options(vpc_bgp_options());
    bgp
}

/// Build VRF config for a VPC
fn vpc_vrf_config(vpc: &ValidatedVpc) -> Result<VrfConfig, ConfigError> {
    debug!("Building VRF config for vpc '{}'", vpc.name());
    /* build vrf config */
    let mut vrf_cfg = VrfConfig::new(&vpc.vrf_name(), Some(vpc.vni()), false)
        .set_vpc_id(vpc.id().clone())
        .set_description(vpc.name());

    // Here we set the table-id for the VRF. This is the table-id that will be used to create a VRF net device.
    // Table ids should be unique per VRF. We could track them and pick unused ones. Alternatively, we need
    // a 1:1 mapping to VNIs which are guaranteed to be unique. The easiest is to let table ids match the Vni,
    // except for Vnis that could match reserved table ids such as 253-255
    let table_id = match vpc.vni().as_u32() {
        253_u32 => Vni::MAX + 1, // local
        254_u32 => Vni::MAX + 2, // main
        255_u32 => Vni::MAX + 3, // default
        _ => vpc.vni().as_u32(),
    };
    let table_id = RouteTableId::try_from(table_id).map_err(|_| {
        let emsg = format!(
            "Could not create RouteTableId from {table_id} for VPC {}",
            vpc.name()
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
    vpc: &ValidatedVpc,
    asn: u32,
    router_id: Option<Ipv4Addr>,
    internal: &mut InternalConfig,
) -> ConfigResult {
    debug!("Building internal config for vpc '{}'", vpc.name());

    /* build VRF config */
    let mut vrf_cfg = vpc_vrf_config(vpc)?;

    /* build bgp config */
    let mut bgp = vpc_vrf_bgp_config(vpc, asn, router_id);

    if vpc.num_peerings() > 0 {
        let mut vpc_rconfig = VpcRoutingConfigIpv4::new(vpc); // fixme build from scratch / no mut
        vpc_rconfig.build_routing_config(
            &internal.gwname,
            vpc,
            &internal.gwgrouptable,
            &internal.commtable,
        )?;
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
    overlay: &ValidatedOverlay,
    asn: u32,
    router_id: Option<Ipv4Addr>,
    internal: &mut InternalConfig,
) -> ConfigResult {
    debug!(
        "Building overlay config ({} VPCs)",
        overlay.vpc_table().len()
    );

    /* Vpcs and peerings */
    for vpc in overlay.vpc_table().values() {
        build_vpc_internal_config(vpc, asn, router_id, internal)?;
    }
    Ok(())
}

pub(crate) const EVPN_RMAP_NO_ADV_COMM: &str = "EVPN-ROUTE-MAP-NO-ADV-COMM";

/// Create a route-map that adds community "no-advertise" to all routes
fn route_map_add_noadv_comm() -> RouteMap {
    let mut rmap = RouteMap::new(EVPN_RMAP_NO_ADV_COMM);
    let entry = RouteMapEntry::new(MatchingPolicy::Permit).add_action(
        RouteMapSetAction::Community(vec![Community::NoAdvertise], true),
    );
    rmap.add_entry(Some(1), entry)
        .unwrap_or_else(|_| unreachable!());
    rmap
}

fn configure_bgp_peers(vrf: &mut VrfConfig, internal: &mut InternalConfig) {
    // build and store route-map to add "no-advertise" community to learnt routes
    let rmap_in = route_map_add_noadv_comm();
    internal.rmap_table.add_route_map(rmap_in.clone());

    // apply rmap to neighbors in l2vpn evpn AF and activate other AFs
    if let Some(bgp) = &mut vrf.bgp {
        bgp.neighbors_mut().for_each(|neigh| {
            let af_l2vp_evpn = BgpNeighAF::with_rmap_in(EVPN_RMAP_NO_ADV_COMM);
            neigh.ipv4_unicast_activate(BgpNeighAF::default());
            neigh.update_capabilities(BgpNeighCapabilities::default());
            neigh.update_send_community(NeighSendCommunities::Both);
            neigh.ipv6_unicast_activate(BgpNeighAF::default());
            neigh.l2vpn_evpn_activate(af_l2vp_evpn);
        });
    }
}

/// Public entry — build with BMP (global options injected into default VRF and import views)
pub fn build_internal_config(
    config: &ValidatedGwConfig,
    bmp: Option<BmpOptions>,
) -> Result<InternalConfig, ConfigError> {
    let genid = config.genid();
    debug!("Building internal config for gen {genid}");
    let external = config.external();

    // Prepare default VRF (possibly inject global BMP with VRF import views)
    let mut default_vrf = external.underlay().vrf.clone();

    // If BMP is provided and default VRF has BGP, attach BMP there and add import views
    if let (Some(mut bmp_opts), Some(bgp_default)) = (bmp, default_vrf.bgp.as_mut()) {
        // Collect all overlay VRF names to import
        for vpc in external.overlay().vpc_table().values() {
            bmp_opts.push_import_vrf_view(vpc.vrf_name());
        }
        // Inject BMP into default VRF BGP
        bgp_default.set_bmp_options(bmp_opts);
    }

    // Build internal config: device and underlay configs are copied as received (with adjusted default_vrf)
    let mut internal = InternalConfig::new(external.gwname(), external.device().clone());

    configure_bgp_peers(&mut default_vrf, &mut internal);

    internal.add_vrf_config(default_vrf)?;
    internal.set_vtep(external.underlay().vtep.clone());
    internal.gwgrouptable = external.gwgroups().clone();
    internal.commtable = external.communities().clone();

    // Build BFD peers from underlay BGP neighbors
    if let Some(bgp) = &external.underlay().vrf.bgp {
        internal.set_bfd_peers(peers_from_bgp_neighbors(&bgp.neighbors));
    }

    // Build overlay config
    if let Some(bgp) = &external.underlay().vrf.bgp {
        let asn = bgp.asn;
        let router_id = bgp.router_id;
        if !external.overlay().vpc_table().is_empty() {
            build_internal_overlay_config(external.overlay(), asn, router_id, &mut internal)?;
        } else {
            debug!("The configuration does not specify any VPCs...");
        }
    }
    debug!("Successfully built internal config for genid {genid}");
    Ok(internal)
}

#[cfg(test)]
mod chain_properties {
    use super::*;
    use config::{ExternalConfig, GenId};
    use k8s_intf::bolero::AddressFamily;

    /// How many cases a run needs before a health check may assert on a rate.
    ///
    /// Under miri and under qemu a property gets a handful of cases, so a fraction of
    /// them says nothing and a threshold on it is pure flake.
    const ENOUGH_CASES: usize = 200;
    use k8s_intf::bolero::crd::{GatewayAgentBuilder, GatewayAgents};
    use k8s_intf::gateway_agent_crd::GatewayAgent;
    use routing::Render;
    use std::collections::BTreeSet;

    fn ipv4_agents() -> GatewayAgents {
        GatewayAgentBuilder::new()
            .families(vec![AddressFamily::V4])
            .build()
    }

    fn chain(agent: &GatewayAgent) -> Option<(GenId, ValidatedGwConfig, InternalConfig)> {
        let external = ExternalConfig::try_from(agent)
            .unwrap_or_else(|e| panic!("a schema-legal CRD did not convert: {e}"));
        let validated = external.validate().ok()?;
        let genid = validated.genid();
        let internal = build(&validated);
        Some((genid, validated, internal))
    }

    /// Build, without treating any failure as a skip.
    ///
    /// This used to fold `ConfigError::Unsupported` into a `None` that each caller
    /// quietly returned on. That error has exactly one producer, `reject_ipv6`, and
    /// these properties generate IPv4 only, so the arm never fired. It stood ready to
    /// turn a real "the validator accepted what the builder refuses" defect into an
    /// invisible skip the moment the generator learned IPv6, and nothing counted how
    /// often it was taken.
    fn build(validated: &ValidatedGwConfig) -> InternalConfig {
        build_internal_config(validated, None).unwrap_or_else(|e| {
            panic!("a validated configuration would not build: {e}\n{validated:#?}")
        })
    }

    /// Assert every prefix a peering advertises survives into the rendered configuration,
    /// and report how many there were.
    ///
    /// This is the only check here that depends on the per-peering half of the build
    /// having run. Without it that half can return early and every other assertion in
    /// this module still holds, because they all read the per-vpc and underlay half.
    ///
    /// Only peerings this gateway actually handles count. `build_routing_config` renders
    /// a peer when the gateway is a member of the group the peering names and a community
    /// exists for its rank in that group; a peering failing either is legitimately absent
    /// from the output, and demanding its prefixes would be asserting a bug into place.
    ///
    /// The prefixes come from the validated configuration rather than the CRD, because
    /// validation collapses and normalises them and the collapsed form is what renders.
    fn advertised_prefixes_reach(validated: &ValidatedGwConfig, text: &str) -> usize {
        let external = validated.external();
        let (gwname, groups, communities) = (
            external.gwname(),
            external.gwgroups(),
            external.communities(),
        );
        let mut count = 0;
        for vpc in external.overlay().vpc_table().values() {
            for peering in vpc.peerings().iter() {
                let handled = groups
                    .get_group_member_rank(peering.gwgroup(), gwname)
                    .is_some_and(|rank| communities.get_community(rank).is_some());
                if !handled {
                    continue;
                }
                for expose in peering.remote().valexp() {
                    for prefix in expose.adv_prefixes() {
                        count += 1;
                        assert!(
                            text.contains(&prefix.to_string()),
                            "{prefix} is advertised by a peering this gateway handles but never \
                             reaches the rendered config"
                        );
                    }
                }
            }
        }
        count
    }

    #[test]
    fn whatever_validates_builds_and_renders() {
        use concurrency::sync::atomic::{AtomicUsize, Ordering};
        static SEEN: AtomicUsize = AtomicUsize::new(0);
        static ADVERTISED: AtomicUsize = AtomicUsize::new(0);

        bolero::check!()
            .with_generator(ipv4_agents())
            .for_each(|agent| {
                SEEN.fetch_add(1, Ordering::Relaxed);
                let Some((genid, validated, internal)) = chain(agent) else {
                    return;
                };
                let text = internal.render(&genid).to_string();
                assert!(
                    text.contains(&format!("! config for gen {genid}")),
                    "the rendered config does not say which generation it is for"
                );
                ADVERTISED.fetch_add(
                    advertised_prefixes_reach(&validated, &text),
                    Ordering::Relaxed,
                );
            });

        let seen = SEEN.load(Ordering::Relaxed);
        let advertised = ADVERTISED.load(Ordering::Relaxed);
        println!("{advertised} advertised prefixes checked across {seen} configurations");
        if seen > ENOUGH_CASES {
            assert!(
                advertised > 0,
                "no configuration advertised anything, so the per-peering half of the build \
                 was never checked"
            );
        }
    }

    #[test]
    fn every_vpc_gets_a_vrf_and_no_more() {
        bolero::check!()
            .with_generator(ipv4_agents())
            .for_each(|agent| {
                let external = ExternalConfig::try_from(agent)
                    .unwrap_or_else(|e| panic!("a schema-legal CRD did not convert: {e}"));
                let Ok(validated) = external.validate() else {
                    return;
                };
                let internal = build(&validated);

                let wanted: BTreeSet<u32> = validated
                    .external()
                    .overlay()
                    .vpc_table()
                    .values()
                    .map(|vpc| vpc.vni().as_u32())
                    .collect();
                let built: BTreeSet<u32> = internal
                    .vrfs
                    .iter_by_name()
                    .filter_map(|vrf| vrf.vni.map(|vni| vni.as_u32()))
                    .collect();
                assert_eq!(built, wanted, "vrfs do not match the vpcs they come from");

                // Matching the set of vnis leaves almost everything about a vrf unchecked:
                // two vrfs sharing a vni collapse into one element, and name, description,
                // vpc id and table id are never looked at. Pointing every vrf at the wrong
                // kernel routing table passed this.
                let mut table_ids = BTreeSet::new();
                for vpc in validated.external().overlay().vpc_table().values() {
                    let vrf = internal
                        .vrfs
                        .iter_by_name()
                        .find(|vrf| vrf.vni == Some(vpc.vni()))
                        .unwrap_or_else(|| panic!("no vrf carries the vni of {}", vpc.name()));

                    assert_eq!(vrf.name, vpc.vrf_name(), "vrf name");
                    assert_eq!(vrf.vpc_id.as_ref(), Some(vpc.id()), "vrf vpc id");
                    assert_eq!(
                        vrf.description.as_deref(),
                        Some(vpc.name()),
                        "vrf description"
                    );

                    // A vrf's route table is the vpc's vni, so that an operator can reach
                    // it by the number they already know. The exception is a vni that
                    // collides with a table id the kernel reserves, which is moved above
                    // the vni space instead.
                    let tableid = vrf
                        .tableid
                        .unwrap_or_else(|| panic!("the vrf for {} has no route table", vpc.name()));
                    let vni = vpc.vni().as_u32();
                    let expected = match vni {
                        253..=255 => Vni::MAX + (vni - 252),
                        _ => vni,
                    };
                    assert_eq!(
                        u32::from(tableid),
                        expected,
                        "the vrf for {} points at the wrong route table",
                        vpc.name()
                    );
                    assert!(
                        !matches!(u32::from(tableid), 253..=255),
                        "the vrf for {} claims a route table the kernel reserves",
                        vpc.name()
                    );
                    assert!(
                        table_ids.insert(tableid),
                        "two vrfs share route table {tableid:?}, so one of them will not exist"
                    );
                }
            });
    }

    #[test]
    fn the_properties_are_not_vacuous() {
        use concurrency::sync::atomic::{AtomicUsize, Ordering};
        static SEEN: AtomicUsize = AtomicUsize::new(0);
        static VALIDATED: AtomicUsize = AtomicUsize::new(0);
        static VPCS: AtomicUsize = AtomicUsize::new(0);
        static PEERINGS: AtomicUsize = AtomicUsize::new(0);
        static ACLS: AtomicUsize = AtomicUsize::new(0);

        bolero::check!()
            .with_generator(ipv4_agents())
            .for_each(|agent| {
                SEEN.fetch_add(1, Ordering::Relaxed);
                let external = ExternalConfig::try_from(agent)
                    .unwrap_or_else(|e| panic!("a schema-legal CRD did not convert: {e}"));
                if let Ok(validated) = external.validate() {
                    VALIDATED.fetch_add(1, Ordering::Relaxed);
                    let table = validated.external().overlay().vpc_table();
                    VPCS.fetch_add(table.len(), Ordering::Relaxed);
                    PEERINGS.fetch_add(
                        table
                            .values()
                            .map(|vpc| vpc.peerings().len())
                            .sum::<usize>(),
                        Ordering::Relaxed,
                    );
                    ACLS.fetch_add(
                        table
                            .values()
                            .flat_map(|vpc| vpc.peerings())
                            .filter(|peering| peering.acl().is_some())
                            .count(),
                        Ordering::Relaxed,
                    );
                }
            });

        let seen = SEEN.load(Ordering::Relaxed);
        let validated = VALIDATED.load(Ordering::Relaxed);
        let vpcs = VPCS.load(Ordering::Relaxed);
        let peerings = PEERINGS.load(Ordering::Relaxed);
        let acls = ACLS.load(Ordering::Relaxed);
        println!(
            "{validated}/{seen} validated, carrying {vpcs} vpcs, {peerings} peerings, {acls} acls"
        );
        assert!(seen > 0, "no configurations were generated");
        // Everything past this point is a rate, and a rate needs a sample behind it.
        // Under miri and under qemu this property gets a handful of cases, where these
        // thresholds measure nothing and are pure flake. The counts above still print, and
        // coverage data is the thing to watch when the sample is this small.
        if seen > ENOUGH_CASES {
            assert!(
                validated * 2 >= seen,
                "only {validated} of {seen} configurations validated: the properties above are \
                 checking much less than they look like they are"
            );
            assert!(vpcs > validated, "validated configurations carry no vpcs");
            assert!(
                peerings > 0,
                "no validated configuration carries a peering, so nothing downstream of \
                 validation has seen the exposes or the NAT"
            );
            // Measured near 51%. A gateway with no groups is a legal shape that carries no
            // peering, and so no acl, so this cannot be held near half without narrowing
            // the generator. A quarter is a tripwire for acls vanishing altogether.
            assert!(
                acls * 4 >= validated,
                "only {acls} of {validated} validated configurations carry an ACL: most generated \
                 ACLs are being refused for something other than what they say"
            );
        }
    }

    #[test]
    fn the_chain_is_deterministic() {
        bolero::check!()
            .with_generator(ipv4_agents())
            .for_each(|agent| {
                let Some((genid, _, once)) = chain(agent) else {
                    return;
                };
                let (_, _, twice) = chain(agent).unwrap_or_else(|| {
                    panic!("the same CRD validated once and not the second time")
                });
                assert_eq!(
                    once.render(&genid).to_string(),
                    twice.render(&genid).to_string(),
                    "the configuration chain is not deterministic"
                );
            });
    }
}
