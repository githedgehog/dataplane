// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Methods to build internal configurations

#[allow(unused)]
use tracing::{debug, error, warn};

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

/// Refuse a peering this module cannot render, by name and before anything is built.
///
/// Nothing here uses [`IpVer::V6`]. Left to themselves the two prefix lists fail differently and
/// both badly:
///
/// * the advertise list is `IpVer::V4` over *unfiltered* prefixes, so a v6 prefix fails
///   `PrefixListEntry::is_version_compatible` and comes back as `ConfigError::InternalFailure` --
///   which is the one rejection `mgmt`'s own mutation property asserts a configuration must never
///   get, because "this is our bug" is not something an operator can act on;
/// * the import list was `IpVer::V4` *and* filtered by `is_ipv4()`, so v6 prefixes were dropped in
///   silence. That is worse than the error: the configuration applies, reports success, and carries
///   no traffic.
///
/// `build_internal_config` runs in `process_incoming_config` **before** `apply`, so this is a clean
/// rejection and nothing has been committed when it fires. What it changes is what the operator is
/// told, and it closes the silent half.
///
/// Deliberately here and not in `VpcExpose::validate`: it is this module that is IPv4-only. NAT's
/// static, masquerade and port-forwarding tables all build and translate v6 today, and refusing a
/// v6 expose outright would take that away to guard a limitation it does not have.
///
/// Lifting this means building both lists per family and threading `IpVer` through the renderer.
/// Deleting this function is how to check that it is done.
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

/// Properties over the whole configuration chain.
///
/// A gateway configuration passes through four steps before the dataplane sees it:
///
/// ```text
/// GatewayAgent (CRD) ──▶ ExternalConfig ──▶ validated ──▶ InternalConfig ──▶ FRR text
/// ```
///
/// The converters and the validator are well covered, and the renderers now are too -- but the
/// renderers were tested against an `InternalConfig` built by hand, and this builder was covered by
/// one sample configuration in a test that printed its output. So the third arrow, the one that
/// turns a *validated* configuration into the one the dataplane applies, has never seen a generated
/// input.
///
/// That arrow is where the interesting failure lives, and there is precedent: a port-forwarding
/// expose that validated and could not be built (`fix(config): Refuse a port-forwarding expose the
/// dataplane cannot build`). It matters because `apply_gw_config` is a linear `?`-chain and there is
/// no transaction: by the time a late step fails, kernel interfaces, the flow filter, ACLs, static
/// NAT and the masquerade allocator have all been committed.
///
/// So the claim is: **whatever validates, builds; and whatever builds, renders.**
#[cfg(test)]
mod chain_properties {
    use super::*;
    use config::{ExternalConfig, GenId};
    use k8s_intf::bolero::AddressFamily;
    use k8s_intf::bolero::crd::{GatewayAgentBuilder, GatewayAgents};
    use k8s_intf::gateway_agent_crd::GatewayAgent;
    use routing::Render;
    use std::collections::BTreeSet;

    /// The configurations these properties draw from: legal, and **IPv4 only**.
    ///
    /// # Why IPv4 only
    ///
    /// Because IPv6 peering configuration cannot be rendered: `internal.rs` never uses `IpVer::V6`,
    /// and [`reject_ipv6`] now says so rather than letting the two prefix lists fail in their own
    /// ways. Neither was reachable from a test until the generated gateway began joining its own
    /// gateway groups, because `build_routing_config_peer` builds nothing for a peering whose group
    /// does not list this gateway.
    ///
    /// The restriction is not load-bearing any more -- [`chain`] treats a declared limitation as a
    /// skip -- so widening it is safe. What it buys is *coverage*: with both families the generator
    /// spends about half its cases on configurations that are skipped rather than checked, and the
    /// vacuity property's count would say so.
    ///
    /// **Widening this to `AddressFamily::all()` and watching that count is how to tell whether v6
    /// has been implemented**, and it is deliberately the only place any of these properties names
    /// a family.
    fn ipv4_agents() -> GatewayAgents {
        GatewayAgentBuilder::new()
            .families(vec![AddressFamily::V4])
            .build()
    }

    /// Everything the chain produces for one generated CRD, or `None` if the configuration was
    /// legal as a CRD but not a valid gateway configuration.
    ///
    /// Validation failing is not a defect: `LegalValue` generates values that are legal against the
    /// *schema*, and plenty of those describe configurations that are semantically wrong -- two vpcs
    /// claiming one vni, exposes that overlap. The claim starts after validation succeeds.
    ///
    /// Neither is [`ConfigError::Unsupported`]. That is the builder declining to build something it
    /// has no implementation for, by name -- see [`reject_ipv6`] -- and "whatever validates, builds"
    /// is a claim about configurations the dataplane says it can carry. Every other build error
    /// still panics, which is the whole point of the property: an `InternalFailure` from here is a
    /// configuration that passed every check and then could not be turned into one.
    fn chain(agent: &GatewayAgent) -> Option<(GenId, InternalConfig)> {
        let external = ExternalConfig::try_from(agent)
            .unwrap_or_else(|e| panic!("a schema-legal CRD did not convert: {e}"));
        let validated = external.validate().ok()?;
        let genid = validated.genid();
        Some((genid, build_or_skip(&validated)?))
    }

    /// Build, or skip a limitation the builder declares.
    ///
    /// Every property that builds goes through here, so that widening [`ipv4_agents`] is the single
    /// change its documentation says it is. It was not: this module had two build sites, and the
    /// second unwrapped, so the documented way to check whether IPv6 had landed would have failed
    /// that property on a *legal* configuration with a message blaming the builder.
    fn build_or_skip(validated: &ValidatedGwConfig) -> Option<InternalConfig> {
        match build_internal_config(validated, None) {
            Ok(internal) => Some(internal),
            Err(ConfigError::Unsupported(_)) => None,
            Err(e) => panic!("a validated configuration would not build: {e}\n{validated:#?}"),
        }
    }

    /// A configuration that validates can be built and rendered.
    ///
    /// The rendering half is not incidental: `Render` returns no `Result`, so the only way it can
    /// fail is to panic, and the renderers had only ever been given hand-written input.
    #[test]
    fn whatever_validates_builds_and_renders() {
        bolero::check!()
            .with_generator(ipv4_agents())
            .for_each(|agent| {
                let Some((genid, internal)) = chain(agent) else {
                    return;
                };
                let text = internal.render(&genid).to_string();
                assert!(
                    text.contains(&format!("! config for gen {genid}")),
                    "the rendered config does not say which generation it is for"
                );
            });
    }

    /// The built configuration carries a vrf for exactly the vnis the overlay's vpcs have.
    ///
    /// This is the correspondence the third arrow is supposed to establish. A vpc without a vrf is a
    /// tenant with no forwarding table; a vrf without a vpc is one FRR will configure and nothing
    /// will use.
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
                let Some(internal) = build_or_skip(&validated) else {
                    return;
                };

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
            });
    }

    /// The properties above are not vacuous, and say how far they reach.
    ///
    /// They are all of the form "if it validates, then ..." -- so they are worth nothing if nothing
    /// validates. It is worth measuring rather than assuming, and the measurement turned out to be
    /// the most useful thing in this module.
    ///
    /// This started out measuring a failure. When first written, about a sixth of configurations
    /// validated and **none of them had a peering** -- twenty-four thousand peerings drawn per four
    /// thousand configurations, not one surviving. Peerings are where the exposes, the NAT and the
    /// ACLs live, so that whole half of the model reached the builder never, while the CRD
    /// generators sat at 94% coverage and every per-converter property passed, because those run
    /// before validation.
    ///
    /// Seven causes, all in the generators, all now fixed: peering pairs drawn independently so a
    /// duplicated pair was near-certain; exposes drawing a mix of address families when one expose
    /// must be single-family; prefixes as short as `/0`, which always overlaps a reserved range; the
    /// NAT flavour chosen *after* the shape it constrains; the two manifests of a peering drawing
    /// families independently when they must agree; both manifests free to use a stateful flavour
    /// when only one may; and a peering naming a gateway group drawn freely rather than one that
    /// exists.
    ///
    /// So the assertions are now the ones worth making: most configurations validate, and they carry
    /// peerings.
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
        assert!(
            validated * 2 >= seen,
            "only {validated} of {seen} configurations validated: the properties above are \
             checking much less than they look like they are"
        );
        assert!(vpcs > validated, "validated configurations carry no vpcs");
        assert!(
            peerings > 0,
            "no validated configuration carries a peering, so nothing downstream of validation \
             has seen the exposes or the NAT"
        );
        // Not merely "more than none": a *share* of them. An ACL rule can be refused for reasons
        // that have nothing to do with the rule -- `scope: flow` needs one side of the peering to be
        // stateful throughout -- so a generator that gets those wrong still produces some valid
        // ACLs, just far fewer. Asserting the share is what notices that.
        assert!(
            acls * 2 >= validated,
            "only {acls} of {validated} validated configurations carry an ACL: most generated ACLs \
             are being refused for something other than what they say"
        );
    }

    /// Building and rendering the same configuration twice gives the same text.
    ///
    /// Already checked over hand-built `InternalConfig`s; here the input comes from a generated CRD,
    /// so the whole chain has to be deterministic, not just the last step of it. It matters because
    /// `frr-reload.py` diffs the output against what FRR is running.
    #[test]
    fn the_chain_is_deterministic() {
        bolero::check!()
            .with_generator(ipv4_agents())
            .for_each(|agent| {
                let Some((genid, once)) = chain(agent) else {
                    return;
                };
                let (_, twice) = chain(agent).unwrap_or_else(|| {
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
