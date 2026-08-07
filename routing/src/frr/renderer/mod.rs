// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! FRR driver for frr-reload.py

pub mod bfd;
pub mod bgp;
pub mod builder;
pub mod frr;
pub mod interface;
pub mod ospf;
pub mod prefixlist;
pub mod routemap;
pub mod statics;
pub mod vrf;

use crate::frr::renderer::builder::{ConfigBuilder, Render};
use crate::frr::renderer::vrf::{render_vrfs_bgp, render_vrfs_ospf};

use config::{GenId, InternalConfig};
use tracing::debug;

fn render_metadata(genid: GenId) -> String {
    format!("! config for gen {genid}")
}

impl Render for InternalConfig {
    type Context = GenId;
    type Output = ConfigBuilder;
    fn render(&self, config: &Self::Context) -> Self::Output {
        debug!("Generating FRR config for genid {config}...");
        let mut cfg = ConfigBuilder::new();

        /* Metadata: TODO */
        cfg += render_metadata(*config);

        /* we always enable logging on stdout */
        cfg += "log stdout";

        /* frr profile */
        cfg += self.frr.render(&());

        /* BFD peers */
        cfg += self.bfd_peers.render(&());

        /* prefix lists */
        cfg += self.plist_table.render(&());

        /* vrfs */
        cfg += self.vrfs.render(&());

        /* interfaces live in vrfs. So, we iterate over all VRFs */
        self.vrfs
            .iter_by_tableid()
            .for_each(|vrf| cfg += vrf.interfaces.render(&()));

        /* Vrf BGP instances */
        cfg += render_vrfs_bgp(&self.vrfs);

        /* vrf OSPF instance */
        cfg += render_vrfs_ospf(&self.vrfs);

        /* route maps */
        cfg += self.rmap_table.render(&());

        cfg
    }
}

/// Properties over the FRR config renderers.
///
/// A renderer's failure mode is not a crash: it is a BFD session, an OSPF area or a vni that never
/// gets configured because a line was not emitted, or that gets configured twice. Neither shows up
/// anywhere but in FRR's own state. Each renderer had one test that printed its output and asserted
/// nothing, so `ospf`, `bfd` and this module were at zero coverage.
///
/// A round-trip oracle would need an FRR parser and is not worth building. What is worth checking is
/// weaker and still catches both failure modes: **every value the config holds appears in the
/// output, and no value it does not hold appears.** That is enough to catch an omitted field, a
/// field emitted when it should not be, and a top-level renderer that forgot to call a sub-renderer.
#[cfg(test)]
mod renderer_properties {
    use super::*;
    use bolero::{Driver, ValueGenerator};
    use config::external::overlay::vpc::VpcId;
    use config::internal::device::DeviceConfig;
    use config::internal::routing::bfd::{
        BFD_DETECT_MULTIPLIER, BFD_RECEIVE_INTERVAL_MS, BFD_TRANSMIT_INTERVAL_MS, BfdPeer,
    };
    use config::internal::routing::ospf::{Ospf, OspfInterface, OspfNetwork};
    use config::internal::routing::vrf::{VrfConfig, VrfConfigTable};
    use net::route::RouteTableId;
    use net::vxlan::Vni;
    use std::net::{IpAddr, Ipv4Addr};
    use std::ops::Bound::Included;
    use std::str::FromStr;

    const NUM_ADDRESSES: u8 = 3;
    const NUM_NETWORKS: u8 = 4;
    const MAX_PEERS: u8 = 3;
    const MAX_VRFS: u8 = 3;

    fn addresses() -> Vec<IpAddr> {
        ["10.0.0.1", "10.0.0.2", "2001:db8::1"]
            .iter()
            .map(|a| IpAddr::from_str(a).unwrap_or_else(|_| unreachable!()))
            .collect()
    }

    fn networks() -> Vec<OspfNetwork> {
        vec![
            OspfNetwork::Broadcast,
            OspfNetwork::NonBroadcast,
            OspfNetwork::Point2Point,
            OspfNetwork::Point2Multipoint,
        ]
    }

    /// The keyword FRR expects for each network type, written out here rather than taken from
    /// `OspfNetwork::rendered`, so a wrong pairing is visible.
    fn network_keyword(network: &OspfNetwork) -> &'static str {
        match network {
            OspfNetwork::Broadcast => "broadcast",
            OspfNetwork::NonBroadcast => "non-broadcast",
            OspfNetwork::Point2Point => "point-to-point",
            OspfNetwork::Point2Multipoint => "point-to-multipoint",
        }
    }

    /// A BFD peer as the generator describes it.
    #[derive(Debug, Clone, Copy)]
    struct PeerSpec {
        address: usize,
        multihop: bool,
        source: Option<usize>,
    }

    /// A vrf as the generator describes it.
    ///
    /// Name, table id, vni and vpc id are all derived from its position rather than generated.
    /// `VrfConfigTable` is a multi-index map with a *unique* index over each of them, and an
    /// `Option` field's `None` counts as a value there -- so it can hold at most one vrf without a
    /// vni, and at most one without a vpc id. Production satisfies that (the default vrf has
    /// neither; every other vrf is a vpc vrf and has both), but the types do not say so, and
    /// `add_vrf_config` calls a collision "a bug". So the harness gives every vrf its own, and the
    /// "renders it only when it has one" cases are checked against `VrfConfig` directly below.
    #[derive(Debug, Clone, Copy)]
    struct VrfSpec {
        ospf: Option<usize>,
    }

    #[derive(Debug, Clone)]
    struct Fabric {
        genid: GenId,
        peers: Vec<PeerSpec>,
        vrfs: Vec<VrfSpec>,
    }

    /// Draws [`Fabric`]s.
    #[derive(Debug, Clone, Copy, Default)]
    struct Fabrics;

    fn index<D: Driver>(driver: &mut D, count: u8) -> Option<usize> {
        driver
            .gen_u8(Included(&0), Included(&(count - 1)))
            .map(usize::from)
    }

    /// An index into a pool of `count`, or `count` itself to mean "absent".
    ///
    /// One draw with a sentinel rather than an `Option<Option<_>>`, whose outer `None` -- the driver
    /// running out of input -- cannot be told from the inner one.
    fn maybe_index<D: Driver>(driver: &mut D, count: u8) -> Option<usize> {
        index(driver, count + 1)
    }

    /// Read a [`maybe_index`] draw back as an option.
    fn drawn(value: usize, count: u8) -> Option<usize> {
        (value < usize::from(count)).then_some(value)
    }

    impl ValueGenerator for Fabrics {
        type Output = Fabric;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Fabric> {
            let genid = GenId::from(driver.gen_u8(Included(&1), Included(&9))?);

            let count = driver.gen_u8(Included(&0), Included(&MAX_PEERS))?;
            let mut peers = Vec::with_capacity(usize::from(count));
            for _ in 0..count {
                peers.push(PeerSpec {
                    address: index(driver, NUM_ADDRESSES)?,
                    multihop: driver.produce::<bool>()?,
                    source: drawn(maybe_index(driver, NUM_ADDRESSES)?, NUM_ADDRESSES),
                });
            }

            let count = driver.gen_u8(Included(&0), Included(&MAX_VRFS))?;
            let mut vrfs = Vec::with_capacity(usize::from(count));
            for _ in 0..count {
                vrfs.push(VrfSpec {
                    ospf: drawn(maybe_index(driver, NUM_ADDRESSES)?, NUM_ADDRESSES),
                });
            }

            Some(Fabric { genid, peers, vrfs })
        }
    }

    fn peer(spec: PeerSpec) -> BfdPeer {
        BfdPeer::new(addresses()[spec.address])
            .set_multihop(spec.multihop)
            .set_source(spec.source.map(|i| addresses()[i]))
    }

    /// A router id for vrf `index`, distinct per vrf so it can be looked for in the output.
    fn router_id(index: usize) -> Ipv4Addr {
        Ipv4Addr::new(
            192,
            168,
            0,
            u8::try_from(index + 1).unwrap_or_else(|_| unreachable!()),
        )
    }

    fn vrf_name(index: usize) -> String {
        format!("VPC-{index}")
    }

    /// A vpc id for vrf `index`.
    ///
    /// Every non-default vrf needs one: `VrfConfigTable` holds a unique index over `vpc_id`, so two
    /// vrfs without one collide. Real configs always have them -- non-default vrfs are vpc vrfs --
    /// but it is not obvious from the type, which takes an `Option`.
    fn vpc_id(index: usize) -> VpcId {
        VpcId::try_from(format!("vpc{index:02}").as_str()).unwrap_or_else(|_| unreachable!())
    }

    fn vni_for(index: usize) -> Vni {
        Vni::new_checked(3000 + u32::try_from(index).unwrap_or_else(|_| unreachable!()))
            .unwrap_or_else(|_| unreachable!())
    }

    fn internal_config(fabric: &Fabric) -> InternalConfig {
        let mut config = InternalConfig::new("GW1", DeviceConfig::new());
        config.bfd_peers = fabric.peers.iter().copied().map(peer).collect();

        let mut vrfs = VrfConfigTable::new();
        for (index, spec) in fabric.vrfs.iter().enumerate() {
            let mut vrf = VrfConfig::new(&vrf_name(index), Some(vni_for(index)), false)
                .set_table_id(
                    RouteTableId::try_from(
                        100 + u32::try_from(index).unwrap_or_else(|_| unreachable!()),
                    )
                    .unwrap_or_else(|_| unreachable!()),
                )
                .set_vpc_id(vpc_id(index));
            if spec.ospf.is_some() {
                let mut ospf = Ospf::new(router_id(index));
                ospf.set_vrf_name(vrf_name(index));
                vrf.set_ospf(ospf);
            }
            vrfs.add_vrf_config(vrf)
                .unwrap_or_else(|e| unreachable!("{e}"));
        }
        config.vrfs = vrfs;
        config
    }

    /// How many times `needle` appears in `haystack`.
    fn occurrences(haystack: &str, needle: &str) -> usize {
        haystack.matches(needle).count()
    }

    /// The pools and the constants that index them agree.
    #[test]
    fn the_pools_are_the_size_the_generator_thinks() {
        assert_eq!(addresses().len(), usize::from(NUM_ADDRESSES));
        assert_eq!(networks().len(), usize::from(NUM_NETWORKS));
        // the derived names, table ids and vnis must be distinct, or `add_vrf_config` would refuse
        // them and the harness would be testing its own collision handling
        let count = usize::from(MAX_VRFS);
        for derived in [
            (0..count).map(vrf_name).collect::<Vec<_>>(),
            (0..count).map(|i| format!("{:?}", vpc_id(i))).collect(),
            (0..count).map(|i| vni_for(i).to_string()).collect(),
            (0..count).map(|i| router_id(i).to_string()).collect(),
        ] {
            let mut sorted = derived.clone();
            sorted.sort();
            sorted.dedup();
            assert_eq!(
                sorted.len(),
                derived.len(),
                "derived values must be distinct"
            );
        }
    }

    /// A BFD peer renders every field it carries, and none it does not.
    ///
    /// Note the one rule that is not "render what is set": a source address is emitted only for a
    /// multihop peer. A single-hop peer with a source silently loses it, which is deliberate --
    /// FRR has nowhere to put it -- and worth having written down.
    #[test]
    fn a_bfd_peer_renders_the_fields_it_carries() {
        bolero::check!()
            .with_generator(Fabrics)
            .cloned()
            .for_each(|fabric: Fabric| {
                for spec in &fabric.peers {
                    let peer = peer(*spec);
                    let text = peer.render(&()).to_string();

                    assert_eq!(
                        occurrences(&text, &format!(" peer {}", peer.address)),
                        1,
                        "peer address once, for {spec:?} in {text}"
                    );
                    assert_eq!(
                        occurrences(&text, " multihop"),
                        usize::from(spec.multihop),
                        "multihop iff set, for {spec:?} in {text}"
                    );

                    let source_shown = spec.multihop && spec.source.is_some();
                    assert_eq!(
                        occurrences(&text, "  source "),
                        usize::from(source_shown),
                        "a source is rendered only for a multihop peer, for {spec:?} in {text}"
                    );
                    if source_shown {
                        let source = addresses()[spec.source.unwrap_or_else(|| unreachable!())];
                        assert_eq!(
                            occurrences(&text, &format!("  source {source}")),
                            1,
                            "the source that was set, for {spec:?} in {text}"
                        );
                    }

                    // and the timing parameters FRR needs to bring the session up at all
                    for line in [
                        "  no shutdown".to_string(),
                        format!("  detect-multiplier {BFD_DETECT_MULTIPLIER}"),
                        format!("  transmit-interval {BFD_TRANSMIT_INTERVAL_MS}"),
                        format!("  receive-interval {BFD_RECEIVE_INTERVAL_MS}"),
                    ] {
                        assert_eq!(occurrences(&text, &line), 1, "{line} once, in {text}");
                    }
                }
            });
    }

    /// A BFD section appears only when there are peers, and holds each of them once.
    #[test]
    fn a_bfd_section_appears_only_for_peers_it_has() {
        bolero::check!()
            .with_generator(Fabrics)
            .cloned()
            .for_each(|fabric: Fabric| {
                let peers: Vec<BfdPeer> = fabric.peers.iter().copied().map(peer).collect();
                let text = peers.render(&()).to_string();

                if peers.is_empty() {
                    assert!(
                        !text.contains("bfd"),
                        "an empty peer list must render no bfd section, got {text}"
                    );
                    return;
                }

                assert_eq!(
                    occurrences(&text, "\nbfd\n"),
                    1,
                    "one bfd section in {text}"
                );
                assert_eq!(occurrences(&text, "\nexit\n"), 1, "one exit in {text}");
                for address in addresses() {
                    let wanted = peers.iter().filter(|p| p.address == address).count();
                    assert_eq!(
                        occurrences(&text, &format!(" peer {address}")),
                        wanted,
                        "{address} appears once per peer that has it, in {text}"
                    );
                }
            });
    }

    /// An OSPF instance renders its router id, and its vrf only when it has one.
    #[test]
    fn an_ospf_instance_renders_its_router_id_and_vrf() {
        bolero::check!()
            .with_generator(Fabrics)
            .cloned()
            .for_each(|fabric: Fabric| {
                for (index, _) in fabric.vrfs.iter().enumerate() {
                    let id = router_id(index);
                    let name = vrf_name(index);

                    let plain = Ospf::new(id).render(&()).to_string();
                    assert_eq!(
                        occurrences(&plain, "router ospf\n"),
                        1,
                        "an ospf instance with no vrf, in {plain}"
                    );
                    assert_eq!(
                        occurrences(&plain, &format!(" ospf router-id {id}")),
                        1,
                        "the router id, in {plain}"
                    );

                    let mut in_vrf = Ospf::new(id);
                    in_vrf.set_vrf_name(name.clone());
                    let text = in_vrf.render(&()).to_string();
                    assert_eq!(
                        occurrences(&text, &format!("router ospf vrf {name}")),
                        1,
                        "an ospf instance in a vrf, in {text}"
                    );
                    assert_eq!(
                        occurrences(&text, &format!(" ospf router-id {id}")),
                        1,
                        "the router id, in {text}"
                    );
                }
            });
    }

    /// An OSPF interface renders its area, and each option only when it is set.
    #[test]
    fn an_ospf_interface_renders_the_options_it_has() {
        bolero::check!()
            .with_generator(bolero::produce::<(u8, bool, Option<u32>, Option<u8>)>())
            .cloned()
            .for_each(
                |(area, passive, cost, network): (u8, bool, Option<u32>, Option<u8>)| {
                    let area = Ipv4Addr::new(0, 0, 0, area);
                    let network =
                        network.map(|n| networks()[usize::from(n) % networks().len()].clone());

                    let mut interface = OspfInterface::new(area).set_passive(passive);
                    if let Some(cost) = cost {
                        interface = interface.set_cost(cost);
                    }
                    if let Some(network) = network.clone() {
                        interface = interface.set_network(network);
                    }
                    let text = interface.render(&()).to_string();

                    assert_eq!(
                        occurrences(&text, &format!(" ip ospf area {area}")),
                        1,
                        "the area, in {text}"
                    );
                    assert_eq!(
                        occurrences(&text, " ip ospf passive"),
                        usize::from(passive),
                        "passive iff set, in {text}"
                    );
                    assert_eq!(
                        occurrences(&text, " ip ospf cost "),
                        usize::from(cost.is_some()),
                        "cost iff set, in {text}"
                    );
                    if let Some(cost) = cost {
                        assert_eq!(occurrences(&text, &format!(" ip ospf cost {cost}")), 1);
                    }
                    assert_eq!(
                        occurrences(&text, " ip ospf network "),
                        usize::from(network.is_some()),
                        "network iff set, in {text}"
                    );
                    if let Some(network) = &network {
                        assert_eq!(
                            occurrences(
                                &text,
                                &format!(" ip ospf network {}", network_keyword(network))
                            ),
                            1,
                            "the network keyword FRR expects, in {text}"
                        );
                    }
                },
            );
    }

    /// Everything the config holds reaches the rendered output.
    ///
    /// This is the property the per-renderer ones cannot give: a sub-renderer that works perfectly is
    /// no use if the top level never calls it, and an object silently missing from an FRR config is
    /// a session or a vni that never comes up.
    #[test]
    fn everything_configured_reaches_the_output() {
        bolero::check!()
            .with_generator(Fabrics)
            .cloned()
            .for_each(|fabric: Fabric| {
                let config = internal_config(&fabric);
                let text = config.render(&fabric.genid).to_string();

                assert_eq!(
                    occurrences(&text, &format!("! config for gen {}", fabric.genid)),
                    1,
                    "the generation this config is for, in {text}"
                );

                for address in addresses() {
                    let wanted = fabric
                        .peers
                        .iter()
                        .filter(|p| addresses()[p.address] == address)
                        .count();
                    assert_eq!(
                        occurrences(&text, &format!(" peer {address}")),
                        wanted,
                        "bfd peer {address}, in {text}"
                    );
                }

                for (index, spec) in fabric.vrfs.iter().enumerate() {
                    let name = vrf_name(index);
                    assert_eq!(
                        occurrences(&text, &format!("\nvrf {name}\n")),
                        1,
                        "vrf {name} declared once, in {text}"
                    );
                    assert_eq!(
                        occurrences(&text, &format!(" vni {}", vni_for(index))),
                        1,
                        "vni of {name}, in {text}"
                    );
                    assert_eq!(
                        occurrences(&text, &format!("router ospf vrf {name}")),
                        usize::from(spec.ospf.is_some()),
                        "ospf instance of {name} iff it has one, in {text}"
                    );
                    assert_eq!(
                        occurrences(&text, &format!(" ospf router-id {}", router_id(index))),
                        usize::from(spec.ospf.is_some()),
                        "router id of {name} iff it has ospf, in {text}"
                    );
                }
            });
    }

    /// A vrf renders its own name and vni only when it should.
    ///
    /// The default vrf is the interesting case: its configuration belongs at the top level of the
    /// FRR config, so it must *not* be wrapped in `vrf <name>` / `exit-vrf`. Wrapping it would put
    /// the underlay's static routes and vni into a vrf that FRR does not have.
    #[test]
    fn a_vrf_renders_its_wrapper_only_when_it_is_not_the_default() {
        bolero::check!()
            .with_generator(bolero::produce::<(bool, bool)>())
            .cloned()
            .for_each(|(default, has_vni): (bool, bool)| {
                let name = if default { "default" } else { "VPC-1" };
                let vni = has_vni.then(|| vni_for(0));
                let text = VrfConfig::new(name, vni, default).render(&()).to_string();

                let wrapped = usize::from(!default);
                assert_eq!(
                    occurrences(&text, &format!("\nvrf {name}\n")),
                    wrapped,
                    "a vrf declaration iff not the default, in {text}"
                );
                assert_eq!(
                    occurrences(&text, "exit-vrf"),
                    wrapped,
                    "an exit-vrf iff not the default, in {text}"
                );
                assert_eq!(
                    occurrences(&text, " vni "),
                    usize::from(has_vni),
                    "a vni iff it has one, in {text}"
                );
            });
    }

    /// Rendering the same config twice gives the same text.
    ///
    /// Worth its own property because the output is handed to `frr-reload.py`, which diffs it against
    /// what FRR is running. A rendering that varied -- an unordered table iterated, say -- would look
    /// like a configuration change on every pass and reload FRR for nothing.
    #[test]
    fn rendering_is_deterministic() {
        bolero::check!()
            .with_generator(Fabrics)
            .cloned()
            .for_each(|fabric: Fabric| {
                let once = internal_config(&fabric).render(&fabric.genid).to_string();
                let twice = internal_config(&fabric).render(&fabric.genid).to_string();
                assert_eq!(once, twice, "rendering is not deterministic");
            });
    }
}
