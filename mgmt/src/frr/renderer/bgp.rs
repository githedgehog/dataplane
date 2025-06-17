// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::frr::renderer::builder::{ConfigBuilder, MARKER, Render};
use crate::models::internal::routing::bgp::BgpConfig;
use crate::models::internal::routing::bgp::BgpNeighType;
use crate::models::internal::routing::bgp::BgpNeighbor;
use crate::models::internal::routing::bgp::BgpOptions;
use crate::models::internal::routing::bgp::BgpUpdateSource;
use crate::models::internal::routing::bgp::NeighSendCommunities;
use crate::models::internal::routing::bgp::Redistribute;
use crate::models::internal::routing::bgp::VrfImports;
use crate::models::internal::routing::bgp::{AfIpv4Ucast, AfIpv6Ucast, AfL2vpnEvpn};
use crate::models::internal::routing::bgp::{BgpNeighCapabilities, Protocol};

use std::fmt::Display;

/* impl Display */
impl Display for BgpNeighType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BgpNeighType::Unset => panic!("Bgp neighbor without type"),
            BgpNeighType::Host(address) => write!(f, "{address}"),
            BgpNeighType::PeerGroup(group) => write!(f, "{group}"),
        }
    }
}
impl Display for BgpUpdateSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BgpUpdateSource::Address(address) => write!(f, "{address}"),
            BgpUpdateSource::Interface(ifname) => write!(f, "{ifname}"),
        }
    }
}
impl Display for NeighSendCommunities {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NeighSendCommunities::All => write!(f, "all"),
            NeighSendCommunities::Both => write!(f, "both"),
            NeighSendCommunities::Extended => write!(f, "extended"),
            NeighSendCommunities::Large => write!(f, "large"),
            NeighSendCommunities::Standard => write!(f, "standard"),
        }
    }
}
impl Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Connected => write!(f, "connected"),
            Protocol::Local => write!(f, "local"),
            Protocol::Static => write!(f, "static"),
            Protocol::ISIS => write!(f, "isis"),
            Protocol::OSPF => write!(f, "ospf"),
        }
    }
}

/* utils to render BGP neighbor configs */
fn bgp_neigh_minimal(neigh: &BgpNeighbor, name: &str) -> String {
    let mut out;
    if neigh.is_peer_group() {
        out = format!(" neighbor {name} peer-group")
    } else {
        out = format!(" neighbor {name}");
        if let Some(peer_group) = &neigh.peer_group {
            out += format!(" peer-group {peer_group}").as_str();
        } else if let Some(remote_as) = neigh.remote_as {
            out += format!(" remote-as {remote_as}").as_str();
        } else {
            panic!("Missing peer-group or ASN");
        }
    }
    out
}
#[allow(clippy::option_map_unit_fn)]
fn bgp_neigh_options(neigh: &BgpNeighbor, prefix: &str) -> ConfigBuilder {
    let mut cfg = ConfigBuilder::new();

    /* remote-as in case of a peer group */
    if neigh.is_peer_group() {
        neigh
            .remote_as
            .map(|asn| cfg += format!(" {} remote-as {asn}", &prefix));
    }

    /* description */
    neigh
        .description
        .as_ref()
        .map(|d| cfg += format!(" {} description {d}", &prefix));

    /* update source */
    neigh
        .update_source
        .as_ref()
        .map(|source| cfg += format!(" {} update-source {source}", &prefix));

    /* route-map in */
    neigh
        .route_map_in
        .as_ref()
        .map(|rmap| cfg += format!(" {} route-map {rmap} in", &prefix));

    /* route-map out */
    neigh
        .route_map_out
        .as_ref()
        .map(|rmap| cfg += format!(" {} route-map {rmap} out", &prefix));

    /* weight */
    neigh
        .weight
        .as_ref()
        .map(|weight| cfg += format!(" {} weight {weight}", &prefix));

    /* send communities */
    neigh
        .send_community
        .as_ref()
        .map(|com| cfg += format!(" {} send-community {com}", &prefix));

    /* ebgp multihop */
    neigh
        .ebgp_multihop
        .as_ref()
        .map(|max_hops| cfg += format!(" {} ebgp-multihop {max_hops}", &prefix));

    /* ttl security */
    neigh
        .ttl_sec_hops
        .as_ref()
        .map(|hops| cfg += format!(" {} ttl-security hops {hops}", &prefix));

    /* advertisement interval */
    neigh
        .advertisement_interval
        .as_ref()
        .map(|interval| cfg += format!(" {} advertisement-interval {interval}", &prefix));

    /* connect timer */
    neigh
        .timer_connect
        .as_ref()
        .map(|timer| cfg += format!(" {} timers connect {timer}", &prefix));

    /* delay-open timer */
    neigh
        .timer_delay_open
        .as_ref()
        .map(|timer| cfg += format!(" {} timers delayopen {timer}", &prefix));

    /* max prefixes in */
    neigh
        .maximum_prefix
        .as_ref()
        .map(|num| cfg += format!(" {} maximum-prefix {num}", &prefix));

    /* max prefixes out */
    neigh
        .maximum_prefix_out
        .as_ref()
        .map(|num| cfg += format!(" {} maximum-prefix-out {num}", &prefix));

    /* TCP MSS  */
    neigh
        .tcp_mss
        .as_ref()
        .map(|mss| cfg += format!(" {} tcp-mss {mss}", &prefix));

    cfg
}
fn bgp_neigh_bool_switches(neigh: &BgpNeighbor, prefix: &str) -> ConfigBuilder {
    let mut cfg = ConfigBuilder::new();

    /* passive */
    if neigh.passive {
        cfg += format!(" {} passive", &prefix);
    }

    /* as override */
    if neigh.as_override {
        cfg += format!(" {} as-override", &prefix);
    }

    /* strict-capability-match */
    if neigh.strict_capability_match {
        cfg += format!(" {} strict-capability-match", &prefix);
    }
    /* strict-capability-match */
    if neigh.dont_capability_negotiate {
        cfg += format!(" {} dont-capability-negotiate", &prefix);
    }

    /* allow as in */
    if neigh.allow_as_in {
        cfg += format!(" {} allowas-in", &prefix);
    }

    /* extended link bw */
    if neigh.extended_link_bandwidth {
        cfg += format!(" {} allowas-in", &prefix);
    }

    /* extended link bw */
    if neigh.next_hop_self {
        cfg += format!(" {} next-hop-self", &prefix);
    }

    /* extended link bw */
    if neigh.remove_private_as {
        cfg += format!(" {} remove-private-AS", &prefix);
    }

    /* extended link bw */
    if neigh.rr_client {
        cfg += format!(" {} route-reflector-client", &prefix);
    }

    /* default originate */
    if neigh.default_originate {
        cfg += format!(" {} default-originate", &prefix);
    }
    cfg
}
fn bgp_neigh_capabilities(capa: &BgpNeighCapabilities, prefix: &str) -> ConfigBuilder {
    let mut cfg = ConfigBuilder::new();
    if capa.dynamic {
        cfg += format!(" {} capability dynamic", &prefix);
    }
    if capa.ext_nhop {
        cfg += format!(" {} capability extended-nexthop", &prefix);
    }
    if capa.fqdn {
        cfg += format!(" {} capability fqdn", &prefix);
    }
    if capa.software_ver {
        cfg += format!(" {} capability software-version", &prefix);
    }
    cfg
}

/* impl Render */
impl Render for Redistribute {
    type Context = ();
    type Output = ConfigBuilder;
    fn render(&self, _: &Self::Context) -> Self::Output {
        let mut redist = format!(" redistribute {}", self.protocol);
        if let Some(metric) = self.metric {
            redist += format!(" metric {metric}").as_str();
        }
        if let Some(rmap) = &self.rmap {
            redist += format!(" route-map {rmap}").as_str();
        }
        ConfigBuilder::from_string(redist)
    }
}
impl Render for VrfImports {
    type Context = ();
    type Output = ConfigBuilder;
    #[allow(clippy::option_map_unit_fn)]
    fn render(&self, _: &Self::Context) -> ConfigBuilder {
        let mut cfg = ConfigBuilder::new();
        self.routemap
            .as_ref()
            .map(|rmap| cfg += format!(" import vrf route-map {rmap}"));
        self.from_vrf
            .iter()
            .for_each(|vrf| cfg += format!(" import vrf {vrf}"));
        cfg
    }
}
impl Render for AfIpv4Ucast {
    type Context = BgpConfig;
    type Output = ConfigBuilder;
    #[allow(clippy::option_map_unit_fn)]
    fn render(&self, bgp: &BgpConfig) -> ConfigBuilder {
        let mut cfg = ConfigBuilder::new();
        cfg += MARKER;
        cfg += "address-family ipv4 unicast";

        /* activate neighbors in AF */
        bgp.neighbors
            .iter()
            .filter(|neigh| neigh.ipv4_unicast)
            .for_each(|neigh| cfg += format!(" neighbor {} activate", neigh.ntype));

        /* redistribution */
        self.redistribute
            .iter()
            .for_each(|redist| cfg += redist.render(&()));

        /* networks */
        bgp.networks
            .iter()
            .filter(|prefix| prefix.is_ipv4())
            .for_each(|prefix| cfg += format!(" network {prefix}"));

        /* VRF imports */
        self.imports
            .as_ref()
            .map(|imports| cfg += imports.render(&()));

        cfg += "exit-address-family";
        cfg += MARKER;
        cfg
    }
}
impl Render for AfIpv6Ucast {
    type Context = BgpConfig;
    type Output = ConfigBuilder;
    #[allow(clippy::option_map_unit_fn)]
    fn render(&self, bgp: &BgpConfig) -> ConfigBuilder {
        let mut cfg = ConfigBuilder::new();
        cfg += MARKER;
        cfg += "address-family ipv6 unicast";

        /* activate neighbors in AF */
        bgp.neighbors
            .iter()
            .filter(|neigh| neigh.ipv6_unicast)
            .for_each(|neigh| cfg += format!(" neighbor {} activate", neigh.ntype));

        /* redistribution */
        self.redistribute
            .iter()
            .for_each(|redist| cfg += redist.render(&()));

        /* networks */
        bgp.networks
            .iter()
            .filter(|prefix| prefix.is_ipv6())
            .for_each(|prefix| cfg += format!(" network {prefix}"));

        /* VRF imports */
        self.imports
            .as_ref()
            .map(|imports| cfg += imports.render(&()));

        cfg += "exit-address-family";
        cfg += MARKER;
        cfg
    }
}
impl Render for AfL2vpnEvpn {
    type Context = BgpConfig;
    type Output = ConfigBuilder;
    #[allow(clippy::option_map_unit_fn)]
    fn render(&self, bgp: &BgpConfig) -> ConfigBuilder {
        let mut cfg = ConfigBuilder::new();
        cfg += MARKER;
        cfg += "address-family l2vpn evpn";

        /* activate neighbors in AF */
        bgp.neighbors
            .iter()
            .filter(|neigh| neigh.l2vpn_evpn)
            .for_each(|neigh| cfg += format!(" neighbor {} activate", neigh.ntype));

        if self.adv_all_vni {
            cfg += " advertise-all-vni";
        }
        if self.adv_default_gw {
            cfg += " advertise-default-gw";
        }
        if self.adv_svi_ip {
            cfg += " advertise-svi-ip";
        }
        if self.adv_ipv4_unicast {
            if let Some(rmap) = &self.adv_ipv4_unicast_rmap {
                cfg += format!(" advertise ipv4 unicast route-map {rmap}");
            } else {
                cfg += " advertise ipv4 unicast";
            }
        }
        if self.adv_ipv6_unicast {
            if let Some(rmap) = &self.adv_ipv6_unicast_rmap {
                cfg += format!(" advertise ipv6 unicast route-map {rmap}");
            } else {
                cfg += " advertise ipv6 unicast";
            }
        }
        if self.default_originate_ipv4 {
            cfg += " default-originate ipv4";
        }
        if self.default_originate_ipv6 {
            cfg += " default-originate ipv6";
        }
        cfg += "exit-address-family";
        cfg += MARKER;
        cfg
    }
}
impl Render for BgpNeighbor {
    type Context = ();
    type Output = ConfigBuilder;
    fn render(&self, _: &Self::Context) -> ConfigBuilder {
        let mut cfg = ConfigBuilder::new();
        let neigh_name = self.ntype.to_string();
        cfg += bgp_neigh_minimal(self, &neigh_name);
        let neigh_prefix = format!("neighbor {neigh_name}");

        cfg += bgp_neigh_capabilities(&self.capabilities, &neigh_prefix);
        cfg += bgp_neigh_options(self, &neigh_prefix);
        cfg += bgp_neigh_bool_switches(self, &neigh_prefix);
        cfg
    }
}
impl Render for BgpOptions {
    type Context = ();
    type Output = ConfigBuilder;
    #[allow(clippy::option_map_unit_fn)]
    fn render(&self, _: &Self::Context) -> ConfigBuilder {
        let mut cfg = ConfigBuilder::new();
        if !self.network_import_check {
            cfg += " no bgp network import-check";
        }
        if !self.ebgp_requires_policy {
            cfg += " no bgp ebgp-requires-policy";
        }
        if !self.bgp_default_unicast {
            cfg += " no bgp default ipv4-unicast";
        }
        if self.supress_fib_pending {
            cfg += " bgp suppress-fib-pending";
        }
        if !self.supress_duplicates {
            cfg += " no bgp suppress-duplicates";
        }
        self.minimum_holdtime
            .as_ref()
            .map(|time| cfg += format!(" bgp minimum-holdtime {time}"));

        self.listen_range
            .as_ref()
            .map(|(prefix, group)| cfg += format!(" bgp listen range {prefix} peer-group {group}"));

        self.listen_limit
            .as_ref()
            .map(|limit| cfg += format!(" bgp listen limit {limit}"));

        cfg
    }
}
impl Render for BgpConfig {
    type Context = ();
    type Output = ConfigBuilder;
    #[allow(clippy::option_map_unit_fn)]
    fn render(&self, _: &Self::Context) -> ConfigBuilder {
        let mut config = ConfigBuilder::new();

        /* main heading */
        let mut heading = format!("router bgp {}", self.asn);
        if let Some(vrf) = &self.vrf {
            heading += format!(" vrf {vrf}").as_str();
        }
        config += heading;

        /* router id */
        if let Some(router_id) = &self.router_id {
            config += format!(" bgp router-id {router_id}");
        }

        /* BGP options: todo */
        config += self.options.render(&());

        /* BGP neighbors */
        self.neighbors.iter().for_each(|n| config += n.render(&()));

        /* Address family ipv4 unicast */
        self.af_ipv4unicast
            .as_ref()
            .map(|evpn| config += evpn.render(self));

        /* Address family ipv4 unicast */
        self.af_ipv6unicast
            .as_ref()
            .map(|evpn| config += evpn.render(self));

        /* Address family l2vpn evpn */
        self.af_l2vpnevpn
            .as_ref()
            .map(|evpn| config += evpn.render(self));

        config += "exit";
        config += MARKER;
        config
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub mod tests {
    use super::*;
    use crate::models::internal::routing::bgp::{
        AfL2vpnEvpn, BgpConfig, BgpNeighbor, NeighSendCommunities, Protocol, Redistribute,
        VrfImports,
    };
    use routing::prefix::Prefix;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    #[test]
    fn test_bgp_render() {
        let mut bgp = BgpConfig::new(65000);
        bgp.set_router_id(Ipv4Addr::from_str("7.0.0.100").expect("Bad address"));

        let options = BgpOptions::new()
            .set_bgp_default_unicast(false)
            .set_ebgp_requires_policy(false)
            .set_network_import_check(false)
            .set_supress_duplicates(true)
            .set_minimum_holdtime(20)
            .set_supress_fib_pending(false)
            .set_listen_range(Prefix::expect_from(("7.0.0.0", 24)), "SPINES".to_owned())
            .set_listen_limit(256);

        bgp.set_bgp_options(options);

        let n1 = BgpNeighbor::new_host(IpAddr::from_str("7.0.0.3").expect("Bad address"))
            .set_remote_as(65001)
            .set_description("A neighbor that does not belong to a peer group")
            .set_update_source_address(IpAddr::from_str("7.0.0.3").expect("Bad address"));

        let n2 = BgpNeighbor::new_host(IpAddr::from_str("8.0.0.4").expect("Bad address"))
            .set_peer_group("SPINES")
            .set_description("A neighbor that belongs to peer group SPINES")
            .set_update_source_interface("lo");

        /* a peer group */
        let group = BgpNeighbor::new_peer_group("SPINES")
            .set_peer_group("Spines")
            .set_remote_as(65002)
            .set_description("Fabric spine nodes")
            .set_update_source_interface("lo")
            .ipv4_unicast_activate(true)
            .ipv6_unicast_activate(false);

        /* neighbor capabilities */
        let capas = BgpNeighCapabilities {
            dynamic: true,
            ext_nhop: true,
            fqdn: true,
            software_ver: true,
        };

        /* a neighbor with lots of tuning */
        let mut full = BgpNeighbor::new_host(IpAddr::from_str("66.66.66.66").expect("Bad address"))
            .set_remote_as(65000)
            .set_capabilities(capas)
            .set_update_source_interface("lo")
            .set_description("A tuned neighbor")
            .set_route_map_in("MY-INBOUND-POLICY")
            .set_route_map_out("MY-OUTBOUND-POLICY")
            .set_weight(2000)
            .set_send_community(NeighSendCommunities::Both)
            .set_ebgp_multihop(10)
            .set_ttl_security(15)
            .set_advertisement_interval(30)
            .set_maximum_prefix(100)
            .set_maximum_prefix_out(10)
            .set_timer_connect(20)
            .set_timer_delay_open(7)
            .set_tcp_mss(4092)
            .set_passive(true)
            .set_as_override(true)
            .set_strict_capability_match(true)
            .set_dont_capability_negotiate(true)
            .set_allow_as_in(true)
            .set_extended_link_bandwidth(true)
            .set_next_hop_self(true)
            .set_remove_private_as(true)
            .set_rr_client(true)
            .set_default_originate(true);

        /* Activate AFs for neighbor */
        full = full
            .ipv4_unicast_activate(true)
            .ipv6_unicast_activate(true)
            .l2vpn_evpn_activate(true);

        /* add some networks */
        bgp.networks.push(Prefix::expect_from("13.13.13.13/32"));
        bgp.networks.push(Prefix::expect_from("19.19.19.19/32"));
        bgp.networks.push(Prefix::expect_from("300:a:b::1/80"));

        /* add neighs */
        bgp.add_neighbor(n1);
        bgp.add_neighbor(n2);
        bgp.add_neighbor(group);
        bgp.add_neighbor(full);

        /* AF l2vp-2vpn */
        let af_evpn = AfL2vpnEvpn::new()
            .set_adv_all_vni(true)
            .set_adv_default_gw(true)
            .set_adv_svi_ip(true)
            .set_adv_ipv4_unicast(true)
            .set_adv_ipv4_unicast_rmap("Route-map-adv-IPv4".to_string())
            .set_adv_ipv6_unicast(true)
            .set_adv_ipv6_unicast_rmap("Route-map-adv-IPv6".to_string())
            .set_default_originate_ipv4(true)
            .set_default_originate_ipv6(true);
        bgp.set_af_l2vpn_evpn(af_evpn);

        /* AF ipv4 unicast */
        let mut af_ipv4 = AfIpv4Ucast::new();

        /* configure ipv4 vrf imports */
        let mut imports = VrfImports::new().set_routemap("Import-into-vrf-1");
        imports.add_vrf("VPC-2");
        imports.add_vrf("VPC-3");
        imports.add_vrf("VPC-4");
        af_ipv4.set_vrf_imports(imports);

        /* redistribution */
        af_ipv4.redistribute(Redistribute::new(Protocol::Connected, None, None));
        af_ipv4.redistribute(Redistribute::new(
            Protocol::Static,
            Some(1000),
            Some("RM-redist-static".to_owned()),
        ));

        /* set the IPv4 unicast config */
        bgp.set_af_ipv4unicast(af_ipv4);

        /* AF ipv4 unicast */
        let mut af_ipv6 = AfIpv6Ucast::new();

        /* configure ipv4 vrf imports */
        let mut imports = VrfImports::new().set_routemap("Import-into-vrf-1-ipv6");
        imports.add_vrf("VPC-2");
        imports.add_vrf("VPC-3");
        imports.add_vrf("VPC-4");

        /* set the imports for Ipv6 */
        af_ipv6.set_vrf_imports(imports);

        /* set the IPv6 unicast config */
        bgp.set_af_ipv6unicast(af_ipv6);

        println!("\n{}", bgp.render(&()));
    }
}
