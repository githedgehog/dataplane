// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: BGP

#![allow(unused)]

use routing::prefix::Prefix;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

// FRR defaults {datacenter | traditional}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Protocol {
    #[default]
    Connected,
    Local,
    Static,
    OSPF,
    ISIS,
}

#[derive(Clone, Debug, Default)]
pub struct Redistribute {
    pub protocol: Protocol,
    pub metric: Option<u32>,
    pub rmap: Option<String>,
}

#[derive(Clone, Debug, Default)]
/// VRF leaking
pub struct VrfImports {
    pub from_vrf: BTreeSet<String>,
    pub routemap: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct AfIpv4Ucast {
    pub redistribute: Vec<Redistribute>,
    pub imports: Option<VrfImports>,
    pub networks: Vec<Prefix>,
}

#[derive(Clone, Debug, Default)]
pub struct AfIpv6Ucast {
    pub redistribute: Vec<Redistribute>,
    pub imports: Option<VrfImports>,
    pub networks: Vec<Prefix>,
}

#[derive(Clone, Debug, Default)]
pub struct AfL2vpnEvpn {
    pub adv_all_vni: bool,
    pub adv_default_gw: bool,
    pub adv_svi_ip: bool,
    pub adv_ipv4_unicast: bool,
    pub adv_ipv6_unicast: bool,
    pub adv_ipv4_unicast_rmap: Option<String>,
    pub adv_ipv6_unicast_rmap: Option<String>,
    pub default_originate_ipv4: bool,
    pub default_originate_ipv6: bool,
}

#[derive(Clone, Debug, Default)]
pub struct BgpNeighCapabilities {
    pub dynamic: bool,
    pub ext_nhop: bool,
    pub fqdn: bool,
    pub software_ver: bool,
    //ORF
}

#[derive(Clone, Debug)]
pub enum NeighSendCommunities {
    All,
    Both,
    Extended,
    Large,
    Standard,
}

#[derive(Clone, Debug)]
pub enum BgpUpdateSource {
    Address(IpAddr),
    Interface(String),
}

#[derive(Clone, Debug, Default)]
pub enum BgpNeighType {
    #[default]
    Unset,
    Host(IpAddr),
    PeerGroup(String),
}

#[derive(Clone, Debug, Default)]
/// A BGP neighbor config
pub struct BgpNeighbor {
    pub ntype: BgpNeighType,
    pub remote_as: Option<u32>,
    pub peer_group: Option<String>,
    pub description: Option<String>,
    pub route_map_in: Option<String>,
    pub route_map_out: Option<String>,
    pub update_source: Option<BgpUpdateSource>,
    pub weight: Option<u16>,
    pub capabilities: BgpNeighCapabilities,
    pub send_community: Option<NeighSendCommunities>,
    pub ebgp_multihop: Option<u8>,
    pub ttl_sec_hops: Option<u8>,
    pub advertisement_interval: Option<u16>,
    pub maximum_prefix: Option<u32>,
    pub maximum_prefix_out: Option<u32>,
    pub timer_connect: Option<u16>,
    pub timer_delay_open: Option<u8>,
    pub tcp_mss: Option<u16>,

    /* switches */
    pub passive: bool,
    pub as_override: bool,
    pub strict_capability_match: bool,
    pub dont_capability_negotiate: bool,
    pub allow_as_in: bool,
    pub extended_link_bandwidth: bool,
    pub next_hop_self: bool,
    pub remove_private_as: bool,
    pub rr_client: bool,
    pub default_originate: bool,

    /* Address families */
    pub ipv4_unicast: bool,
    pub ipv6_unicast: bool,
    pub l2vpn_evpn: bool,
}

#[derive(Clone, Debug, Default)]
pub struct BgpDefaultsAF {
    flow_spec: bool,
    labeled_unicast: bool,
    unicast: bool,
    multicast: bool,
    vpn: bool,
}

#[derive(Clone, Debug, Default)]
/// BGP configuration options
pub struct BgpDefaults {
    dynamic_capability: bool,
    ipv4: BgpDefaultsAF,
    ipv6: BgpDefaultsAF,
    l2vpn_evpn: bool,
}

#[derive(Clone, Debug)]
/// BGP global configuration options
pub struct BgpOptions {
    pub network_import_check: bool,
    pub ebgp_requires_policy: bool,
    pub bgp_default_unicast: bool,
    pub supress_fib_pending: bool,
    pub supress_duplicates: bool,
    pub minimum_holdtime: Option<u16>,
    pub listen_range: Option<(Prefix, String)>,
    pub listen_limit: Option<u16>,
}
impl Default for BgpOptions {
    fn default() -> Self {
        Self {
            network_import_check: false,
            ebgp_requires_policy: false,
            bgp_default_unicast: false,
            supress_duplicates: true,
            supress_fib_pending: false,
            minimum_holdtime: None,
            listen_range: None,
            listen_limit: None,
        }
    }
}

#[derive(Clone, Debug, Default)]
/// A BGP instance config, within a certain VRF
pub struct BgpConfig {
    pub asn: u32,
    pub vrf: Option<String>,
    pub router_id: Option<Ipv4Addr>,
    pub options: BgpOptions,
    pub neighbors: Vec<BgpNeighbor>,
    pub af_ipv4unicast: Option<AfIpv4Ucast>,
    pub af_ipv6unicast: Option<AfIpv6Ucast>,
    pub af_l2vpnevpn: Option<AfL2vpnEvpn>,
}

/* ===== impls: Builders ===== */
impl Redistribute {
    pub fn new(protocol: Protocol, metric: Option<u32>, rmap: Option<String>) -> Self {
        Self {
            protocol,
            metric,
            rmap,
        }
    }
}
impl VrfImports {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set_routemap(mut self, routemap: &str) -> Self {
        self.routemap = Some(routemap.to_owned());
        self
    }
    pub fn add_vrf(&mut self, vrf: &str) {
        self.from_vrf.insert(vrf.to_owned());
    }
}
impl AfIpv4Ucast {
    pub fn new() -> Self {
        Self {
            redistribute: vec![],
            imports: None,
            networks: vec![],
        }
    }
    pub fn set_vrf_imports(&mut self, imports: VrfImports) {
        self.imports = Some(imports);
    }
    // redistribution is configured by adding one or more redistribute objects
    pub fn redistribute(&mut self, redistribute: Redistribute) {
        self.redistribute.push(redistribute);
    }
    pub fn add_network(&mut self, network: Prefix) {
        self.networks.push(network);
    }
    pub fn add_networks(&mut self, networks: impl IntoIterator<Item = Prefix>) {
        self.networks.extend(networks);
    }
}
impl AfIpv6Ucast {
    pub fn new() -> Self {
        Self {
            redistribute: vec![],
            imports: None,
            networks: vec![],
        }
    }
    pub fn set_vrf_imports(&mut self, imports: VrfImports) {
        self.imports = Some(imports);
    }
    pub fn redistribute(&mut self, redistribute: Redistribute) {
        self.redistribute.push(redistribute);
    }
    pub fn add_network(&mut self, network: Prefix) {
        self.networks.push(network);
    }
    pub fn add_networks(&mut self, networks: impl IntoIterator<Item = Prefix>) {
        self.networks.extend(networks);
    }
}
impl AfL2vpnEvpn {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set_adv_all_vni(mut self, value: bool) -> Self {
        self.adv_all_vni = value;
        self
    }
    pub fn set_adv_default_gw(mut self, value: bool) -> Self {
        self.adv_default_gw = value;
        self
    }
    pub fn set_adv_svi_ip(mut self, value: bool) -> Self {
        self.adv_svi_ip = value;
        self
    }
    pub fn set_adv_ipv4_unicast(mut self, value: bool) -> Self {
        self.adv_ipv4_unicast = value;
        self
    }
    pub fn set_adv_ipv4_unicast_rmap(mut self, rmap: String) -> Self {
        self.adv_ipv4_unicast_rmap = Some(rmap);
        self
    }
    pub fn set_adv_ipv6_unicast(mut self, value: bool) -> Self {
        self.adv_ipv6_unicast = value;
        self
    }
    pub fn set_adv_ipv6_unicast_rmap(mut self, rmap: String) -> Self {
        self.adv_ipv6_unicast_rmap = Some(rmap);
        self
    }
    pub fn set_default_originate_ipv4(mut self, value: bool) -> Self {
        self.default_originate_ipv4 = value;
        self
    }
    pub fn set_default_originate_ipv6(mut self, value: bool) -> Self {
        self.default_originate_ipv6 = value;
        self
    }
}
impl BgpNeighCapabilities {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn dynamic(mut self, value: bool) -> Self {
        self.dynamic = value;
        self
    }
    pub fn ext_nhop(mut self, value: bool) -> Self {
        self.ext_nhop = value;
        self
    }
    pub fn fqdn(mut self, value: bool) -> Self {
        self.fqdn = value;
        self
    }
    pub fn software_ver(mut self, value: bool) -> Self {
        self.software_ver = value;
        self
    }
}
impl BgpNeighbor {
    pub fn new_host(address: IpAddr) -> Self {
        Self {
            ntype: BgpNeighType::Host(address),
            ..Default::default()
        }
    }
    pub fn new_peer_group(group: &str) -> Self {
        Self {
            ntype: BgpNeighType::PeerGroup(group.to_owned()),
            ..Default::default()
        }
    }
    pub fn is_peer_group(&self) -> bool {
        matches!(self.ntype, BgpNeighType::PeerGroup(_))
    }

    /* capabilities */
    pub fn set_capabilities(mut self, capas: BgpNeighCapabilities) -> Self {
        self.capabilities = capas;
        self
    }

    /* === options == */
    pub fn set_route_map_in(mut self, rmap_name: &str) -> Self {
        self.route_map_in = Some(rmap_name.to_owned());
        self
    }
    pub fn set_route_map_out(mut self, rmap_name: &str) -> Self {
        self.route_map_out = Some(rmap_name.to_owned());
        self
    }
    pub fn set_remote_as(mut self, asn: u32) -> Self {
        self.remote_as = Some(asn);
        self
    }
    pub fn set_peer_group(mut self, peer_group: &str) -> Self {
        self.peer_group = Some(peer_group.to_owned());
        self
    }
    pub fn set_description(mut self, description: &str) -> Self {
        self.description = Some(description.to_owned());
        self
    }
    pub fn set_update_source_address(mut self, address: IpAddr) -> Self {
        self.update_source = Some(BgpUpdateSource::Address(address));
        self
    }
    pub fn set_update_source_interface(mut self, ifname: &str) -> Self {
        self.update_source = Some(BgpUpdateSource::Interface(ifname.to_owned()));
        self
    }
    pub fn set_update_source(mut self, update_source: Option<BgpUpdateSource>) -> Self {
        self.update_source = update_source;
        self
    }
    pub fn set_weight(mut self, weight: u16) -> Self {
        self.weight = Some(weight);
        self
    }
    pub fn set_send_community(mut self, comm: NeighSendCommunities) -> Self {
        self.send_community = Some(comm);
        self
    }
    pub fn set_ebgp_multihop(mut self, max_hops: u8) -> Self {
        self.ebgp_multihop = Some(max_hops);
        self
    }
    pub fn set_ttl_security(mut self, hops: u8) -> Self {
        self.ttl_sec_hops = Some(hops);
        self
    }
    pub fn set_advertisement_interval(mut self, interval: u16) -> Self {
        self.advertisement_interval = Some(interval);
        self
    }
    pub fn set_maximum_prefix(mut self, max: u32) -> Self {
        self.maximum_prefix = Some(max);
        self
    }
    pub fn set_maximum_prefix_out(mut self, max: u32) -> Self {
        self.maximum_prefix_out = Some(max);
        self
    }
    pub fn set_timer_connect(mut self, timer: u16) -> Self {
        self.timer_connect = Some(timer);
        self
    }
    pub fn set_timer_delay_open(mut self, timer: u8) -> Self {
        self.timer_delay_open = Some(timer);
        self
    }
    pub fn set_tcp_mss(mut self, mss: u16) -> Self {
        self.tcp_mss = Some(mss);
        self
    }

    /* === switches == */
    pub fn set_passive(mut self, value: bool) -> Self {
        self.passive = value;
        self
    }
    pub fn set_as_override(mut self, value: bool) -> Self {
        self.as_override = value;
        self
    }
    pub fn set_strict_capability_match(mut self, value: bool) -> Self {
        self.strict_capability_match = value;
        self
    }
    pub fn set_dont_capability_negotiate(mut self, value: bool) -> Self {
        self.dont_capability_negotiate = value;
        self
    }
    pub fn set_allow_as_in(mut self, value: bool) -> Self {
        self.allow_as_in = value;
        self
    }
    pub fn set_extended_link_bandwidth(mut self, value: bool) -> Self {
        self.extended_link_bandwidth = value;
        self
    }
    pub fn set_next_hop_self(mut self, value: bool) -> Self {
        self.next_hop_self = value;
        self
    }
    pub fn set_remove_private_as(mut self, value: bool) -> Self {
        self.remove_private_as = value;
        self
    }
    pub fn set_rr_client(mut self, value: bool) -> Self {
        self.rr_client = value;
        self
    }
    pub fn set_default_originate(mut self, value: bool) -> Self {
        self.default_originate = value;
        self
    }

    /* AFs: activated explicitly */
    pub fn ipv4_unicast_activate(mut self, value: bool) -> Self {
        self.ipv4_unicast = value;
        self
    }
    pub fn ipv6_unicast_activate(mut self, value: bool) -> Self {
        self.ipv6_unicast = value;
        self
    }
    pub fn l2vpn_evpn_activate(mut self, value: bool) -> Self {
        self.l2vpn_evpn = value;
        self
    }
}

impl BgpOptions {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set_network_import_check(mut self, value: bool) -> Self {
        self.network_import_check = value;
        self
    }
    pub fn set_ebgp_requires_policy(mut self, value: bool) -> Self {
        self.ebgp_requires_policy = value;
        self
    }
    pub fn set_bgp_default_unicast(mut self, value: bool) -> Self {
        self.bgp_default_unicast = value;
        self
    }
    pub fn set_supress_fib_pending(mut self, value: bool) -> Self {
        self.supress_fib_pending = value;
        self
    }
    pub fn set_supress_duplicates(mut self, value: bool) -> Self {
        self.supress_duplicates = value;
        self
    }
    pub fn set_minimum_holdtime(mut self, min_hold_time: u16) -> Self {
        self.minimum_holdtime = Some(min_hold_time);
        self
    }
    pub fn set_listen_range(mut self, prefix: Prefix, group: String) -> Self {
        self.listen_range = Some((prefix, group));
        self
    }
    pub fn set_listen_limit(mut self, limit: u16) -> Self {
        self.listen_limit = Some(limit);
        self
    }
}
impl BgpConfig {
    pub fn new(asn: u32) -> Self {
        Self {
            asn,
            ..Default::default()
        }
    }
    pub fn set_vrf_name(mut self, vrf_name: String) -> Self {
        self.vrf = Some(vrf_name);
        self
    }
    pub fn set_router_id(&mut self, router_id: Ipv4Addr) -> &Self {
        self.router_id = Some(router_id);
        self
    }
    pub fn set_bgp_options(&mut self, options: BgpOptions) -> &Self {
        self.options = options;
        self
    }
    pub fn add_neighbor(&mut self, neigh: BgpNeighbor) {
        self.neighbors.push(neigh);
    }
    pub fn set_af_l2vpn_evpn(&mut self, af_l2vpnevpn: AfL2vpnEvpn) {
        self.af_l2vpnevpn = Some(af_l2vpnevpn);
    }
    pub fn set_af_ipv4unicast(&mut self, af_ipv4unicast: AfIpv4Ucast) {
        self.af_ipv4unicast = Some(af_ipv4unicast);
    }
    pub fn set_af_ipv6unicast(&mut self, af_ipv6unicast: AfIpv6Ucast) {
        self.af_ipv6unicast = Some(af_ipv6unicast);
    }
}
