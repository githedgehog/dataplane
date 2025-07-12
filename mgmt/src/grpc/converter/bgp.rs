// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use gateway_config::config as gateway_config;
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use crate::models::internal::routing::bgp::{
    AfIpv4Ucast, AfIpv6Ucast, AfL2vpnEvpn, BgpConfig, BgpNeighCapabilities, BgpNeighType,
    BgpNeighbor, BgpOptions, BgpUpdateSource, NeighSendCommunities, Protocol, Redistribute,
};

use lpm::prefix::{Prefix, PrefixString};

use gateway_config::bgp_neighbor_update_source::Source;

#[repr(transparent)]
pub struct OptBgpUpdateSource(pub Option<BgpUpdateSource>);
#[repr(transparent)]
pub struct OptGRPCBgpNeighborUpdateSource(pub Option<gateway_config::BgpNeighborUpdateSource>);

fn has_redistribute(redistribute: &[Redistribute], protocol: &Protocol) -> bool {
    redistribute.iter().any(|r| r.protocol == *protocol)
}

impl TryFrom<&gateway_config::BgpAddressFamilyIPv4> for AfIpv4Ucast {
    type Error = String;

    fn try_from(ipv4: &gateway_config::BgpAddressFamilyIPv4) -> Result<Self, Self::Error> {
        let mut afipv4 = AfIpv4Ucast::new();

        if ipv4.redistribute_static {
            afipv4.redistribute(Redistribute::new(Protocol::Static, None, None));
        }

        if ipv4.redistribute_connected {
            afipv4.redistribute(Redistribute::new(Protocol::Connected, None, None));
        }

        let networks = ipv4
            .networks
            .iter()
            .map(|n| {
                let prefix = Prefix::try_from(PrefixString(n))
                    .map_err(|e| format!("Invalid network prefix {n}: {e}"))?;
                if !prefix.is_ipv4() {
                    return Err(format!("Invalid network prefix {n}: not an IPv4 prefix"));
                }
                Ok(prefix)
            })
            .collect::<Result<Vec<_>, _>>()?;

        afipv4.add_networks(networks);

        Ok(afipv4)
    }
}

impl TryFrom<&gateway_config::BgpAddressFamilyIPv6> for AfIpv6Ucast {
    type Error = String;

    fn try_from(ipv6: &gateway_config::BgpAddressFamilyIPv6) -> Result<Self, Self::Error> {
        let mut afipv6 = AfIpv6Ucast::new();

        if ipv6.redistribute_static {
            afipv6
                .redistribute
                .push(Redistribute::new(Protocol::Static, None, None));
        }

        if ipv6.redistribute_connected {
            afipv6
                .redistribute
                .push(Redistribute::new(Protocol::Connected, None, None));
        }

        let networks = ipv6
            .networks
            .iter()
            .map(|n| {
                let prefix = Prefix::try_from(PrefixString(n))
                    .map_err(|e| format!("Invalid network prefix {n}: {e}"))?;
                if !prefix.is_ipv6() {
                    return Err(format!("Invalid network prefix {n}: not an IPv6 prefix"));
                }
                Ok(prefix)
            })
            .collect::<Result<Vec<_>, _>>()?;

        afipv6.add_networks(networks);

        Ok(afipv6)
    }
}

impl TryFrom<&gateway_config::BgpNeighbor> for BgpNeighbor {
    type Error = String;

    fn try_from(neighbor: &gateway_config::BgpNeighbor) -> Result<Self, Self::Error> {
        // Parse remote ASN
        let remote_as = neighbor
            .remote_asn
            .parse::<u32>()
            .map_err(|_| format!("Invalid remote ASN format: {}", neighbor.remote_asn))?;

        // Create neighbor address for ntype
        let neighbor_addr = IpAddr::from_str(&neighbor.address)
            .map_err(|_| format!("Invalid neighbor address: {}", neighbor.address))?;

        // Determine which address families are activated
        let mut ipv4_unicast = false;
        let mut ipv6_unicast = false;
        let mut l2vpn_evpn = false;

        for af in &neighbor.af_activate {
            match gateway_config::BgpAf::try_from(*af) {
                Ok(gateway_config::BgpAf::Ipv4Unicast) => ipv4_unicast = true,
                Ok(gateway_config::BgpAf::Ipv6Unicast) => ipv6_unicast = true,
                Ok(gateway_config::BgpAf::L2vpnEvpn) => l2vpn_evpn = true,
                Err(_) => return Err(format!("Unknown BGP address family: {af}")),
            }
        }

        // Create the neighbor config
        let mut neigh = BgpNeighbor::new_host(neighbor_addr)
            .set_remote_as(remote_as)
            .set_capabilities(BgpNeighCapabilities::default())
            .set_send_community(NeighSendCommunities::Both)
            .ipv4_unicast_activate(ipv4_unicast)
            .ipv6_unicast_activate(ipv6_unicast)
            .l2vpn_evpn_activate(l2vpn_evpn);

        // set update source
        if let Some(update_source) = &neighbor.update_source {
            let upd_source = OptBgpUpdateSource::try_from(update_source)
                .map_err(|e| format!("Bad update source: {e}"))?;
            neigh = neigh.set_update_source(upd_source.0);
        }

        Ok(neigh)
    }
}

impl TryFrom<&BgpNeighbor> for gateway_config::BgpNeighbor {
    type Error = String;

    fn try_from(neighbor: &BgpNeighbor) -> Result<Self, Self::Error> {
        // Get neighbor address safely
        let address = match &neighbor.ntype {
            BgpNeighType::Host(addr) => addr.to_string(),
            BgpNeighType::PeerGroup(name) => {
                return Err(format!("Peer group type not supported in gRPC: {name}"));
            }
            BgpNeighType::Unset => {
                return Err("Unset BGP neighbor type not supported in gRPC".to_string());
            }
        };

        // Get remote ASN safely
        let remote_asn = neighbor
            .remote_as
            .as_ref()
            .ok_or_else(|| "Missing remote ASN for BGP neighbor".to_string())?
            .to_string();

        // Build address family activation list
        let mut af_activate = Vec::new();
        if neighbor.ipv4_unicast {
            af_activate.push(gateway_config::BgpAf::Ipv4Unicast.into());
        }
        if neighbor.ipv6_unicast {
            af_activate.push(gateway_config::BgpAf::Ipv6Unicast.into());
        }
        if neighbor.l2vpn_evpn {
            af_activate.push(gateway_config::BgpAf::L2vpnEvpn.into());
        }

        let update_source = OptGRPCBgpNeighborUpdateSource::try_from(&neighbor.update_source)
            .map_err(|e| format!("Bad update source: {e}"))?
            .0;

        Ok(gateway_config::BgpNeighbor {
            address,
            remote_asn,
            af_activate,
            update_source,
        })
    }
}

impl TryFrom<&gateway_config::BgpNeighborUpdateSource> for OptBgpUpdateSource {
    type Error = String;

    fn try_from(neighbor: &gateway_config::BgpNeighborUpdateSource) -> Result<Self, Self::Error> {
        match &neighbor.source {
            Some(Source::Address(address)) => {
                Ok(OptBgpUpdateSource(Some(BgpUpdateSource::Address(
                    address
                        .parse()
                        .map_err(|e| format!("Bad update source address {e}"))?,
                ))))
            }
            Some(Source::Interface(ifname)) => Ok(OptBgpUpdateSource(Some(
                BgpUpdateSource::Interface(ifname.to_owned()),
            ))),
            None => Ok(OptBgpUpdateSource(None)),
        }
    }
}

impl TryFrom<&Option<BgpUpdateSource>> for OptGRPCBgpNeighborUpdateSource {
    type Error = String;

    fn try_from(update_source: &Option<BgpUpdateSource>) -> Result<Self, Self::Error> {
        match update_source {
            Some(BgpUpdateSource::Address(addr)) => Ok(OptGRPCBgpNeighborUpdateSource(Some(
                gateway_config::BgpNeighborUpdateSource {
                    source: Some(gateway_config::bgp_neighbor_update_source::Source::Address(
                        addr.to_string(),
                    )),
                },
            ))),

            Some(BgpUpdateSource::Interface(iface)) => Ok(OptGRPCBgpNeighborUpdateSource(Some(
                gateway_config::BgpNeighborUpdateSource {
                    source: Some(
                        gateway_config::bgp_neighbor_update_source::Source::Interface(
                            iface.to_string(),
                        ),
                    ),
                },
            ))),
            None => Ok(OptGRPCBgpNeighborUpdateSource(None)),
        }
    }
}

// BgpConfig conversions
impl TryFrom<&gateway_config::RouterConfig> for BgpConfig {
    type Error = String;

    fn try_from(router: &gateway_config::RouterConfig) -> Result<Self, Self::Error> {
        // Parse ASN from string to u32
        let asn = router
            .asn
            .parse::<u32>()
            .map_err(|_| format!("Invalid ASN format: {}", router.asn))?;

        // Parse router_id from string to Ipv4Addr
        let router_id = router
            .router_id
            .parse::<Ipv4Addr>()
            .map_err(|_| format!("Invalid router ID format: {}", router.router_id))?;

        // Use default options
        let options = BgpOptions::default();

        // Convert neighbors
        let mut neighbors = Vec::new();
        for neighbor in &router.neighbors {
            neighbors.push(BgpNeighbor::try_from(neighbor)?);
        }

        // Convert IPv4 Unicast address family if present
        let af_ipv4unicast = match &router.ipv4_unicast {
            Some(ipv4) => AfIpv4Ucast::try_from(ipv4)?,
            None => AfIpv4Ucast::new(),
        };
        let af_ipv6unicast = match &router.ipv6_unicast {
            Some(ipv6) => AfIpv6Ucast::try_from(ipv6)?,
            None => AfIpv6Ucast::new(),
        };

        let af_l2vpnevpn = AfL2vpnEvpn::new()
            .set_adv_all_vni(router.l2vpn_evpn.is_none_or(|evpn| evpn.advertise_all_vni))
            .set_adv_default_gw(true)
            .set_adv_svi_ip(true)
            .set_adv_ipv4_unicast(true)
            .set_adv_ipv6_unicast(false)
            .set_default_originate_ipv4(false)
            .set_default_originate_ipv6(false);

        let mut bgpconfig = BgpConfig::new(asn);
        bgpconfig.set_router_id(router_id);
        bgpconfig.set_bgp_options(options);
        if router.ipv4_unicast.is_some() {
            bgpconfig.set_af_ipv4unicast(af_ipv4unicast);
        }
        if router.ipv6_unicast.is_some() {
            bgpconfig.set_af_ipv6unicast(af_ipv6unicast);
        }
        if router.l2vpn_evpn.is_some() {
            bgpconfig.set_af_l2vpn_evpn(af_l2vpnevpn);
        }

        // Add each neighbor to the BGP config
        for neighbor in &router.neighbors {
            bgpconfig.add_neighbor(BgpNeighbor::try_from(neighbor)?);
        }

        Ok(bgpconfig)
    }
}

impl TryFrom<&BgpConfig> for gateway_config::RouterConfig {
    type Error = String;

    fn try_from(bgp: &BgpConfig) -> Result<Self, Self::Error> {
        // Convert BGP neighbors
        let mut neighbors = Vec::with_capacity(bgp.neighbors.len());
        for neighbor in &bgp.neighbors {
            let grpc_neighbor = gateway_config::BgpNeighbor::try_from(neighbor)?;
            neighbors.push(grpc_neighbor);
        }

        // Get router ID safely
        let router_id = bgp
            .router_id
            .as_ref()
            .map_or(String::new(), ToString::to_string);

        // Create IPv4 unicast config if enabled
        let ipv4_unicast =
            bgp.af_ipv4unicast
                .as_ref()
                .map(|c| gateway_config::BgpAddressFamilyIPv4 {
                    redistribute_connected: has_redistribute(&c.redistribute, &Protocol::Connected),
                    redistribute_static: has_redistribute(&c.redistribute, &Protocol::Static),
                    networks: c.networks.iter().map(ToString::to_string).collect(),
                });

        // Create IPv6 unicast config if enabled
        let ipv6_unicast =
            bgp.af_ipv6unicast
                .as_ref()
                .map(|c| gateway_config::BgpAddressFamilyIPv6 {
                    redistribute_connected: has_redistribute(&c.redistribute, &Protocol::Connected),
                    redistribute_static: has_redistribute(&c.redistribute, &Protocol::Static),
                    networks: c.networks.iter().map(ToString::to_string).collect(),
                });

        // Create L2VPN EVPN config if enabled
        let l2vpn_evpn =
            bgp.af_l2vpnevpn
                .as_ref()
                .map(|config| gateway_config::BgpAddressFamilyL2vpnEvpn {
                    advertise_all_vni: config.adv_all_vni,
                });

        // Create route maps (empty for now)
        let route_maps = Vec::new(); // TODO: Implement route map conversion

        Ok(gateway_config::RouterConfig {
            asn: bgp.asn.to_string(),
            router_id,
            neighbors,
            ipv4_unicast,
            ipv6_unicast,
            l2vpn_evpn,
            route_maps,
        })
    }
}
