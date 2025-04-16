// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Config renderer: route maps

use crate::config::routing::routemap::*;
use crate::frr::renderer::builder::{ConfigBuilder, MARKER, Render};
use std::fmt::Display;

/* Impl Display */
impl Display for MatchingPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MatchingPolicy::Deny => write!(f, "deny"),
            MatchingPolicy::Permit => write!(f, "permit"),
        }
    }
}
impl Display for Community {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Community::None => write!(f, "none"),
            Community::ASNVAL(asn, val) => write!(f, "{asn}{val}"),
            Community::NoAdvertise => write!(f, "no-advertise"),
            Community::NoPeer => write!(f, "no-peer"),
            Community::NoExport => write!(f, "no-export"),
            Community::Blackhole => write!(f, "blackhole"),
            Community::LocalAs => write!(f, "local-AS"),
            Community::GracefulShutdown => write!(f, "graceful-shutdown"),
            Community::AcceptOwn => write!(f, "accept-own"),
        }
    }
}

/* Impl Render */
impl Render for RouteMapSetAction {
    type Context = ();
    type Output = String;
    fn render(&self, _ctx: &Self::Context) -> Self::Output {
        let mut statement = match self {
            RouteMapSetAction::Tag(tag) => format!("tag {tag}"),
            RouteMapSetAction::Distance(dist) => format!("distance {dist}"),
            RouteMapSetAction::Weight(weight) => format!("weight {weight}"),
            RouteMapSetAction::LocalPreference(lp) => format!("local-preference {lp}"),
            RouteMapSetAction::Community(comms, additive) => {
                let mut communities = "community".to_string();
                for c in comms {
                    communities += " ";
                    communities += c.to_string().as_str();
                }
                if *additive {
                    communities += " additive";
                }
                communities
            }
        };
        statement.insert_str(0, " set ");
        statement
    }
}
impl Render for Vec<RouteMapSetAction> {
    type Context = ();
    type Output = ConfigBuilder;
    fn render(&self, _ctx: &Self::Context) -> Self::Output {
        let mut config = ConfigBuilder::new();
        self.iter().for_each(|e| config += e.render(&()));
        config
    }
}

impl Render for RouteMapMatch {
    type Context = ();
    type Output = String;
    fn render(&self, _ctx: &Self::Context) -> Self::Output {
        let mut statement = match self {
            RouteMapMatch::SrcVrf(vrfname) => format!("source-vrf {vrfname}"),
            RouteMapMatch::Ipv4AddressPrefixList(preflistname) => {
                format!("ip address prefix-list {preflistname}")
            }
            RouteMapMatch::Ipv6AddressPrefixList(preflistname) => {
                format!("ipv6 address prefix-list {preflistname}")
            }
            RouteMapMatch::Ipv4PrefixLen(len) => format!("ip address prefix-len {len}"),
            RouteMapMatch::Ipv6PrefixLen(len) => format!("ipv6 address prefix-len {len}"),
            RouteMapMatch::Ipv4NextHopPrefixList(nhpreflist) => format!("ip next-hop {nhpreflist}"),
            RouteMapMatch::Ipv6NextHopPrefixList(nhpreflist) => {
                format!("ipv6 next-hop {nhpreflist}")
            }
            RouteMapMatch::Metric(metric) => format!("metric {metric}"),
            RouteMapMatch::EvpnRouteType(rtnum) => format!("evpn route-type {rtnum}"),
            RouteMapMatch::EvpnVni(vni) => format!("evpn vni {vni}"),
        };
        statement.insert_str(0, " match ");
        statement
    }
}
impl Render for Vec<RouteMapMatch> {
    type Context = ();
    type Output = ConfigBuilder;
    fn render(&self, _ctx: &Self::Context) -> Self::Output {
        let mut config = ConfigBuilder::new();
        self.iter().for_each(|m| config += m.render(&()));
        config
    }
}
impl Render for RouteMapEntry {
    type Context = String;
    type Output = ConfigBuilder;
    fn render(&self, ctx: &Self::Context) -> Self::Output {
        let mut config = ConfigBuilder::new();
        config += format!("{} {} {}", ctx, self.policy, self.seq);
        config += self.matches.render(&());
        config += self.actions.render(&());
        config += "exit";
        config += MARKER;
        config
    }
}
impl Render for RouteMap {
    type Context = ();
    type Output = ConfigBuilder;
    fn render(&self, _ctx: &Self::Context) -> Self::Output {
        let mut config = ConfigBuilder::new();
        config += MARKER;
        let prefix = format!("route-map {}", self.name.to_uppercase());
        self.entries
            .iter()
            .for_each(|e| config += e.render(&prefix));
        config
    }
}
impl Render for RouteMapTable {
    type Context = ();
    type Output = ConfigBuilder;
    fn render(&self, _: &Self::Context) -> ConfigBuilder {
        let mut cfg = ConfigBuilder::new();
        let _ = self.values().map(|plist| cfg += plist.render(&()));
        cfg
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;
    use crate::config::routing::routemap::RouteMap;
    use net::vxlan::Vni;

    #[test]
    fn test_route_map_render() {
        let mut rmap = RouteMap::new("Sample-route-map");
        let entry = RouteMapEntry::new(10, MatchingPolicy::Permit)
            .add_match(RouteMapMatch::SrcVrf("vrf-1".to_string()))
            .add_match(RouteMapMatch::EvpnVni(Vni::new_checked(3000).unwrap()))
            .add_match(RouteMapMatch::Ipv4AddressPrefixList(
                "prefix-list-1".to_string(),
            ));
        rmap.add_entry(entry);

        let entry = RouteMapEntry::new(20, MatchingPolicy::Permit)
            .add_match(RouteMapMatch::Metric(100))
            .add_action(RouteMapSetAction::Tag(13))
            .add_action(RouteMapSetAction::Weight(4000))
            .add_action(RouteMapSetAction::LocalPreference(100));
        rmap.add_entry(entry);

        let entry = RouteMapEntry::new(30, MatchingPolicy::Permit)
            .add_match(RouteMapMatch::Ipv4NextHopPrefixList(
                "NHOP-PLIST".to_string(),
            ))
            .add_action(RouteMapSetAction::Community(
                vec![Community::NoExport, Community::LocalAs],
                true,
            ));
        rmap.add_entry(entry);

        let entry = RouteMapEntry::new(40, MatchingPolicy::Deny);
        rmap.add_entry(entry);

        println!("{}", rmap.render(&()));

        println!("{:#?}", rmap.render(&()));
    }
}
