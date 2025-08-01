// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Config renderer: route maps

use crate::frr::renderer::builder::{ConfigBuilder, MARKER, Render, Rendered};
use config::internal::routing::routemap::*;

/* Impl Display */
impl Rendered for MatchingPolicy {
    fn rendered(&self) -> String {
        match self {
            MatchingPolicy::Deny => "deny".to_string(),
            MatchingPolicy::Permit => "permit".to_string(),
        }
    }
}
impl Rendered for Community {
    fn rendered(&self) -> String {
        match self {
            Community::None => "none".to_string(),
            Community::ASNVAL(asn, val) => format!("{asn}{val}"),
            Community::NoAdvertise => "no-advertise".to_string(),
            Community::NoPeer => "no-peer".to_string(),
            Community::NoExport => "no-export".to_string(),
            Community::Blackhole => "blackhole".to_string(),
            Community::LocalAs => "local-AS".to_string(),
            Community::GracefulShutdown => "graceful-shutdown".to_string(),
            Community::AcceptOwn => "accept-own".to_string(),
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
                    communities += c.rendered().as_str();
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
    type Context = (String, u32); /* u32 is sequence number */
    type Output = ConfigBuilder;
    fn render(&self, ctx: &Self::Context) -> Self::Output {
        let mut config = ConfigBuilder::new();
        config += format!("{} {} {}", ctx.0, self.policy.rendered(), ctx.1);
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
        let render_prefix = format!("route-map {}", self.name);
        self.entries
            .iter()
            .for_each(|(seq, e)| config += e.render(&(render_prefix.clone(), *seq)));
        config
    }
}
impl Render for RouteMapTable {
    type Context = ();
    type Output = ConfigBuilder;
    fn render(&self, _: &Self::Context) -> ConfigBuilder {
        let mut cfg = ConfigBuilder::new();
        self.values().for_each(|plist| cfg += plist.render(&()));
        cfg
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;
    use config::internal::routing::routemap::RouteMap;
    use net::vxlan::Vni;

    fn build_test_route_map() -> RouteMap {
        let mut rmap = RouteMap::new("Sample-route-map");
        let entry = RouteMapEntry::new(MatchingPolicy::Permit)
            .add_match(RouteMapMatch::SrcVrf("vrf-1".to_string()))
            .add_match(RouteMapMatch::EvpnVni(Vni::new_checked(3000).unwrap()))
            .add_match(RouteMapMatch::Ipv4AddressPrefixList(
                "prefix-list-1".to_string(),
            ));
        rmap.add_entry(None, entry).unwrap();

        let entry = RouteMapEntry::new(MatchingPolicy::Permit)
            .add_match(RouteMapMatch::Metric(100))
            .add_action(RouteMapSetAction::Tag(13))
            .add_action(RouteMapSetAction::Weight(4000))
            .add_action(RouteMapSetAction::LocalPreference(100));
        rmap.add_entry(None, entry).unwrap();

        let entry = RouteMapEntry::new(MatchingPolicy::Permit)
            .add_match(RouteMapMatch::Ipv4NextHopPrefixList(
                "NHOP-PLIST".to_string(),
            ))
            .add_action(RouteMapSetAction::Community(
                vec![Community::NoExport, Community::LocalAs],
                true,
            ));
        rmap.add_entry(None, entry).unwrap();

        let entry = RouteMapEntry::new(MatchingPolicy::Deny);
        rmap.add_entry(None, entry).unwrap();
        rmap
    }

    #[test]
    fn test_route_map_render() {
        let rmap = build_test_route_map();
        //println!("{}", rmap.render(&()));

        let mut rmap_table = RouteMapTable::new();
        rmap_table.add_route_map(rmap);
        println!("{rmap_table:#?}");
        println!("{}", rmap_table.render(&()));
    }
}
