// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Config renderer: static routes

use std::fmt::Display;

use crate::frr::renderer::builder::{ConfigBuilder, Render};
use crate::models::internal::routing::statics::{StaticRoute, StaticRouteNhop};
use routing::prefix::Prefix;

/* impl Display */
impl Display for StaticRouteNhop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StaticRouteNhop::Interface(ifname) => write!(f, "{ifname}"),
            StaticRouteNhop::Address(address) => write!(f, "{address}"),
            StaticRouteNhop::Null0 => write!(f, "Null0"),
            StaticRouteNhop::Reject => write!(f, "reject"),
            StaticRouteNhop::Blackhole => write!(f, "blackhole"),
            StaticRouteNhop::Unset => panic!("Missing next-hop"),
        }
    }
}

fn ip_route_type_str(prefix: &Prefix) -> &'static str {
    match prefix {
        Prefix::IPV4(_) => "ip",
        Prefix::IPV6(_) => "ipv6",
    }
}

/* impl Render */
impl Render for StaticRoute {
    type Context = ();
    type Output = ConfigBuilder;
    fn render(&self, _ctx: &Self::Context) -> Self::Output {
        let mut config = ConfigBuilder::new();
        let mut statement = format!(
            " {} route {} {}",
            ip_route_type_str(&self.prefix),
            self.prefix,
            self.next_hop
        );
        if let Some(nhop_vrf) = &self.next_hop_vrf {
            statement += format!(" nexthop-vrf {nhop_vrf}").as_ref();
        }
        if let Some(tag) = &self.tag {
            statement += format!(" tag {tag}").as_ref();
        }
        config += statement;
        config
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub mod tests {
    use super::*;
    use crate::models::internal::routing::statics::StaticRoute;
    use std::collections::BTreeSet;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn test_static_route_render() {
        let route = StaticRoute::new(Prefix::expect_from(("192.168.1.0", 24)))
            .nhop_addr(IpAddr::from_str("7.0.0.1").expect("Bad address"))
            .nhop_vrf("default".to_owned())
            .tag(1000);
        print!("\n{}", route.render(&()));

        let route = StaticRoute::new(Prefix::expect_from(("192.168.2.0", 24)))
            .nhop_iface("Eth1.200".to_owned())
            .tag(2000);
        print!("{}", route.render(&()));

        let route = StaticRoute::new(Prefix::expect_from(("192.168.3.0", 24))).nhop_blackhole();
        print!("{}", route.render(&()));

        let route = StaticRoute::new(Prefix::expect_from(("192.168.4.0", 29))).nhop_reject();
        print!("{}", route.render(&()));
    }

    pub fn build_static_routes() -> BTreeSet<StaticRoute> {
        let mut statics = BTreeSet::new();
        let route = StaticRoute::new(Prefix::expect_from(("192.168.1.0", 24)))
            .nhop_addr(IpAddr::from_str("7.0.0.1").expect("Bad address"))
            .nhop_vrf("VPC-1".to_owned())
            .tag(1000);
        statics.insert(route);

        let route = StaticRoute::new(Prefix::expect_from(("192.168.2.0", 24)))
            .nhop_addr(IpAddr::from_str("7.0.0.2").expect("Bad address"))
            .nhop_vrf("VPC-2".to_owned())
            .tag(1000);
        statics.insert(route);
        statics
    }
}
