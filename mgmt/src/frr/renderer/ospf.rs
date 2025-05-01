// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::frr::renderer::builder::{ConfigBuilder, MARKER, Render};

use crate::models::internal::routing::ospf::Ospf;
use crate::models::internal::routing::ospf::OspfInterface;
use crate::models::internal::routing::ospf::OspfNetwork;

use std::fmt::Display;

impl Display for OspfNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OspfNetwork::Broadcast => write!(f, "broadcast"),
            OspfNetwork::NonBroadcast => write!(f, "non-broadcast"),
            OspfNetwork::Point2Point => write!(f, "point-to-point"),
            OspfNetwork::Point2Multipoint => write!(f, "point-to-multipoint"),
        }
    }
}

impl Render for Ospf {
    type Context = ();
    type Output = ConfigBuilder;
    fn render(&self, _: &Self::Context) -> ConfigBuilder {
        let mut config = ConfigBuilder::new();
        let mut heading = "router ospf".to_string();
        if let Some(vrf) = &self.vrf {
            heading += format!(" vrf {vrf}").as_str();
        }
        config += heading;
        config += format!(" ospf router-id {}", self.router_id);

        config += MARKER;
        config
    }
}

impl Render for OspfInterface {
    type Context = ();
    type Output = ConfigBuilder;
    fn render(&self, _: &Self::Context) -> ConfigBuilder {
        let mut config = ConfigBuilder::new();
        config += format!(" ip ospf area {}", self.area);
        if let Some(network) = &self.network {
            config += format!(" ip ospf network {network}");
        }
        if let Some(cost) = &self.cost {
            config += format!(" ip ospf cost {cost}");
        }
        if self.passive {
            config += " ip ospf passive".to_string();
        }
        config
    }
}
