// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::frr::renderer::builder::{ConfigBuilder, MARKER, Render, Rendered};

use config::internal::routing::ospf::Ospf;
use config::internal::routing::ospf::OspfInterface;
use config::internal::routing::ospf::OspfNetwork;

impl Rendered for OspfNetwork {
    fn rendered(&self) -> String {
        match self {
            OspfNetwork::Broadcast => "broadcast".to_string(),
            OspfNetwork::NonBroadcast => "non-broadcast".to_string(),
            OspfNetwork::Point2Point => "point-to-point".to_string(),
            OspfNetwork::Point2Multipoint => "point-to-multipoint".to_string(),
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
            config += format!(" ip ospf network {}", network.rendered());
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
