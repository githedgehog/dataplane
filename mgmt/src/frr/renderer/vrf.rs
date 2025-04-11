// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Config renderer: vrfs

use crate::frr::renderer::builder::{ConfigBuilder, MARKER, Render};
use crate::models::internal::routing::vrf::{VrfConfig, VrfConfigTable};

/* impl Render */
impl Render for VrfConfig {
    type Context = ();
    type Output = ConfigBuilder;
    fn render(&self, _ctx: &Self::Context) -> Self::Output {
        let mut cfg = ConfigBuilder::new();
        if !self.default {
            cfg += MARKER;
            cfg += format!("vrf {}", &self.name);
        }

        /* static routes */
        self.static_routes.iter().for_each(|s| cfg += s.render(&()));

        /* we don't render BGP here even if it is inside VRF in the model */

        /* vni */
        if let Some(vni) = &self.vni {
            cfg += format!(" vni {vni}");
        }
        if !self.default {
            cfg += "exit-vrf";
            cfg += MARKER;
        }
        cfg
    }
}
impl Render for VrfConfigTable {
    type Context = ();
    type Output = ConfigBuilder;
    fn render(&self, _ctx: &Self::Context) -> Self::Output {
        let mut cfg = ConfigBuilder::new();
        self.iter().for_each(|vrf| cfg += vrf.render(&()));
        cfg
    }
}
impl VrfConfig {
    pub fn render_vrf_bgp(&self) -> ConfigBuilder {
        let mut cfg = ConfigBuilder::new();
        if let Some(bgp) = self.bgp.as_ref() {
            cfg += bgp.render(&());
        }
        cfg
    }
}
impl VrfConfigTable {
    pub fn render_vrf_bgp(&self) -> ConfigBuilder {
        let mut cfg = ConfigBuilder::new();
        self.iter().for_each(|vrf| cfg += vrf.render_vrf_bgp());
        cfg
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;
    use crate::frr::renderer::statics::tests::build_static_routes;
    use crate::models::internal::routing::vrf::VrfConfig;
    use net::vxlan::Vni;

    #[test]
    fn test_vrf_render() {
        let mut vrf_cfg = VrfConfig::new("VPC-1", Some(Vni::new_checked(3000).unwrap()), false);
        vrf_cfg.static_routes = build_static_routes();
        println!("\n{}", vrf_cfg.render(&()));
    }
}
