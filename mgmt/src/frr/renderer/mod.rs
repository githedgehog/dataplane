// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! FRR driver for frr-reload.py

pub mod bgp;
pub mod builder;
pub mod frr;
pub mod interface;
pub mod prefixlist;
pub mod routemap;
pub mod statics;
pub mod vrf;

use crate::frr::renderer::builder::{ConfigBuilder, Render};
use crate::models::external::configdb::gwconfig::GwConfig;
use crate::models::internal::InternalConfig;

fn render_metadata(config: &GwConfig) -> String {
    format!("! config for gen {}", config.external.genid)
}

impl Render for InternalConfig {
    type Context = GwConfig;
    type Output = ConfigBuilder;
    fn render(&self, config: &Self::Context) -> Self::Output {
        let mut cfg = ConfigBuilder::new();

        /* Metadata: TODO */
        cfg += render_metadata(config);

        /* we always enable logging on stdout */
        cfg += "log stdout";

        /* frr profile */
        cfg += self.frr.render(&());

        /* prefix lists */
        cfg += self.plist_table.render(&());

        /* vrfs */
        cfg += self.vrfs.render(&());

        /* interfaces live in vrfs. So, we iterate over all VRFs */
        self.vrfs
            .iter()
            .for_each(|vrf| cfg += vrf.interfaces.render(&()));

        /* Vrf BGP instances */
        cfg += self.vrfs.render_vrf_bgp();

        /* route maps */
        cfg += self.rmap_table.render(&());

        cfg
    }
}
