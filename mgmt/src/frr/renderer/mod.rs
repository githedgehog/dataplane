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

use crate::config::InternalConfig;
use crate::frr::renderer::builder::{ConfigBuilder, Render};

impl Render for InternalConfig {
    type Context = ();
    type Output = ConfigBuilder;
    fn render(&self, _: &Self::Context) -> Self::Output {
        let mut cfg = ConfigBuilder::new();
        self.frr.as_ref().map(|frr| cfg += frr.render(&()));

        /* vrfs */
        cfg += self.vrfs.render(&());

        /* interfaces */
        cfg += self.interfaces.render(&());

        /* Vrf BGP instances */
        cfg += self.vrfs.render_vrf_bgp();

        cfg
    }
}
