// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Config renderer: BFD

#![allow(unused)]

use crate::frr::renderer::builder::{ConfigBuilder, MARKER, Render};

use config::internal::routing::bfd::{
    BFD_DETECT_MULTIPLIER, BFD_RECEIVE_INTERVAL_MS, BFD_TRANSMIT_INTERVAL_MS, BfdPeer,
};

impl Render for BfdPeer {
    type Context = ();
    type Output = ConfigBuilder;

    fn render(&self, (): &Self::Context) -> Self::Output {
        let mut cfg = ConfigBuilder::new();

        /* peer heading */
        let mut peer = format!(" peer {}", self.address);
        if self.multihop {
            peer += " multihop";
        }
        cfg += peer;

        /* optional source (only meaningful for multihop) */
        if self.multihop {
            if let Some(src) = self.source.as_ref() {
                cfg += format!("  source {src}");
            }
        }
        /* hard-coded BFD params */
        cfg += "  no shutdown";
        cfg += format!("  detect-multiplier {BFD_DETECT_MULTIPLIER}");
        cfg += format!("  transmit-interval {BFD_TRANSMIT_INTERVAL_MS}");
        cfg += format!("  receive-interval {BFD_RECEIVE_INTERVAL_MS}");

        cfg
    }
}

impl Render for Vec<BfdPeer> {
    type Context = ();
    type Output = ConfigBuilder;

    fn render(&self, (): &Self::Context) -> Self::Output {
        let mut cfg = ConfigBuilder::new();

        /* don't render empty BFD section if global config flag is unset */
        if self.is_empty() {
            return cfg;
        }

        cfg += MARKER;
        cfg += "bfd";

        for p in self {
            cfg += p.render(&());
        }

        cfg += "exit";
        cfg += MARKER;
        cfg
    }
}
