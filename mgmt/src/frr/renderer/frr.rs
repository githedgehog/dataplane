// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Config renderer: frr

use crate::frr::renderer::builder::{ConfigBuilder, MARKER, Render, Rendered};
use config::internal::routing::frr::{Frr, FrrProfile};

/* Display */
impl Rendered for FrrProfile {
    fn rendered(&self) -> String {
        match self {
            FrrProfile::Datacenter => "datacenter".to_string(),
            FrrProfile::Traditional => "traditional".to_string(),
        }
    }
}

/* impl Render */
impl Render for Frr {
    type Context = ();
    type Output = ConfigBuilder;
    fn render(&self, _: &Self::Context) -> Self::Output {
        let mut cfg = ConfigBuilder::new();
        cfg += format!("frr defaults {}", self.profile.rendered()).as_str();
        cfg += format!("hostname {}", self.hostname).as_str();
        cfg += "service integrated-vtysh-config";
        cfg += MARKER;
        cfg
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub mod tests {
    use super::*;

    #[test]
    fn test_frr_render() {
        let frr = Frr::new(FrrProfile::Datacenter, "GW1");

        println!("{}", frr.render(&()));
    }
}
