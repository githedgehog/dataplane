// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Config renderer: frr

use crate::frr::renderer::builder::{ConfigBuilder, MARKER, Render};
use crate::models::internal::routing::frr::{Frr, FrrProfile};
use std::fmt::Display;

/* Display */
impl Display for FrrProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrrProfile::Datacenter => write!(f, "datacenter"),
            FrrProfile::Traditional => write!(f, "traditional"),
        }
    }
}

/* impl Render */
impl Render for Frr {
    type Context = ();
    type Output = ConfigBuilder;
    fn render(&self, _: &Self::Context) -> Self::Output {
        let mut cfg = ConfigBuilder::new();
        cfg += format!("frr defaults {}", self.profile).as_str();
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
