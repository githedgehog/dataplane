// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Methods for config names generation

#![allow(unused)]

use crate::models::external::overlay::vpc::{Vpc, VpcId};

impl VpcId {
    pub(crate) fn vrf_name(&self) -> String {
        format!("{self}-vrf")
    }
    pub(crate) fn bridge_name(&self) -> String {
        format!("{self}-bri")
    }
    pub(crate) fn vtep_name(&self) -> String {
        format!("{self}-vtp")
    }
}

impl Vpc {
    pub(crate) fn vrf_name(&self) -> String {
        self.id.vrf_name()
    }
    pub(crate) fn import_route_map_ipv4(&self) -> String {
        format!("RM-IMPORT-{}", self.name.to_uppercase())
    }
    pub(crate) fn plist_with_vpc(&self, remote_name: &str) -> String {
        format!(
            "{}-FROM-{}",
            &self.name.to_uppercase(),
            remote_name.to_uppercase()
        )
    }
    pub(crate) fn plist_with_vpc_descr(&self, remote_name: &str) -> String {
        format!("Prefixes of {} reachable by {}", remote_name, self.name)
    }
}
