// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Methods for config names generation

#![allow(unused)]

use crate::models::external::overlay::vpc::{Vpc, VpcId};
use net::interface::InterfaceName;

impl VpcId {
    pub(crate) fn vrf_name(&self) -> InterfaceName {
        InterfaceName::try_from(format!("{self}-vrf")).unwrap_or_else(|_| unreachable!())
    }
    pub(crate) fn bridge_name(&self) -> InterfaceName {
        InterfaceName::try_from(format!("{self}-bri")).unwrap_or_else(|_| unreachable!())
    }
    pub(crate) fn vtep_name(&self) -> InterfaceName {
        InterfaceName::try_from(format!("{self}-vtp")).unwrap_or_else(|_| unreachable!())
    }
}

impl Vpc {
    pub(crate) fn vrf_name(&self) -> String {
        self.id.vrf_name().to_string()
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
