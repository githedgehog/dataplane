// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Traits and implementations for configuration name generations.
//! Defines convenience traits to generate names for configurations.
//! These traits only exist so that we can implement additional methods
//! for `VpcId` and `Vpc`, defined in the config crate. The reason to
//! implement those here and not in the config crate is because these
//! represent just one particular way of populating the configuration
//! objects defined there.

#![allow(unused)]

use config::external::overlay::vpc::{Vpc, VpcId};
use net::interface::InterfaceName;

////////////////////////////////////////////////////////////////////////
/// Convenience trait to generate interface names for a VPC. We only
/// implement the trait for `VpcId`.
////////////////////////////////////////////////////////////////////////
pub(crate) trait VpcInterfacesNames
where
    Self: std::fmt::Display,
{
    fn vrf_name(&self) -> InterfaceName;
    fn bridge_name(&self) -> InterfaceName;
    fn vtep_name(&self) -> InterfaceName;
}
impl VpcInterfacesNames for VpcId {
    fn vrf_name(&self) -> InterfaceName {
        InterfaceName::try_from(format!("{self}-vrf")).unwrap_or_else(|_| unreachable!())
    }
    fn bridge_name(&self) -> InterfaceName {
        InterfaceName::try_from(format!("{self}-bri")).unwrap_or_else(|_| unreachable!())
    }
    fn vtep_name(&self) -> InterfaceName {
        InterfaceName::try_from(format!("{self}-vtp")).unwrap_or_else(|_| unreachable!())
    }
}

////////////////////////////////////////////////////////////////////////////
/// Convenience trait to generate names for distinct config bits for a `Vpc`.
/// This trait is only implemented for `Vpc`
////////////////////////////////////////////////////////////////////////////
pub(crate) trait VpcConfigNames {
    fn vrf_name(&self) -> String;
    fn import_rmap_ipv4(&self) -> String;
    fn import_rmap_ipv6(&self) -> String;
    fn import_plist_peer(&self, remote_name: &str) -> String;
    fn import_plist_peer_desc(&self, remote_name: &str) -> String;
    fn adv_plist(&self) -> String;
    fn adv_plist_desc(&self) -> String;
    fn adv_rmap(&self) -> String;
}

impl VpcConfigNames for Vpc {
    fn vrf_name(&self) -> String {
        self.id.vrf_name().to_string()
    }
    fn import_rmap_ipv4(&self) -> String {
        format!("{}-IPV4-IMPORTS", self.name.to_uppercase())
    }
    fn import_rmap_ipv6(&self) -> String {
        format!("{}-IPV6-IMPORTS", self.name.to_uppercase())
    }
    fn import_plist_peer(&self, remote_name: &str) -> String {
        format!(
            "{}-FROM-{}",
            &self.name.to_uppercase(),
            remote_name.to_uppercase()
        )
    }
    fn import_plist_peer_desc(&self, remote_name: &str) -> String {
        format!("Prefixes of {} reachable by {}", remote_name, self.name)
    }
    fn adv_plist(&self) -> String {
        format!("ADV-TO-{}", &self.name.to_uppercase())
    }
    fn adv_plist_desc(&self) -> String {
        format!(
            "Prefixes allowed to advertised to {}",
            &self.name.to_uppercase()
        )
    }
    fn adv_rmap(&self) -> String {
        format!("ADV-TO-{}", &self.name.to_uppercase())
    }
}
