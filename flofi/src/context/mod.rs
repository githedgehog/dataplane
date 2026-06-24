// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Context table build

use config::ConfigError;
use config::external::overlay::ValidatedOverlay;
use config::external::overlay::vpcpeering::{ValidatedExpose, VpcExposeNatConfig};

mod acls;
mod routing;

use acls::AclTablesMap;
use routing::PeeringTables;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NatRequirement {
    Static,
    Masquerade,
    PortForwarding,
}

impl NatRequirement {
    fn from_expose(expose: &ValidatedExpose) -> Option<Self> {
        match expose.nat_config()? {
            VpcExposeNatConfig::Masquerade(_) => Some(Self::Masquerade),
            VpcExposeNatConfig::Static(_) => Some(Self::Static),
            VpcExposeNatConfig::PortForwarding(_) => Some(Self::PortForwarding),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlofiContext {
    routes: PeeringTables,
    acls: AclTablesMap,
}

impl TryFrom<&ValidatedOverlay> for FlofiContext {
    type Error = ConfigError;

    fn try_from(overlay: &ValidatedOverlay) -> Result<Self, Self::Error> {
        let route_lookup_tables_map = PeeringTables::from(overlay);
        let acl_tables_map = AclTablesMap::from(overlay);
        Ok(Self {
            routes: route_lookup_tables_map,
            acls: acl_tables_map,
        })
    }
}
