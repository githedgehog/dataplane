// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Context table build

use crate::NatRequirement;
use config::ConfigError;
use config::external::overlay::ValidatedOverlay;
use net::ip::NextHeader;
use net::packet::VpcDiscriminant;

mod acls;
mod display;
mod routing;
#[cfg(test)]
mod routing_tests;

use acls::AclTablesMap;
use routing::PeeringTables;

#[derive(Debug, Default, Clone)]
pub struct FlofiContext {
    routes: PeeringTables,
    acls: AclTablesMap,
}

impl TryFrom<&ValidatedOverlay> for FlofiContext {
    type Error = ConfigError;

    fn try_from(overlay: &ValidatedOverlay) -> Result<Self, Self::Error> {
        let route_lookup_tables_map = PeeringTables::from(overlay);
        // FIXME
        //let acl_tables_map = AclTablesMap::from(overlay);
        let acl_tables_map = AclTablesMap::default();
        Ok(Self {
            routes: route_lookup_tables_map,
            acls: acl_tables_map,
        })
    }
}

impl FlofiContext {
    pub(crate) fn lookup_route(
        &self,
        src_vpcd: VpcDiscriminant,
        src_ip: std::net::IpAddr,
        dst_ip: std::net::IpAddr,
        proto: NextHeader,
        ports: Option<(u16, u16)>,
    ) -> Option<(
        VpcDiscriminant,
        Option<NatRequirement>,
        Option<NatRequirement>,
    )> {
        self.routes.lookup(src_vpcd, src_ip, dst_ip, proto, ports)
    }

    pub(crate) fn lookup_acls(&self) -> bool {
        println!("lookup_acls called, acls: {:?}", self.acls);
        todo!()
    }
}
