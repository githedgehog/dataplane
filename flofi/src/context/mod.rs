// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Context table build

use crate::NatRequirement;
use config::ConfigError;
use config::external::overlay::ValidatedOverlay;
use net::ip::NextHeader;
use net::packet::VpcDiscriminant;

mod display;
mod tables;

use tables::PeeringTables;

#[derive(Debug, Default, Clone)]
pub struct FlofiContext {
    routes: PeeringTables,
}

impl TryFrom<&ValidatedOverlay> for FlofiContext {
    type Error = ConfigError;

    fn try_from(overlay: &ValidatedOverlay) -> Result<Self, Self::Error> {
        let route_lookup_tables_map = PeeringTables::from(overlay);
        Ok(Self {
            routes: route_lookup_tables_map,
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
}
