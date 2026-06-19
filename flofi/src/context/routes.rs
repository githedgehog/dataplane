// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Context table build (Routes)

use super::NatRequirement;
use config::ConfigError;
use config::external::overlay::ValidatedOverlay;
use config::external::overlay::vpc::ValidatedPeering;
use config::external::overlay::vpcpeering::ValidatedExpose;
use lpm::prefix::Prefix;
use lpm::prefix::with_ports::{L4Protocol, PortRange};
use net::ip::NextHeader;
use net::packet::VpcDiscriminant;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Protocol(NextHeader);

impl Protocol {
    fn from_l4proto(l4_proto: L4Protocol) -> Option<Self> {
        match l4_proto {
            L4Protocol::Tcp => Some(Self(NextHeader::TCP)),
            L4Protocol::Udp => Some(Self(NextHeader::UDP)),
            L4Protocol::Any => None,
        }
    }

    fn from_expose(expose: &ValidatedExpose) -> Option<Self> {
        expose.nat().and_then(|nat| Self::from_l4proto(nat.proto))
    }

    fn from_exposes(
        local_expose: &ValidatedExpose,
        remote_expose: &ValidatedExpose,
    ) -> Option<Protocol> {
        let l4_proto = match (local_expose.nat(), remote_expose.nat()) {
            (Some(local_nat), Some(remote_nat)) => local_nat.proto.intersection(&remote_nat.proto),
            (Some(nat), None) | (None, Some(nat)) => Some(nat.proto),
            (None, None) => None,
        }?;
        Self::from_l4proto(l4_proto)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Route {
    src: Option<Prefix>,
    dst: Option<Prefix>,
    proto: Option<Protocol>,
    src_port: Option<PortRange>,
    dst_port: Option<PortRange>,
    dst_vpcd: VpcDiscriminant,
    src_nat: Option<NatRequirement>,
    dst_nat: Option<NatRequirement>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct RouteTable {
    routes: Vec<Route>,
    default_expose_routes: Vec<Route>,
}

impl RouteTable {
    fn from_peeering(dst_vpcd: VpcDiscriminant, peering: &ValidatedPeering) -> Self {
        let mut table = Self::default();
        for local_expose in peering
            .local()
            .valexp()
            .iter()
            .filter(|expose| expose.can_init_connection())
        {
            for remote_expose in peering
                .remote()
                .valexp()
                .iter()
                .filter(|expose| expose.can_receive_connection())
            {
                match (local_expose.is_default(), remote_expose.is_default()) {
                    (false, false) => table.build_route(dst_vpcd, local_expose, remote_expose),
                    (true, false) => table.build_route_for_local_default(dst_vpcd, remote_expose),
                    (false, true) => table.build_route_for_remote_default(dst_vpcd, local_expose),
                    (true, true) => table.build_route_for_double_default(dst_vpcd),
                }
            }
        }
        table
    }

    fn build_route(
        &mut self,
        dst_vpcd: VpcDiscriminant,
        local_expose: &ValidatedExpose,
        remote_expose: &ValidatedExpose,
    ) {
        for local_prefix in local_expose.ips() {
            for remote_prefix in remote_expose.public_ips() {
                self.routes.push(Route {
                    src: Some(local_prefix.prefix()),
                    dst: Some(remote_prefix.prefix()),
                    proto: Protocol::from_exposes(local_expose, remote_expose),
                    src_port: local_prefix.ports(),
                    dst_port: remote_prefix.ports(),
                    dst_vpcd,
                    src_nat: NatRequirement::from_expose(local_expose),
                    dst_nat: NatRequirement::from_expose(remote_expose),
                });
            }
        }
    }

    fn build_route_for_local_default(
        &mut self,
        dst_vpcd: VpcDiscriminant,
        remote_expose: &ValidatedExpose,
    ) {
        for remote_prefix in remote_expose.public_ips() {
            self.default_expose_routes.push(Route {
                src: None,
                dst: Some(remote_prefix.prefix()),
                proto: Protocol::from_expose(remote_expose),
                src_port: None,
                dst_port: remote_prefix.ports(),
                dst_vpcd,
                src_nat: None,
                dst_nat: NatRequirement::from_expose(remote_expose),
            });
        }
    }

    fn build_route_for_remote_default(
        &mut self,
        dst_vpcd: VpcDiscriminant,
        local_expose: &ValidatedExpose,
    ) {
        for local_prefix in local_expose.ips() {
            self.default_expose_routes.push(Route {
                src: Some(local_prefix.prefix()),
                dst: None,
                proto: Protocol::from_expose(local_expose),
                src_port: local_prefix.ports(),
                dst_port: None,
                dst_vpcd,
                src_nat: NatRequirement::from_expose(local_expose),
                dst_nat: None,
            });
        }
    }

    fn build_route_for_double_default(&mut self, dst_vpcd: VpcDiscriminant) {
        self.default_expose_routes.push(Route {
            src: None,
            dst: None,
            proto: None,
            src_port: None,
            dst_port: None,
            dst_vpcd,
            src_nat: None,
            dst_nat: None,
        });
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct RouteTablesMap {
    tables: HashMap<VpcDiscriminant, RouteTable>,
}

impl RouteTablesMap {
    fn add_peering(
        &mut self,
        local_vpcd: VpcDiscriminant,
        remote_vpcd: VpcDiscriminant,
        peering: &ValidatedPeering,
    ) {
        let table = RouteTable::from_peeering(remote_vpcd, peering);
        self.tables.insert(local_vpcd, table);
    }
}

impl From<&ValidatedOverlay> for RouteTablesMap {
    fn from(overlay: &ValidatedOverlay) -> Self {
        let mut map = Self::default();
        for vpc in overlay.vpc_table().values() {
            let local_vpcd = VpcDiscriminant::VNI(vpc.vni());
            for peering in vpc.peerings() {
                let remote_vpcd = VpcDiscriminant::VNI(overlay.vpc_table().get_remote_vni(peering));
                map.add_peering(local_vpcd, remote_vpcd, peering);
            }
        }
        map
    }
}

// -------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteAction {
    dst_vpcd: VpcDiscriminant,
    src_nat: Option<NatRequirement>,
    dst_nat: Option<NatRequirement>,
}

impl From<&Route> for RouteAction {
    fn from(route: &Route) -> Self {
        Self {
            dst_vpcd: route.dst_vpcd,
            src_nat: route.src_nat,
            dst_nat: route.dst_nat,
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ActionTable {
    actions: Vec<RouteAction>,
}

impl ActionTable {
    pub(crate) fn insert_route(&mut self, route: &Route) -> Result<u32, ConfigError> {
        let index = u32::try_from(self.actions.len()).map_err(|_| ConfigError::TooManyRules)?;
        self.actions.push(route.into());
        Ok(index)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteTuple {
    src: Option<Prefix>,
    dst: Option<Prefix>,
    proto: Option<Protocol>,
    src_port: Option<PortRange>,
    dst_port: Option<PortRange>,
}

impl From<&Route> for RouteTuple {
    fn from(route: &Route) -> Self {
        Self {
            src: route.src,
            dst: route.dst,
            proto: route.proto,
            src_port: route.src_port,
            dst_port: route.dst_port,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct RouteLookupTable {
    opaque_struct: Vec<(RouteTuple, u32)>,
    actions: ActionTable,
}

impl RouteLookupTable {
    fn insert(&mut self, route: &Route) -> Result<(), ConfigError> {
        let action_index = self.actions.insert_route(route)?;
        self.opaque_struct
            .push((RouteTuple::from(route), action_index));
        Ok(())
    }
}

impl TryFrom<&RouteTable> for RouteLookupTable {
    type Error = ConfigError;

    fn try_from(table: &RouteTable) -> Result<Self, Self::Error> {
        let mut lookup_table = Self::default();
        for route in &table.default_expose_routes {
            // TODO: Insert differently (priority)
            lookup_table.insert(route)?;
        }
        for route in &table.routes {
            lookup_table.insert(route)?;
        }
        Ok(lookup_table)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RouteLookupTablesMap {
    tables: HashMap<VpcDiscriminant, RouteLookupTable>,
}

impl TryFrom<&RouteTablesMap> for RouteLookupTablesMap {
    type Error = ConfigError;

    fn try_from(map: &RouteTablesMap) -> Result<Self, Self::Error> {
        let mut lookup_map = Self::default();
        for (vpcd, table) in &map.tables {
            let lookup_table = RouteLookupTable::try_from(table)?;
            lookup_map.tables.insert(*vpcd, lookup_table);
        }
        Ok(lookup_map)
    }
}

impl TryFrom<&ValidatedOverlay> for RouteLookupTablesMap {
    type Error = ConfigError;

    fn try_from(overlay: &ValidatedOverlay) -> Result<Self, Self::Error> {
        let route_tables_map = RouteTablesMap::from(overlay);
        RouteLookupTablesMap::try_from(&route_tables_map)
    }
}
