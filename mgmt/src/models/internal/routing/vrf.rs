// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: VRFs

use super::bgp::BgpConfig;
use super::ospf::Ospf;
use super::statics::StaticRoute;
use crate::models::internal::{InterfaceConfig, MultiIndexInterfaceConfigMap};
use multi_index_map::{MultiIndexMap, UniquenessError};
use net::interface::InterfaceName;
use net::route::RouteTableId;
use net::vxlan::Vni;
use routing::prefix::Prefix;
use std::collections::BTreeSet;

#[derive(Clone, Debug, MultiIndexMap)]
#[multi_index_derive(Debug, Clone)]
pub struct VrfConfig {
    #[multi_index(ordered_unique)]
    pub name: InterfaceName,
    pub default: bool,
    #[multi_index(ordered_unique)]
    pub tableid: Option<RouteTableId>,
    #[multi_index(ordered_unique)]
    pub vni: Option<Vni>,
    pub subnets: BTreeSet<Prefix>,
    pub static_routes: BTreeSet<StaticRoute>,
    pub bgp: Option<BgpConfig>,
    pub interfaces: MultiIndexInterfaceConfigMap,
    pub ospf: Option<Ospf>,
}

impl Default for VrfConfig {
    fn default() -> Self {
        Self {
            name: "default".try_into().unwrap_or_else(|_| unreachable!()),
            default: true,
            tableid: None,
            vni: None,
            subnets: BTreeSet::new(),
            static_routes: BTreeSet::new(),
            bgp: None,
            interfaces: MultiIndexInterfaceConfigMap::new(),
            ospf: None,
        }
    }
}

impl VrfConfig {
    pub fn new(name: InterfaceName, vni: Option<Vni>, default: bool) -> Self {
        Self {
            name,
            default,
            tableid: None,
            vni,
            ..Default::default()
        }
    }
    pub fn set_table_id(mut self, tableid: RouteTableId) -> Self {
        if self.default {
            panic!("Can't set table id for default vrf");
        }
        self.tableid = Some(tableid);
        self
    }
    pub fn set_bgp(&mut self, bgp: BgpConfig) -> &Self {
        self.bgp = Some(bgp);
        self
    }
    pub fn set_ospf(&mut self, ospf: Ospf) -> &Self {
        self.ospf = Some(ospf);
        self
    }
    pub fn add_subnet(&mut self, subnet: Prefix) {
        self.subnets.insert(subnet);
    }
    pub fn add_static_route(&mut self, static_route: StaticRoute) {
        self.static_routes.insert(static_route);
    }
    pub fn add_interface_config(
        &mut self,
        if_cfg: InterfaceConfig,
    ) -> Result<&InterfaceConfig, UniquenessError<InterfaceConfig>> {
        self.interfaces.try_insert(if_cfg)
    }
}

impl MultiIndexVrfConfigMap {
    pub fn new() -> Self {
        MultiIndexVrfConfigMap::default()
    }
    pub fn add_vrf_config(&mut self, vrf_cfg: VrfConfig) {
        // TODO: must not panic here
        self.try_insert(vrf_cfg).expect("Can't insert vrf config");
    }
}
