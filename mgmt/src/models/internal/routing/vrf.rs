// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: VRFs

use super::bgp::BgpConfig;
use super::ospf::Ospf;
use super::statics::StaticRoute;
use crate::models::external::{ConfigError, overlay::vpc::VpcId};
use crate::models::internal::{ConfigResult, InterfaceConfig, InterfaceConfigTable};
use multi_index_map::MultiIndexMap;
use net::route::RouteTableId;
use net::vxlan::Vni;
use routing::prefix::Prefix;
use std::collections::BTreeSet;

#[derive(Clone, Debug, MultiIndexMap)]
#[multi_index_derive(Debug, Clone)]
pub struct VrfConfig {
    #[multi_index(ordered_unique)]
    pub name: String,
    pub default: bool,
    #[multi_index(ordered_unique)]
    pub tableid: Option<RouteTableId>,
    #[multi_index(ordered_unique)]
    pub vni: Option<Vni>,
    pub subnets: BTreeSet<Prefix>,
    pub static_routes: BTreeSet<StaticRoute>,
    pub bgp: Option<BgpConfig>,
    pub interfaces: InterfaceConfigTable,
    pub ospf: Option<Ospf>,
    #[multi_index(ordered_unique)]
    pub vpc_id: Option<VpcId>,
}

impl Default for VrfConfig {
    fn default() -> Self {
        Self {
            name: "default".to_owned(),
            default: true,
            tableid: None,
            vni: None,
            subnets: BTreeSet::new(),
            static_routes: BTreeSet::new(),
            bgp: None,
            interfaces: InterfaceConfigTable::new(),
            vpc_id: None,
            ospf: None,
        }
    }
}

impl VrfConfig {
    pub fn new(name: &str, vni: Option<Vni>, default: bool) -> Self {
        Self {
            name: name.to_owned(),
            default,
            tableid: None,
            vni,
            ..Default::default()
        }
    }
    pub fn set_vpc_id(mut self, vpc_id: VpcId) -> Self {
        if self.default {
            panic!("Can't set vpc_id for default vrf");
        }
        self.vpc_id = Some(vpc_id);
        self
    }
    pub fn set_table_id(mut self, tableid: RouteTableId) -> Self {
        if self.default {
            panic!("Can't set table id for default vrf");
        }
        self.tableid = Some(tableid);
        self
    }
    pub fn set_bgp(&mut self, mut bgp: BgpConfig) -> &Self {
        self.bgp = Some(bgp);
        self
    }
    pub fn set_ospf(&mut self, mut ospf: Ospf) -> &Self {
        self.ospf = Some(ospf);
        self
    }
    pub fn add_subnet(&mut self, subnet: Prefix) {
        self.subnets.insert(subnet);
    }
    pub fn add_static_route(&mut self, static_route: StaticRoute) {
        self.static_routes.insert(static_route);
    }
    pub fn add_interface_config(&mut self, if_cfg: InterfaceConfig) {
        self.interfaces.add_interface_config(if_cfg);
    }
}

pub type VrfConfigTable = MultiIndexVrfConfigMap;

use tracing::{debug, error};
impl VrfConfigTable {
    pub fn new() -> Self {
        VrfConfigTable::default()
    }
    pub fn add_vrf_config(&mut self, vrf_cfg: VrfConfig) -> ConfigResult {
        let name = vrf_cfg.name.clone();
        debug!(
            "Adding VRF config for vrf: {} vpcid: {:?} tableid: {:?} vni: {:?}",
            vrf_cfg.name, vrf_cfg.vpc_id, vrf_cfg.tableid, vrf_cfg.vni,
        );
        if let Err(e) = self.try_insert(vrf_cfg) {
            let msg = format!("Failed to add vrf {name}: {e}");
            error!("{msg}");
            Err(ConfigError::InternalFailure(
                "Duplicate VRF fields when building internal config. This is a bug.",
            ))
        } else {
            Ok(())
        }
    }
}
