// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: VRFs

use std::collections::BTreeSet;

use crate::models::internal::{InterfaceConfig, InterfaceConfigTable};
use net::vxlan::Vni;
use routing::prefix::Prefix;

use super::bgp::BgpConfig;
use super::ospf::Ospf;
use super::statics::StaticRoute;

#[derive(Clone, Debug, Default)]

pub struct VrfConfig {
    pub name: String,
    pub default: bool,
    pub tableid: Option<u32>,
    pub vni: Option<Vni>,
    pub subnets: BTreeSet<Prefix>,
    pub static_routes: BTreeSet<StaticRoute>,
    pub bgp: Option<BgpConfig>,
    pub interfaces: InterfaceConfigTable,
    pub ospf: Option<Ospf>,
}

impl VrfConfig {
    pub fn new(name: &str, vni: Option<Vni>, default: bool) -> Self {
        Self {
            name: name.to_owned(),
            default,
            tableid: None,
            vni,
            subnets: BTreeSet::new(),
            static_routes: BTreeSet::new(),
            bgp: None,
            interfaces: InterfaceConfigTable::new(),
            ospf: None,
        }
    }
    pub fn set_table_id(mut self, tableid: u32) -> Self {
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

#[derive(Clone, Debug, Default)]
pub struct VrfConfigTable(Vec<VrfConfig>);

impl VrfConfigTable {
    pub fn new() -> Self {
        VrfConfigTable(vec![])
    }
    pub fn add_vrf_config(&mut self, vrf_cfg: VrfConfig) {
        self.0.push(vrf_cfg);
    }
    pub fn iter(&self) -> impl Iterator<Item = &VrfConfig> {
        self.0.iter()
    }
}
