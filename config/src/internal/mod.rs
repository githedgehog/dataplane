// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane internal configuration model and builders.
//! The internal configuration model is the source of truth wrt to the gateway configuration.
//! Any configuration received externally (e.g. via gRPC) causes an internal configuration to be built and applied.
//! This module should contain all the tools to build a configuration in memory.

#![allow(unused)]

pub mod device;
pub mod interfaces;
pub mod routing;

use derive_builder::Builder;

use super::ConfigResult;
use crate::external::GenId;
use crate::internal::device::DeviceConfig;
use crate::internal::interfaces::interface::{InterfaceConfig, InterfaceConfigTable};
use crate::internal::routing::evpn::VtepConfig;
use crate::internal::routing::frr::Frr;
use crate::internal::routing::prefixlist::{PrefixList, PrefixListTable};
use crate::internal::routing::routemap::{RouteMap, RouteMapTable};
use crate::internal::routing::vrf::{VrfConfig, VrfConfigTable};

#[derive(Clone, Debug)]
/* Main internal GW configuration */
pub struct InternalConfig {
    pub dev_cfg: DeviceConfig,
    pub frr: Frr,
    pub vtep: Option<VtepConfig>, // As a network interface
    pub vrfs: VrfConfigTable,
    pub plist_table: PrefixListTable,
    pub rmap_table: RouteMapTable,
}

impl InternalConfig {
    #[must_use]
    pub fn new(dev_cfg: DeviceConfig) -> Self {
        // Frr profile is not configurable for the time being
        let frr = Frr::new(
            routing::frr::FrrProfile::Datacenter,
            &dev_cfg.settings.hostname,
        );
        Self {
            dev_cfg,
            frr,
            vtep: None,
            vrfs: VrfConfigTable::new(),
            plist_table: PrefixListTable::new(),
            rmap_table: RouteMapTable::new(),
        }
    }
    pub fn set_vtep(&mut self, vtep: Option<VtepConfig>) {
        self.vtep = vtep;
    }
    #[must_use]
    pub fn get_vtep(&self) -> &Option<VtepConfig> {
        &self.vtep
    }
    pub fn add_vrf_config(&mut self, vrf_cfg: VrfConfig) -> ConfigResult {
        self.vrfs.add_vrf_config(vrf_cfg)
    }
    pub fn add_prefix_list(&mut self, plist: PrefixList) {
        self.plist_table.add_prefix_list(plist);
    }
    pub fn add_prefix_lists(&mut self, plists: impl IntoIterator<Item = PrefixList>) {
        self.plist_table.add_prefix_lists(plists);
    }
    pub fn add_route_map(&mut self, rmap: RouteMap) {
        self.rmap_table.add_route_map(rmap);
    }
}
