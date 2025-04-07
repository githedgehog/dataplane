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
pub mod service;

use crate::config::device::DeviceConfig;
use crate::config::interfaces::interface::{InterfaceConfig, InterfaceConfigTable};
use crate::config::routing::evpn::VtepConfig;
use crate::config::routing::frr::Frr;
use crate::config::routing::vrf::{VrfConfig, VrfConfigTable};

#[derive(Default)]
/* Main internal GW configuration */
pub struct GwConfig {
    device_config: Option<DeviceConfig>,
    frr: Option<Frr>,
    vtep: Option<VtepConfig>,
    vrfs: VrfConfigTable,
    interfaces: InterfaceConfigTable,
}

impl GwConfig {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set_device_config(&mut self, device_config: &DeviceConfig) {
        self.device_config = Some(device_config.clone());
    }
    pub fn set_frr(&mut self, frr: Frr) {
        self.frr = Some(frr);
    }
    pub fn set_vtep(&mut self, vtep: VtepConfig) {
        self.vtep = Some(vtep);
    }
    pub fn add_vrf_config(&mut self, vrf_cfg: VrfConfig) {
        self.vrfs.add_vrf_config(vrf_cfg);
    }
    pub fn add_interface_config(&mut self, if_cfg: InterfaceConfig) {
        self.interfaces.add_interface_config(if_cfg);
    }
}
