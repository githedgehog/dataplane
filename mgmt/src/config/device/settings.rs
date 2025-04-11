// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Device settings

#![allow(unused)]

use tracing::Level;

#[derive(Clone, Debug, Default)]

pub struct EalConfig {}

#[derive(Clone, Debug)]

pub struct KernelPacketConfig {}

#[derive(Clone, Debug)]
pub enum PacketDriver {
    DPDK(EalConfig),
    Kernel(KernelPacketConfig),
}

#[derive(Clone, Debug)]
pub struct DeviceSettings {
    hostname: Option<String>,
    loglevel: Level,
    driver: PacketDriver,
}

impl Default for DeviceSettings {
    fn default() -> Self {
        Self {
            hostname: None,
            loglevel: Level::ERROR,
            driver: PacketDriver::DPDK(EalConfig::default()),
        }
    }
}
impl DeviceSettings {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set_hostname(mut self, hostname: &str) -> Self {
        self.hostname = Some(hostname.to_owned());
        self
    }
    pub fn set_loglevel(mut self, loglevel: Level) -> Self {
        self.loglevel = loglevel;
        self
    }
    pub fn set_packet_driver(mut self, driver: PacketDriver) -> Self {
        self.driver = driver;
        self
    }
}
