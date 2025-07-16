// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Device settings

#![allow(unused)]

use tracing::Level;

#[derive(Clone, Debug, Default)]

pub struct DpdkPortConfig {}

#[derive(Clone, Debug)]

pub struct KernelPacketConfig {}

#[derive(Clone, Debug)]
pub enum PacketDriver {
    DPDK(DpdkPortConfig),
    Kernel(KernelPacketConfig),
}

#[derive(Clone, Debug)]
pub struct DeviceSettings {
    pub hostname: String,
    pub loglevel: Level,
    pub driver: PacketDriver,
}

impl DeviceSettings {
    pub fn new(hostname: &str) -> Self {
        Self {
            hostname: hostname.to_owned(),
            loglevel: Level::ERROR,
            driver: PacketDriver::DPDK(DpdkPortConfig::default()),
        }
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
