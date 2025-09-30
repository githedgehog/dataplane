// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Device settings

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
    pub driver: PacketDriver,
}

impl DeviceSettings {
    #[must_use]
    pub fn new(hostname: &str) -> Self {
        Self {
            hostname: hostname.to_owned(),
            driver: PacketDriver::DPDK(DpdkPortConfig::default()),
        }
    }
    #[must_use]
    pub fn set_packet_driver(mut self, driver: PacketDriver) -> Self {
        self.driver = driver;
        self
    }
}
