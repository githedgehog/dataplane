// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use serde::{Deserialize, Serialize};

/// A communication channel between the host and the device.
///
/// This enum represents the different types of buses that can be used to communicate between the host and the device.
///
/// In normal dataplane operation this only includes the PCI bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Deserialize, Serialize)]
pub enum Bus {
    /// PCI bus
    Pci,
    #[cfg(feature = "netdevsim")]
    /// NetDevSim bus
    NetDevSim,
}
