// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Deserialize, Serialize)]
pub enum Bus {
    Pci,
    #[cfg(feature = "netdevsim")]
    NetDevSim,
}
