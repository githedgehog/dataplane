// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
#![cfg(feature = "netdevsim")]

//! [Network Device Simulator (netdevsim)][netdevsim] is a function of Linux mostly useful for testing
//! and development purposes.
//! It provides a simulated network device that can be used to test some low level network operations,
//! especially those relating to switchdev and hardware offloads.
//!
//! [netdevsim]: https://www.kernel.org/doc/html/latest/networking/devlink/netdevsim.html

use derive_builder::Builder;
use id::Id;
use multi_index_map::MultiIndexMap;
use serde::{Deserialize, Serialize};

/// Represents a simulated network device.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
#[non_exhaustive]
pub struct NetDevSimDevice {
    /// Network namespace unique identifier for the device.
    pub id: Id<Self, u32>,
}

/// Represents a simulated network port (a component of a simulated network device).
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
#[non_exhaustive]
pub struct NetDevSimPort {
    /// The parent device of the port.
    pub device: NetDevSimDevice,
    /// Identifier of the port within the device.
    pub id: Id<Self, u32>,
}

/// The properties of a simulated network device interface.
#[derive(
    Builder,
    Clone,
    Debug,
    Eq,
    Hash,
    MultiIndexMap,
    Ord,
    PartialEq,
    PartialOrd,
    Deserialize,
    Serialize,
)]
#[multi_index_derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub struct NetDevSimProperties {
    #[multi_index(ordered_unique)]
    pub port: NetDevSimPort,
}
