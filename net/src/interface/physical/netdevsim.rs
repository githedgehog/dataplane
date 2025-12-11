// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use derive_builder::Builder;
use id::Id;
use multi_index_map::MultiIndexMap;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
#[non_exhaustive]
pub struct NetDevSimDevice {
    pub id: Id<Self, u32>,
}
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
#[non_exhaustive]
pub struct NetDevSimPort {
    pub device: NetDevSimDevice,
    pub id: Id<Self, u32>,
}

#[derive(Builder, Clone, Debug, Eq, Hash, MultiIndexMap, Ord, PartialEq, PartialOrd)]
#[multi_index_derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", multi_index_derive(Serialize, Deserialize))]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub struct NetDevSimProperties {
    #[multi_index(ordered_unique)]
    pub port: NetDevSimPort,
}
