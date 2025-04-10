// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::eth::ethtype::EthType;
use derive_builder::Builder;
use multi_index_map::MultiIndexMap;
use serde::{Deserialize, Serialize};

#[allow(clippy::unsafe_derive_deserialize)] // trusted generation
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
pub struct BridgeProperties {
    #[builder(default = false)]
    pub vlan_filtering: bool,
    #[builder(default = EthType::VLAN)]
    pub vlan_protocol: EthType,
}
