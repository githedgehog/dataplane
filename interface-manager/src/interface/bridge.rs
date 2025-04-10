// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use derive_builder::Builder;
use multi_index_map::MultiIndexMap;
use net::eth::ethtype::EthType;
use net::interface::BridgeProperties;
use rekon::AsRequirement;
use serde::{Deserialize, Serialize};

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
pub struct BridgePropertiesSpec {
    #[builder(default = false)]
    pub vlan_filtering: bool,
    #[builder(default = EthType::VLAN)]
    pub vlan_protocol: EthType,
}

impl AsRequirement<BridgePropertiesSpec> for BridgeProperties {
    type Requirement<'a>
        = BridgePropertiesSpec
    where
        Self: 'a;

    fn as_requirement<'a>(&self) -> BridgePropertiesSpec
    where
        Self: 'a,
    {
        BridgePropertiesSpec {
            vlan_filtering: self.vlan_filtering,
            vlan_protocol: self.vlan_protocol,
        }
    }
}

impl PartialEq<BridgeProperties> for BridgePropertiesSpec {
    fn eq(&self, other: &BridgeProperties) -> bool {
        self == &other.as_requirement()
    }
}
