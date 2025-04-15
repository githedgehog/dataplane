// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::eth::ethtype::EthType;
use derive_builder::Builder;
use multi_index_map::MultiIndexMap;
use serde::{Deserialize, Serialize};

#[cfg(any(test, feature = "arbitrary"))]
#[allow(unused_imports)] // re-export
pub use contracts::*;

/// Bridge-specific properties
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
    /// `true` if the bridge is vlan aware
    #[builder(default = false)]
    pub vlan_filtering: bool,
    /// The ethertype of the vlan headers for this bridge
    #[builder(default = EthType::VLAN)]
    pub vlan_protocol: EthType,
}

#[cfg(any(test, feature = "arbitrary"))]
mod contracts {
    use crate::eth::ethtype::EthType;
    use crate::interface::BridgeProperties;
    use bolero::{Driver, TypeGenerator, ValueGenerator};

    pub struct ValidBridgeProperties;

    impl ValueGenerator for ValidBridgeProperties {
        type Output = BridgeProperties;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let vlan_protocol = if driver.produce::<bool>()? {
                EthType::VLAN
            } else {
                EthType::VLAN_QINQ
            };
            Some(BridgeProperties {
                vlan_filtering: driver.produce()?,
                vlan_protocol,
            })
        }
    }

    impl TypeGenerator for BridgeProperties {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(Self {
                vlan_filtering: driver.produce()?,
                vlan_protocol: driver.produce()?,
            })
        }
    }
}
