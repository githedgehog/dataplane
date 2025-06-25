// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use derive_builder::Builder;
use multi_index_map::MultiIndexMap;
use net::eth::ethtype::EthType;
use net::interface::BridgeProperties;
use rekon::AsRequirement;
use serde::{Deserialize, Serialize};

/// The "planned" properties for a bridge.
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
    /// Set to true to make the bridge vlan aware.
    #[builder(default = false)]
    pub vlan_filtering: bool,
    /// Set to [`EthType::VLAN`] (the default) to make an 802.1Q bridge.
    /// Set to [`EthType::VLAN_QINQ`] to make an 802.1AD bridge.
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

#[cfg(any(test, feature = "bolero"))]
mod contracts {
    use crate::interface::bridge::BridgePropertiesSpec;
    use bolero::{Driver, TypeGenerator};
    use net::eth::ethtype::EthType;

    impl TypeGenerator for BridgePropertiesSpec {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            if driver.produce::<bool>()? {
                Some(Self {
                    vlan_protocol: EthType::VLAN,
                    vlan_filtering: driver.produce()?,
                })
            } else {
                Some(Self {
                    vlan_protocol: EthType::VLAN_QINQ,
                    vlan_filtering: driver.produce()?,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::interface::bridge::BridgePropertiesSpec;
    use net::interface::BridgeProperties;
    use rekon::AsRequirement;

    #[test]
    fn as_requirement_obeys_contract() {
        bolero::check!()
            .with_type()
            .for_each(|props: &BridgeProperties| {
                let requirement = props.as_requirement();
                assert_eq!(&requirement, props);
                assert_eq!(requirement, props.as_requirement());
            });
    }

    #[test]
    fn equality_meaning() {
        bolero::check!().with_type().for_each(
            |(requirement, observation): &(BridgePropertiesSpec, BridgeProperties)| {
                if requirement == observation {
                    assert_eq!(requirement, &observation.as_requirement());
                } else {
                    assert_ne!(requirement, &observation.as_requirement());
                }
            },
        );
    }
}
