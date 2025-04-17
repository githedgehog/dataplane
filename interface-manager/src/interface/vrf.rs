// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use derive_builder::Builder;
use multi_index_map::MultiIndexMap;
use net::interface::VrfProperties;
use net::route::RouteTableId;
use rekon::AsRequirement;
use serde::{Deserialize, Serialize};

/// The planned properties of a VRF interface.
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
pub struct VrfPropertiesSpec {
    /// The route table id of the VRF interface.
    #[multi_index(ordered_unique)]
    pub route_table_id: RouteTableId,
}

impl AsRequirement<VrfPropertiesSpec> for VrfProperties {
    type Requirement<'a>
        = VrfPropertiesSpec
    where
        Self: 'a;

    fn as_requirement<'a>(&self) -> Self::Requirement<'a> {
        VrfPropertiesSpec {
            route_table_id: self.route_table_id,
        }
    }
}

impl PartialEq<VrfProperties> for VrfPropertiesSpec {
    fn eq(&self, other: &VrfProperties) -> bool {
        self == &other.as_requirement()
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::interface::VrfPropertiesSpec;
    use bolero::{Driver, TypeGenerator};
    use net::route::RouteTableId;

    impl TypeGenerator for VrfPropertiesSpec {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(Self {
                route_table_id: RouteTableId::generate(driver)?,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::interface::VrfPropertiesSpec;
    use net::interface::VrfProperties;
    use rekon::AsRequirement;

    #[test]
    fn as_requirement_obeys_contract() {
        bolero::check!()
            .with_type()
            .for_each(|observed: &VrfProperties| {
                let requirement = observed.as_requirement();
                assert_eq!(&requirement, observed);
                assert_eq!(requirement, observed.as_requirement());
            });
    }

    #[test]
    fn equality_meaning() {
        bolero::check!().with_type().for_each(
            |(requirement, observation): &(VrfPropertiesSpec, VrfProperties)| {
                if requirement == observation {
                    assert_eq!(requirement, &observation.as_requirement());
                } else {
                    assert_ne!(requirement, &observation.as_requirement());
                }
            },
        );
    }
}
