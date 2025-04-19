// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::interface::bridge::BridgePropertiesSpec;
use crate::interface::{VrfPropertiesSpec, VtepPropertiesSpec};
use net::interface::InterfaceProperties;
use rekon::AsRequirement;
use serde::{Deserialize, Serialize};

/// The planned properties of a network interface.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub enum InterfacePropertiesSpec {
    /// The planned properties of a bridge.
    Bridge(BridgePropertiesSpec),
    /// The planned properties of a vtep (vxlan device).
    Vtep(VtepPropertiesSpec),
    /// The planned properties of a vrf
    Vrf(VrfPropertiesSpec),
}

impl AsRequirement<InterfacePropertiesSpec> for InterfaceProperties {
    type Requirement<'a>
        = Option<InterfacePropertiesSpec>
    where
        Self: 'a;

    fn as_requirement<'a>(&self) -> Self::Requirement<'a> {
        Some(match self {
            InterfaceProperties::Bridge(props) => {
                InterfacePropertiesSpec::Bridge(props.as_requirement())
            }
            InterfaceProperties::Vtep(props) => {
                InterfacePropertiesSpec::Vtep(props.as_requirement()?)
            }
            InterfaceProperties::Vrf(props) => InterfacePropertiesSpec::Vrf(props.as_requirement()),
            InterfaceProperties::Other => return None,
        })
    }
}

impl PartialEq<InterfaceProperties> for InterfacePropertiesSpec {
    fn eq(&self, other: &InterfaceProperties) -> bool {
        match other.as_requirement() {
            None => false,
            Some(other) => other == *self,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::InterfacePropertiesSpec;
    use net::interface::InterfaceProperties;
    use rekon::AsRequirement;

    #[test]
    fn as_requirement_obeys_contract() {
        bolero::check!()
            .with_type()
            .for_each(
                |observed: &InterfaceProperties| match observed.as_requirement() {
                    None => {}
                    Some(observed_req) => {
                        assert_eq!(&observed_req, observed);
                        assert_eq!(observed_req, observed.as_requirement().unwrap());
                    }
                },
            );
    }

    #[test]
    fn equality_meaning() {
        bolero::check!().with_type().for_each(
            |(requirement, observation): &(InterfacePropertiesSpec, InterfaceProperties)| {
                if requirement == observation {
                    assert_eq!(requirement, &observation.as_requirement().unwrap());
                } else {
                    match observation.as_requirement() {
                        None => {}
                        Some(observation_req) => {
                            assert_ne!(requirement, &observation_req);
                        }
                    }
                }
            },
        );
    }
}
