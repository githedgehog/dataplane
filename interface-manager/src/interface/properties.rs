// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::interface::{BridgePropertiesSpec, VrfPropertiesSpec, VtepPropertiesSpec};
use net::interface::InterfaceProperties;
use rekon::AsRequirement;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub enum InterfacePropertiesSpec {
    Bridge(BridgePropertiesSpec),
    Vtep(VtepPropertiesSpec),
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
