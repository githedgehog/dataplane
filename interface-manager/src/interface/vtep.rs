// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use derive_builder::Builder;
use multi_index_map::MultiIndexMap;
use net::interface::VtepProperties;
use net::vxlan::Vni;
use rekon::AsRequirement;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(
    Builder,
    Clone,
    Debug,
    Deserialize,
    Eq,
    Hash,
    MultiIndexMap,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[multi_index_derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct VtepPropertiesSpec {
    #[multi_index(ordered_unique)]
    pub vni: Vni,
    pub local: Ipv4Addr,
    #[builder(default = 64)]
    pub ttl: u8,
}

impl AsRequirement<VtepPropertiesSpec> for VtepProperties {
    type Requirement<'a>
        = Option<VtepPropertiesSpec>
    where
        Self: 'a;

    fn as_requirement<'a>(&self) -> Option<VtepPropertiesSpec>
    where
        Self: 'a,
    {
        match (self.vni, self.local, self.ttl) {
            (Some(vni), Some(local), Some(ttl)) => Some(VtepPropertiesSpec { vni, local, ttl }),
            _ => None,
        }
    }
}

impl PartialEq<VtepProperties> for VtepPropertiesSpec {
    fn eq(&self, other: &VtepProperties) -> bool {
        match other.as_requirement() {
            None => false,
            Some(props) => self == &props,
        }
    }
}
