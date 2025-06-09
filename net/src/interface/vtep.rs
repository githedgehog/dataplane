// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::ipv4::UnicastIpv4Addr;
use crate::vxlan::Vni;
use derive_builder::Builder;
use multi_index_map::MultiIndexMap;
use serde::{Deserialize, Serialize};

/// Vtep (vxlan device) specific properties
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
pub struct VtepProperties {
    /// The VNI associated with this vtep.
    /// This value can be `None` in the event of an "external" vtep.
    #[multi_index(hashed_unique)]
    pub vni: Option<Vni>,
    /// The local ip address to be associated with this vxlan device.
    /// I.e., the source ip address to be used by encapsulating packets.
    /// This value can be `None` if the vtep did not have a local value specified when it was
    /// created.
    #[builder(default)]
    pub local: Option<UnicastIpv4Addr>,
    /// The TTL of the vtep.
    /// This value can be `None` if the use did not specify the value when the VTEP was created or,
    /// for whatever reason, the value is not available in the netlink message describing the vtep.
    #[builder(default = Some(0))]
    pub ttl: Option<u8>,
}

#[cfg(any(test, feature = "bolero"))]
mod contracts {
    use crate::interface::VtepProperties;
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for VtepProperties {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(Self {
                ttl: driver.produce()?,
                local: driver.produce()?,
                vni: driver.produce()?,
            })
        }
    }
}
