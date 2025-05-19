// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::{Manager, manager_of};
use derive_builder::Builder;
use multi_index_map::MultiIndexMap;
use net::interface::{Interface, InterfaceProperties, VtepProperties};
use net::ipv4::UnicastIpv4Addr;
use net::vxlan::Vni;
use rekon::{AsRequirement, Remove, Update};
use serde::{Deserialize, Serialize};

/// The "planned" properties of a VTEP / vxlan device.
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
    /// The vni to be used for this device.
    #[multi_index(ordered_unique)]
    pub vni: Vni,
    /// The local IPv4 address to be used for this device.
    pub local: UnicastIpv4Addr,
    /// The ttl to be used for packets encapsulated by this device.
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

impl Update for Manager<VtepProperties> {
    type Requirement<'a>
        = &'a VtepPropertiesSpec
    where
        Self: 'a;
    type Observation<'a>
        = &'a Interface
    where
        Self: 'a;
    type Outcome<'a>
        = Result<(), rtnetlink::Error>
    where
        Self: 'a;

    /// Linux does not really support update for most vtep properties.  All you can do is destroy
    /// the interface and the wait for the reconcile loop to address re-create
    async fn update<'a>(
        &self,
        requirement: Self::Requirement<'a>,
        observation: Self::Observation<'a>,
    ) -> Result<(), rtnetlink::Error>
    where
        Self: 'a,
    {
        #[allow(clippy::collapsible_if)]
        if let InterfaceProperties::Vtep(props) = &observation.properties {
            if requirement == props {
                return Ok(());
            }
        }
        manager_of::<Interface>(self).remove(observation).await
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::interface::VtepPropertiesSpec;
    use bolero::{Driver, TypeGenerator};
    use net::ipv4::UnicastIpv4Addr;
    use std::net::Ipv4Addr;

    impl TypeGenerator for VtepPropertiesSpec {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let local = {
                let local = driver.produce::<UnicastIpv4Addr>()?;
                if local.inner().is_unspecified() {
                    #[allow(clippy::unwrap_used)] // err case impossible
                    UnicastIpv4Addr::new(Ipv4Addr::new(0, 0, 0, 1)).unwrap()
                } else {
                    local
                }
            };
            Some(Self {
                vni: driver.produce()?,
                local,
                ttl: driver.produce()?,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::interface::VtepPropertiesSpec;
    use net::interface::VtepProperties;
    use rekon::AsRequirement;

    #[test]
    fn as_requirement_obeys_contract() {
        bolero::check!()
            .with_type()
            .for_each(|observed: &VtepProperties| {
                let requirement = observed.as_requirement();
                match requirement {
                    None => {
                        assert!(
                            observed.local.is_none()
                                || observed.vni.is_none()
                                || observed.ttl.is_none()
                        );
                    }
                    Some(requirement) => {
                        assert_eq!(&requirement, observed);
                        assert_eq!(requirement, observed.as_requirement().unwrap());
                    }
                }
            });
    }

    #[test]
    fn equality_meaning() {
        bolero::check!().with_type().for_each(
            |(required, observed): &(VtepPropertiesSpec, VtepProperties)| {
                if required == observed {
                    assert_eq!(required, &observed.as_requirement().unwrap());
                } else {
                    match observed.as_requirement() {
                        None => {}
                        Some(observed_req) => {
                            assert_ne!(&observed_req, required);
                        }
                    }
                }
            },
        );
    }
}
