// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::collections::BTreeMap;
use std::ops::Bound;

use bolero::{Driver, ValueGenerator};

use crate::bolero::expose::LegalValueExposeGenerator;
use crate::bolero::{SubnetMap, VpcSubnetMap};
use crate::gateway_agent_crd::{GatewayAgentPeerings, GatewayAgentPeeringsPeering};

/// Generate legal values for `GatewayAgentPeeringsPeering`
///
/// This does not attempt to be exhaustive for vpc names, just generate relevant legal values.
/// In particular, subnet names are restricted.  Lengths of various lists is also limited to 16
pub struct LegalValuePeeringsPeeringGenerator<'a> {
    subnets: &'a SubnetMap,
}

impl<'a> LegalValuePeeringsPeeringGenerator<'a> {
    #[must_use]
    pub fn new(subnets: &'a SubnetMap) -> Self {
        Self { subnets }
    }
}

impl ValueGenerator for LegalValuePeeringsPeeringGenerator<'_> {
    type Output = GatewayAgentPeeringsPeering;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        let num_expose = d.gen_usize(Bound::Included(&1), Bound::Included(&16))?;
        let expose_gen = LegalValueExposeGenerator::new(self.subnets);
        let expose = (0..num_expose)
            .map(|_| expose_gen.generate(d))
            .collect::<Option<Vec<_>>>()?;

        Some(GatewayAgentPeeringsPeering {
            expose: Some(expose).filter(|e| !e.is_empty()),
        })
    }
}

/// Generate legal values for `GatewayAgentPeerings`
///
/// This does not attempt to be exhaustive for vpc names, just generate relevant legal values.
pub struct LegalValuePeeringsGenerator<'a> {
    vpc_subnets: &'a VpcSubnetMap,
    vpc_names: Vec<&'a String>,
}

impl<'a> LegalValuePeeringsGenerator<'a> {
    /// Create a new `LegalValuePeeringsGenerator`
    ///
    /// # Errors
    ///
    /// Returns an error if there are less than two VPCs in the subnet map.
    pub fn new(vpc_subnets: &'a VpcSubnetMap) -> Result<Self, String> {
        if vpc_subnets.len() < 2 {
            return Err("At least two VPCs are required to generate peerings".to_string());
        }
        let vpc_names = vpc_subnets.keys().collect();
        Ok(Self {
            vpc_subnets,
            vpc_names,
        })
    }
}

fn pick2<'a, D: Driver, T>(d: &mut D, items: &[&'a T]) -> Option<[&'a T; 2]> {
    assert!(items.len() >= 2);

    let index1 = d.gen_usize(Bound::Included(&0), Bound::Excluded(&items.len()))?;
    let mut index2 = d.gen_usize(Bound::Included(&0), Bound::Excluded(&items.len()))?;
    if index1 == index2 {
        index2 = (index2 + 1) % items.len();
    }
    Some([items[index1], items[index2]])
}

impl ValueGenerator for LegalValuePeeringsGenerator<'_> {
    type Output = GatewayAgentPeerings;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        let vpc_names = pick2(d, &self.vpc_names)?;
        let empty_map = SubnetMap::new();
        let peerings_gens = vpc_names.map(|n| {
            LegalValuePeeringsPeeringGenerator::new(self.vpc_subnets.get(n).unwrap_or(&empty_map))
        });
        let peering = (0..=1)
            .map(|i| Some((vpc_names[i].clone(), peerings_gens[i].generate(d)?)))
            .collect::<Option<BTreeMap<_, _>>>()?;

        Some(GatewayAgentPeerings {
            gateway_group: None, // FIXME(mvachhar) Add a proper implementation when used
            peering: Some(peering),
        })
    }
}
