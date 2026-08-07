// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::collections::BTreeMap;
use std::ops::Bound;

use bolero::{Driver, ValueGenerator};

use crate::bolero::expose::ExposeGenerator;
use crate::bolero::{AddressFamily, NatFlavour, SubnetMap, VpcSubnetMap};
use crate::gateway_agent_crd::{GatewayAgentPeerings, GatewayAgentPeeringsPeering};

/// Generate legal values for `GatewayAgentPeeringsPeering`
///
/// This does not attempt to be exhaustive for vpc names, just generate relevant legal values.
/// In particular, subnet names are restricted.  Lengths of various lists is also limited to 16
pub struct LegalValuePeeringsPeeringGenerator<'a> {
    subnets: &'a SubnetMap,
    flavours: &'a [NatFlavour],
    family: AddressFamily,
    max_exposes: u8,
}

impl<'a> LegalValuePeeringsPeeringGenerator<'a> {
    #[must_use]
    pub fn new(
        subnets: &'a SubnetMap,
        flavours: &'a [NatFlavour],
        family: AddressFamily,
        max_exposes: u8,
    ) -> Self {
        Self {
            subnets,
            flavours,
            family,
            max_exposes,
        }
    }
}

impl ValueGenerator for LegalValuePeeringsPeeringGenerator<'_> {
    type Output = GatewayAgentPeeringsPeering;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        let num_expose = d.gen_u8(Bound::Included(&1), Bound::Included(&self.max_exposes))?;
        let mut expose = Vec::with_capacity(usize::from(num_expose));
        for _ in 0..num_expose {
            let flavour = self.flavours
                [d.gen_usize(Bound::Included(&0), Bound::Excluded(&self.flavours.len()))?];
            expose.push(ExposeGenerator::new(flavour, self.family, self.subnets).generate(d)?);
        }

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
    flavours: &'a [NatFlavour],
    families: &'a [AddressFamily],
    max_exposes: u8,
    groups: &'a [String],
}

impl<'a> LegalValuePeeringsGenerator<'a> {
    /// Create a new `LegalValuePeeringsGenerator`
    ///
    /// # Errors
    ///
    /// Returns an error if there are less than two VPCs in the subnet map.
    pub fn new(
        vpc_subnets: &'a VpcSubnetMap,
        flavours: &'a [NatFlavour],
        families: &'a [AddressFamily],
        max_exposes: u8,
        groups: &'a [String],
    ) -> Result<Self, String> {
        if vpc_subnets.len() < 2 {
            return Err("At least two VPCs are required to generate peerings".to_string());
        }
        if groups.is_empty() {
            return Err("At least one gateway group is required".to_string());
        }
        let vpc_names = vpc_subnets.keys().collect();
        Ok(Self {
            vpc_subnets,
            vpc_names,
            flavours,
            families,
            max_exposes,
            groups,
        })
    }

    fn stateless_of(&self) -> Vec<NatFlavour> {
        let stateless: Vec<NatFlavour> = self
            .flavours
            .iter()
            .copied()
            .filter(|flavour| !flavour.is_stateful())
            .collect();
        if stateless.is_empty() {
            vec![NatFlavour::None]
        } else {
            stateless
        }
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

impl LegalValuePeeringsGenerator<'_> {
    #[must_use]
    pub fn pairs(&self) -> Vec<[&String; 2]> {
        let names = &self.vpc_names;
        let mut out = Vec::with_capacity(names.len() * names.len() / 2);
        for (i, first) in names.iter().enumerate() {
            for second in names.iter().skip(i + 1) {
                out.push([*first, *second]);
            }
        }
        out
    }

    pub fn generate_for<D: Driver>(
        &self,
        d: &mut D,
        vpc_names: [&String; 2],
    ) -> Option<GatewayAgentPeerings> {
        let family = self.families
            [d.gen_usize(Bound::Included(&0), Bound::Excluded(&self.families.len()))?];

        let stateful_side = d.gen_usize(Bound::Included(&0), Bound::Included(&1))?;
        let stateless = self.stateless_of();

        let empty_map = SubnetMap::new();
        let peering = (0..=1)
            .map(|i| {
                let flavours: &[NatFlavour] = if i == stateful_side {
                    self.flavours
                } else {
                    &stateless
                };
                let generator = LegalValuePeeringsPeeringGenerator::new(
                    self.vpc_subnets.get(vpc_names[i]).unwrap_or(&empty_map),
                    flavours,
                    family,
                    self.max_exposes,
                );
                Some((vpc_names[i].clone(), generator.generate(d)?))
            })
            .collect::<Option<BTreeMap<_, _>>>()?;

        let group = self.groups
            [d.gen_usize(Bound::Included(&0), Bound::Excluded(&self.groups.len()))?]
        .clone();

        Some(GatewayAgentPeerings {
            gateway_group: Some(group),
            peering: Some(peering),
            acl: None, // FIXME: Add a proper implementation when used
        })
    }
}

impl ValueGenerator for LegalValuePeeringsGenerator<'_> {
    type Output = GatewayAgentPeerings;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        let vpc_names = pick2(d, &self.vpc_names)?;
        self.generate_for(d, vpc_names)
    }
}
