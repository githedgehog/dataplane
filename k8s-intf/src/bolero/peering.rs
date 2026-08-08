// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::collections::BTreeMap;
use std::ops::Bound;

use bolero::{Driver, ValueGenerator};

use crate::bolero::acl::{AclGenerator, SideFacts};
use crate::bolero::expose::{ExposeGenerator, Which};
use crate::bolero::support::blocks;
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
    slot_base: u8,
}

impl<'a> LegalValuePeeringsPeeringGenerator<'a> {
    #[must_use]
    pub fn new(
        subnets: &'a SubnetMap,
        flavours: &'a [NatFlavour],
        family: AddressFamily,
        max_exposes: u8,
        vpc: u8,
    ) -> Self {
        Self {
            subnets,
            flavours,
            family,
            max_exposes,
            slot_base: blocks::expose_slot(vpc, max_exposes, 0),
        }
    }
}

impl ValueGenerator for LegalValuePeeringsPeeringGenerator<'_> {
    type Output = GatewayAgentPeeringsPeering;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        let num_expose = d.gen_u8(Bound::Included(&1), Bound::Included(&self.max_exposes))?;
        let mut expose = Vec::with_capacity(usize::from(num_expose));
        for index in 0..num_expose {
            let flavour = self.flavours
                [d.gen_usize(Bound::Included(&0), Bound::Excluded(&self.flavours.len()))?];
            let which = Which::nth(self.slot_base.saturating_add(index), index, num_expose);
            expose
                .push(ExposeGenerator::new(flavour, self.family, which, self.subnets).generate(d)?);
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

fn pick2<D: Driver>(d: &mut D, len: usize) -> Option<[usize; 2]> {
    assert!(len >= 2);

    let index1 = d.gen_usize(Bound::Included(&0), Bound::Excluded(&len))?;
    let mut index2 = d.gen_usize(Bound::Included(&0), Bound::Excluded(&len))?;
    if index1 == index2 {
        index2 = (index2 + 1) % len;
    }
    Some([index1, index2])
}

impl LegalValuePeeringsGenerator<'_> {
    #[must_use]
    pub fn pairs(&self) -> Vec<[usize; 2]> {
        let n = self.vpc_names.len();
        let mut out = Vec::with_capacity(n * n / 2);
        for first in 0..n {
            for second in (first + 1)..n {
                out.push([first, second]);
            }
        }
        out
    }

    pub fn generate_for<D: Driver>(
        &self,
        d: &mut D,
        vpcs: [usize; 2],
    ) -> Option<GatewayAgentPeerings> {
        let vpc_names = [*self.vpc_names.get(vpcs[0])?, *self.vpc_names.get(vpcs[1])?];
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
                    u8::try_from(vpcs[i]).unwrap_or(u8::MAX),
                );
                Some((vpc_names[i].clone(), generator.generate(d)?))
            })
            .collect::<Option<BTreeMap<_, _>>>()?;

        let group = self.groups
            [d.gen_usize(Bound::Included(&0), Bound::Excluded(&self.groups.len()))?]
        .clone();

        let acl = if d.produce::<bool>()? {
            let facts: Vec<SideFacts> = peering
                .iter()
                .map(|(vpc, manifest)| SideFacts::of(vpc, manifest))
                .collect();
            let [left, right] = <[SideFacts; 2]>::try_from(facts).ok()?;
            Some(AclGenerator::new(left, right).generate(d)?)
        } else {
            None
        };

        Some(GatewayAgentPeerings {
            gateway_group: Some(group),
            peering: Some(peering),
            acl,
        })
    }
}

impl ValueGenerator for LegalValuePeeringsGenerator<'_> {
    type Output = GatewayAgentPeerings;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        let pair = pick2(d, self.vpc_names.len())?;
        self.generate_for(d, pair)
    }
}
