// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::collections::BTreeMap;
use std::ops::Bound;

use bolero::{Driver, ValueGenerator};

use crate::bolero::acl::LegalValueAclGenerator;
use crate::bolero::expose::LegalValueExposeGenerator;
use crate::bolero::support::{PrefixPool, choose};
use crate::bolero::{SubnetMap, VpcSubnetMap};
use crate::gateway_agent_crd::{GatewayAgentPeerings, GatewayAgentPeeringsPeering};

/// Generate legal values for `GatewayAgentPeeringsPeering`
///
/// This does not attempt to be exhaustive for vpc names, just generate relevant legal values.
/// In particular, subnet names are restricted.  Lengths of various lists is also limited to 16
///
/// By default this never generates a "default" expose, because legality of one is not decidable
/// from a single side of a peering: `VpcManifest::validate` allows at most one per manifest, and
/// `Peering::validate` forbids a default expose on *both* sides of the same peering.  Use
/// [`LegalValuePeeringsPeeringGenerator::allow_default_expose`] from a caller that owns both
/// sides and can uphold that.
pub struct LegalValuePeeringsPeeringGenerator<'a> {
    subnets: &'a SubnetMap,
    allow_default: bool,
    allow_masquerade: bool,
    pool: Option<&'a PrefixPool>,
}

impl<'a> LegalValuePeeringsPeeringGenerator<'a> {
    #[must_use]
    pub fn new(subnets: &'a SubnetMap) -> Self {
        Self {
            subnets,
            allow_default: false,
            allow_masquerade: false,
            pool: None,
        }
    }

    /// Permit this side to carry (at most one) default expose.
    ///
    /// The caller must not enable this for both sides of the same peering.
    #[must_use]
    pub fn allow_default_expose(mut self) -> Self {
        self.allow_default = true;
        self
    }

    /// Draw expose addresses from `pool`; see
    /// [`crate::bolero::expose::LegalValueExposeGenerator::from_pool`].
    #[must_use]
    pub fn from_pool(mut self, pool: &'a PrefixPool) -> Self {
        self.pool = Some(pool);
        self
    }

    /// Permit this side to masquerade.
    ///
    /// The caller must not enable this for both sides of the same peering; see
    /// [`crate::bolero::expose::LegalValueExposeGenerator::allow_masquerade`].
    #[must_use]
    pub fn allow_masquerade(mut self) -> Self {
        self.allow_masquerade = true;
        self
    }
}

impl ValueGenerator for LegalValuePeeringsPeeringGenerator<'_> {
    type Output = GatewayAgentPeeringsPeering;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        let num_expose = d.gen_usize(Bound::Included(&1), Bound::Included(&16))?;
        let expose_gen = LegalValueExposeGenerator::new(self.subnets);
        let expose_gen = match self.pool {
            Some(pool) => expose_gen.from_pool(pool),
            None => expose_gen,
        };
        let expose_gen = if self.allow_masquerade {
            expose_gen.allow_masquerade()
        } else {
            expose_gen
        };
        let mut expose = (0..num_expose)
            .map(|_| expose_gen.generate(d))
            .collect::<Option<Vec<_>>>()?;

        if self.allow_default && d.gen_bool(None)? {
            expose.push(crate::bolero::expose::default_expose());
        }

        Some(GatewayAgentPeeringsPeering {
            expose: Some(expose).filter(|e| !e.is_empty()),
        })
    }
}

/// Generate legal values for `GatewayAgentPeerings`
///
/// This does not attempt to be exhaustive for vpc names, just generate relevant legal values.
///
/// `gwgroup_names` must be the names present in the spec's `groups` table:
/// `ExternalConfig::validate` rejects a peering whose `gatewayGroup` is not in that table, so a
/// peering generated against an unrelated name is convertible but not *valid*.
pub struct LegalValuePeeringsGenerator<'a> {
    vpc_subnets: &'a VpcSubnetMap,
    vpc_names: Vec<&'a String>,
    gwgroup_names: &'a [String],
    pool: Option<&'a PrefixPool>,
}

impl<'a> LegalValuePeeringsGenerator<'a> {
    /// Create a new `LegalValuePeeringsGenerator`
    ///
    /// # Errors
    ///
    /// Returns an error if there are less than two VPCs in the subnet map, or if no gateway group
    /// names were supplied for the peering to reference.
    pub fn new(vpc_subnets: &'a VpcSubnetMap, gwgroup_names: &'a [String]) -> Result<Self, String> {
        if vpc_subnets.len() < 2 {
            return Err("At least two VPCs are required to generate peerings".to_string());
        }
        if gwgroup_names.is_empty() {
            return Err("At least one gateway group is required to generate peerings".to_string());
        }
        let vpc_names = vpc_subnets.keys().collect();
        Ok(Self {
            vpc_subnets,
            vpc_names,
            gwgroup_names,
            pool: None,
        })
    }

    /// Restrict generation to peerings that survive `ExternalConfig::validate`, drawing expose
    /// addresses from `pool`.
    ///
    /// Without this, a generated peering is legal with respect to conversion only: validation
    /// couples exposes to each other and ACL rules to the exposes.  See
    /// [`crate::bolero::expose::LegalValueExposeGenerator::from_pool`] and
    /// [`crate::bolero::acl::LegalValueAclGenerator::independent_of_exposes`] for what each
    /// restriction costs in coverage.
    #[must_use]
    pub fn validation_legal(mut self, pool: &'a PrefixPool) -> Self {
        self.pool = Some(pool);
        self
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
    /// Generate a peering between two named VPCs, optionally letting one side carry a default
    /// expose.
    ///
    /// Prefer this over [`ValueGenerator::generate`] when generating several peerings for one
    /// spec: two validation rules span the whole overlay and only the caller building the whole set
    /// can uphold them.
    ///
    /// - `Vpc::check_peering_count` rejects an overlay in which the same pair of VPCs peers more
    ///   than once, so the caller must not repeat a pair.
    /// - `VpcRouteTable::validate` rejects a VPC with more than one default destination, and a
    ///   default expose on one side of a peering *is* a default destination for the other side.  So
    ///   `default_side` must be `None` unless the opposite VPC has no default from any peering.
    pub fn generate_for_pair<D: Driver>(
        &self,
        d: &mut D,
        vpc_a: &str,
        vpc_b: &str,
        default_side: Option<usize>,
    ) -> Option<GatewayAgentPeerings> {
        self.generate_inner(d, [vpc_a, vpc_b], default_side)
    }

    fn generate_inner<D: Driver>(
        &self,
        d: &mut D,
        vpc_names: [&str; 2],
        default_side: Option<usize>,
    ) -> Option<GatewayAgentPeerings> {
        let empty_map = SubnetMap::new();

        let side_gen = |name: &str| {
            let side = LegalValuePeeringsPeeringGenerator::new(
                self.vpc_subnets.get(name).unwrap_or(&empty_map),
            );
            match self.pool {
                Some(pool) => side.from_pool(pool),
                None => side,
            }
        };
        let first = side_gen(vpc_names[0]);
        let second = side_gen(vpc_names[1]);
        let (first, second) = match default_side {
            Some(0) => (first.allow_default_expose(), second),
            Some(1) => (first, second.allow_default_expose()),
            _ => (first, second),
        };

        // `Peering::check_nat_modes` forbids masquerade on both sides at once, so at most one side
        // may masquerade.  `2` means neither.  Independent of `default_side`: a manifest may hold
        // both a default expose and a masquerading one.
        let masquerade_side = d.gen_usize(Bound::Included(&0), Bound::Included(&2))?;
        let (first, second) = match masquerade_side {
            0 => (first.allow_masquerade(), second),
            1 => (first, second.allow_masquerade()),
            _ => (first, second),
        };

        let peering = BTreeMap::from([
            (vpc_names[0].to_string(), first.generate(d)?),
            (vpc_names[1].to_string(), second.generate(d)?),
        ]);

        // `VpcPeering::try_from` names the sides by iterating the `peering` map, so `left` is the
        // lexicographically smaller of the two VPC names.  The ACL's `from`/`to` must agree with
        // that, so derive the names from the map rather than from `vpc_names`.
        let mut side_names = peering.keys();
        let left_name = side_names.next()?;
        let right_name = side_names.next()?;

        let acl = if d.gen_bool(None)? {
            let acl_gen = LegalValueAclGenerator::new(self.vpc_subnets, left_name, right_name);
            let acl_gen = if self.pool.is_some() {
                acl_gen.independent_of_exposes()
            } else {
                acl_gen
            };
            Some(acl_gen.generate(d)?)
        } else {
            None
        };

        Some(GatewayAgentPeerings {
            gateway_group: Some(choose(d, self.gwgroup_names)?),
            peering: Some(peering),
            acl,
        })
    }
}

/// Generates a peering between a randomly chosen pair of the known VPCs.
///
/// Safe for a spec holding a single peering; use
/// [`LegalValuePeeringsGenerator::generate_for_pair`] when generating several, so that no pair of
/// VPCs peers twice and no VPC collects two default destinations.
impl ValueGenerator for LegalValuePeeringsGenerator<'_> {
    type Output = GatewayAgentPeerings;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        let vpc_names = pick2(d, &self.vpc_names)?;
        // With only one peering in play, either side may carry a default.
        let default_side = match d.gen_usize(Bound::Included(&0), Bound::Included(&2))? {
            side @ (0 | 1) => Some(side),
            _ => None,
        };
        self.generate_inner(
            d,
            [vpc_names[0].as_str(), vpc_names[1].as_str()],
            default_side,
        )
    }
}
