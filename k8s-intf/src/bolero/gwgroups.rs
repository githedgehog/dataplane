// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use bolero::{Driver, TypeGenerator, ValueGenerator};
use net::ipv4::UnicastIpv4Addr;
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::ops::Bound;

use crate::bolero::LegalValue;
use crate::bolero::support::{K8sName, K8sNameGenerator};
use crate::gateway_agent_crd::{
    GatewayAgentGatewayGroups, GatewayAgentGroups, GatewayAgentGroupsMembers,
};

/// Largest number of members a generated group may have.
///
/// A group's members are ranked by position after sorting, and `ExternalConfig::validate` demands
/// a community for every rank, so `LegalValue<GatewayAgentSpec>` must supply at least this many
/// communities for the resulting config to validate.
pub const MAX_GROUP_MEMBERS: usize = 10;

impl TypeGenerator for LegalValue<GatewayAgentGatewayGroups> {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        let g = GatewayAgentGatewayGroups {
            name: driver
                .produce::<Option<K8sName>>()?
                .map(crate::bolero::support::K8sName::take),
            priority: Some(driver.gen_u32(Bound::Included(&0), Bound::Included(&10))?),
        };
        Some(LegalValue(g))
    }
}

/// Generate one member of a gateway group.
///
/// `priority` is deliberately narrow (`0..=10`) so that generated groups contain ties, which is
/// what exercises the name/address tiebreak in `GwGroupMember`'s `Ord`.  That restriction is why
/// this is a `LegalValue` rather than a bare `TypeGenerator` on the CRD type.
impl TypeGenerator for LegalValue<GatewayAgentGroupsMembers> {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        let gmember = GatewayAgentGroupsMembers {
            name: driver.produce::<K8sName>()?.take(),
            priority: driver.gen_u32(Bound::Included(&0), Bound::Included(&10))?,
            vtep_ip: driver.produce::<UnicastIpv4Addr>()?.to_string(),
        };
        Some(LegalValue(gmember))
    }
}

/// Generate a gateway group with `0..=MAX_GROUP_MEMBERS` members.
///
/// `GwGroup::add_member` rejects duplicate member names *and* duplicate member addresses, so both
/// have to be unique within a group for the value to be legal.  Collisions are repaired in place
/// (lengthen the name, walk the address) rather than by redrawing, so that every value the driver
/// produced still contributes and a collision costs a bounded amount of work.
impl TypeGenerator for LegalValue<GatewayAgentGroups> {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        let num_members =
            driver.gen_usize(Bound::Included(&0), Bound::Included(&MAX_GROUP_MEMBERS))?;

        let mut members = Vec::with_capacity(num_members);
        let mut names = BTreeSet::new();
        let mut addrs = BTreeSet::new();

        for _ in 0..num_members {
            let mut member = driver
                .produce::<LegalValue<GatewayAgentGroupsMembers>>()?
                .take();

            while !names.insert(member.name.clone()) {
                member.name.push('x');
            }

            // `LegalValue<GatewayAgentGroupsMembers>` draws a unicast address, so parsing it back
            // cannot fail.  Walk it on collision, skipping over the non-unicast space.
            #[allow(clippy::unwrap_used)]
            let mut addr = member.vtep_ip.parse::<Ipv4Addr>().unwrap().to_bits();
            while !addrs.insert(addr) {
                addr = addr.wrapping_add(1);
                let candidate = Ipv4Addr::from(addr);
                if candidate.is_multicast() || candidate.is_broadcast() {
                    addr = 0x0100_0000;
                }
            }
            member.vtep_ip = Ipv4Addr::from(addr).to_string();

            members.push(member);
        }

        Some(LegalValue(GatewayAgentGroups {
            members: Some(members),
        }))
    }
}

/// Generate the `spec.groups` map along with the group names, which peerings must reference.
///
/// Returns the map plus the sorted list of names, so the caller can hand the names to
/// [`crate::bolero::peering::LegalValuePeeringsGenerator`]: a peering naming a group that is not
/// in this table fails `ExternalConfig::validate`.
pub struct LegalValueGroupsTableGenerator {
    count: usize,
}

impl LegalValueGroupsTableGenerator {
    #[must_use]
    pub fn new(count: usize) -> Self {
        Self { count }
    }
}

impl ValueGenerator for LegalValueGroupsTableGenerator {
    type Output = (
        std::collections::BTreeMap<String, GatewayAgentGroups>,
        Vec<String>,
    );

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        let mut groups = std::collections::BTreeMap::new();
        let name_gen = K8sNameGenerator::new(1, 12);
        let mut names = Vec::with_capacity(self.count);
        for i in 0..self.count {
            // Suffix with the index so group names are distinct without a retry loop;
            // `GwGroupTable::add_group` rejects duplicates.
            let name = format!("{}-{i}", name_gen.generate(d)?);
            groups.insert(
                name.clone(),
                d.produce::<LegalValue<GatewayAgentGroups>>()?.take(),
            );
            names.push(name);
        }
        Some((groups, names))
    }
}
