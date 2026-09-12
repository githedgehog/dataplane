// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use bolero::{Driver, TypeGenerator};
use net::ipv4::UnicastIpv4Addr;
use std::collections::HashSet;
use std::ops::Bound;

use crate::bolero::LegalValue;
use crate::gateway_agent_crd::{
    GatewayAgentGatewayGroups, GatewayAgentGroups, GatewayAgentGroupsMembers,
};

impl TypeGenerator for LegalValue<GatewayAgentGatewayGroups> {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        let g = GatewayAgentGatewayGroups {
            name: driver.produce::<String>(),
            priority: Some(driver.gen_u32(Bound::Included(&0), Bound::Included(&10))?),
        };
        Some(LegalValue(g))
    }
}

impl TypeGenerator for GatewayAgentGroupsMembers {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        let gmember = GatewayAgentGroupsMembers {
            name: driver.produce::<String>()?,
            priority: driver.gen_u32(Bound::Included(&0), Bound::Included(&10))?,
            vtep_ip: driver.produce::<UnicastIpv4Addr>()?.to_string(),
        };
        Some(gmember)
    }
}

impl TypeGenerator for GatewayAgentGroups {
    fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
        let num_members = driver.gen_usize(Bound::Included(&0), Bound::Included(&10))?;
        let mut members = Vec::with_capacity(num_members);
        let mut addresses = HashSet::new();
        for i in 0..num_members {
            let mut member = driver.produce::<GatewayAgentGroupsMembers>()?;
            // A member's rank is its position in the group, and `GwGroup::add_member`
            // refuses a repeated name or vtep address, so a group whose members collide
            // is not a legal configuration. Suffix the name to make it distinct by
            // construction, and drop a member whose address repeats rather than redrawing,
            // so this loop cannot spin on a driver that keeps handing back one value.
            member.name = format!("{}-{i}", member.name);
            if !addresses.insert(member.vtep_ip.clone()) {
                continue;
            }
            members.push(member);
        }
        Some(GatewayAgentGroups {
            members: Some(members),
        })
    }
}
