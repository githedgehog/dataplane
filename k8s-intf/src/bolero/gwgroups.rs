// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use bolero::{Driver, TypeGenerator};
use net::ipv4::UnicastIpv4Addr;
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
        let mut members = vec![];
        if num_members > 0 {
            members.push(driver.produce::<GatewayAgentGroupsMembers>()?);
        }
        Some(GatewayAgentGroups {
            members: Some(members),
        })
    }
}
