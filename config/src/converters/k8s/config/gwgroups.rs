// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::converters::k8s::FromK8sConversionError;
use crate::converters::strings::parse_address;
use k8s_intf::gateway_agent_crd::{GatewayAgentGroupsMembers, GatewayAgentSpec};

use crate::external::gwgroup::{GwGroup, GwGroupMember, GwGroupTable};

impl TryFrom<&GatewayAgentGroupsMembers> for GwGroupMember {
    type Error = FromK8sConversionError;

    fn try_from(value: &GatewayAgentGroupsMembers) -> Result<Self, Self::Error> {
        let address = value.vtep_ip.as_str();
        let ipaddress = parse_address(address)
            .map_err(|e| Self::Error::InvalidData(format!("ip address {address}: {e}")))?;

        Ok(Self {
            name: value.name.clone(),
            priority: value.priority,
            ipaddress,
        })
    }
}

impl TryFrom<&GatewayAgentSpec> for GwGroupTable {
    type Error = FromK8sConversionError;

    fn try_from(spec: &GatewayAgentSpec) -> Result<Self, Self::Error> {
        let mut group_table = GwGroupTable::new();

        match &spec.groups {
            None => Ok(group_table),
            Some(map) => {
                for (name, gagroups) in map {
                    let mut group = GwGroup::new(name);
                    if let Some(members) = gagroups.members.as_ref() {
                        for m in members {
                            let member = GwGroupMember::try_from(m)?;
                            group.add_member(member)?;
                        }
                    } else {
                        // we don't complain on empty groups, which are shared resources
                        // we may want to complain later if a peering refers to an empty group
                    }
                    group_table.add_group(group)?;
                }
                Ok(group_table)
            }
        }
    }
}
