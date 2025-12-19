// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::converters::k8s::FromK8sConversionError;
use crate::converters::strings::parse_address;
use k8s_intf::gateway_agent_crd::{GatewayAgentGroupsMembers, GatewayAgentSpec};

use crate::external::gwgroup::{GwGroup, GwGroupMember, GwGroupTable};

impl TryFrom<&GatewayAgentGroupsMembers> for GwGroupMember {
    type Error = FromK8sConversionError;

    fn try_from(value: &GatewayAgentGroupsMembers) -> Result<Self, Self::Error> {
        let name = value
            .name
            .as_ref()
            .ok_or_else(|| Self::Error::MissingData("Gateway group member name".to_string()))?;

        let priority: u32 = value.priority.unwrap_or(0);
        //.ok_or_else(|| Self::Error::MissingData("Gateway group member priority".to_string()))?;

        let address = value.vtep_ip.as_ref().ok_or_else(|| {
            Self::Error::MissingData("Gateway group member ip address".to_string())
        })?;
        let ipaddress = parse_address(address)
            .map_err(|e| Self::Error::ParseError(format!("Invalid ip address {address}: {e}")))?;

        Ok(Self {
            name: name.clone(),
            priority,
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
                    let members = gagroups.members.as_ref().ok_or_else(|| {
                        Self::Error::MissingData(format!("Gateway group members for group {name}"))
                    })?;
                    for m in members {
                        let member = GwGroupMember::try_from(m)?;
                        group.add_member(member)?;
                    }
                    group_table.add_group(group)?;
                }
                Ok(group_table)
            }
        }
    }
}
