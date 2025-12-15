// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::converters::strings::parse_address;
use crate::external::gwgroup::{GwGroup, GwGroupMember};
use gateway_config::config as gateway_config;

impl TryFrom<&gateway_config::GatewayGroupMember> for GwGroupMember {
    type Error = String;

    fn try_from(value: &gateway_config::GatewayGroupMember) -> Result<Self, Self::Error> {
        let address = parse_address(&value.ipaddress)
            .map_err(|e| format!("Bad ip address '{}': {e}", value.ipaddress))?;
        Ok(GwGroupMember::new(&value.name, value.priority, address))
    }
}
impl TryFrom<&GwGroupMember> for gateway_config::GatewayGroupMember {
    type Error = String;

    fn try_from(value: &GwGroupMember) -> Result<Self, Self::Error> {
        Ok(gateway_config::GatewayGroupMember {
            name: value.name.clone(),
            priority: value.priority,
            ipaddress: value.ipaddress.to_string(),
        })
    }
}

impl TryFrom<&gateway_config::GatewayGroup> for GwGroup {
    type Error = String;

    fn try_from(value: &gateway_config::GatewayGroup) -> Result<Self, Self::Error> {
        let mut rgroup = GwGroup::new(&value.name);
        for m in &value.members {
            let member = GwGroupMember::try_from(m)?;
            rgroup.add_member(member).map_err(|e| e.to_string())?;
        }
        Ok(rgroup)
    }
}

impl TryFrom<&GwGroup> for gateway_config::GatewayGroup {
    type Error = String;

    fn try_from(value: &GwGroup) -> Result<Self, Self::Error> {
        let members: Vec<_> = value
            .iter()
            .map(|m| {
                gateway_config::GatewayGroupMember::try_from(m).unwrap_or_else(|_| unreachable!())
            })
            .collect();
        Ok(Self {
            name: value.name().to_owned(),
            members,
        })
    }
}
