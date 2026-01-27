// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::converters::k8s::FromK8sConversionError;
use k8s_intf::gateway_agent_crd::GatewayAgentSpec;

use crate::external::communities::PriorityCommunityTable;

impl TryFrom<&GatewayAgentSpec> for PriorityCommunityTable {
    type Error = FromK8sConversionError;

    fn try_from(spec: &GatewayAgentSpec) -> Result<Self, Self::Error> {
        let mut comtable = PriorityCommunityTable::new();
        match &spec.communities {
            None => Ok(comtable),
            Some(map) => {
                for (prio, community) in map {
                    let priority: u32 = prio.parse().map_err(|e| {
                        Self::Error::InvalidData(format!("community priority {prio}: {e}"))
                    })?;
                    comtable.insert(priority, community)?;
                }
                Ok(comtable)
            }
        }
    }
}
