// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use k8s_types::gateway_agent_crd::GatewayAgentStatusStatePeerings;

use crate::converters::k8s::ToK8sConversionError;
use crate::internal::status::VpcPeeringCounters;

impl TryFrom<&VpcPeeringCounters> for GatewayAgentStatusStatePeerings {
    type Error = ToK8sConversionError;

    fn try_from(counters: &VpcPeeringCounters) -> Result<Self, Self::Error> {
        Ok(GatewayAgentStatusStatePeerings {
            b: Some(counters.bytes),
            d: Some(counters.drops),
            p: Some(counters.packets),
            bps: Some(counters.bps),
            pps: Some(counters.pps),
        })
    }
}
