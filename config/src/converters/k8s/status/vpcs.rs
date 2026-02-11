// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use k8s_types::gateway_agent_crd::GatewayAgentStatusStateVpcs;

use crate::converters::k8s::ToK8sConversionError;
use crate::internal::status::VpcCounters;

impl TryFrom<&VpcCounters> for GatewayAgentStatusStateVpcs {
    type Error = ToK8sConversionError;

    fn try_from(vpc_counters: &VpcCounters) -> Result<Self, Self::Error> {
        Ok(GatewayAgentStatusStateVpcs {
            b: Some(vpc_counters.bytes),
            d: Some(vpc_counters.drops),
            p: Some(vpc_counters.packets),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::internal::status::contract::LegalValue;

    #[test]
    fn test_vpc_status_conversion() {
        bolero::check!()
            .with_type::<LegalValue<VpcCounters>>()
            .for_each(|status| {
                let status = status.as_ref();
                let k8s_vpc_status = GatewayAgentStatusStateVpcs::try_from(status)
                    .expect("Failed to convert frr status");

                assert_eq!(status.bytes, k8s_vpc_status.b.expect("K8s vpcs b not set"),);
                assert_eq!(status.drops, k8s_vpc_status.d.expect("K8s vpcs d not set"),);
                assert_eq!(
                    status.packets,
                    k8s_vpc_status.p.expect("K8s vpcs p not set"),
                );
            });
    }
}
