// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use k8s_types::gateway_agent_crd::GatewayAgentStatusStateFrr;

use crate::converters::k8s::ToK8sConversionError;
use crate::internal::status::FrrStatus;

impl TryFrom<&FrrStatus> for GatewayAgentStatusStateFrr {
    type Error = ToK8sConversionError;

    fn try_from(status: &FrrStatus) -> Result<Self, Self::Error> {
        Ok(GatewayAgentStatusStateFrr {
            last_applied_gen: Some(status.applied_config_gen),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::internal::status::contract::LegalValue;

    #[test]
    fn test_frr_status_conversion() {
        bolero::check!()
            .with_type::<LegalValue<FrrStatus>>()
            .for_each(|status| {
                let status = status.as_ref();
                let k8s_frr_status = GatewayAgentStatusStateFrr::try_from(status)
                    .expect("Failed to convert frr status");

                assert_eq!(
                    status.applied_config_gen,
                    k8s_frr_status
                        .last_applied_gen
                        .expect("K8s frr last applied gen not set"),
                );
            });
    }
}
