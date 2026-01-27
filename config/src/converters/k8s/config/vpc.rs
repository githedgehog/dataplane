// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::convert::TryFrom;

use k8s_intf::gateway_agent_crd::GatewayAgentVpcs;

use crate::converters::k8s::FromK8sConversionError;
use crate::external::overlay::vpc::Vpc;

impl TryFrom<(&str, &GatewayAgentVpcs)> for Vpc {
    type Error = FromK8sConversionError;

    fn try_from((vpc_name, k8s_vpc): (&str, &GatewayAgentVpcs)) -> Result<Self, Self::Error> {
        let internal_id =
            k8s_vpc
                .internal_id
                .as_ref()
                .ok_or(FromK8sConversionError::MissingData(
                    "Internal ID not found".to_string(),
                ))?;

        let vni = k8s_vpc
            .vni
            .as_ref()
            .ok_or(FromK8sConversionError::MissingData(
                "VNI not found".to_string(),
            ))?;

        // Create a new VPC with name and VNI
        Vpc::new(vpc_name, internal_id, *vni).map_err(|e| {
            FromK8sConversionError::InternalError(format!("Could not create VPC: {e}"))
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use k8s_intf::bolero::LegalValue;

    #[test]
    fn test_vpc_conversion() {
        bolero::check!()
            .with_type::<LegalValue<GatewayAgentVpcs>>()
            .for_each(|k8s_vpc| {
                let k8s_vpc = k8s_vpc.as_ref();

                let vpc = Vpc::try_from(("test", k8s_vpc)).unwrap();

                assert_eq!(vpc.name, "test");
                assert_eq!(Some(vpc.id.to_string()), k8s_vpc.internal_id);
            });
    }
}
